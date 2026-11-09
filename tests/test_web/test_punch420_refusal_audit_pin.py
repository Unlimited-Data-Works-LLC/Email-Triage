"""Punch  item 6 — a refused Bearer attempt is a RECORD, and the record is bounded.

Design 420 item 6: "a scope REFUSAL should be observable ... `verify_api_key` does
not currently log unknown-key attempts at all". The route-scope WIP deliberately
wrote no audit row (it feared an unbounded write rate onto the single serialized
SQLite writer). This pin holds the reconciled shape:

* a scoped key used off-scope, a role refused off its allowlist, and a Bearer
  credential that resolves to nobody each write ONE ``auth_events`` row through the
  ``record_auth_event`` emitter SSOT (PD#3, never a raw INSERT);
* the row rate is capped per source (``_route_scope.refusal_audit_decision``): the
  first ``REFUSAL_AUDIT_MAX_PER_WINDOW`` rows are individual, ONE further row says
  the rest are counted not written, and nothing more is written in that window — so
  the loss is itself on the record and the write cost of a refusal stream is bounded;
* ``/health/runtime-deps`` admits ``health_ro`` (the N-536 arm) and still refuses a
  plain non-admin.

Every arm has a teeth test (R38): the cap is shown to fire, and the emit is shown to
disappear when the seam stops calling it.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

import email_triage.web._route_scope as rs
from email_triage.engine.models import UserRole
from email_triage.web.auth import generate_api_key, hash_api_key
from email_triage.web.auth import store_api_key as _store_api_key


def store_api_key(db, *args, **kwargs):
    kwargs.setdefault("actor_email", "test:punch420-audit-pin")
    kwargs.setdefault("source", "test")
    return _store_api_key(db, *args, **kwargs)


@pytest.fixture(autouse=True)
def _fresh_refusal_windows():
    rs.reset_refusal_audit_state()
    yield
    rs.reset_refusal_audit_state()


def _rows(db, event_type: str, after_id: int = 0):
    return db.execute(
        "SELECT id, event_type, email, user_id, key_id, ip, outcome, detail "
        "FROM auth_events WHERE event_type = ? AND id > ? ORDER BY id",
        (event_type, after_id),
    ).fetchall()


def _max_id(db) -> int:
    return db.execute("SELECT COALESCE(MAX(id), 0) FROM auth_events").fetchone()[0]


def _health_ro_user(db) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("health-ro-audit@test.com", "Monitor", UserRole.HEALTH_RO.value, now),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# the decision function (unit) + teeth
# ---------------------------------------------------------------------------

def test_decision_emits_then_caps_once_then_skips_then_resets():
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    t0 = 1000.0
    seen = [rs.refusal_audit_decision("k", now=t0 + i * 0.001) for i in range(n + 5)]
    assert seen[:n] == ["emit"] * n
    assert seen[n] == "capped"
    assert seen[n + 1:] == ["skip"] * 4
    # A new window starts fresh.
    assert rs.refusal_audit_decision("k", now=t0 + rs.REFUSAL_AUDIT_WINDOW_S + 1) == "emit"
    # Sources are independent.
    assert rs.refusal_audit_decision("other", now=t0) == "emit"


def _flood_unknown_sources(count: int, now: float = 5.0):
    """``count`` distinct unknown-key sources, one refusal each (a rotating client)."""
    return [
        rs.refusal_audit_verdict(f"unknown_key:198.51.100.{i // 250}.{i % 250}", now=now)
        for i in range(count)
    ]


def test_decision_table_is_bounded_under_a_source_flood():
    cap = rs.REFUSAL_AUDIT_MAX_SOURCES
    _flood_unknown_sources(cap + 50)
    assert len(rs._refusal_audit_state) <= cap
    # Past the bound a NEW unknown source is folded into the shared overflow
    # source: the table still cannot grow, and it is not silently untracked.
    verdict = rs.refusal_audit_verdict("unknown_key:203.0.113.77", now=5.0)
    assert verdict.source == rs.REFUSAL_AUDIT_OVERFLOW_SOURCE
    assert len(rs._refusal_audit_state) <= cap


def test_principal_sources_are_never_subject_to_the_table_bound():
    """hipaa MUST-1 (a): a flood of rotated unknown-key addresses must not blind the
    record of an authenticated principal's off-scope use."""
    cap = rs.REFUSAL_AUDIT_MAX_SOURCES
    _flood_unknown_sources(cap + 50)
    for source in ("key:77", "user:5"):
        assert rs.refusal_audit_verdict(source, now=5.0).decision == "emit", source
    # They keep the per-source window cap: emit, one cap notice, then counted skips.
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    seen = [rs.refusal_audit_decision("key:88", now=6.0 + i * 0.001) for i in range(n + 3)]
    assert seen[:n] == ["emit"] * n and seen[n] == "capped" and seen[n + 1:] == ["skip"] * 2
    assert len(rs._refusal_audit_state) <= cap


def test_overflow_source_gets_one_window_one_cap_notice(monkeypatch):
    """hipaa MUST-1 (a)/(b): every unknown source past the bound shares ONE overflow
    source, which writes the capped row ONCE per window (no individual rows, so
    rotated addresses cannot buy 20 rows apiece). Nothing is dropped without a count."""
    cap = rs.REFUSAL_AUDIT_MAX_SOURCES
    verdicts = _flood_unknown_sources(cap + 100)
    overflow = [v for v in verdicts if v.source == rs.REFUSAL_AUDIT_OVERFLOW_SOURCE]
    assert len(overflow) == len(verdicts) - (cap - 1)
    assert [v.decision for v in overflow].count("emit") == 0
    assert [v.decision for v in overflow].count("capped") == 1
    assert overflow[0].decision == "capped"
    skipped = [v for v in overflow if v.decision == "skip"]
    assert len(skipped) == len(overflow) - 1
    # ... and the overflow's unreported count is on the record when its window ends.
    warned: list[dict] = []
    monkeypatch.setattr(rs.log, "warning", lambda msg, **kw: warned.append(kw))
    nxt = rs.refusal_audit_verdict(
        "unknown_key:192.0.2.1", now=5.0 + rs.REFUSAL_AUDIT_WINDOW_S + 1,
    )
    assert nxt.decision == "emit" and nxt.source == "unknown_key:192.0.2.1"
    assert [w["suppressed"] for w in warned] == [len(skipped)]


def test_every_skip_is_counted_and_the_count_rides_the_next_window_row():
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    t0 = 1000.0
    for i in range(n + 5):
        rs.refusal_audit_verdict("key:9", now=t0 + i * 0.001)   # 4 skips after the notice
    later = rs.refusal_audit_verdict("key:9", now=t0 + rs.REFUSAL_AUDIT_WINDOW_S + 1)
    assert (later.decision, later.suppressed) == ("emit", 4)
    # Reported once: the row after it carries nothing.
    assert rs.refusal_audit_verdict("key:9", now=t0 + rs.REFUSAL_AUDIT_WINDOW_S + 2).suppressed == 0


def test_a_window_that_expires_unreturned_reports_its_count_in_one_warning(monkeypatch):
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    t0 = 1000.0
    for i in range(n + 6):
        rs.refusal_audit_verdict("unknown_key:198.51.100.9", now=t0 + i * 0.001)
    warned: list[dict] = []
    monkeypatch.setattr(rs.log, "warning", lambda msg, **kw: warned.append({"msg": msg, **kw}))
    # The source never returns; any later refusal sweeps the expired window.
    rs.refusal_audit_verdict("key:1", now=t0 + rs.REFUSAL_AUDIT_WINDOW_S + 5)
    assert len(warned) == 1, warned
    assert warned[0]["suppressed"] == 5 and warned[0]["sources"] == 1
    assert "198.51.100.9" not in repr(warned)       # a count, never the address


def test_a_returning_source_rerouted_to_the_overflow_keeps_its_count(monkeypatch):
    """DA re-attest R1: a tracked source whose window expired with a count comes
    back while the table is full of LIVE sources. Its expired entry is removed, the
    table is still full, so the refusal is charged to the (live) overflow. The
    source's carried count must move with it onto the overflow, never vanish."""
    cap = rs.REFUSAL_AUDIT_MAX_SOURCES
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    t0 = 1000.0
    returning = "unknown_key:203.0.113.9"
    for i in range(n + 5):                                  # 4 counted skips
        rs.refusal_audit_verdict(returning, now=t0 + i * 0.001)
    t1 = t0 + rs.REFUSAL_AUDIT_WINDOW_S / 2
    # Fill the table at t1: cap-2 new sources fit, the next opens the overflow
    # (its cap notice) and the last is one counted overflow skip.
    _flood_unknown_sources(cap, now=t1)
    assert rs.REFUSAL_AUDIT_OVERFLOW_SOURCE in rs._refusal_audit_state
    warned: list[dict] = []
    monkeypatch.setattr(rs.log, "warning", lambda msg, **kw: warned.append(kw))
    back = rs.refusal_audit_verdict(returning, now=t0 + rs.REFUSAL_AUDIT_WINDOW_S + 1)
    assert back.source == rs.REFUSAL_AUDIT_OVERFLOW_SOURCE
    assert warned == []
    # The overflow's window ends: its count (1 flood skip + this refusal + the
    # returning source's 4) is reported once, as counts only.
    rs.refusal_audit_verdict("unknown_key:192.0.2.50", now=t1 + rs.REFUSAL_AUDIT_WINDOW_S + 1)
    assert [w["suppressed"] for w in warned] == [1 + 1 + 4], warned


# ---------------------------------------------------------------------------
# live: each refusal writes its row through the emitter
# ---------------------------------------------------------------------------

def test_off_scope_use_writes_an_api_key_scope_row(raw_client, db, admin_user):
    raw = generate_api_key()
    key_id = store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after = _max_id(db)
    resp = raw_client.get("/health/detail", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403
    rows = _rows(db, "api_key_scope", after)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["outcome"] == "denied:api_key_out_of_scope"
    assert row["key_id"] == key_id
    assert row["user_id"] == admin_user["id"]
    assert row["detail"].startswith("GET "), row["detail"]
    # The raw key is never in the row.
    assert raw not in json.dumps(dict(row))


def test_health_ro_off_allowlist_writes_a_role_route_fence_row(raw_client, db):
    uid = _health_ro_user(db)
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), "cve-arc", uid)
    after = _max_id(db)
    resp = raw_client.get("/api/status", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403
    rows = _rows(db, "role_route_fence", after)
    assert len(rows) == 1, rows
    assert rows[0]["outcome"] == "denied:role_not_allowed_on_route"
    assert rows[0]["user_id"] == uid


def test_unknown_key_writes_an_api_key_auth_row_and_no_secret(raw_client, db):
    bogus = generate_api_key()
    after = _max_id(db)
    resp = raw_client.get("/health/build", headers={"Authorization": f"Bearer {bogus}"})
    assert resp.status_code in (401, 403)
    rows = _rows(db, "api_key_auth", after)
    assert len(rows) == 1, rows
    assert rows[0]["outcome"] == "denied:key_not_accepted"
    assert rows[0]["key_id"] is None
    assert bogus not in json.dumps(dict(rows[0]))
    assert hash_api_key(bogus) not in json.dumps(dict(rows[0]))


def test_admitted_request_writes_no_refusal_row(raw_client, db, admin_user):
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after = _max_id(db)
    assert raw_client.get(
        "/health/build", headers={"Authorization": f"Bearer {raw}"},
    ).status_code == 200
    assert _rows(db, "api_key_scope", after) == []
    assert _rows(db, "api_key_auth", after) == []


def test_refusal_stream_is_bounded_and_the_cap_is_on_the_record(raw_client, db):
    bogus = generate_api_key()
    after = _max_id(db)
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    for _ in range(n + 15):
        raw_client.get("/health/build", headers={"Authorization": f"Bearer {bogus}"})
    rows = _rows(db, "api_key_auth", after)
    assert len(rows) == n + 1, f"expected {n} individual rows + 1 cap notice, got {len(rows)}"
    assert [r["outcome"] for r in rows[:n]] == ["denied:key_not_accepted"] * n
    assert rows[n]["outcome"] == "denied:audit_rate_capped"


def test_cap_notice_does_not_claim_the_warning_log_counts_unknown_keys(raw_client, db):
    """hipaa MUST-1 (b): ``verify_api_key`` returns None for an unknown hash with NO
    log line, so a notice saying the WARNING log counts these refusals was false."""
    bogus = generate_api_key()
    after = _max_id(db)
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    for _ in range(n + 3):
        raw_client.get("/health/build", headers={"Authorization": f"Bearer {bogus}"})
    notice = _rows(db, "api_key_auth", after)[n]
    assert notice["outcome"] == "denied:audit_rate_capped"
    assert "counted by the WARNING log" not in notice["detail"]
    assert "not written as rows" in notice["detail"]
    assert "next audit row" in notice["detail"] and "WARNING" in notice["detail"]


def test_suppressed_count_rides_the_next_row_for_the_source(raw_client, db):
    """hipaa MUST-1 (b): the volume of dropped refusals is on the record."""
    bogus = generate_api_key()
    after = _max_id(db)
    n = rs.REFUSAL_AUDIT_MAX_PER_WINDOW
    for _ in range(n + 15):     # n rows, 1 cap notice, 14 counted skips
        raw_client.get("/health/build", headers={"Authorization": f"Bearer {bogus}"})
    assert len(_rows(db, "api_key_auth", after)) == n + 1
    for entry in rs._refusal_audit_state.values():      # age every window past its end
        entry[0] -= rs.REFUSAL_AUDIT_WINDOW_S + 1
    raw_client.get("/health/build", headers={"Authorization": f"Bearer {bogus}"})
    rows = _rows(db, "api_key_auth", after)
    assert len(rows) == n + 2
    assert rows[-1]["outcome"] == "denied:key_not_accepted"
    assert rows[-1]["detail"].endswith(" suppressed=14"), rows[-1]["detail"]
    assert all("suppressed=" not in r["detail"] for r in rows[:-1])


def test_a_principal_row_survives_a_full_unknown_key_table(raw_client, db, admin_user):
    """hipaa MUST-1 (a), end to end: a flood of rotated unknown-key addresses fills the
    table; a scoped key used off-scope still gets its own row."""
    _flood_unknown_sources(rs.REFUSAL_AUDIT_MAX_SOURCES + 50, now=time.monotonic())
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after = _max_id(db)
    assert raw_client.get(
        "/health/detail", headers={"Authorization": f"Bearer {raw}"},
    ).status_code == 403
    rows = _rows(db, "api_key_scope", after)
    assert len(rows) == 1 and rows[0]["outcome"] == "denied:api_key_out_of_scope"


class _StubRequest:
    """Just enough request for ``_check_bearer_token`` / ``_audit_bearer_refusal``."""

    def __init__(self, db, *, peer="203.0.113.5", xff="", trusted=None, auth=None):
        from types import SimpleNamespace
        self.client = SimpleNamespace(host=peer)
        self.headers = {"user-agent": "pytest", "x-forwarded-for": xff}
        if auth:
            self.headers["Authorization"] = auth
        self.method = "GET"
        self.scope = {"client": (peer, 0), "route": None}
        self.state = SimpleNamespace()
        state = SimpleNamespace(db=db)
        if trusted is not None:
            state.config = SimpleNamespace(audit=SimpleNamespace(trusted_proxies=trusted))
        self.app = SimpleNamespace(state=state)


def test_unknown_key_source_follows_the_forwarded_for_ssot(db, monkeypatch):
    """db S1: behind a listed proxy the source is the real client (N-321/N-337), so
    one rotating-address client does not share a budget with everyone else."""
    import email_triage.web.dependencies as deps

    seen: list[str] = []
    monkeypatch.setattr(deps, "verify_api_key", lambda *_a, **_k: None)
    monkeypatch.setattr(deps, "_audit_bearer_refusal", lambda *_a, **kw: seen.append(kw["source"]))
    req = _StubRequest(db, peer="10.0.0.2", xff="198.51.100.9", trusted=["10.0.0.0/8"],
                       auth="Bearer not-a-real-key")
    assert deps._check_bearer_token(req) is None
    assert seen == ["unknown_key:198.51.100.9"]
    # No proxy listed: the raw peer, exactly as before.
    seen.clear()
    req = _StubRequest(db, peer="10.0.0.2", xff="198.51.100.9", trusted=[],
                       auth="Bearer not-a-real-key")
    deps._check_bearer_token(req)
    assert seen == ["unknown_key:10.0.0.2"]


def test_refusal_row_ip_follows_the_forwarded_for_ssot(db):
    import email_triage.web.dependencies as deps

    req = _StubRequest(db, peer="10.0.0.2", xff="198.51.100.9", trusted=["10.0.0.0/8"])
    after = _max_id(db)
    deps._audit_bearer_refusal(
        req, event_type="api_key_auth", reason="key_not_accepted",
        source="unknown_key:198.51.100.9",
    )
    rows = _rows(db, "api_key_auth", after)
    assert len(rows) == 1 and rows[0]["ip"] == "198.51.100.9"


def test_a_reason_outside_the_closed_set_is_recorded_as_unclassified(db):
    """DA S2: the ``denied:<reason>`` outcome is a closed set in code, not a comment."""
    import email_triage.web.dependencies as deps

    after = _max_id(db)
    deps._audit_bearer_refusal(
        _StubRequest(db), event_type="api_key_auth",
        reason="free text an attacker influenced", source="unknown_key:203.0.113.5",
    )
    rows = _rows(db, "api_key_auth", after)
    assert [r["outcome"] for r in rows] == ["denied:unclassified"]


def test_every_scope_refusal_reason_is_in_the_closed_set():
    """A ``ScopeRefused`` reason added without widening the set would silently become
    ``unclassified``; make the widening a conscious step."""
    import ast
    import inspect

    import email_triage.web.dependencies as deps

    reasons = {
        n.args[0].value
        for n in ast.walk(ast.parse(inspect.getsource(rs)))
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "ScopeRefused"
        and n.args and isinstance(n.args[0], ast.Constant)
    }
    assert reasons, "no ScopeRefused raise found: the scan is broken"
    assert reasons <= deps._BEARER_REFUSAL_REASONS, reasons - deps._BEARER_REFUSAL_REASONS
    assert "key_not_accepted" in deps._BEARER_REFUSAL_REASONS


def test_teeth_no_row_when_the_seam_stops_emitting(raw_client, db, admin_user, monkeypatch):
    """Plant "the seam never audits": the row-count assertion must then FAIL."""
    import email_triage.web.dependencies as deps

    monkeypatch.setattr(deps, "_audit_bearer_refusal", lambda *a, **k: None)
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after = _max_id(db)
    assert raw_client.get(
        "/health/detail", headers={"Authorization": f"Bearer {raw}"},
    ).status_code == 403
    assert _rows(db, "api_key_scope", after) == [], (
        "with the emit stubbed out there must be no row — if this fails the other "
        "arms are not measuring the seam"
    )


# ---------------------------------------------------------------------------
# /health/runtime-deps: admin OR health_ro
# ---------------------------------------------------------------------------

def test_runtime_deps_admits_health_ro_and_refuses_a_plain_user(raw_client, db, admin_user):
    uid = _health_ro_user(db)
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), "cve-arc", uid)
    resp = raw_client.get("/health/runtime-deps", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200, resp.status_code
    assert "distributions" in resp.json()

    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("plain-audit@test.com", "Plain", UserRole.USER.value, now),
    )
    db.commit()
    plain = generate_api_key()
    store_api_key(db, hash_api_key(plain), "plain", cur.lastrowid)
    refused = raw_client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {plain}"},
    )
    assert refused.status_code == 403, refused.status_code


def test_is_health_ro_fails_closed():
    from email_triage.web.dependencies import is_health_ro

    assert is_health_ro({"role": "health_ro"}) is True
    for bad in (None, {}, {"role": None}, {"role": 7}, {"role": "admin"}, {"role": "HEALTH_RO"}):
        assert is_health_ro(bad) is False, bad
