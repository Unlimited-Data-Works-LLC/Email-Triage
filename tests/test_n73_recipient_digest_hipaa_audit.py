"""N-73 recipient-digest HIPAA audit bookend — behavioural + structural pin.

Fix verified: _fire_one_digest now writes a hipaa_access_events row
(operation='recipient_digest_sent') when hipaa=True, mirroring the N-33-B
pattern from web/topic_digest_sender.py.

Behavioural contracts:
  * A HIPAA recipient-digest SEND produces one hipaa_access_events row
    with operation='recipient_digest_sent' and outcome='ok'.
  * A non-HIPAA send produces NO hipaa_access_events row.
  * Audit failure MUST NOT fail the send (wrapped; access_log still written).

Structural (count-agnostic) pin (PD#3 / audit-emit inverse):
  * Every digest sender module that imports record_access_event AND
    has a HIPAA send path must ALSO import record_hipaa_access_event —
    the co-emission inverse for HIPAA-capable senders.
"""

from __future__ import annotations

import ast
import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

import ast

# census run13 #4 — use the harness root + relpath, not re-rolled boilerplate
from _pin_harness import SRC_ROOT as SRC, iter_src_files, parse_module, relpath as _relpath
DIGEST_PY = SRC / "web" / "digest.py"
TOPIC_DIGEST_PY = SRC / "web" / "topic_digest_sender.py"

# ---------------------------------------------------------------------------
# Structural pin — co-emission inverse (PD#3)
# ---------------------------------------------------------------------------

# Modules that write access_log (call ``record_access_event``) but are VERIFIED
# NOT to be PHI-egress digest SENDERS, so the N-33-B/N-73 co-emission invariant
# does not apply — each records a route-access / ops / infra / watch-fire event,
# NEVER a digest emailing PHI to a recipient (census run14 #3, verified per-site
# at HEAD). Keying on an EXCLUDE list (not the old hardcoded INCLUDE list) makes
# the pin FAIL-SAFE: a NEW digest sender that is NOT excluded is FLAGGED until it
# co-emits or is justified-excluded — the old INCLUDE list silently SKIPPED a
# forgotten 3rd sender (the gap census run14 #3 found).
_NOT_DIGEST_SENDERS = {
    "web/routers/ui/calendars.py",    # calendar-surrogate ROUTE access (not a digest send)
    "web/routers/ui/retry_queue.py",  # admin retry-queue ops route
    "web/routers/health.py",          # health endpoint
    "web/dependencies.py",            # auth/access dependency
    "web/access_audit.py",            # the access_log WRITER infrastructure itself
    "web/csrf.py",                    # CSRF (no HIPAA send path)
    "engine/store.py",                # engine store
    # watch-FIRE audit — its actions are HIPAA-redacted (subject->[redacted],
    # body never appears; "PHI never leaves the box via webhook"), so it records
    # the matcher's PHI-touch but never EGRESSES PHI like a digest. Verified run14 #3.
    "web/email_watches.py",
}


def _digest_sender_candidates() -> list[str]:
    """Every src module that writes access_log (``record_access_event``) and is
    NOT a verified non-sender — the DERIVED set the digest co-emission invariant
    applies to (replaces the old hardcoded INCLUDE list; census run14 #3). A
    module that already co-emits (``record_hipaa_access_event``) for some OTHER
    reason simply passes the co-emission check below, so it need not be excluded.
    """
    out: list[str] = []
    for p in iter_src_files():
        rel = _relpath(p)
        if rel in _NOT_DIGEST_SENDERS:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover
            continue
        if "record_access_event" in text:
            out.append(rel)
    return out


def test_digest_senders_co_emit_hipaa_access_events():
    """Count-agnostic co-emission inverse (PD#3 / N-33-B / N-73): every DERIVED
    digest-sender candidate (writes access_log, not exclude-listed) must ALSO
    emit ``record_hipaa_access_event``. Now FAIL-SAFE for a future 3rd sender —
    the candidate set is derived, not a hardcoded list a new sender can slip."""
    offenders = []
    for rel in _digest_sender_candidates():
        text = (SRC / rel).read_text(encoding="utf-8")
        if "record_hipaa_access_event" not in text:
            offenders.append(rel)

    assert not offenders, (
        "A module writes access_log (record_access_event) but NEVER "
        f"record_hipaa_access_event, and is not exclude-listed: {offenders}. If "
        "it is a HIPAA digest SENDER, emit record_hipaa_access_event on the HIPAA "
        "send (co-emission invariant, PD#3 / N-33-B / N-73). If it is NOT a "
        "PHI-egress sender (a route-access / ops / infra / watch-fire writer), add "
        "it to _NOT_DIGEST_SENDERS WITH a one-line justification."
    )


def _call_name(node: "ast.AST"):
    f = getattr(node, "func", None)
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


# Dispatchers that INVOKE a function passed as their first positional arg — the
# audit write hops the seam (PD#2: pin the seam, not the source). The SCHEDULED
# senders dispatch their record_access_event / record_hipaa_access_event off the
# loop via db_call(fn, …) (digest.py:708, topic_digest_sender.py:653), so a bare
# .func-name match is BLIND to them (DA run15 #8 — the pin passed vacuously).
_DISPATCHERS = {"db_call", "to_thread", "run_in_executor"}


def _effective_callee(call: "ast.Call"):
    """``(callee_name, applicable_kwargs)``. For a dispatcher seam — ``db_call(fn,
    …, outcome=…)`` — the effective callee is the function REFERENCE passed as the
    first positional arg, and the ``outcome=`` kwarg is on the DISPATCHER call.
    For a direct call it's the call's own name + kwargs."""
    nm = _call_name(call)
    if nm in _DISPATCHERS and call.args:
        a0 = call.args[0]
        inner = a0.id if isinstance(a0, ast.Name) else a0.attr if isinstance(a0, ast.Attribute) else None
        return inner, call.keywords
    return nm, call.keywords


def _outcome_is_digest_send(node: "ast.AST") -> bool:
    """An ``outcome=`` value (Constant or f-string) whose literal text contains
    ``digest_sent`` — the digest-SEND access_log signature."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "digest_sent" in node.value
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.Constant) and isinstance(v.value, str) and "digest_sent" in v.value
            for v in node.values
        )
    return False


def test_digest_send_FUNCTION_co_emits_hipaa_access_event():
    """FUNCTION-LEVEL co-emission (census run15 #8 — PD#2 "pin the seam, not the
    module"). The module-level check above is BLIND to a sender FUNCTION that omits
    the §164.312(b) row when the SAME MODULE emits it elsewhere — exactly
    ``accounts.recipient_digest_send_now``, whose module (accounts.py) has 10 OTHER
    ``record_hipaa_access_event`` calls that masked the per-function gap. So: any
    function that writes a digest-SEND access_log (``record_access_event(outcome=
    …digest_sent…)``) must ALSO call ``record_hipaa_access_event`` in its body — a
    HIPAA digest send is a PHI exfiltration. Interprocedural: ``ast.walk`` descends
    into the ``db_call`` closures where the audit writes live."""
    offenders = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            sends_digest = emits_hipaa = False
            for n in ast.walk(fn):
                if not isinstance(n, ast.Call):
                    continue
                callee, kwargs = _effective_callee(n)  # unwraps the db_call(fn,…) seam (PD#2)
                if callee == "record_access_event" and any(
                    kw.arg == "outcome" and _outcome_is_digest_send(kw.value) for kw in kwargs
                ):
                    sends_digest = True
                elif callee == "record_hipaa_access_event":
                    emits_hipaa = True
            if sends_digest and not emits_hipaa:
                offenders.append(f"{_relpath(p)}::{fn.name}")
    assert not offenders, (
        "A FUNCTION writes a digest-SEND access_log (record_access_event "
        f"outcome=…digest_sent…) but never record_hipaa_access_event: {offenders}. "
        "A HIPAA digest send is a §164.312(b) PHI exfiltration — emit the "
        "hipaa_access_events row in the SAME function's HIPAA branch (census run15 "
        "#8; the module-level check is blind to a per-function gap)."
    )


def test_known_digest_senders_are_in_the_candidate_set():
    """Guard the derivation against vacuity: the two known HIPAA digest senders
    MUST still be derived as candidates (write access_log + not excluded). If a
    refactor drops record_access_event from one — or wrongly excludes it — the
    co-emission pin would pass vacuously with nothing to check."""
    candidates = set(_digest_sender_candidates())
    for sender in ("web/digest.py", "web/topic_digest_sender.py"):
        assert sender in candidates, (
            f"{sender} is no longer a derived digest-sender candidate — it either "
            "stopped writing access_log (pin vacuous) or got wrongly excluded."
        )


def test_exclude_list_has_no_rot():
    """PD#7 (census the censusers): every ``_NOT_DIGEST_SENDERS`` entry must still
    exist AND still write access_log — else a stale exclude silently exempts a
    future sender written under that path."""
    stale = []
    for rel in _NOT_DIGEST_SENDERS:
        p = SRC / rel
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            stale.append(f"{rel} (missing)")
            continue
        if "record_access_event" not in text:
            stale.append(f"{rel} (no longer writes access_log)")
    assert not stale, (
        f"_NOT_DIGEST_SENDERS has stale entries (allow-list rot): {stale}. Remove "
        "them — a stale exclude silently un-checks a future sender under the path."
    )


# ---------------------------------------------------------------------------
# Behavioural tests — _fire_one_digest with hipaa=True/False
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("owner@example.com", "Owner", "user", _now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(conn: sqlite3.Connection, *, user_id: int, hipaa: bool = True) -> dict:
    now = _now()
    # Include email_address in config_json so account_addresses() resolves a
    # non-empty set — the _fire_one_digest guard rejects a mismatched/empty
    # to_addr before reaching the audit path.
    config_json = json.dumps({"email_address": "owner@example.com"})
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, hipaa, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Test Mailbox", "imap", config_json, int(hipaa), now, now),
    )
    conn.commit()
    acct_id = int(cur.lastrowid)
    from email_triage.web.db import get_email_account
    return get_email_account(conn, acct_id)


def _make_digest_config(hipaa: bool = True):
    from email_triage.actions.digest_configs import DigestConfig, DigestFormat
    return DigestConfig(
        id="digest_test_n73",
        kind="custom",
        name="N-73 test digest",
        enabled=True,
        format=DigestFormat(render_as="grouped_list"),
    )


def _make_smtp_cfg():
    smtp = MagicMock()
    smtp.host = "smtp.test"
    smtp.port = 587
    smtp.username = "u"
    smtp.from_addr = "owner@example.com"
    smtp.from_name = "Owner"
    smtp.use_tls = False
    return smtp


@pytest.mark.asyncio
async def test_hipaa_recipient_digest_creates_hipaa_access_event():
    """A HIPAA recipient-digest send writes one hipaa_access_events row
    with operation='recipient_digest_sent'."""
    conn = _make_db()
    user_id = _seed_user(conn)
    acct = _seed_account(conn, user_id=user_id, hipaa=True)
    dcfg = _make_digest_config(hipaa=True)

    smtp = _make_smtp_cfg()
    secrets = MagicMock()
    config = MagicMock()
    config.smtp = smtp
    now_utc = datetime.now(timezone.utc)

    # _fire_one_digest calls _render_digest_payload (async) + send_recipient_digest
    # (sync via asyncio.to_thread) + audit writes. We mock the send + render so
    # the test is deterministic.
    fake_rows = [{"msg_id": "id1", "subject": "Test", "sender": "s@test.com"}]

    # send_recipient_digest is a late import inside _fire_one_digest —
    # patch at the source module where it's actually called.
    with (
        patch(
            "email_triage.web.digest._render_digest_payload",
            new_callable=AsyncMock,
            return_value=(
                "Test Subject", "<html>", "plain", fake_rows,
                len(fake_rows),
            ),
        ),
        patch("email_triage.actions.recipient_digest.send_recipient_digest"),
        patch("email_triage.actions.digest_configs.mark_sent"),
    ):
        from email_triage.web.digest import _fire_one_digest
        await _fire_one_digest(
            db=conn,
            secrets=secrets,
            smtp=smtp,
            acct=acct,
            dcfg=dcfg,
            hipaa=True,
            to_addr=acct["email_address"],
            now_utc=now_utc,
            last_sent=None,
            config=config,
            is_test_send=False,
        )

    rows = conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id = ?",
        (acct["id"],)
    ).fetchall()
    assert len(rows) == 1, (
        f"Expected 1 hipaa_access_events row for HIPAA digest send, got {len(rows)}"
    )
    row = dict(rows[0])
    assert row["operation"] == "recipient_digest_sent", (
        f"Unexpected operation value: {row['operation']!r}"
    )
    assert row["outcome"] == "ok", (
        f"Unexpected outcome value: {row['outcome']!r}"
    )
    # actor_user_id must be None (system-initiated)
    assert row["actor_user_id"] is None, (
        f"System-initiated send should have actor_user_id=None, got {row['actor_user_id']}"
    )


@pytest.mark.asyncio
async def test_non_hipaa_recipient_digest_no_hipaa_access_event():
    """A non-HIPAA recipient-digest send writes NO hipaa_access_events row."""
    conn = _make_db()
    user_id = _seed_user(conn)
    acct = _seed_account(conn, user_id=user_id, hipaa=False)
    dcfg = _make_digest_config(hipaa=False)

    smtp = _make_smtp_cfg()
    secrets = MagicMock()
    config = MagicMock()
    config.smtp = smtp
    now_utc = datetime.now(timezone.utc)

    fake_rows = [{"msg_id": "id1", "subject": "Test", "sender": "s@test.com"}]

    with (
        patch(
            "email_triage.web.digest._render_digest_payload",
            new_callable=AsyncMock,
            return_value=(
                "Test Subject", "<html>", "plain", fake_rows,
                len(fake_rows),
            ),
        ),
        patch("email_triage.actions.recipient_digest.send_recipient_digest"),
        patch("email_triage.actions.digest_configs.mark_sent"),
    ):
        from email_triage.web.digest import _fire_one_digest
        await _fire_one_digest(
            db=conn,
            secrets=secrets,
            smtp=smtp,
            acct=acct,
            dcfg=dcfg,
            hipaa=False,
            to_addr=acct["email_address"],
            now_utc=now_utc,
            last_sent=None,
            config=config,
            is_test_send=False,
        )

    rows = conn.execute(
        "SELECT * FROM hipaa_access_events WHERE account_id = ?",
        (acct["id"],)
    ).fetchall()
    assert len(rows) == 0, (
        f"Non-HIPAA digest send should produce NO hipaa_access_events row, got {len(rows)}"
    )


@pytest.mark.asyncio
async def test_hipaa_audit_failure_does_not_fail_send():
    """An audit write failure must NOT prevent the send from completing.

    This verifies the try/except wrapping on the hipaa_access_events write
    (the send is not wrapped — SMTP failures propagate; audit failures must not).
    """
    conn = _make_db()
    user_id = _seed_user(conn)
    acct = _seed_account(conn, user_id=user_id, hipaa=True)
    dcfg = _make_digest_config(hipaa=True)

    smtp = _make_smtp_cfg()
    secrets = MagicMock()
    config = MagicMock()
    config.smtp = smtp
    now_utc = datetime.now(timezone.utc)
    fake_rows = [{"msg_id": "id1"}]

    send_called = []

    def mock_send(**kwargs):
        send_called.append(True)

    with (
        patch(
            "email_triage.web.digest._render_digest_payload",
            new_callable=AsyncMock,
            return_value=(
                "Subject", "<html>", "plain", fake_rows, len(fake_rows),
            ),
        ),
        patch("email_triage.actions.recipient_digest.send_recipient_digest",
              side_effect=mock_send),
        patch("email_triage.actions.digest_configs.mark_sent"),
        # Force the hipaa_access_events write to fail
        patch(
            "email_triage.web.db.record_hipaa_access_event",
            side_effect=RuntimeError("DB locked"),
        ),
    ):
        from email_triage.web.digest import _fire_one_digest
        result = await _fire_one_digest(
            db=conn,
            secrets=secrets,
            smtp=smtp,
            acct=acct,
            dcfg=dcfg,
            hipaa=True,
            to_addr=acct["email_address"],
            now_utc=now_utc,
            last_sent=None,
            config=config,
            is_test_send=False,
        )

    # The send must have been called despite the audit failure
    assert send_called, "SMTP send was not called — audit failure blocked the send"
    assert result == 1, f"Expected 1 (rows sent), got {result}"
