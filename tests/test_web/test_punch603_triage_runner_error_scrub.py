"""Punch 603: a per-message error from ``run_triage`` is secret-scrubbed.

Before the fix both per-message ``except`` branches of ``run_triage`` put a
PHI-only scrub into the result entry: the fetch branch used
``_flash.scrub_exc`` (no ``key=value`` token leg) and the triage branch
``fmt_exc`` (no token leg, no length cap). That entry is returned to the
agent API caller and persisted in ``triage_runs.results_json``, so an
``access_token=ya29...`` in an exception reached both, uncapped. The bulk
sibling (``triage_runner_bulk``) already used ``scrub_class_error_for_persist``.

SCOPE CAVEAT: the pin walks ``web/triage_runner*.py`` only. An entry built
inside ``triage_one.triage_single_message`` (``res.entry``) is not followed.
"""
from __future__ import annotations

import ast
import asyncio
import json
from types import SimpleNamespace

import pytest

from _pin_harness import assert_pin_has_teeth, hop_target, walk_src

SECRET = "ya29.SECRETVALUE603"
EXC_TEXT = f"token refresh failed: access_token={SECRET} for alice@clinic.org " + "x" * 900


class _Provider:
    async def search(self, query, limit):
        return ["m-fetch", "m-triage"]

    async def fetch_message(self, msg_id):
        if msg_id == "m-fetch":
            raise RuntimeError(EXC_TEXT)
        return SimpleNamespace(raw_metadata={}, hipaa=False)

    async def close(self):
        return None


@pytest.fixture
def stubbed_run(db, admin_user, monkeypatch):
    from email_triage.db.accounts import create_email_account, get_email_account
    from email_triage.web.routers import ui as ui_pkg
    from email_triage.web import triage_one

    acct_id = create_email_account(db, admin_user["id"], "Acct 603", "imap", {}, hipaa=False)
    monkeypatch.setattr(ui_pkg, "_create_provider_from_account", lambda a, s: _Provider())
    monkeypatch.setattr(ui_pkg, "_build_classifier_from_config", lambda c: object())
    monkeypatch.setattr(ui_pkg, "_get_categories_from_db", lambda d, user_id=None: {"misc": "Misc"})

    async def _boom(ctx, message, msg_id):
        raise RuntimeError(EXC_TEXT)

    monkeypatch.setattr(triage_one, "triage_single_message", _boom)
    return get_email_account(db, acct_id)


def test_both_per_message_errors_are_secret_scrubbed_and_capped(app, db, stubbed_run):
    from email_triage.web.triage_runner import run_triage

    res = asyncio.run(run_triage(
        db, app.state.config, app.state.secrets, stubbed_run,
        query="in:inbox", limit=5, actor_user_id=None,
    ))
    by_id = {e["message_id"]: e for e in res["results"]}
    assert set(by_id) == {"m-fetch", "m-triage"}      # both branches ran
    for entry in by_id.values():
        assert entry["status"] == "error"
        assert SECRET not in entry["error"]
        assert "alice@clinic.org" not in entry["error"]
        assert len(entry["error"]) <= 500
    row = db.execute(
        "SELECT results_json FROM triage_runs WHERE account_id = ? "
        "ORDER BY id DESC LIMIT 1", (stubbed_run["id"],)).fetchone()
    assert row is not None and SECRET not in row["results_json"]
    assert len(json.loads(row["results_json"])) == 2


# ---------------------------------------------------------------------------
# Pin: every error string a triage runner returns or persists goes through
# the persisted-error scrub SSOT (PHI + secret legs + cap).
# ---------------------------------------------------------------------------

_SCRUB_SSOT = {"scrub_class_error_for_persist", "scrub_error_for_persist"}
#: Exception renderers that scrub PHI only (no token leg, no cap).
_PHI_ONLY = {"fmt_exc", "scrub_exc", "redact_exc"}
#: Calls whose error argument is scrubbed INSIDE the callee, at the sink.
#: Each entry is proven by test_sink_scrubbers_still_scrub below.
_SINK_SCRUBBED = {"finish_triage_job": "web/db.py scrubs error_text (_scrub_err_persist)"}
_DISPATCHERS = {"db_call", "db_call_async", "run_in_threadpool"}


def _callee(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _except_names(tree: ast.AST) -> set[str]:
    return {h.name for h in ast.walk(tree) if isinstance(h, ast.ExceptHandler) and h.name}


def _ok(value: ast.AST, exc_names: set[str]) -> bool:
    """OK: a literal, a scrub-SSOT call, or text that renders no exception (a
    config-built message). Violation: any part renders an exception (an
    ``except ... as e`` name, or a PHI-only renderer) outside the SSOT."""
    if isinstance(value, ast.Constant) or _callee(value) in _SCRUB_SSOT:
        return True
    for n in ast.walk(value):
        if isinstance(n, ast.Name) and n.id in exc_names:
            return False
        if _callee(n) in _PHI_ONLY:
            return False
    return True


def _sink_scrubbed(call: ast.Call) -> bool:
    if _callee(call) in _SINK_SCRUBBED:
        return True
    hop = hop_target(call, frozenset(_DISPATCHERS))  # punch 672: one hop resolver
    return hop is not None and hop.name in _SINK_SCRUBBED


def _error_sinks(tree: ast.AST):
    """Yield every value that becomes a returned/persisted error string."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and k.value == "error":
                    yield v
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "error"):
                    yield n.value
        elif isinstance(n, ast.Call) and not _sink_scrubbed(n):
            if (isinstance(n.func, ast.Attribute) and n.func.attr == "append"
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "errors"):
                yield from n.args
            for kw in n.keywords:
                if kw.arg == "errors" and isinstance(kw.value, ast.List):
                    yield from kw.value.elts
                elif kw.arg in ("error_text", "error_msg"):
                    yield kw.value


def _violations(tree: ast.AST) -> list[str]:
    exc_names = _except_names(tree)
    return [f"line {v.lineno}: {ast.unparse(v)[:80]}"
            for v in _error_sinks(tree) if not _ok(v, exc_names)]


def _runner_trees():
    return [(rel, tree) for _p, rel, tree in walk_src("web")
            if rel.split("/")[-1].startswith("triage_runner")]


def test_every_triage_runner_error_routes_through_the_scrub_ssot():
    trees = _runner_trees()
    assert {"web/triage_runner.py", "web/triage_runner_bulk.py"} <= {r for r, _ in trees}
    assert sum(1 for _r, t in trees for _ in _error_sinks(t)) > 0, "pin scans nothing"
    bad = [f"{rel} {v}" for rel, t in trees for v in _violations(t)]
    assert bad == []


def test_sink_scrubbers_still_scrub():
    import inspect
    from email_triage.web import db as webdb
    assert "_scrub_err_persist(error_text)" in inspect.getsource(webdb.finish_triage_job)


_BAD = '''
async def f():
    try:
        pass
    except Exception as e:
        entry = {"message_id": 1, "status": "error", "error": fmt_exc(e)}
        entry["error"] = scrub_exc(e, purpose="triage")
        errors.append(f"search: {e}")
'''
_GOOD = '''
async def f():
    try:
        pass
    except Exception as e:
        entry = {"message_id": 1, "status": "error", "error": scrub_class_error_for_persist(e)}
        errors.append(scrub_error_for_persist(f"search: {e}"))
        errors.append(f"blocked ({cfg['backend']})")
        await db_call(finish_triage_job, c, j, status="failed", error_text=f"x {e}")
'''


def test_pin_has_teeth():
    from _pin_harness import parse_source
    assert_pin_has_teeth(_violations, _BAD, _GOOD)
    assert len(_violations(parse_source(_BAD))) == 3


# ---------------------------------------------------------------------------
# The persisted-error SSOT is a SUPERSET (lead ruling z5d): PHI shapes (the
# ones scrub_exc strips, imported not copied) + addresses + mailbox paths +
# secret tokens + cap. scrub_exc gains the token leg.
# ---------------------------------------------------------------------------

#: (input text, the sensitive substring that must not survive)
PHI_SHAPES = [
    ("SSN 123-45-6789 rejected", "123-45-6789"),
    ("member 123456789 rejected", "123456789"),
    ("call 555-123-4567 back", "555-123-4567"),
    ("dob 1980-01-02 mismatch", "1980-01-02"),
    ("dob 01/02/1980 mismatch", "01/02/1980"),
    ("MRN: A12345 not found", "A12345"),
    ("connect 10.1.2.3 refused", "10.1.2.3"),
    ("connect fe80:0:0:1 refused", "fe80:0:0:1"),
    ("rcpt alice@clinic.org refused", "alice@clinic.org"),
    ("[Errno 2] open '/var/mail/.INBOX.Smith-Labs/cur/1.eml'", "Smith-Labs"),
]
TOKEN_SHAPES = [
    (f"refresh failed access_token={SECRET}", SECRET),
    ("dev mode code=482913", "482913"),
    ("login password='hunter2-603'", "hunter2-603"),
    ('{"refresh_token": "rt-603-abc"}', "rt-603-abc"),
    ("Authorization=Bearer ya29.bearer603 next", "ya29.bearer603"),
]


@pytest.mark.parametrize("text, needle", PHI_SHAPES + TOKEN_SHAPES)
def test_persist_ssot_redacts_every_shape(text, needle):
    from email_triage._errfmt import scrub_class_error_for_persist, scrub_error_for_persist
    assert needle not in scrub_class_error_for_persist(RuntimeError(text))
    assert needle not in scrub_error_for_persist(text)


def test_persist_ssot_caps_long_input():
    from email_triage._errfmt import scrub_class_error_for_persist
    assert len(scrub_class_error_for_persist(RuntimeError("z" * 5000))) <= 500


@pytest.mark.parametrize("text, needle", PHI_SHAPES + TOKEN_SHAPES)
def test_persist_ssot_is_idempotent(text, needle):
    from email_triage._errfmt import scrub_error_for_persist
    once = scrub_error_for_persist(text)
    assert scrub_error_for_persist(once) == once


@pytest.mark.parametrize("text, needle", TOKEN_SHAPES + [
    ("[Errno 2] open '/var/mail/.INBOX.Smith-Labs/cur/1.eml'", "Smith-Labs"),
])
def test_scrub_exc_redacts_token_shapes(text, needle):
    from email_triage.web._flash import scrub_exc
    assert needle not in scrub_exc(RuntimeError(text), purpose="triage")


def test_flash_redirect_query_string_carries_no_token():
    from email_triage.web._flash import flash_redirect
    resp = flash_redirect("/triage", err=RuntimeError(f"refresh failed access_token={SECRET}"),
                          purpose="triage")
    loc = resp.headers["location"]
    assert SECRET not in loc and "REDACTED" in loc


def test_phi_shape_patterns_live_in_one_place():
    """scrub_exc and the persist SSOT share ONE PHI-shape funnel
    (``_errfmt.redact_phi_shapes``); neither carries its own copy."""
    import inspect
    from email_triage.web import _flash
    from email_triage import _errfmt
    src = inspect.getsource(_flash.scrub_exc)
    assert "redact_phi_shapes(" in src and r"\d{3}-\d{2}-\d{4}" not in src
    assert "redact_secret_tokens(" in src and "redact_paths(" in src
    persist = inspect.getsource(_errfmt.scrub_error_for_persist)
    assert "redact_phi_shapes(" in persist
    assert "scrub_error_for_persist(" in inspect.getsource(_errfmt.scrub_class_error_for_persist)
