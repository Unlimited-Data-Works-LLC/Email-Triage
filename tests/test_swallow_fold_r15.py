"""Silent-swallow class, panel r15 fold: behaviour tests for the findings.

One test (or pair) per folded finding. Each names the finding it pins. The
render half of the BAA finding lives in
``tests/test_web/test_swallow_fold_r15_baa_render.py`` (it needs the web
fixtures).
"""

from __future__ import annotations

import io
import sqlite3
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest


class _RecLog:
    """Stand-in for a TriageLogger: records (level, msg, kwargs)."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def _rec(self, level):
        def _f(msg, *a, **k):
            assert not a, "TriageLogger takes no positional args after msg"
            self.calls.append((level, msg, k))
        return _f

    def __getattr__(self, name):
        if name in ("debug", "info", "warning", "error", "critical"):
            return self._rec(name)
        raise AttributeError(name)

    def levels(self) -> list[str]:
        return [c[0] for c in self.calls]


# ---------------------------------------------------------------------------
# 1. MUST (DA): _write_config_yaml_locked must not rewrite an unreadable file
# ---------------------------------------------------------------------------

def test_write_config_yaml_refuses_when_existing_yaml_unreadable(tmp_path, monkeypatch):
    import yaml

    from email_triage.config import TriageConfig
    from email_triage.web.routers.ui._shared import _write_config_yaml_locked

    monkeypatch.chdir(tmp_path)
    target = tmp_path / "email-triage.yaml"
    bad = b"provider:\n  imap: {host: [unclosed\n"
    target.write_bytes(bad)

    with pytest.raises(yaml.YAMLError):
        _write_config_yaml_locked(TriageConfig())

    # The operator's file (and its provider section) is untouched.
    assert target.read_bytes() == bad


# ---------------------------------------------------------------------------
# 2. MUST (db) / FIX (hipaa): the overlap guard's ``except ValueError`` was dead
# ---------------------------------------------------------------------------

def test_path_overlap_ops_never_raise_across_drives():
    """The proof the deleted handler was dead: the three operations the guard
    runs do not raise on paths from different drives; they compare unequal."""
    a, b = PureWindowsPath("C:/srv/www"), PureWindowsPath("D:/certs")
    assert (a == b) is False
    assert (b in a.parents) is False
    assert (a in b.parents) is False


def test_webroot_overlap_guard_still_refuses_and_still_allows(tmp_path):
    from email_triage.config import ConfigError, load_config

    certs = tmp_path / "certs"
    certs.mkdir()

    def _cfg(webroot: Path) -> Path:
        f = tmp_path / "config.yaml"
        f.write_text(
            "tls:\n"
            f"  cert_dir: '{certs.as_posix()}'\n"
            "  acme:\n"
            "    enabled: true\n"
            "    challenge: http-01\n"
            "    http01:\n"
            "      mode: webroot\n"
            f"      webroot_path: '{webroot.as_posix()}'\n",
            encoding="utf-8",
        )
        return f

    with pytest.raises(ConfigError, match="overlaps a sensitive directory"):
        load_config(_cfg(certs / "acme"))
    cfg = load_config(_cfg(tmp_path / "webroot"))
    assert cfg.tls.acme.http01.mode == "webroot"


# ---------------------------------------------------------------------------
# 4. SHOULD: a chmod failure on the Tailscale key must not leave it readable
# ---------------------------------------------------------------------------

def test_tailscale_key_chmod_failure_with_open_mode_fails_closed(tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    import email_triage.tls as tls

    real_chmod = tls.os.chmod

    def fake_run(cmd, **kwargs):
        crt = Path(cmd[cmd.index("--cert-file") + 1])
        key = Path(cmd[cmd.index("--key-file") + 1])
        crt.write_bytes(b"cert")
        key.write_bytes(b"key")
        real_chmod(key, 0o644)  # group/world readable (Windows reports 0o666)
        return MagicMock(returncode=0, stdout="", stderr="")

    def failing_chmod(path, mode, *a, **k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr(tls.os, "chmod", failing_chmod)
    with pytest.raises(RuntimeError, match="group/world-accessible"):
        tls.fetch_tailscale_cert("h.example.ts.net", tmp_path / "certs")


# ---------------------------------------------------------------------------
# 5. SHOULD: a failed HIPAA access-event count is "unavailable", never 0
# ---------------------------------------------------------------------------

def test_hipaa_events_count_unavailable_not_zero(monkeypatch):
    from _db_tracking import track

    from email_triage.config import TriageConfig
    from email_triage.web import daily_health as dh
    from email_triage.web.db import init_db

    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: None)
    monkeypatch.setattr(dh, "is_hipaa_mode", lambda: False)
    db = track(init_db(":memory:"))
    db.execute("DROP TABLE hipaa_access_events")
    db.commit()

    cfg = TriageConfig()
    cfg.health_email.include_hipaa_events = True
    state = dh.gather_health_state(db, cfg)

    assert state["hipaa_events_count"] is None
    assert any("HIPAA access-event count unavailable" in r
               for r in state["attention_reasons"])
    assert dh.is_interesting(state) is True
    html, text = dh._render_html(state, cfg), dh._render_text(state, cfg)
    assert "Count last 24h: <strong>unavailable" in html
    assert "HIPAA access events:\n  Count last 24h: unavailable" in text


# ---------------------------------------------------------------------------
# 6. SHOULD: actor lookup failure -> ERROR + the /health audit-failure counter
# ---------------------------------------------------------------------------

# The bare :memory: DB has no access_log table, so the middleware's own
# access-log write fails on purpose. It lands inside this test on CI and lags
# past teardown locally; no count, so either timing is excused (CI 42424155221).
@pytest.mark.audit_failure_expected(
    match="access_log GET route=/classify/test status=200",
    reason="bare in-memory DB has no access_log table; the actor lookup is the subject",
)
def test_access_audit_actor_lookup_failure_is_error_and_counted(monkeypatch):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    import email_triage.web._audit as _audit
    import email_triage.web.access_audit as aa
    import email_triage.web.dependencies as deps

    async def phi(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/classify/test", phi)])
    app.add_middleware(aa.AccessAuditMiddleware)
    app.add_middleware(aa.RequestIdMiddleware)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    app.state.db = db

    def boom(request):
        raise RuntimeError("user table unreadable")

    rec = _RecLog()
    bumps: list[int] = []
    monkeypatch.setattr(deps, "get_current_user", boom)
    monkeypatch.setattr(aa, "_log", rec)
    monkeypatch.setattr(_audit, "_audit_failure_sink", lambda: bumps.append(1))

    try:
        with TestClient(app) as client:
            assert client.get("/classify/test").status_code == 200
    finally:
        db.close()

    actor = [c for c in rec.calls if "actor lookup failed" in c[1]]
    assert [c[0] for c in actor] == ["error"], rec.calls
    assert "exc_info" in actor[0][2]
    assert bumps, "the /health audit-failure counter was not bumped"


# ---------------------------------------------------------------------------
# 7. SHOULD: "plaintext pages may remain" is ERROR and names the path
# ---------------------------------------------------------------------------

def test_verify_sidecar_cleanup_failure_is_error_with_path(tmp_path, monkeypatch):
    import email_triage.backup as backup

    snap = tmp_path / "snap.db"
    c = sqlite3.connect(str(snap))
    c.execute("CREATE TABLE t (x)")
    c.commit()
    c.close()

    real_unlink = Path.unlink

    def unlink(self, *a, **k):
        if self.name.endswith(("-wal", "-shm")):
            raise PermissionError(13, "denied")
        return real_unlink(self, *a, **k)

    rec = _RecLog()
    monkeypatch.setattr(backup, "logger", rec)
    monkeypatch.setattr(Path, "unlink", unlink)
    assert backup._verify_snapshot_file(snap) == "ok"

    hits = [c for c in rec.calls if "plaintext pages may remain" in c[1]]
    assert hits and all(c[0] == "error" for c in hits), rec.calls
    assert all(str(snap) in c[1] for c in hits)


# ---------------------------------------------------------------------------
# 8. SHOULD: mark_triaged / prune_push_deliveries log the outer DB failure
# ---------------------------------------------------------------------------

def _patch_web_db_logger(monkeypatch) -> _RecLog:
    import email_triage.triage_logging as tl
    rec = _RecLog()
    monkeypatch.setattr(tl, "get_logger", lambda name=None: rec)
    return rec


def test_mark_triaged_failure_is_logged(monkeypatch):
    from email_triage.web.db import mark_triaged

    rec = _patch_web_db_logger(monkeypatch)
    conn = sqlite3.connect(":memory:")  # no triaged_messages table
    try:
        mark_triaged(conn, 7, "<m@x.invalid>")
    finally:
        conn.close()
    hits = [c for c in rec.calls if "mark_triaged failed" in c[1]]
    assert [c[0] for c in hits] == ["error"], rec.calls
    assert hits[0][2].get("account_id") == 7


def test_prune_push_deliveries_failure_is_logged(monkeypatch):
    from email_triage.web.db import prune_push_deliveries

    rec = _patch_web_db_logger(monkeypatch)
    conn = sqlite3.connect(":memory:")  # no push_deliveries table
    try:
        assert prune_push_deliveries(conn) == 0
    finally:
        conn.close()
    hits = [c for c in rec.calls if "push-delivery prune failed" in c[1]]
    assert [c[0] for c in hits] == ["error"], rec.calls


# ---------------------------------------------------------------------------
# 9. SHOULD: the provider-outcome ERROR line carries account_id
# ---------------------------------------------------------------------------

def test_record_provider_outcome_error_carries_account_id(monkeypatch):
    import email_triage.web.app as app_mod

    rec = _RecLog()
    monkeypatch.setattr(app_mod, "log", rec)

    def boom(*a, **k):
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(app_mod, "_maybe_mark_auth_stale", boom)
    app_mod.record_provider_outcome(None, {"id": 42}, RuntimeError("x"))
    hits = [c for c in rec.calls if "auth-state update failed" in c[1]]
    assert hits and hits[0][0] == "error"
    assert hits[0][2].get("account_id") == 42


# ---------------------------------------------------------------------------
# 10. SHOULD (DA): the audit-handler stderr report never carries the message
# ---------------------------------------------------------------------------

def test_report_handler_fault_withholds_exception_message(monkeypatch):
    from email_triage.triage_logging import _report_handler_fault

    buf = io.StringIO()
    monkeypatch.setattr(sys, "stderr", buf)
    # Message built apart from the raise line: the report writes source
    # lines of the frames (code), and this test must see only the message.
    msg = "row for jane.doe@hosp.invalid MRN 00482913 /var/mail/Smith/1.eml"
    try:
        raise sqlite3.OperationalError(msg)
    except sqlite3.OperationalError:
        _report_handler_fault("flush commit")
    out = buf.getvalue()
    assert "flush commit" in out and "OperationalError" in out
    for leaked in ("jane.doe", "hosp.invalid", "00482913", "Smith"):
        assert leaked not in out, out


def test_report_handler_fault_tolerates_closed_stderr(monkeypatch):
    from email_triage.triage_logging import _report_handler_fault

    buf = io.StringIO()
    buf.close()
    monkeypatch.setattr(sys, "stderr", buf)
    try:
        raise RuntimeError("x")
    except RuntimeError:
        _report_handler_fault("closed")  # must not raise
    monkeypatch.setattr(sys, "stderr", None)
    try:
        raise RuntimeError("x")
    except RuntimeError:
        _report_handler_fault("none")  # must not raise
