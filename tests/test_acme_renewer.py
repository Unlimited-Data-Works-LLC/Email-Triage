"""Tests for the ACME renewer module.

Network-side ACME flow + DNS-01 publish are mocked — the unit tests
cover the pure-Python orchestration (config validation, cert
expiry detection, atomic write, renewal-log row, test-step
shape, mtime hot-reload signaling).

The full end-to-end flow against LE staging is covered manually
via /admin/acme-status -> "Issue from STAGING directory".
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from email_triage.config import AcmeConfig, Rfc2136Config
from email_triage.web.acme_renewer import (
    AcmeRenewer,
    Rfc2136Publisher,
    TestRunResult,
    TestStepResult,
)
from email_triage.web.db import init_db
from email_triage.web.db_auth_helpers import (
    insert_acme_renewal_log,
    list_acme_renewal_log,
)
from email_triage.tls import cert_mtime, generate_self_signed_cert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    from _db_tracking import track
    return track(init_db(str(tmp_path / "test.db")))


class _MemSecrets:
    """In-memory secrets-store stub matching the ``.get`` / ``.set``
    interface the renewer uses."""
    def __init__(self):
        self._data: dict[str, str] = {}

    def get(self, key: str):
        return self._data.get(key)

    def set(self, key: str, value: str):
        self._data[key] = value


@pytest.fixture
def secrets():
    return _MemSecrets()


@pytest.fixture
def cfg():
    rfc = Rfc2136Config(
        nameserver="192.0.2.1",
        tsig_key_name="probe.",
        tsig_secret_ref="acme_tsig_secret",
        update_zone="auth.example.com",
    )
    return AcmeConfig(
        enabled=True,
        directory_url="https://acme-staging-v02.api.letsencrypt.invalid/directory",
        account_email="ops@example.com",
        domains=["triage.example.com"],
        challenge="dns-01",
        renewal_threshold_days=30,
        rfc2136=rfc,
    )


@pytest.fixture
def renewer(cfg, secrets, db, tmp_path):
    return AcmeRenewer(
        cfg=cfg,
        cert_dir=str(tmp_path / "certs"),
        secrets_store=secrets,
        db=db,
    )


# ---------------------------------------------------------------------------
# Account key
# ---------------------------------------------------------------------------

class TestAccountKey:
    def test_generated_on_first_call(self, renewer, secrets):
        pem = renewer.ensure_account_key()
        assert pem.startswith(b"-----BEGIN")
        assert secrets.get("acme_account_key") is not None

    def test_persists_across_calls(self, renewer):
        pem1 = renewer.ensure_account_key()
        pem2 = renewer.ensure_account_key()
        # Same byte string returned the second time (no regeneration).
        assert pem1 == pem2


# ---------------------------------------------------------------------------
# Cert metadata + expiry
# ---------------------------------------------------------------------------

class TestCertMetadata:
    def test_no_cert_returns_present_false(self, renewer):
        meta = renewer.cert_metadata()
        assert meta["present"] is False

    def test_needs_renewal_when_cert_missing(self, renewer):
        assert renewer.needs_renewal() is True

    def test_metadata_after_self_signed_write(self, renewer):
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=10,
        )
        renewer._atomic_write_cert(cert_pem, key_pem)
        meta = renewer.cert_metadata()
        assert meta["present"] is True
        assert meta["subject_cn"] == "triage.example.com"
        assert "triage.example.com" in meta["sans"]
        assert meta["days_remaining"] >= 9

    def test_parse_failure_surfaces_the_scrubbed_text_not_the_parser_message(self, renewer):
        """Punch 426: the dict feeds acme_status.html and /health/detail; the parser text
        (here a planted address in the PEM body) stays on the log side."""
        crt, _ = renewer.cert_paths()
        crt.parent.mkdir(parents=True, exist_ok=True)
        crt.write_bytes(b"-----BEGIN CERTIFICATE-----\npatient.smith@example.invalid\n"
                        b"-----END CERTIFICATE-----\n")
        meta = renewer.cert_metadata()
        assert meta["present"] is True and meta["valid"] is False
        assert meta["parse_error"] == "config operation failed"
        assert "smith" not in repr(meta) and "PEM" not in repr(meta)

    def test_health_block_carries_the_scrubbed_parse_error(self, renewer, monkeypatch):
        from email_triage.web import acme_renewer as mod
        crt, _ = renewer.cert_paths()
        crt.parent.mkdir(parents=True, exist_ok=True)
        crt.write_bytes(b"not a certificate: /srv/triage/secret-path token=abc123")
        monkeypatch.setattr(mod, "_build_renewer_from_app", lambda app: renewer)
        block = mod.read_tls_cert_health(object())
        assert block["present"] is True and block["error"] == "config operation failed"

    def test_health_block_scrubs_a_failure_to_even_build_the_renewer(self, monkeypatch):
        from email_triage.web import acme_renewer as mod

        def boom(app):
            raise RuntimeError("read /srv/triage/data/keyfile failed for jane@example.invalid")

        monkeypatch.setattr(mod, "_build_renewer_from_app", boom)
        block = mod.read_tls_cert_health(object())
        assert block["present"] is False and block["error"] == "config operation failed"
        assert "jane" not in repr(block) and "keyfile" not in repr(block)

    def test_needs_renewal_within_threshold(self, renewer):
        # Write a cert valid for 5 days. Threshold is 30 days, so it
        # should signal needs renewal.
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=5,
        )
        renewer._atomic_write_cert(cert_pem, key_pem)
        assert renewer.needs_renewal() is True

    def test_no_renewal_when_fresh(self, renewer):
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=300,
        )
        renewer._atomic_write_cert(cert_pem, key_pem)
        assert renewer.needs_renewal() is False


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_writes_both_files(self, renewer):
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=30,
        )
        renewer._atomic_write_cert(cert_pem, key_pem)
        crt, key = renewer.cert_paths()
        assert crt.read_bytes() == cert_pem
        assert key.read_bytes() == key_pem

    def test_overwrite_replaces_atomically(self, renewer):
        cert_pem_a, key_pem_a = generate_self_signed_cert(
            "triage.example.com", valid_days=10,
        )
        renewer._atomic_write_cert(cert_pem_a, key_pem_a)
        crt, _ = renewer.cert_paths()
        mtime_before = cert_mtime(crt)
        # Sleep to guarantee mtime resolution.
        import time
        time.sleep(0.05)
        cert_pem_b, key_pem_b = generate_self_signed_cert(
            "triage.example.com", valid_days=20,
        )
        renewer._atomic_write_cert(cert_pem_b, key_pem_b)
        mtime_after = cert_mtime(crt)
        assert mtime_after is not None
        assert mtime_before is not None
        assert mtime_after >= mtime_before


# ---------------------------------------------------------------------------
# check_and_renew skip paths (no network)
# ---------------------------------------------------------------------------

class TestCheckAndRenew:
    def test_skipped_when_disabled(self, cfg, secrets, db, tmp_path):
        cfg.enabled = False
        r = AcmeRenewer(
            cfg=cfg, cert_dir=str(tmp_path / "certs"),
            secrets_store=secrets, db=db,
        )
        result = r.check_and_renew()
        assert result == {"skipped": "acme.enabled=false"}

    def test_skipped_when_no_domains(self, cfg, secrets, db, tmp_path):
        cfg.domains = []
        r = AcmeRenewer(
            cfg=cfg, cert_dir=str(tmp_path / "certs"),
            secrets_store=secrets, db=db,
        )
        result = r.check_and_renew()
        assert result == {"skipped": "acme.domains empty"}

    def test_fresh_cert_skipped_with_log_row(self, renewer, db):
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=300,
        )
        renewer._atomic_write_cert(cert_pem, key_pem)
        result = renewer.check_and_renew()
        assert result["action"] == "skipped"
        rows = list_acme_renewal_log(db)
        assert any(r["outcome"] == "skipped_fresh" for r in rows)


# ---------------------------------------------------------------------------
# Renewal log
# ---------------------------------------------------------------------------

class TestRenewalLog:
    def test_insert_and_list(self, db):
        insert_acme_renewal_log(
            db, domain="triage.example.com", outcome="renewed",
            not_after="2099-01-01T00:00:00+00:00",
        )
        insert_acme_renewal_log(
            db, domain="triage.example.com", outcome="failed",
            error="fake error",
        )
        rows = list_acme_renewal_log(db, limit=10)
        assert len(rows) == 2
        assert rows[0]["outcome"] == "failed"  # newest first
        assert rows[1]["outcome"] == "renewed"


# ---------------------------------------------------------------------------
# Test-button result shape
# ---------------------------------------------------------------------------

class TestStepResultShape:
    def test_step_result_to_dict(self):
        s = TestStepResult("X", True, 100, detail="ok")
        run = TestRunResult(
            overall_ok=True, steps=[s],
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
        )
        d = run.to_dict()
        assert d["overall_ok"] is True
        assert d["steps"][0]["name"] == "X"
        assert d["steps"][0]["elapsed_ms"] == 100


# ---------------------------------------------------------------------------
# Rfc2136Publisher config validation
# ---------------------------------------------------------------------------

class TestPublisherValidation:
    def test_missing_nameserver_raises(self):
        rfc = Rfc2136Config(
            nameserver="", tsig_key_name="k", tsig_secret_ref="s",
        )
        with pytest.raises(ValueError, match="nameserver"):
            Rfc2136Publisher(rfc, "tsig-secret")

    def test_missing_tsig_key_name_raises(self):
        rfc = Rfc2136Config(
            nameserver="1.2.3.4", tsig_key_name="", tsig_secret_ref="s",
        )
        with pytest.raises(ValueError, match="tsig_key_name"):
            Rfc2136Publisher(rfc, "tsig-secret")

    def test_missing_tsig_secret_raises(self):
        rfc = Rfc2136Config(
            nameserver="1.2.3.4", tsig_key_name="k", tsig_secret_ref="s",
        )
        with pytest.raises(ValueError, match="acme_tsig_secret"):
            Rfc2136Publisher(rfc, "")


# ---------------------------------------------------------------------------
#  — supervised cert-renewer + tls_cert health block
# ---------------------------------------------------------------------------

from types import SimpleNamespace  # noqa: E402

from email_triage.config import TLSConfig, PersistenceConfig  # noqa: E402
from email_triage.web.acme_renewer import (  # noqa: E402
    _build_renewer_from_app,
    _resume_pending_acme_jobs,
    read_tls_cert_health,
)


def _fake_app(cfg, secrets, db, tmp_path, *, cert_dir=None):
    """Minimal app-state stand-in for the supervised-renewer helpers."""
    tls = TLSConfig(
        cert_dir=str(cert_dir) if cert_dir else "",
        acme=cfg,
    )
    persistence = PersistenceConfig(db_path=str(tmp_path / "test.db"))
    config = SimpleNamespace(
        tls=tls, persistence=persistence, smtp=None,
    )
    return SimpleNamespace(
        state=SimpleNamespace(config=config, secrets=secrets, db=db),
    )


class TestBuildRenewerFromApp:
    def test_uses_explicit_cert_dir(self, cfg, secrets, db, tmp_path):
        cd = tmp_path / "explicit_certs"
        app = _fake_app(cfg, secrets, db, tmp_path, cert_dir=cd)
        r = _build_renewer_from_app(app)
        assert isinstance(r, AcmeRenewer)
        assert r.cert_dir == cd

    def test_falls_back_to_data_dir_certs(self, cfg, secrets, db, tmp_path):
        app = _fake_app(cfg, secrets, db, tmp_path)
        r = _build_renewer_from_app(app)
        # No explicit cert_dir → <db_path parent>/certs.
        assert r.cert_dir == tmp_path / "certs"


class TestReadTlsCertHealth:
    def test_absent_cert_reports_not_present(
        self, cfg, secrets, db, tmp_path,
    ):
        app = _fake_app(cfg, secrets, db, tmp_path)
        block = read_tls_cert_health(app)
        assert block["present"] is False
        assert block["not_after"] is None
        assert block["days_remaining"] is None

    def test_present_cert_reports_expiry(
        self, cfg, secrets, db, tmp_path,
    ):
        cd = tmp_path / "certs"
        cd.mkdir(parents=True, exist_ok=True)
        cert_pem, key_pem = generate_self_signed_cert(
            "triage.example.com", valid_days=42,
        )
        (cd / "server.crt").write_bytes(cert_pem)
        (cd / "server.key").write_bytes(key_pem)
        app = _fake_app(cfg, secrets, db, tmp_path, cert_dir=cd)
        block = read_tls_cert_health(app)
        assert block["present"] is True
        assert block["not_after"] is not None
        # 42-day cert — days_remaining lands in [40, 42] allowing for
        # the boundary-day truncation.
        assert 40 <= block["days_remaining"] <= 42

    def test_never_raises_on_bad_config(self, secrets, db):
        # A wholly broken app object must degrade, not raise.
        broken = SimpleNamespace(state=SimpleNamespace())
        block = read_tls_cert_health(broken)
        assert block["present"] is False
        assert "error" in block


@pytest.mark.asyncio
class TestResumePendingAcmeJobs:
    async def test_no_rows_returns_zero(self, cfg, secrets, db, tmp_path):
        app = _fake_app(cfg, secrets, db, tmp_path)
        renewer = _build_renewer_from_app(app)
        from email_triage.web import acme_job_state
        acme_job_state.set_db_handle(db)
        try:
            resolved = await _resume_pending_acme_jobs(app, renewer)
        finally:
            acme_job_state.set_db_handle(None)
        assert resolved == 0

    async def test_consumes_resume_pending_row(
        self, cfg, secrets, db, tmp_path,
    ):
        """A 'resume_pending'-stamped acme_jobs row is closed terminally
        by the resume worker."""
        from email_triage.web import acme_job_state
        app = _fake_app(cfg, secrets, db, tmp_path)
        renewer = _build_renewer_from_app(app)
        acme_job_state.set_db_handle(db)
        try:
            # Start a job + drive it to a non-terminal phase, persist an
            # order_url, then stamp it resume_pending the way
            # resume_on_startup does for a recent interrupted order.
            job_id = acme_job_state.start(
                domains=["triage.example.com"],
                directory_url=cfg.directory_url,
                max_attempts=3,
            )
            acme_job_state.transition(
                "publishing", order_url="https://le.invalid/order/abc",
            )
            resolved_startup = acme_job_state.resume_on_startup()
            assert any(
                r.get("_verdict") == "resume_pending"
                for r in resolved_startup
            )
            # Resume worker consumes it.
            count = await _resume_pending_acme_jobs(app, renewer)
            assert count == 1
            row = acme_job_state.get_persisted_row(job_id)
            assert row["phase"] in ("failed", "cancelled")
            assert row["last_error_kind"] == "resume_abandoned"
        finally:
            acme_job_state.set_db_handle(None)
            acme_job_state.reset()



# ---------------------------------------------------------------------------
# N-550 (539 fold, round 5): the scheduled renewal's FAIL-SOFT system-actor witness
# ---------------------------------------------------------------------------

def _renewal_rows(db):
    return db.execute(
        "SELECT user_id, outcome, detail FROM auth_events WHERE event_type = ?",
        (AcmeRenewer.RENEWAL_EVENT_TYPE,),
    ).fetchall()


def _write_self_signed(renewer):
    from email_triage.tls import generate_self_signed_cert, write_cert_files

    cert_pem, key_pem = generate_self_signed_cert("triage.example.com")
    crt, _key = renewer.cert_paths()
    write_cert_files(Path(crt).parent, cert_pem, key_pem)


class TestScheduledRenewalWitness:
    def test_success_writes_a_system_actor_row_with_the_cert_identity(
        self, renewer, db, monkeypatch,
    ):
        monkeypatch.setattr(renewer, "needs_renewal", lambda: True)

        def fake_issue(**_kw):
            _write_self_signed(renewer)
            return {"not_after": "x"}

        monkeypatch.setattr(renewer, "issue_now", fake_issue)
        assert renewer.check_and_renew()["action"] == "renewed"
        rows = _renewal_rows(db)
        assert len(rows) == 1, rows
        user_id, outcome, detail = rows[0][0], rows[0][1], rows[0][2]
        assert user_id is None and outcome == "success"
        assert "serial=" in detail and "sha256=" in detail and "job_id=" in detail
        assert len(detail.split("sha256=")[1].split()[0]) == 64

    def test_failure_writes_a_failure_row_and_still_raises(
        self, renewer, db, monkeypatch,
    ):
        monkeypatch.setattr(renewer, "needs_renewal", lambda: True)

        def boom(**_kw):
            raise RuntimeError("acme down")

        monkeypatch.setattr(renewer, "issue_now", boom)
        with pytest.raises(RuntimeError):
            renewer.check_and_renew()
        rows = _renewal_rows(db)
        assert [(r[0], r[1]) for r in rows] == [(None, "failure")]
        assert "error=RuntimeError" in rows[0][2]

    @pytest.mark.audit_failure_expected(
        match='acme_cert_renewed:success',
        count=1,
    )
    def test_a_witness_miss_does_not_stop_the_renewal(
        self, renewer, db, monkeypatch,
    ):
        """FAIL-SOFT by design: the emitter raises, the renewal still reports
        renewed, and the miss goes through safe_audit_write (logged + counted)."""
        from email_triage.web import _audit
        from email_triage.web import db as web_db

        monkeypatch.setattr(renewer, "needs_renewal", lambda: True)
        monkeypatch.setattr(renewer, "issue_now", lambda **_kw: (_write_self_signed(renewer), {})[1])

        def failing_emit(*_a, **_kw):
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(web_db, "record_auth_event", failing_emit)
        bumps: list[int] = []
        monkeypatch.setattr(_audit, "_bump_failure_counter", lambda: bumps.append(1))
        assert renewer.check_and_renew()["action"] == "renewed"
        assert bumps == [1], "the miss must be counted for /health"


def _witness_arms(fn) -> dict[str, int]:
    """Witness calls per arm of the renewal ``try``: the success arm (``else``)
    and each ``except Exception`` handler (the failure arm)."""
    import ast
    import inspect
    import textwrap

    names = ("_witness_scheduled_renewal", "_witness_scheduled_renewal_async")

    def count(nodes) -> int:
        return sum(
            1 for node in nodes for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in names
        )

    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    tries = [n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.orelse]
    assert len(tries) == 1, "expected one try/except/else around the issuance"
    t = tries[0]
    failure = [h for h in t.handlers
               if isinstance(h.type, ast.Name) and h.type.id == "Exception"]
    assert len(failure) == 1
    return {"success": count(t.orelse), "failure": count(failure[0].body),
            "in_try_body": count(t.body)}


def test_both_renewal_entrypoints_reach_the_emitter():
    """Structural pin, per ARM (devils-advocate round 5): each entrypoint has a
    witness on the success arm (``else``, so a witness can never be reported as
    a failed renewal) and on the ``except Exception`` failure arm, and none
    inside the ``try`` body."""
    import inspect

    for fn in (AcmeRenewer.check_and_renew, AcmeRenewer.check_and_renew_async):
        assert _witness_arms(fn) == {"success": 1, "failure": 1, "in_try_body": 0}, fn
    # the witnesses reach the emitter SSOT, not a raw INSERT
    for fn in (AcmeRenewer._witness_scheduled_renewal, AcmeRenewer._witness_scheduled_renewal_async):
        src = inspect.getsource(fn)
        assert "record_auth_event" in src and "safe_audit_write" in src


def test_the_arm_pin_has_teeth():
    """Moving the success witness INTO the try body, or dropping the failure
    witness, changes the per-arm counts the pin asserts."""
    import ast
    import inspect
    import textwrap

    src = textwrap.dedent(inspect.getsource(AcmeRenewer.check_and_renew))
    no_failure = src.replace(
        'self._witness_scheduled_renewal(outcome="failure", error=type(e).__name__)', "pass", 1,
    )
    assert no_failure != src
    tree = ast.parse(no_failure)
    t = next(n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.orelse)
    h = next(h for h in t.handlers if isinstance(h.type, ast.Name) and h.type.id == "Exception")
    assert not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "_witness_scheduled_renewal"
        for node in h.body for n in ast.walk(node)
    )


@pytest.mark.asyncio
async def test_the_async_entrypoint_writes_the_witness(renewer, db, monkeypatch):
    """devils-advocate round 5: ``renewal_loop`` drives check_and_renew_async,
    so the production path is exercised too (db_call forwarding + async SSOT)."""
    monkeypatch.setattr(renewer, "needs_renewal", lambda: True)

    async def fake_issue_async(**_kw):
        _write_self_signed(renewer)
        return {}

    monkeypatch.setattr(renewer, "issue_now_async", fake_issue_async)
    result = await renewer.check_and_renew_async()
    assert result["action"] == "renewed"
    rows = _renewal_rows(db)
    assert [(r[0], r[1]) for r in rows] == [(None, "success")]
    assert "sha256=" in rows[0][2]
