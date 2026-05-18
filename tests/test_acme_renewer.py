"""Tests for the ACME renewer module (#67).

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
    return init_db(str(tmp_path / "test.db"))


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
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
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
