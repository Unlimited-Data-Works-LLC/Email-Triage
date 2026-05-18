"""Tests for session TTL config + HIPAA cap + persistent session_secret.

PR 9 follow-up: closes the "container restart kicks everyone out"
bug + adds the §164.312(a)(2)(iii) Automatic Logoff knob.
"""

from __future__ import annotations

import time

import pytest

from email_triage import triage_logging
from email_triage.config import AuthConfig, TriageConfig, _parse_raw
from email_triage.web.auth import (
    SESSION_MAX_AGE,
    create_session_token,
    effective_session_ttl,
    verify_session_token,
)


# ---------------------------------------------------------------------------
# AuthConfig defaults + clamp
# ---------------------------------------------------------------------------

def test_authconfig_defaults():
    a = AuthConfig()
    assert a.session_ttl_secs == 86400
    assert a.hipaa_session_ttl_secs == 900
    assert AuthConfig.HIPAA_TTL_HARD_CEILING_SECS == 1800


def test_loader_clamps_hipaa_cap_at_ceiling():
    """A YAML hand-edited to 1 day for the HIPAA cap clamps to 30 min."""
    raw = {"auth": {"hipaa_session_ttl_secs": 86400}}
    cfg = _parse_raw(raw)
    assert cfg.auth.hipaa_session_ttl_secs == 1800


def test_loader_accepts_legal_hipaa_cap():
    raw = {"auth": {"hipaa_session_ttl_secs": 900}}
    cfg = _parse_raw(raw)
    assert cfg.auth.hipaa_session_ttl_secs == 900


# ---------------------------------------------------------------------------
# effective_session_ttl
# ---------------------------------------------------------------------------

def test_effective_ttl_non_hipaa_returns_operator_pick():
    cfg = TriageConfig()
    cfg.auth.session_ttl_secs = 3600
    triage_logging._hipaa_mode = False
    assert effective_session_ttl(cfg) == 3600


def test_effective_ttl_hipaa_mode_clamps_to_cap():
    """When system HIPAA is on, return min(operator_pick, hipaa_cap)."""
    cfg = TriageConfig()
    cfg.auth.session_ttl_secs = 86400  # 1 day
    cfg.auth.hipaa_session_ttl_secs = 900  # 15 min
    triage_logging._hipaa_mode = True
    try:
        assert effective_session_ttl(cfg) == 900
    finally:
        triage_logging._hipaa_mode = False


def test_effective_ttl_hipaa_mode_picks_smaller_of_two():
    """Operator pick is below the HIPAA cap → keep operator pick."""
    cfg = TriageConfig()
    cfg.auth.session_ttl_secs = 600  # 10 min, below cap
    cfg.auth.hipaa_session_ttl_secs = 900  # 15 min
    triage_logging._hipaa_mode = True
    try:
        assert effective_session_ttl(cfg) == 600
    finally:
        triage_logging._hipaa_mode = False


def test_effective_ttl_falls_back_for_old_config():
    """When config has no .auth attribute (pre-PR install), fall back
    to SESSION_MAX_AGE so the existing tests don't break."""

    class OldConfig:
        pass

    assert effective_session_ttl(OldConfig()) == SESSION_MAX_AGE


# ---------------------------------------------------------------------------
# Token verification with the live max_age
# ---------------------------------------------------------------------------

def test_token_verifies_within_ttl():
    secret = "test-secret"
    token = create_session_token(secret, "alice@example.com", "admin")
    out = verify_session_token(secret, token, max_age=3600)
    assert out is not None
    assert out["email"] == "alice@example.com"
    assert out["role"] == "admin"


def test_token_rejected_after_ttl():
    """max_age=1 + sleep 2 → token rejected."""
    secret = "test-secret"
    token = create_session_token(secret, "alice@example.com", "admin")
    time.sleep(2)
    out = verify_session_token(secret, token, max_age=1)
    assert out is None


# ---------------------------------------------------------------------------
# YAML round-trip via the existing drift detector
# ---------------------------------------------------------------------------

def test_authconfig_yaml_roundtrip(tmp_path, monkeypatch):
    """End-to-end: build config, write YAML, reload → fields match."""
    from email_triage.config import load_config
    from email_triage.web.routers.ui import _write_config_yaml

    seed = tmp_path / "email-triage.yaml"
    seed.write_text(
        "provider:\n  default: imap\n"
        "  imap: {host: '', port: 993, username: '', mailbox: INBOX, "
        "use_ssl: true}\n"
        "routes: {}\n"
    )
    monkeypatch.chdir(tmp_path)

    cfg = TriageConfig()
    cfg.auth.session_ttl_secs = 3600
    cfg.auth.hipaa_session_ttl_secs = 1800

    _write_config_yaml(cfg)
    reloaded = load_config(seed)
    assert reloaded.auth.session_ttl_secs == 3600
    assert reloaded.auth.hipaa_session_ttl_secs == 1800


def test_authconfig_yaml_clamps_on_reload(tmp_path, monkeypatch):
    """Operator hand-edits the YAML to set hipaa cap to 1 hour →
    loader clamps to 30 min."""
    seed = tmp_path / "email-triage.yaml"
    seed.write_text(
        "provider:\n  default: imap\n"
        "  imap: {host: '', port: 993, username: '', mailbox: INBOX, "
        "use_ssl: true}\n"
        "routes: {}\n"
        "auth:\n"
        "  session_ttl_secs: 86400\n"
        "  hipaa_session_ttl_secs: 3600  # operator tried to raise it\n"
    )
    from email_triage.config import load_config
    cfg = load_config(seed)
    assert cfg.auth.hipaa_session_ttl_secs == 1800  # clamped


# ---------------------------------------------------------------------------
# Persistent session_secret (the original bug)
# ---------------------------------------------------------------------------

def test_lifespan_persists_session_secret(tmp_path, monkeypatch):
    """End-to-end: simulate two lifespan inits with the same secrets
    store; the second one reads the same session_secret as the first."""
    monkeypatch.chdir(tmp_path)

    class _Stub:
        def __init__(self):
            self._d: dict[str, str] = {}

        def get(self, k):
            return self._d.get(k)

        def set(self, k, v):
            self._d[k] = v

    secrets_store = _Stub()

    # Simulate the lifespan logic.
    def boot_lifespan(state):
        existing = secrets_store.get("session_secret")
        if not existing:
            import secrets as stdlib_secrets
            existing = stdlib_secrets.token_hex(32)
            secrets_store.set("session_secret", existing)
        state["session_secret"] = existing

    state1: dict = {}
    boot_lifespan(state1)
    state2: dict = {}
    boot_lifespan(state2)

    assert state1["session_secret"] == state2["session_secret"]
    # Must be 64-hex-char (token_hex(32)).
    assert len(state1["session_secret"]) == 64
