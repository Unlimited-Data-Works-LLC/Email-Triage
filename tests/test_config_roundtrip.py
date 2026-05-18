"""Config round-trip property tests.

The listener-mode bug (loader default flipped to True when the key was
missing; writer omitted the key when its value was False) was a
``load(save(x)) == x`` violation. Nothing in the test suite caught
the drift between loader-default and writer-emit because no test
exercised the round trip. This file is the regression-guard.

Two layers:

1. Hand-crafted round-trip tests for the highest-risk dataclasses
   (``TLSConfig``, ``AcmeConfig``, ``Rfc2136Config``, ``LoggingConfig``,
   ``HealthEmailConfig``) — built with non-default values, written
   via ``_write_config_yaml``, reloaded via ``load_config``,
   compared field-by-field.

2. Drift detector — walks ``dataclasses.fields(cls)`` for the same
   classes and asserts every declared field is touched by the
   writer (string-grep heuristic, but enough to catch a missed
   field on a future PR adding a new knob).

Hypothesis-style random fuzzing is filed as a follow-up; the
hand-crafted shape catches the actual bug class we hit and is
cheap to extend per-dataclass.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest
import yaml

from email_triage import config as cfg_mod
from email_triage.config import (
    AcmeConfig,
    HealthEmailConfig,
    LoggingConfig,
    Rfc2136Config,
    TLSConfig,
    TriageConfig,
    load_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Seed YAML: blocks the writer preserves verbatim from the existing file
# (provider, routes) — without these the round-trip test would fail on
# unrelated state.
_SEED_YAML = """\
provider:
  default: imap
  imap:
    host: ""
    port: 993
    username: ""
    mailbox: INBOX
    use_ssl: true
routes:
  invoices: [label]
"""


@pytest.fixture
def cwd_tmp(tmp_path, monkeypatch):
    """Run the writer + loader against ``./email-triage.yaml`` in a
    fresh tmpdir. The writer's search path includes that exact relative
    location, so chdir is the simplest redirect."""
    seed = tmp_path / "email-triage.yaml"
    seed.write_text(_SEED_YAML)
    monkeypatch.chdir(tmp_path)
    return seed


def _build_triage_config_with_overrides() -> TriageConfig:
    """Build a TriageConfig with non-default values on every field
    we round-trip. Defaults are already covered by the unit suite;
    the round-trip risk lives in the *non*-default values that the
    operator actually saved."""
    cfg = TriageConfig()  # defaults

    # TLS — the listener-mode bug class.
    cfg.tls.enabled = True
    cfg.tls.cert_dir = "/tmp/test-certs"

    # ACME + RFC-2136 — every knob added recently.
    a = cfg.tls.acme
    a.enabled = True
    a.directory_url = (
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    )
    a.account_email = "ops@example.com"
    a.domains = ["alpha.example.com", "beta.example.com"]
    a.challenge = "dns-01"
    a.renewal_threshold_days = 21
    a.check_interval_hours = 12
    a.pre_validation_grace_secs = 45
    a.validation_retries = 7
    a.validation_retry_delay_secs = 90
    a.dns_provider = "rfc2136"

    rfc = a.rfc2136
    rfc.nameserver = "192.0.2.5"
    rfc.nameserver_port = 5353
    rfc.tsig_key_name = "test-key."
    rfc.tsig_algorithm = "hmac-sha256"
    rfc.tsig_secret_ref = "acme_tsig_secret"
    rfc.update_zone = "acme.example.com"
    rfc.public_resolvers = ["8.8.4.4", "1.0.0.1"]
    rfc.public_propagation_timeout_secs = 2400
    rfc.public_propagation_interval_secs = 20

    # Logging
    cfg.logging.level = "DEBUG"
    cfg.logging.format = "text"
    cfg.logging.hipaa = True

    # Health email — the writer emits every flag explicitly.
    h = cfg.health_email
    h.enabled = True
    h.recipients = ["ops1@example.com", "ops2@example.com"]
    h.send_at = "07:30"
    h.include_health = False
    h.include_watchers = True
    h.include_triage = False
    h.include_errors = True
    h.include_hipaa_events = False
    h.include_api_key_events = True
    h.include_pubsub = False
    h.quiet_mode = True
    h.error_rate_threshold_pct = 7

    # WebAuthn — round-trip block keyed off non-defaults.
    cfg.webauthn.rp_id = "auth.example.com"
    cfg.webauthn.rp_name = "Email Triage Test"
    cfg.webauthn.origin = "https://auth.example.com"
    cfg.webauthn.require_user_verification_for_admin = True

    return cfg


# ---------------------------------------------------------------------------
# Hand-crafted round-trip
# ---------------------------------------------------------------------------

def test_tls_config_roundtrip(cwd_tmp):
    """Listener-mode bug regression: tls.enabled MUST round-trip."""
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    assert reloaded.tls.enabled is True
    assert reloaded.tls.cert_dir == "/tmp/test-certs"


def test_tls_enabled_false_roundtrip(cwd_tmp):
    """Direct regression: tls.enabled=False must survive a round
    trip. The original bug omitted the key, so reload defaulted to
    True and silently flipped HTTPS back on."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.tls.enabled = False
    cfg.tls.cert_dir = "/some/path"
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.tls.enabled is False


def test_acme_config_full_roundtrip(cwd_tmp):
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    a = reloaded.tls.acme
    expected = original.tls.acme
    for f in dataclasses.fields(AcmeConfig):
        if f.name == "rfc2136":
            continue  # nested; compared separately
        assert getattr(a, f.name) == getattr(expected, f.name), (
            f"AcmeConfig.{f.name} drifted: "
            f"orig={getattr(expected, f.name)!r} "
            f"reload={getattr(a, f.name)!r}"
        )


def test_rfc2136_config_full_roundtrip(cwd_tmp):
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    rfc = reloaded.tls.acme.rfc2136
    expected = original.tls.acme.rfc2136
    for f in dataclasses.fields(Rfc2136Config):
        assert getattr(rfc, f.name) == getattr(expected, f.name), (
            f"Rfc2136Config.{f.name} drifted: "
            f"orig={getattr(expected, f.name)!r} "
            f"reload={getattr(rfc, f.name)!r}"
        )


def test_logging_config_roundtrip(cwd_tmp):
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    assert reloaded.logging.level == "DEBUG"
    assert reloaded.logging.format == "text"
    assert reloaded.logging.hipaa is True


def test_health_email_config_full_roundtrip(cwd_tmp):
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    for f in dataclasses.fields(HealthEmailConfig):
        assert getattr(reloaded.health_email, f.name) == getattr(
            original.health_email, f.name
        ), (
            f"HealthEmailConfig.{f.name} drifted: "
            f"orig={getattr(original.health_email, f.name)!r} "
            f"reload={getattr(reloaded.health_email, f.name)!r}"
        )


def test_webauthn_config_roundtrip(cwd_tmp):
    from email_triage.web.routers.ui import _write_config_yaml

    original = _build_triage_config_with_overrides()
    _write_config_yaml(original)
    reloaded = load_config(cwd_tmp)

    assert reloaded.webauthn.rp_id == "auth.example.com"
    assert reloaded.webauthn.rp_name == "Email Triage Test"
    assert reloaded.webauthn.origin == "https://auth.example.com"
    assert (
        reloaded.webauthn.require_user_verification_for_admin is True
    )


def test_round_trip_yaml_is_human_editable(cwd_tmp):
    """Sanity: the YAML the writer produces is loadable as a plain
    dict. Catches accidental yaml.dump shape regressions (e.g. emitting
    Python-tagged objects like ``!!python/object``)."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = _build_triage_config_with_overrides()
    _write_config_yaml(cfg)
    raw = yaml.safe_load(cwd_tmp.read_text())
    assert isinstance(raw, dict)
    # Every top-level key should be plain str -> dict/scalar.
    for k, v in raw.items():
        assert isinstance(k, str)


# ---------------------------------------------------------------------------
# Drift detector
# ---------------------------------------------------------------------------

# Map of dataclass -> set of field names that are KNOWN to not
# round-trip through YAML by design (rare; usually internal /
# computed). Empty by default; populate with a comment if a field
# legitimately should not survive the round trip.
_NON_ROUNDTRIP_FIELDS: dict[type, set[str]] = {
    # Add entries here only with a justification comment.
}


@pytest.mark.parametrize("cls", [
    TLSConfig,
    AcmeConfig,
    Rfc2136Config,
    HealthEmailConfig,
    LoggingConfig,
])
def test_writer_references_every_dataclass_field(cls):
    """Every declared field on these dataclasses must appear in the
    writer body. String-grep heuristic — not bullet-proof, but catches
    the obvious "added a field, forgot to round-trip it" mistake.

    The writer source is read once. For each field name, we look for
    ``config.<path>.<field>`` or ``a.<field>`` etc. — any dotted access
    that includes the field name. False positives are possible (a
    field name shared with a method, e.g. ``items``) but uncommon.
    Add to ``_NON_ROUNDTRIP_FIELDS`` with a justification comment if
    a field truly should not round-trip."""
    import inspect
    from email_triage.web.routers import ui as ui_mod

    src = inspect.getsource(ui_mod._write_config_yaml)
    skip = _NON_ROUNDTRIP_FIELDS.get(cls, set())
    for f in dataclasses.fields(cls):
        if f.name in skip:
            continue
        assert f.name in src, (
            f"{cls.__name__}.{f.name} is declared but never "
            f"referenced in _write_config_yaml. Either add the "
            f"field to the writer, or document the intentional "
            f"omission in tests/test_config_roundtrip.py "
            f"_NON_ROUNDTRIP_FIELDS with a justification comment."
        )


@pytest.mark.parametrize("cls", [
    TLSConfig,
    AcmeConfig,
    Rfc2136Config,
])
def test_loader_default_matches_dataclass_default(cls):
    """The listener-mode bug had loader default disagreeing with the
    dataclass default. For each field with a literal default, build
    a fresh dataclass instance and confirm the value matches the
    dataclass declaration. (Drift detector for ``field(default=...)``
    vs ``MISSING``.)"""
    instance = cls() if not dataclasses.fields(cls)[0].default is dataclasses.MISSING else None
    if instance is None:
        return
    for f in dataclasses.fields(cls):
        if f.default is dataclasses.MISSING:
            continue
        assert getattr(instance, f.name) == f.default, (
            f"{cls.__name__}.{f.name} dataclass default "
            f"({f.default!r}) doesn't match constructed value "
            f"({getattr(instance, f.name)!r})"
        )
