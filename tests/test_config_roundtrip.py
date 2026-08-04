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
    AuthConfig,
    GoogleOAuthConfig,
    HealthEmailConfig,
    IngestionConfig,
    LoggingConfig,
    Office365OAuthConfig,
    ProviderConfig,
    Rfc2136Config,
    RouteConfig,
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


def test_classifier_embedding_skip_roundtrip(cwd_tmp):
    """D-A1 (2am audit 2026-06-07): the / classifier knobs must
    survive _write_config_yaml -> load_config. The classifier block is a
    FULL REBUILD, so a field the writer doesn't emit is silently dropped
    and reverts to its default on reload — which re-breaks the 
    embedding-skip for an operator who extended embedding_name_markers
    (e.g. to cover bge/gte/e5), and drops the  backup_models failover
    list. Same drift class as the TLS listener-mode bug this file guards."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    c = cfg.classifier
    c.prefer_loaded = False
    c.prefer_loaded_skip_embeddings = False
    c.embedding_name_markers = ["embed", "bge", "gte", "e5"]
    c.backup_models = ["qwen3.6:8b", "qwen3.6:4b"]
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.classifier.prefer_loaded is False
    assert reloaded.classifier.prefer_loaded_skip_embeddings is False
    assert reloaded.classifier.embedding_name_markers == [
        "embed", "bge", "gte", "e5",
    ]
    assert reloaded.classifier.backup_models == ["qwen3.6:8b", "qwen3.6:4b"]


def test_classifier_embedding_skip_defaults_roundtrip(cwd_tmp):
    """The default (True / ['embed']) must also survive — i.e. the
    conditional-emit must not corrupt the default-reload path."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()  # defaults: prefer_loaded* True, markers ['embed']
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.classifier.prefer_loaded is True
    assert reloaded.classifier.prefer_loaded_skip_embeddings is True
    assert reloaded.classifier.embedding_name_markers == ["embed"]


def test_classifier_num_ctx_roundtrip(cwd_tmp):
    """ — a pinned ``num_ctx`` must survive _write_config_yaml -> load_config.
    The classifier block is a FULL REBUILD (D-A1), so a writer that doesn't emit
    num_ctx silently drops the operator's pinned context window on every Save —
    the same drift class as the  backup_models trap above."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.classifier.num_ctx = 98304
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)
    assert reloaded.classifier.num_ctx == 98304


def test_classifier_num_ctx_default_none_roundtrip(cwd_tmp):
    """The default (None = inherit) must also survive — the conditional-emit
    must not write a spurious num_ctx that flips inherit into a pinned value."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()  # num_ctx default None
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)
    assert reloaded.classifier.num_ctx is None


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
# #8-FULL (census 2026-06-10) — round-trip proofs for the serializer gaps
# the db-sme enumeration surfaced. The writer (`_write_config_yaml_locked`)
# is a FULL REBUILD (`data = {}`): any field the loader reads but the writer
# never emits is silently DROPPED on Save and reverts to its dataclass
# default on the next reload. These are real data-loss defects, not just a
# pin gap. Each test below was RED before the writer fix landed and is the
# behavioural regression proof per style-guide R4 (prove the gap is real).
# ---------------------------------------------------------------------------

def test_persistence_encryption_enabled_roundtrip(cwd_tmp):
    """HIGHEST severity: ``persistence.encryption_enabled`` is the
    §164.312(a)(2)(iv) SQLCipher encryption-at-rest gate. The writer emitted
    only ``db_path``, so an admin Save of ANY unrelated setting silently
    dropped an operator's ``encryption_enabled: true`` from YAML — next boot
    reverts to plaintext (or fails closed in HIPAA mode with the env
    override). Must round-trip."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.persistence.db_path = "/tmp/enc-triage.db"
    cfg.persistence.encryption_enabled = True
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.persistence.encryption_enabled is True
    assert reloaded.persistence.db_path == "/tmp/enc-triage.db"


def test_webhooks_roundtrip(cwd_tmp):
    """``webhooks`` (operator-configured outbound targets) were never
    written — an admin Save WIPED the configured webhook list. The
    ``secret_key`` is a key-NAME reference (not the secret value), so it
    is safe to YAML and must round-trip too."""
    from email_triage.config import WebhookTarget
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.webhooks = [
        WebhookTarget(
            url="https://hooks.internal.example.com/triage",
            events=["classified", "escalated"],
            secret_key="webhook_hmac_internal",
        ),
        WebhookTarget(url="https://ops.example.com/wh", events=["error"]),
    ]
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert len(reloaded.webhooks) == 2
    assert reloaded.webhooks[0].url == "https://hooks.internal.example.com/triage"
    assert reloaded.webhooks[0].events == ["classified", "escalated"]
    assert reloaded.webhooks[0].secret_key == "webhook_hmac_internal"
    assert reloaded.webhooks[1].url == "https://ops.example.com/wh"
    assert reloaded.webhooks[1].events == ["error"]


def test_webhooks_allow_external_roundtrip(cwd_tmp):
    """ deny-by-default external-webhook guard. The admin form sets it
    (``integrations.py``) and the dispatch path consumes it (``app.py`` /
    ``watch_runner.py``), but it was NEITHER written NOR read — so an
    operator's UI toggle silently reverted to deny on restart. Fails *safe*
    (reverts to the more-restrictive value) but is still a real lost-setting
    defect: requires writer-emit AND loader-read."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.webhooks_allow_external = True
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.webhooks_allow_external is True


def test_llm_maintenance_windows_roundtrip(cwd_tmp):
    """ Bundle C operator-defined maintenance windows. Loader reads
    them (keeping only windows with cron+backend+duration>0); the writer
    never emitted them, so they vanished on the next Save."""
    from email_triage.config import LLMMaintenanceWindow
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.llm_maintenance_windows = [
        LLMMaintenanceWindow(
            host="llm-host", cron="0 3 * * 0",
            duration_minutes=120, backend="ollama",
        ),
    ]
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert len(reloaded.llm_maintenance_windows) == 1
    w = reloaded.llm_maintenance_windows[0]
    assert w.host == "llm-host"
    assert w.cron == "0 3 * * 0"
    assert w.duration_minutes == 120
    assert w.backend == "ollama"


def test_secrets_master_key_name_roundtrip(cwd_tmp):
    """``secrets.master_key_name`` is a key-NAME pointer (e.g. the
    container-secret filename the master key lives under), already
    YAML-resident by design (the loader reads it, config.py:1306). The
    writer comment said "preserve from existing" but the code rebuilt the
    secrets block as just ``{backend, keyfile_path}`` — so a hand-set custom
    master key name was DROPPED on the next admin Save, and the next boot
    looked under the default ``ET_MASTER_KEY`` → could not find the master
    key → secrets-store availability failure. (db-sme had mis-classified
    this BENIGN; the loader-read evidence makes it a REAL gap.) #8-FULL."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.secrets.master_key_name = "ET_MASTER_KEY_PROD_V2"
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.secrets.master_key_name == "ET_MASTER_KEY_PROD_V2"


def test_secrets_external_provider_roundtrip(cwd_tmp):
    """``secrets.external`` is the external-provider (Vault/KeePass) plugin
    CONFIG dict — connection params, NOT a managed secret value (those live
    in the encrypted DB column). It is loader-read (config.py:1307); the
    writer dropped it, so an operator using ``backend: external:<name>``
    lost the provider config on Save → next boot the backend can't
    initialize → can't read the master key. Already YAML-resident by
    design, so emitting it adds no plaintext-secret exposure. #8-FULL."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.secrets.backend = "external:vault"
    cfg.secrets.external = {"vault": {"url": "https://vault.internal:8200",
                                      "mount": "secret", "path": "email-triage"}}
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.secrets.backend == "external:vault"
    assert reloaded.secrets.external == {
        "vault": {"url": "https://vault.internal:8200",
                  "mount": "secret", "path": "email-triage"},
    }


def test_push_office365_renewal_window_roundtrip(cwd_tmp):
    """``push.office365_subscription_renewal_window_hours`` is read by the
    loader but was never written — it reverted to 24 on every Save, so an
    operator on a shaky Graph link who shrank the window lost it."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.push.office365_subscription_renewal_window_hours = 6
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.push.office365_subscription_renewal_window_hours == 6


def test_backup_config_roundtrip(cwd_tmp):
    """ — the ``backup:`` section is a disaster-recovery control. The
    full-rebuild writer dropped it entirely (same class as
    ``encryption_enabled`` above), so an admin Save of any UNRELATED tab
    silently reverted an operator's automated backups to DISABLED — the worst
    direction for a DR control. Every BackupConfig field must round-trip. The
    structural pin's substring heuristic false-passes on ``enabled`` /
    ``retention`` (substrings of other emitted fields), so this behavioural
    test is the real guard for ``cadence`` / ``public_key`` / the toggle."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.backup.enabled = True
    cfg.backup.cadence = "daily"
    cfg.backup.format = "db"
    cfg.backup.retention = "2w"
    cfg.backup.dir = "/srv/backups/email-triage"
    cfg.backup.encryption = "public-key"
    cfg.backup.public_key = (
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEA\n"
        "-----END PUBLIC KEY-----\n"
    )
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.backup.enabled is True
    assert reloaded.backup.cadence == "daily"
    assert reloaded.backup.format == "db"
    assert reloaded.backup.retention == "2w"
    assert reloaded.backup.dir == "/srv/backups/email-triage"
    assert reloaded.backup.encryption == "public-key"
    assert "BEGIN PUBLIC KEY" in reloaded.backup.public_key


def test_regulatory_clock_config_roundtrip(cwd_tmp):
    """ — ``regulatory_clock`` is loader-read (detection flag + the
    per-install working-day/holiday calendar) but the full-rebuild writer
    never emitted it, so an admin Save silently dropped it. Dropping the
    holiday calendar can miscompute a deadline into a false ``breached``
    chained into the immutable audit log — so this round-trip is a
    correctness control, not a convenience."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()
    cfg.regulatory_clock.detection_enabled = True
    cfg.regulatory_clock.working_day_holidays = ["2026-07-03", "2026-12-25"]
    cfg.regulatory_clock.working_week = [0, 1, 2, 3, 4, 5]  # Sat is a working day
    _write_config_yaml(cfg)
    reloaded = load_config(cwd_tmp)

    assert reloaded.regulatory_clock.detection_enabled is True
    assert reloaded.regulatory_clock.working_day_holidays == [
        "2026-07-03", "2026-12-25",
    ]
    assert reloaded.regulatory_clock.working_week == [0, 1, 2, 3, 4, 5]


def test_legacy_health_recipients_promote_to_admin_email_on_load(cwd_tmp):
    """CR-2c deprecation fix (operator 2026-06-18 "fix the health_email.recipients
    deprecation"): a YAML that still uses ONLY the legacy
    ``health_email.recipients`` promotes to ``admin_email.recipients`` at load —
    so the canonical field is populated, resolve_admin_recipients reads it, and
    the once-per-process deprecation WARNING no longer fires (while the operator's
    recipients are still honoured)."""
    import email_triage.web.daily_health as dh

    cwd_tmp.write_text(
        "provider:\n  type: imap\n"
        "health_email:\n  enabled: true\n"
        "  recipients: [ops@example.com, admin@example.com]\n"
    )
    cfg = load_config(cwd_tmp)

    # Promoted to the canonical field at load.
    assert cfg.admin_email.recipients == ["ops@example.com", "admin@example.com"]

    # resolve_admin_recipients now reads the canonical field → warning never fires.
    dh._reset_deprecation_warning()
    assert dh.resolve_admin_recipients(cfg) == [
        "ops@example.com", "admin@example.com",
    ]
    assert dh._legacy_recipient_warning_logged is False


def test_admin_email_recipients_win_over_legacy_on_load(cwd_tmp):
    """When BOTH are set, the canonical admin_email.recipients is kept as-is
    (the promotion only fills an EMPTY canonical field — never overwrites)."""
    cwd_tmp.write_text(
        "provider:\n  type: imap\n"
        "health_email:\n  recipients: [old@example.com]\n"
        "admin_email:\n  recipients: [new@example.com]\n"
    )
    cfg = load_config(cwd_tmp)
    assert cfg.admin_email.recipients == ["new@example.com"]


def test_backup_disabled_default_stays_minimal_but_loads(cwd_tmp):
    """A fresh disabled-default backup config must NOT bloat the YAML (the
    conditional-emit keeps it absent) yet still reload as disabled — the
    conditional-emit must not corrupt the default-reload path."""
    from email_triage.web.routers.ui import _write_config_yaml

    cfg = TriageConfig()  # backup defaults: disabled / manual / etbk / "14"
    _write_config_yaml(cfg)
    raw = yaml.safe_load(cwd_tmp.read_text())
    assert "backup" not in raw  # minimal YAML — no dead disabled block

    reloaded = load_config(cwd_tmp)
    assert reloaded.backup.enabled is False
    assert reloaded.backup.cadence == "manual"


# ---------------------------------------------------------------------------
# Drift detector
# ---------------------------------------------------------------------------

# Map of dataclass -> set of field names that are KNOWN to not round-trip
# through YAML BY DESIGN. Every entry is a justified exemption, classified
# from the db-sme #8-FULL enumeration (2026-06-10). Three legitimate reasons
# a config field is absent from the serializer:
#
#   (1) SECRET VALUE — hydrated from the encrypted secrets store at startup,
#       never read from OR written to plaintext config.yaml. Emitting these
#       would be the R8/R11 fail-OPEN defect this pin exists to PREVENT, so
#       they are exempt by design (NOT a gap). The managed user secrets
#       (IMAP/SMTP/OAuth tokens) live in the encrypted DB column.
#   (2) CLASS CONSTANT — a bound / ceiling that is not operator-editable, so
#       there is nothing to round-trip.
#   (3) PASSTHROUGH-PRESERVED — the writer copies the entire `provider` /
#       `routes` YAML block verbatim from the existing file
#       (``data["provider"] = existing["provider"]``), so these fields
#       round-trip by block preservation, not by field-name emission.
#
# Anything NOT in here MUST be referenced in the serializer (the loader-read
# fields that were genuinely lost on Save — encryption_enabled, webhooks,
# webhooks_allow_external, llm_maintenance_windows, push.office365_*,
# secrets.master_key_name, secrets.external — were FIXED in the writer, not
# added here).
_NON_ROUNDTRIP_FIELDS: dict[type, set[str]] = {
    # (1) secret values — store-only, never plaintext YAML
    GoogleOAuthConfig: {
        "web_client_id", "web_client_secret",
        "desktop_client_id", "desktop_client_secret",
    },
    Office365OAuthConfig: {"tenant_id", "client_id", "client_secret"},
    # (2) class constants — ingestion cadence bounds + HIPAA TTL ceiling
    IngestionConfig: {"POLL_MIN", "POLL_MAX", "POLL_STEP",
                      "PUSH_MIN", "PUSH_MAX", "STEP"},
    AuthConfig: {"HIPAA_TTL_HARD_CEILING_SECS"},
    # (3) passthrough-preserved blocks
    ProviderConfig: {"type", "gmail_api", "imap", "office365"},
    RouteConfig: {"actions"},
    # secret-CONTAINER fields on TriageConfig (the two OAuth dataclasses
    # above) — never serialized; their nested fields are exempt under (1)
    TriageConfig: {"google_oauth", "office365_oauth"},
}


def _writer_code_without_comments() -> str:
    """``_write_config_yaml_locked`` source with COMMENT tokens stripped.

    The round-trip pin matches a field name as a substring of the serializer
    source. The #8-FULL fix added several comment blocks that MENTION field
    names in prose (``encryption_enabled``, ``master_key_name``,
    ``office365_subscription_renewal_window_hours`` …) — a raw-text scan would
    then count a future field that is only NAMED IN A COMMENT but never
    actually emitted as "covered" (a false pass). Stripping comments closes
    that hole. STRING tokens are deliberately KEPT: the legitimate emit shapes
    ``getattr(p, "field")`` and ``block["field"] = …`` carry the field name
    inside a string literal, and those ARE real emits the pin must detect.
    (Comment-strip is the down-payment; the full read⟺write AST symmetry is a
    tracked follow-up — the behavioural ``*_roundtrip`` tests backstop the
    security-relevant fields meanwhile.)"""
    import inspect
    import io
    import tokenize
    from email_triage.web.routers import ui as ui_mod

    src = inspect.getsource(ui_mod._write_config_yaml_locked)
    pieces: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            pieces.append(tok.string)
    except tokenize.TokenError:  # pragma: no cover - fall back to raw text
        return src
    return " ".join(pieces)


def _all_config_dataclasses() -> list[type]:
    """Every dataclass reachable from ``TriageConfig`` through
    dataclass-typed fields, INCLUDING those nested inside ``list[X]`` /
    ``dict[K, V]`` generics. Reflective + count-agnostic: a new config
    dataclass or a new nested field is covered automatically, with no
    hardcoded class list to drift (the iron-rule shape from
    ``pattern_count_agnostic_structural_drift_catch``). Resolves string
    annotations via ``get_type_hints`` so ``from __future__ import
    annotations`` doesn't collapse the walk."""
    import typing

    seen: dict[type, None] = {}

    def _unwrap(t) -> list[type]:
        out: list[type] = []
        for a in typing.get_args(t):
            out += _unwrap(a)
        if dataclasses.is_dataclass(t):
            out.append(t)
        return out

    def _walk(cls) -> None:
        if cls in seen:
            return
        seen[cls] = None
        hints = typing.get_type_hints(cls)
        for f in dataclasses.fields(cls):
            for sub in _unwrap(hints.get(f.name, f.type)):
                _walk(sub)

    _walk(TriageConfig)
    return list(seen)


def test_config_universe_is_fully_discovered():
    """R7 (census the censusers) teeth — the reflective walker MUST find
    the universe, not silently collapse to a near-empty set (which would
    turn the round-trip pin below into a no-op — exactly what happens if
    ``get_type_hints`` ever stops resolving the string annotations). Lock a
    floor so a walker regression fails loudly instead of passing vacuously."""
    classes = _all_config_dataclasses()
    assert TriageConfig in classes
    assert len(classes) >= 25, (
        f"config-dataclass walker found only {len(classes)} classes — "
        "expected >=25. The reflective walk regressed (string annotations "
        "unresolved?) and the round-trip pin would be near-empty."
    )


def test_writer_references_every_config_field():
    """COUNT-AGNOSTIC read⟺write symmetry pin.

    For EVERY config dataclass reachable from ``TriageConfig``, every
    declared field MUST either be referenced in the
    ``_write_config_yaml_locked`` serializer source OR be explicitly
    justified in ``_NON_ROUNDTRIP_FIELDS``. This REPLACES the old hardcoded
    5-class subset (``TLS/Acme/Rfc2136/HealthEmail/Logging``) — add a new
    config dataclass or field and it is covered with no test edit.

    The serializer is a FULL REBUILD (``data = {}``): any loader-read field
    it forgets to emit is silently dropped on Save and reverts to its
    dataclass default on the next reload — the exact data-loss class that
    bricked encryption_enabled / webhooks / secrets.master_key_name. This is
    the structural net; the dynamic ``*_roundtrip`` tests above are the
    behavioural backstop for the specific high-risk fields.

    Heuristic: a field's NAME appearing as a substring in the writer source
    (covers ``config.x.field`` / ``getattr(x, "field")`` / ``blk["field"]``
    emit shapes), with COMMENT tokens stripped so a field named only in a
    comment can't false-pass (see ``_writer_code_without_comments``).
    Substring collisions are possible but rare given the specific field
    names; the behavioural round-trip tests close that gap for the
    security-relevant fields."""
    # Inspect the LOCKED serializer (comments stripped) where the fields are
    # actually written — _write_config_yaml is a thin lock+atomic-write
    # wrapper that references no fields.
    src = _writer_code_without_comments()
    offenders: list[str] = []
    for cls in _all_config_dataclasses():
        skip = _NON_ROUNDTRIP_FIELDS.get(cls, set())
        for f in dataclasses.fields(cls):
            if f.name in skip:
                continue
            if f.name not in src:
                offenders.append(f"{cls.__name__}.{f.name}")
    assert offenders == [], (
        "config field(s) the serializer never emits and which are NOT "
        f"justified in _NON_ROUNDTRIP_FIELDS: {offenders}. Either round-trip "
        "the field in _write_config_yaml_locked, or add it to "
        "_NON_ROUNDTRIP_FIELDS with a justification (secret-store-only / "
        "class-constant / passthrough-preserved)."
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
