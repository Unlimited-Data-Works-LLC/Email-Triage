"""Tests for YAML configuration loading and validation."""

import tempfile
from pathlib import Path

import pytest

from email_triage.config import (
    ConfigError,
    TriageConfig,
    load_config,
    validate_config,
    _parse_raw,
)


class TestDefaults:
    def test_default_config_is_valid(self):
        cfg = TriageConfig()
        issues = validate_config(cfg)
        assert issues == []

    def test_default_categories_populated(self):
        cfg = TriageConfig()
        assert "to-respond" in cfg.classifier.categories
        assert "invoices" in cfg.classifier.categories
        assert len(cfg.classifier.categories) == 10

    def test_default_backend_is_ollama(self):
        cfg = TriageConfig()
        assert cfg.classifier.backend == "ollama"

    def test_default_hipaa_off(self):
        cfg = TriageConfig()
        assert cfg.logging.hipaa is False

    def test_secrets_parser_default_backend_is_auto_not_env(self, tmp_path):
        """R-4 per H-07 verify-don't-accept review 2026-05-24 (DA-4
        catch). When operator YAML has a `secrets:` block but omits the
        `backend:` line, the parser MUST default to `auto`, not `env`.

        Before this fix (config.py:1181 `s.get("backend", "env")`), the
        parser silently leaked `"env"` whenever the operator's YAML had
        a `secrets:` block configured for `keyfile_path` / `external` /
        etc. but didn't explicitly name `backend:`. That's the second
        site of H-07's structural-hollow closure surface (alongside the
        init template at cli.py:1496).

        Per project_hipaa_asap_policy.md no-defer-tier, both sites had
        to land Cycle 6.
        """
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "secrets:\n"
            "  keyfile_path: ~/.config/email-triage/key\n"
        )
        cfg = load_config(str(yaml_file))
        assert cfg.secrets.backend == "auto", (
            "parser default for missing `backend:` must be `auto` per "
            "H-07 closure. Got: " + repr(cfg.secrets.backend)
        )


class TestLoadFromYaml:
    def test_load_minimal_yaml(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
provider:
  type: imap
classifier:
  backend: ollama
  model: qwen3.5:35b
  ollama_url: http://llmhost:11434
""")
        cfg = load_config(yaml_file)
        assert cfg.provider.type == "imap"
        assert cfg.classifier.ollama_url == "http://llmhost:11434"

    def test_load_with_routes(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
routes:
  to-respond: [notify, draft_reply]
  invoices: [label]
  newsletters: [label]
""")
        cfg = load_config(yaml_file)
        assert cfg.routes["to-respond"].actions == ["notify", "draft_reply"]
        assert cfg.routes["invoices"].actions == ["label"]

    def test_load_with_escalation(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
escalation:
  enabled: true
  categories: [to-respond, action-required]
""")
        cfg = load_config(yaml_file)
        assert cfg.escalation.enabled is True
        assert cfg.escalation.categories == ["to-respond", "action-required"]

    def test_load_with_webhooks(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
webhooks:
  - url: http://the agent host:3000/hooks/triage
    events: [flow.classified, flow.finished]
    secret_key: webhook_hmac_secret
""")
        cfg = load_config(yaml_file)
        assert len(cfg.webhooks) == 1
        assert cfg.webhooks[0].url == "http://the agent host:3000/hooks/triage"
        assert "flow.classified" in cfg.webhooks[0].events

    def test_missing_explicit_path_raises(self):
        with pytest.raises(ConfigError):
            load_config("/nonexistent/path/config.yaml")

    def test_no_config_returns_defaults(self, tmp_path: Path, monkeypatch):
        # Ensure none of the search paths exist.
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.provider.type == "gmail_api"

    def test_hipaa_mode_from_yaml(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
logging:
  hipaa: true
  level: WARNING
""")
        cfg = load_config(yaml_file)
        assert cfg.logging.hipaa is True
        assert cfg.logging.level == "WARNING"


class TestValidation:
    def test_unknown_backend(self):
        cfg = TriageConfig()
        cfg.classifier.backend = "gpt4all"
        issues = validate_config(cfg)
        assert any("classifier backend" in i for i in issues)

    def test_unknown_provider(self):
        cfg = TriageConfig()
        cfg.provider.type = "yahoo"
        issues = validate_config(cfg)
        assert any("provider type" in i for i in issues)

    def test_unknown_secrets_backend(self):
        cfg = TriageConfig()
        cfg.secrets.backend = "hashicorp"
        issues = validate_config(cfg)
        assert any("secrets backend" in i for i in issues)

    def test_route_without_category_warns(self):
        cfg = TriageConfig()
        from email_triage.config import RouteConfig
        cfg.routes["nonexistent-cat"] = RouteConfig(actions=["notify"])
        issues = validate_config(cfg)
        assert any("nonexistent-cat" in i for i in issues)

    def test_empty_categories_warns(self):
        cfg = TriageConfig()
        cfg.classifier.categories = {}
        issues = validate_config(cfg)
        assert any("categories" in i for i in issues)


class TestAcmeChallengeValidation:
    """tls.acme.challenge: both dns-01 and http-01 are implemented. Config load
    must FAIL FAST when ACME is enabled with an UNKNOWN challenge type (a
    misconfig or typo like ``challenge: tls-alpn-01``) instead of raising a
    misleading NotImplementedError deep in the renewer's order loop. When the
    challenge is http-01, the mode-specific required fields (webroot_path for
    mode=webroot; valid bind_host+bind_port for mode=standalone) must also be
    present at load time."""

    def test_enabled_acme_http01_loads_clean(self, tmp_path: Path):
        """HTTP-01 with default standalone mode + default bind is valid."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: http-01
""")
        cfg = load_config(yaml_file)
        assert cfg.tls.acme.challenge == "http-01"
        assert cfg.tls.acme.http01.mode == "standalone"
        assert cfg.tls.acme.http01.bind_host == "0.0.0.0"
        assert cfg.tls.acme.http01.bind_port == 80

    def test_enabled_acme_http01_webroot_requires_path(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: http-01
    http01:
      mode: webroot
""")
        with pytest.raises(ConfigError, match="webroot_path"):
            load_config(yaml_file)

    def test_enabled_acme_http01_webroot_with_path_loads_clean(
        self, tmp_path: Path
    ):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: http-01
    http01:
      mode: webroot
      webroot_path: /var/www/acme-challenge
""")
        cfg = load_config(yaml_file)
        assert cfg.tls.acme.http01.mode == "webroot"
        assert cfg.tls.acme.http01.webroot_path == "/var/www/acme-challenge"

    def test_enabled_acme_unknown_challenge_raises_at_load(
        self, tmp_path: Path
    ):
        """Any challenge type OTHER than dns-01 / http-01 rejects fail-fast."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: tls-alpn-01
""")
        with pytest.raises(ConfigError, match="not supported"):
            load_config(yaml_file)

    def test_enabled_acme_http01_bad_mode_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: http-01
    http01:
      mode: sidecar
""")
        with pytest.raises(ConfigError, match="http01.mode"):
            load_config(yaml_file)

    def test_enabled_acme_http01_bad_port_raises(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: http-01
    http01:
      bind_port: 99999
""")
        with pytest.raises(ConfigError, match="bind_port"):
            load_config(yaml_file)

    def test_enabled_acme_dns01_loads_clean(self, tmp_path: Path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: true
    challenge: dns-01
""")
        cfg = load_config(yaml_file)
        assert cfg.tls.acme.challenge == "dns-01"

    def test_disabled_acme_with_stale_challenge_is_left_alone(
        self, tmp_path: Path
    ):
        # A disabled-ACME config carrying a stale unknown challenge must NOT
        # error — nothing runs, so don't break an upgrade on a dormant field.
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
tls:
  acme:
    enabled: false
    challenge: tls-alpn-01
""")
        cfg = load_config(yaml_file)
        assert cfg.tls.acme.enabled is False
        assert cfg.tls.acme.challenge == "tls-alpn-01"


class TestDevModeRemoved:
    """Dev-mode was retired wholesale 2026-05-16. The YAML loader
    must hard-reject any lingering ``_dev:`` block with a migration
    hint pointing at the supported replacement paths so operators
    upgrading from older configs don't silently lose a knob's intent
    (or worse, assume the old behaviour is still in effect)."""

    def test_yaml_with_dev_block_raises_config_error(self, tmp_path: Path):
        """Any ``_dev:`` block — even one carrying only the previously-
        canonical ``enabled``/``verbose_logs`` keys — is now rejected.
        The error message points operators at the supported auth
        replacements (``/admin/dev-keys`` or ``/profile/hardware-keys``)
        so a confused upgrade path lands on the right surface."""
        from email_triage.config import ConfigError
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("""\
_dev:
  enabled: true
  verbose_logs: true
""")
        with pytest.raises(ConfigError) as exc_info:
            load_config(yaml_file)
        msg = str(exc_info.value)
        assert "/admin/dev-keys" in msg or "/profile/hardware-keys" in msg

    def test_yaml_without_dev_block_loads(self, tmp_path: Path):
        """Configs that never mentioned ``_dev:`` continue to load
        cleanly — the rejection is keyed on presence, not absence."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("provider:\n  type: imap\n")
        cfg = load_config(yaml_file)
        # Sanity — load succeeded and parsed the rest.
        assert cfg.provider.type == "imap"

    def test_no_dev_attribute_on_triage_config(self):
        """The ``DevConfig`` dataclass and the ``dev`` field on
        ``TriageConfig`` were removed in the wholesale-removal change.
        Pinning the absence prevents an accidental re-introduction
        from passing review."""
        cfg = TriageConfig()
        assert not hasattr(cfg, "dev")

    def test_login_handler_has_no_static_secret_branch(self):
        """Source-level guard: the login handler must not contain a
        static-secret comparison branch under any name. Catches future
        regressions where someone re-introduces a server-side YAML-level
        secret check ahead of the OTP/dev-keypair/WebAuthn paths.
        Ported from the retired tests/test_dev_config_strict.py."""
        #  — login handler lives in `routers/ui/users.py` after
        # the per-concern split.
        src = (
            Path(__file__).resolve().parents[0].parent
            / "src" / "email_triage" / "web" / "routers" / "ui" / "users.py"
        )
        text = src.read_text(encoding="utf-8")
        # Any local variable named after a static-secret bypass is
        # forbidden — treated as a smell. Documentation comments may
        # reference the historical name but no executable assignment.
        forbidden_assignment_patterns = [
            "dev_bypass = ",
            "config.dev.otp_bypass_code",
        ]
        for pattern in forbidden_assignment_patterns:
            assert pattern not in text, (
                f"Forbidden pattern {pattern!r} reappeared in users.py — "
                "static-secret login bypass branches are not permitted."
            )
