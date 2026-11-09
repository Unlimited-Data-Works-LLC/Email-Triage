"""Punch 598 — YAML boolean settings parse strictly, through one funnel.

THE DEFECT
==========
``push.webhook_enabled`` (the operator's global webhook kill switch) was read
raw: ``p.get("webhook_enabled", p.get("openclaw_webhook_enabled", True))``. A
hand-edited quoted ``"false"`` stays the string ``'false'``, which is truthy, so
``events.fire_triage_completed`` kept firing webhooks (fail-OPEN on egress).

The census of every bool-annotated config field (29 fields) found the same loose
parse at 25 sites: 4 raw ``.get`` reads and 21 ``bool(x.get(...))`` coercions
(``bool("false") is True``). Fail-open members include
``webhooks_allow_external`` (quoted "false" ALLOWED external webhook targets),
``escalation.enabled``, ``health_email.enabled``, ``tls.acme.enabled``. One site
(``persistence.encryption_enabled``) already parsed strictly; three classifier
knobs accept only a real bool and warn otherwise.

THE FIX
=======
``config._parse_config_bool`` (strings through ``_envbool.parse_bool_tristate``,
the R17 SSOT) + ``config._cfg_bool`` (key lookup, default for a MISSING key,
legacy-key fallback). ``true/false/yes/no/on/off/1/0`` in any case parse; an
explicit null, an empty string or any other token REFUSES the config at load
with the dotted key named. ``_parse_encryption_enabled`` delegates to the same
parser (its null -> encrypted default is the one documented exception: that
default is the protective direction).

Structural pin: ``tests/test_punch598_config_bool_parse_pin.py``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from email_triage.config import ConfigError, _parse_raw


@pytest.fixture(autouse=True)
def _reset_dedicated_conn_encryption():
    """A CLI run stamps the process-global dedicated-conn encryption context
    (``_cli_stamp_db_encryption``). Where sqlcipher3 is installed (CI) an
    encrypted arm left it encrypted=True, and later plaintext tests on the same
    worker opened their DBs with a key (CI run 38182484137). Reset after every test."""
    yield
    from email_triage.db._engine import reset_dedicated_conn_encryption
    reset_dedicated_conn_encryption()


def _load(yaml_text: str):
    return _parse_raw(yaml.safe_load(yaml_text) or {})


# (yaml section path, key, attribute getter). Every funnel-routed two-state field.
_FIELDS = [
    (("classifier",), "prefer_loaded", lambda c: c.classifier.prefer_loaded),
    (("classifier",), "prefer_loaded_skip_embeddings",
     lambda c: c.classifier.prefer_loaded_skip_embeddings),
    (("escalation",), "enabled", lambda c: c.escalation.enabled),
    (("logging",), "hipaa", lambda c: c.logging.hipaa),
    (("logging",), "require_https_app_layer", lambda c: c.logging.require_https_app_layer),
    (("regulatory_clock",), "detection_enabled",
     lambda c: c.regulatory_clock.detection_enabled),
    (("tls",), "enabled", lambda c: c.tls.enabled),
    (("tls",), "csrf_enforce", lambda c: c.tls.csrf_enforce),
    (("tls", "acme"), "enabled", lambda c: c.tls.acme.enabled),
    (("tls", "acme"), "caa_enforce", lambda c: c.tls.acme.caa_enforce),
    (("smtp",), "use_tls", lambda c: c.smtp.use_tls),
    (("push",), "webhook_enabled", lambda c: c.push.webhook_enabled),
    (("push",), "openclaw_webhook_enabled", lambda c: c.push.webhook_enabled),
    (("backup",), "enabled", lambda c: c.backup.enabled),
    (("health_email",), "enabled", lambda c: c.health_email.enabled),
    (("health_email",), "include_health", lambda c: c.health_email.include_health),
    (("health_email",), "include_watchers", lambda c: c.health_email.include_watchers),
    (("health_email",), "include_triage", lambda c: c.health_email.include_triage),
    (("health_email",), "include_errors", lambda c: c.health_email.include_errors),
    (("health_email",), "include_hipaa_events",
     lambda c: c.health_email.include_hipaa_events),
    (("health_email",), "include_api_key_events",
     lambda c: c.health_email.include_api_key_events),
    (("health_email",), "include_pubsub", lambda c: c.health_email.include_pubsub),
    (("health_email",), "include_update_available",
     lambda c: c.health_email.include_update_available),
    (("health_email",), "quiet_mode", lambda c: c.health_email.quiet_mode),
    (("webauthn",), "require_user_verification_for_admin",
     lambda c: c.webauthn.require_user_verification_for_admin),
    ((), "webhooks_allow_external", lambda c: c.webhooks_allow_external),
    (("persistence",), "encryption_enabled", lambda c: c.persistence.encryption_enabled),
]
_IDS = [".".join((*s, k)) for s, k, _ in _FIELDS]


def _raw_with(section: tuple[str, ...], key: str, value) -> dict:
    raw: dict = {}
    node = raw
    for part in section:
        node = node.setdefault(part, {})
    node[key] = value
    return raw


@pytest.mark.parametrize("section,key,get", _FIELDS, ids=_IDS)
@pytest.mark.parametrize("token", ["false", "FALSE", "no", "Off", "0"])
def test_quoted_false_tokens_parse_false(section, key, get, token):
    """A quoted false-token is False at every bool site (was truthy at 25 sites)."""
    assert get(_parse_raw(_raw_with(section, key, token))) is False


@pytest.mark.parametrize("section,key,get", _FIELDS, ids=_IDS)
def test_unparseable_value_refuses_the_config(section, key, get):
    """Anything that is not a recognised token refuses at load, naming the key."""
    with pytest.raises(ConfigError) as exc:
        _parse_raw(_raw_with(section, key, "maybe"))
    assert key in str(exc.value)


_SAFE_TRUE = [f for f in _FIELDS if f[0][:2] != ("tls", "acme") and f[0] != ("tls",)]


@pytest.mark.parametrize("section,key,get", _SAFE_TRUE,
                         ids=[".".join((*s, k)) for s, k, _ in _SAFE_TRUE])
@pytest.mark.parametrize("token", ["true", "Yes", "ON", "1", True, 1])
def test_true_tokens_parse_true(section, key, get, token):
    assert get(_parse_raw(_raw_with(section, key, token))) is True


@pytest.mark.parametrize("section,key,get",
                         [f for f in _FIELDS if f[1] != "encryption_enabled"],
                         ids=[i for i in _IDS if not i.endswith("encryption_enabled")])
def test_explicit_null_refuses(section, key, get):
    """``key:`` with no value is not a decision. Refused (a null kill switch used
    to read as falsy for some keys and the default for others)."""
    with pytest.raises(ConfigError):
        _parse_raw(_raw_with(section, key, None))


def test_encryption_enabled_null_keeps_the_encrypted_default():
    """The one documented exception: null -> encrypted (the protective default)."""
    assert _parse_raw({"persistence": {"encryption_enabled": None}}) \
        .persistence.encryption_enabled is True


# --- The kill switch the row was filed on -----------------------------------

def test_webhook_kill_switch_quoted_false_from_yaml_text():
    cfg = _load('push:\n  webhook_enabled: "false"\n')
    assert cfg.push.webhook_enabled is False


def test_webhook_kill_switch_legacy_key_is_still_honoured():
    assert _load("push:\n  openclaw_webhook_enabled: false\n").push.webhook_enabled is False
    assert _load('push:\n  openclaw_webhook_enabled: "off"\n').push.webhook_enabled is False


def test_webhook_kill_switch_new_key_wins_over_legacy():
    cfg = _load("push:\n  webhook_enabled: true\n  openclaw_webhook_enabled: false\n")
    assert cfg.push.webhook_enabled is True
    cfg = _load("push:\n  webhook_enabled: false\n  openclaw_webhook_enabled: true\n")
    assert cfg.push.webhook_enabled is False


def test_webhook_kill_switch_absent_defaults_on():
    assert _load("push:\n  listen_port: 8080\n").push.webhook_enabled is True


def test_webhooks_allow_external_quoted_false_denies():
    """The fail-open member of the census: quoted "false" used to ALLOW external
    webhook targets (bool('false') is True)."""
    assert _load('webhooks_allow_external: "false"\n').webhooks_allow_external is False


async def test_fire_triage_completed_honours_a_quoted_false_kill_switch():
    """Behaviour at the actuator: the parsed config suppresses the emit."""
    from email_triage.web.events import fire_triage_completed

    cfg = _load('push:\n  webhook_enabled: "false"\n')
    dispatcher = MagicMock()
    dispatcher.dispatch = AsyncMock()
    fired = await fire_triage_completed(
        dispatcher, MagicMock(), cfg, {"id": 1, "hipaa": 0}, {"id": "r1"},
    )
    assert fired is False
    dispatcher.dispatch.assert_not_called()


def test_preflight_prints_the_resolved_hipaa_and_encryption_values(tmp_path, capsys):
    """Panel B3 hipaa-sme (N-596): a VALID token can flip meaning, which the
    strict parse cannot refuse. A quoted `logging.hipaa: "false"` read as ON
    before punch 598 and reads as OFF now. preflight prints both resolved
    values, so deploy.sh step 5a' shows them before the swap."""
    import argparse

    from email_triage.cli import cmd_preflight

    p = tmp_path / "email-triage.yaml"
    p.write_text(
        'logging:\n  hipaa: "false"\n'
        f"persistence:\n  encryption_enabled: false\n  db_path: {(tmp_path / 'x.db').as_posix()}\n",
        encoding="utf-8",
    )
    assert cmd_preflight(argparse.Namespace(config=str(p))) == 0
    out = capsys.readouterr().out
    assert "preflight: resolved logging.hipaa=False" in out
    assert "preflight: resolved persistence.encryption_enabled=False" in out
    assert "preflight: OK" in out
