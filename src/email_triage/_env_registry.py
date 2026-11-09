"""Punch 547 — the ONE registry of environment-variable reads (SSOT).

Operator directive 2026-09-29: *remove, do not document, any read that can
override a security control, an audit or identity value, or a fail-closed
decision. A documented override does not count as a justification.* An env var
that reaches a control is a bypass anyone with quadlet or ``.env`` write access
can type, with no code change and no image rebuild.

So this module holds two lists:

* :data:`ENV_READS` — every environment touch that REMAINS in
  ``src/email_triage``, keyed ``(path, function, key)`` (``path`` is
  ``_pin_harness.relpath`` form, ``function`` the class-qualified enclosing
  name — both stable under unrelated line shifts), with its class and why it is
  allowed. ``CONTROL-OVERRIDE`` is deliberately NOT a legal class: such a read
  is removed, never registered.
* :data:`RETIRED` — keys whose read was removed, mapped to what replaced them.
  A process that still carries one is REFUSED (:func:`refuse_retired_env`, at
  web lifespan and CLI start), so a leftover quadlet drop-in or compose line
  fails loudly and closed instead of being silently ignored.

``tests/test_env_registry_pin.py`` walks every env touch in src (the shared
``_pin_harness.env_read_sites`` scanner, interprocedural through helpers) and
fails on any site without a row here, any row without a site, any illegal
class, and any read of a retired key.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

SECRET_VIA_ENV = "SECRET-VIA-ENV"
TUNABLE = "TUNABLE"
DEBUG = "DEBUG"
THIRD_PARTY_HYGIENE = "THIRD-PARTY-HYGIENE"
HELPER = "HELPER"
RETIRED_REFUSE = "RETIRED-REFUSE"
#: A read another in-flight change removes (the justification names the punch).
#: Its row goes stale — and the pin goes red — the moment that change lands, so
#: the row cannot outlive the read.
OWED_REMOVAL = "OWED-REMOVAL"

LEGAL_CLASSES: frozenset[str] = frozenset({
    SECRET_VIA_ENV, TUNABLE, DEBUG, THIRD_PARTY_HYGIENE, HELPER,
    RETIRED_REFUSE, OWED_REMOVAL,
})


@dataclass(frozen=True)
class EnvRead:
    path: str
    function: str
    key: str  # a literal env name, or "*" for a documented dynamic key
    cls: str
    justification: str


ENV_READS: tuple[EnvRead, ...] = (
    EnvRead("_egress.py", "resolve_egress_trust", "SSL_CERT_FILE", TUNABLE,
            "Operator ruling A3 (2026-10-21): the well-known CA-bundle variable is "
            "honoured again for HTTPS egress; outbound_tls.ca_bundle overrides it and "
            "outbound_tls.ignore_env switches every environment read off."),
    EnvRead("_egress.py", "resolve_egress_trust", "REQUESTS_CA_BUNDLE", TUNABLE,
            "Operator ruling A3 (2026-10-21): the well-known CA-bundle variable is "
            "honoured again for HTTPS egress; outbound_tls.ca_bundle overrides it and "
            "outbound_tls.ignore_env switches every environment read off."),
    EnvRead("_egress.py", "resolve_egress_trust", "CURL_CA_BUNDLE", TUNABLE,
            "Operator ruling A3 (2026-10-21): the well-known CA-bundle variable is "
            "honoured again for HTTPS egress; outbound_tls.ca_bundle overrides it and "
            "outbound_tls.ignore_env switches every environment read off."),
    EnvRead("_egress.py", "resolve_egress_trust", "SSL_CERT_DIR", TUNABLE,
            "Operator ruling A3 (2026-10-21): the well-known CA-bundle variable is "
            "honoured again for HTTPS egress; outbound_tls.ca_bundle overrides it and "
            "outbound_tls.ignore_env switches every environment read off."),
    EnvRead("_envbool.py", "env_bool", "*", HELPER,
            "The string->bool env helper; its key is the caller's argument. "
            "Every caller is resolved by the pin and needs its own row."),
    EnvRead("web/access_audit.py", "AccessAuditMiddleware.dispatch",
            "EMAIL_TRIAGE_AUDIT_STRICT", DEBUG,
            "Makes the access-audit write synchronous and re-raising. It can only "
            "make the audit STRICTER (unset = fire-and-forget through the "
            "never-raise SSOT; both paths bump audit_failures)."),
    EnvRead("web/access_audit.py", "_audit_write", "EMAIL_TRIAGE_AUDIT_STRICT", DEBUG,
            "Same knob, the emit half: strict mode re-raises the original "
            "exception instead of swallowing it. Stricter-only."),
    EnvRead("actions/topic_configs.py", "_resolve_confidence_floor",
            "ET_TOPIC_MATCH_CONFIDENCE_FLOOR", TUNABLE,
            "Digest surfacing floor, clamped to [0,1]. Not a control. OPEN: "
            "config-surface audit 2026-09-11 finding #2 (move to config)."),
    EnvRead("cli.py", "cmd_backup", "ET_BACKUP_TRIGGER_TIMEOUT_SECS", TUNABLE,
            "HTTP timeout of the loopback backup trigger. Not a control; the "
            "trigger URL is fixed. OPEN: config-surface audit 2026-09-11 finding #5."),
    EnvRead("db/_writer.py", "_resolve_queue_maxsize",
            "EMAIL_TRIAGE_WRITER_QUEUE_MAXSIZE", TUNABLE,
            "Writer queue depth. Not a control. OPEN: config-surface audit "
            "2026-09-11 finding #4."),
    EnvRead("embedding_bits/__init__.py", "<module>", "TRANSFORMERS_OFFLINE",
            THIRD_PARTY_HYGIENE,
            "setdefault('0') for the HF library. An env value can only make it "
            "STRICTER ('1' = offline), so env winning is safe."),
    EnvRead("embedding_bits/__init__.py", "<module>", "HF_HUB_DISABLE_TELEMETRY",
            THIRD_PARTY_HYGIENE, "FORCED write (never read): telemetry off."),
    EnvRead("embedding_bits/__init__.py", "<module>", "DO_NOT_TRACK",
            THIRD_PARTY_HYGIENE, "FORCED write (never read): telemetry off."),
    EnvRead("embedding_bits/__init__.py", "<module>", "HF_HUB_DISABLE_IMPLICIT_TOKEN",
            THIRD_PARTY_HYGIENE, "FORCED write (never read): no implicit HF token."),
    EnvRead("embedding_bits/__init__.py", "<module>", "HF_HUB_DISABLE_PROGRESS_BARS",
            THIRD_PARTY_HYGIENE, "FORCED write (never read): cosmetic."),
    EnvRead("embedding_bits/__init__.py", "<module>", "PIP_DISABLE_PIP_VERSION_CHECK",
            THIRD_PARTY_HYGIENE, "FORCED write (never read): pip never calls home."),
    EnvRead("embedding_bits/__init__.py", "_update_runtime_locked", "HF_HOME",
            THIRD_PARTY_HYGIENE,
            "Punch 569: FORCED write resetting HF_HOME to the LIVE prefix's cache "
            "after an update staged in <prefix>.next (whose path no longer "
            "exists after the swap). Never read to choose a model dir."),
    EnvRead("embedding_bits/__init__.py", "_install_common", "HF_HOME",
            THIRD_PARTY_HYGIENE,
            "FORCED write of the derived cache dir for the HF library in the "
            "installer process. The app never READS HF_HOME to choose a model dir."),
    EnvRead("secrets.py", "EnvSecrets.get", "*", SECRET_VIA_ENV,
            "The deprecated env bootstrap secrets backend (H-07): env IS the "
            "secret store when secrets.backend=env. HIPAA mode refuses it (G1'). "
            "Its callers are the secret-read class (test_secret_read_funnel_pin)."),
    EnvRead("web/routers/health.py", "_read_ops_token", "ET_HEALTH_OPS_TOKEN",
            SECRET_VIA_ENV,
            "The loopback ops credential (N-365 named deviation: it bootstraps "
            "before DbSecrets is readable). _ops_token_authorized fails closed on "
            "blank/weak."),
    EnvRead("web/routers/ui/_shared.py", "_load_meeting_prefs_with_default_tz", "TZ",
            TUNABLE,
            "Platform timezone as the first-render seed of an EMPTY meeting-prefs "
            "record; the stored DB value wins once saved. Not a control."),
    EnvRead("_env_registry.py", "retired_env_present", "*", RETIRED_REFUSE,
            "Presence check of the RETIRED keys. It can only REFUSE a boot, never "
            "change what a control does."),
)


#: Removed reads -> what replaced them. Presence of any of these REFUSES the
#: process (exit :data:`RETIRED_ENV_EXIT_CODE` from the CLI; RuntimeError at web
#: lifespan). The CA-bundle variables (``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` /
#: ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE``) left this list on 2026-10-21
#: (operator ruling A3): they are honoured again, with ``outbound_tls`` config
#: overriding them (``_egress.resolve_egress_trust``).
RETIRED: dict[str, str] = {
    "EMAIL_TRIAGE_DB_ENCRYPTION":
        "persistence.encryption_enabled in the config file",
    "EMAIL_TRIAGE_PATH3_BASELINE":
        "nothing: the image carries its own Path-3 marker",
    "EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS":
        "email-triage version-check --previous-schema-caps N (deploy.sh passes it)",
    "ET_BACKUP_TRIGGER_URL":
        "nothing: the backup trigger always targets the in-container listener",
    "ET_CLASSIFY_DEBUG_CAPTURE":
        "classifier.debug_capture_raw_head in the config file (loud WARNING + admin banner while on)",
    "EMAIL_TRIAGE_ALLOW_ENV_MASTER_KEY":
        "nothing: the env secrets-backend warning always fires",
    "EMBEDDING_BITS_MANIFEST":
        "nothing: downloads verify against the baked /app/scripts/embedding-bits-manifest.json (punch 539 R7)",
    "EMBEDDING_BITS_RUNTIME_DEPS":
        "nothing: the runtime-deps prefix is fixed at /app/data/runtime-deps",
    "EMAIL_TRIAGE_VERSION":
        "nothing: the build identity is the file baked into the image, read only by email_triage._build_sha",
    "EMAIL_TRIAGE_CSRF_ENFORCE":
        "tls.csrf_enforce in the config file",
    "EMAIL_TRIAGE_CONFIG":
        "nothing: it was never read; the config is ./config/email-triage.yaml",
}

#: CLI exit status for a refused environment (sysexits EX_CONFIG). Distinct from
#: every subcommand's own codes so ``scripts/deploy.sh`` can tell a refusal from
#: an infrastructure failure.
RETIRED_ENV_EXIT_CODE = 78

#: ``email-triage preflight``'s "ran, but hit an infrastructure error" status
#: (sysexits EX_TEMPFAIL; punch 568, da O11-F1). The ONE definition: cli.py and
#: the tests import it from here, and deploy.sh step 5a' matches this literal.
#: Distinct from rc 1 (an uncaught exception or a missing dispatch entry) and
#: rc 2 (an argparse usage error), so the deploy can read every rc other than
#: 0 / 75 / 78 as "the check did not run" and abort. That also answers hipaa
#: R3-O11-1: "the check ran" is now distinguishable from "it never ran".
PREFLIGHT_INFRA_EXIT_CODE = 75


class RetiredEnvError(RuntimeError):
    """The process environment carries a key whose read was removed."""


def retired_env_present() -> list[str]:
    """The RETIRED keys present in this process's environment, sorted."""
    return sorted(k for k in RETIRED if k in os.environ)


def format_retired_env(found: list[str]) -> str:
    lines = [
        "Refusing to start: the environment sets variable(s) this version no "
        "longer honours (punch 547 — an env var must not override a control). "
        "Remove them from the quadlet / drop-in / compose file:",
    ]
    lines += [f"  {k} -> {RETIRED[k]}" for k in found]
    return "\n".join(lines)


def refuse_retired_env() -> None:
    """Raise :class:`RetiredEnvError` when any RETIRED key is present."""
    found = retired_env_present()
    if found:
        raise RetiredEnvError(format_retired_env(found))
