"""the backlog  (2026-07-12): ACME wire `TriageConfig.acme` AttributeError.

`_wire_module_singletons(cfg: TriageConfig)` at src/email_triage/config.py
read `cfg.acme.dns_query_timeout_secs` — but `acme` lives on `TLSConfig`,
not `TriageConfig` (the field is `cfg.tls.acme`, added when TLS wrapped
the ACME config in TLSConfig). The AttributeError was silently swallowed
by the wrapping `try/except Exception -> _log_singleton_wire_failure`,
so every acme dns.query.* site fell back to the module default (10.0s /
5.0s) regardless of what the operator configured — matches STATE's
"AttributeError: 'TriageConfig' has no attribute 'acme'" report.

Fix: use `cfg.tls.acme.*` in both wire lines. This test pins that:
  1. The wire helper does NOT raise/log a wire_singleton failure for
     the acme setter on a stock TriageConfig().
  2. The acme_renewer module singletons DO get updated when the
     operator sets non-default acme timeouts in TriageConfig.
"""
from __future__ import annotations

from unittest import mock

import pytest

from email_triage.config import TriageConfig, _wire_module_singletons


def test_wire_no_acme_attribute_error_on_default_config():
    """Pin: `_wire_module_singletons(TriageConfig())` does NOT emit a
    `wire_singleton failed: configure_acme_dns_query_timeout` debug log."""
    with mock.patch(
        "email_triage.config._log_singleton_wire_failure"
    ) as failed:
        _wire_module_singletons(TriageConfig())
    failure_names = [call.args[0] for call in failed.call_args_list]
    assert "configure_acme_dns_query_timeout" not in failure_names, (
        f"wire_singleton silently swallowed an AttributeError on the "
        f"acme wire — the acme dns.query.* timeouts will not honor the "
        f"operator config. All swallowed failures this run: {failure_names}"
    )


def test_wire_reaches_acme_renewer_singletons():
    """Pin: an operator-configured `cfg.tls.acme.dns_query_timeout_secs`
    reaches `acme_renewer._ACME_DNS_UPDATE_TIMEOUT_SECS` after wire.

    Regression net: if the attribute path breaks again (e.g. cfg.acme
    reintroduced, or acme moves out of TLSConfig), the wire will silently
    revert to the module default and this test will FAIL."""
    from email_triage.web import acme_renewer

    cfg = TriageConfig()
    cfg.tls.acme.dns_query_timeout_secs = 42.0
    cfg.tls.acme.dns_probe_timeout_secs = 7.0

    saved_update = acme_renewer._ACME_DNS_UPDATE_TIMEOUT_SECS
    saved_probe = acme_renewer._ACME_DNS_PROBE_TIMEOUT_SECS
    try:
        _wire_module_singletons(cfg)
        assert acme_renewer._ACME_DNS_UPDATE_TIMEOUT_SECS == 42.0
        assert acme_renewer._ACME_DNS_PROBE_TIMEOUT_SECS == 7.0
    finally:
        acme_renewer._ACME_DNS_UPDATE_TIMEOUT_SECS = saved_update
        acme_renewer._ACME_DNS_PROBE_TIMEOUT_SECS = saved_probe


def test_no_wire_setter_silently_swallowed_on_default_config():
    """the backlog  broader-class pin: on a stock `TriageConfig()`,
    NO `_wire_module_singletons` setter should silently AttributeError
    into `_log_singleton_wire_failure`. Any silent-swallow means an
    attribute-path defect like N-401 is present RIGHT NOW, hidden by
    the wrapping try/except that only surfaces at DEBUG.

    This is the broader pin the N-401 acme-specific pin above only
    covered one setter of. All 9 setters share the same
    try/except/_log_singleton_wire_failure pattern (see
    config.py:1671-1740), so any of them could regress the same way.
    A single `assert failed.call_args_list == []` catches them all
    without hardcoding the setter name list (which drifts every time
    someone adds a new wire — the whole point of a count-agnostic pin).
    """
    with mock.patch(
        "email_triage.config._log_singleton_wire_failure"
    ) as failed:
        _wire_module_singletons(TriageConfig())
    silently_swallowed = [call.args[0] for call in failed.call_args_list]
    assert silently_swallowed == [], (
        f"On stock TriageConfig(), `_wire_module_singletons` silently "
        f"AttributeError-swallowed {len(silently_swallowed)} setter(s): "
        f"{silently_swallowed}. Each is a hidden attribute-path or "
        f"import defect (like N-401 for acme). Fix the cfg.<...> path "
        f"in `_wire_module_singletons` to match the actual TriageConfig "
        f"structure, then this pin passes."
    )


def test_triage_config_has_no_acme_attribute_only_via_tls():
    """Pin: guard the shape — TriageConfig deliberately does NOT expose
    `.acme` directly (it's under `.tls.acme`). A future refactor that
    adds `TriageConfig.acme` would allow the pre-fix bare `cfg.acme.*`
    to accidentally work again, silently, without going through TLSConfig.
    """
    cfg = TriageConfig()
    assert not hasattr(cfg, "acme"), (
        "TriageConfig.acme was reintroduced — the wire helper at "
        "config.py::_wire_module_singletons was corrected to `cfg.tls.acme` "
        "on the assumption that no bare `.acme` exists. If this changed "
        "deliberately, update the wire back to `cfg.acme` and delete this pin."
    )
    assert hasattr(cfg.tls, "acme"), "TLSConfig.acme missing — wire path broken."
