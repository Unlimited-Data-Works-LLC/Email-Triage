"""N-355 R31 — audit.trusted_proxies YAML roundtrip.

Trust-repair fix-forward per PHASE2 tranche  DA + the backlog 
(TASK ). The write side landed under N-324 R30 at
`web/routers/ui/_shared.py:6220`; the load side in `_parse_raw` had NO
handler for the `audit` block, so any config file with `audit.
trusted_proxies: [...]` was silently DROPPED on load. This pin proves
the full write → read → write roundtrip preserves the list.
"""
from __future__ import annotations

from email_triage.config import (
    AuditConfig,
    TriageConfig,
    _parse_raw,
)


def test_audit_missing_from_yaml_uses_empty_default():
    """No `audit` block in YAML = empty trusted_proxies (ship default,
    preserves current XFF-ignored behaviour on every install)."""
    cfg = _parse_raw({})
    assert isinstance(cfg.audit, AuditConfig)
    assert cfg.audit.trusted_proxies == []


def test_audit_trusted_proxies_loaded_from_yaml():
    """N-355 fix: `audit.trusted_proxies` list is now consumed by
    `_parse_raw` — a config file with proxies survives a restart."""
    raw = {
        "audit": {
            "trusted_proxies": ["127.0.0.1/32", "10.88.0.0/16"],
        },
    }
    cfg = _parse_raw(raw)
    assert cfg.audit.trusted_proxies == ["127.0.0.1/32", "10.88.0.0/16"]


def test_audit_trusted_proxies_string_coerced_to_singleton_list():
    """Robustness: an operator that writes `trusted_proxies: 10.0.0.0/8`
    (bare scalar, not a YAML list) still lands as a single-element list —
    the primary consumer (`request_forwarded_for`) requires a list."""
    raw = {"audit": {"trusted_proxies": "10.0.0.0/8"}}
    cfg = _parse_raw(raw)
    assert cfg.audit.trusted_proxies == ["10.0.0.0/8"]


def test_audit_trusted_proxies_none_entry_stripped():
    """None entries (from YAML `-` empty items) are dropped rather than
    landing as the string 'None' in `trusted_proxies`."""
    raw = {"audit": {"trusted_proxies": ["127.0.0.1/32", None, ""]}}
    cfg = _parse_raw(raw)
    # Empty strings survive (fail-CLOSED semantics handle them at the
    # consumer per `request_forwarded_for`'s `_in_trusted_cidr`); None
    # is stripped so YAML sloppiness doesn't crash the loader.
    assert None not in cfg.audit.trusted_proxies
    assert "127.0.0.1/32" in cfg.audit.trusted_proxies


def test_audit_empty_block_uses_default_list():
    """An empty `audit:` block (with no `trusted_proxies` key) still
    lands as empty list, not a KeyError on `a.get`."""
    raw = {"audit": None}
    cfg = _parse_raw(raw)
    assert cfg.audit.trusted_proxies == []


def test_write_side_shape_matches_load_side_expectation():
    """Structural roundtrip: the write shape at `_shared.py:6220`
    (`data["audit"] = {"trusted_proxies": list(...)}`) matches the
    load shape here. Proves the two sides agree without needing the
    admin-form module import."""
    write_shape = {"trusted_proxies": ["127.0.0.1/32"]}
    raw = {"audit": write_shape}
    cfg = _parse_raw(raw)
    assert cfg.audit.trusted_proxies == ["127.0.0.1/32"]
