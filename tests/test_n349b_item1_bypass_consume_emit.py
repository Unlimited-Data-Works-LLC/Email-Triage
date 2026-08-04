"""N-349b Item 1 R31 structural pin — HMAC clobber bypass consumption
emitter is registered + wired at every callsite (2026-07-07).

Closes the SME panel's §164.312(b) audit-controls gap where the CLI ARM
event emitted an audit row but the CONSUME event fired only a stdlib
`logger.warning`. The 3 census-known watch-HMAC hydration sites
(`agent_api.py:2510`, `profile.py:3543` + :3646) MUST pass a
`bypass_audit_emit` closure over `record_hmac_clobber_bypass_consumed`
so the CONSUME event lands in the HMAC-chained `log_entries` envelope.

WHAT IT PINS (count-agnostic structural):

1. The emitter helper `record_hmac_clobber_bypass_consumed` exists in
   `email_triage.db.audit`, is `@audit_emitter`-tagged (has
   `_is_audit_emitter=True`), and has a keyword-only signature with
   the documented fields.
2. The per-emitter redaction map (`_AUDIT_EMITTER_REDACTION_MAP`) has
   an entry for the helper name — otherwise a write failure would
   emit an unknown-helper gap row with empty payload (safe-fail, but
   the map SHOULD be authored).
3. `get_or_mint_secret` accepts a `bypass_audit_emit` keyword-only
   parameter — a caller-supplied closure invoked after mint+set
   succeed on the operator-armed recovery path.
4. Every callsite passing `bypass_check=` (the bypass-consumption
   surface) ALSO passes `bypass_audit_emit=`. A caller that wires
   bypass_check without bypass_audit_emit would silently ship a
   bypass without a chained audit row — exactly the §164.312(b) gap
   N-349b Item 1 was written to close.

Fn-scope keyed to survive line drift (PD #1 count-agnostic + N-341b
allow-list keying convention).
"""
from __future__ import annotations

import ast
import inspect

from _pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
)


def test_emitter_is_registered():
    """The helper is exported, decorated `@audit_emitter`, and has the
    3 documented keyword-only args."""
    from email_triage.db.audit import (
        record_hmac_clobber_bypass_consumed,
        _AUDIT_EMITTER_REDACTION_MAP,
    )
    # `@audit_emitter` sets `_is_audit_emitter=True` (see
    # `db/audit.py::audit_emitter`). `@db_write` wraps outside, but
    # the attr is on the wrapped fn's underlying obj.
    assert getattr(
        record_hmac_clobber_bypass_consumed, "_is_audit_emitter", False
    ) is True, (
        "record_hmac_clobber_bypass_consumed missing @audit_emitter decoration"
    )
    sig = inspect.signature(record_hmac_clobber_bypass_consumed)
    # conn is positional-or-keyword; the 3 extras are keyword-only.
    assert "conn" in sig.parameters, "missing conn parameter"
    for kw in ("secret_key", "actor_user_id", "watch_id"):
        assert kw in sig.parameters, f"missing {kw!r} keyword arg"
        assert sig.parameters[kw].kind == inspect.Parameter.KEYWORD_ONLY, (
            f"{kw!r} must be keyword-only (matches emitter convention)"
        )
    assert "record_hmac_clobber_bypass_consumed" in _AUDIT_EMITTER_REDACTION_MAP, (
        "record_hmac_clobber_bypass_consumed missing redaction-map entry"
    )
    spec = _AUDIT_EMITTER_REDACTION_MAP["record_hmac_clobber_bypass_consumed"]
    # secret_key + actor_user_id + watch_id are Safe-Harbor-class
    # (typed IDs + operator-namespaced strings) — all IN, no OUT.
    assert spec["in"] == {"secret_key", "actor_user_id", "watch_id"}, (
        f"redaction-map IN mismatch: {spec['in']!r}"
    )
    assert spec["out"] == set(), (
        f"redaction-map OUT should be empty (no PHI-class fields): {spec['out']!r}"
    )


def test_get_or_mint_secret_accepts_bypass_audit_emit():
    """The SSOT signature exposes a bypass_audit_emit parameter so
    callers can wire the emitter without re-implementing the
    guarded-invocation contract."""
    from email_triage.secrets import get_or_mint_secret
    sig = inspect.signature(get_or_mint_secret)
    assert "bypass_audit_emit" in sig.parameters, (
        "get_or_mint_secret missing bypass_audit_emit parameter — "
        "callers cannot wire the N-349b Item 1 audit-emit closure"
    )
    assert sig.parameters["bypass_audit_emit"].kind == inspect.Parameter.KEYWORD_ONLY, (
        "bypass_audit_emit must be keyword-only (matches bypass_check "
        "/ bypass_clear convention)"
    )
    assert sig.parameters["bypass_audit_emit"].default is None, (
        "bypass_audit_emit default must be None (opt-in per callsite)"
    )


def test_all_bypass_check_sites_also_wire_bypass_audit_emit():
    """Count-agnostic sweep: any callsite that passes `bypass_check=`
    to `get_or_mint_secret` MUST also pass `bypass_audit_emit=`.
    Otherwise the CONSUME event lands OUT-of-chain (§164.312(b) gap).

    Uses the `_pin_harness` iter_files + AST walker to stay
    count-agnostic. A NEW callsite that wires bypass without the
    audit-emit closure FIRES this pin at import time.
    """
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Match calls whose kwargs include `bypass_check` —
            # canonical shape for the get_or_mint_secret bypass API.
            # We don't gate on the callee-name (get_or_mint_secret is
            # sometimes imported as `_get_or_mint_secret`); the
            # kwarg-name is the invariant.
            kwarg_names = {
                kw.arg for kw in node.keywords if kw.arg is not None
            }
            if "bypass_check" not in kwarg_names:
                continue
            if "bypass_audit_emit" not in kwarg_names:
                offenders.append(
                    f"{rel}:{node.lineno} — get_or_mint_secret call "
                    "passes bypass_check without bypass_audit_emit "
                    "(§164.312(b) audit-controls gap; N-349b Item 1)"
                )
    assert not offenders, (
        "N-349b Item 1 audit-emit wiring incomplete: every "
        "get_or_mint_secret call that passes bypass_check MUST also "
        "pass bypass_audit_emit so the CONSUME event lands in the "
        "HMAC-chained log_entries envelope. Fix each site or, if a "
        "site legitimately cannot emit (out-of-scope caller), add a "
        "documented allow-list entry to this pin.\n\n"
        + "\n".join(offenders)
    )
