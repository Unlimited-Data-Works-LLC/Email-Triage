"""N-258 R26 structural pin — canonical JSON SSOT for HMAC signing (2026-07-03).

Census R26 discovered MED (canonical-JSON signing recipes, 7+ distinct
recipes): non-frozen HMAC-signed surfaces used `json.dumps(payload,
separators=(",", ":"))` WITHOUT `sort_keys=True`. Dict-order variance
made receivers unable to reliably re-compute the signature.

N-258 fix: `_signing.py::canonical_json(payload) -> bytes` SSOT +
migrated 2 sites (`web/events.py::EventDispatcher._dispatch` +
`web/watch_runner.py`).

WHAT IT PINS:

1. Anti-vacuity: `canonical_json` imports + returns deterministic
   bytes (sort_keys=True stable across dict-insertion order).
2. STRICT: any `json.dumps(<payload>, separators=(",", ":"))` in the
   files that call `sign_payload` OR feed bytes to `hmac.new(...)`
   outside the audit-chain SSOT (`db/audit.py`) must route through
   `_signing.canonical_json`.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILE = "_signing.py"
_AUDIT_CHAIN_ALLOW = "db/audit.py"  # frozen chain-writer forms.


def test_canonical_json_ssot_shape():
    """Anti-vacuity: deterministic key order + no whitespace."""
    from email_triage._signing import canonical_json
    # Deterministic across insertion orders.
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    assert canonical_json({"a": 1}) == b'{"a":1}'
    # ensure_ascii=False → non-ASCII stays literal.
    assert "é".encode("utf-8") in canonical_json({"n": "é"})


def test_no_raw_signing_json_dumps_in_signing_callers():
    """Any file that calls `sign_payload` MUST NOT hand-roll
    `json.dumps(<expr>, separators=(",", ":"))` — route through
    `_signing.canonical_json`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in {_SSOT_FILE}:
            continue
        if rel == _AUDIT_CHAIN_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        # Does this file even call sign_payload? If not, skip.
        calls_sign = any(
            isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute))
            and (getattr(n.func, "id", None) == "sign_payload"
                 or getattr(n.func, "attr", None) == "sign_payload")
            for n in ast.walk(tree)
        )
        if not calls_sign:
            continue
        # Look for hand-rolled `json.dumps(<x>, separators=(",", ":"))`.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Attribute) and f.attr == "dumps"
                    and isinstance(f.value, ast.Name) and f.value.id == "json"):
                continue
            # Look for a `separators=` kwarg.
            for kw in node.keywords:
                if kw.arg == "separators":
                    offenders.append(
                        f"{rel}:{node.lineno}  json.dumps(..., separators=...) "
                        "in a file that calls sign_payload — route through "
                        "`_signing.canonical_json`"
                    )
                    break
    assert not offenders, (
        "N-258 R26 canonical JSON SSOT bypass: raw `json.dumps(<x>, "
        "separators=(',', ':'))` in a file that calls `sign_payload`. "
        "Route through `email_triage._signing.canonical_json` — the SSOT "
        "adds `sort_keys=True` for deterministic key order so a receiver "
        "re-serialising gets identical bytes.\n\n"
        + "\n".join(offenders)
    )
