"""N-217 R23 structural pin — REDACTED_PLACEHOLDER SSOT ratchet (2026-07-02).

Census R23 flagged 35 bare `"[redacted]"` string literals across 8 files
(actions/digest, actions/digest_render, actions/recipient_digest,
web/email_watches, web/routers/ui/profile, web/routers/ui/triage_classify,
web/triage_one, triage_logging). Naming/drift class — a coordinated
placeholder change (e.g. `[REDACTED]` for a11y contrast, `[hidden]` for
localization) would need 35 replacements + coordinated review.

SSOT: `triage_logging.REDACTED_PLACEHOLDER` (public alias of the pre-N-217
`_REDACTED_PLACEHOLDER`). Every caller-side literal migrates to the
constant; the ratchet ensures we never regress upward.

Ratchet baseline (2026-07-02): 32. Decrements per migration commit
(N-178 pattern).

Waives:
- `triage_logging.py` itself — the SSOT def.
- Docstring / comment text — the pin scopes to `ast.Constant` string
  values only, not source text.
- Test files (`tests/`) — those verify the redaction end-to-end using
  the literal on purpose.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_REDACTED = "[redacted]"
_SSOT_MODULE = "triage_logging.py"
_MAX_RAW_LITERAL = 0  # 2026-07-02 N-217d R23: -6 → CLASS FULLY CONVERGED (all 6 remaining in digest_render.py migrated)


def _find_raw_literals(tree: ast.AST) -> list[int]:
    hits: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and node.value == _REDACTED):
            continue
        hits.append(node.lineno)
    return hits


def test_redacted_literal_ratchet():
    """Every `"[redacted]"` literal outside `triage_logging.py`'s SSOT def
    must trend to zero. Baseline decrements in the SAME commit that migrates
    a callsite (N-178 pattern)."""
    total = 0
    per_file: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == _SSOT_MODULE:
            continue  # SSOT def
        tree = parse_module(path)
        if tree is None:
            continue
        hits = _find_raw_literals(tree)
        if hits:
            total += len(hits)
            per_file.append(f"{rel}: {len(hits)}")
    assert total <= _MAX_RAW_LITERAL, (
        f"N-217 R23: bare `\"{_REDACTED}\"` literal count {total} > "
        f"baseline {_MAX_RAW_LITERAL}. Migrate site + decrement baseline.\n"
        + "\n".join(per_file[:10])
    )
