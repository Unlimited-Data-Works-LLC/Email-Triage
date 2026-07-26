"""the backlog  sub-item — run_id / correlation-id SSOT pin.

Structural + cross-module: no ``f"..._{int(time.time())}"`` (or the
``str(int(time.time()))`` variants) may appear in ``run_id=`` slots
across ``src/email_triage``. Route through
``_ids.new_run_id(kind, account_id, *extra)`` — the SSOT with a
collision-free random tail (Census v3 re-run #6 — second-precision
epoch is COLLIDABLE at load; two ingestion terminals firing in the
same second minted duplicate run_ids, breaking triage_runs
observability for a burst).

Prime Directive #6: routes through the shared ``_pin_harness``
walker.

Scope: bans ``int(time.time())`` string-concatenation shapes anywhere
in src outside the SSOT. Bounded because the collision problem is
per-second, not per-tick; a plain ``time.time()`` (float) inside a
non-string context is unrelated to correlation IDs and NOT flagged.
"""
from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, relpath


_SSOT_RELPATH = "_ids.py"

# Named deviations — sites where an ``int(time.time())`` string is
# semantically NOT a triage-run correlation ID (so the census 
# collision-at-load hazard does not apply). Each entry names WHY the
# shape is safe here.
#  (2026-07-11): migrated from line-anchored `(rel, lineno)` to
# name-anchored `(rel, enclosing_fn)` per feedback_divergence_audit_
# and_ssot_pin. The prior key `(_shared.py, 5082)` drifted to `5086`
# then to `5084` across three sessions as unrelated code shifted
# lines; name-anchoring on `enclosing_fn` survives line shifts.
_NAMED_DEVIATIONS: dict[tuple[str, str], str] = {
    # `_shared.py::_parse_raw_email` — synthetic Message-ID fallback
    # for a message pasted into the classify-test UI with no
    # RFC-standard `Message-ID:` header. This is an RFC-5322 message
    # identifier, NOT a run correlation ID; second-precision
    # collisions do not cause triage_runs duplicates (there IS no
    # triage_runs row for a paste-preview classify).
    ("web/routers/ui/_shared.py", "_parse_raw_email"): "classify-test synthetic Message-ID",
}


def _is_int_time_time_call(node: ast.AST) -> bool:
    """Return True if `node` is `int(time.time())`."""
    if not isinstance(node, ast.Call):
        return False
    if not (isinstance(node.func, ast.Name) and node.func.id == "int"):
        return False
    if len(node.args) != 1:
        return False
    inner = node.args[0]
    if not isinstance(inner, ast.Call):
        return False
    f = inner.func
    if isinstance(f, ast.Attribute):
        return (
            f.attr == "time"
            and isinstance(f.value, ast.Name)
            and f.value.id == "time"
        )
    return False


def _fstring_contains_int_time(node: ast.JoinedStr) -> bool:
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            if _is_int_time_time_call(part.value):
                return True
    return False


def test_no_int_time_time_in_fstring_outside_ssot():
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel.endswith(_SSOT_RELPATH):
            continue
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.JoinedStr)
                    and _fstring_contains_int_time(node)):
                continue
            if (rel, enclosing_fn(node)) in _NAMED_DEVIATIONS:
                continue
            offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "Census  run_id-SSOT: f-string embedding "
        "`{int(time.time())}` outside `_ids.py` — second-precision "
        "epoch is collidable at load. Route through "
        "`_ids.new_run_id(kind, account_id, *extra)` for a "
        "collision-free correlation ID:\n\n" +
        "\n".join(offenders)
    )
