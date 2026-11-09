""" -- `time.time() - t0` duration ratchet pin.

`time.time()` returns POSIX wall-clock time, which can go BACKWARDS
under NTP correction or manual system-clock adjustment. A duration
computed via `time.time() - t0` can then be NEGATIVE or LARGER-THAN-
REAL, corrupting observability metrics + rate-limit / retry back-off
calculations. `time.monotonic()` guarantees no backwards travel --
the correct primitive for duration measurement.

This pin is a RATCHET: the 9 pre-#143 `(rel, enclosing_fn)` pairs at
2026-07-11 baseline are grandfathered; NEW `time.time() - time.time()`
subtraction shape in a fn NOT in baseline fails CI. As sites migrate
onto `time.monotonic()` pairs, baseline shrinks via
`test_baseline_never_grows`.

Prime Directive #6: routes through `_pin_harness`. Name-anchored per
 R38.

Grounding: 2026-07-11 direct AST walker detected `ast.BinOp(op=Sub)`
with `time.time()` on either side in 9 unique (rel, async_fn or fn)
pairs across `src/email_triage/**/*.py`.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


# Baseline: 9 unique `(rel, enclosing_fn)` pairs at HEAD `ac54e1f2`.
# Each has at least one `time.time() - <expr>` or `<expr> - time.time()`
# subtraction inside the fn body -- typically the elapsed-time paired
# with a matching `t0 = time.time()` above. The (rel, fn) is
# grandfathered; NEW sites in different fns must migrate to
# `time.monotonic()`.
_BASELINE_TIME_TIME_DIFF: frozenset[tuple[str, str]] = frozenset({
    # ("web/gmail_push_auth.py", "_expired") PRUNED 2026-09-29 by punch 548:
    # `_CertCache` moved every duration base onto `time.monotonic()` (the
    # JWKS rate gate must not open early under an NTP step), so the pair no
    # longer contains the banned shape and `test_baseline_never_grows`
    # requires the entry to go. The historical "9 pairs" count in this
    # module's docstring is the 2026-07-11 measurement and is left as-is.
    ("web/ingestion_push.py", "_process_office365_push_item"),
    ("web/ingestion_push.py", "_process_push_item"),
    ("web/poll_ingestion.py", "_poll_once_office365"),
    ("web/routers/ui/triage_classify.py", "classify_run"),
    ("web/routers/ui/triage_classify.py", "discover_run"),
    ("web/triage_runner.py", "run_triage"),
    ("web/watcher.py", "_watch_account"),
})


def _is_time_time_call(node: ast.AST) -> bool:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr != "time":
        return False
    v = node.func.value
    return isinstance(v, ast.Name) and v.id == "time"


def _enclosing_fn(node: ast.AST, tree: ast.Module) -> str:
    best_name = "<module>"
    best_start = -1
    for c in ast.walk(tree):
        if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        c_start = c.lineno
        c_end = getattr(c, "end_lineno", c_start) or c_start
        if c_start <= node.lineno <= c_end and c_start > best_start:
            best_name = c.name
            best_start = c_start
    return best_name


def _collect_offenders() -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)):
                continue
            if not (_is_time_time_call(node.left)
                    or _is_time_time_call(node.right)):
                continue
            out.add((rel, _enclosing_fn(node, tree)))
    return out


def test_no_new_time_time_diff_outside_baseline():
    """Ban NEW `time.time() - <expr>` OR `<expr> - time.time()` in
    an (rel, fn) pair NOT in the 2026-07-11 baseline. Use
    `time.monotonic()` (with a paired `t0 = time.monotonic()`) for
    duration measurement -- monotonic never travels backwards under
    NTP correction. If a genuinely wall-clock-driven use case
    exists, add `(rel, enclosing_fn)` to `_BASELINE_TIME_TIME_DIFF`
    with a justification comment."""
    fresh = _collect_offenders() - _BASELINE_TIME_TIME_DIFF
    assert not fresh, (
        "#143 time.time() duration ratchet: NEW `time.time() - <expr>` "
        "in a (rel, fn) pair NOT in baseline. `time.time()` can go "
        "backwards under NTP correction; use `time.monotonic()` for "
        "duration measurement.\n\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(fresh))
    )


def test_baseline_never_grows():
    """Strict-shrink: baseline entries whose (rel, fn) no longer
    contains the `time.time() - <expr>` shape MUST be pruned so the
    ratchet ratchets."""
    live = _collect_offenders()
    stale = _BASELINE_TIME_TIME_DIFF - live
    assert not stale, (
        "#143 time.time() duration ratchet: baseline shrunk -- prune "
        "the following (rel, fn) pairs from `_BASELINE_TIME_TIME_DIFF` "
        "(their time.time-diff has been removed):\n\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(stale))
    )
