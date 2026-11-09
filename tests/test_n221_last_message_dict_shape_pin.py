"""N-221 R22 structural pin — state['last_message'] assign shape contract (2026-07-02).

Census R22 (run22 backlog HIGH #2) verified: `_watch_status_recorder.record_
message_result` wrote `state["last_message"] = str(message_id)` (a bare str),
BUT the reader `_aggregate_status` in `web/watcher.py` calls `lm.get("at", "")`
for recency comparison — a str has no `.get()`, so `/watch/status`, `/health`,
and the dashboard chip crashed with `AttributeError` on every account whose
ingestion routed through this SSOT.

Existing `test_n213_watch_status_recorder_pin.py` enforced that callers route
through the SSOT function; it did NOT enforce the SHAPE the SSOT writes.
N-221 adds the shape contract.

WHAT IT PINS (count-agnostic, over-every-site — never `len(X)==N`):

Every assignment of the form `state["last_message"] = <RHS>` MUST have `<RHS>`
be either:
  1. an `ast.Dict` literal (the reader contract's shape), OR
  2. an `ast.Constant(value=None)` (the "no message yet" initializer), OR
  3. a `_watch_status_recorder`-family funnel call whose return type is
     documented dict|None (currently the pin is textual — see caveat).

Also asserts the reader `_aggregate_status.watcher.py` still calls `.get(` on
`last_message` — the shape contract is only load-bearing while the reader
depends on it (anti-vacuity).

SCOPE CAVEAT (honest): the pin doesn't type-check the RHS beyond the AST
node kind — it can't tell a `dict()` builtin call from an unrelated call.
Approved trade: catches every raw-str regression (the actual defect); a
future call-returning-dict would need an allow-list entry.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


def _is_last_message_assign(node: ast.AST) -> ast.Subscript | None:
    """Return the Subscript target if `node` is an assign of `state["last_message"]`."""
    if not isinstance(node, ast.Assign):
        return None
    for tgt in node.targets:
        if not isinstance(tgt, ast.Subscript):
            continue
        # `state["last_message"]` — subscript slice must be Constant("last_message")
        # ast.Subscript.slice at Py 3.9+ is the slice node directly.
        sl = tgt.slice
        if isinstance(sl, ast.Constant) and sl.value == "last_message":
            return tgt
        # Older shape: ast.Index wrapper — 3.8 compat, not needed on this
        # codebase but cheap to keep.
        if isinstance(sl, ast.Index):  # pragma: no cover
            inner = sl.value
            if isinstance(inner, ast.Constant) and inner.value == "last_message":
                return tgt
    return None


def _rhs_is_valid(rhs: ast.AST, *, tree: ast.AST | None = None) -> bool:
    """Valid RHS for `state["last_message"] = ...`: Dict literal, None, or
    a Call whose func name matches a known dict-returning funnel, OR a
    Name bound to a Dict literal earlier in the same module (N-261 R26
    widening — the SSOT now builds `lm = {...}` then assigns
    `state["last_message"] = lm` so optional keys can be added
    conditionally between the two)."""
    if isinstance(rhs, ast.Dict):
        return True
    if isinstance(rhs, ast.Constant) and rhs.value is None:
        return True
    if isinstance(rhs, ast.Name) and rhs.id == "None":  # pragma: no cover
        return True
    # If it's a Call, allow a small set of known dict-returning funnels
    if isinstance(rhs, ast.Call):
        f = rhs.func
        name = (f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None)
        if name in {"dict", "_watch_status_payload"}:
            return True
    # N-261 R26 widening: Name whose id was bound to a Dict literal at
    # module-scope walk. Structural fallback for the "lm = {...}; add
    # optional keys; state['last_message'] = lm" pattern.
    if isinstance(rhs, ast.Name) and tree is not None:
        for n in ast.walk(tree):
            if not isinstance(n, ast.AnnAssign) and not isinstance(n, ast.Assign):
                continue
            targets = ([n.target] if isinstance(n, ast.AnnAssign)
                       else list(n.targets))
            for t in targets:
                if isinstance(t, ast.Name) and t.id == rhs.id:
                    if isinstance(n.value, ast.Dict):
                        return True
    return False


def test_ssot_writes_dict_shape():
    """Anti-vacuity: `_watch_status_recorder.record_message_result` must
    contain at least one `state["last_message"] = <Dict>` assign, else the
    pin has nothing to guard."""
    path = None
    for p in iter_files(SRC_ROOT):
        if relpath(p).endswith("web/_watch_status_recorder.py"):
            path = p
            break
    assert path is not None, "SSOT file _watch_status_recorder.py not found"
    tree = parse_module(path)
    assert tree is not None
    seen = False
    for node in ast.walk(tree):
        tgt = _is_last_message_assign(node)
        if tgt is None:
            continue
        assign = node  # type: ignore[assignment]
        assert isinstance(assign, ast.Assign)
        # N-261 R26: accept either a Dict-literal RHS directly OR a Name
        # bound to a Dict-literal earlier in the same module (the
        # `lm = {...}; state[...] = lm` shape the SSOT now uses so it
        # can add optional keys conditionally between the two assigns).
        if _rhs_is_valid(assign.value, tree=tree):
            seen = True
    assert seen, (
        "N-221 R22 anti-vacuity: SSOT `_watch_status_recorder.record_message_"
        "result` no longer contains a `state['last_message'] = <Dict>` assign. "
        "If the SSOT changed shape, update the pin's valid-RHS list."
    )


def test_all_last_message_assigns_use_dict_shape():
    """Every `state['last_message'] = <RHS>` tree-wide must have a valid RHS."""
    bad: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            tgt = _is_last_message_assign(node)
            if tgt is None:
                continue
            assign = node  # ast.Assign
            if not _rhs_is_valid(assign.value, tree=tree):  # type: ignore[union-attr]
                bad.append(
                    f"{rel}:{assign.lineno} — `state['last_message'] = "
                    f"{type(assign.value).__name__}(...)`; expected Dict "
                    "literal | None | dict()"
                )
    assert not bad, (
        "N-221 R22: `state['last_message'] = <RHS>` must be a Dict literal "
        "matching the reader contract in `_aggregate_status` (which calls "
        "`.get('at', '')` on the value). See `web/_watch_status_recorder.py` "
        "for the canonical shape.\n\n"
        + "\n".join(bad)
    )


def test_reader_still_dict_shape_dependent():
    """Anti-vacuity for the SHAPE contract: the reader in watcher.py must still
    call `.get(` on `last_message` — if it stops depending on dict shape, the
    pin becomes vacuous and should be reconsidered."""
    watcher_path = None
    for p in iter_files(SRC_ROOT):
        if relpath(p).endswith("web/watcher.py"):
            watcher_path = p
            break
    assert watcher_path is not None
    src = watcher_path.read_text(encoding="utf-8", errors="replace")
    # Textual grep for the reader shape; a proper AST walk is cheaper next round.
    assert "last_message" in src and ".get(" in src, (
        "N-221 R22 anti-vacuity: `web/watcher.py::_aggregate_status` no "
        "longer reads `last_message` via `.get(...)`. If it stopped depending "
        "on the dict shape, this pin is no longer load-bearing."
    )
