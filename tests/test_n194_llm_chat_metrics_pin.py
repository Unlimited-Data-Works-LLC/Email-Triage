"""N-194 R20_13 structural pin — LLM chat_complete metrics-timer wrap.

Census run20 R20_13 finding: 12 LLM round-trips emit ZERO `/metrics` — draft_reply,
digest article extraction, discovery loops, safety-detect, 2 topic-match,
style-profile, 3 distill paths + more. Only the CLASSIFY hot path is metered
(`et_llm_classify_seconds` at classify/base.py:642 via `_metrics.timer`).

Fix per census: wrap each chat_complete callsite in
`metrics.timer("et_llm_chat_seconds", backend=..., purpose=...)`. This pin
captures the current baseline of un-metered sites and ratchets it down.
Full ADAPTER-level wrap is N-194b follow-up (4 adapter implementations).

Pin arm: every `await <name>.chat_complete(...)` / `await <name>.complete(...)`
call in a `src/email_triage/{actions,style_learning}/**` file MUST sit inside a
`with metrics.timer("et_llm_chat_seconds", ...)` block — else it's on the
ratchet baseline.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# Ratchet baseline (2026-07-01) — un-metered LLM chat/complete callsites in
# actions/ + style_learning/. Decrement in the SAME commit that adds
# metrics.timer around the call (N-178 commit-coupled pattern).
_MAX_UNMETERED_LLM_CALLS = 6  # 2026-07-01 initial baseline; N-194b landed adapter-level metric wrap 2026-07-02 (base.py::meter_chat_complete decorator applied to all 4 adapters), so callers in actions/ + style_learning/ are AUTO-metered at the adapter body — this ratchet remains at 6 (unchanged) since the callers themselves don't wrap in `metrics.timer`, but the metric IS emitted via the decorator. N-194c follow-up: retire the caller-side pin (adapter-decorator covers it) OR re-key to assert the decorator is applied.

_LLM_METHODS = frozenset({"chat_complete", "complete"})


def _in_metrics_timer_context(fn: ast.AST, call: ast.Call) -> bool:
    """True if `call` is lexically inside a `with metrics.timer("et_llm_chat_seconds", ...)`
    (or `_metrics.timer(...)`) block within `fn`."""
    # Build parent map for this function.
    parent = {}
    for p in ast.walk(fn):
        for c in ast.iter_child_nodes(p):
            parent[id(c)] = p
    cur = call
    while cur is not None:
        cur = parent.get(id(cur))
        if isinstance(cur, ast.With):
            for item in cur.items:
                ctx = item.context_expr
                if not isinstance(ctx, ast.Call):
                    continue
                f = ctx.func
                called = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                if called != "timer":
                    continue
                # First positional arg = histogram name; check it's et_llm_*.
                if ctx.args and isinstance(ctx.args[0], ast.Constant) \
                        and isinstance(ctx.args[0].value, str) \
                        and "et_llm" in ctx.args[0].value:
                    return True
    return False


def _find_unmetered_llm_calls(tree: ast.AST) -> list[int]:
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in _LLM_METHODS:
                continue
            # Only track calls where the receiver Name suggests an adapter/
            # classifier (adapter / classifier / self._adapter — heuristic).
            recv = node.func.value
            recv_name = None
            if isinstance(recv, ast.Name):
                recv_name = recv.id
            elif isinstance(recv, ast.Attribute):
                recv_name = recv.attr
            if recv_name not in {"adapter", "classifier", "self", "_adapter"}:
                continue
            if _in_metrics_timer_context(fn, node):
                continue
            hits.append(node.lineno)
    return hits


def _walk_scope():
    """Files under `src/email_triage/{actions, style_learning}/` — the census-
    flagged surface for R20_13."""
    for sub in ("actions", "style_learning"):
        for path in iter_files(SRC_ROOT / sub):
            yield path


def test_unmetered_chat_complete_ratchet():
    """Every un-metered `.chat_complete` / `.complete` on an adapter/classifier
    receiver in the census-flagged directories must ride the ratchet baseline.
    New callers MUST wrap in `with metrics.timer("et_llm_chat_seconds", ...)`."""
    offenders: list[str] = []
    for path in _walk_scope():
        tree = parse_module(path)
        if tree is None:
            continue
        for ln in _find_unmetered_llm_calls(tree):
            offenders.append(f"{relpath(path)}:{ln}")
    assert len(offenders) <= _MAX_UNMETERED_LLM_CALLS, (
        f"N-194 R20_13 un-metered LLM chat count {len(offenders)} > baseline "
        f"{_MAX_UNMETERED_LLM_CALLS}: " + ", ".join(offenders[:10])
    )


def test_pin_has_teeth():
    """Planted bad + good shapes."""
    bad = ast.parse("""
async def h(adapter):
    return await adapter.chat_complete(msgs)
""")
    hits = _find_unmetered_llm_calls(bad)
    assert hits, f"teeth: bad shape must fire, got {hits}"

    good = ast.parse("""
async def h(adapter):
    with metrics.timer("et_llm_chat_seconds", backend="ollama"):
        return await adapter.chat_complete(msgs)
""")
    hits = _find_unmetered_llm_calls(good)
    assert not hits, f"teeth: good shape must not fire, got {hits}"

    # Aliased `_metrics.timer` also accepted.
    good_alias = ast.parse("""
async def h(adapter):
    with _metrics.timer("et_llm_chat_seconds", backend="ollama"):
        return await adapter.chat_complete(msgs)
""")
    hits = _find_unmetered_llm_calls(good_alias)
    assert not hits, f"teeth: aliased _metrics.timer good shape must not fire"
