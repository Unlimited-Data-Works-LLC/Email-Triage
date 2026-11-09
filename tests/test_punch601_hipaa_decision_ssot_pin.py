"""Punch 601 — structural pin: classify/engine HIPAA decisions read the SSOT, not the raw stamp.

``EmailMessage.hipaa`` defaults to False and no provider sets it, so a HIPAA
decision keyed on the raw stamp fails OPEN on every path that did not stamp it.
Behaviour is pinned in ``test_punch601_classify_hipaa_effective.py``; this file
pins the shape so a new site cannot regress it (count-agnostic: properties over
every site, not a list of the sites fixed today).

Invariants
----------
A. (src-wide) Every ``is_hipaa=`` passed to ``cache_store_for_message`` /
   ``acache_store_for_message`` (any alias or receiver) is a call to
   ``account_hipaa_effective``. That kwarg decides whether the LLM ``reason``
   free text is cached.
B. (``classify/**``, ``engine/flow.py``) No raw read of a ``.hipaa`` attribute
   and no ``getattr(<x>, "hipaa", ...)``. Stores (``message.hipaa = ...``) are
   allowed: they are the stamp.
C. (``engine/flow.py``) Every ``fetch_message(`` call sits inside the
   ``_fetch_message`` funnel, which stamps the effective value.

SCOPE CAVEAT (what a green run does NOT prove)
----------------------------------------------
* B covers only the classify layer and the FlowEngine. The action layer
  (``actions/*``) reads the stamp by design (the SSOT docstring accepts the stamp
  as a convenience); it is correct only where the ingestion path stamped it. The
  stamping paths are ``web/triage_one.py``, ``web/digest.py``, the triage-classify
  Discover loop, ``FlowEngine._fetch_message`` and the topic back-scan; the
  back-scan stamp is pinned behaviourally, not here.
* A follows the kwarg at the call site only. A value computed into a local first
  (``h = account_hipaa_effective(...); store(..., is_hipaa=h)``) is reported, by
  design: keep the call inline so the pin can see it.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    relpath,
    SRC_ROOT,
)

_STORE_FNS = frozenset({"cache_store_for_message", "acache_store_for_message"})
_SSOT = "account_hipaa_effective"
_FUNNEL = "_fetch_message"


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _store_aliases(tree: ast.AST) -> set[str]:
    """Local names bound to a store function (``import ... as x``)."""
    names = set(_STORE_FNS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name in _STORE_FNS and a.asname:
                    names.add(a.asname)
    return names


def store_kwarg_violations(tree: ast.AST) -> list[int]:
    """Invariant A: line numbers of store calls whose ``is_hipaa`` is not the SSOT call."""
    aliases = _store_aliases(tree)
    out: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node.func) in aliases):
            continue
        for kw in node.keywords:
            if kw.arg != "is_hipaa":
                continue
            val = kw.value
            if not (isinstance(val, ast.Call) and _call_name(val.func) == _SSOT):
                out.append(node.lineno)
    return out


def raw_stamp_reads(tree: ast.AST) -> list[int]:
    """Invariant B: line numbers of raw ``.hipaa`` loads / ``getattr(x, "hipaa")``."""
    out: list[int] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr == "hipaa"
                and isinstance(node.ctx, ast.Load)):
            out.append(node.lineno)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in ("getattr", "hasattr") and len(node.args) >= 2
              and isinstance(node.args[1], ast.Constant)
              and node.args[1].value == "hipaa"):
            out.append(node.lineno)
    return out


def unfunneled_fetches(tree: ast.AST) -> list[int]:
    """Invariant C: ``fetch_message(`` calls outside the stamping funnel."""
    out: list[int] = []

    def visit(node: ast.AST, inside: bool) -> None:
        for child in ast.iter_child_nodes(node):
            now_inside = inside or (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == _FUNNEL
            )
            if (isinstance(child, ast.Call) and _call_name(child.func) == "fetch_message"
                    and not now_inside):
                out.append(child.lineno)
            visit(child, now_inside)

    visit(tree, False)
    return out


def _b_scope():
    for path in iter_src_files("classify"):
        yield path
    yield SRC_ROOT / "engine" / "flow.py"


def test_every_cache_store_is_hipaa_comes_from_the_ssot():
    bad: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        bad += [f"{relpath(path)}:{ln}" for ln in store_kwarg_violations(tree)]
    assert not bad, (
        "classification-cache store called with is_hipaa= not computed by "
        f"account_hipaa_effective(...) (punch 601, fail-open on PHI reason): {bad}"
    )


def test_no_raw_hipaa_stamp_read_in_classify_or_flow_engine():
    bad: list[str] = []
    for path in _b_scope():
        tree = parse_module(path)
        if tree is None:
            continue
        bad += [f"{relpath(path)}:{ln}" for ln in raw_stamp_reads(tree)]
    assert not bad, (
        "raw message.hipaa read in the classify layer / FlowEngine; route the "
        f"decision through account_hipaa_effective(message=...) (punch 601): {bad}"
    )


def test_flow_engine_fetches_only_through_the_stamping_funnel():
    path = SRC_ROOT / "engine" / "flow.py"
    tree = parse_module(path)
    assert tree is not None
    bad = unfunneled_fetches(tree)
    assert not bad, (
        "FlowEngine fetches a message outside _fetch_message, so it reaches the "
        f"engine's HIPAA gates unstamped (punch 601): lines {bad}"
    )
    # The funnel must exist and actually stamp via the SSOT (not vacuous).
    funnels = [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == _FUNNEL]
    assert len(funnels) == 1, "FlowEngine._fetch_message funnel missing"
    stamps = [n for n in ast.walk(funnels[0])
              if isinstance(n, ast.Assign) and any(
                  isinstance(t, ast.Attribute) and t.attr == "hipaa" for t in n.targets)
              and isinstance(n.value, ast.Call) and _call_name(n.value.func) == _SSOT]
    assert stamps, "_fetch_message does not stamp message.hipaa from account_hipaa_effective"


def test_pin_has_teeth():
    assert_pin_has_teeth(
        store_kwarg_violations,
        "async def f(m):\n"
        "    await acache_store_for_message(a, b, c, d, e, is_hipaa=bool(m.hipaa))\n",
        "async def f(m):\n"
        "    await acache_store_for_message(a, b, c, d, e,\n"
        "        is_hipaa=account_hipaa_effective(message=m))\n",
    )
    assert_pin_has_teeth(  # aliased import + getattr shape
        store_kwarg_violations,
        "from email_triage.cache.classification import cache_store_for_message as cs\n"
        "def f(m):\n"
        "    cs(a, b, c, d, e, is_hipaa=getattr(m, 'hipaa', False))\n",
    )
    assert_pin_has_teeth(
        raw_stamp_reads,
        "def f(message):\n    if message.hipaa:\n        pass\n",
        "def f(message):\n    message.hipaa = account_hipaa_effective(message=message)\n",
    )
    assert_pin_has_teeth(
        raw_stamp_reads,
        "def f(message):\n    return bool(getattr(message, 'hipaa', False))\n",
    )
    assert_pin_has_teeth(
        unfunneled_fetches,
        "class E:\n"
        "    async def fetch(self, f):\n"
        "        return await self._provider.fetch_message(f.message_id)\n",
        "class E:\n"
        "    async def _fetch_message(self, mid):\n"
        "        m = await self._provider.fetch_message(mid)\n"
        "        m.hipaa = account_hipaa_effective(message=m)\n"
        "        return m\n",
    )
