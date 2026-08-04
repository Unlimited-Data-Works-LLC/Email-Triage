"""run17 #9 — metrics-adoption FUNCTION-keyed pin (observability drift-prevention).

Verify-don't-accept (run17 #9, 2026-06-27) confirmed the census finding: the
triage/classify hot path (the module's raison d'etre) emitted ZERO Prometheus
metrics while the registry (``email_triage.metrics``) already existed and was
adopted on the security edges (auth / csrf / acme). The fix wraps the core
classify model call in ``metrics.timer``. This pin guards against a FUTURE
regression — a new code path that issues the core LLM classify request WITHOUT
timing it, re-opening the latency-creep blind spot.

WHAT IT PINS (count-agnostic, a property over every site — never ``len(X)==N``):
every function that issues the core-classify model call (a ``self._chat_resilient
(...)`` call — the resilient wrapper  that EVERY HTTP chat backend routes core
classify through) references ``metrics.timer`` in the SAME function (incl. its
nested closures), OR is a justified ``rel::funcname`` allow-list entry.

Keying on the ``_chat_resilient`` seam (not the lower ``_chat``, nor the
digest-side ``_chat_topics`` / ``_chat_safety``) targets the CORE classify hot
path precisely: at HEAD exactly ``JsonChatClassifier.classify`` calls it, and the
Ollama ``_chat_resilient`` OVERRIDE delegates to ``_chat`` (not back to
``_chat_resilient``), so the override is not a false target.

SCOPE CAVEAT (honest, R55): asserts a ``metrics.timer`` call is REFERENCED in the
same top-level function as the ``_chat_resilient`` call — it does NOT prove the
timer textually encloses the call on every path, nor does it follow a model call
DELEGATED to a cross-module helper (the interprocedural residual). At HEAD the
timer wraps the call directly in ``classify``; a future refactor that hoists the
call into a helper must keep the timer co-located OR add an allow-list entry.
FUNCTION-keyed (not module-keyed) so a timer in a sibling function can't green-
light an untimed one. Anti-vacuity: ``test_core_llm_call_site_exists`` fails if
the ``_chat_resilient`` seam is renamed/removed (else the pin passes on 0 sites).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, walk_src

SRC = SRC_ROOT

# The core-classify model-call seam. ``JsonChatClassifier.classify`` issues the
# LLM request through ``self._chat_resilient(...)``; keying here (not on the
# lower ``_chat`` nor the digest-side ``_chat_topics`` / ``_chat_safety``)
# targets the CORE classify hot path the census flagged.
_LLM_CALL_ATTRS = frozenset({"_chat_resilient"})

# metrics-module aliases a wrap may bind it under: ``from email_triage import
# metrics`` / ``... as _metrics`` / ``... as metrics_mod``. The wrap call is
# ``<alias>.timer(...)``.
_METRICS_NAMES = frozenset({"metrics", "_metrics", "metrics_mod"})
_TIMER_ATTR = "timer"

# ``rel::funcname`` exemptions — a function that issues the core LLM call but
# legitimately is NOT timer-wrapped. NONE at HEAD. FUNCTION-level (not file-
# level) so an exemption can't mask a sibling. Each future entry needs a reason.
_ALLOWED: frozenset[str] = frozenset()


def _calls_core_llm(node: ast.AST) -> bool:
    """True if the function (incl. nested closures) issues the core-classify
    model call — a ``<x>._chat_resilient(...)`` attribute call anywhere in the
    body (``await`` is transparent to ``ast.walk``)."""
    for n in ast.walk(node):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in _LLM_CALL_ATTRS):
            return True
    return False


def _wraps_in_metrics_timer(node: ast.AST) -> bool:
    """True if the function references a ``<metrics-alias>.timer(...)`` call
    anywhere in its body (incl. nested closures + the ``with`` it heads)."""
    for n in ast.walk(node):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == _TIMER_ATTR
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id in _METRICS_NAMES):
            return True
    return False


def _iter_top_level_functions():
    """Yield ``(rel, qualname, node)`` for every module-level function AND every
    direct method of a module-level class under ``classify/`` — the ``classify``
    SSOT is a ``JsonChatClassifier`` METHOD, so a module-body-only walk would
    miss it. A nested closure stays part of its enclosing unit (the detectors
    ``ast.walk`` into it), matching the function-keyed authz pins. ``qualname``
    is ``Class.method`` or a bare ``func`` (line-stable; survives a line shift)."""
    for _path, rel, tree in walk_src("classify"):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield rel, node.name, node
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        yield rel, f"{node.name}.{sub.name}", sub


def _iter_core_llm_functions():
    """Yield ``(rel, qualname, node)`` for every unit whose body issues the
    core-classify model call."""
    for rel, qual, node in _iter_top_level_functions():
        if _calls_core_llm(node):
            yield rel, qual, node


def _find_violations() -> list[str]:
    violations: list[str] = []
    for rel, qual, node in _iter_core_llm_functions():
        if f"{rel}::{qual}" in _ALLOWED:
            continue
        if not _wraps_in_metrics_timer(node):
            violations.append(
                f"{rel}:{node.lineno} ({qual!r} issues the core LLM classify "
                "call without a metrics.timer in the same function)"
            )
    return violations


def test_core_llm_call_site_is_metrics_timer_wrapped():
    """Every function that issues the core-classify model call wraps it in
    ``metrics.timer`` (run17 #9 hot-path observability). Count-agnostic +
    FUNCTION-keyed."""
    offenders = _find_violations()
    assert offenders == [], (
        "The core LLM classify call is NOT timed (re-opening the latency-creep "
        "blind spot run17 #9 closed):\n  " + "\n  ".join(offenders)
        + "\nWrap the model call in `with metrics.timer(\"et_llm_classify_"
        "seconds\", backend=...):` (the timer is fail-open — telemetry never "
        "breaks a classify), OR add a justified _ALLOWED `rel::funcname` entry."
    )


def test_core_llm_call_site_exists():
    """Anti-vacuity: at least one function must issue the ``_chat_resilient``
    core-classify call — else the seam was renamed/removed and the pin above
    would pass on ZERO sites (vacuous green). If this fails, RE-KEY
    ``_LLM_CALL_ATTRS`` to the new seam, don't delete the guard."""
    sites = list(_iter_core_llm_functions())
    assert sites, (
        "no function issues a `_chat_resilient` core-classify call — the seam "
        "this pin keys on was renamed/removed; re-point _LLM_CALL_ATTRS"
    )


def test_metrics_timer_ssot_still_exists():
    """Guard the load-bearing wrap primitive: ``email_triage.metrics`` must
    still expose ``timer`` (removing it would silently make the wrap a no-op /
    AttributeError)."""
    from email_triage import metrics as _m

    assert hasattr(_m, "timer"), "email_triage.metrics.timer SSOT gone"
    assert hasattr(_m, "histogram") and hasattr(_m, "counter")


def test_pin_has_teeth():
    """A function issuing the core LLM call WITHOUT a timer is flagged; the same
    call wrapped in ``metrics.timer`` (under a metrics alias) is not. A sibling
    function's timer must NOT green-light an untimed one (function-keyed)."""
    bad = ast.parse(
        "async def classify(self):\n"
        "    return await self._chat_resilient(s, u, m)\n"
    ).body[0]
    assert _calls_core_llm(bad) and not _wraps_in_metrics_timer(bad)

    good = ast.parse(
        "async def classify(self):\n"
        "    from email_triage import metrics as _metrics\n"
        "    with _metrics.timer('et_llm_classify_seconds', backend=b):\n"
        "        return await self._chat_resilient(s, u, m)\n"
    ).body[0]
    assert _calls_core_llm(good) and _wraps_in_metrics_timer(good)

    # The plain ``metrics.timer`` alias is recognized too.
    good2 = ast.parse(
        "async def classify(self):\n"
        "    with metrics.timer('x'):\n"
        "        return await self._chat_resilient(s, u, m)\n"
    ).body[0]
    assert _wraps_in_metrics_timer(good2)

    # Function-keyed: a timed sibling does NOT exempt an untimed core-call fn.
    module = ast.parse(
        "async def timed(self):\n"
        "    with metrics.timer('x'):\n"
        "        return await self._chat_resilient(s, u, m)\n"
        "async def untimed(self):\n"
        "    return await self._chat_resilient(s, u, m)\n"
    )
    fns = {n.name: n for n in module.body
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert _wraps_in_metrics_timer(fns["timed"])
    assert _calls_core_llm(fns["untimed"]) and not _wraps_in_metrics_timer(
        fns["untimed"]
    )

    # A NON-core call (digest-side _chat_topics) is out of scope — not a target.
    other = ast.parse(
        "async def classify_with_topics(self):\n"
        "    return await self._chat_topics(p, m)\n"
    ).body[0]
    assert not _calls_core_llm(other)


def test_allow_list_entries_are_real_and_still_offend():
    """PD#7 non-staleness: every ``_ALLOWED`` ``rel::funcname`` must still EXIST,
    issue the core LLM call, and lack a timer — else it was timed/refactored and
    the exemption is dead. (Empty at HEAD → trivially satisfied.)"""
    for entry in _ALLOWED:
        _rel, sep, qual = entry.partition("::")
        assert sep and qual, f"_ALLOWED entry {entry!r} must be 'rel::qualname'"
    present = {
        f"{rel}::{qual}": node
        for rel, qual, node in _iter_top_level_functions()
    }
    seen: set[str] = set()
    for entry in _ALLOWED:
        node = present.get(entry)
        assert node is not None, (
            f"_ALLOWED {entry} no longer exists — drop it"
        )
        assert _calls_core_llm(node) and not _wraps_in_metrics_timer(node), (
            f"_ALLOWED {entry} is no longer an untimed core-LLM-call function "
            "(timed/refactored) — drop the stale exemption"
        )
        seen.add(entry)
    assert seen == set(_ALLOWED), (
        f"_ALLOWED entries not found: {set(_ALLOWED) - seen}"
    )
