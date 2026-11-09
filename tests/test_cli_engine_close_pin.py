"""Count-agnostic structural pin (N-132): a cli.py command that builds a
FlowEngine must CLOSE it (engine.aclose()) — else the engine's lazily-created
provider + classifier httpx.AsyncClients leak.

THE BUG THIS CATCHES
====================
``cmd_run`` / polling ``cmd_watch`` / ``_cmd_watch_push`` build
``engine = _build_engine(config)`` and drive it via ``asyncio.run`` WITHOUT ever
closing the engine. FlowEngine owns a provider AND a classifier, each of which
lazily creates an ``httpx.AsyncClient`` in the work loop; never closing the engine
leaks both (the  leak family — the engine-owned sibling of N-131's CLI-direct
provider close). Bounded by the CLI process exit, but the FD churn / leak is real.
Fix: ``FlowEngine.aclose()`` (closes provider + classifier in-loop), awaited in
each command's work coroutine.

This pin: every cli.py function that calls ``_build_engine(...)`` must also
reference ``.aclose()`` — a property over every site, not ``len==N``.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, innermost_fn_at_lineno, parse_module, parse_source

CLI_PATH = SRC_ROOT / "cli.py"
_BUILD_ENGINE = "_build_engine"
_CLOSE_ATTR = "aclose"


def _call_name(call: ast.Call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _references_aclose(fn: ast.AST) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr == _CLOSE_ATTR:
            return True
    return False


def _find_offenders(tree: ast.AST) -> list[tuple[int, str]]:
    """_build_engine calls whose enclosing function does NOT reference .aclose()."""
    # Resolve the enclosing function NODE by line span, never by name: cli.py
    # defines several nested `_run` functions, so a name lookup would check the
    # wrong body.
    offenders: list[tuple[int, str]] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or _call_name(call) != _BUILD_ENGINE:
            continue
        fn = innermost_fn_at_lineno(tree, call.lineno)
        if fn is None:
            continue
        if not _references_aclose(fn):
            offenders.append((getattr(call, "lineno", -1), fn.name))
    return offenders


def test_cli_engine_built_is_closed():
    """No cli.py command builds a FlowEngine without closing it (engine.aclose())."""
    tree = parse_module(CLI_PATH)
    assert tree is not None, f"could not parse {CLI_PATH}"
    offenders = _find_offenders(tree)
    assert not offenders, (
        "cli.py function(s) call _build_engine WITHOUT referencing .aclose() -> the "
        "engine's provider + classifier httpx clients leak (N-132). Await "
        f"engine.aclose() in the work coroutine. Offenders (lineno, fn): {offenders}"
    )


def test_pin_has_teeth():
    """RED on build-without-close; GREEN on build-with-aclose + a non-engine fn."""
    bad = (
        "def cmd_x(config):\n"
        "    engine = _build_engine(config)\n"
        "    asyncio.run(engine.run_cycle('q', 1))\n"
    )
    good = (
        "def cmd_y(config):\n"
        "    engine = _build_engine(config)\n"
        "    async def _r():\n"
        "        try:\n"
        "            return await engine.run_cycle('q', 1)\n"
        "        finally:\n"
        "            await engine.aclose()\n"
        "    asyncio.run(_r())\n"
    )
    no_engine = "def cmd_z(config):\n    db = _cli_open_config_db(config)\n"
    assert _find_offenders(parse_source(bad)), "pin missed a build-without-close"
    for src in (good, no_engine):
        assert not _find_offenders(parse_source(src)), f"pin false-positive:\n{src}"


def test_engine_aclose_closes_provider_and_classifier_log_not_raise():
    """engine.aclose() awaits close() on provider + classifier, and LOGS (never
    raises) if one fails — a teardown error can't mask the command result, and one
    failure can't block closing the other."""
    import asyncio

    from email_triage.engine.flow import FlowEngine

    class _FakeProvider:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    class _FakeBadClassifier:
        async def close(self):
            raise RuntimeError("classifier-close-boom")

    # aclose only touches _provider / _classifier; bypass __init__ to avoid the
    # full dependency graph.
    eng = FlowEngine.__new__(FlowEngine)
    prov = _FakeProvider()
    eng._provider = prov
    eng._classifier = _FakeBadClassifier()

    asyncio.run(eng.aclose())  # must NOT raise despite the classifier failure
    assert prov.closed, "aclose did not close the provider (closed before the failing classifier)"
