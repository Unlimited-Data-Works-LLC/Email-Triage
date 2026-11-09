"""Count-agnostic funnel pin (punch 820): the best-effort provider close has ONE home.

Before this fold three helpers did the same job with three different log levels --
``render_probe.close_provider`` (debug), ``cli._aclose_provider_quietly`` (a WARNING
with the  diagnostic) and ``topic_digest_sender._close_provider`` (a silent
``pass``). Mirrored copies drift (PD#5): the digest one swallowed in silence, the
CLI one could not tolerate a sync ``close()``.

Property over every function in ``src/``: no function OUTSIDE ``providers/render_probe.py``
is a *swallowed-close helper*, meaning one whose whole job is a ``try/except`` around
closing one of its own parameters. "Whole job" is checked by its calls: every call it
makes is in the close vocabulary (``close``/``aclose``/``getattr``/``iscoroutine``/a
logger level/``fmt_exc``) or is a local alias of the closed method. A function that
also does real work (any other call) is a caller, not a helper, and is not flagged.

SCOPE CAVEAT (PD#2): inline ``try: await provider.close()`` inside a larger function
(the sweepers, the push consumers, the agent API) is not a helper and is not covered;
a helper that reaches its provider through an attribute or a dict, not a parameter, is
not followed; and a helper split across two functions is not recognised.
"""

from __future__ import annotations

import ast

from _pin_harness import assert_pin_has_teeth, parse_source, walk_src

SSOT_HOME = "providers/render_probe.py"
SSOT_NAME = "close_provider"
_CLOSE_ATTRS = frozenset({"close", "aclose"})
_VOCAB = frozenset({
    "close", "aclose", "getattr", "iscoroutine", "isawaitable",
    "debug", "info", "warning", "error", "fmt_exc",
})

_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _params(fn) -> set[str]:
    a = fn.args
    names = {p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]}
    return names - {"self", "cls"}


def _is_close_of(call: ast.Call, params: set[str]) -> bool:
    """``<param>.close()`` / ``<param>.aclose()`` or ``getattr(<param>, "close"...)``."""
    f = call.func
    if (isinstance(f, ast.Attribute) and f.attr in _CLOSE_ATTRS
            and isinstance(f.value, ast.Name) and f.value.id in params):
        return True
    return (isinstance(f, ast.Name) and f.id == "getattr" and len(call.args) >= 2
            and isinstance(call.args[0], ast.Name) and call.args[0].id in params
            and isinstance(call.args[1], ast.Constant)
            and call.args[1].value in _CLOSE_ATTRS)


def swallowed_close_helpers(tree: ast.AST) -> list[tuple[str, int]]:
    """``(function name, line)`` of every function whose whole job is a swallowed close."""
    hits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, _FUNCS):
            continue
        params = _params(fn)
        # Local aliases of the closed method (``close = getattr(provider, "close")``).
        aliases = {
            tgt.id for a in ast.walk(fn) if isinstance(a, ast.Assign)
            and isinstance(a.value, ast.Call) and _is_close_of(a.value, params)
            for tgt in a.targets if isinstance(tgt, ast.Name)
        }

        def closes(c: ast.AST) -> bool:
            return isinstance(c, ast.Call) and (
                _is_close_of(c, params)
                or (isinstance(c.func, ast.Name) and c.func.id in aliases))

        closing = [
            t for t in ast.walk(fn) if isinstance(t, ast.Try) and t.handlers
            and any(closes(c) for b in t.body for c in ast.walk(b))
        ]
        if not params or not closing:
            continue
        called = set()
        for c in ast.walk(fn):
            if not isinstance(c, ast.Call):
                continue
            f = c.func
            called.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "?"))
        if called <= (_VOCAB | aliases):
            hits.append((fn.name, fn.lineno))
    return hits


def test_the_provider_close_has_one_home():
    offenders = []
    seen_ssot = False
    for _path, rel, tree in walk_src():
        found = swallowed_close_helpers(tree)
        if rel == SSOT_HOME:
            seen_ssot = [n for n, _ in found] == [SSOT_NAME]
            continue
        offenders += [f"{rel}:{line} {name}" for name, line in found]
    assert seen_ssot, (
        f"the detector no longer sees {SSOT_NAME} in {SSOT_HOME}: the pin is blind"
    )
    assert not offenders, (
        "A second best-effort provider close. Call render_probe.close_provider "
        "(loud=True for a command-line run) instead of keeping a copy:\n  "
        + "\n  ".join(offenders)
    )


def test_detector_has_teeth():
    cli_shape = (
        "async def _aclose(provider):\n"
        "    try:\n        await provider.close()\n"
        "    except Exception as e:\n        log.warning('x', error=fmt_exc(e))\n"
    )
    digest_shape = (
        "async def _close(provider):\n"
        "    try:\n"
        "        close = getattr(provider, 'close', None)\n"
        "        if close is not None:\n"
        "            result = close()\n"
        "            if asyncio.iscoroutine(result):\n                await result\n"
        "    except Exception:\n        pass\n"
    )
    ssot_shape = (
        "async def close_provider(provider):\n"
        "    close = getattr(provider, 'close', None)\n"
        "    if close is None:\n        return\n"
        "    try:\n        result = close()\n"
        "        if asyncio.iscoroutine(result):\n            await result\n"
        "    except Exception as exc:\n        _log.debug('x', error=fmt_exc(exc))\n"
    )
    real_work = (
        "async def fetch_all(provider):\n"
        "    try:\n        rows = await provider.fetch()\n        await provider.close()\n"
        "    except Exception:\n        pass\n"
    )
    no_try = "async def f(provider):\n    await provider.close()\n"
    for src in (cli_shape, digest_shape, ssot_shape):
        assert_pin_has_teeth(swallowed_close_helpers, src)
    for src in (real_work, no_try):
        assert not swallowed_close_helpers(parse_source(src)), src
