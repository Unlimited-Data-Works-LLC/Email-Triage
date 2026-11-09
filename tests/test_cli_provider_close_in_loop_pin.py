"""Count-agnostic structural pin (N-131): a CLI provider must be closed IN-LOOP,
never via a second ``asyncio.run(provider.close())``.

THE BUG THIS CATCHES
====================
A provider's ``httpx.AsyncClient`` is created lazily inside the
``asyncio.run(_run())`` that drives its work (loop1). Closing it from a SEPARATE
``asyncio.run(provider.close())`` runs in a fresh loop2 after loop1 is already
closed -> ``RuntimeError: Event loop is closed`` on EVERY run. Three cli.py
commands shipped this shape (``cmd_style_profile``, ``cmd_sent_mail_index``,
``cmd_watch_push``); the  leak-diagnostic warning fired constantly (drowning
a real leak) and the un-wrapped ``cmd_watch_push`` site even RAISED out of its
finally. It went unpinned because the CLI mine paths were never exercised
end-to-end (the same blind spot as N-129/N-130 — they died earlier on the
encrypted-DB-open / client_id errors before ever reaching close).

Fix: wrap ``_run`` so close is ``await``ed in-loop via
``render_probe.close_provider(provider, loud=True)`` (punch 820 folded the CLI's own
``_aclose_provider_quietly`` onto it).

This pin: no ``asyncio.run(...)`` call in cli.py takes a ``<x>.close(...)`` /
``<x>.aclose(...)`` coroutine as its argument -- a property over every site, not
``len==N``.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, parse_source

CLI_PATH = SRC_ROOT / "cli.py"
_CLOSE_METHODS = {"close", "aclose"}


def _is_close_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CLOSE_METHODS
    )


# Drivers that spin up / drive a FRESH top-level loop. Closing a provider as the
# argument to ANY of these runs in a different loop than the work loop the
# provider's client was created in. The pin must assert the PROPERTY ("no provider
# close is driven by a fresh top-level loop"), not just the `asyncio.run` spelling
# — `loop.run_until_complete(provider.close())` re-introduces the exact N-131 bug
# (devils-advocate N-131).
_FRESH_LOOP_DRIVERS = {"run", "run_until_complete"}


def _is_asyncio_run(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    # asyncio.run(...) / loop.run_until_complete(...) / get_event_loop().run_until_complete(...)
    if isinstance(f, ast.Attribute) and f.attr in _FRESH_LOOP_DRIVERS:
        return True
    if isinstance(f, ast.Name) and f.id in _FRESH_LOOP_DRIVERS:  # from asyncio import run
        return True
    return False


def _find_offenders(tree: ast.AST) -> list[int]:
    """asyncio.run(<x>.close(...)) calls -- a provider closed in its own fresh loop."""
    offenders: list[int] = []
    for node in ast.walk(tree):
        if not _is_asyncio_run(node):
            continue
        if node.args and _is_close_call(node.args[0]):
            offenders.append(getattr(node, "lineno", -1))
    return offenders


def test_cli_provider_closed_in_loop():
    """No cli.py command closes a provider via a second asyncio.run(...close())."""
    tree = parse_module(CLI_PATH)
    assert tree is not None, f"could not parse {CLI_PATH}"
    offenders = _find_offenders(tree)
    assert not offenders, (
        "cli.py closes a provider via asyncio.run(<x>.close()) -- a SECOND event "
        "loop after the work loop closed -> 'Event loop is closed' on every run "
        "(N-131). Close in-loop via close_provider(..., loud=True) inside the work "
        f"coroutine instead. Offending asyncio.run(...) at lines: {offenders}"
    )


def test_pin_has_teeth():
    """RED on the cross-loop close (close + aclose); GREEN on in-loop await + wrapper."""
    bad_close = "import asyncio\nasyncio.run(provider.close())\n"
    bad_aclose = "import asyncio\nasyncio.run(client.aclose())\n"
    # the run_until_complete spelling is the SAME cross-loop bug (DA N-131)
    bad_run_until = "import asyncio\nasyncio.get_event_loop().run_until_complete(provider.aclose())\n"
    good_await = "async def f():\n    await provider.close()\n"  # in-loop await
    good_wrap = "import asyncio\nasyncio.run(_run_and_close())\n"  # close is inside
    good_sync = "conn.close()\n"  # a sync close, not wrapped in a fresh-loop driver
    good_run_work = "import asyncio\nasyncio.get_event_loop().run_until_complete(_run())\n"  # drives work, not a close
    for src in (bad_close, bad_aclose, bad_run_until):
        assert _find_offenders(parse_source(src)), f"pin missed a bad shape:\n{src}"
    for src in (good_await, good_wrap, good_sync, good_run_work):
        assert not _find_offenders(parse_source(src)), f"pin false-positive:\n{src}"


def test_cli_close_swallows_and_awaits():
    """The CLI's close awaits close on success and LOGS (never raises) on failure."""
    import asyncio

    from email_triage.providers.render_probe import close_provider

    class _BadProvider:
        async def close(self):
            raise RuntimeError("Event loop is closed")

    # Must NOT raise -- it logs the  warning instead of masking the exit code.
    asyncio.run(close_provider(_BadProvider(), loud=True))

    class _GoodProvider:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    p = _GoodProvider()
    asyncio.run(close_provider(p, loud=True))
    assert p.closed, "close_provider did not await provider.close()"


def test_cli_close_logs_the_why_not_dead_exc_info(caplog):
    """N-131/PD#10: the close-failure WARNING must carry the exception detail
    (error=fmt_exc), NOT a dead `exc_info=True` that TriageLogger.warning silently
    drops -> a hollow diagnostic that logs the symptom but never the cause.
    (db-sme N-131 — the original test only checked no-raise + awaited, so it would
    NOT have caught the hollow exc_info.)"""
    import asyncio
    import logging

    from email_triage.providers.render_probe import close_provider

    class _BadProvider:
        async def close(self):
            raise RuntimeError("simulated-close-boom-xyz")

    with caplog.at_level(logging.WARNING, logger="email_triage.providers.render_probe"):
        asyncio.run(close_provider(_BadProvider(), loud=True))  # must not raise

    recs = [r for r in caplog.records if "provider.close failed" in r.getMessage()]
    assert recs, "expected a 'provider.close failed' WARNING record"
    # The exception detail (the WHY) must surface somewhere on the record — the
    # rendered message OR a structured field. A dead exc_info=True carries none.
    blob = " ".join(
        r.getMessage() + " " + " ".join(f"{k}={v}" for k, v in vars(r).items())
        for r in recs
    )
    assert "simulated-close-boom-xyz" in blob or "RuntimeError" in blob, (
        "close-failure WARNING carried NO exception detail — the #275 diagnostic "
        "is hollow (TriageLogger.warning ignores exc_info; use error=fmt_exc(e))"
    )
