"""The bound on a live provider probe made while serving a page (t20; panel X).

``render_probe`` is the SSOT for every probe a request handler reaches, directly
(``web/routers``, through the re-export in ``web/routers/ui/_shared``) or through a helper
such as ``providers/provider_labels.list_provider_labels_for_account``. It lives here, under
``providers/``, so a provider-side helper can use it without importing ``web/``.
Pin: ``tests/test_render_probe_bound_pin.py`` (interprocedural from ``web/routers``).

``probe_session`` is the SSOT for releasing the session a probe opened (punch 694): a handler
that creates a provider only to probe it runs the probe inside ``async with probe_session(p):``
so the session closes on a failed probe too, not only on the happy path.
Pin: ``tests/test_probe_session_close_pin.py``.

The watcher and poller do not use it. Their IMAP budget is the provider's own: ONE combined
10 s budget for the connect, the TLS handshake and the greeting
(``imap_fetch_transport.aioimaplib_wait_hello``), where before t20 the handshake wait and the
greeting wait could take up to 10 s each.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from email_triage._errfmt import fmt_exc
from email_triage.triage_logging import get_logger

_log = get_logger("providers.render_probe")

#: The bound on one render-time probe: connect, greeting and LIST together.
RENDER_PROBE_TIMEOUT_S = 3.0

#: The bound on a probe the user started and is waiting on (the discover scan, punch 693):
#: the provider's own 10 s budget (aioimaplib's ``TIMEOUT_SECONDS``), not the 3 s page-render
#: bound, which would turn a slow server into an error on a scan the user asked for.
USER_SCAN_PROBE_TIMEOUT_S = 10.0


class RenderProbeTimeout(TimeoutError):
    """A render-time provider probe hit its bound."""


async def render_probe(provider, call: str = "list_folders", *,
                       account_id: int | None = None, timeout_s: float | None = None):
    """``await provider.<call>()`` for a page, bounded at ``RENDER_PROBE_TIMEOUT_S`` (or at
    ``timeout_s`` for a probe the user started, see ``USER_SCAN_PROBE_TIMEOUT_S``).

    "Never block the edit flow on a network probe". On its OWN bound it logs once at INFO
    (host:port and the typed ``account_id`` only, no PHI: never the account name or address)
    and raises :class:`RenderProbeTimeout`, a ``TimeoutError``, so each caller's existing
    failure path degrades exactly as it does for any other probe failure. A ``TimeoutError``
    the provider raises itself, before the bound, passes through unchanged and is not logged
    as the bound (panel X NOTE-2 / DA-X1-4)."""
    if timeout_s is None:
        timeout_s = RENDER_PROBE_TIMEOUT_S
    try:
        async with asyncio.timeout(timeout_s) as bound:
            return await getattr(provider, call)()
    except TimeoutError:
        if not bound.expired():
            raise
        host = getattr(provider, "_host", None)
        port = getattr(provider, "_port", None)
        typed_id = account_id if type(account_id) is int else None
        _log.info("render probe bound", host=host, port=port, account_id=typed_id,
                  timeout_s=timeout_s, call=call)
        raise RenderProbeTimeout(
            f"render probe bound: no answer within {timeout_s:g} s") from None


async def close_provider(provider, *, loud: bool = False) -> None:
    """Release ``provider``'s session, best-effort (punch 694): a close that fails is logged
    at debug and never raised, so it can neither mask a probe's own error nor fail a listing
    that succeeded. Tolerates a sync ``close()``.

    ``loud=True`` logs the failure at WARNING instead (punch 820): a command-line run owns
    the provider for its whole life, so a session that will not close is what its operator
    needs to see. It must be awaited in the SAME event loop that drove
    the provider's work (N-131: the client is created lazily in that loop; a second
    ``asyncio.run(provider.close())`` fails ``Event loop is closed`` on every run).

    The ONE best-effort provider close: ``tests/test_provider_close_funnel_pin.py`` fails a
    second helper whose whole job is a swallowed provider close."""
    close = getattr(provider, "close", None)
    if close is None:
        return
    try:
        result = close()
        if asyncio.iscoroutine(result):
            await result
    except Exception as exc:
        if loud:
            # PD#10: `_log` is a TriageLogger; `.warning` does not forward `exc_info`, so the
            # WHY travels as `error=` (a dead `exc_info=True` would log a hollow diagnostic).
            _log.warning("provider.close failed", error=fmt_exc(exc, with_class=True))
        else:
            _log.debug("probe session close failed", error=fmt_exc(exc, with_class=True))


@asynccontextmanager
async def probe_session(provider):
    """Yield ``provider`` and release its session on EVERY exit (punch 694), a failed probe
    included. The one funnel for a handler that creates a provider only to probe it; a caller
    that keeps using the provider afterwards owns the close in its own ``finally`` through
    :func:`close_provider`."""
    try:
        yield provider
    finally:
        await close_provider(provider)
