"""Shared test helper: hold ONE TestClient event loop across request(s) and
the wait that follows them (punch 577; DA F569-11 shared-helper fold).

Import as ``from _portal_loop import _one_portal_loop`` (``tests`` is on
``pythonpath``). ``tests/test_no_cross_loop_audit_drain_pin.py`` keys on
``with _one_portal_loop(`` — keep the name.
"""

from __future__ import annotations

import contextlib

import anyio


@contextlib.contextmanager
def _one_portal_loop(client):
    """Run every ``client`` request in the block on ONE event loop that
    outlives the responses, so a wait inside the block (an audit drain, a
    background-task poll) still has a live loop driving the work.

    Mechanism: a TestClient used WITHOUT ``with client:`` gets a fresh
    anyio portal loop per request, and that loop closes as the response
    returns. Closing it cancels any fire-and-forget task the request spawned
    (e.g. the access-audit middleware's write) that has not yet dispatched
    its work to a thread -> the row never lands and the drain times out.
    ``TestClient._portal_factory`` reuses ``client.portal`` whenever it is
    set, so pinning it here keeps one loop alive for every request in the
    block and through the wait, as uvicorn's single loop does in
    production.

    ``with client:`` itself is not used: it enters the app lifespan, which
    re-opens the DB from config and fails closed without ``sqlcipher3``.

    If ``client.portal`` is already set (the caller is inside
    ``with client:``), that portal is already the one loop and is reused.
    On exit the PRIOR ``client.portal`` is restored (F577-3), never forced
    to ``None``.
    """
    prior = client.portal
    if prior is not None:
        yield client
        return
    with anyio.from_thread.start_blocking_portal(**client.async_backend) as portal:
        client.portal = portal
        try:
            yield client
        finally:
            client.portal = prior
