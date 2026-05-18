"""Shared OAuth-HTTP requester for Gmail + O365 providers (#138.4).

Both providers carried a near-identical 30-line ``_request`` method:
look up the cached httpx client, attach the bearer token, fire the
request, on 401 refresh the token once and retry, raise a provider-
specific error class on >=400. The two methods diverged on:

* how the token is acquired (Gmail returns the token from the call;
  O365 historically mutated the client's default ``Authorization``
  header);
* the error class shape (``GmailApiError(status, body, path)`` vs.
  ``GraphError(status, body, path)``).

Phase 2 (#138 phase 2) lifts both ``_request`` bodies onto
:func:`oauth_request`. The auth-attach divergence is solved by a
caller-supplied ``attach_auth(headers, token) -> dict`` callable
that returns the per-request ``headers`` dict — so each provider
stays in charge of its own header dialect, but neither has to
reimplement the 401-refresh-retry loop.

Companion :func:`refresh_lock_for` returns a per-instance
``asyncio.Lock`` used by the providers' refresh paths to prevent
concurrent-refresh thundering herd (#142). The lock lives on the
provider instance; this module only formalises the access pattern.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

logger = logging.getLogger("email_triage.providers._oauth_http")


def refresh_lock_for(provider) -> asyncio.Lock:
    """Lazy-init an ``asyncio.Lock`` on the provider instance.

    Stored as ``_refresh_lock`` — created on first access. The lazy
    init avoids a cross-loop bind issue: ``asyncio.Lock()`` constructed
    at provider ``__init__`` time would bind to whichever loop happened
    to be running at construction (often there's no loop at all in
    test fixtures), and later use from a different loop would error.
    Lazy init binds to the active loop on first acquire.
    """
    lock = getattr(provider, "_refresh_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        provider._refresh_lock = lock
    return lock


async def oauth_request(
    *,
    client,
    method: str,
    path: str,
    refresh_token: Callable[[], Awaitable[str]],
    initial_token: str,
    error_factory: Callable[[int, Any, str], Exception],
    attach_auth: Callable[[dict[str, str], str], dict[str, str]] | None = None,
    params: dict[str, Any] | None = None,
    json_data: Any = None,
    extra_headers: dict[str, str] | None = None,
    on_204_returns: Any = None,
) -> Any:
    """Make an authenticated request with one 401 retry.

    Args:
        client: ``httpx.AsyncClient`` to issue the request on.
        method: HTTP verb (``GET`` / ``POST`` / ``PATCH`` / ``DELETE``).
        path: Path relative to client base, OR absolute URL.
        params: Optional query-string params dict.
        json_data: Optional JSON body for POST / PATCH.
        attach_auth: Callable invoked with ``(headers_dict, token)``
            that mutates / returns the per-request headers dict with
            the provider's auth dialect attached. Default attaches
            ``Authorization: Bearer <token>``. Gmail + O365 both use
            the default — the historical "mutate client default
            headers" path on O365 was load-bearing nowhere and is
            collapsed in #138 phase 2.
        refresh_token: Callable returning a fresh token (awaitable).
        initial_token: Token to try on the first attempt.
        error_factory: Callable returning the provider-specific
            exception class to raise on >=400.
        extra_headers: Optional header dict to merge into the request.
        on_204_returns: Value to return on 204 No Content. Default
            is ``None`` — both providers return None for 204.

    Returns:
        Parsed JSON body, or ``None`` for 204 / empty content.

    Raises:
        ``error_factory(...)``: on >=400 after refresh.
    """
    if attach_auth is None:
        def attach_auth(headers: dict[str, str], token: str) -> dict[str, str]:
            headers["Authorization"] = f"Bearer {token}"
            return headers

    token = initial_token

    for attempt in range(2):
        # Build a fresh headers dict every attempt so a stale token
        # from the prior loop iteration doesn't survive into the
        # retry. ``attach_auth`` writes the dialect-specific keys.
        headers: dict[str, str] = dict(extra_headers) if extra_headers else {}
        attach_auth(headers, token)

        request_kwargs: dict[str, Any] = {"headers": headers}
        if params is not None:
            request_kwargs["params"] = params
        if json_data is not None:
            request_kwargs["json"] = json_data

        resp = await client.request(method, path, **request_kwargs)

        if resp.status_code == 401 and attempt == 0:
            logger.debug(
                "OAuth token rejected; refreshing", extra={"path": path},
            )
            token = await refresh_token()
            continue

        if resp.status_code == 204:
            return on_204_returns
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            raise error_factory(resp.status_code, body, path)

        if not resp.content:
            return None
        try:
            return resp.json()
        except Exception:
            return resp.text

    # Both attempts hit 401 — surface as auth failure.
    raise error_factory(401, "Auth failed after refresh", path)
