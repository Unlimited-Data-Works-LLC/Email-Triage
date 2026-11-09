"""IMAP fetch-transport SSOT — the ONE place an IMAP client is constructed
(divergence census run12 #3, the egress-mechanism-agnostic half).

The IMAP message-fetch path pulls full PHI bodies (`BODY.PEEK[]`) over connections
that were each constructed independently at 5 sites — the async provider
(`providers/imap.py`), the three stdlib `imap_blocking` fetch layers (the
aioimaplib-bug Layer-3 fallback), and the dispatcher's connection probe. No
chokepoint meant no single place to see or police the IMAP egress. These two
wrappers are that chokepoint: a raw `imaplib.IMAP4(_SSL)` / `aioimaplib.IMAP4(_SSL)`
construction anywhere ELSE now fails `tests/test_egress_funnel_pin.py`.

★ Certificate checking is the one policy these wrappers apply (punch 651, N-119;
operator modes 2026-10-21). Every SSL connection runs under the account's
:class:`email_triage.tls.CertPolicy` (``cert_check`` / ``cert_enforce``: the
account's own setting, else the global ``outbound_tls`` one):

* check off: connect without validating (setup and troubleshooting mode);
* check on, enforce off (validate-only): validate the certificate and hostname;
  on a failure ``email_triage.tls`` logs one ``tls_cert_check_failed`` WARNING
  and the connection goes ahead unverified;
* check on, enforce on (the default): validate, and refuse the connection on
  failure (``tls.CertCheckRefused``, naming the host) before ``login``.

Before punch 651, ``imap_connect`` built a bare ``imaplib.IMAP4_SSL(host, port)``
(CERT_NONE, no check and no log). TLS itself is still selectable per account
(``use_ssl=False`` builds plain ``IMAP4``), tracked as N-625. §164.312(e)(1);
NIST SP 800-52r2 §4.5.1. Pin: ``tests/test_punch645_client_tls_context_pin.py``.

No allowlist or audit is added here. The destination is the operator's own
configured mail server (census run12 #3 LIVE-GAP verdict: no live leak); a
per-server allowlist or per-fetch PHI-access audit would land here, in ONE place,
if ever needed.
"""

from __future__ import annotations

import asyncio
import functools
import imaplib
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.tls import CertPolicy, guard_caller_tls, tls_connect, tls_connect_async
from email_triage.triage_logging import get_logger

_log = get_logger("providers.imap_fetch_transport")


def imap_connect(
    host: str,
    port: int,
    *,
    use_ssl: bool = True,
    ssl_context: Any = None,
    cert_policy: CertPolicy | None = None,
) -> imaplib.IMAP4:
    """The SSOT for a SYNC stdlib ``imaplib`` connection (the ``imap_blocking``
    fetch layers + the dispatcher probe). When ``use_ssl``: ``IMAP4_SSL(host,
    port, ssl_context=ctx)`` under ``cert_policy`` (default: the global one) via
    ``tls.tls_connect``, or with the caller's own ``ssl_context``, guarded
    (``tls.guard_caller_tls``, cycle P DA P4-4: the distrusted-key chain check
    applies to it too); else plain ``IMAP4(host, port)``. The result carries
    ``_et_cert_verdict``."""
    if not use_ssl:
        return imaplib.IMAP4(host, port)
    if ssl_context is not None:
        return imaplib.IMAP4_SSL(host, port, ssl_context=guard_caller_tls(ssl_context))
    return tls_connect(
        lambda ctx: imaplib.IMAP4_SSL(host, port, ssl_context=ctx),
        host=host, port=port, protocol="imap", policy=cert_policy,
    )


def _aioimaplib_timeout(mod: Any) -> float:
    """aioimaplib's own command timeout (``IMAP4.TIMEOUT_SECONDS``, 10 s in
    2.0.1), the same default the client applies to its hello."""
    value = getattr(getattr(mod, "IMAP4", None), "TIMEOUT_SECONDS", None)
    return float(value) if isinstance(value, (int, float)) else 10.0


async def aioimaplib_connect(
    host: str,
    port: int,
    *,
    use_ssl: bool = True,
    cert_policy: CertPolicy | None = None,
    timeout: float | None = None,
) -> Any:
    """The SSOT for an ASYNC ``aioimaplib`` connection (``providers/imap.py``).
    When ``use_ssl``: ``aioimaplib.IMAP4_SSL(host=…, port=…, ssl_context=ctx)``
    under ``cert_policy`` via ``tls.tls_connect_async``, which awaits the
    client's own connection task (aioimaplib 2.x ``_client_task``: its handshake
    runs there, and a failed verification otherwise shows up only as a hello
    timeout); else ``aioimaplib.IMAP4(host=…, port=…)``. If a future aioimaplib
    drops that attribute there is no verdict to read and the verifying client is
    returned as is. The caller waits for the greeting with
    :func:`aioimaplib_wait_hello` and drives ``login()`` itself. If the caller is
    cancelled during the handshake wait (a render-probe bound), the client it will
    never receive goes to :func:`aioimaplib_discard` (panel X db SHOULD-2)."""
    import aioimaplib

    if use_ssl:
        return await tls_connect_async(
            lambda ctx: aioimaplib.IMAP4_SSL(host=host, port=port, ssl_context=ctx),
            host=host, port=port, protocol="imap", policy=cert_policy,
            handshake=lambda client: getattr(client, "_client_task", None),
            # Panel M T7: wait as long as the client itself would (aioimaplib's
            # own TIMEOUT_SECONDS unless the caller passes its timeout).
            timeout=timeout if timeout is not None else _aioimaplib_timeout(aioimaplib),
            discard=aioimaplib_discard,
        )
    return aioimaplib.IMAP4(host=host, port=port)


def _close_transport(client: Any, _task: Any = None) -> None:
    """Best-effort close of an aioimaplib client's transport (none yet: nothing to do)."""
    try:
        transport = getattr(getattr(client, "protocol", None), "transport", None)
        if transport is not None:
            transport.close()
    except Exception as exc:
        _log.debug("IMAP transport close failed", error=fmt_exc(exc))


def aioimaplib_discard(client: Any) -> None:
    """Close a client from :func:`aioimaplib_connect` that nobody will use: a connect
    that failed or was cancelled before ``login`` finished (panel X DA-X1-1). Sync and
    best-effort, so it is safe on a cancellation path. A connection task that is still
    running (cancelled mid-connect, db SHOULD-2 (i)) gets at most one more aioimaplib
    budget, so a certificate failure it ends in is still logged by the M-DA-7
    done-callback, and is then cancelled, which closes its socket; without that the
    socket stayed open until asyncio's own 60 s handshake timeout. Its transport is
    closed when the task lands."""
    import aioimaplib

    task = getattr(client, "_client_task", None)
    if isinstance(task, asyncio.Future) and not task.done():
        task.add_done_callback(functools.partial(_close_transport, client))
        task.get_loop().call_later(_aioimaplib_timeout(aioimaplib), task.cancel)
    else:
        _close_transport(client)


async def aioimaplib_wait_hello(client: Any, *, started: float,
                                timeout: float | None = None) -> None:
    """Wait for the server greeting of a client from :func:`aioimaplib_connect`
    inside ONE budget that began when the connect did. ``started`` is the running
    loop's ``time()`` taken before the connect; ``timeout`` is aioimaplib's own
    ``TIMEOUT_SECONDS`` unless given (panel M T7).

    Two waits used to run back to back (t20). ``tls_connect_async`` waits up to the
    budget for the handshake and, when that wait times out, returns the client
    (panel M M-DA-7); the client's ``wait_hello_from_server()`` then waited a full
    budget again, so an unreachable server cost 10 s + 10 s. And a connection that
    had already FAILED (refused, unknown name, reset) was invisible to the hello,
    which waited out its budget and reported a timeout in place of the error. Here
    the greeting gets only what is left of the budget, and a failed connection task
    (aioimaplib 2.x ``_client_task``) raises its own exception at once. A
    certificate failure after the handshake wait is logged once by the M-DA-7
    done-callback either way. It reaches the caller as that error, not as a timeout,
    only while budget remains; once the budget is spent the caller gets the timeout."""
    import aioimaplib

    loop = asyncio.get_running_loop()
    budget = timeout if timeout is not None else _aioimaplib_timeout(aioimaplib)
    deadline = started + budget
    hello = asyncio.ensure_future(client.wait_hello_from_server())
    task = getattr(client, "_client_task", None)
    waiting = {hello}
    if isinstance(task, asyncio.Future):
        waiting.add(task)
    try:
        while True:
            done, _ = await asyncio.wait(
                waiting, timeout=max(0.0, deadline - loop.time()),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if hello in done:
                return hello.result()
            if not done:
                raise asyncio.TimeoutError(
                    f"IMAP server greeting not received within {budget:g} s")
            waiting.discard(task)
            if not task.cancelled() and task.exception() is not None:
                raise task.exception()
    finally:
        if not hello.done():
            hello.cancel()
