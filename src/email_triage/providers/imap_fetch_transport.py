"""IMAP fetch-transport SSOT — the ONE place an IMAP client is constructed
(divergence census run12 #3, the egress-mechanism-agnostic half).

The IMAP message-fetch path pulls full PHI bodies (`BODY.PEEK[]`) over connections
that were each constructed independently at 5 sites — the async provider
(`providers/imap.py`), the three stdlib `imap_blocking` fetch layers (the
aioimaplib-bug Layer-3 fallback), and the dispatcher's connection probe. No
chokepoint meant no single place to see or police the IMAP egress. These two
wrappers are that chokepoint: a raw `imaplib.IMAP4(_SSL)` / `aioimaplib.IMAP4(_SSL)`
construction anywhere ELSE now fails `tests/test_egress_funnel_pin.py`.

★ Behaviour-EXACT by design. The wrappers ONLY reproduce each site's exact
construction (positional vs keyword args, the optional explicit `ssl_context`) —
they add NO logging, policy, or validation. The destination is the operator's
own configured mail server (trusted by config, verified NOT code-injectable —
census run12 #3 LIVE-GAP verdict: no live leak), so there is nothing to gate
today; this module is the SEAM where a future per-server allowlist or
per-fetch PHI-access audit would land, in ONE place, if ever needed.
"""

from __future__ import annotations

import imaplib
from typing import Any


def imap_connect(
    host: str,
    port: int,
    *,
    use_ssl: bool = True,
    ssl_context: Any = None,
) -> imaplib.IMAP4:
    """The SSOT for a SYNC stdlib ``imaplib`` connection (the ``imap_blocking``
    fetch layers + the dispatcher probe). Behaviour-exact: ``IMAP4_SSL(host,
    port[, ssl_context=ctx])`` when ``use_ssl`` (the explicit ``ssl_context`` is
    passed only when the caller supplies one — imaplib otherwise builds its own
    default context), else plain ``IMAP4(host, port)``."""
    if use_ssl:
        if ssl_context is not None:
            return imaplib.IMAP4_SSL(host, port, ssl_context=ssl_context)
        return imaplib.IMAP4_SSL(host, port)
    return imaplib.IMAP4(host, port)


def aioimaplib_connect(host: str, port: int, *, use_ssl: bool = True) -> Any:
    """The SSOT for an ASYNC ``aioimaplib`` connection (``providers/imap.py``).
    Behaviour-exact: ``aioimaplib.IMAP4_SSL(host=…, port=…)`` (keyword args, as the
    site constructs it) when ``use_ssl``, else ``aioimaplib.IMAP4(host=…, port=…)``.
    The caller still drives ``wait_hello_from_server()`` / ``login()`` itself."""
    import aioimaplib

    if use_ssl:
        return aioimaplib.IMAP4_SSL(host=host, port=port)
    return aioimaplib.IMAP4(host=host, port=port)
