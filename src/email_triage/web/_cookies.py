"""Cookie-security SSOT (N-200 — census run22 discovery, 2026-07-02).

Single decision surface for the `Secure` flag on every server-side
`response.set_cookie(...)` call across the web tree. The pre-N-197
formula
    secure = bool(getattr(config, "tls", None).enabled)
misses the reverse-proxy topology (nginx terminates TLS on :443 and
forwards plain HTTP to uvicorn on :8080), so `config.tls.enabled` is
False even though the client-server hop IS HTTPS. A cookie without
`Secure` on an HTTPS session is a same-site downgrade credential leak
(§164.312(e)(1) — encryption-in-transit for e-PHI-adjacent auth
material).

N-197 fixed the dev-keypair-challenge cookie in-line. Run22 census
discovered three sibling sites still on the OLD formula: the session
cookie (`auth.py`), the CSRF cookie (via `api.py`), and the passkey
challenge cookie (`auth_keys.py`). This module centralises the
decision so every `set_cookie` call site routes through one SSOT and
future cookie additions inherit the correct posture.

Formula: `is_request_https = (request.url.scheme == "https") OR
config.tls.enabled`. The OR gives us both the direct-uvicorn HTTPS
listener (config.tls.enabled path) AND the nginx-front topology
(request.url.scheme='https' set via `X-Forwarded-Proto` when
uvicorn is invoked with `--proxy-headers`). Either signal is
sufficient — a `False` from one does NOT poison the other.

Pin: `tests/test_n200_cookie_secure_flag_ssot_pin.py` bans a raw
`secure=<literal>` or `secure=<config.tls.enabled-only-expr>` in
`web/**` — every cookie-secure decision MUST come through
`is_request_https(request, config)`.
"""
from __future__ import annotations

from typing import Any


def is_request_https(request: Any, config: Any = None) -> bool:
    """Return True when the current request-response hop should carry
    `Secure` on server-set cookies.

    - `request.url.scheme == "https"` covers the reverse-proxy topology
      (nginx terminates TLS + forwards to uvicorn with
      `X-Forwarded-Proto: https` when `uvicorn --proxy-headers` is set).
    - `config.tls.enabled` covers the direct-uvicorn HTTPS listener.

    Defensive: both signals are read via `getattr` chains — a missing
    request/config attribute defaults to False (no `Secure` flag → the
    dev/HTTP path). The caller may pass `config=None`; the SSOT still
    returns the request-scheme-only decision.

    Never invert this to `AND` — the OR is intentional (either signal
    alone is enough; neither is required together).
    """
    scheme = getattr(getattr(request, "url", None), "scheme", "") or ""
    from_scheme = (scheme == "https")
    from_config = bool(getattr(getattr(config, "tls", None), "enabled", False))
    return from_scheme or from_config
