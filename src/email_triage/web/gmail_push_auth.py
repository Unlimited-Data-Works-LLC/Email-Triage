"""JWT verification for Gmail Pub/Sub push deliveries.

Google Cloud Pub/Sub sends push notifications with an Authorization
header of the form ``Bearer <JWT>``. The JWT is signed RS256 by Google
and carries the service-account identity the subscription was created
with. We verify signature, issuer, audience, and SA email, and reject
anything that doesn't match.

This module intentionally does not depend on FastAPI or the rest of
the web package — it's a pure verification utility so tests can mint
JWTs with a generated RSA keypair and stub the public-cert fetch.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from email_triage._http_client import Intent, LazyHttpClient

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.web.gmail_push_auth")  # N-196b R21_4

# Google publishes the OAuth2 signing certs here. The x509 variant is
# the one whose `kid` matches the `kid` in Pub/Sub push JWTs.
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"

VALID_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}


class GmailPushVerificationError(Exception):
    """Raised when the inbound JWT fails signature or claim checks."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class GmailPushTransientFetchError(Exception):
    """N-288 R30 — raised when the JWKS cert fetch fails for a
    TRANSIENT reason (DNS blip, connect timeout, upstream 5xx).

    Distinct from :class:`GmailPushVerificationError` so the webhook
    receiver can respond 503 (retry-able) instead of 500 (stack
    trace) — Google Pub/Sub retries hard on 5xx, so a brief infra
    blip used to flood the log with thousands of stack traces
    (2026-06-25 Tailscale MagicDNS outage — ~6,775 traces in a few
    hours). A 503 still tells Pub/Sub to retry but is the
    RFC-preferred response for a transient upstream dependency
    failure + suppresses the stack trace.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# -d (2026-07-11) — CONFIG-DRIVEN Gmail JWKS-fetch client timeout,
# per feedback_dynamic_over_hardcoding. Pre-fix ``timeout=10.0`` was
# a hardcoded float literal inside _CertCache.__init__. Now module-
# level with a boot-wired setter; a NEW _CertCache picks up the tuned
# value at construction. (Existing instances keep their captured
# timeout — call sites re-instantiate on app startup via
# app.state._gmail_cert_cache = _CertCache(), so a boot-time tune
# reaches the singleton.)
_GMAIL_CERT_TIMEOUT_SECS: float = 10.0


def configure_gmail_cert_timeout(timeout_secs: float) -> None:
    """-d — set the Gmail JWKS-fetch client timeout budget.

    Called at boot from ``load_config._wire_module_singletons`` with
    the resolved ``config.push.gmail_cert_timeout_secs`` value.
    Rejects non-positive values.
    """
    global _GMAIL_CERT_TIMEOUT_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _GMAIL_CERT_TIMEOUT_SECS = float(timeout_secs)


class _CertCache:
    """In-memory cache of Google's public signing certs, keyed by ``kid``."""

    def __init__(self, ttl_seconds: int = 3600):
        self._ttl = ttl_seconds
        self._fetched_at: float = 0.0
        self._keys: dict[str, Any] = {}
        # Long-lived httpx client. The cache is a per-process
        # singleton on ``app.state._gmail_cert_cache``; the JWKS
        # refresh fires on cold-start + every ``ttl_seconds`` (1 h
        # default) + on any unknown ``kid``. Holding the connection
        # pool open trims the cold-path TLS handshake to once per
        # process. -d: timeout is now the module-level SSOT so a
        # config tune reaches the singleton on next startup.
        self._http = LazyHttpClient(
            intent=Intent.PROVIDER_API, timeout=_GMAIL_CERT_TIMEOUT_SECS,
        )

    def _expired(self) -> bool:
        return (time.time() - self._fetched_at) >= self._ttl

    async def get_key(self, kid: str) -> Any:
        if not self._keys or self._expired():
            await self._refresh()
        key = self._keys.get(kid)
        if key is None:
            # Maybe the signing key rotated since our cache — force a refresh.
            await self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise GmailPushVerificationError(f"unknown signing key kid={kid}")
        return key

    async def _refresh(self) -> None:
        client = await self._http.get()
        # N-288 R30: transient network failure (DNS blip, connect
        # timeout) during JWKS fetch used to escape uncaught → the
        # webhook receiver returned a 500 stack-trace, Google Pub/Sub
        # retried hard, producing thousands of error rows on a brief
        # infra blip (2026-06-25 Tailscale MagicDNS outage). Convert
        # to `GmailPushTransientFetchError` so the receiver can return
        # a 503 (transient/retry) instead of a 500.
        try:
            resp = await client.get(GOOGLE_JWKS_URL)
        except httpx.RequestError as e:
            # N-298 R30 CI-red fix-forward: route through `fmt_exc` SSOT
            # (with_class=True keeps the ClassName: prefix while
            # PHI-scrubbing the message body) — the exc-render twin pin
            # caught the bare `f"{type(e).__name__}: {e}"` idiom.
            from email_triage._errfmt import fmt_exc
            raise GmailPushTransientFetchError(
                f"transient fetch failure for Google JWKS: "
                f"{fmt_exc(e, with_class=True)}"
            ) from e
        if resp.status_code != 200:
            # 5xx from Google itself is ALSO a transient case (retry-able);
            # 429 (rate-limit) is transient too — retrying after backoff is
            # correct per HTTP semantics. 4xx (except 429) is a real config
            # failure — raise the verification error.
            # N-297 R30 (DB-SME FU-3 on N-288): 429 added to the transient
            # set. Rare in practice for JWKS but easy to close.
            if 500 <= resp.status_code < 600 or resp.status_code == 429:
                raise GmailPushTransientFetchError(
                    f"Google JWKS transient upstream status: {resp.status_code}"
                )
            raise GmailPushVerificationError(
                f"failed to fetch Google JWKS: {resp.status_code}"
            )
        data = resp.json()
        from jwt.algorithms import RSAAlgorithm  # lazy — uses cryptography
        new_keys: dict[str, Any] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            if kid:
                new_keys[kid] = RSAAlgorithm.from_jwk(jwk)
        self._keys = new_keys
        self._fetched_at = time.time()

    async def aclose(self) -> None:
        """Drain the long-lived httpx client. Idempotent."""
        await self._http.aclose()


async def verify_pubsub_jwt(
    token: str,
    *,
    audience: str,
    sa_email: str,
    cert_cache: _CertCache | None = None,
    leeway: int = 60,
) -> dict[str, Any]:
    """Verify a Google-signed Pub/Sub push JWT and return its claims.

    Raises :class:`GmailPushVerificationError` on any failure — bad
    signature, wrong issuer, wrong audience, wrong SA email, expired.
    """
    if not token:
        raise GmailPushVerificationError("missing token")
    if not audience:
        raise GmailPushVerificationError("audience not configured")
    if not sa_email:
        raise GmailPushVerificationError("SA email not configured")

    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:  # noqa: BLE001 — PyJWT exposes many variants
        raise GmailPushVerificationError(f"malformed JWT header: {e}") from e

    kid = header.get("kid")
    if not kid:
        raise GmailPushVerificationError("JWT header missing kid")

    cache = cert_cache or _CertCache()
    key = await cache.get_key(kid)

    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=audience,
            leeway=leeway,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise GmailPushVerificationError("JWT expired") from e
    except jwt.InvalidAudienceError as e:
        raise GmailPushVerificationError("wrong audience") from e
    except jwt.InvalidSignatureError as e:
        raise GmailPushVerificationError("bad signature") from e
    except jwt.PyJWTError as e:
        raise GmailPushVerificationError(f"JWT decode failed: {e}") from e

    if claims.get("iss") not in VALID_ISSUERS:
        raise GmailPushVerificationError(f"unexpected issuer: {claims.get('iss')!r}")

    if claims.get("email") != sa_email:
        raise GmailPushVerificationError(
            f"unexpected SA email: {claims.get('email')!r}"
        )

    if claims.get("email_verified") is not True:
        raise GmailPushVerificationError("email_verified is not true")

    return claims
