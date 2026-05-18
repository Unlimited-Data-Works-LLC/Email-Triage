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

from email_triage._http_client import LazyHttpClient

logger = logging.getLogger("email_triage.web.gmail_push_auth")

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


class _CertCache:
    """In-memory cache of Google's public signing certs, keyed by ``kid``."""

    def __init__(self, ttl_seconds: int = 3600):
        self._ttl = ttl_seconds
        self._fetched_at: float = 0.0
        self._keys: dict[str, Any] = {}
        # Long-lived httpx client (#139). The cache is a per-process
        # singleton on ``app.state._gmail_cert_cache``; the JWKS
        # refresh fires on cold-start + every ``ttl_seconds`` (1 h
        # default) + on any unknown ``kid``. Holding the connection
        # pool open trims the cold-path TLS handshake to once per
        # process.
        self._http = LazyHttpClient(timeout=10.0)

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
        resp = await client.get(GOOGLE_JWKS_URL)
        if resp.status_code != 200:
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
