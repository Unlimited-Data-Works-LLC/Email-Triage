"""Single hash function for STORED bearer secrets (census run14 #1).

The same ``hashlib.sha256(secret.encode()).hexdigest()`` idiom was hand-rolled
in THREE byte-identical credential-hash functions — ``auth._hash_code`` (OTP),
``auth.hash_api_key`` (API key), ``mfa._hash_code`` (recovery codes +
operator-recovery tokens) — the last of which even documented itself as
"Identical mechanism to ``auth._hash_code`` — duplicated by-name". Three forks
of a security primitive is a partial-fix hazard: a future work-factor / KDF
migration (argon2 / scrypt / a pepper) done in two of the three desyncs the
hash side from the verify side, and a stored-vs-recomputed mismatch rejects
EVERY credential of that class (a fail-closed lockout). There was no SSOT and
no pin, so a fourth credential class would silently fork a fourth copy.

``hash_credential`` is the ONE definition. Every credential hash AND its
verify/compare edge routes through here, so the algorithm lives in exactly one
place.

ENTROPY POSTURE (why bare SHA-256 is defensible TODAY, and why the SSOT still
matters): the secrets hashed here are high-entropy — API keys are
``secrets.token_urlsafe(32)`` (~2^256), recovery codes ~2^48, operator-recovery
tokens ~2^128 — so a SHA-256 preimage is infeasible without per-row work-factor.
The one low-entropy caller is the e-mail OTP code, which is additionally
protected by ``login_guard`` rate-limiting + short expiry + single-use. The SSOT
exists so THAT posture can be upgraded in one place if the risk calculus ever
changes (e.g. moving the OTP to a salted KDF) — instead of a three-site edit
that is one forgotten copy away from a credential-class lockout.

NOT for: content/integrity hashing (cache keys, the HMAC audit chain, file
checksums, SSH-key fingerprints, the CSRF session-binding derivation). Those are
not stored bearer secrets compared on an auth path and must NOT route here — see
``tests/test_credential_hash_ssot_pin.py`` for the (documented) exceptions.
"""

from __future__ import annotations

import hashlib


def hash_credential(secret: str) -> str:
    """SHA-256 hex of a stored bearer secret (OTP / API key / recovery code /
    operator-recovery token). The SSOT — both the store side and the verify
    side of every credential class call THIS, so a future KDF migration is a
    one-line change here, never a multi-fork partial fix."""
    return hashlib.sha256(secret.encode()).hexdigest()
