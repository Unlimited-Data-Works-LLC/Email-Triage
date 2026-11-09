"""N-151 — Fernet envelope for the MSAL token cache (2026-07-08).

The MSAL ``SerializableTokenCache`` persists OAuth access + refresh tokens
in JSON.  Prior to N-151 this file was written to disk in PLAINTEXT (at
0o600) *outside* the SQLCipher DB — a  flagged the plaintext
refresh-token exposure as the residual §164.312(a)(2)(iv) at-rest gap
that the SQLCipher opener could not cover.

This module wraps the cache in a Fernet envelope keyed by the app's
bootstrap master key (the same key that guards ``DbSecrets``).  The file
on disk retains its shape (per-account or CLI-scoped path returned by
``providers.factory.msal_cache_path_for_*``) so the N-236 dispose SSOT +
N-281 on-disk-artifact registry + N-177 backup glob pin all continue to
apply unchanged — only the CONTENTS change from plaintext JSON to
Fernet ciphertext.

Fail-CLOSED semantics (Prime Directive #8):

* ``decrypt_cache`` returns ``None`` on any decrypt failure (corrupt
  ciphertext, master-key mismatch, truncated file, wrong-envelope-flavor).
  The caller MUST treat ``None`` as "cache unusable — start an empty
  in-memory cache and force re-auth on next silent-acquire", NEVER as
  "fall back to reading the raw bytes as plaintext".
* ``encrypt_cache`` raises if the master key is unavailable.  Refusing
  to write PLAINTEXT is the fail-CLOSED behaviour; silently degrading
  to unencrypted-at-rest is the exact defect this landing closes.

Legacy plaintext migration (one-shot, on read):

* If ``decrypt_cache`` returns ``None`` AND the raw bytes match the
  ``looks_like_legacy_plaintext`` predicate (starts with ``{`` after
  whitespace — the MSAL JSON envelope), the caller MAY treat the raw
  bytes as plaintext for a SINGLE read + re-encrypt on the next save.
  After the migration write, the file is Fernet-shaped and the legacy
  branch is dead until an external process rewrites the file (which
  is itself a defect the pin below catches).

Master-key resolution:

The module exposes ``_get_master_key`` as a lazy accessor that reads
the config + bootstrap backend at first use and caches the resulting
Fernet key.  Constructor injection into ``Office365Provider`` was
considered and rejected — the callsite fan-out (15 files: 5 prod, 10
tests) turns the injection into a repo-wide surgery, and the master
key is already a process-wide singleton.  Tests that need to override
the key can monkeypatch ``_get_master_key`` directly.
"""
from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def looks_like_legacy_plaintext(data: bytes) -> bool:
    """Return True if ``data`` looks like a legacy plaintext MSAL cache
    (a JSON object).  Used ONLY for the one-shot migration branch — do
    not reach for this as a "is-this-encrypted" check; the ciphertext
    envelope has its own version bytes via Fernet."""
    # MSAL SerializableTokenCache.serialize() returns a JSON object.
    # An empty cache serializes to `"{}"`.  Anything starting with `{`
    # (after leading whitespace, which msal never emits but be lenient)
    # is a plausible legacy plaintext.  Fernet ciphertext starts with
    # `gAAAAA` (the base64 of the version byte + timestamp), so the two
    # shapes never collide.
    return data.lstrip().startswith(b"{")


#: Minimum byte length of a Fernet token after base64url decoding:
#: 1 version byte + 8 timestamp + 16 IV + ONE 16-byte ciphertext block +
#: 32 HMAC. An empty MSAL cache encrypts to EXACTLY this, so the bound is
#: an inclusive floor — see the ``>=`` note below.
#:
#: 73, not 57. The header+trailer alone are 57 (1 version + 8 timestamp +
#: 16 IV + 32 HMAC), but PKCS7 guarantees AT LEAST ONE 16-byte ciphertext
#: block — a zero-block Fernet token is structurally impossible, and even
#: an empty cache (``"{}"``) pads to a full block. db-sme measured a
#: 76-char prefix of a real token decoding to exactly 57 bytes and being
#: ACCEPTED. Honest about the size of the win: that is 1 of the 79 offsets
#: the congruence still admits, so this removes an impossible shape rather
#: than a meaningful fraction. The residual ~1.5% is truncations landing
#: exactly on a block boundary, which nothing short of the HMAC can catch.
#:
#: THE COMPARISON MUST STAY ``>=``. Measured 2026-09-12: an EMPTY MSAL
#: cache (``"{}"``, 2 bytes) encrypts to a token decoding to EXACTLY 73 —
#: it sits ON the floor, not above it. "Tightening" the check to ``>``
#: would silently drop the cache of every account that has not yet
#: acquired a token, which is precisely the class of silent omission
#: N-472 exists to close.
_FERNET_MIN_DECODED_LEN = 73
#: Fernet's envelope version byte, asserted on the decoded prefix.
_FERNET_VERSION_BYTE = 0x80
#: AES-CBC block size.  Fernet's ciphertext segment is always a whole
#: number of blocks, so a decoded token's length is EXACTLY
#: ``_FERNET_MIN_DECODED_LEN + 16k`` — the fixed header and trailer plus
#: k blocks.  That makes the length a congruence, not merely a floor,
#: and the congruence is what actually detects a torn write.
_FERNET_BLOCK_LEN = 16


def is_valid_cache_payload(data: bytes, *, source: str = "") -> bool:
    """Return True if ``data`` is a structurally intact MSAL cache file.

    N-472 (2026-09-12) — the VALIDITY predicate for on-disk MSAL cache
    bytes, owned by the module that WRITES them.  ``backup.py`` calls
    this instead of hand-rolling its own check, so a format migration
    like N-151's plaintext-to-Fernet cutover propagates by construction
    rather than silently invalidating every downstream reader.

    Accepts BOTH on-disk shapes the codebase can legitimately hold:

    * Fernet ciphertext — what ``encrypt_cache`` writes today.
    * Legacy plaintext JSON — a pre-N-151 install whose one-shot
      migration has not run yet (the read path still honours it, so a
      backup that omitted it would drop a live account's refresh token).

    NOT PURE: the legacy-plaintext branch emits a WARNING naming
    ``source``.  Declared here because a predicate that logs is a real
    smell and a caller deserves to know before wiring it into a loop —
    it fires at most once per legacy cache per call, and ``source`` is
    the caller's own identity, the one thing this module cannot derive
    from bytes.

    Deliberately STRUCTURAL, never decrypting.  ``_get_master_key``
    reads the bootstrap secrets backend, and a caller like the backup
    collector can legitimately run with the key unavailable — the
    writer itself has a "refusing to write, master key unavailable"
    branch.  Gating backup inclusion on key availability would make a
    key outage silently shrink the bundle, which is the same failure
    class this predicate exists to close.

    A ``False`` return means "torn or corrupt" and the caller should
    omit the file AND say so — a truncated cache in an archive is worse
    than a missing one, because restore leaves that account with an
    unusable refresh token and no signal.
    """
    if not data:
        return False
    if looks_like_legacy_plaintext(data):
        import json as _json

        try:
            _json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        # The WARNING lives HERE, not at the caller (devils-advocate
        # self-correction, 2026-09-12). A caller wanting to report the
        # legacy branch would have to call `looks_like_legacy_plaintext`
        # itself — which is the misuse this module's own docstring forbids
        # ("do not reach for this as an is-this-encrypted check") AND the
        # re-inlined shape check the N-472 pin bans. Format knowledge stays
        # in the owning module; the caller gets a bool.
        #
        # Post-N-151 a plaintext cache means that account's encrypt-at-rest
        # migration has not run — an unencrypted OAuth refresh token on
        # disk. Valid, and worth saying out loud.
        _warn_legacy_plaintext(source)
        return True
    import base64 as _base64
    import binascii as _binascii

    try:
        decoded = _base64.urlsafe_b64decode(data)
    except (_binascii.Error, ValueError):
        return False
    if len(decoded) < _FERNET_MIN_DECODED_LEN:
        return False
    # The CONGRUENCE, not the floor, is what catches a torn write.
    # Measured by devils-advocate 2026-09-12 over every truncation offset
    # of a real ~4 KB cache: floor + version byte alone ACCEPTED 1344 of
    # 5376 truncations (25.0%) — every offset congruent to 0 mod 4, where
    # base64 decoding succeeds and the surviving prefix still carries a
    # valid header. The 75% that were caught were caught by a base64
    # padding error, which is an accident of the offset and not a check.
    # Requiring a whole number of AES blocks drops that to 84 (1.6%).
    # Without this line the comment in `backup.py` promising that a torn
    # cache is kept out of the archive is substantially unenforced for
    # the only shape that exists in production.
    if (len(decoded) - _FERNET_MIN_DECODED_LEN) % _FERNET_BLOCK_LEN != 0:
        return False
    return decoded[0] == _FERNET_VERSION_BYTE


def read_legacy_plaintext(data: bytes, *, source: str = "") -> str | None:
    """The READ path's legacy branch (punch 430): the decoded plaintext when
    ``data`` is a legacy plaintext cache, else ``None``.

    Before punch 430 the provider's loader called
    :func:`looks_like_legacy_plaintext` itself and logged at INFO, so the
    at-rest WARNING (an unencrypted OAuth refresh token is on disk) fired only
    from the backup collector: an install that never ran a backup never heard
    it. Both readers now raise the same WARNING through
    :func:`_warn_legacy_plaintext`, and only this module tests the shape.
    """
    if not looks_like_legacy_plaintext(data):
        return None
    _warn_legacy_plaintext(source)
    return data.decode("utf-8", errors="replace")


def _warn_legacy_plaintext(source: str) -> None:
    """The ONE legacy-plaintext at-rest WARNING (backup collector and loader)."""
    # N-242 R24 SSOT route, same as `decrypt_cache` below.
    from email_triage.triage_logging import get_logger

    get_logger("providers._msal_cache_crypto").warning(
        "MSAL cache is LEGACY PLAINTEXT — the N-151 encrypt-at-rest "
        "migration has not run for this account, so an unencrypted "
        "OAuth refresh token is on disk. It migrates on the next "
        "token save. Treated as VALID so it is not dropped from "
        "backups, which would lose a live account's refresh token.",
        # `source` is the ONE thing this module cannot derive: it
        # receives bytes and structurally cannot know which file
        # produced them, while the caller holds the path. Without it
        # devils-advocate measured three different legacy caches
        # emitting three BYTE-IDENTICAL warnings — an operator told an
        # unencrypted refresh token is on disk, and not told whose.
        # `msal_cache_path_for_*` is per-account and this project
        # targets multi-mailbox reuse, so that is the only question
        # the warning exists to answer. Reporting a state without its
        # artifact is half a fix, which is N-472's own lesson.
        source=source or "<unspecified>",
    )


def encrypt_cache(plaintext: str) -> bytes:
    """Fernet-encrypt an MSAL cache serialization for on-disk storage.

    Raises on unavailable master key — see fail-CLOSED contract in the
    module docstring.
    """
    from cryptography.fernet import Fernet

    key = _get_master_key()
    return Fernet(key).encrypt(plaintext.encode("utf-8"))


def decrypt_cache(ciphertext: bytes) -> str | None:
    """Fernet-decrypt an MSAL cache file's bytes.

    Returns ``None`` on ANY decrypt failure (corrupt, wrong key,
    truncated, wrong envelope).  Callers MUST NOT interpret a ``None``
    return as "fall back to plaintext" — see the module docstring.
    """
    from cryptography.fernet import Fernet, InvalidToken

    try:
        key = _get_master_key()
    except Exception:
        # Master key unavailable (config missing, bootstrap backend
        # unreachable).  Refuse to read; caller falls back to empty
        # cache + re-auth.  Not raising here lets the read path stay
        # symmetric with the "corrupt file" branch — both surface as
        # None, both push the caller to re-auth.  N-151 db-sme fold #1
        # observability: WARN log so a bootstrap regression surfaces
        # instead of masquerading as a mysterious mass re-auth event.
        # N-242 R24 SSOT: route through triage_logging.get_logger so
        # the WARN rides the HMAC chain — a raw logging.getLogger call
        # trips the growth-cap ratchet pin (test_n242_triage_logger_ssot_ratchet_pin).
        from email_triage.triage_logging import get_logger
        get_logger("providers._msal_cache_crypto").warning(
            "N-151 msal cache: master key unavailable — forcing re-auth "
            "(bootstrap/config regression?)",
        )
        return None
    try:
        return Fernet(key).decrypt(ciphertext).decode("utf-8")
    except InvalidToken:
        return None


@lru_cache(maxsize=1)
def _get_master_key() -> bytes:
    """Resolve the Fernet master key from the bootstrap backend.

    Cached process-wide — the master key is a singleton for the life
    of the process (rotating it requires a restart per the
    ``secrets.KeyRotation`` flow's process-cache invalidation note).
    """
    from email_triage.config import load_config
    from email_triage.secrets import read_bootstrap_master_key

    cfg = load_config()
    key_str = read_bootstrap_master_key(cfg)
    return key_str.encode("utf-8") if isinstance(key_str, str) else key_str


def _reset_master_key_cache_for_tests() -> None:
    """Test-only helper — clear the lru_cache so a test can re-monkeypatch
    ``load_config`` / ``read_bootstrap_master_key`` and see the new value.

    Tolerant of an already-monkeypatched ``_get_master_key`` (a plain
    lambda has no ``.cache_clear``); the reset is a no-op in that case.
    """
    clear = getattr(_get_master_key, "cache_clear", None)
    if clear is not None:
        clear()


# ---------------------------------------------------------------------------
# N-151 SOFT-gate predicate (the backlog  REDESIGNED v3 Part 0)
# ---------------------------------------------------------------------------
#
# The canonical LEVEL predicate + reason SSOT for "is the MSAL master key
# currently unavailable".  Callers (health probe /  pattern-alert
# circuit-breaker / any future SOFT-gate consumer) probe this — NEVER
# hand-roll their own try/except on ``_get_master_key`` — so the reason
# enum and the class-name partition stay in ONE place.
#
# Semantics — decided explicitly (see also ``_get_master_key`` source):
#
#   * ``_get_master_key`` does NOT raise a single typed exception on
#     unavailable — it can raise any of several classes depending on
#     which layer failed (config load / secrets-backend read / sqlite
#     read on the backend DB).  This is why the existing SOFT-gate
#     partitions BY CLASS NAME in ``web/routers/health.py:1332`` (the
#     ``_UNAVAIL_TYPES`` frozenset).  We mirror that partition here so
#     the two SSOTs stay coherent — a class-name string set, no
#     exception-tree imports (which would be a boot-cycle hazard if a
#     secrets backend is later swapped).
#
#   * Gate is ACTIVE (``True``) on ANY exception from the probe, both
#     the expected ``_UNAVAIL_TYPES`` and the unexpected ``probe_error``
#     tail — fail-CLOSED per Prime Directive #8.  Only a successful key
#     retrieval flips it to ``False``.
#
#   * Reason enum matches ``_MSAL_MASTER_KEY_REASON_ENUM`` in
#     ``web/routers/health.py:1232`` (subset — this file cannot surface
#     ``import_error`` on itself, so only ``available`` / ``unavailable``
#     / ``probe_error`` are reachable here).
#
# The predicate never stores.  ``_get_master_key`` is ``@lru_cache``'d for
# the SUCCESS path, so a healthy probe is O(1) after the first hit; the
# failure path is not cached by ``lru_cache`` and is re-evaluated each
# call, which is desired (a transient locked-backend recovers on the next
# probe without a manual cache clear).

_N151_UNAVAIL_TYPES: frozenset[str] = frozenset({
    "FileNotFoundError",
    "KeyError",
    "OperationalError",         # sqlite3.OperationalError on locked backend
    "SecretsBackendError",
    "BootstrapMasterKeyMissing",
})


def _n151_classify_probe() -> tuple[bool, str]:
    """Probe ``_get_master_key`` once and return ``(active, reason)``.

    Internal helper — the two public predicates below share this so a
    caller's ``active`` and ``reason`` observations always come from ONE
    probe (no torn read across two calls, no double lru_cache miss on
    an unavailable transient).
    """
    try:
        _get_master_key()
    except Exception as exc:
        err_type = type(exc).__name__
        reason = "unavailable" if err_type in _N151_UNAVAIL_TYPES else "probe_error"
        return (True, reason)
    return (False, "available")


def n151_soft_gate_state() -> tuple[bool, str]:
    """Single-probe accessor returning ``(active, reason)`` atomically.

    Callers MUST use this over calling ``n151_soft_gate_active()`` +
    ``n151_soft_gate_reason()`` separately — dual-call tears on
    transitions (probe A succeeds, probe B lands after the master key
    rotates or the backend flaps and the two observations disagree).
    One probe, one atomic tuple.

    Return values match the reachable subset of
    ``_MSAL_MASTER_KEY_REASON_ENUM`` in ``web/routers/health.py:1232``:

      * ``(False, "available")``   — probe returned a key
      * ``(True,  "unavailable")`` — probe raised a class in ``_N151_UNAVAIL_TYPES``
      * ``(True,  "probe_error")`` — probe raised an unexpected class
        (fail-CLOSED per Prime Directive #8)

    Rotation caveat: ``_get_master_key`` uses ``@lru_cache`` — a
    successful probe pins the master key for the process lifetime, so a
    runtime rotation without a restart bypasses this gate (the cached
    key is still returned and the probe still reports ``available``).
    See the module docstring for the follow-up ``cache_clear()`` plan
    (TODO: track this under a the backlog ticket — do NOT invent a number
    here; the caveat is durable regardless of the eventual ticket ID).

    Never stores — callers call, never cache locally.
    """
    return _n151_classify_probe()


def n151_soft_gate_active() -> bool:
    """LEVEL predicate: True iff the MSAL master key is currently unavailable.

    Probes ``_get_master_key`` (already ``@lru_cache``'d for the success
    path, O(1) after first hit).  Fail-CLOSED: ANY exception from the
    probe — expected ``_N151_UNAVAIL_TYPES`` OR unexpected ``probe_error``
    tail — flips the gate ACTIVE, matching the ``available: bool | None``
    "None-is-still-degraded" shape in ``msal_master_key_status``.

    DEPRECATED for dual-call use: prefer ``n151_soft_gate_state()`` for
    callers that need both fields — this call plus
    ``n151_soft_gate_reason()`` risks a torn read on the transition tick
    (the two probes cross a rotation / backend-flap and disagree).  This
    predicate stays supported for existing tests and non-migrated call
    sites that need ``active`` alone.

    Rotation caveat: ``_get_master_key`` uses ``@lru_cache`` — a
    successful probe pins the master key for the process lifetime, so a
    runtime rotation without a restart bypasses this gate.  See the
    module docstring for the follow-up ``cache_clear()`` plan (TODO:
    track under a the backlog ticket — do NOT invent a number here).

    Never stores — callers call, never cache locally.
    """
    active, _reason = _n151_classify_probe()
    return active


def n151_soft_gate_reason() -> str:
    """Return the canonical reason enum string.

    Values (subset of ``_MSAL_MASTER_KEY_REASON_ENUM`` in
    ``web/routers/health.py:1232``; ``import_error`` is unreachable from
    inside this module):

      * ``"available"``   — probe returned a key (gate NOT active)
      * ``"unavailable"`` — probe raised a class in ``_N151_UNAVAIL_TYPES``
      * ``"probe_error"`` — probe raised an unexpected class

    DEPRECATED for dual-call use: prefer ``n151_soft_gate_state()`` for
    callers that need both fields — ``n151_soft_gate_active()`` plus
    this call risks a torn read on the transition tick.  This accessor
    stays supported for existing tests and non-migrated call sites that
    need ``reason`` alone.

    Rotation caveat: ``_get_master_key`` uses ``@lru_cache`` — a
    successful probe pins the master key for the process lifetime, so a
    runtime rotation without a restart bypasses this gate.  See the
    module docstring for the follow-up ``cache_clear()`` plan (TODO:
    track under a the backlog ticket — do NOT invent a number here).

    Never stores — callers call, never cache locally.
    """
    _active, reason = _n151_classify_probe()
    return reason
