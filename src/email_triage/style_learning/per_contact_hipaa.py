"""HIPAA-safe per-contact style descriptor.

Pipeline
========

For a HIPAA-flagged account with the operator opt-in (the same M-1+M-2
toggle that gates the M-3 account-level distill), this module ships
a parallel describe-and-discard pass scoped to a single recurring
recipient. The descriptor JSON shape is identical to M-3 (closed-
vocabulary schema from
:mod:`email_triage.style_learning.phi_scrubber`); the scrubber is
shared verbatim. The only differences from M-3 are:

  * **Corpus selection** — caller passes the last N=20 messages SENT
    TO a single recipient, rather than the last-N messages from the
    sent folder regardless of recipient.
  * **Prompt framing** — the system message tells the LLM the
    descriptor is an OVERLAY for a specific correspondent rather than
    the operator's general voice. The schema is identical.
  * **Storage** — the scrubbed descriptor lands in
    ``per_contact_style_hipaa`` keyed on ``(account_id,
    recipient_hash)`` rather than ``hipaa_style_descriptors`` keyed on
    ``account_id`` alone.
  * **Recipient identity NEVER persisted in plaintext** — the table
    stores ``SHA-256(install_style_salt || recipient.lower())``. The
    plaintext address falls out of scope on function exit. Audit rows
    (``style_distill_events`` with ``kind='per_contact'``) also carry
    only the hash.

Salt source
===========

The salt is a 64-byte random secret stored in ``secrets_store`` under
:data:`HIPAA_RECIPIENT_SALT_SECRET_KEY` (Fernet-encrypted via the
install's ``DbSecrets`` wrapper). Auto-generated on first call to
:func:`get_or_init_recipient_salt`.

Why a dedicated style-salt rather than literally the master key:

  * The master key is the Fernet key for the entire secrets_store.
    Exposing the raw bytes to a hashing routine widens its blast
    radius for no privacy benefit — a dedicated salt is just as
    install-stable.
  * Master-key rotation (operator action, see
    :meth:`DbSecrets.rotate_master_key`) re-encrypts every row but
    keeps the same plaintext values. If we used the master key as
    the salt, every recipient hash would silently change on rotation
    + every per-contact row would become unreachable. With a dedicated
    salt, master-key rotation has no effect on the per-contact
    look-up; rotating the salt (operator action, NOT in scope for W3)
    invalidates all per-contact rows in one place.
  * Per-install isolation is preserved: each install generates its
    own random salt, so leaking one install's DB cannot be correlated
    with another install's DB to identify shared contacts.

Failure mode: when no salt can be obtained (no ``DbSecrets`` available
+ no fallback path), :func:`hash_recipient_for_install` raises
``RuntimeError`` rather than falling back to a fixed / empty salt.
The empty-salt path is a rainbow-table attack vector — better to
fail loudly than to hash with a known-blank salt.

Body NEVER persisted, NEVER logged
==================================

Same invariant as M-3: the in-memory message list, corpus string, and
LLM raw response all drop out of scope before the function returns.
The persistence write carries only the scrubbed descriptor.

Per-contact retry queue
=======================

Failures land in ``style_distill_queue_contacts`` (v28, keyed on
``(account_id, recipient_hash)``). Same exponential-backoff schedule
as the account-level queue (:data:`STYLE_DISTILL_BACKOFF_SECONDS`).
Pause semantics are scoped to the contact — pausing one contact's
overlay does NOT pause the account-level descriptor or other contacts.
"""

from __future__ import annotations

from email_triage._errfmt import fmt_exc
from email_triage.secrets import read_secret

import hashlib
import logging
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from email_triage._int_utils import parse_int_or_none  # N-219c/11 R23
from email_triage._isotime import to_utc_iso, now_utc_iso, parse_iso, parse_iso_aware  # N-203 R22 + N-283 R29 + N-357b R31
from typing import Any, Iterable

from email_triage.ai_backends import (
    BackendAdapter,
    BackendBAARequiredError,
    BackendError,
    load_backend,
)
from email_triage.engine.models import EmailMessage
from email_triage.style_learning.distill_hipaa import (
    DESCRIPTOR_VERSION,
    DISTILL_JSON_SCHEMA,
    OUTCOME_BAA_REQUIRED,
    OUTCOME_BACKEND_FAIL,
    OUTCOME_CADENCE_SKIP,
    OUTCOME_DISABLED,
    OUTCOME_NO_MESSAGES,
    OUTCOME_NOT_HIPAA,
    OUTCOME_NOT_OPTED_IN,
    OUTCOME_SCRUBBED_PARTIAL,
    OUTCOME_SCRUBBER_FAIL,
    OUTCOME_SUCCESS,
    _build_corpus_block,
    _format_distill_prompt,
    _get_account_backend_id,
    _parse_descriptor_json,
)
from email_triage.style_learning.phi_scrubber import (
    ScrubResult,
    scrub_descriptor,
)
from email_triage.mail_headers import canonical_email
from email_triage.triage_logging import is_account_hipaa
from email_triage.web.db import (
    HIPAA_PER_CONTACT_FRESHNESS_DAYS,
    HIPAA_PER_CONTACT_GC_DAYS,
    clear_style_distill_contact_queue_entry,
    delete_per_contact_style_hipaa,
    enqueue_style_distill_contact_retry,
    gc_per_contact_style_hipaa,
    get_per_contact_style_hipaa,
    is_hipaa_style_distill_enabled,
    is_style_knobs_hipaa_allow,
    pause_style_distill_contact,
    record_style_distill_event,
    set_per_contact_style_hipaa,
)
# run18 #2 — route the best-effort §164.502(e) egress-accounting emits through
# the audit-write SSOT (sync + async-seam siblings): run it, never raise, log a
# uniform audit_write_failed WARNING (/health drift) on failure.
from email_triage.web._audit import safe_audit_write, safe_audit_write_async

from email_triage.triage_logging import get_logger  # N-196b R21_4
log = get_logger("email_triage.style_learning.per_contact_hipaa")  # N-196b R21_4


# ---------------------------------------------------------------------------
# Salt source + recipient hashing
# ---------------------------------------------------------------------------

#: secrets_store key under which the install-stable per-contact hash
#: salt is stored (Fernet-encrypted via DbSecrets). Auto-generated on
#: first use. A salt rotation is operator-driven (NOT in scope for W3);
#: rotating invalidates every per-contact row because the hashes change.
HIPAA_RECIPIENT_SALT_SECRET_KEY = "style_learning:hipaa_recipient_salt_v1"

#: Hash digest length (hex chars). SHA-256 → 64 hex chars.
RECIPIENT_HASH_LEN = 64


class SaltUnavailableError(RuntimeError):
    """Raised when no salt is available + no fallback is safe.

    Callers MUST treat this as a fatal config error — refusing to hash
    rather than hashing with an empty / known salt. The empty-salt
    path is a rainbow-table attack vector on small contact lists.
    """


def get_or_init_recipient_salt(secrets: Any) -> bytes:
    """Read the install style-salt, generating one on first use.

    ``secrets`` is a :class:`email_triage.secrets.DbSecrets` (or
    compatible: ``get(key) -> str | None`` + ``set(key, value)``).
    Returns the raw salt bytes.

    Generation: 64 random bytes from ``secrets.token_bytes`` (CSPRNG).
    The first caller wins; subsequent readers see the persisted value.

    Raises :class:`SaltUnavailableError` if ``secrets`` is None or
    fails the ``get``/``set`` round-trip.
    """
    import secrets as _stdlib_secrets

    if secrets is None:
        raise SaltUnavailableError(
            "no secrets provider — refusing to hash with empty salt"
        )

    try:
        existing = read_secret(secrets, HIPAA_RECIPIENT_SALT_SECRET_KEY)
    except Exception as exc:
        raise SaltUnavailableError(
            f"failed to read style-salt: {type(exc).__name__}"
        ) from exc

    if existing:
        # Stored as hex string for readability + safe storage in a
        # text column. Decode back to bytes for hashing.
        try:
            salt = bytes.fromhex(existing)
        except ValueError as exc:
            raise SaltUnavailableError(
                "stored style-salt is not valid hex"
            ) from exc
        if len(salt) < 32:
            raise SaltUnavailableError(
                f"stored style-salt is too short ({len(salt)} bytes)"
            )
        return salt

    # First-use generation.
    salt = _stdlib_secrets.token_bytes(64)
    try:
        secrets.set(HIPAA_RECIPIENT_SALT_SECRET_KEY, salt.hex())
    except Exception as exc:
        raise SaltUnavailableError(
            f"failed to persist generated style-salt: {type(exc).__name__}"
        ) from exc
    return salt


# N-346c (2026-07-08) — dual-lookup shim (WAITING-ON-OP default LANDED).
# Hash-shape enum: which pre-image normalization to use before HMAC.
#
# 'legacy'   — bare.strip().lower(); the pre-image shape every persisted
#              row currently uses. Preserves the current hash of every
#              existing recipient row; no orphaning class.
# 'canonical' — canonical_email(recipient_address); adds IDNA domain
#              normalization (München → xn--mnchen-3ya) on top of
#              strip().lower(). For all-ASCII installs (the common case)
#              this yields the SAME hash as 'legacy'; for IDN addresses
#              it differs — a person whose envelope arrives as an
#              A-label variant will hash-match a U-label persisted row.
#
# The migration story (§164.316(b)(2)(i) documentation-integrity): every
# WRITE stays 'legacy' at v0.2.0 (no orphaning risk). Every READ tries
# BOTH shapes via `hash_recipient_for_install_all_shapes()` — the
# canonical-shape probe is a no-op cost for ASCII installs and closes the
# IDN-envelope collision class for IDN installs, without touching any
# persisted row. Flipping WRITE to 'canonical' later is a one-line
# operator decision when he chooses to migrate; existing rows stay
# addressable via the same dual-lookup shim. This is the "MOST-COMPLETE
# / MOST-FUTURE-PROOF" shape the WAITING-ON-OP default named.
_HASH_SHAPES: tuple[str, ...] = ("canonical", "legacy")


def _normalize_recipient_for_hash(
    recipient_address: str, shape: str,
) -> str:
    """N-346c pre-image normalizer per shape. Extracted so a single
    functional-testable helper covers the difference between the two
    shapes; the HMAC construction downstream is identical.
    """
    from email_triage.mail_headers import _extract_addr
    bare = _extract_addr(recipient_address)
    if not bare or "@" not in bare:
        raise ValueError(
            "recipient_address did not parse to a bare local@host"
        )
    if shape == "canonical":
        # Re-use the canonical_email SSOT (§4.312(a)(1) allow-list gate
        # already routes through it) — the shared truth for
        # display-name-strip + strip().lower() + IDNA encode. Import
        # lives at module scope (hoisted at the backlog  fold).
        canonical = canonical_email(recipient_address)
        # canonical_email may return "" on an unparseable domain; on that
        # path, fall back to the bare form so the caller doesn't hash the
        # empty string (which would collide across bad inputs).
        return canonical or bare.strip().lower()
    if shape == "legacy":
        return bare.strip().lower()
    raise ValueError(f"unknown hash shape: {shape!r}")


def hash_recipient_for_install(
    recipient_address: str, *, secrets: Any, shape: str = "legacy",
) -> str:
    """Return the install-stable salted-SHA-256 hash of an address.

    Normalisation: lowercase + strip whitespace + remove RFC-5322
    display-name wrapper (``Name <a@b>`` → ``a@b``).

    The salt MUST be a non-empty per-install secret obtained via
    :func:`get_or_init_recipient_salt`. Passing ``secrets=None`` (or
    any secrets backend that yields no salt) raises
    :class:`SaltUnavailableError` — there is NO fallback to an empty
    salt or a hard-coded constant. That would be a rainbow-table
    attack on small recipient lists.

    Returns a 64-char lowercase hex string.

    N-346c (2026-07-08): the ``shape`` kwarg selects the pre-image
    normalization. ``'legacy'`` (default) is ``bare.strip().lower()`` —
    the pre-image every persisted row currently uses; safe for WRITE
    callers. ``'canonical'`` adds ``canonical_email()``'s IDNA domain
    normalization; use it for a FUTURE migration where existing rows
    are backfilled or the operator has opted into the canonical shape.
    READ callers should use :func:`hash_recipient_for_install_all_shapes`
    which returns every shape's hash for a dual-lookup probe.

    Raises
    ------
    ValueError
        ``recipient_address`` is empty or unparseable as an address.
    SaltUnavailableError
        no install salt is available.
    """
    if not recipient_address or not isinstance(recipient_address, str):
        raise ValueError("recipient_address must be a non-empty string")

    normalised = _normalize_recipient_for_hash(recipient_address, shape)

    salt = get_or_init_recipient_salt(secrets)
    # NIST guidance: HMAC-SHA-256 is a stronger construction than
    # naive sha256(salt || msg) for fixed-salt deterministic hashing.
    # Both prevent rainbow-table reuse across installs; HMAC is the
    # safer default + matches the project's broader posture.
    import hmac
    digest = hmac.new(
        salt, normalised.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return digest


def hash_recipient_for_install_all_shapes(
    recipient_address: str, *, secrets: Any,
) -> list[str]:
    """N-346c dual-lookup SSOT — return the hash under EVERY known shape.

    Callers doing a READ (looking up an existing row by address) SHOULD
    route through this — try each hash in order until one matches. For
    ASCII installs both shapes hash-collide so the list is effectively
    one item's cost; for IDN installs the canonical-shape probe closes
    the A-label / U-label envelope collision class without touching any
    persisted row.

    Order: ``'canonical'`` first (the future-target shape) then
    ``'legacy'`` (the currently-persisted shape). Both are deterministic;
    a caller that hits a match on the canonical probe MAY choose to
    incrementally rewrite the row's hash on the next natural
    persistence event, migrating without a downtime backfill window.

    Duplicates ARE de-duplicated (order-preserving) — the ASCII fast-
    path collides both shapes to the same hash, so returning a 2-element
    list would issue two identical DB round-trips per lookup. `dict`-
    based dedup keeps Python 3.7+ insertion order (canonical first). The
    correctness contract is unchanged — every declared shape's hash is
    still covered — and the hot READ path avoids the redundant probe
    (db-sme H2 fold at N-346c SME panel 2026-07-08).

    Raises
    ------
    ValueError
        ``recipient_address`` is empty or unparseable as an address.
    SaltUnavailableError
        no install salt is available.
    """
    hashes = [
        hash_recipient_for_install(
            recipient_address, secrets=secrets, shape=s,
        )
        for s in _HASH_SHAPES
    ]
    # N-346c db-sme H2 fold — dedup collapsed shapes on the ASCII fast-
    # path via `dict.fromkeys` (order-preserving in Python 3.7+, canonical
    # first). Correctness is unchanged: every declared shape's hash is
    # still covered by the returned list; the hot READ path avoids the
    # 50% redundant DB round-trip on ASCII installs. IDN installs (rare)
    # still see 2 distinct hashes as expected.
    return list(dict.fromkeys(hashes))


def hash_message_id_for_install(
    rfc_message_id: str, *, secrets: Any,
) -> str:
    """Return the install-stable salted-SHA-256 hash of a Message-ID.

    Used by :class:`HipaaSentCounterLoop` to dedup Sent-folder
    scans without storing plaintext Message-IDs on disk for HIPAA-
    flagged accounts. Message-IDs are not strictly PHI but they ARE
    communication metadata under HIPAA's "minimum necessary"
    interpretation — storing the salted hash satisfies both the dedup
    requirement (deterministic per install) and the privacy posture
    (one-way; opaque to anyone without the install salt).

    Normalisation: strip whitespace + angle-bracket wrappers
    (``<abc@example.com>`` → ``abc@example.com``) + lowercase. RFC
    5322 says Message-ID is case-sensitive, but in practice some
    relays uppercase the local-part; lowercasing makes the dedup
    resilient to that.

    Salt source: same install salt as
    :func:`hash_recipient_for_install`. A salt rotation invalidates
    both surfaces consistently — recipient counters reset to zero
    AND dedup history resets to empty, so the rotated install starts
    fresh on both planes.

    Returns a 64-char lowercase hex string.

    Raises
    ------
    ValueError
        ``rfc_message_id`` is empty or not a string.
    SaltUnavailableError
        no install salt is available.
    """
    if not rfc_message_id or not isinstance(rfc_message_id, str):
        raise ValueError("rfc_message_id must be a non-empty string")

    # Normalise: strip angle brackets + whitespace + lowercase.
    normalised = rfc_message_id.strip().lstrip("<").rstrip(">").strip().lower()
    if not normalised:
        raise ValueError("rfc_message_id was empty after normalisation")

    salt = get_or_init_recipient_salt(secrets)
    import hmac
    digest = hmac.new(
        salt, normalised.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return digest


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PerContactDistillResult:
    """Outcome of a single ``distill_hipaa_per_contact`` invocation.

    Mirrors :class:`distill_hipaa.DistillResult` with one extra field:
    ``recipient_hash`` (NEVER the plaintext recipient).
    """

    status: str
    recipient_hash: str
    descriptor: dict[str, Any] | None = None
    backend_id: int | None = None
    backend_type: str = ""
    was_cloud: bool = False
    latency_ms: int = 0
    scrub: ScrubResult | None = None
    error_class: str | None = None
    message_count: int = 0


# ---------------------------------------------------------------------------
# Per-contact prompt prefix
# ---------------------------------------------------------------------------

#: System framing appended to the M-3 prompt for per-contact runs.
#: The schema + closed-vocabulary rules are identical to the account-
#: level prompt; this prefix just tells the LLM the descriptor will
#: be used to STYLE outgoing drafts to a recurring correspondent
#: (not to summarise WHAT the correspondence is about).
PER_CONTACT_SYSTEM_FRAMING = (
    "You are a privacy-preserving writing-style classifier. The sent "
    "emails below are all to ONE RECURRING CORRESPONDENT. The "
    "descriptor you produce will be used as a style OVERLAY for "
    "future drafts to that correspondent — produce style markers "
    "ONLY, never summarise content, never name the correspondent or "
    "any third party. Output JSON only; never include PHI."
)


# ---------------------------------------------------------------------------
# Per-contact cadence
# ---------------------------------------------------------------------------

#: Re-distill cadence for per-contact descriptors. Same target as
#: M-3 account-level: weekly (168 hours).
HIPAA_PER_CONTACT_REBUILD_INTERVAL_HOURS = 168


def _is_within_per_contact_cadence(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> bool:
    """Return True when an existing per-contact row was distilled
    within the cadence window — caller should skip the LLM call."""
    row = get_per_contact_style_hipaa(
        conn, account_id=account_id, recipient_hash=recipient_hash,
    )
    if row is None:
        return False
    rebuilt_at = row.get("last_distilled_at")
    if not rebuilt_at:
        return False
    # N-357b (2026-07-06 baseline shrink): parse_iso_aware SSOT.
    ts = parse_iso_aware(rebuilt_at)
    if ts is None:
        return False
    now = datetime.now(timezone.utc)
    age = now - ts
    interval = timedelta(
        hours=HIPAA_PER_CONTACT_REBUILD_INTERVAL_HOURS,
    )
    return age < interval


# ---------------------------------------------------------------------------
# Public entrypoint — distill
# ---------------------------------------------------------------------------

async def distill_hipaa_per_contact(
    account_id: int,
    recipient_address: str,
    *,
    db_conn: sqlite3.Connection,
    secrets: Any = None,
    config: Any = None,
    messages: Iterable[EmailMessage],
    actor_user_id: int | None = None,
    force: bool = False,
    skip_ner: bool = False,
) -> PerContactDistillResult:
    """Run a single per-contact distill pass.

    Parameters mirror :func:`distill_hipaa_account` with one added
    positional: ``recipient_address`` (the plaintext To: address of the
    recurring correspondent). The plaintext address is used ONLY to
    derive the hash + lives in a local variable that drops out of scope
    on function exit — it never lands in storage or the audit row.

    The ``messages`` iterable MUST already be filtered to messages
    SENT TO this single recipient. The function does not re-filter —
    that decision lives upstream (the caller knows which messages
    constitute the contact's corpus, which may include CC handling
    or aliasing rules not appropriate here).

    Returns :class:`PerContactDistillResult`. The audit row is written
    before return; the result.recipient_hash is the salted SHA-256.
    """
    # Compute the hash BEFORE any other work — this enforces the
    # invariant that the recipient is hashed exactly once + the
    # plaintext is held briefly. The local ``plaintext_recipient``
    # is overwritten with the hash before any persistence call.
    try:
        recipient_hash = hash_recipient_for_install(
            recipient_address, secrets=secrets,
        )
    except SaltUnavailableError as exc:
        # Cannot hash safely. Treat as backend_fail so the retry
        # queue picks it up after the operator wires up secrets.
        log.error(
            "per_contact distill: salt unavailable, refusing to hash",
            extra={"_extra": {
                "account_id": account_id,
                "error_type": type(exc).__name__,
            }},
        )
        # We do NOT have a recipient_hash to key the audit row on,
        # but the audit row still needs a kind+account.  Drop the
        # plaintext immediately + return a result with no hash.
        result = PerContactDistillResult(
            status=OUTCOME_BACKEND_FAIL,
            recipient_hash="",
            error_class="SaltUnavailableError",
        )
        #  — record_style_distill_event is @db_write; if this
        # function is wired onto an event-loop task the write must hop
        # to the threadpool. db_call is the canonical dispatch helper.
        from email_triage.web.db_threadpool import db_call
        # run18 #2 — route through the SSOT (never-raise + uniform
        # audit_write_failed WARNING for /health drift), not a swallowing try.
        await safe_audit_write_async(
            lambda: db_call(
                record_style_distill_event,
                db_conn,
                account_id=account_id,
                actor_user_id=actor_user_id,
                backend_id=None,
                backend_type="",
                was_cloud=False,
                outcome=OUTCOME_BACKEND_FAIL,
                latency_ms=0,
                error_class="SaltUnavailableError",
                kind="per_contact",
                recipient_hash=None,
            ),
            description=(
                f"per_contact_style_distill account={account_id} "
                f"outcome={OUTCOME_BACKEND_FAIL}"
            ),
        )
        return result
    except ValueError as exc:
        result = PerContactDistillResult(
            status=OUTCOME_BACKEND_FAIL,
            recipient_hash="",
            error_class="ValueError",
        )
        log.warning(
            "per_contact distill: bad recipient address",
            extra={"_extra": {
                "account_id": account_id,
                "error_type": type(exc).__name__,
            }},
        )
        return result

    # Drop the plaintext recipient reference. The hash is everything
    # we need from here on. Explicit cleanup so a leak via lingering
    # references is impossible.
    plaintext_recipient_address = None  # noqa: F841 — sentinel
    del recipient_address

    result = PerContactDistillResult(
        status=OUTCOME_NOT_HIPAA,
        recipient_hash=recipient_hash,
    )

    #  — per_contact distill is an async def touching the shared
    # connection; every DB touch hops to the threadpool via db_call.
    from email_triage.web.db_threadpool import db_call

    # ---- Gating ---------------------------------------------------------

    # Account-row read + the install/HIPAA/opt-in/cadence gates run in
    # one threadpool hop. Returns (account_dict_or_None, status); a
    # non-None status is a short-circuit outcome.
    def _per_contact_gating():
        row = db_conn.execute(
            "SELECT id, hipaa, user_id FROM email_accounts WHERE id = ?",
            (int(account_id),),
        ).fetchone()
        if row is None:
            return None, OUTCOME_NOT_HIPAA
        acct = {
            "id": int(row["id"]),
            "hipaa": int(row["hipaa"] or 0),
            "user_id": row["user_id"],
        }
        if not is_hipaa_style_distill_enabled(db_conn):
            return acct, OUTCOME_DISABLED
        if not is_account_hipaa(acct):
            return acct, OUTCOME_NOT_HIPAA
        if not is_style_knobs_hipaa_allow(db_conn, account_id):
            return acct, OUTCOME_NOT_OPTED_IN
        if not force and _is_within_per_contact_cadence(
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
        ):
            return acct, OUTCOME_CADENCE_SKIP
        return acct, None

    account_dict, _gate_status = await db_call(_per_contact_gating)
    if _gate_status is not None:
        result.status = _gate_status
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        return result

    # ---- Backend resolution --------------------------------------------

    backend_id = await db_call(_get_account_backend_id, db_conn, account_id)
    try:
        adapter: BackendAdapter = await db_call(
            load_backend,
            backend_id,
            db_conn=db_conn,
            secrets=secrets,
            config=config,
            # Census N-63 — HIPAA per-contact distill: demand a BAA-certified,
            # non-expired backend at the load chokepoint (§164.502(a)(1)).
            require_baa_certified=is_account_hipaa(account_dict),
        )
    except BackendBAARequiredError as exc:
        # BAA lapsed/de-certified after selection — refuse + audit the BAA
        # cause; no backoff retry (won't self-heal). PAUSE any pre-existing due
        # per-contact row so a retry worker could not re-select + re-fire it in
        # a tight loop (db-sme PD#18) — no such worker exists at HEAD (N-474),
        # so this is a guard for a future one; pause parks a row if none exists.
        # No PHI egressed (gate precedes any chat_complete).
        result.status = OUTCOME_BAA_REQUIRED
        result.backend_id = backend_id
        result.error_class = type(exc).__name__
        await db_call(
            pause_style_distill_contact,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
            last_error=f"baa_required:{result.error_class}",
        )
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        return result
    except BackendError as exc:
        result.status = OUTCOME_BACKEND_FAIL
        result.backend_id = backend_id
        result.error_class = type(exc).__name__
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        await db_call(
            enqueue_style_distill_contact_retry,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
            last_error=f"backend_fail:{result.error_class}",
        )
        return result

    result.backend_id = backend_id
    result.backend_type = getattr(adapter, "backend_type", "") or ""
    result.was_cloud = not bool(getattr(adapter, "is_local", False))

    # ---- Corpus assembly + LLM call ------------------------------------

    messages_list = list(messages)
    corpus, message_count = _build_corpus_block(messages_list)
    result.message_count = int(message_count)

    if message_count <= 0:
        result.status = OUTCOME_NO_MESSAGES
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        return result

    prompt = _format_distill_prompt(corpus)
    del messages_list
    del corpus

    chat_messages = [
        {"role": "system", "content": PER_CONTACT_SYSTEM_FRAMING},
        {"role": "user", "content": prompt},
    ]

    t0 = time.monotonic()
    try:
        raw = await adapter.chat_complete(
            chat_messages,
            response_format=DISTILL_JSON_SCHEMA,
            max_tokens=2048,
        )
    except Exception as exc:  # noqa: BLE001 — backend errors are audited
        result.status = OUTCOME_BACKEND_FAIL
        result.error_class = type(exc).__name__
        result.latency_ms = int((time.monotonic() - t0) * 1000)
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        await db_call(
            enqueue_style_distill_contact_retry,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
            last_error=f"backend_fail:{result.error_class}",
        )
        try:
            await adapter.close()
        except Exception as close_exc:
            log.warning(
                "per_contact_hipaa: adapter close failed on backend-fail path",
                error=fmt_exc(close_exc),
            )
        return result
    finally:
        prompt = ""

    result.latency_ms = int((time.monotonic() - t0) * 1000)

    try:
        await adapter.close()
    except Exception as close_exc:
        log.warning(
            "per_contact_hipaa: adapter close failed after chat_complete",
            error=fmt_exc(close_exc),
        )

    # ---- Parse + scrub -------------------------------------------------

    parsed = _parse_descriptor_json(raw)
    del raw

    if not parsed:
        result.status = OUTCOME_BACKEND_FAIL
        result.error_class = "JSONDecodeError"
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        await db_call(
            enqueue_style_distill_contact_retry,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
            last_error="backend_fail:JSONDecodeError",
        )
        return result

    scrub = scrub_descriptor(parsed, skip_ner=skip_ner)
    result.scrub = scrub

    if not scrub.passed:
        # Drop any stale row from a prior cleaner run.
        try:
            await db_call(
                delete_per_contact_style_hipaa,
                db_conn,
                account_id=account_id,
                recipient_hash=recipient_hash,
            )
        except Exception:
            log.exception(
                "per_contact distill: stale-descriptor delete failed",
            )
        result.status = OUTCOME_SCRUBBER_FAIL
        await db_call(
            _audit_per_contact, db_conn, account_id, actor_user_id, result,
        )
        # Pause ONLY this contact — account-level + other contacts
        # stay active.
        await db_call(
            pause_style_distill_contact,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
            last_error="scrubber_fail:structural_leak",
        )
        return result

    # ---- Persist + audit -----------------------------------------------

    await db_call(
        set_per_contact_style_hipaa,
        db_conn,
        account_id=account_id,
        recipient_hash=recipient_hash,
        descriptor=scrub.scrubbed_descriptor,
        version=DESCRIPTOR_VERSION,
        message_count=int(message_count),
        scrubber_outcome="clean",
    )

    phrase_drops = sum(
        1 for f, _l in scrub.layer2_matches if f == "common_phrases"
    )
    if phrase_drops or scrub.layer1_drop_count:
        result.status = OUTCOME_SCRUBBED_PARTIAL
    else:
        result.status = OUTCOME_SUCCESS
    result.descriptor = dict(scrub.scrubbed_descriptor)

    try:
        await db_call(
            clear_style_distill_contact_queue_entry,
            db_conn,
            account_id=account_id,
            recipient_hash=recipient_hash,
        )
    except Exception:
        log.exception(
            "per_contact distill: queue-clear failed on success path",
        )

    await db_call(
        _audit_per_contact, db_conn, account_id, actor_user_id, result,
    )
    return result


def _audit_per_contact(
    conn: sqlite3.Connection,
    account_id: int,
    actor_user_id: int | None,
    result: PerContactDistillResult,
) -> None:
    """Audit-row helper for per-contact runs. ``kind='per_contact'``;
    recipient_hash carries the digest (NEVER plaintext)."""
    scrub = result.scrub
    layer1 = scrub.layer1_drop_count if scrub else 0
    layer2 = scrub.layer2_match_count if scrub else 0
    if scrub is None:
        layer3 = 0
        degraded = False
    elif scrub.degraded:
        layer3 = -1
        degraded = True
    else:
        layer3 = scrub.layer3_entity_count
        degraded = False
    # Never let an audit-row failure bubble up; the SSOT logs a uniform
    # audit_write_failed WARNING (/health drift) on failure (run18 #2).
    safe_audit_write(
        lambda: record_style_distill_event(
            conn,
            account_id=account_id,
            actor_user_id=actor_user_id,
            backend_id=result.backend_id,
            backend_type=result.backend_type,
            was_cloud=result.was_cloud,
            outcome=result.status,
            latency_ms=result.latency_ms,
            layer1_drops=layer1,
            layer2_matches=layer2,
            layer3_entities=layer3,
            scrubber_degraded=degraded,
            error_class=result.error_class,
            kind="per_contact",
            recipient_hash=result.recipient_hash or None,
        ),
        description=(
            f"per_contact_style_distill account={account_id} "
            f"outcome={result.status}"
        ),
    )
    # N-241b R31 (2026-07-07 census r24 close-out — mirror sibling in
    # ``distill_hipaa._audit_and_return``): on any TERMINAL per-contact
    # outcome, clear the pre-existing ``style_distill_contact_queue``
    # row so a leftover retry doesn't re-fire the same terminal path
    # forever. Same set-selection rationale as the account-scope
    # sibling — CADENCE_SKIP re-fires, BACKEND_FAIL uses its retry
    # queue, BAA_REQUIRED calls the pause helper.
    #
    # Guard on ``result.recipient_hash`` truthiness: the salt-unavailable
    # and bad-address early-fail leaves use ``recipient_hash=""`` as a
    # sentinel (no valid hash yet) — those outcomes are BACKEND_FAIL
    # (not in the terminal set), so this guard is defensive-only.
    if (
        result.status in _TERMINAL_OUTCOMES_PER_CONTACT
        and result.recipient_hash
    ):
        try:
            clear_style_distill_contact_queue_entry(
                conn,
                account_id=account_id,
                recipient_hash=result.recipient_hash,
            )
        except Exception as _n241b_e:
            # Mirror N-304 R30 (silent-swallow → debug) on the account-
            # sibling: a transient DB error on terminal-outcome clear
            # silently persists the row → a retry worker (none exists at
            # HEAD — N-474) would re-select it and re-fire the terminal
            # path forever, defeating the
            # N-241b fix. Log at debug so /health isn't spammed but
            # forensics can find the miss on next incident.
            log.debug(
                "style_distill_contact_queue clear failed on terminal outcome",
                account_id=account_id,
                outcome=result.status,
                error=type(_n241b_e).__name__,
            )


# N-241b R31 (2026-07-07 census r24 close-out): outcomes that end the
# per-contact queue entry's life. Mirrors the sibling
# ``distill_hipaa._TERMINAL_OUTCOMES``. NOT the transient outcomes
# (CADENCE_SKIP is expected to re-fire; BACKEND_FAIL uses its own
# retry queue; BAA_REQUIRED calls pause_style_distill_account). Kept
# as a separate frozenset (not an import from sibling) so a future
# per-contact-only extension (e.g. treating a specific salt/address
# failure as terminal after N attempts) doesn't have to widen the
# sibling.
# SCRUBBED_PARTIAL is intentionally NOT in this set: the sibling
# ``distill_hipaa._TERMINAL_OUTCOMES`` also excludes it, and the
# explicit success-path clear at the caller site (mirrored here at
# line ~759 in the ``distill_hipaa_per_contact`` orchestrator body)
# owns the SCRUBBED_PARTIAL clear. Keeps the SSOT scope 1:1 with
# the sibling.
_TERMINAL_OUTCOMES_PER_CONTACT = frozenset({
    OUTCOME_SUCCESS,
    OUTCOME_NOT_HIPAA,
    OUTCOME_DISABLED,
    OUTCOME_NOT_OPTED_IN,
    OUTCOME_NO_MESSAGES,
})


# ---------------------------------------------------------------------------
# Draft-time look-up — overlay helper
# ---------------------------------------------------------------------------

def get_contact_style_overlay_with_hash(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_address: str,
    secrets: Any,
    freshness_days: int | None = None,
) -> tuple[dict[str, Any], str] | None:
    """N-346c-tail-B (hipaa-sme H1 same-commit fold per
    `feedback_dont_over_defer`) — same contract as
    :func:`get_contact_style_overlay` but returns the ``(descriptor,
    matched_hash)`` tuple so the audit-trail caller can record the
    EXACT hash under which the row was matched (§164.312(b) audit-
    trail cross-reference). Existing callers who only need the
    descriptor route through :func:`get_contact_style_overlay` which
    is now a thin ``(_, tuple[0])`` wrapper — no test signature drift.

    Returns ``None`` on any of the failure modes documented for
    :func:`get_contact_style_overlay`.
    """
    if not recipient_address:
        return None
    try:
        # N-346c dual-lookup — try every shape until a row matches. For
        # ASCII installs both shapes collide, one probe hits; for IDN
        # installs the canonical shape closes the A-label/U-label
        # collision without a persisted-hash migration.
        rhs = hash_recipient_for_install_all_shapes(
            recipient_address, secrets=secrets,
        )
    except (ValueError, SaltUnavailableError):
        return None

    row = None
    matched_hash: str | None = None
    for rh in rhs:
        row = get_per_contact_style_hipaa(
            conn, account_id=account_id, recipient_hash=rh,
        )
        if row is not None:
            matched_hash = rh
            break
    if row is None or matched_hash is None:
        return None

    # Freshness gate (identical semantics to the pre-N-346c-tail-B
    # `get_contact_style_overlay` body — kept inline here so both entry
    # points share ONE implementation of the freshness contract).
    fresh = (
        HIPAA_PER_CONTACT_FRESHNESS_DAYS
        if freshness_days is None
        else int(freshness_days)
    )
    rebuilt_at = row.get("last_distilled_at")
    if not rebuilt_at:
        return None
    ts = parse_iso_aware(rebuilt_at)
    if ts is None:
        return None
    age = datetime.now(timezone.utc) - ts
    if age > timedelta(days=fresh):
        return None
    return dict(row.get("descriptor") or {}), matched_hash


def get_contact_style_overlay(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_address: str,
    secrets: Any,
    freshness_days: int | None = None,
) -> dict[str, Any] | None:
    """Return the per-contact style descriptor for a recipient, or None.

    Hashes the recipient with the install salt + looks up the
    ``per_contact_style_hipaa`` row. Returns the descriptor dict ONLY
    if the row is fresher than ``freshness_days`` (default
    :data:`HIPAA_PER_CONTACT_FRESHNESS_DAYS` / 30 days). Stale rows
    return None so the caller falls back to the account-level
    descriptor without an overlay.

    The draft-time caller is responsible for the actual overlay merge
    (combining account-level + per-contact descriptors into one
    prompt prefix). This helper is the lookup layer; the merge
    semantics live in the draft path.

    N-346c-tail-B: this function is now a thin wrapper on
    :func:`get_contact_style_overlay_with_hash` which returns the
    matched-hash tuple for audit-trail-integrity callers. Existing
    callers who only need the descriptor keep this signature.

    Failure modes (return None, never raise):
      * ``recipient_address`` empty / unparseable
      * salt unavailable
      * no per-contact row for the hashed key
      * row exists but is older than ``freshness_days``
      * stored descriptor JSON is corrupt
    """
    got = get_contact_style_overlay_with_hash(
        conn,
        account_id=account_id,
        recipient_address=recipient_address,
        secrets=secrets,
        freshness_days=freshness_days,
    )
    if got is None:
        return None
    # `_with_hash` already applied the freshness gate; return the
    # descriptor (first tuple element).
    return got[0]


# ---------------------------------------------------------------------------
# Daily GC sweep
# ---------------------------------------------------------------------------

def per_contact_gc_daily_sweep(
    conn: sqlite3.Connection,
    *,
    gc_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Delete per-contact descriptors older than ``gc_days`` (default 90).

    Sibling to :func:`email_triage.baa_expiry.baa_expiry_daily_sweep`.
    Returns a summary ``{"removed": <int>, "swept_at": "<ISO>", "gc_days": <int>}``.

    Idempotent — re-running on a clean state returns ``removed=0``.

    The supervised loop in :mod:`email_triage.web.app` calls this once
    per day; the sweep itself is cheap (single DELETE) so running it
    multiple times is harmless.
    """
    days = HIPAA_PER_CONTACT_GC_DAYS if gc_days is None else int(gc_days)
    removed = gc_per_contact_style_hipaa(
        conn, gc_days=days, now=now,
    )
    return {
        "removed": int(removed),
        # N-203 R22 (2026-07-02): route through the A10 stored-ISO SSOT
        # (`_isotime.to_utc_iso` for a supplied `now`, else `now_utc_iso()`).
        # The pre-N-203 `(now or datetime.now(tz)).isoformat()` BoolOp shape
        # bypassed the pin's Name/BinOp/Call/UnaryOp coverage — A10 pin has
        # been widened to walk BoolOp too (see test_now_iso_utc_pin_a10.py).
        "swept_at": to_utc_iso(now) if now is not None else now_utc_iso(),
        "gc_days": days,
    }


# ---------------------------------------------------------------------------
# Draft-time merge helpers
# ---------------------------------------------------------------------------

#: Descriptor fields treated as strings — overlay wins when its value
#: is non-empty AND differs from base.
_OVERLAY_STRING_FIELDS = (
    "tone",
    "greeting_style",
    "signoff_style",
    "sentence_length_pref",
    "vocabulary_register",
)

#: Descriptor fields treated as integers — overlay wins for any
#: different value, INCLUDING 0 (a per-contact descriptor that says
#: "formality_level=1, terse" is a meaningful override of an account-
#: level "formality_level=3").
_OVERLAY_NUMERIC_FIELDS = (
    "formality_level",
    "paragraph_count_typical",
)

#: Descriptor fields treated as ordered lists. Overlay values are
#: UNIONED with the base; deduplication is case-insensitive but
#: order-preserving (base order first, then any overlay entries not
#: already represented).
_OVERLAY_LIST_FIELDS = (
    "common_phrases",
)


def apply_contact_overlay(
    base: dict[str, Any] | None,
    overlay: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    """Merge ``overlay`` on top of ``base``. Pure logic.

    Returns ``(merged_dict, overridden_fields)``. Semantics:

    * String fields (``_OVERLAY_STRING_FIELDS``): overlay wins when its
      value is non-empty AND differs from base.
    * Numeric fields (``_OVERLAY_NUMERIC_FIELDS``): overlay wins for any
      different value, including 0.
    * List fields (``_OVERLAY_LIST_FIELDS``): union + dedup
      case-insensitively, preserving base order then appending overlay
      entries that aren't already represented.
    * Unknown overlay fields (not in any of the above lists) are
      forwarded verbatim — forward compatibility for descriptor schema
      additions that ship before this helper is updated.

    Boundary cases:

    * ``overlay`` is None or empty -> returns ``(dict(base or {}), [])``.
    * ``base`` is None or empty + ``overlay`` non-empty -> returns
      ``(dict(overlay), [<every overlay field>])``.

    Never raises — descriptor sources are trusted to be dicts but a
    malformed entry just falls through without contributing.
    """
    merged: dict[str, Any] = dict(base or {})
    overridden: list[str] = []

    if not overlay:
        return merged, overridden

    # Empty-base + overlay -> overlay verbatim, every overlay field
    # counts as an override. Keeps the contract simple for the
    # "no account-level descriptor at all" path.
    if not base:
        out = dict(overlay)
        return out, list(overlay.keys())

    # Strings — overlay wins on non-empty + different.
    for field_name in _OVERLAY_STRING_FIELDS:
        if field_name not in overlay:
            continue
        ov_val = overlay.get(field_name)
        if ov_val is None:
            continue
        ov_str = str(ov_val).strip()
        if not ov_str:
            continue
        base_val = merged.get(field_name)
        base_str = "" if base_val is None else str(base_val).strip()
        if ov_str != base_str:
            merged[field_name] = ov_val
            overridden.append(field_name)

    # Numerics — overlay wins on any different value, including 0.
    for field_name in _OVERLAY_NUMERIC_FIELDS:
        if field_name not in overlay:
            continue
        ov_val = overlay.get(field_name)
        if ov_val is None:
            continue
        ov_int = parse_int_or_none(ov_val)  # N-219c/11 R23: SSOT
        if ov_int is None:
            continue
        base_val = merged.get(field_name)
        base_int = parse_int_or_none(base_val)  # N-219c/42 R23: SSOT
        if ov_int != base_int:
            merged[field_name] = ov_int
            overridden.append(field_name)

    # Lists — union + case-insensitive dedup, base order first.
    for field_name in _OVERLAY_LIST_FIELDS:
        if field_name not in overlay:
            continue
        ov_list = overlay.get(field_name)
        if not isinstance(ov_list, list):
            continue
        base_list = merged.get(field_name) or []
        if not isinstance(base_list, list):
            base_list = []
        seen_lower: set[str] = set()
        out_list: list[Any] = []
        for item in base_list:
            if not isinstance(item, str):
                continue
            key = item.strip().lower()
            if not key or key in seen_lower:
                continue
            seen_lower.add(key)
            out_list.append(item)
        added = False
        for item in ov_list:
            if not isinstance(item, str):
                continue
            key = item.strip().lower()
            if not key or key in seen_lower:
                continue
            seen_lower.add(key)
            out_list.append(item)
            added = True
        merged[field_name] = out_list
        if added:
            overridden.append(field_name)

    # Forward-compat: unknown overlay fields get copied straight across
    # so a descriptor-schema addition lands without a parallel update
    # to this helper.
    known = (
        set(_OVERLAY_STRING_FIELDS)
        | set(_OVERLAY_NUMERIC_FIELDS)
        | set(_OVERLAY_LIST_FIELDS)
    )
    for k, v in overlay.items():
        if k in known:
            continue
        if merged.get(k) != v:
            merged[k] = v
            overridden.append(k)

    return merged, overridden


def merge_overlays_for_recipients(
    conn: sqlite3.Connection,
    account_id: int,
    recipient_addresses: Iterable[str],
    *,
    secrets: Any,
    freshness_days: int | None = None,
    cache: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Layer per-contact overlays for a multi-recipient draft.

    For each address in ``recipient_addresses`` (typically the To: list
    of a draft, which equals the From: of the inbound message), looks
    up the per-contact overlay via :func:`get_contact_style_overlay`
    and pairwise-merges via :func:`apply_contact_overlay`.

    Returns ``(merged_overlay_or_None, list_of_recipient_hashes)``.
    The second element is the hashes (NOT the plaintext addresses) of
    recipients that contributed an overlay — suitable for audit
    logging.

    Multi-recipient precedence: layered left-to-right, so the last
    recipient in the iterable wins on scalar conflicts (the union
    semantic on list fields means all phrases survive). Callers that
    care about a specific recipient should pass that recipient first.

    ``cache`` is an optional per-request dict for memoizing the salt
    + per-address lookups; pass the same dict across multiple draft
    builds in the same request to avoid re-hashing.

    Failure-safe — never raises. A None / empty ``recipient_addresses``
    returns ``(None, [])``; addresses with no overlay are silently
    skipped.
    """
    addresses_list = [a for a in recipient_addresses if a]
    if not addresses_list:
        return None, []

    merged: dict[str, Any] | None = None
    contributing_hashes: list[str] = []
    seen_hashes: set[str] = set()
    cache_dict = cache if cache is not None else {}

    for addr in addresses_list:
        # the backlog  sub-finding (DA panel F1 same-drive closure —
        # feedback_dont_over_defer): per-address memoization keyed on
        # the CANONICAL address, not raw ``.strip().lower()``. Under
        # display-name-wrap divergence (``"Name <a@b>"`` vs ``"a@b"``)
        # or IDNA divergence (U-label vs A-label), the raw form would
        # allocate TWO cache slots for the same real recipient — a
        # miss on the second slot degraded the per-contact HIPAA
        # overlay to the global scrubber (§164.312(c)(1) integrity
        # gap). The plaintext address NEVER leaves this function on
        # the audit path; the cache key is internal-only.
        cache_key = ("overlay", account_id, canonical_email(addr))
        if cache_key in cache_dict:
            entry = cache_dict[cache_key]
            overlay = entry.get("overlay")
            # N-346c-tail-B (fold — hipaa-sme H1): cache carries the
            # SINGLE matched hash (post-fold from the earlier "hashes"
            # list). Accept legacy single-"hash" AND legacy list-"hashes"
            # cache entries opportunistically to avoid a hard cache-
            # invalidation on hot-reload; new entries always use "hash".
            matched_hash = entry.get("hash")
            if matched_hash is None:
                _legacy_hashes = entry.get("hashes")
                if _legacy_hashes:
                    matched_hash = _legacy_hashes[0]
        else:
            overlay = None
            matched_hash: str | None = None
            try:
                # N-346c-tail-B (fold — hipaa-sme H1 + DA F1 combined
                # per operator directive 2026-07-08 "no more WAITING-ON-
                # OP as a defer mechanism"): use the _with_hash entry
                # point so the audit-trail records the EXACT shape hash
                # under which the row was matched. Records ONE hash per
                # row (not all shapes), so `contributing_hashes` stays
                # a minimal audit surface + closes the §164.312(b)
                # cross-reference class post-backfill without a size
                # bloat + without a downtime backfill window.
                got = get_contact_style_overlay_with_hash(
                    conn,
                    account_id=account_id,
                    recipient_address=addr,
                    secrets=secrets,
                    freshness_days=freshness_days,
                )
                if got is not None:
                    overlay, matched_hash = got
            except Exception:
                # Lookup failure-safe — never let a draft fail because
                # the overlay layer threw. Log + skip.
                log.exception(
                    "merge_overlays_for_recipients: lookup failed",
                    extra={"_extra": {"account_id": account_id}},
                )
                overlay = None
                matched_hash = None
            cache_dict[cache_key] = {"overlay": overlay, "hash": matched_hash}

        if overlay is None:
            continue
        merged, _overridden = apply_contact_overlay(merged, overlay)
        if matched_hash and matched_hash not in seen_hashes:
            seen_hashes.add(matched_hash)
            contributing_hashes.append(matched_hash)

    return merged, contributing_hashes


__all__ = [
    "HIPAA_RECIPIENT_SALT_SECRET_KEY",
    "RECIPIENT_HASH_LEN",
    "PER_CONTACT_SYSTEM_FRAMING",
    "HIPAA_PER_CONTACT_REBUILD_INTERVAL_HOURS",
    "PerContactDistillResult",
    "SaltUnavailableError",
    "apply_contact_overlay",
    "distill_hipaa_per_contact",
    "get_contact_style_overlay",
    "get_or_init_recipient_salt",
    "hash_message_id_for_install",
    "hash_recipient_for_install",
    "merge_overlays_for_recipients",
    "per_contact_gc_daily_sweep",
]
