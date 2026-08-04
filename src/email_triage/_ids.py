"""N-244 R24 — short-id minter SSOT (2026-07-03).

Census R24 discovered MED (short-id minter unification): 11 sites
tree-wide fork the "prefix + short-random-suffix" ID minter across 4
shapes:

- `uuid.uuid4().hex[:12]` (5 sites — topic_configs.py, email_watches.py, etc.).
- `secrets.token_hex(6)` (2 sites — acme_job_state.py, etc.).
- 8-hex vs 16-hex tails on ACME probe/attempt IDs (acme_renewer.py).

Format families already split (uuid vs secrets) — the SSOT must be
width-parametric to converge them. Migration bodies (frozen per
`incident_2026-06-11_migration_body_immutability`) are excluded — those
2 sites re-fork legitimately and are exempted from the pin.

Choice: `secrets.token_hex(length)` — cryptographically random,
matches the existing acme + session convention, no uuid coupling to
the 128-bit-uuid layout. Returns lowercase hex.
"""
from __future__ import annotations

import secrets as _stdlib_secrets

# Default length: 12 chars = 6 bytes = 48 bits of entropy — plenty
# for a random suffix in a scoped table + operator-visible ID.
_DEFAULT_LENGTH = 12


def new_run_id(kind: str, account_id: int, *extra: str | int,
                length: int = _DEFAULT_LENGTH) -> str:
    """Mint a fresh triage-run correlation ID.

    Shape: ``<kind>_<account_id>[_<extra>...]_<random-hex>`` — matches the
    tree-wide ``<trigger>_<account_id>_<tag>`` convention that
    ``record_triage_run`` + downstream operators grep for, but with a
    collision-free random tail replacing the ``int(time.time())`` epoch
    (Census v3 re-run #6 — second-precision epoch is COLLIDABLE at
    load; two ingestion terminals firing within the same second minted
    duplicate run_ids, breaking ``triage_runs`` unique-observability
    for the burst).

    ``extra`` positional parts fold into the ID between account_id and
    the random tail (used by IMAP-poll to encode the mailbox — e.g.
    ``new_run_id("imap_poll", 42, "INBOX")`` →
    ``"imap_poll_42_INBOX_a1b2c3d4e5f6"``).

    Prime Directive #6: this SSOT ships with ``tests/test_new_run_id_
    ssot_pin.py`` in the same change (see census recommendation).
    """
    parts = [str(kind), str(account_id), *(str(x) for x in extra)]
    return new_short_id("_".join(parts), length=length)


def new_short_id(prefix: str, *, length: int = _DEFAULT_LENGTH) -> str:
    """Mint a fresh short random ID: ``<prefix>_<random-hex>``.

    ``length`` is the number of HEX CHARACTERS (not bytes) in the
    random tail. `secrets.token_hex(n)` returns ``2n`` hex chars, so
    the call site here divides by 2. Odd `length` rounds up to the
    next even value.

    Example: ``new_short_id("watch")`` → ``"watch_a1b2c3d4e5f6"``.
    ``new_short_id("acme", length=8)`` → ``"acme_1a2b3c4d"``.

    The prefix separator is ``_`` (matches existing acme_/watch_/tdig_
    conventions). Empty prefix yields the bare hex tail (useful for
    attempt_id-shaped uses where the caller composes the label
    elsewhere).
    """
    byte_count = (length + 1) // 2
    hex_tail = _stdlib_secrets.token_hex(byte_count)[:length]
    if not prefix:
        return hex_tail
    return f"{prefix}_{hex_tail}"
