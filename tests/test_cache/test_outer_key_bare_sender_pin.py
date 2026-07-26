"""census run17  — classification outer cache key keys on the BARE sender.

``make_outer_cache_key`` buckets every classification from one sender into a
single Redis HASH (the inner field — subject + body_hash — discriminates the
individual message). Before this fix the bucket key used ``_norm(sender)``,
which lower-cases + collapses whitespace but KEEPS the display name. So two
sends from the SAME address with a drifting display name —
``"Acme News" <news@acme.com>`` vs ``"Acme News via Mailgun" <news@acme.com>``
— forked into two HASHes for one sender, a silent cache-hit-rate loss on the
classifier hot path. The fix routes the sender through the
``mail_headers.extract_bare_address`` SSOT, so the bucket is keyed on the bare
address and display-name drift no longer fragments it.

WHY A BEHAVIORAL PIN, NOT A BLANKET STRUCTURAL ONE (verify-don't-accept note):
census  framed this as "sender-identity keys route through
extract_bare_address" across "2 groupers + 2 cache keys". On inspection the
four sites are NOT one copy-pasted grouper — they are semantically distinct
surfaces with different correctness constraints:

  * ``cache/classification.py:make_outer_cache_key`` — the LIVE cache bucket
    (this file's subject). Keying on the bare address is purely beneficial:
    cache-only, no delivery impact, and strictly more correct. FIXED.
  * ``cache/classification.py:make_cache_key`` — the LEGACY flat key, no
    longer on the live lookup/store path and kept ONLY for back-compat with
    tests that pin its pre-2026-05-13 hash shape. Re-keying it would break
    those pins for zero live benefit. LEFT AS-IS (documented residual).
  * ``actions/digest.py`` (newsletter ``SenderGroup``) and
    ``actions/digest_render.py`` (``group_by == "sender"``) — DELIVERY
    grouping. ``digest_render`` carries an explicit comment that it
    deliberately keys on the raw header; changing either alters the section
    grouping of a *delivered* digest. Per the delivery-correctness rule these
    are NOT force-changed. LEFT AS-IS (documented residual).
  * ``actions/style_profile.py`` already buckets via
    ``db.accounts.normalise_from_address``, which composes on
    ``extract_bare_address`` — already SSOT-routed. No change.

A blanket structural "every sender key calls extract_bare_address" pin would
false-positive on the two deliberate delivery groupers, so the fix is pinned
behaviorally on the one site it changes.
"""

from __future__ import annotations

from email_triage.cache.classification import make_outer_cache_key


_COMMON = dict(
    account_id=7,
    classifier_model="qwen3.5:35b",
    categories={"fyi": "info"},
)


def test_outer_key_is_display_name_independent():
    """Same bare address, drifting display name → SAME outer bucket key."""
    bare = make_outer_cache_key(sender="news@acme.com", **_COMMON)
    named = make_outer_cache_key(sender='"Acme News" <news@acme.com>', **_COMMON)
    via = make_outer_cache_key(
        sender='"Acme News via Mailgun" <NEWS@acme.com>', **_COMMON,
    )
    assert bare == named == via, (
        "outer cache key must not fork on display-name (or casing) drift for "
        "one sender address — it should key on extract_bare_address(sender)"
    )


def test_outer_key_distinguishes_distinct_addresses():
    """Different addresses → different bucket keys (no over-collapse)."""
    a = make_outer_cache_key(sender="news@acme.com", **_COMMON)
    b = make_outer_cache_key(sender="news@other.com", **_COMMON)
    assert a != b


def test_outer_key_routes_through_bare_address_ssot():
    """The key derivation matches feeding the bare address straight in — i.e.
    it is the SSOT's output that lands in the key, not the raw header."""
    from email_triage.mail_headers import extract_bare_address

    raw = '"Acme News" <news@acme.com>'
    assert extract_bare_address(raw) == "news@acme.com"
    assert make_outer_cache_key(sender=raw, **_COMMON) == make_outer_cache_key(
        sender=extract_bare_address(raw), **_COMMON,
    )
