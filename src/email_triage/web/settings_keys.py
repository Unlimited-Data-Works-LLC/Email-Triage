"""Centralised settings-key catalogue.

All ``settings`` table keys go through this module so the canonical
shape lives in one place. Two motivations:

1. **Naming consistency** — most keys are ``<thing>:<id>`` (e.g.
   ``watch:42``); a small number of legacy keys use the inverted
   ``<scope>:<id>:<thing>`` shape (e.g. ``account_state:42:foo``,
   ``user:1:bar``). New keys MUST use ``<thing>:<id>``; legacy keys
   are preserved here as documented exceptions so a per-account
   delete sweep can find every tombstone without grepping the
   codebase.

2. **Per-account delete sweep** — :func:`account_settings_keys`
   returns every key shape that is parameterised by ``account_id``,
   and :func:`delete_account_settings` deletes them all in one
   transaction. Useful for the future account-delete handler
   plus backup/restore tests that want to round-trip a single
   account's settings cleanly.

Existing call sites pass keys built from f-strings inline; this
module exposes builder functions so code can read as
``S.watch(account_id)`` instead of ``f"watch:{account_id}"``. Both
shapes resolve to the same string, so a partial migration is safe —
this is a code-readability cleanup, not a data migration.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable


# ---------------------------------------------------------------------------
# Per-account keys (<thing>:<id> shape)
# ---------------------------------------------------------------------------

def watch(account_id: int) -> str:
    """``watch:<id>`` — IMAP-IDLE watcher enabled flag (legacy mirror)."""
    return f"watch:{int(account_id)}"


def watch_hwm(account_id: int) -> str:
    """``watch_hwm:<id>`` — INBOX HWM (legacy single-mailbox shape)."""
    return f"watch_hwm:{int(account_id)}"


def watch_hwm_mailbox(account_id: int, mailbox: str) -> str:
    """``watch_hwm:<id>:mailbox:<name>`` — per-mailbox HWM."""
    return f"watch_hwm:{int(account_id)}:mailbox:{mailbox}"


def calendar_enabled(account_id: int) -> str:
    """``calendar_enabled:<id>`` — per-account calendar opt-in."""
    return f"calendar_enabled:{int(account_id)}"


def digest(account_id: int) -> str:
    """``digest:<id>`` — legacy single-config digest settings key.

    The UI that read/wrote this (digest_save_config + digest_generate)
    was retired in . Key builder stays: old installs can carry
    vestigial ``digest:<id>`` rows and ``_ACCOUNT_KEY_CATALOG``
    references the prefix for delete-sweep cleanup. Canonical
    definition of the key shape.
    """
    return f"digest:{int(account_id)}"


def digest_schedules(account_id: int) -> str:
    """``digest_schedules:<id>`` — legacy multi-schedule digest config.

    The digest_schedules CRUD UI was retired in , but the key
    builder stays: old installs can still carry vestigial
    ``digest_schedules:<id>`` rows, and ``_ACCOUNT_KEY_CATALOG``
    references this prefix so the per-account delete sweep cleans
    them up. This function is the canonical definition of that key
    shape.
    """
    return f"digest_schedules:{int(account_id)}"


def auth_stale(account_id: int) -> str:
    """``auth_stale:<id>`` — OAuth refresh-token-death flag."""
    return f"auth_stale:{int(account_id)}"


def backfill_capped(account_id: int) -> str:
    """``backfill_capped:<id>`` — set when a cursor-expiry recovery
    (Gmail history-expired / O365 delta-resync) saturated the bounded
    backfill cap, so older mail in the gap may not have been
    enumerated/triaged. Surfaced as an account-row chip on
    /accounts (which carries the dismiss) AND a banner on the dashboard
    landing page; cleared by a manual dismiss or account delete."""
    return f"backfill_capped:{int(account_id)}"


def gmail_oauth_flow(account_id: int) -> str:
    """``gmail_oauth_flow:<id>`` — 'manual' | 'web'."""
    return f"gmail_oauth_flow:{int(account_id)}"


def poll_state(account_id: int) -> str:
    """``poll_state:<id>`` — last unified-poll timestamp."""
    return f"poll_state:{int(account_id)}"


def openclaw_quiet(account_id: int) -> str:
    """``openclaw_quiet:<id>`` — LEGACY outbound-webhook mute toggle.

    Kept as a read-fallback for pre-rename installs (see ``webhook_quiet``).
    New writes go through ``webhook_quiet``; readers try the new key first
    and fall back to this one, so old rows keep working without a migration.

    SUNSET GUARD (db-sme F2): do NOT remove this builder OR its
    ``("openclaw_quiet:", True)`` catalog entry until a one-time migration has
    rewritten every ``openclaw_quiet:<id>`` row to ``webhook_quiet:<id>``.
    Removal before then silently ORPHANS pre-rename rows on account-delete (the
    disposal sweep is catalog-driven — §164.310(d)(2)(i)). While a read-fallback
    to this key exists in src, the catalog entry is mandatory — enforced by
    ``tests/test_settings_key_catalog_pin.py`` (legacy-read ⇒ disposal-catalog leg).
    """
    return f"openclaw_quiet:{int(account_id)}"


def webhook_quiet(account_id: int) -> str:
    """``webhook_quiet:<id>`` — per-account outbound-webhook mute toggle."""
    return f"webhook_quiet:{int(account_id)}"


def style_profile(account_id: int) -> str:
    """``style_profile:<id>`` — RAG/M-series style learnings."""
    return f"style_profile:{int(account_id)}"


def rag_sent_index_enabled(account_id: int) -> str:
    """``rag_sent_index_enabled:<id>`` — sent-mail RAG index toggle."""
    return f"rag_sent_index_enabled:{int(account_id)}"


def style_knobs_hipaa_allow(account_id: int) -> str:
    """``style_knobs_hipaa_allow:<id>`` — per-account opt-in for the
    M-1+M-2 operator-stated style knobs on a HIPAA-flagged account.

    the backlog  Phase 2 (2026-05-11). Default OFF; operator
    explicitly ticks to enable. M-1+M-2 take operator-typed strings
    (style guide + tone / length / greeting / signature radios), which
    are operator self-disclosure (§164.502(a)) — not PHI by
    construction. M-3 / M-4 / M-7 stay hard-off regardless of this
    flag; see ``docs/hipaa-audit.md`` for the audit and
    ``internal documentation`` for the sign-off log.
    """
    return f"style_knobs_hipaa_allow:{int(account_id)}"


def office365_clientstate(account_id: int) -> str:
    """``office365_clientstate:<id>`` — Graph webhook clientState (in secrets)."""
    return f"office365_clientstate:{int(account_id)}"


def office365_poll_cursor(account_id: int) -> str:
    """``office365_poll_cursor:<id>`` — Graph delta cursor for poll mode.

     — the unified poll loop's O365 dispatch walks the Inbox delta
    feed; the ``@odata.deltaLink`` it gets back must persist between
    ticks so the next tick fetches only what changed. The push path
    stores its cursor on the ``office365_subscriptions`` row, but a
    poll-only account (push not configured) has no such row — this
    settings key is the poll-mode cursor home. Value shape:
    ``{"delta_link": "<absolute-url>"}``.
    """
    return f"office365_poll_cursor:{int(account_id)}"


# ---------------------------------------------------------------------------
# Per-user keys (<thing>:<id> shape)
# ---------------------------------------------------------------------------

def meeting_prefs(user_id: int) -> str:
    """``meeting_prefs:<id>`` — per-user calendar preferences."""
    return f"meeting_prefs:{int(user_id)}"


def escalation_sms(user_id: int) -> str:
    """``escalation_sms:<id>`` — per-user SMS escalation prefs."""
    return f"escalation_sms:{int(user_id)}"


def last_routes_account_id(user_id: int) -> str:
    """``last_routes_account_id:<id>`` — sticky /routes account selector."""
    return f"last_routes_account_id:{int(user_id)}"


# ---------------------------------------------------------------------------
# Install-wide (non-parameterised) keys
# ---------------------------------------------------------------------------

#: ``cache.redis_url`` — install-wide Redis connection URL for the
#: optional classification cache. Empty / missing = cache OFF.
#: Real persistence lives in YAML (``config.redis_cache.url``); these
#: constants exist so call sites can reach for the same name as the
#: settings key registry rather than hand-typing the string. The
#: settings-table row is treated as the cached read-time hint and is
#: kept in lockstep with YAML by the admin save handler.
CACHE_REDIS_URL = "cache.redis_url"

#: ``cache.classification_enabled`` — derived flag (URL non-empty ⇒
#: enabled). Reserved for future use if an operator wants to keep the
#: URL on file but disable the cache temporarily without clearing
#: state. Not currently surfaced in the admin UI; URL empty = OFF.
CACHE_CLASSIFICATION_ENABLED = "cache.classification_enabled"

#: ``cache.classification_ttl_seconds`` — TTL applied to cache entries.
#: Bounded [3600, 7_776_000] = 1h to 90d via
#: :func:`email_triage.cache.classification.clamp_ttl_secs`.
CACHE_CLASSIFICATION_TTL_SECONDS = "cache.classification_ttl_seconds"

#: ``cache.skip_hipaa_accounts`` — operator-visible name for the
#: HIPAA-skip behaviour. Hard-on by design — the cache module's
#: ``cache_lookup_for_message`` checks ``message.hipaa`` regardless
#: of this key. Constant kept so future "encrypted-value variant"
#: work has a stable name to grow into without inventing one mid-flight.
CACHE_SKIP_HIPAA_ACCOUNTS = "cache.skip_hipaa_accounts"


#: ``anti_ai_style_guide_global`` — install-wide free-text list of AI
#: mannerisms the draft-reply LLM should avoid. Operator-typed in the
#: textarea on /config. Persisted as a JSON string (single value, no
#: dict wrapper) via ``set_setting`` / ``get_setting``. Default missing
#: row is treated as the empty string. Per-user override lives on the
#: ``users`` table (column ``anti_ai_style_guide_user``); the two stack
#: at draft-reply prompt-build time unless the user ticks "Disable the
#: install-wide guide for my account".
ANTI_AI_STYLE_GUIDE_GLOBAL = "anti_ai_style_guide_global"


# ---------------------------------------------------------------------------
# DOCUMENTED LEGACY EXCEPTIONS — `<scope>:<id>:<thing>` shape.
#
# These keys predate the convention and are preserved verbatim for
# back-compat. Existing rows under these keys MUST keep working;
# new keys should use the ``<thing>:<id>`` shape above.
# ---------------------------------------------------------------------------

def account_state(account_id: int, thing: str) -> str:
    """``account_state:<id>:<thing>`` — legacy per-account state bag."""
    return f"account_state:{int(account_id)}:{thing}"


def user_scoped(user_id: int, thing: str) -> str:
    """``user:<id>:<thing>`` — legacy per-user state bag."""
    return f"user:{int(user_id)}:{thing}"


# ---------------------------------------------------------------------------
# Per-account delete sweep
# ---------------------------------------------------------------------------

# Catalogue of every key prefix that is parameterised by account_id.
# Each entry maps to a tuple ``(prefix, exact_match)``:
#   - ``exact_match=True``  → key equals ``<prefix><id>`` (e.g. ``watch:42``)
#   - ``exact_match=False`` → key starts with ``<prefix><id>`` and may have
#     additional segments (e.g. ``watch_hwm:42:mailbox:INBOX``)
#
# This list is the per-account DISPOSAL net (§164.310(d)(2)(i)). It is bound by
# the BIDIRECTIONAL, count-agnostic, interprocedural pin
# ``tests/test_settings_key_catalog_pin.py``: every account-scoped
# ``set_setting``-written prefix MUST be here (no ORPHAN that survives a delete),
# and every prefix here MUST have a writer or a ``settings_keys`` builder (no
# PHANTOM / false coverage). When you add an account-scoped key anywhere in src,
# add it here too — the pin will fail until you do.
#
# A key whose value lives in the SECRETS store (not the ``settings`` table) does
# NOT belong here — it is purged via the secrets path in
# ``db/accounts.py::purge_account_local_state`` (see ``office365_clientstate``
# above: a Graph webhook clientState, removed from this catalog in run17 
# because a settings-sweep entry was a no-op against the settings table and
# falsely implied coverage).
_ACCOUNT_KEY_CATALOG: tuple[tuple[str, bool], ...] = (
    ("watch:", True),
    ("watch_hwm:", False),  # covers both legacy-single + per-mailbox shapes
    ("calendar_enabled:", True),
    # --- Digest family (all account-scoped, all written via set_setting) -----
    ("digest:", True),            # legacy single-config (read/write UI retired )
    ("digest_schedules:", True),  # legacy multi-schedule (CRUD UI retired )
    ("digest_configs:", True),    # unified per-account digest config store
    ("digest_state:", False),     # per-digest send state: digest_state:<id>:<digest_id>
    ("recipient_digest_state:", True),  # legacy single-config send state
    # -------------------------------------------------------------------------
    ("auth_stale:", True),
    ("backfill_capped:", True),
    ("gmail_oauth_flow:", True),
    ("poll_state:", True),
    ("openclaw_quiet:", True),   # legacy read-fallback — MANDATORY while src still
                                 # reads this key; removal orphans pre-rename rows
                                 # on delete (sunset guard, see openclaw_quiet()).
    ("webhook_quiet:", True),
    ("style_profile:", True),
    ("rag_sent_index_enabled:", True),
    ("style_knobs_hipaa_allow:", True),
    ("office365_poll_cursor:", True),
    ("account_state:", False),  # legacy <prefix><id>:<thing> (e.g. :wizard_step)
    ("mailbox_routes:", False),  # per-mailbox routing: mailbox_routes:<id>:<mailbox>
    ("ratelimit:triage_preview:", True),  # per-account preview rate-limit row
)


def account_settings_keys(account_id: int) -> Iterable[tuple[str, bool]]:
    """Yield ``(key_or_prefix, exact_match)`` pairs for ``account_id``.

    Useful for callers that want to inspect (e.g. backup ) what's
    on file before / after a delete sweep.
    """
    aid = int(account_id)
    for prefix, exact in _ACCOUNT_KEY_CATALOG:
        yield (f"{prefix}{aid}", exact)


def delete_account_settings(
    conn: sqlite3.Connection,
    account_id: int,
) -> int:
    """Delete every ``settings`` row keyed off ``account_id``.

    Returns the number of rows deleted. Single transaction; safe
    against partial-failure mid-delete. Does NOT touch ``email_accounts``
    itself — callers that want a full account purge should call this
    plus the row-delete in one outer transaction.
    """
    aid = int(account_id)
    deleted = 0
    cur = conn.cursor()
    try:
        for prefix, exact in _ACCOUNT_KEY_CATALOG:
            if exact:
                # Direct equality — fast path.
                r = cur.execute(
                    "DELETE FROM settings WHERE key = ?",
                    (f"{prefix}{aid}",),
                )
            else:
                # LIKE prefix — covers legacy <prefix><id>:<segments...>.
                # Anchor with the colon so ``watch_hwm:1`` doesn't
                # accidentally match ``watch_hwm:10`` etc. ESCAPE the LIKE
                # metachars in the literal head: the catalog prefixes contain
                # ``_`` (a LIKE single-char wildcard, e.g. ``recipient_digest_state:``),
                # so without escaping a near-colliding key could be over-deleted
                # (run17  DA defense-in-depth; metachars are confined to the
                # constant prefix, so this is hardening, not a live over-delete).
                head = f"{prefix}{aid}:".replace("\\", "\\\\").replace("_", "\\_").replace("%", "\\%")
                r = cur.execute(
                    "DELETE FROM settings WHERE key = ? OR key LIKE ? ESCAPE '\\'",
                    (f"{prefix}{aid}", f"{head}%"),
                )
            deleted += r.rowcount or 0
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # Keep the in-process settings cache coherent. The bulk
    # DELETE bypasses delete_setting(); a per-key invalidation here
    # would require knowing every legacy <prefix>:<id>:<segments>
    # variant in flight, so flush the entire cache instead. Account
    # deletion is rare; cost is negligible.
    from email_triage.web.db import invalidate_setting_cache
    invalidate_setting_cache()

    return deleted
