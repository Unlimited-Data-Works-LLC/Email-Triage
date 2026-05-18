"""Centralised settings-key catalogue (#140.3).

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
   transaction. Useful for the future account-delete handler (#65)
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
    """``digest:<id>`` — legacy single-schedule digest config."""
    return f"digest:{int(account_id)}"


def digest_schedules(account_id: int) -> str:
    """``digest_schedules:<id>`` — multi-schedule digest config."""
    return f"digest_schedules:{int(account_id)}"


def auth_stale(account_id: int) -> str:
    """``auth_stale:<id>`` — OAuth refresh-token-death flag."""
    return f"auth_stale:{int(account_id)}"


def gmail_oauth_flow(account_id: int) -> str:
    """``gmail_oauth_flow:<id>`` — 'manual' | 'web'."""
    return f"gmail_oauth_flow:{int(account_id)}"


def poll_state(account_id: int) -> str:
    """``poll_state:<id>`` — last unified-poll timestamp."""
    return f"poll_state:{int(account_id)}"


def openclaw_quiet(account_id: int) -> str:
    """``openclaw_quiet:<id>`` — OpenClaw outbound mute toggle."""
    return f"openclaw_quiet:{int(account_id)}"


def style_profile(account_id: int) -> str:
    """``style_profile:<id>`` — RAG/M-series style learnings."""
    return f"style_profile:{int(account_id)}"


def rag_sent_index_enabled(account_id: int) -> str:
    """``rag_sent_index_enabled:<id>`` — sent-mail RAG index toggle."""
    return f"rag_sent_index_enabled:{int(account_id)}"


def style_knobs_hipaa_allow(account_id: int) -> str:
    """``style_knobs_hipaa_allow:<id>`` — per-account opt-in for the
    M-1+M-2 operator-stated style knobs on a HIPAA-flagged account.

    Punch-list #152 Phase 2 (2026-05-11). Default OFF; operator
    explicitly ticks to enable. M-1+M-2 take operator-typed strings
    (style guide + tone / length / greeting / signature radios), which
    are operator self-disclosure (§164.502(a)) — not PHI by
    construction. M-3 / M-4 / M-7 stay hard-off regardless of this
    flag; see ``docs/m-series-hipaa-audit.md`` for the audit and
    ``docs/privacy-audit-runbook.md`` for the sign-off log.
    """
    return f"style_knobs_hipaa_allow:{int(account_id)}"


def office365_clientstate(account_id: int) -> str:
    """``office365_clientstate:<id>`` — Graph webhook clientState (in secrets)."""
    return f"office365_clientstate:{int(account_id)}"


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
#: optional classification cache (#151). Empty / missing = cache OFF.
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
_ACCOUNT_KEY_CATALOG: tuple[tuple[str, bool], ...] = (
    ("watch:", True),
    ("watch_hwm:", False),  # covers both legacy-single + per-mailbox shapes
    ("calendar_enabled:", True),
    ("digest:", True),
    ("digest_schedules:", True),
    ("digest_test_lock:", True),
    ("auth_stale:", True),
    ("gmail_oauth_flow:", True),
    ("poll_state:", True),
    ("openclaw_quiet:", True),
    ("style_profile:", True),
    ("rag_sent_index_enabled:", True),
    ("style_knobs_hipaa_allow:", True),
    ("office365_clientstate:", True),
    ("account_state:", False),  # legacy <prefix><id>:<thing>
    ("backup_paths:", True),
    ("listener_restart_pending:", True),
)


def account_settings_keys(account_id: int) -> Iterable[tuple[str, bool]]:
    """Yield ``(key_or_prefix, exact_match)`` pairs for ``account_id``.

    Useful for callers that want to inspect (e.g. backup #65) what's
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
                # accidentally match ``watch_hwm:10`` etc.
                r = cur.execute(
                    "DELETE FROM settings WHERE key = ? OR key LIKE ?",
                    (f"{prefix}{aid}", f"{prefix}{aid}:%"),
                )
            deleted += r.rowcount or 0
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # Keep the in-process settings cache (#140.2) coherent. The bulk
    # DELETE bypasses delete_setting(); a per-key invalidation here
    # would require knowing every legacy <prefix>:<id>:<segments>
    # variant in flight, so flush the entire cache instead. Account
    # deletion is rare; cost is negligible.
    from email_triage.web.db import invalidate_setting_cache
    invalidate_setting_cache()

    return deleted
