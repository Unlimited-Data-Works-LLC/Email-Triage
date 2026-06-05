"""Style-cluster DB helpers — extracted from web/db.py.

Drop-in refactor. NO semantic changes. The style subsystem (the
``account_style_per_alias`` / ``style_distill_events`` /
``style_distill_queue`` (+ contacts) / ``per_contact_style_hipaa`` /
``hipaa_style_descriptors`` / ``sent_mail_index`` tables, the users-table
style columns, and the settings-keyed style config layer) moves here from
``web/db.py`` as the 3rd  god-module extraction (after ``db/audit.py``
#277a ``64ea61b`` and ``db/accounts.py`` #277b ``f1c5300``). ``web/db.py``
keeps an explicit re-export shim at its bottom so every existing
``from email_triage.web.db import <name>`` import string keeps working
unchanged — the public surface stays superset-or-equal (zero names lost).

Partition axis: TABLE OWNERSHIP, not name (db-sme manifest gate
2026-05-29). Distinguishing rule for the settings-keyed style flags
(db-sme R1, reverses the #277b mailbox-HWM "STAY" call without
contradicting it): the style settings flags are the *config layer of a
cohesive subsystem* (move with the subsystem), not an orphan 5-helper
fragment like mailbox-HWM (which had no home but a hypothetical future
``db/settings.py``). The user-NAMED-but-style-OWNED defs
(``get/set_user_style_knobs``, ``get/set_user_anti_ai_style_guide``,
db-sme R2) live here, NOT a future ``db/users.py`` — avoids a later
tug-of-war.

``resolve_account_mine_limit`` moved too (db-sme Option-1, 2026-05-29):
it was the SINGLE bidirectional entanglement — a "staying" def that both
called ``get_style_learning_mine_limit_default`` and used the
``STYLE_LEARNING_MINE_LIMIT_MIN/MAX`` consts. Moving it (with those
consts) eliminates the only back-edge; zero cross-module constant
sharing.

Module-level style-config constants moved with their helpers (lead
disposition 2026-05-29, applying db-sme R1 cohesion + verified mechanically
0 staying references; cross-module importers — ``routers/ui/profile.py``,
``actions/hipaa_style_distill.py``, ``style_learning/per_contact_hipaa.py``,
``web/app.py`` — keep their ``from email_triage.web.db import <CONST>``
imports working via the bottom shim re-export): ``STYLE_KNOB_DEFAULTS``,
``STYLE_LEARNING_CAPTURE_INTERVAL_{MIN,MAX,DEFAULT}_HOURS``,
``STYLE_LEARNING_MINE_LIMIT_{MIN,MAX,DEFAULT}``,
``STYLE_LEARNING_HIPAA_DISTILL_ENABLED``, ``HIPAA_PER_CONTACT_GC_DAYS``.
The presentation-layer allowlists (``STYLE_TONE/LENGTH/GREETING_CHOICES``)
and the ``STYLE_DISTILL_BACKOFF_SECONDS`` / ``STYLE_DISTILL_MAX_ATTEMPTS``
derived tuple STAY in web/db.py (no moved helper references them).

Dependency cut (db-sme Criterion-1 CONFIRMED clean — no shim-unbreakable
cycle; only ``resolve_account_mine_limit`` reached into style CORE and it
moved):
  * ``_rows`` / ``_row`` / ``_has_table`` / ``_has_column`` come from
    :mod:`email_triage.db._helpers` (``_has_table`` / ``_has_column``
    promoted there per db-sme SUB-1 OVERRIDE — generic schema
    introspection, 3+ cross-module consumers).
  * ``_STYLE_DISTILL_SCHEDULE`` / ``_compute_next_attempt_at`` re-import
    directly from :mod:`email_triage.retry_backoff` (the schedule SSOT,
     R-A) — no cycle.
  * ``get_setting`` / ``set_setting`` / ``delete_setting`` /
    ``get_bool_setting`` / ``set_bool_setting`` (the settings k-v layer),
    ``normalise_from_address`` (now in ``db/accounts.py``, re-exported by
    web.db), and ``_validate_recipient_hash_or_aggregate`` (+ its
    ``HIPAA_SEND_COUNTER_AGGREGATE_HASH`` const) are LATE-IMPORTED from
    ``email_triage.web.db`` inside the wrappers that need them (db-sme
    SUB-2) — avoids a top-level import cycle, since web.db re-exports the
    names defined here.

HIPAA (hipaa-sme dual-gate CLEAR 2026-05-29):
    §164.514(b) De-identification — the ``recipient_hash`` SHA-256 + the
        '@'-rejection ``_validate_recipient_hash_or_aggregate`` validator
        STAY in web.db (late-imported); de-identification semantics are
        byte-identical across the move.
    §164.312(a)(2)(iv) Encryption / EQM-08 — PHI-at-rest stays whole-file
        SQLCipher on the same ``triage.db``; relocation changes nothing.
        The moved ``sent_mail_index`` helpers are metadata/count/delete
        only (COUNT/MIN/MAX + model name + delete) — the RAG vector store
        is engine-side and untouched.
    §164.502(a) Minimum-Necessary — ``get_sent_mail_index_summary``
        returns ``sample_subjects`` UN-redacted BY DESIGN; the redaction
        gate is at the route (``_shared.py`` / ``profile.py``, both
        callers), not the DB helper. Pure relocation + shim adds zero new
        callers, so the route-level contract is preserved.
    All 7 PHI writers are single-statement ``@db_write`` (no explicit
        BEGIN/COMMIT) — no cross-table atomic tx to keep single-module
        (simpler than #277b ``set_account_hipaa``).
"""

from __future__ import annotations

import sqlite3

from email_triage.db._helpers import _has_column, _has_table, _row, _rows
from email_triage.retry_backoff import (
    STYLE_DISTILL_SCHEDULE as _STYLE_DISTILL_SCHEDULE,
    compute_next_attempt_at as _compute_next_attempt_at,
)
from email_triage.web.db_writelock import db_write


def _style_profile_key(account_id: int) -> str:
    from email_triage.web.settings_keys import style_profile
    return style_profile(account_id)

def get_style_profile(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    """Return the persisted style-profile dict for ``account_id``.

    Returns ``None`` when no profile has been built yet. Callers
    typically pass the result to
    :meth:`email_triage.actions.style_profile.StyleProfile.from_dict`
    to rehydrate a typed object — that method tolerates missing keys
    so a hand-edit or older schema does not crash startup.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_setting
    raw = get_setting(conn, _style_profile_key(account_id))
    if raw is None or not isinstance(raw, dict):
        return None
    return raw

def set_style_profile(
    conn: sqlite3.Connection, account_id: int, profile: dict,
) -> None:
    """Persist a style profile dict for ``account_id`` (upsert)."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_setting
    if not isinstance(profile, dict):
        raise ValueError("style profile must be a dict")
    set_setting(conn, _style_profile_key(account_id), profile)

def delete_style_profile(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Drop the persisted style profile for ``account_id``.

    Returns True when a row was deleted. Used by the M-8 "Forget my
    style profile" UI when it lands.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import delete_setting
    return delete_setting(conn, _style_profile_key(account_id))

def get_account_style_per_alias(
    conn: sqlite3.Connection, account_id: int, from_address: str,
) -> dict | None:
    """Return the per-alias descriptor dict, or None if absent.

    ``from_address`` is normalised before lookup so the caller may
    pass the raw header value. The empty string is a valid key (the
    "no alias bucket / default" row) but the picker that consumes
    this helper always falls back to the account-wide descriptor
    when the per-alias row is missing.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import normalise_from_address
    addr = normalise_from_address(from_address)
    try:
        row = conn.execute(
            "SELECT descriptor_json FROM account_style_per_alias "
            "WHERE account_id = ? AND from_address = ?",
            (int(account_id), addr),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v23 install -- treat as "no row".
        return None
    if row is None:
        return None
    import json as _json
    raw = row["descriptor_json"] if hasattr(row, "keys") else row[0]
    try:
        parsed = _json.loads(raw or "{}")
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None

@db_write
def set_account_style_per_alias(
    conn: sqlite3.Connection,
    account_id: int,
    from_address: str,
    descriptor: dict,
    *,
    sample_count: int | None = None,
) -> None:
    """Upsert a per-alias descriptor.

    ``from_address`` is normalised before write; the same address in
    any case / display-name shape lands in the same row. The
    ``sample_count`` argument lets the caller record the contributing
    sample count without inspecting the dict (useful when the dict
    came from a third-party shape that didn't include the field).
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import normalise_from_address
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    addr = normalise_from_address(from_address)
    import json as _json
    from datetime import datetime, timezone
    sc = sample_count if sample_count is not None else int(
        descriptor.get("sample_count") or 0,
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO account_style_per_alias "
        "(account_id, from_address, descriptor_json, sample_count, updated_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id, from_address) DO UPDATE SET "
        "  descriptor_json = excluded.descriptor_json, "
        "  sample_count    = excluded.sample_count, "
        "  updated_at      = excluded.updated_at",
        (int(account_id), addr, _json.dumps(descriptor), int(sc), now),
    )
    conn.commit()

def list_account_style_per_alias(
    conn: sqlite3.Connection, account_id: int,
) -> list[dict]:
    """Return all per-alias descriptor rows for ``account_id``.

    Each entry is ``{"from_address": str, "descriptor": dict,
    "sample_count": int, "updated_at": str}``. Ordered by
    ``from_address`` (lexicographic) so the operator-facing picker
    has a stable layout. Returns ``[]`` on pre-v23 installs.
    """
    try:
        rows = conn.execute(
            "SELECT from_address, descriptor_json, sample_count, updated_at "
            "FROM account_style_per_alias "
            "WHERE account_id = ? "
            "ORDER BY from_address",
            (int(account_id),),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    import json as _json
    out: list[dict] = []
    for r in rows:
        raw = r["descriptor_json"] if hasattr(r, "keys") else r[1]
        try:
            desc = _json.loads(raw or "{}")
        except (TypeError, ValueError):
            desc = {}
        if not isinstance(desc, dict):
            desc = {}
        out.append({
            "from_address": (
                r["from_address"] if hasattr(r, "keys") else r[0]
            ),
            "descriptor": desc,
            "sample_count": int(
                (r["sample_count"] if hasattr(r, "keys") else r[2]) or 0,
            ),
            "updated_at": (
                r["updated_at"] if hasattr(r, "keys") else r[3]
            ) or "",
        })
    return out

@db_write
def delete_account_style_per_alias(
    conn: sqlite3.Connection,
    account_id: int,
    from_address: str | None = None,
) -> int:
    """Delete per-alias descriptor rows.

    When ``from_address`` is None, every per-alias row for the account
    is dropped. When given, only the matching row is dropped (the
    address is normalised first so case / suffix variants resolve to
    the same row).

    Returns the number of rows deleted.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import normalise_from_address
    if from_address is None:
        cur = conn.execute(
            "DELETE FROM account_style_per_alias WHERE account_id = ?",
            (int(account_id),),
        )
    else:
        addr = normalise_from_address(from_address)
        cur = conn.execute(
            "DELETE FROM account_style_per_alias "
            "WHERE account_id = ? AND from_address = ?",
            (int(account_id), addr),
        )
    conn.commit()
    return cur.rowcount or 0

STYLE_KNOB_DEFAULTS = {
    "style_guide": "",
    "style_tone": "neutral",
    "style_length": "medium",
    "style_signature": "",
    "style_greeting": "first-name",
    "style_greeting_custom": "",
}

def get_user_style_knobs(
    conn: sqlite3.Connection, user_id: int | None,
) -> dict:
    """Return the user's style-knob dict, defaulted on missing keys.

    Returns the canonical default dict (matching ``STYLE_KNOB_DEFAULTS``)
    when ``user_id`` is None or the row is absent. Older DBs that
    haven't yet run migration v11 don't have the columns; the
    KeyError-on-row-access falls back to defaults so this is safe to
    call before the migration runs.
    """
    if not user_id:
        return dict(STYLE_KNOB_DEFAULTS)
    try:
        row = conn.execute(
            "SELECT style_guide, style_tone, style_length, "
            "       style_signature, style_greeting, style_greeting_custom "
            "FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v11 DB (columns don't exist yet).
        return dict(STYLE_KNOB_DEFAULTS)
    if row is None:
        return dict(STYLE_KNOB_DEFAULTS)
    out = dict(STYLE_KNOB_DEFAULTS)
    for k in STYLE_KNOB_DEFAULTS:
        v = row[k] if hasattr(row, "keys") else None
        if v is None:
            continue
        out[k] = str(v)
    return out

@db_write
def set_user_style_knobs(
    conn: sqlite3.Connection, user_id: int, knobs: dict,
) -> None:
    """Persist the user's style knobs (full upsert across all columns).

    Caller must validate values against the allowlists; this helper
    only enforces type coercion (everything stored as TEXT). Missing
    keys fall back to ``STYLE_KNOB_DEFAULTS`` so the DB stays in a
    valid post-v11 state.
    """
    merged = dict(STYLE_KNOB_DEFAULTS)
    for k in STYLE_KNOB_DEFAULTS:
        if k in knobs and knobs[k] is not None:
            merged[k] = str(knobs[k])
    conn.execute(
        "UPDATE users SET "
        "  style_guide = ?, style_tone = ?, style_length = ?, "
        "  style_signature = ?, style_greeting = ?, "
        "  style_greeting_custom = ? "
        "WHERE id = ?",
        (
            merged["style_guide"],
            merged["style_tone"],
            merged["style_length"],
            merged["style_signature"],
            merged["style_greeting"],
            merged["style_greeting_custom"],
            int(user_id),
        ),
    )
    conn.commit()

def is_style_learning_master_enabled(conn: sqlite3.Connection) -> bool:
    """Return the install-wide style-learning master toggle.

    Stored under settings key ``style_learning:master`` as
    ``{"enabled": bool}``. Default ON when the row is missing — this
    is the privacy-neutral default for user-stated knobs (no
    cross-user inference involved). The Cross-cutting toggle at
    /config flips this off when the operator wants to suppress all
    style influence on draft replies.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_bool_setting
    return get_bool_setting(conn, "style_learning:master", default=True)

def set_style_learning_master_enabled(
    conn: sqlite3.Connection, enabled: bool,
) -> None:
    """Flip the install-wide style-learning master toggle."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_bool_setting
    set_bool_setting(conn, "style_learning:master", enabled)

STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS = 1

STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS = 72

STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS = 6

STYLE_LEARNING_MINE_LIMIT_MIN = 1

STYLE_LEARNING_MINE_LIMIT_MAX = 500

STYLE_LEARNING_MINE_LIMIT_DEFAULT = 50

def get_style_learning_capture_interval_hours(
    conn: sqlite3.Connection,
) -> int:
    """Read the install-wide capture-loop cadence (hours).

    Returns the operator-set value, or
    :data:`STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS` when no
    explicit value is stored. Out-of-range / non-numeric values
    clamp into the documented range so the loop's sleep helper
    never sees a value it can't honour."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_setting
    raw = get_setting(conn, "style_learning:capture_interval_hours")
    hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if isinstance(raw, dict):
        try:
            hours = int(
                raw.get("hours")
                or STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
            )
        except (TypeError, ValueError):
            hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    elif isinstance(raw, (int, float)):
        try:
            hours = int(raw)
        except (TypeError, ValueError):
            hours = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if hours < STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS:
        hours = STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS
    elif hours > STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS:
        hours = STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS
    return hours

def set_style_learning_capture_interval_hours(
    conn: sqlite3.Connection, hours: int,
) -> None:
    """Persist the install-wide capture-loop cadence (hours).

    Clamps to the documented range; the YAML loader / loop reader
    re-clamps defensively in case the row is hand-edited."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_setting
    try:
        h = int(hours)
    except (TypeError, ValueError):
        h = STYLE_LEARNING_CAPTURE_INTERVAL_DEFAULT_HOURS
    if h < STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS:
        h = STYLE_LEARNING_CAPTURE_INTERVAL_MIN_HOURS
    elif h > STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS:
        h = STYLE_LEARNING_CAPTURE_INTERVAL_MAX_HOURS
    set_setting(conn, "style_learning:capture_interval_hours", {"hours": h})

def get_style_learning_mine_limit_default(
    conn: sqlite3.Connection,
) -> int:
    """Read the install-wide default for the mine-now / preview limit.

    Out-of-range / non-numeric values clamp into the documented range;
    missing row falls back to
    :data:`STYLE_LEARNING_MINE_LIMIT_DEFAULT` (50)."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_setting
    raw = get_setting(conn, "style_learning:mine_limit_default")
    val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if isinstance(raw, dict):
        try:
            val = int(
                raw.get("limit") or STYLE_LEARNING_MINE_LIMIT_DEFAULT
            )
        except (TypeError, ValueError):
            val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    elif isinstance(raw, (int, float)):
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if val < STYLE_LEARNING_MINE_LIMIT_MIN:
        val = STYLE_LEARNING_MINE_LIMIT_MIN
    elif val > STYLE_LEARNING_MINE_LIMIT_MAX:
        val = STYLE_LEARNING_MINE_LIMIT_MAX
    return val

def set_style_learning_mine_limit_default(
    conn: sqlite3.Connection, limit: int,
) -> None:
    """Persist the install-wide default mine-now / preview limit.

    Clamps to the documented range so a typo doesn't wedge the inline
    path with a giant scan."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_setting
    try:
        v = int(limit)
    except (TypeError, ValueError):
        v = STYLE_LEARNING_MINE_LIMIT_DEFAULT
    if v < STYLE_LEARNING_MINE_LIMIT_MIN:
        v = STYLE_LEARNING_MINE_LIMIT_MIN
    elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
        v = STYLE_LEARNING_MINE_LIMIT_MAX
    set_setting(conn, "style_learning:mine_limit_default", {"limit": v})

def resolve_account_mine_limit(
    conn: sqlite3.Connection, account: dict | None,
) -> int:
    """Resolve the effective mine-now / preview limit for one account.

    Per-account override (``config_json.mine_limit_override``) wins
    when present and positive; falls through to the install-wide
    default. Empty / unset / non-positive override → install default.
    """
    if account is not None and isinstance(account, dict):
        cfg = account.get("config") or {}
        if isinstance(cfg, dict):
            raw = cfg.get("mine_limit_override")
            if raw is not None and raw != "":
                try:
                    v = int(raw)
                    if v > 0:
                        if v < STYLE_LEARNING_MINE_LIMIT_MIN:
                            v = STYLE_LEARNING_MINE_LIMIT_MIN
                        elif v > STYLE_LEARNING_MINE_LIMIT_MAX:
                            v = STYLE_LEARNING_MINE_LIMIT_MAX
                        return v
                except (TypeError, ValueError):
                    pass
    return get_style_learning_mine_limit_default(conn)

def is_style_learning_account_enabled(account: dict | None) -> bool:
    """Return the per-account style-learning toggle from config.

    Pulled from ``account.config["style_learning_enabled"]``. Default
    is True (on) — opt-out shape so existing accounts keep working
    when columns are first added. Sites that mutate this go through
    the standard account-edit save path which writes config_json.
    """
    if account is None:
        return False
    cfg = account.get("config") if isinstance(account, dict) else None
    if not isinstance(cfg, dict):
        return True
    val = cfg.get("style_learning_enabled")
    if val is None:
        return True
    return bool(val)

def _rag_sent_index_key(account_id: int) -> str:
    from email_triage.web.settings_keys import rag_sent_index_enabled
    return rag_sent_index_enabled(account_id)

def is_rag_sent_index_enabled(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    account: dict | None = None,
) -> bool:
    """Return True when the per-account RAG-over-sent-mail toggle is on.

    Default-on / default-off is HIPAA-aware. When
    the operator has not explicitly toggled the setting, the per-render
    default depends on the account's HIPAA flag:

      * HIPAA-flagged account → default OFF. Owner must opt IN
        explicitly. Under §164.502(a) the owner gets the choice but
        the install does not auto-mine PHI mail.
      * Non-HIPAA account → default ON. The "AI learns from your
        past replies" experience is the project's mainline; new
        accounts should benefit without a manual toggle.

    Existing accounts with an explicitly-saved value keep that value;
    the HIPAA-aware split applies only when no row exists in the
    settings table. The HIPAA hard gates layered on the M-4 path
    itself (e.g. ``SentMailIndex._hipaa_short_circuit``) are unchanged
    — they still refuse a HIPAA-flagged account even if this helper
    returned True; the toggle is the operator UX surface, the hard
    gate is the privacy guarantee.

    Parameters
    ----------
    conn:
        Active SQLite connection.
    account_id:
        Account whose setting we're reading.
    account:
        Optional account dict (with ``hipaa`` field) for the
        HIPAA-aware default. Callers that already have the dict in
        hand (e.g. the background loop) should pass it to avoid a
        round-trip; callers that don't fall through to the legacy
        default-off behaviour (the conservative posture). When
        ``account is None`` we do NOT load the account row ourselves
        — the caller's path may not have the account_id privilege
        check we'd need, and the conservative default cannot leak data.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_setting
    raw = get_setting(conn, _rag_sent_index_key(account_id))
    if raw is None:
        # No explicit value saved — apply the HIPAA-aware default.
        if account is not None:
            from email_triage.triage_logging import is_account_hipaa
            if is_account_hipaa(account):
                return False
            return True
        # Caller didn't supply the account — use the conservative
        # default to keep the existing posture for any pre-#157 path
        # that doesn't yet know about the split.
        return False
    if isinstance(raw, dict):
        if "enabled" in raw:
            return bool(raw.get("enabled"))
        return False
    return bool(raw)

def set_rag_sent_index_enabled(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Persist the per-account RAG toggle (upsert)."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_bool_setting
    set_bool_setting(conn, _rag_sent_index_key(account_id), enabled)

def _style_knobs_hipaa_allow_key(account_id: int) -> str:
    from email_triage.web.settings_keys import style_knobs_hipaa_allow
    return style_knobs_hipaa_allow(account_id)

def is_style_knobs_hipaa_allow(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Return True when the operator has opted in to M-1+M-2 for this
    HIPAA-flagged account. Default False."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_bool_setting
    return get_bool_setting(
        conn, _style_knobs_hipaa_allow_key(account_id), default=False,
    )

def set_style_knobs_hipaa_allow(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Persist the per-account M-1+M-2 HIPAA-allow opt-in (upsert)."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_bool_setting
    set_bool_setting(
        conn, _style_knobs_hipaa_allow_key(account_id), enabled,
    )

#: Install-wide settings-table key for the phase-3 HIPAA distill flag.
#: Default OFF. Lives on /config under the privacy section.
STYLE_LEARNING_HIPAA_DISTILL_ENABLED = "style_learning:hipaa_distill_enabled"

def is_hipaa_style_distill_enabled(conn: sqlite3.Connection) -> bool:
    """Install-wide gate on the phase-3 distill pipeline.

    Default OFF. The pipeline scaffold lives in
    :mod:`email_triage.actions.hipaa_style_distill` but is not wired into
    any production caller until the operator both (a) flips this flag and
    (b) signs off on the LLM-backend posture (Ollama-local-only per the
    current default).
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_bool_setting
    return get_bool_setting(
        conn, STYLE_LEARNING_HIPAA_DISTILL_ENABLED, default=False,
    )

def set_hipaa_style_distill_enabled(
    conn: sqlite3.Connection, enabled: bool,
) -> None:
    """Flip the install-wide HIPAA-distill enabled flag."""
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_bool_setting
    set_bool_setting(
        conn, STYLE_LEARNING_HIPAA_DISTILL_ENABLED, enabled,
    )

def get_hipaa_style_descriptor(
    conn: sqlite3.Connection, account_id: int,
) -> dict | None:
    """Return the persisted HIPAA descriptor row, or None.

    Shape::

        {
            "descriptor": <dict>,        # parsed descriptor_json
            "version": <int>,            # descriptor_version
            "rebuilt_at": <iso8601 str>,
            "message_count": <int>,
            "scrubber_outcome": <str>,
        }

    Returns ``None`` when no row exists (descriptor never built).
    Tolerant of corrupt JSON: a parse failure also returns ``None`` so
    the caller falls back to "no descriptor available; either re-distill
    or render empty".
    """
    import json as _json
    row = conn.execute(
        "SELECT descriptor_json, descriptor_version, rebuilt_at, "
        "       message_count, scrubber_outcome "
        "FROM hipaa_style_descriptors WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if row is None:
        return None
    try:
        descriptor = _json.loads(
            row["descriptor_json"] if hasattr(row, "keys") else row[0]
        )
    except (ValueError, TypeError):
        return None
    if not isinstance(descriptor, dict):
        return None
    return {
        "descriptor": descriptor,
        "version": int(
            row["descriptor_version"] if hasattr(row, "keys") else row[1]
        ),
        "rebuilt_at": (
            row["rebuilt_at"] if hasattr(row, "keys") else row[2]
        ),
        "message_count": int(
            row["message_count"] if hasattr(row, "keys") else row[3]
        ),
        "scrubber_outcome": (
            row["scrubber_outcome"] if hasattr(row, "keys") else row[4]
        ),
    }

@db_write
def set_hipaa_style_descriptor(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    descriptor: dict,
    version: int,
    message_count: int,
    scrubber_outcome: str = "clean",
) -> None:
    """Persist a scrubbed HIPAA descriptor (upsert).

    Callers should only invoke this AFTER the scrubber pass returns
    clean. A 'dropped' outcome is an error path — the action should
    delete any existing row rather than writing a fresh one with
    ``scrubber_outcome='dropped'`` so a future read can't see a
    partial / poisoned descriptor.
    """
    import json as _json
    from datetime import datetime, timezone
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO hipaa_style_descriptors "
        "(account_id, descriptor_json, descriptor_version, rebuilt_at, "
        " message_count, scrubber_outcome) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  descriptor_json    = excluded.descriptor_json, "
        "  descriptor_version = excluded.descriptor_version, "
        "  rebuilt_at         = excluded.rebuilt_at, "
        "  message_count      = excluded.message_count, "
        "  scrubber_outcome   = excluded.scrubber_outcome",
        (
            int(account_id),
            _json.dumps(descriptor),
            int(version),
            now,
            int(message_count),
            str(scrubber_outcome or "clean"),
        ),
    )
    conn.commit()

@db_write
def delete_hipaa_style_descriptor(
    conn: sqlite3.Connection, account_id: int,
) -> None:
    """Remove the HIPAA descriptor row for ``account_id`` (idempotent).

    Called by the distill action when the scrubber drops the descriptor
    (a clean descriptor never landed; remove any stale one too).
    """
    conn.execute(
        "DELETE FROM hipaa_style_descriptors WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()

@db_write
def record_style_distill_event(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: int | None,
    backend_id: int | None,
    backend_type: str,
    was_cloud: bool,
    outcome: str,
    latency_ms: int = 0,
    layer1_drops: int = 0,
    layer2_matches: int = 0,
    layer3_entities: int = 0,
    scrubber_degraded: bool = False,
    error_class: str | None = None,
    kind: str = "account_m3",
    recipient_hash: str | None = None,
) -> int:
    """Insert one ``style_distill_events`` row + return the id.

    The PHI-safety contract: callers pass COUNTS only, never the
    matched text or raw error message. ``error_class`` is the type-
    name of the exception (``"HTTPError"`` / ``"TimeoutError"``) —
    never ``str(exc)`` since some providers embed the request body in
    the message string.

    ``kind`` discriminates the audit row's pipeline (``'account_m3'``
    for the v27 M-3 path; ``'per_contact'`` for the v28 M-7 HIPAA path).
    ``recipient_hash`` is the 64-hex SHA-256 digest of the recipient
    address for ``kind='per_contact'`` rows — NEVER the plaintext
    address. NULL for ``kind='account_m3'`` rows.
    """
    from datetime import datetime, timezone
    # Defensive: reject anything that looks like a plaintext email.
    # The hash is exactly 64 hex chars, lower-cased; plaintext would
    # carry an ``@`` or be the wrong length.
    if recipient_hash is not None:
        h = str(recipient_hash).lower()
        if "@" in h:
            raise ValueError(
                "recipient_hash carries '@' — caller passed plaintext"
            )
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(
                "recipient_hash must be a 64-char SHA-256 hex digest"
            )
        recipient_hash = h
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO style_distill_events "
        "(ts, account_id, actor_user_id, backend_id, backend_type, "
        " was_cloud, outcome, latency_ms, layer1_drops, layer2_matches, "
        " layer3_entities, scrubber_degraded, error_class, kind, "
        " recipient_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            int(account_id),
            actor_user_id if actor_user_id is None else int(actor_user_id),
            backend_id if backend_id is None else int(backend_id),
            str(backend_type or ""),
            1 if was_cloud else 0,
            str(outcome),
            int(latency_ms or 0),
            int(layer1_drops or 0),
            int(layer2_matches or 0),
            int(layer3_entities) if layer3_entities is not None else 0,
            1 if scrubber_degraded else 0,
            (str(error_class) if error_class else None),
            str(kind or "account_m3"),
            recipient_hash,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)

def style_distill_event_counts(
    conn: sqlite3.Connection,
    *,
    since_iso: str | None = None,
) -> dict:
    """Return per-bucket counters for the /health/detail summary.

    Shape::

        {
            "local_24h":            <int>,  # was_cloud=0 successes
            "cloud_24h":            <int>,  # was_cloud=1 successes
            "failures_24h":         <int>,  # outcome=backend_fail
            "scrubber_rejects_24h": <int>,  # outcome=scrubber_fail
            "total_24h":            <int>,  # any outcome in the window
        }

    ``since_iso`` defaults to ``now - 24h`` (UTC). Caller may pass an
    explicit cutoff to inspect a different window.
    """
    from datetime import datetime, timezone, timedelta
    if since_iso is None:
        since_iso = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
    out = {
        "local_24h": 0,
        "cloud_24h": 0,
        "failures_24h": 0,
        "scrubber_rejects_24h": 0,
        "total_24h": 0,
    }
    rows = conn.execute(
        "SELECT outcome, was_cloud, COUNT(*) AS cnt "
        "FROM style_distill_events "
        "WHERE ts >= ? "
        "GROUP BY outcome, was_cloud",
        (since_iso,),
    ).fetchall()
    for row in rows:
        outcome = row["outcome"] if hasattr(row, "keys") else row[0]
        was_cloud = int(row["was_cloud"] if hasattr(row, "keys") else row[1])
        cnt = int(row["cnt"] if hasattr(row, "keys") else row[2])
        out["total_24h"] += cnt
        if outcome == "success":
            if was_cloud:
                out["cloud_24h"] += cnt
            else:
                out["local_24h"] += cnt
        elif outcome == "backend_fail":
            out["failures_24h"] += cnt
        elif outcome == "scrubber_fail":
            out["scrubber_rejects_24h"] += cnt
    return out

def list_style_distill_events(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """List events newest-first with optional per-account filter."""
    where = ""
    params: list = []
    if account_id is not None:
        where = "WHERE account_id = ?"
        params.append(int(account_id))
    params.append(int(limit))
    rows = conn.execute(
        f"SELECT * FROM style_distill_events {where} "
        f"ORDER BY ts DESC LIMIT ?",
        params,
    ).fetchall()
    return _rows(rows)

def _style_distill_compute_next_retry(
    attempt_count: int, *, now: "datetime | None" = None,
) -> "str | None":
    """Compute the ISO timestamp for the next retry, or None when
    ``attempt_count`` exceeds the schedule (final attempt landed).

    Note on indexing
    ----------------
    The style-distill queue uses 1-based attempt numbering ("attempt 1
    just landed; compute wait for attempt 2"); the shared
    :func:`email_triage.retry_backoff.compute_next_attempt_at` uses
    0-based ("0 failures so far; compute wait for the first retry").
    We bridge the off-by-one here: ``attempt_count=1`` → index 0 in
    the shared helper. This preserves the public contract that
    :data:`STYLE_DISTILL_BACKOFF_SECONDS[0]` is the wait after attempt
    1, used by the pinned tests in ``test_style_distill_queue.py``.
    """
    if attempt_count <= 0:
        attempt_count = 1
    next_dt = _compute_next_attempt_at(
        attempt_count - 1,  # 1-based → 0-based bridge
        _STYLE_DISTILL_SCHEDULE,
        now=now,
    )
    if next_dt is None:
        return None
    return next_dt.isoformat()

@db_write
def enqueue_style_distill_retry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    last_error: str | None,
    commit: bool = True,
) -> dict:
    """Schedule a HIPAA-distill retry after a ``backend_fail``.

    Upsert by ``account_id``: increments ``attempt_count`` on an existing
    row, inserts a fresh row at attempt 1 when none exists. ``last_error``
    is the short class-name of the failure (NEVER raw error text). Returns
    the row shape post-update.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT attempt_count, paused FROM style_distill_queue "
        "WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if existing is None:
        attempt = 1
    else:
        if int(existing["paused"]):
            # Paused rows don't auto-retry; operator must unpause.
            return {
                "account_id": int(account_id),
                "attempt_count": int(existing["attempt_count"]),
                "next_retry_at": None,
                "last_error": last_error,
                "paused": True,
            }
        attempt = int(existing["attempt_count"]) + 1
    next_retry = _style_distill_compute_next_retry(attempt)
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (
                int(account_id), attempt, next_retry,
                last_error, now, now,
            ),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue SET "
            "  attempt_count = ?, "
            "  next_retry_at = ?, "
            "  last_error = ?, "
            "  last_attempt_at = ? "
            "WHERE account_id = ?",
            (attempt, next_retry, last_error, now, int(account_id)),
        )
    if commit:
        conn.commit()
    return {
        "account_id": int(account_id),
        "attempt_count": attempt,
        "next_retry_at": next_retry,
        "last_error": last_error,
        "paused": False,
    }

@db_write
def pause_style_distill_account(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    last_error: str,
) -> None:
    """Mark a queue row paused after ``scrubber_fail``.

    Retrying a leaky LLM does not help; the account stays out of the
    auto-retry loop until operator intervention. Admin UI surfaces
    paused accounts in a banner.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT account_id FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue "
            "(account_id, attempt_count, next_retry_at, last_error, "
            " last_attempt_at, paused, created_at) "
            "VALUES (?, 1, NULL, ?, ?, 1, ?)",
            (int(account_id), last_error, now, now),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue SET "
            "  paused = 1, next_retry_at = NULL, "
            "  last_error = ?, last_attempt_at = ? "
            "WHERE account_id = ?",
            (last_error, now, int(account_id)),
        )
    conn.commit()

@db_write
def unpause_style_distill_account(
    conn: sqlite3.Connection, *, account_id: int,
) -> None:
    """Operator action: clear the paused flag + reset attempt_count.

    Used when an operator has investigated a scrubber-paused account
    + wants it back in the retry loop (e.g. swapped backends).
    """
    conn.execute(
        "UPDATE style_distill_queue SET "
        "  paused = 0, attempt_count = 0, next_retry_at = NULL, "
        "  last_error = NULL "
        "WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()

@db_write
def clear_style_distill_queue_entry(
    conn: sqlite3.Connection, *, account_id: int,
) -> None:
    """Remove a queue row after a successful distill.

    Idempotent — second call on the same account is a no-op.
    """
    conn.execute(
        "DELETE FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()

def get_style_distill_queue_entry(
    conn: sqlite3.Connection, *, account_id: int,
) -> dict | None:
    """Return the queue row for an account, or None."""
    row = conn.execute(
        "SELECT * FROM style_distill_queue WHERE account_id = ?",
        (int(account_id),),
    ).fetchone()
    return _row(row)

def list_paused_style_distill_accounts(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return all paused queue rows, joined with account name.

    Used by the admin banner that warns "the following accounts have
    paused style learning (scrubber rejected the descriptor)".
    """
    rows = conn.execute(
        "SELECT q.*, ea.name AS account_name "
        "FROM style_distill_queue q "
        "LEFT JOIN email_accounts ea ON ea.id = q.account_id "
        "WHERE q.paused = 1 "
        "ORDER BY q.last_attempt_at DESC"
    ).fetchall()
    return _rows(rows)

def claim_next_style_distill_queue_entry(
    conn: sqlite3.Connection,
) -> dict | None:
    """Pick the oldest queue row whose ``next_retry_at`` is in the past.

    Returns None when no row is ready. The worker calls this on a
    short polling loop; SQLite's single-writer guarantee makes the
    poll-and-update sequence safe.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT * FROM style_distill_queue "
        "WHERE paused = 0 AND next_retry_at IS NOT NULL "
        "  AND next_retry_at <= ? "
        "ORDER BY next_retry_at ASC LIMIT 1",
        (now,),
    ).fetchone()
    return _row(row)

#: Per-contact GC cut-off. Rows older than this with no re-distill
#: trigger get deleted by the daily sweep. Matches the punch spec
#: ("operator may have stopped emailing that contact").
HIPAA_PER_CONTACT_GC_DAYS = 90

def get_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> dict | None:
    """Return the per-contact descriptor row, or None.

    Shape::

        {
            "descriptor": <dict>,        # parsed descriptor_json
            "version": <int>,
            "message_count": <int>,
            "last_distilled_at": <iso8601 str>,
            "last_updated": <iso8601 str>,
            "scrubber_outcome": <str>,
        }

    Tolerant of corrupt JSON (returns None) so a hand-edit / legacy
    shape doesn't crash the draft-time look-up.
    """
    import json as _json
    if not recipient_hash:
        return None
    row = conn.execute(
        "SELECT descriptor_json, descriptor_version, message_count, "
        "       last_distilled_at, last_updated, scrubber_outcome "
        "FROM per_contact_style_hipaa "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash)),
    ).fetchone()
    if row is None:
        return None
    try:
        descriptor = _json.loads(
            row["descriptor_json"] if hasattr(row, "keys") else row[0]
        )
    except (ValueError, TypeError):
        return None
    if not isinstance(descriptor, dict):
        return None
    return {
        "descriptor": descriptor,
        "version": int(
            row["descriptor_version"] if hasattr(row, "keys") else row[1]
        ),
        "message_count": int(
            row["message_count"] if hasattr(row, "keys") else row[2]
        ),
        "last_distilled_at": (
            row["last_distilled_at"] if hasattr(row, "keys") else row[3]
        ),
        "last_updated": (
            row["last_updated"] if hasattr(row, "keys") else row[4]
        ),
        "scrubber_outcome": (
            row["scrubber_outcome"] if hasattr(row, "keys") else row[5]
        ),
    }

@db_write
def set_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    descriptor: dict,
    version: int,
    message_count: int,
    scrubber_outcome: str = "clean",
) -> None:
    """Persist (UPSERT) a scrubbed per-contact descriptor.

    Callers MUST hash the recipient via
    :func:`email_triage.style_learning.hash_recipient_for_install`
    before calling — this helper does NOT accept a plaintext address.
    The ``recipient_hash`` parameter is enforced to look like a 64-hex
    SHA-256 digest; anything else raises ``ValueError`` to catch the
    "accidentally passed the plaintext address" mistake.
    """
    import json as _json
    from datetime import datetime, timezone
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a dict")
    if not isinstance(recipient_hash, str):
        raise ValueError("recipient_hash must be a string")
    h = recipient_hash.lower()
    if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError(
            "recipient_hash must be a 64-char lowercase SHA-256 hex digest"
        )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO per_contact_style_hipaa "
        "(account_id, recipient_hash, descriptor_json, "
        " descriptor_version, message_count, "
        " last_distilled_at, last_updated, scrubber_outcome) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(account_id, recipient_hash) DO UPDATE SET "
        "  descriptor_json    = excluded.descriptor_json, "
        "  descriptor_version = excluded.descriptor_version, "
        "  message_count      = excluded.message_count, "
        "  last_distilled_at  = excluded.last_distilled_at, "
        "  last_updated       = excluded.last_updated, "
        "  scrubber_outcome   = excluded.scrubber_outcome",
        (
            int(account_id),
            h,
            _json.dumps(descriptor),
            int(version),
            int(message_count),
            now,
            now,
            str(scrubber_outcome or "clean"),
        ),
    )
    conn.commit()

@db_write
def delete_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Remove a single per-contact descriptor row (idempotent)."""
    conn.execute(
        "DELETE FROM per_contact_style_hipaa "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()

@db_write
def delete_all_per_contact_style_hipaa(
    conn: sqlite3.Connection, *, account_id: int,
) -> int:
    """Clear every per-contact descriptor for an account.

    Used by the operator "Clear style data" surface (when one exists)
    and during account deletion paths that want belt-and-braces over
    the ON DELETE CASCADE. Returns the rowcount.
    """
    cur = conn.execute(
        "DELETE FROM per_contact_style_hipaa WHERE account_id = ?",
        (int(account_id),),
    )
    conn.commit()
    return cur.rowcount

def list_per_contact_style_hipaa_for_account(
    conn: sqlite3.Connection, *, account_id: int,
) -> list[dict]:
    """Return per-contact rows (hashes + metadata, NOT the descriptor JSON).

    Used by the operator admin surface listing "we have style data for
    N recurring contacts on this account". The descriptor JSON is
    intentionally omitted — caller asks for one specific hash to read
    the full descriptor.
    """
    rows = conn.execute(
        "SELECT recipient_hash, descriptor_version, message_count, "
        "       last_distilled_at, last_updated, scrubber_outcome "
        "FROM per_contact_style_hipaa WHERE account_id = ? "
        "ORDER BY last_distilled_at DESC",
        (int(account_id),),
    ).fetchall()
    return _rows(rows)

@db_write
def gc_per_contact_style_hipaa(
    conn: sqlite3.Connection,
    *,
    gc_days: int | None = None,
    now: "datetime | None" = None,
) -> int:
    """Delete per-contact descriptors older than ``gc_days`` since
    last distill. Returns the count of removed rows.

    Daily sweep — sibling to :func:`baa_expiry_daily_sweep`. The
    cut-off defaults to :data:`HIPAA_PER_CONTACT_GC_DAYS` (90 days);
    callers may override for tests. Idempotent — a re-run on a clean
    DB returns 0.

    Per the punch spec: "operator may have stopped emailing that
    contact". A row with no re-distill in 90 days means no new mail
    has crossed the trigger threshold; the overlay is stale + the
    hash storage is no longer earning its keep.
    """
    from datetime import datetime, timezone, timedelta
    days = HIPAA_PER_CONTACT_GC_DAYS if gc_days is None else int(gc_days)
    base = now or datetime.now(timezone.utc)
    cutoff = (base - timedelta(days=days)).isoformat()
    cur = conn.execute(
        "DELETE FROM per_contact_style_hipaa "
        "WHERE last_distilled_at < ?",
        (cutoff,),
    )
    conn.commit()
    return cur.rowcount

@db_write
def enqueue_style_distill_contact_retry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    last_error: str | None,
    commit: bool = True,
) -> dict:
    """Schedule a per-contact distill retry after a ``backend_fail``.

    Same exponential-backoff schedule as the account-level queue
    (:data:`STYLE_DISTILL_BACKOFF_SECONDS`). Upsert by ``(account_id,
    recipient_hash)``.
    """
    from datetime import datetime, timezone
    if not recipient_hash:
        raise ValueError("recipient_hash required")
    h = str(recipient_hash).lower()
    if len(h) != 64:
        raise ValueError(
            "recipient_hash must be a 64-char SHA-256 hex digest"
        )
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT attempt_count, paused FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    ).fetchone()
    if existing is None:
        attempt = 1
    else:
        if int(existing["paused"]):
            return {
                "account_id": int(account_id),
                "recipient_hash": h,
                "attempt_count": int(existing["attempt_count"]),
                "next_retry_at": None,
                "last_error": last_error,
                "paused": True,
            }
        attempt = int(existing["attempt_count"]) + 1
    next_retry = _style_distill_compute_next_retry(attempt)
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue_contacts "
            "(account_id, recipient_hash, attempt_count, next_retry_at, "
            " last_error, last_attempt_at, paused, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (
                int(account_id), h, attempt, next_retry,
                last_error, now, now,
            ),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue_contacts SET "
            "  attempt_count = ?, "
            "  next_retry_at = ?, "
            "  last_error = ?, "
            "  last_attempt_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (attempt, next_retry, last_error, now, int(account_id), h),
        )
    if commit:
        conn.commit()
    return {
        "account_id": int(account_id),
        "recipient_hash": h,
        "attempt_count": attempt,
        "next_retry_at": next_retry,
        "last_error": last_error,
        "paused": False,
    }

@db_write
def pause_style_distill_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
    last_error: str,
) -> None:
    """Pause a per-contact queue row after ``scrubber_fail``.

    The account-level row stays active; only THIS contact pauses.
    Operator clears via :func:`unpause_style_distill_contact`.
    """
    from datetime import datetime, timezone
    h = str(recipient_hash).lower()
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT 1 FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), h),
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO style_distill_queue_contacts "
            "(account_id, recipient_hash, attempt_count, next_retry_at, "
            " last_error, last_attempt_at, paused, created_at) "
            "VALUES (?, ?, 1, NULL, ?, ?, 1, ?)",
            (int(account_id), h, last_error, now, now),
        )
    else:
        conn.execute(
            "UPDATE style_distill_queue_contacts SET "
            "  paused = 1, next_retry_at = NULL, "
            "  last_error = ?, last_attempt_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (last_error, now, int(account_id), h),
        )
    conn.commit()

@db_write
def unpause_style_distill_contact(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Operator action: clear paused flag for a specific contact row."""
    conn.execute(
        "UPDATE style_distill_queue_contacts SET "
        "  paused = 0, attempt_count = 0, next_retry_at = NULL, "
        "  last_error = NULL "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()

@db_write
def clear_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> None:
    """Remove a per-contact queue row after a successful distill.

    Idempotent — second call on the same key is a no-op.
    """
    conn.execute(
        "DELETE FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    )
    conn.commit()

def get_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_hash: str,
) -> dict | None:
    """Return the per-contact queue row for ``(account, contact)``, or None."""
    row = conn.execute(
        "SELECT * FROM style_distill_queue_contacts "
        "WHERE account_id = ? AND recipient_hash = ?",
        (int(account_id), str(recipient_hash).lower()),
    ).fetchone()
    return _row(row)

def list_paused_style_distill_contacts(
    conn: sqlite3.Connection,
) -> list[dict]:
    """Return all paused per-contact queue rows joined with account name.

    Sibling to :func:`list_paused_style_distill_accounts`. Plaintext
    recipient is NEVER joined in — the row stores only the hash.
    """
    rows = conn.execute(
        "SELECT q.*, ea.name AS account_name "
        "FROM style_distill_queue_contacts q "
        "LEFT JOIN email_accounts ea ON ea.id = q.account_id "
        "WHERE q.paused = 1 "
        "ORDER BY q.last_attempt_at DESC"
    ).fetchall()
    return _rows(rows)

def claim_next_style_distill_contact_queue_entry(
    conn: sqlite3.Connection,
) -> dict | None:
    """Pick the oldest per-contact queue row whose ``next_retry_at`` is past.

    Sibling to :func:`claim_next_style_distill_queue_entry`. Worker
    polls both queues on each tick.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT * FROM style_distill_queue_contacts "
        "WHERE paused = 0 AND next_retry_at IS NOT NULL "
        "  AND next_retry_at <= ? "
        "ORDER BY next_retry_at ASC LIMIT 1",
        (now,),
    ).fetchone()
    return _row(row)

def last_successful_style_distill_at(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    kind: str = "account_m3",
    recipient_hash: str | None = None,
) -> str | None:
    """Return the ISO timestamp of the most-recent successful distill, or None.

    Reads ``style_distill_events``. ``outcome='success'`` AND
    (when applicable) the matching ``recipient_hash`` filter:

      * ``kind='account_m3'``:  recipient_hash IS NULL filter.
      * ``kind='per_contact'``: recipient_hash = <hash> filter.

    Returns None when no qualifying row exists (first-time trigger
    fires on this).
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import _validate_recipient_hash_or_aggregate, HIPAA_SEND_COUNTER_AGGREGATE_HASH
    where_parts = [
        "account_id = ?",
        "kind = ?",
        "outcome = 'success'",
    ]
    params: list = [int(account_id), str(kind)]
    if kind == "per_contact":
        if recipient_hash is None:
            raise ValueError(
                "recipient_hash required for kind='per_contact'"
            )
        h = _validate_recipient_hash_or_aggregate(recipient_hash)
        if h == HIPAA_SEND_COUNTER_AGGREGATE_HASH:
            raise ValueError(
                "recipient_hash sentinel '' not valid for "
                "kind='per_contact' lookup"
            )
        where_parts.append("recipient_hash = ?")
        params.append(h)
    else:
        where_parts.append("recipient_hash IS NULL")
    sql = (
        "SELECT ts FROM style_distill_events "
        "WHERE " + " AND ".join(where_parts) + " "
        "ORDER BY ts DESC LIMIT 1"
    )
    row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    return row["ts"] if hasattr(row, "keys") else row[0]

def get_global_anti_ai_style_guide(conn: sqlite3.Connection) -> str:
    """Return the install-wide anti-AI style guide string.

    Returns the empty string when the row is missing or the stored
    value isn't a plain string (defensive: a hand-edit / legacy dict
    shape will not crash the prompt build).
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import get_setting
    from email_triage.web.settings_keys import ANTI_AI_STYLE_GUIDE_GLOBAL
    raw = get_setting(conn, ANTI_AI_STYLE_GUIDE_GLOBAL)
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    # Defensive: settings table can hold any JSON shape. A dict written
    # by an older code path collapses to empty rather than leaking
    # ``{"value": "..."}``-style ugliness into the LLM prompt.
    return ""

def set_global_anti_ai_style_guide(
    conn: sqlite3.Connection, text: str,
) -> None:
    """Persist the install-wide anti-AI style guide (upsert).

    Stores a plain JSON string (no dict wrapper). Empty / whitespace-only
    input is normalised to the empty string so a "clear the field"
    operator action takes effect immediately.
    """
    # Late import: web.db re-exports the names defined
    # here; importing at module top would cycle. Mirrors the
    # accounts.py #277b late-import precedent.
    from email_triage.web.db import set_setting
    from email_triage.web.settings_keys import ANTI_AI_STYLE_GUIDE_GLOBAL
    cleaned = (text or "").strip()
    set_setting(conn, ANTI_AI_STYLE_GUIDE_GLOBAL, cleaned)

def get_user_anti_ai_style_guide(
    conn: sqlite3.Connection, user_id: int | None,
) -> tuple[str, bool]:
    """Return ``(user_text, disable_global)`` for the user.

    Returns ``("", False)`` when ``user_id`` is missing or the columns
    haven't been added yet (pre-v20 DB). The disable flag is forced to
    False on a None user so an anonymous prompt-build path doesn't
    accidentally suppress the install-wide guide.
    """
    if not user_id:
        return ("", False)
    try:
        row = conn.execute(
            "SELECT anti_ai_style_guide_user, "
            "       anti_ai_style_guide_disable_global "
            "FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        # Pre-v20 DB — columns don't exist yet.
        return ("", False)
    if row is None:
        return ("", False)
    text = ""
    disable = False
    try:
        text = str(row["anti_ai_style_guide_user"] or "")
        disable = bool(row["anti_ai_style_guide_disable_global"])
    except (KeyError, IndexError, TypeError):
        # Defensive: row factory may not return mapping-style rows in
        # some test fixtures; fall back to the empty defaults.
        return ("", False)
    return (text, disable)

@db_write
def set_user_anti_ai_style_guide(
    conn: sqlite3.Connection, user_id: int, *,
    text: str, disable_global: bool,
) -> None:
    """Persist the per-user anti-AI guide + disable-global flag."""
    cleaned = (text or "").strip()
    conn.execute(
        "UPDATE users SET "
        "  anti_ai_style_guide_user = ?, "
        "  anti_ai_style_guide_disable_global = ? "
        "WHERE id = ?",
        (cleaned, 1 if disable_global else 0, int(user_id)),
    )
    conn.commit()

def get_sent_mail_index_summary(
    conn: sqlite3.Connection, account_id: int,
) -> dict:
    """Summarise the sent-mail-index rows for ``account_id``.

    Returns a dict shaped for the /profile/style-data page:

    * ``count``: total indexed rows (0 if table absent or no rows).
    * ``oldest``: ISO timestamp of the oldest sent_at, or None.
    * ``newest``: ISO timestamp of the newest sent_at, or None.
    * ``embedding_model``: most-recently-used embedding model name,
      or empty string.
    * ``sample_subjects``: up to 3 subjects (caller redacts under
      HIPAA; this helper does NOT redact — gating is at the route).
    * ``available``: True when the M-4 table exists. False is the
      "feature not installed yet" signal the template uses to hide
      the section entirely.
    """
    out: dict = {
        "count": 0,
        "oldest": None,
        "newest": None,
        "embedding_model": "",
        "sample_subjects": [],
        "available": False,
    }
    if not _has_table(conn, "sent_mail_index"):
        return out
    out["available"] = True

    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(sent_at) AS oldest, "
        "       MAX(sent_at) AS newest "
        "FROM sent_mail_index WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    if row is not None:
        out["count"] = int(
            row["n"] if hasattr(row, "keys") else row[0],
        )
        out["oldest"] = (
            row["oldest"] if hasattr(row, "keys") else row[1]
        )
        out["newest"] = (
            row["newest"] if hasattr(row, "keys") else row[2]
        )

    if out["count"] == 0:
        return out

    # Most-recent embedding model name (an account could have rows from
    # multiple models if the operator swapped backends; we surface the
    # newest). One row is plenty.
    model_row = conn.execute(
        "SELECT embedding_model FROM sent_mail_index "
        "WHERE account_id = ? "
        "ORDER BY indexed_at DESC LIMIT 1",
        (account_id,),
    ).fetchone()
    if model_row is not None:
        out["embedding_model"] = (
            (model_row["embedding_model"]
             if hasattr(model_row, "keys")
             else model_row[0]) or ""
        )

    sample_rows = conn.execute(
        "SELECT subject FROM sent_mail_index "
        "WHERE account_id = ? "
        "ORDER BY sent_at DESC LIMIT 3",
        (account_id,),
    ).fetchall()
    out["sample_subjects"] = [
        (r["subject"] if hasattr(r, "keys") else r[0]) or "(no subject)"
        for r in sample_rows
    ]
    return out

def get_captured_pair_count(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Count rows where ``is_captured_pair = 1`` for ``account_id``.

    M-6 (the capture loop) ships this column in a parallel branch.
    Until that lands, the column is absent and this helper returns 0.
    Defence-in-depth: even when the column exists, missing-row counts
    return 0 instead of raising.
    """
    if not _has_column(conn, "sent_mail_index", "is_captured_pair"):
        return 0
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM sent_mail_index "
            "WHERE account_id = ? AND is_captured_pair = 1",
            (account_id,),
        ).fetchone()
    except sqlite3.Error:
        return 0
    if row is None:
        return 0
    return int(row["n"] if hasattr(row, "keys") else row[0])

@db_write
def delete_sent_mail_index_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> int:
    """Drop every sent_mail_index row for ``account_id``.

    Mirrors :meth:`SentMailIndex.delete_account_index` but stays
    DB-only so the /profile/style-data delete path doesn't need to
    instantiate the M-4 helper (which requires an embedding backend).
    Returns the number of rows deleted (0 when the table is absent).
    """
    if not _has_table(conn, "sent_mail_index"):
        return 0
    cur = conn.execute(
        "DELETE FROM sent_mail_index WHERE account_id = ?",
        (account_id,),
    )
    conn.commit()
    try:
        return int(cur.rowcount or 0)
    except Exception:
        return 0

def is_style_learning_per_contact_enabled(account: dict | None) -> bool:
    """Return the per-account "match by recipient" sub-toggle.

    Read from ``account.config["style_learning_per_contact_enabled"]``.
    Default is True (on) -- the privacy-neutral refinement of an
    already-opted-in M-4 surface. The HIPAA gate at
    :class:`SentMailIndex` short-circuits regardless of this value;
    this flag is the operator UX surface only.
    """
    if account is None:
        return False
    cfg = account.get("config") if isinstance(account, dict) else None
    if not isinstance(cfg, dict):
        return True
    val = cfg.get("style_learning_per_contact_enabled")
    if val is None:
        return True
    return bool(val)
