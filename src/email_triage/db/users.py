"""DB-layer auth/user helpers — canonical home.

Byte-identical move of the former ``web/db_auth_helpers.py`` into the ``db/``
layer where it belongs (it is 100% DB CRUD on ``dev_keys``/``hardware_keys``/
``webauthn_challenges``/``users``/``acme_renewal_log`` — zero web/route code).
``web/db_auth_helpers.py`` remains as a thin re-export shim so all existing
``from email_triage.web.db_auth_helpers import …`` call sites keep resolving
(the #277b/#277c precedent). Only the DB-layer subset of #277e moved cleanly;
``web/auth.py``'s session/cookie/SMTP cluster is WEB-layer and stays put (its
split is a design decision, deliberately deferred — see the backlog #277e).

Original note: lives in its own module so the giant ``db.py`` doesn't grow
further; imports are local-style (each function imports what it needs).
"""

from __future__ import annotations

from email_triage.db.columns import (
    ACME_RENEWAL_LOG_COLUMNS,
    DEV_KEYS_COLUMNS,
    HARDWARE_KEYS_COLUMNS,
    USERS_COLUMNS,
)
from email_triage._isotime import now_utc_iso, to_utc_iso

from email_triage.db._helpers import dump_json_col, load_json_col

import sqlite3
from typing import Any, NamedTuple

from email_triage.web.db_writelock import db_write as _db_write


# ---------------------------------------------------------------------------
# Dev-keypair helpers
# ---------------------------------------------------------------------------

def add_dev_key_txn(
    conn: sqlite3.Connection,
    *,
    name: str,
    public_key: str,
    fingerprint: str,
    email_allowlist: list[str],
    created_by_user_id: int | None,
    expires_at: str,
) -> int:
    """TXN-AWARE ``dev_keys`` insert — does NOT commit. Returns the new id.

    Punch 627 (N-611) — the ``*_txn`` sibling (N-520 convention, same as
    ``add_hardware_key_txn``): THE one author of the row shape, used inside
    ``db.audit.record_dev_key_registration`` so the dev-key GRANT and its
    ``dev_key_registered`` audit row commit or roll back together. Undecorated
    for the same reason as ``db.audit.record_auth_event_txn``: a
    ``@db_write`` here would roll back the caller's transaction on a raise.

    ``expires_at`` is mandatory (TTL is a hard policy, not optional).
    Raises ``sqlite3.IntegrityError`` if the fingerprint is already
    registered (admin should revoke + re-add rather than re-add a
    duplicate).
    """
    now = now_utc_iso()
    cur = conn.execute(
        "INSERT INTO dev_keys "
        "(name, public_key, fingerprint, email_allowlist_json, "
        " created_by_user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            name, public_key, fingerprint,
            dump_json_col(email_allowlist),
            created_by_user_id, now, expires_at,
        ),
    )
    return int(cur.lastrowid)


@_db_write
def add_dev_key(
    conn: sqlite3.Connection,
    *,
    name: str,
    public_key: str,
    fingerprint: str,
    email_allowlist: list[str],
    created_by_user_id: int | None,
    expires_at: str,
) -> int:
    """Insert a dev_keys row, own-commit, WITHOUT an audit row.

    Returns the new id. Punch 627: the admin route no longer comes here — it
    goes through ``db.audit.record_dev_key_registration`` (insert + witness in
    one transaction). A new src caller of this own-commit writer grants a
    credential with no audit row; the grant-audit pin in
    ``tests/test_session_epoch_on_revoke_pin.py`` turns RED on one.
    """
    new_id = add_dev_key_txn(
        conn, name=name, public_key=public_key, fingerprint=fingerprint,
        email_allowlist=email_allowlist,
        created_by_user_id=created_by_user_id, expires_at=expires_at,
    )
    conn.commit()
    return new_id


def list_dev_keys(conn: sqlite3.Connection) -> list[dict]:
    """All dev_keys rows, newest first.

    Includes revoked + expired so /admin/dev-keys can show full
    history; UI greys out the inactive rows. Email allowlist JSON
    is decoded into ``email_allowlist``.
    """
    import json
    rows = conn.execute(
        "SELECT dk.*, u.email AS created_by_email, "
        "u.name AS created_by_name "
        "FROM dev_keys dk "
        "LEFT JOIN users u ON dk.created_by_user_id = u.id "
        "ORDER BY dk.id DESC"
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        try:
            d["email_allowlist"] = load_json_col(d.pop("email_allowlist_json", None), default=[])
        except Exception:
            d["email_allowlist"] = []
        out.append(d)
    return out


def find_dev_key_by_fingerprint(
    conn: sqlite3.Connection, fingerprint: str,
) -> dict | None:
    """Return the dev_keys row for the given fingerprint, or None."""
    import json
    row = conn.execute(
        f"SELECT {DEV_KEYS_COLUMNS} FROM dev_keys WHERE fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    try:
        d["email_allowlist"] = load_json_col(d.pop("email_allowlist_json", None), default=[])
    except Exception:
        d["email_allowlist"] = []
    return d


@_db_write
def revoke_dev_key(
    conn: sqlite3.Connection, key_id: int, revoked_by_user_id: int | None,
) -> bool:
    """Set ``revoked_at`` + ``revoked_by_user_id``.

    Idempotent: re-revoking is a no-op (we keep the original
    timestamp). Returns True on first revoke, False if already
    revoked or missing.

    OWN-COMMIT wrapper over :func:`revoke_dev_key_txn` (one author).
    """
    revoked = revoke_dev_key_txn(conn, key_id, revoked_by_user_id)
    conn.commit()
    return revoked


def revoke_dev_key_txn(
    conn: sqlite3.Connection, key_id: int, revoked_by_user_id: int | None,
) -> bool:
    """TXN-AWARE body of :func:`revoke_dev_key`: does NOT commit (N-520).

    Undecorated for the reason on ``db/audit.record_auth_event_txn``: the
    caller (``db/audit.record_witnessed_state_change``) owns the transaction,
    so the revoke and its ``dev_key_revoked`` witness commit together.
    """
    now = now_utc_iso()
    cur = conn.execute(
        "UPDATE dev_keys SET revoked_at = ?, revoked_by_user_id = ? "
        "WHERE id = ? AND revoked_at IS NULL",
        (now, revoked_by_user_id, key_id),
    )
    if cur.rowcount > 0:
        #  — a dev-key authenticates as ANY email in its allowlist, and
        # session tokens don't record which credential authed them, so we
        # can't be surgical: fail-secure by bumping ``session_epoch`` for
        # every allowlisted user (a no-op for emails with no user row). This
        # rides the SAME implicit transaction as the revoke above (one
        # ``conn.commit()`` below) → atomic + fail-closed: if the bump can't
        # be written the revoke rolls back too, because a revoked credential
        # whose live sessions survive is the worse state. Revoking a
        # (possibly compromised) dev-key MUST cut the session, not merely
        # block the next login.
        row = conn.execute(
            "SELECT email_allowlist_json FROM dev_keys WHERE id = ?", (key_id,),
        ).fetchone()
        emails = load_json_col(
            row["email_allowlist_json"] if row is not None else None,
            default=[], label="dev_key.email_allowlist_json",
        )
        for email in emails:
            if not isinstance(email, str):
                continue
            conn.execute(
                "UPDATE users SET session_epoch = session_epoch + 1 "
                "WHERE email = ?",
                (email,),
            )
    return cur.rowcount > 0


@_db_write
def mark_dev_key_used(
    conn: sqlite3.Connection,
    key_id: int,
    *,
    email: str,
    ip: str,
) -> None:
    """Stamp last_used_at + last_used_email + last_used_ip on the row."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE dev_keys SET last_used_at = ?, last_used_email = ?, "
        "last_used_ip = ? WHERE id = ?",
        (now, email, ip, key_id),
    )
    conn.commit()


def is_dev_key_active(row: dict, now_iso: str) -> bool:
    """True iff revoked_at is null AND expires_at is in the future.

    Pure function: testable without a DB. Caller computes
    ``now_iso`` once per request and reuses across many rows.
    """
    if row.get("revoked_at"):
        return False
    return (row.get("expires_at") or "") > now_iso


# ---------------------------------------------------------------------------
# Hardware-key (WebAuthn) helpers
# ---------------------------------------------------------------------------

def add_hardware_key_txn(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    transports: list[str] | None,
    aaguid: bytes | None,
    nickname: str,
) -> int:
    """TXN-AWARE ``hardware_keys`` insert — does NOT commit. Returns the new id.

    Punch  — the ``*_txn`` sibling (N-520 convention, same as
    ``db.audit.record_auth_event_txn``): THE one author of the row shape, used
    inside ``db.audit.record_hardware_key_registration`` so the credential
    GRANT and its ``hardware_key_registered`` audit row commit or roll back
    together. Undecorated for the same reason as ``record_auth_event_txn``: a
    ``@db_write`` here would roll back the caller's transaction on a raise.
    """
    now = now_utc_iso()
    cur = conn.execute(
        "INSERT INTO hardware_keys "
        "(user_id, credential_id, public_key, sign_count, transports, "
        " aaguid, nickname, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, credential_id, public_key, int(sign_count),
            dump_json_col(list(transports) if transports else []),  # N-199 R21_7 SSOT
            aaguid, nickname, now,
        ),
    )
    return int(cur.lastrowid)


@_db_write
def add_hardware_key(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    transports: list[str] | None,
    aaguid: bytes | None,
    nickname: str,
) -> int:
    """Insert a hardware_keys row, own-commit, WITHOUT an audit row.

    Returns the new id. Punch : the registration route no longer comes
    here — it goes through ``db.audit.record_hardware_key_registration`` (insert
    + witness in one transaction). A new src caller of this own-commit writer
    grants a credential with no audit row; the grant-audit pin in
    ``tests/test_session_epoch_on_revoke_pin.py`` turns RED on one.
    """
    new_id = add_hardware_key_txn(
        conn, user_id=user_id, credential_id=credential_id,
        public_key=public_key, sign_count=sign_count, transports=transports,
        aaguid=aaguid, nickname=nickname,
    )
    conn.commit()
    return new_id


def list_hardware_keys(
    conn: sqlite3.Connection,
    user_id: int | None,
    *,
    include_revoked: bool = False,
) -> list[dict]:
    """List passkeys, newest first.

    ``user_id=None`` returns ALL users' keys (admin-only view) with
    ``owner_email`` + ``owner_name`` joined for the filter dropdown
    + per-row labelling. Default excludes revoked rows. ``transports``
    decoded from JSON.
    """
    import json
    revoke_clause = "" if include_revoked else "AND hk.revoked_at IS NULL"
    if user_id is None:
        rows = conn.execute(
            f"SELECT hk.*, u.email AS owner_email, u.name AS owner_name "
            f"FROM hardware_keys hk "
            f"LEFT JOIN users u ON u.id = hk.user_id "
            f"WHERE 1=1 {revoke_clause} "
            f"ORDER BY hk.id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT hk.*, u.email AS owner_email, u.name AS owner_name "
            f"FROM hardware_keys hk "
            f"LEFT JOIN users u ON u.id = hk.user_id "
            f"WHERE hk.user_id = ? {revoke_clause} "
            f"ORDER BY hk.id DESC",
            (user_id,),
        ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        try:
            d["transports"] = load_json_col(d.get("transports"), default=[])
        except Exception:
            d["transports"] = []
        out.append(d)
    return out


def find_hardware_key_by_credential_id(
    conn: sqlite3.Connection, credential_id: bytes,
) -> dict | None:
    row = conn.execute(
        f"SELECT {HARDWARE_KEYS_COLUMNS} FROM hardware_keys WHERE credential_id = ? "
        "AND revoked_at IS NULL",
        (credential_id,),
    ).fetchone()
    return dict(row) if row else None


def update_hardware_key_sign_count_txn(
    conn: sqlite3.Connection, key_id: int, new_count: int,
) -> None:
    """Non-committing body of :func:`update_hardware_key_sign_count`, for a
    caller that owns the transaction (N-520 step 2: the login success edge
    commits this with its witness row in ONE transaction)."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE hardware_keys SET sign_count = ?, last_used_at = ? "
        "WHERE id = ?",
        (int(new_count), now, key_id),
    )


@_db_write
def update_hardware_key_sign_count(
    conn: sqlite3.Connection, key_id: int, new_count: int,
) -> None:
    """Bump sign_count + last_used_at after a successful authentication.

    The ``new_count`` MUST be greater than the current count. A
    regression is the cloned-authenticator signal and must be
    rejected by the caller before this function is called.
    """
    update_hardware_key_sign_count_txn(conn, key_id, new_count)
    conn.commit()


@_db_write
def revoke_hardware_key(conn: sqlite3.Connection, key_id: int) -> bool:
    """Soft-revoke a passkey. Returns True on first revoke.

    On a real revoke this also bumps the key OWNER's ``session_epoch`` in the SAME implicit transaction (one ``conn.commit()`` below),
    so a live session that authenticated via the now-revoked passkey dies
    immediately — revoking a (possibly compromised) credential must cut the
    session, not merely block the next login. Fail-closed: if the bump
    can't be written the revoke rolls back too.

    OWN-COMMIT wrapper over :func:`revoke_hardware_key_txn` (one author).
    """
    revoked = revoke_hardware_key_txn(conn, key_id)
    conn.commit()
    return revoked


def revoke_hardware_key_txn(conn: sqlite3.Connection, key_id: int) -> bool:
    """TXN-AWARE body of :func:`revoke_hardware_key`: does NOT commit (N-520).

    Undecorated; the caller (``db/audit.record_witnessed_state_change``) owns
    the transaction, so the revoke and its ``hardware_key_revoked`` witness
    commit together.
    """
    now = now_utc_iso()
    cur = conn.execute(
        "UPDATE hardware_keys SET revoked_at = ? "
        "WHERE id = ? AND revoked_at IS NULL",
        (now, key_id),
    )
    if cur.rowcount > 0:
        conn.execute(
            "UPDATE users SET session_epoch = session_epoch + 1 "
            "WHERE id = (SELECT user_id FROM hardware_keys WHERE id = ?)",
            (key_id,),
        )
    return cur.rowcount > 0


def user_has_active_hardware_key(
    conn: sqlite3.Connection, user_id: int,
) -> bool:
    """True if the user has at least one non-revoked passkey.

    Drives the hardware-key-wins rule for dev-keypair login (when
    True, dev-keypair logins for this user's email are denied) and
    the login-page method picker (when True, render the choose step).
    """
    row = conn.execute(
        "SELECT 1 FROM hardware_keys "
        "WHERE user_id = ? AND revoked_at IS NULL LIMIT 1",
        (user_id,),
    ).fetchone()
    return row is not None


@_db_write
def get_or_create_webauthn_user_handle(
    conn: sqlite3.Connection, user_id: int,
) -> bytes:
    """Return the user's WebAuthn handle, generating + storing one
    on first call.

    WebAuthn spec requires a stable, server-assigned 16-64 byte ID
    per user. Generated once with ``os.urandom``, never changed.
    """
    import os
    row = conn.execute(
        "SELECT webauthn_user_handle FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row and row["webauthn_user_handle"] is not None:
        return bytes(row["webauthn_user_handle"])
    handle = os.urandom(32)
    conn.execute(
        "UPDATE users SET webauthn_user_handle = ? WHERE id = ?",
        (handle, user_id),
    )
    conn.commit()
    return handle


def find_user_by_webauthn_handle(
    conn: sqlite3.Connection, handle: bytes,
) -> dict | None:
    row = conn.execute(
        f"SELECT {USERS_COLUMNS} FROM users WHERE webauthn_user_handle = ?",
        (handle,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# WebAuthn challenge helpers
# ---------------------------------------------------------------------------

class WebAuthnChallenge(NamedTuple):
    """A consumed ceremony challenge and the user-verification requirement
    its begin step asked for (punch ). ``require_user_verification`` is
    None only for a row written before migration v53; callers must refuse it."""

    challenge: bytes
    require_user_verification: bool | None


@_db_write
def store_webauthn_challenge(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    email: str | None,
    kind: str,
    challenge: bytes,
    require_user_verification: bool,
    ttl_seconds: int = 300,
) -> int:
    """Store a per-ceremony challenge with TTL.

    ``kind`` is 'register', 'authenticate' or 'passkey'. Caller looks up by
    (user_id, kind), (email, kind), or -- for 'passkey', which has neither a
    user_id nor an email at begin time -- by the row id this returns
    (``consume_webauthn_challenge(challenge_id=...)``) at finish time.

    ``require_user_verification`` has no default on purpose (punch ):
    it is what the begin step asked the authenticator for, and the finish
    step enforces exactly that. Every caller states it.
    """
    from datetime import datetime, timedelta, timezone
    expires_at = to_utc_iso(
        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    )
    cur = conn.execute(
        "INSERT INTO webauthn_challenges "
        "(user_id, email, kind, challenge, expires_at, require_uv) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, email, kind, challenge, expires_at,
         1 if require_user_verification else 0),
    )
    conn.commit()
    return int(cur.lastrowid)


@_db_write
def consume_webauthn_challenge(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    email: str | None,
    kind: str,
    challenge_id: int | None = None,
) -> WebAuthnChallenge | None:
    """Committing form of :func:`consume_webauthn_challenge_txn`: the burn is
    durable when this returns (a refused ceremony stays burned)."""
    stored = consume_webauthn_challenge_txn(
        conn, user_id=user_id, email=email, kind=kind, challenge_id=challenge_id,
    )
    conn.commit()
    return stored


def consume_webauthn_challenge_txn(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    email: str | None,
    kind: str,
    challenge_id: int | None = None,
) -> WebAuthnChallenge | None:
    """Return + delete the most recent unexpired challenge, with the
    user-verification requirement stored beside it. Does NOT commit: the
    caller owns the transaction (N-520 step 2 login funnel; the committing
    form is :func:`consume_webauthn_challenge`).

    None if no match (or expired). Single-use, and the single use is proved by
    the statement rather than by the caller's serialisation (panel F15): the read
    and the delete are ONE `DELETE ... RETURNING`, so two racing consumers cannot
    both see the row. The previous SELECT-then-DELETE rested entirely on the
    process-wide ``@_db_write`` lock; that holds as shipped (the deploy is
    single-process) but degrades to an authentication BYPASS -- a replay -- the
    day the app runs more than one worker process.

    ``challenge_id`` (punch ) selects ONE row by primary key instead of
    by owner: the passkey login has no user_id and no email at begin time, so
    its begin step hands the caller that row id and its finish step redeems
    it. ``kind`` is still matched, so a handle minted for one ceremony kind
    cannot be redeemed at another kind's finish step. ``user_id`` / ``email``
    are ignored when it is given. This is the SAME single-use store the
    hardware-key path uses, with a second way to name a row -- not a second
    challenge store.
    """
    now_iso = now_utc_iso()
    if challenge_id is not None:
        # Named by primary key. The owner clause is not redundant: a passkey row
        # is owned by NEITHER a user_id nor an email, so without it a handle could
        # name some other user's ceremony row of the same kind (panel F15 --
        # latent today because only the passkey flow mints these handles).
        rows = conn.execute(
            "DELETE FROM webauthn_challenges "
            "WHERE id = ? AND kind = ? AND expires_at > ? "
            "AND user_id IS NULL AND email IS NULL "
            "RETURNING challenge, require_uv",
            (challenge_id, kind, now_iso),
        ).fetchall()
    elif user_id is not None:
        # SQLite rejects ORDER BY / LIMIT on DELETE, so the newest row is picked
        # by a scalar subquery and the DELETE names exactly that id.
        rows = conn.execute(
            "DELETE FROM webauthn_challenges WHERE id = ("
            "  SELECT id FROM webauthn_challenges "
            "  WHERE user_id = ? AND kind = ? AND expires_at > ? "
            "  ORDER BY id DESC LIMIT 1"
            ") RETURNING challenge, require_uv",
            (user_id, kind, now_iso),
        ).fetchall()
    else:
        rows = conn.execute(
            "DELETE FROM webauthn_challenges WHERE id = ("
            "  SELECT id FROM webauthn_challenges "
            "  WHERE email = ? AND kind = ? AND expires_at > ? "
            "  ORDER BY id DESC LIMIT 1"
            ") RETURNING challenge, require_uv",
            (email, kind, now_iso),
        ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        # Unreachable by construction (both shapes name one id). Fail CLOSED if
        # it ever is reached: consuming N rows is not a single use.
        raise RuntimeError(
            f"consume_webauthn_challenge deleted {len(rows)} rows for one "
            f"ceremony (kind={kind!r}); a single-use challenge store must "
            "consume exactly one"
        )
    row = rows[0]
    uv = row["require_uv"]
    return WebAuthnChallenge(
        challenge=bytes(row["challenge"]),
        require_user_verification=None if uv is None else bool(uv),
    )


@_db_write
def prune_expired_webauthn_challenges(conn: sqlite3.Connection) -> int:
    """Garbage-collect expired challenges.

    Caller drives via a periodic task. Returns the number of rows
    deleted.
    """
    now_iso = now_utc_iso()
    cur = conn.execute(
        "DELETE FROM webauthn_challenges WHERE expires_at <= ?",
        (now_iso,),
    )
    conn.commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# ACME renewal log
# ---------------------------------------------------------------------------

@_db_write
def insert_acme_renewal_log(
    conn: sqlite3.Connection,
    *,
    domain: str,
    outcome: str,
    not_before: str | None = None,
    not_after: str | None = None,
    error: str | None = None,
) -> int:
    """Append a renewal-log row.

    ``outcome`` ∈ {'renewed', 'skipped_fresh', 'failed', 'test_ok',
    'test_failed'}.

    // — the ``@_db_write`` decorator serialises this
    INSERT+commit on the process-wide write lock for every caller,
    including the ACME ``renewal_loop`` background task, which bypasses
    ``db_call`` (it runs both on the event loop via
    ``check_and_renew_async`` and on a worker thread via ``issue_now``).
    """
    ts = now_utc_iso()
    cur = conn.execute(
        "INSERT INTO acme_renewal_log "
        "(ts, domain, outcome, not_before, not_after, error) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ts, domain, outcome, not_before, not_after, error),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_acme_renewal_log(
    conn: sqlite3.Connection, limit: int = 50,
) -> list[dict]:
    """Most recent N rows, newest first."""
    rows = conn.execute(
        f"SELECT {ACME_RENEWAL_LOG_COLUMNS} FROM acme_renewal_log ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(r) for r in rows]
