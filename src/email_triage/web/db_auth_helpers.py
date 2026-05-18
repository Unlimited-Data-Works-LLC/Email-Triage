"""Helper functions for the #67 auth-surface upgrade.

Lives in its own module so the giant ``db.py`` doesn't grow further.
Imports are local-style (each function imports what it needs) to
match the rest of the codebase pattern and keep the public surface
of the module as the function names rather than implicit re-exports.
"""

from __future__ import annotations

import sqlite3
from typing import Any


# ---------------------------------------------------------------------------
# Dev-keypair helpers
# ---------------------------------------------------------------------------

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
    """Insert a new dev_keys row.

    ``expires_at`` is mandatory (TTL is a hard policy, not optional).
    Raises ``sqlite3.IntegrityError`` if the fingerprint is already
    registered (admin should revoke + re-add rather than re-add a
    duplicate).
    """
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO dev_keys "
        "(name, public_key, fingerprint, email_allowlist_json, "
        " created_by_user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            name, public_key, fingerprint,
            json.dumps(email_allowlist),
            created_by_user_id, now, expires_at,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


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
            d["email_allowlist"] = json.loads(d.pop("email_allowlist_json") or "[]")
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
        "SELECT * FROM dev_keys WHERE fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    try:
        d["email_allowlist"] = json.loads(d.pop("email_allowlist_json") or "[]")
    except Exception:
        d["email_allowlist"] = []
    return d


def revoke_dev_key(
    conn: sqlite3.Connection, key_id: int, revoked_by_user_id: int | None,
) -> bool:
    """Set ``revoked_at`` + ``revoked_by_user_id``.

    Idempotent: re-revoking is a no-op (we keep the original
    timestamp). Returns True on first revoke, False if already
    revoked or missing.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "UPDATE dev_keys SET revoked_at = ?, revoked_by_user_id = ? "
        "WHERE id = ? AND revoked_at IS NULL",
        (now, revoked_by_user_id, key_id),
    )
    conn.commit()
    return cur.rowcount > 0


def mark_dev_key_used(
    conn: sqlite3.Connection,
    key_id: int,
    *,
    email: str,
    ip: str,
) -> None:
    """Stamp last_used_at + last_used_email + last_used_ip on the row."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
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
    """Insert a hardware_keys row after a successful registration.

    Returns the new id.
    """
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO hardware_keys "
        "(user_id, credential_id, public_key, sign_count, transports, "
        " aaguid, nickname, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, credential_id, public_key, int(sign_count),
            json.dumps(list(transports) if transports else []),
            aaguid, nickname, now,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_hardware_keys(
    conn: sqlite3.Connection,
    user_id: int | None,
    *,
    include_revoked: bool = False,
) -> list[dict]:
    """List hardware keys, newest first.

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
            d["transports"] = json.loads(d.get("transports") or "[]")
        except Exception:
            d["transports"] = []
        out.append(d)
    return out


def find_hardware_key_by_credential_id(
    conn: sqlite3.Connection, credential_id: bytes,
) -> dict | None:
    row = conn.execute(
        "SELECT * FROM hardware_keys WHERE credential_id = ? "
        "AND revoked_at IS NULL",
        (credential_id,),
    ).fetchone()
    return dict(row) if row else None


def update_hardware_key_sign_count(
    conn: sqlite3.Connection, key_id: int, new_count: int,
) -> None:
    """Bump sign_count + last_used_at after a successful authentication.

    The ``new_count`` MUST be greater than the current count. A
    regression is the cloned-authenticator signal and must be
    rejected by the caller before this function is called.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE hardware_keys SET sign_count = ?, last_used_at = ? "
        "WHERE id = ?",
        (int(new_count), now, key_id),
    )
    conn.commit()


def revoke_hardware_key(conn: sqlite3.Connection, key_id: int) -> bool:
    """Soft-revoke a hardware key. Returns True on first revoke."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "UPDATE hardware_keys SET revoked_at = ? "
        "WHERE id = ? AND revoked_at IS NULL",
        (now, key_id),
    )
    conn.commit()
    return cur.rowcount > 0


def user_has_active_hardware_key(
    conn: sqlite3.Connection, user_id: int,
) -> bool:
    """True if the user has at least one non-revoked hardware key.

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
        "SELECT * FROM users WHERE webauthn_user_handle = ?",
        (handle,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# WebAuthn challenge helpers
# ---------------------------------------------------------------------------

def store_webauthn_challenge(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    email: str | None,
    kind: str,
    challenge: bytes,
    ttl_seconds: int = 300,
) -> int:
    """Store a per-ceremony challenge with TTL.

    ``kind`` is 'register' or 'authenticate'. Caller looks up by
    (user_id, kind) or (email, kind) at finish time.
    """
    from datetime import datetime, timedelta, timezone
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    ).isoformat()
    cur = conn.execute(
        "INSERT INTO webauthn_challenges "
        "(user_id, email, kind, challenge, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, email, kind, challenge, expires_at),
    )
    conn.commit()
    return int(cur.lastrowid)


def consume_webauthn_challenge(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    email: str | None,
    kind: str,
) -> bytes | None:
    """Return + delete the most recent unexpired challenge.

    None if no match (or expired). Single-use.
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    if user_id is not None:
        row = conn.execute(
            "SELECT id, challenge FROM webauthn_challenges "
            "WHERE user_id = ? AND kind = ? AND expires_at > ? "
            "ORDER BY id DESC LIMIT 1",
            (user_id, kind, now_iso),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id, challenge FROM webauthn_challenges "
            "WHERE email = ? AND kind = ? AND expires_at > ? "
            "ORDER BY id DESC LIMIT 1",
            (email, kind, now_iso),
        ).fetchone()
    if row is None:
        return None
    conn.execute(
        "DELETE FROM webauthn_challenges WHERE id = ?", (row["id"],),
    )
    conn.commit()
    return bytes(row["challenge"])


def prune_expired_webauthn_challenges(conn: sqlite3.Connection) -> int:
    """Garbage-collect expired challenges.

    Caller drives via a periodic task. Returns the number of rows
    deleted.
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "DELETE FROM webauthn_challenges WHERE expires_at <= ?",
        (now_iso,),
    )
    conn.commit()
    return cur.rowcount


# ---------------------------------------------------------------------------
# ACME renewal log
# ---------------------------------------------------------------------------

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
    """
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()
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
        "SELECT * FROM acme_renewal_log ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(r) for r in rows]
