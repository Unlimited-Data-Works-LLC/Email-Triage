"""Re-export shim — the DB-layer auth/user helpers moved to ``db/users.py``.

This module is now a thin compatibility shim. The implementations live in
:mod:`email_triage.db.users` (their canonical DB-layer home). This shim keeps
every existing ``from email_triage.web.db_auth_helpers import …`` call site
resolving unchanged — the same re-export pattern #277b/#277c used when
``db/accounts.py`` and ``db/style.py`` were extracted.

Prefer importing from :mod:`email_triage.db.users` in new code.
"""

from __future__ import annotations

from email_triage.db.users import (  # noqa: F401  (re-export for back-compat)
    add_dev_key,
    list_dev_keys,
    find_dev_key_by_fingerprint,
    revoke_dev_key,
    mark_dev_key_used,
    is_dev_key_active,
    add_hardware_key,
    list_hardware_keys,
    find_hardware_key_by_credential_id,
    update_hardware_key_sign_count,
    revoke_hardware_key,
    user_has_active_hardware_key,
    get_or_create_webauthn_user_handle,
    find_user_by_webauthn_handle,
    store_webauthn_challenge,
    consume_webauthn_challenge,
    WebAuthnChallenge,
    prune_expired_webauthn_challenges,
    insert_acme_renewal_log,
    list_acme_renewal_log,
)

__all__ = [
    "add_dev_key",
    "list_dev_keys",
    "find_dev_key_by_fingerprint",
    "revoke_dev_key",
    "mark_dev_key_used",
    "is_dev_key_active",
    "add_hardware_key",
    "list_hardware_keys",
    "find_hardware_key_by_credential_id",
    "update_hardware_key_sign_count",
    "revoke_hardware_key",
    "user_has_active_hardware_key",
    "get_or_create_webauthn_user_handle",
    "find_user_by_webauthn_handle",
    "store_webauthn_challenge",
    "consume_webauthn_challenge",
    "WebAuthnChallenge",
    "prune_expired_webauthn_challenges",
    "insert_acme_renewal_log",
    "list_acme_renewal_log",
]
