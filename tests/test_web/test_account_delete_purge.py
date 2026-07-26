"""Behavioural tests for account-delete credential + watcher purge.

Loop-6 census L1 (§164.310(d)(2)(i)) + L2 fix.

Covers:
  * Single account delete via DELETE /accounts/{id} — secrets gone,
    settings gone, watcher stopped.
  * User delete via POST /users/{id}/delete — multi-account case,
    ALL accounts' secrets + settings gone, watchers stopped.
  * API user delete via DELETE /users/{id} — same as UI delete.
  * purge_account_local_state in isolation: correct counts returned,
    idempotent on second call.

Fixture strategy: reuse the ``db`` + ``app`` + ``client`` fixtures from
tests/test_web/conftest.py (session app, _InMemorySecrets, in-memory DB).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token

from . import conftest as _conftest

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

def _create_user(db, email="owner@example.com", role="user", name="Owner"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, name, role, now),
    )
    db.commit()
    return cur.lastrowid


def _create_account(db, user_id, name="Test Account", ptype="imap"):
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cfg = json.dumps({"push_enabled": False, "poll_enabled": False})
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, ptype, cfg, now, now),
    )
    db.commit()
    return cur.lastrowid


def _authed_client(app, db, role="admin", email="admin@example.com"):
    """Return a TestClient pre-loaded with a valid session cookie."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    # Upsert the admin user.
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        uid = existing["id"]
    else:
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
            (email, "Admin", role, now),
        )
        db.commit()
        uid = cur.lastrowid
    import time as _time
    token = create_session_token(
        _conftest.TEST_SECRET, email, role,
        mfa_verified_at=int(_time.time()),
    )
    # Use the CSRF-token-injecting client (migration step 2) so guarded
    # DELETE/POSTs carry a valid token under the enforce=True default.
    client = _conftest._CsrfClient(app, raise_server_exceptions=True)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    return client, uid


def _seed_secrets(secrets, account_id, provider_type="imap"):
    """Seed a fake provider credential into the in-memory secrets store."""
    from email_triage.providers.traits import secret_key_for_account
    sk = secret_key_for_account(account_id, provider_type)
    if sk:
        secrets.set(sk, "fake-credential-value")
        return sk
    return None


def _seed_clientstate(secrets, account_id):
    from email_triage.web import settings_keys as _S
    key = _S.office365_clientstate(account_id)
    secrets.set(key, "fake-client-state")
    return key


def _seed_setting(db, key, value="1"):
    from email_triage.web.db import set_setting
    set_setting(db, key, value)


# ---------------------------------------------------------------------------
# Unit: purge_account_local_state in isolation
# ---------------------------------------------------------------------------

class TestPurgeAccountLocalState:
    def test_purge_removes_imap_secret(self, db, app):
        secrets = app.state.secrets
        user_id = _create_user(db)
        acct_id = _create_account(db, user_id, ptype="imap")
        sk = _seed_secrets(secrets, acct_id, "imap")
        assert secrets.get(sk) is not None

        from email_triage.db.accounts import purge_account_local_state
        result = purge_account_local_state(db, acct_id, secrets)

        assert secrets.get(sk) is None, "IMAP_PASSWORD should have been purged"
        assert result["secrets_deleted"] >= 1
        assert result["account_id"] == acct_id

    def test_purge_removes_gmail_secret(self, db, app):
        secrets = app.state.secrets
        user_id = _create_user(db, email="gmail@example.com")
        acct_id = _create_account(db, user_id, ptype="gmail_api")
        sk = _seed_secrets(secrets, acct_id, "gmail_api")
        assert secrets.get(sk) is not None

        from email_triage.db.accounts import purge_account_local_state
        result = purge_account_local_state(db, acct_id, secrets)

        assert secrets.get(sk) is None, "GMAIL_REFRESH_TOKEN should have been purged"
        assert result["secrets_deleted"] >= 1

    def test_purge_removes_o365_secret(self, db, app):
        secrets = app.state.secrets
        user_id = _create_user(db, email="o365@example.com")
        acct_id = _create_account(db, user_id, ptype="office365")
        sk = _seed_secrets(secrets, acct_id, "office365")
        assert secrets.get(sk) is not None

        from email_triage.db.accounts import purge_account_local_state
        result = purge_account_local_state(db, acct_id, secrets)

        assert secrets.get(sk) is None, "O365_SECRET should have been purged"
        assert result["secrets_deleted"] >= 1

    def test_purge_removes_office365_clientstate(self, db, app):
        secrets = app.state.secrets
        user_id = _create_user(db, email="cs@example.com")
        acct_id = _create_account(db, user_id, ptype="office365")
        cs_key = _seed_clientstate(secrets, acct_id)
        assert secrets.get(cs_key) is not None

        from email_triage.db.accounts import purge_account_local_state
        purge_account_local_state(db, acct_id, secrets)

        assert secrets.get(cs_key) is None, (
            "office365_clientstate should have been purged from secrets_store"
        )

    def test_purge_removes_settings_rows(self, db, app):
        secrets = app.state.secrets
        user_id = _create_user(db, email="stg@example.com")
        acct_id = _create_account(db, user_id)
        from email_triage.web import settings_keys as _S
        # Seed a couple of settings rows.
        _seed_setting(db, _S.watch(acct_id), "1")
        _seed_setting(db, _S.poll_state(acct_id), '{"last_poll_at": "2026-01-01T00:00:00Z"}')

        from email_triage.db.accounts import purge_account_local_state
        result = purge_account_local_state(db, acct_id, secrets)

        # Verify the rows are gone.
        row_watch = db.execute(
            "SELECT value_json FROM settings WHERE key = ?", (_S.watch(acct_id),)
        ).fetchone()
        row_poll = db.execute(
            "SELECT value_json FROM settings WHERE key = ?", (_S.poll_state(acct_id),)
        ).fetchone()
        assert row_watch is None, "watch:{id} setting should be deleted"
        assert row_poll is None, "poll_state:{id} setting should be deleted"
        assert result["settings_deleted"] >= 2

    def test_purge_is_idempotent(self, db, app):
        """Second call on an already-purged account returns zeros without error."""
        secrets = app.state.secrets
        user_id = _create_user(db, email="idem@example.com")
        acct_id = _create_account(db, user_id)
        _seed_secrets(secrets, acct_id, "imap")

        from email_triage.db.accounts import purge_account_local_state
        purge_account_local_state(db, acct_id, secrets)
        result2 = purge_account_local_state(db, acct_id, secrets)

        assert result2["secrets_deleted"] == 0
        assert result2["settings_deleted"] == 0

    def test_purge_without_secrets_arg_only_sweeps_settings(self, db, app):
        """When secrets=None, settings are purged and no exception is raised."""
        secrets = app.state.secrets
        user_id = _create_user(db, email="nosec@example.com")
        acct_id = _create_account(db, user_id)
        sk = _seed_secrets(secrets, acct_id, "imap")
        from email_triage.web import settings_keys as _S
        _seed_setting(db, _S.watch(acct_id), "1")

        from email_triage.db.accounts import purge_account_local_state
        result = purge_account_local_state(db, acct_id, None)

        # Settings purged.
        assert result["settings_deleted"] >= 1
        # Secrets NOT purged (no secrets arg).
        assert secrets.get(sk) is not None, "secrets should be intact when secrets=None"
        assert result["secrets_deleted"] == 0

    def test_purge_unlinks_per_account_msal_token_cache(
        self, db, app, tmp_path, monkeypatch
    ):
        """run18 #1 — the §164.310(d)(2)(i) disposal SSOT must UNLINK the
        on-disk per-account MSAL token-cache file (PLAINTEXT O365 OAuth
        tokens), not just DB-backed stores. Create the REAL file at the SSOT
        path, purge, assert it is GONE."""
        from email_triage.db.accounts import purge_account_local_state
        from email_triage.providers.factory import msal_cache_path_for_account

        user_id = _create_user(db, email="msalcache@example.com")
        acct_id = _create_account(db, user_id, ptype="office365")

        # The SSOT path is CWD-relative (./data/...); chdir into tmp_path so it
        # lands there and the real ./data dir is never touched.
        monkeypatch.chdir(tmp_path)
        cache_path = msal_cache_path_for_account(acct_id)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text('{"AccessToken": {"x": "plaintext-token"}}')
        assert cache_path.is_file()

        result = purge_account_local_state(db, acct_id, app.state.secrets)

        assert not cache_path.exists(), (
            "the per-account MSAL token-cache FILE must be unlinked on purge — "
            "plaintext OAuth tokens survived account deletion (run18 #1)"
        )
        assert result["msal_cache_deleted"] == 1

    def test_purge_msal_cache_absent_is_benign(
        self, db, app, tmp_path, monkeypatch
    ):
        """missing_ok=True — no cache file present (the common case) is NOT an
        error and reports zero disposed (the purge still succeeds)."""
        from email_triage.db.accounts import purge_account_local_state

        user_id = _create_user(db, email="nocache@example.com")
        acct_id = _create_account(db, user_id, ptype="imap")
        monkeypatch.chdir(tmp_path)

        result = purge_account_local_state(db, acct_id, app.state.secrets)
        assert result["msal_cache_deleted"] == 0

    def test_real_writer_path_equals_purge_path(
        self, db, app, tmp_path, monkeypatch
    ):
        """run18 #1 (DA Attack 4 + hipaa-sme) — drive the REAL writer seam
        (``Office365Provider._save_cache``), NOT a fabricated file, to prove the
        path the WRITER persists to is the SAME path
        ``purge_account_local_state`` unlinks.

        The sibling ``test_purge_unlinks_per_account_msal_token_cache`` writes
        the file at the PURGE's own SSOT path, so a future writer↔purge path
        divergence would slip past it ("mock the boundary, not the seam" —
        pattern_parallel_build_mock_the_boundary_not_the_seam). Here the file is
        created by REAL provider code at the provider's own ``_token_cache_path``
        (derived from the constructor arg the factory builds via the SSOT), and
        the purge — which derives the SAME SSOT path — must find and unlink it.
        """
        pytest.importorskip("msal")  # provider __init__ guards on HAS_MSAL
        from unittest.mock import MagicMock

        from email_triage.db.accounts import purge_account_local_state
        from email_triage.providers.factory import msal_cache_path_for_account
        from email_triage.providers.office365 import Office365Provider

        user_id = _create_user(db, email="realwriter@example.com")
        acct_id = _create_account(db, user_id, ptype="office365")

        # The SSOT path is CWD-relative (./data/...); chdir into tmp_path so it
        # lands there and the real ./data dir is never touched.
        monkeypatch.chdir(tmp_path)
        ssot_path = msal_cache_path_for_account(acct_id)

        # Build the provider EXACTLY as factory.py:338 does — token_cache_path
        # from the SSOT. The provider stores ``Path(token_cache_path)`` and
        # writes THERE in _save_cache; the test fabricates no path.
        provider = Office365Provider(
            client_id="cid",
            token_cache_path=str(ssot_path),
            username="realwriter@example.com",
        )
        # The writer's resolved path MUST be the factory SSOT path (the
        # invariant the run18 #1 fix turns on — writer-path == purge-path).
        assert provider._token_cache_path == ssot_path

        # Drive the REAL writer seam. _save_cache persists only when the MSAL
        # cache reports has_state_changed (the flag MSAL sets on every token
        # add); reuse the established tests/test_providers/test_office365.py
        # ::test_close pattern to trip it with plaintext-token-shaped content,
        # then call the provider's OWN writer — the file is created by real
        # provider code, not by the test.
        provider._cache = MagicMock()
        provider._cache.has_state_changed = True
        provider._cache.serialize.return_value = (
            '{"AccessToken": {"x": {"secret": "plaintext-oauth-token"}}}'
        )
        provider._save_cache()
        assert ssot_path.is_file(), (
            "the REAL Office365Provider writer (_save_cache) must create the "
            "per-account token-cache file at its token_cache_path"
        )

        # The purge derives the SAME SSOT path and must unlink the file the
        # WRITER created — writer-path == purge-path, proven end-to-end through
        # the real provider seam.
        result = purge_account_local_state(db, acct_id, app.state.secrets)
        assert not ssot_path.exists(), (
            "purge_account_local_state must unlink the file the REAL provider "
            "writer created — writer-path and purge-path must resolve to the "
            "same factory SSOT path (run18 #1; DA Attack 4)"
        )
        assert result["msal_cache_deleted"] == 1


# ---------------------------------------------------------------------------
# Integration: accounts_delete route
# ---------------------------------------------------------------------------

class TestAccountsDeleteRoute:
    def test_account_delete_purges_secrets(self, db, app):
        """DELETE /accounts/{id} must purge the account's secrets."""
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db)

        owner_id = _create_user(db, email="owner2@example.com")
        acct_id = _create_account(db, owner_id, ptype="imap")
        sk = _seed_secrets(secrets, acct_id, "imap")
        assert secrets.get(sk) is not None

        resp = client.delete(f"/accounts/{acct_id}")
        assert resp.status_code in (200, 204), (
            f"expected 2xx, got {resp.status_code}: {resp.text}"
        )
        assert secrets.get(sk) is None, (
            "IMAP_PASSWORD should have been purged after account delete"
        )

    def test_account_delete_purges_clientstate(self, db, app):
        """DELETE /accounts/{id} must purge office365_clientstate from secrets."""
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin3@example.com")

        owner_id = _create_user(db, email="owner3@example.com")
        acct_id = _create_account(db, owner_id, ptype="office365")
        cs_key = _seed_clientstate(secrets, acct_id)
        assert secrets.get(cs_key) is not None

        resp = client.delete(f"/accounts/{acct_id}")
        assert resp.status_code in (200, 204)
        assert secrets.get(cs_key) is None, (
            "office365_clientstate should have been purged after account delete"
        )

    def test_account_delete_stops_watcher(self, db, app):
        """DELETE /accounts/{id} must stop any live watcher."""
        import asyncio
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin4@example.com")

        owner_id = _create_user(db, email="owner4@example.com")
        acct_id = _create_account(db, owner_id)

        wm = app.state.watcher_manager
        # Manually enroll in poll (simulates a running watcher).
        wm._poll_registered[acct_id] = {"last_poll_at": None}
        assert wm.is_poll_running(acct_id)

        resp = client.delete(f"/accounts/{acct_id}")
        assert resp.status_code in (200, 204)
        assert not wm.is_running(acct_id), (
            "watcher should have been stopped after account delete"
        )

    def test_account_delete_fails_closed_on_purge_error(self, db, app, monkeypatch):
        """PD#8 — if the credential purge raises, the account row must NOT be
        deleted; deleting it would orphan the credentials (the L1 defect). The
        operator gets a 500 + retries."""
        from email_triage.web.db import get_email_account
        client, admin_id = _authed_client(app, db, email="admin_fc@example.com")
        owner_id = _create_user(db, email="owner_fc@example.com")
        acct_id = _create_account(db, owner_id, ptype="imap")

        wm = app.state.watcher_manager

        async def _boom(account_id):
            raise RuntimeError("simulated purge failure")
        monkeypatch.setattr(wm, "apply_account_deleted", _boom)

        resp = client.delete(f"/accounts/{acct_id}")
        assert resp.status_code == 500
        # Fail CLOSED — the account row is still present (not orphaned).
        assert get_email_account(db, acct_id) is not None, (
            "account row must NOT be deleted when the purge fails (fail-closed)"
        )

    def test_account_delete_purges_settings(self, db, app):
        """DELETE /accounts/{id} must remove settings rows for the account."""
        from email_triage.web import settings_keys as _S
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin5@example.com")

        owner_id = _create_user(db, email="owner5@example.com")
        acct_id = _create_account(db, owner_id)
        _seed_setting(db, _S.auth_stale(acct_id), "1")
        _seed_setting(db, _S.watch(acct_id), "1")

        resp = client.delete(f"/accounts/{acct_id}")
        assert resp.status_code in (200, 204)

        row = db.execute(
            "SELECT key FROM settings WHERE key LIKE ? OR key LIKE ?",
            (f"%:{acct_id}", f"%:{acct_id}:%"),
        ).fetchone()
        assert row is None, (
            f"settings row for account {acct_id} should be deleted: {row}"
        )


# ---------------------------------------------------------------------------
# Integration: delete_user route (multi-account)
# ---------------------------------------------------------------------------

class TestDeleteUserRoute:
    def test_delete_user_purges_all_account_secrets(self, db, app):
        """POST /users/{id}/delete must purge secrets for ALL user accounts."""
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin6@example.com")

        owner_id = _create_user(db, email="multiacct@example.com")
        # Two accounts, two secret types.
        acct1 = _create_account(db, owner_id, name="IMAP Account", ptype="imap")
        acct2 = _create_account(db, owner_id, name="Gmail Account", ptype="gmail_api")
        sk1 = _seed_secrets(secrets, acct1, "imap")
        sk2 = _seed_secrets(secrets, acct2, "gmail_api")
        cs_key = _seed_clientstate(secrets, acct1)
        assert secrets.get(sk1) is not None
        assert secrets.get(sk2) is not None
        assert secrets.get(cs_key) is not None

        resp = client.post(f"/users/{owner_id}/delete")
        # Expect redirect to /users on success.
        assert resp.status_code in (200, 302, 303), (
            f"expected 2xx or redirect, got {resp.status_code}: {resp.text}"
        )

        assert secrets.get(sk1) is None, "IMAP_PASSWORD for account1 should be purged"
        assert secrets.get(sk2) is None, "GMAIL_REFRESH_TOKEN for account2 should be purged"
        assert secrets.get(cs_key) is None, "office365_clientstate for account1 should be purged"

    def test_delete_user_stops_all_watchers(self, db, app):
        """POST /users/{id}/delete must stop watchers for ALL user accounts."""
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin7@example.com")

        owner_id = _create_user(db, email="watchowner@example.com")
        acct1 = _create_account(db, owner_id, name="Watch1", ptype="imap")
        acct2 = _create_account(db, owner_id, name="Watch2", ptype="imap")

        wm = app.state.watcher_manager
        wm._poll_registered[acct1] = {"last_poll_at": None}
        wm._poll_registered[acct2] = {"last_poll_at": None}
        assert wm.is_poll_running(acct1)
        assert wm.is_poll_running(acct2)

        resp = client.post(f"/users/{owner_id}/delete")
        assert resp.status_code in (200, 302, 303)

        assert not wm.is_running(acct1), "watcher for account1 should be stopped"
        assert not wm.is_running(acct2), "watcher for account2 should be stopped"

    def test_delete_user_purges_settings_for_all_accounts(self, db, app):
        """POST /users/{id}/delete must purge settings for all user accounts."""
        from email_triage.web import settings_keys as _S
        secrets = app.state.secrets
        client, admin_id = _authed_client(app, db, email="admin8@example.com")

        owner_id = _create_user(db, email="settingowner@example.com")
        acct1 = _create_account(db, owner_id, name="S1")
        acct2 = _create_account(db, owner_id, name="S2")
        _seed_setting(db, _S.watch(acct1), "1")
        _seed_setting(db, _S.watch(acct2), "1")

        resp = client.post(f"/users/{owner_id}/delete")
        assert resp.status_code in (200, 302, 303)

        # Both setting rows should be gone.
        for acct_id in (acct1, acct2):
            row = db.execute(
                "SELECT value_json FROM settings WHERE key = ?",
                (_S.watch(acct_id),),
            ).fetchone()
            assert row is None, f"watch:{acct_id} setting should be deleted after user delete"


class TestUserOffboardSoftDelete:
    """Operator ruling 2026-06-19: admin Remove SOFT-DISABLES the user and
    DEACTIVATES (not deletes) the accounts — preserving the §164.312(b)/(c)(1)
    audit trail that a hard ``DELETE FROM users`` would NULL/cascade-destroy."""

    def test_remove_soft_disables_user_deactivates_accounts_keeps_audit(self, db, app):
        from email_triage.db.audit import record_hipaa_access_event
        client, _admin_id = _authed_client(app, db, email="offboard_admin@example.com")
        owner_id = _create_user(db, email="offboard_owner@example.com")
        acct = _create_account(db, owner_id, name="OffAcct", ptype="imap")
        # Seed the PHI-access audit row a hard delete would CASCADE-destroy
        # (hipaa_access_events.account_id is ON DELETE CASCADE).
        record_hipaa_access_event(db, owner_id, acct, "offboard_seed")
        db.commit()
        before = db.execute(
            "SELECT COUNT(*) c FROM hipaa_access_events WHERE account_id = ?", (acct,)
        ).fetchone()["c"]
        assert before >= 1

        resp = client.post(f"/users/{owner_id}/delete")
        assert resp.status_code in (200, 302, 303), resp.text

        # User row RETAINED + soft-disabled (NEVER hard-deleted).
        urow = db.execute(
            "SELECT disabled FROM users WHERE id = ?", (owner_id,)
        ).fetchone()
        assert urow is not None, "user row must be RETAINED (never hard-deleted)"
        assert urow["disabled"] == 1, "user must be soft-disabled"

        # Account row RETAINED + deactivated (NEVER hard-deleted).
        arow = db.execute(
            "SELECT is_active FROM email_accounts WHERE id = ?", (acct,)
        ).fetchone()
        assert arow is not None, "account row must be RETAINED (never hard-deleted)"
        assert arow["is_active"] == 0, "account must be deactivated, not deleted"

        # THE load-bearing guarantee: the §164.312(b) PHI-access trail SURVIVES
        # (a hard delete would have cascade-deleted these rows). The SEEDED row
        # is still there, and the offboard correctly APPENDS its own
        # "account_purged" audit event — so the trail GROWS, never shrinks.
        seed_survived = db.execute(
            "SELECT COUNT(*) c FROM hipaa_access_events "
            "WHERE account_id = ? AND operation = 'offboard_seed'", (acct,)
        ).fetchone()["c"]
        assert seed_survived == 1, (
            "the seeded PHI-access audit row must SURVIVE the offboard — a hard "
            "delete would have cascade-deleted it"
        )
        after = db.execute(
            "SELECT COUNT(*) c FROM hipaa_access_events WHERE account_id = ?", (acct,)
        ).fetchone()["c"]
        assert after >= before, (
            f"the append-only audit trail must never shrink (before={before}, "
            f"after={after})"
        )

    def test_users_page_renders_remove_button_not_delete(self, db, app):
        """Rendered-view assertion (feedback_test_the_view): the manage page shows
        the honest "Remove" label, not "Delete", for a non-self user — and the
        confirm text no longer says "Delete user"."""
        client, _admin_id = _authed_client(app, db, email="render_admin@example.com")
        _create_user(db, email="render_target@example.com")
        resp = client.get("/users")
        assert resp.status_code == 200
        html = resp.text
        assert ">Remove</button>" in html, "the offboard button must read 'Remove'"
        assert ">Delete</button>" not in html, "the old 'Delete' label must be gone"
        assert "RETAINED" in html, "confirm text must explain the record is retained"


# ---------------------------------------------------------------------------
# Integration: api_delete_user route
# ---------------------------------------------------------------------------

class TestApiDeleteUserRoute:
    def _api_authed_client(self, app, db, email="apiadmin@example.com"):
        """Bearer-token auth via session cookie for the API route."""
        return _authed_client(app, db, role="admin", email=email)

    def test_api_delete_user_purges_secrets(self, db, app):
        """DELETE /api/users/{id} must purge secrets for all user accounts."""
        secrets = app.state.secrets
        client, admin_id = self._api_authed_client(app, db)

        owner_id = _create_user(db, email="apiowner@example.com")
        acct_id = _create_account(db, owner_id, ptype="imap")
        sk = _seed_secrets(secrets, acct_id, "imap")
        cs_key = _seed_clientstate(secrets, acct_id)

        resp = client.delete(f"/api/users/{owner_id}")
        assert resp.status_code in (200, 204), (
            f"expected 2xx, got {resp.status_code}: {resp.text}"
        )
        assert secrets.get(sk) is None, (
            "IMAP_PASSWORD should have been purged via API delete"
        )
        assert secrets.get(cs_key) is None, (
            "office365_clientstate should have been purged via API delete"
        )


# ---------------------------------------------------------------------------
# Census N-64 SME-panel must-fixes (rework after the BLOCK verdict)
# ---------------------------------------------------------------------------

class TestPurgeReworkMustFixes:
    def test_fail_closed_when_secret_delete_raises(self, db, app):
        """DA must-fix — a secrets.delete() that RAISES (locked/decrypt-error
        store) must NOT be swallowed: purge_account_local_state re-raises so
        the caller fails closed instead of orphaning credentials."""
        from email_triage.db.accounts import purge_account_local_state
        base = app.state.secrets
        user_id = _create_user(db, email="fcsec@example.com")
        acct_id = _create_account(db, user_id, ptype="imap")
        _seed_secrets(base, acct_id, "imap")

        class _RaisingSecrets:
            def delete(self, key):
                raise RuntimeError("secrets backend locked")
            def list_keys(self):
                return base.list_keys()

        with pytest.raises(Exception):
            purge_account_local_state(db, acct_id, _RaisingSecrets())

    def test_purges_watch_hmac_secret(self, db, app):
        """DA must-fix — per-watch HMAC secret (watch_{id}_hmac) is keyed by
        watch id (not ACCOUNT_{id}_*), so it must be swept explicitly."""
        from datetime import datetime, timezone
        from email_triage.db.accounts import purge_account_local_state
        secrets = app.state.secrets
        user_id = _create_user(db, email="whmac@example.com")
        acct_id = _create_account(db, user_id)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_watches "
            "(watch_id, name, account_id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)", ("w-7", "W", acct_id, now, now),
        )
        db.commit()
        from email_triage.web.email_watches import hmac_secret_key
        secrets.set(hmac_secret_key("w-7"), "fake-hmac-key")
        assert secrets.get(hmac_secret_key("w-7")) is not None

        purge_account_local_state(db, acct_id, secrets)
        assert secrets.get(hmac_secret_key("w-7")) is None, (
            "per-watch HMAC secret must be purged on account delete"
        )

    def test_purges_phi_style_tables_defense_in_depth(self, db, app):
        """hipaa-sme flagged these (the FK cascade is the primary disposal;
        this explicit sweep is belt-and-braces). Assert the explicit DELETE
        removes seeded PHI rows."""
        from datetime import datetime, timezone
        from email_triage.db.accounts import purge_account_local_state
        secrets = app.state.secrets
        user_id = _create_user(db, email="phi@example.com")
        acct_id = _create_account(db, user_id)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO hipaa_style_descriptors "
            "(account_id, descriptor_json, rebuilt_at) VALUES (?, '{}', ?)",
            (acct_id, now),
        )
        db.execute(
            "INSERT INTO per_contact_style_hipaa "
            "(account_id, recipient_hash, descriptor_json, last_distilled_at) "
            "VALUES (?, 'h', '{}', ?)", (acct_id, now),
        )
        db.commit()

        result = purge_account_local_state(db, acct_id, secrets)
        assert result["phi_rows_deleted"] >= 2
        assert db.execute(
            "SELECT COUNT(*) FROM hipaa_style_descriptors WHERE account_id=?",
            (acct_id,)).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM per_contact_style_hipaa WHERE account_id=?",
            (acct_id,)).fetchone()[0] == 0

    def test_funnel_emits_account_purged_audit(self, db, app):
        """hipaa-sme must-fix — the funnel (the SSOT seam every delete actuator
        routes through) emits ONE §164.312(b)/§164.308(a)(4)(ii)(C) audit row
        on the disposal. Driven at the funnel level (the route's TestClient
        threadpool uses a connection the post-hoc query can't observe; the
        funnel writes to app.state.db which IS the test connection)."""
        import asyncio
        owner_id = _create_user(db, email="auditowner@example.com")
        acct_id = _create_account(db, owner_id, ptype="imap")
        _seed_secrets(app.state.secrets, acct_id, "imap")

        wm = app.state.watcher_manager
        asyncio.run(wm.apply_account_deleted(acct_id, actor_user_id=owner_id))

        rows = db.execute(
            "SELECT operation, outcome, actor_user_id FROM hipaa_access_events "
            "WHERE account_id=? AND operation='account_purged'", (acct_id,)
        ).fetchall()
        assert rows, "an account_purged audit row must be written on disposal"
        assert rows[-1]["outcome"] == "ok"
        assert rows[-1]["actor_user_id"] == owner_id

    def test_funnel_audits_error_outcome_on_purge_failure(self, db, app, monkeypatch):
        """The funnel must also audit the FAIL-CLOSED branch (outcome=error)
        and propagate so the caller refuses the delete."""
        import asyncio
        owner_id = _create_user(db, email="auditerr@example.com")
        acct_id = _create_account(db, owner_id, ptype="imap")
        wm = app.state.watcher_manager

        import email_triage.db.accounts as _acc
        def _boom(conn, account_id, secrets=None):
            raise RuntimeError("purge backend down")
        monkeypatch.setattr(_acc, "purge_account_local_state", _boom)

        with pytest.raises(Exception):
            asyncio.run(wm.apply_account_deleted(acct_id, actor_user_id=owner_id))
        rows = db.execute(
            "SELECT outcome FROM hipaa_access_events "
            "WHERE account_id=? AND operation='account_purged'", (acct_id,)
        ).fetchall()
        assert rows and rows[-1]["outcome"] == "error"
