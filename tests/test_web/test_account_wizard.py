"""Tests for the #95 sub-A account-setup wizard.

Five-step flow at /accounts/new?step=N. Each step's GET renders the
matching template; each step's POST handler does its work and 303s
to the next step.

Coverage:
- Step 1 GET renders the form (anonymous → 303 to /login).
- Step 1 POST creates the account row + redirects to step 2.
- Step 2 GET renders provider-specific form (IMAP creds /
  Gmail OAuth button / O365 creds).
- Step 2-imap POST persists creds + redirects to step 3.
- Step 3 GET renders push/poll knobs.
- Step 3 POST persists config + auto-starts watcher (best-effort).
- Step 4 GET shows copy-from-other-account radios when other
  accounts exist.
- Step 4 POST copies routes when requested; skips on "fresh".
- Step 5 GET renders digest + escalation form.
- Step 5 POST persists prefs + redirects to /dashboard.
- can_manage_account gate: cross-user account_id is rejected.
"""

from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Step 1
# ---------------------------------------------------------------------------


class TestWizardStep1:
    def test_get_renders_form(self, client, regular_user, user_cookies):
        r = client.get("/accounts/new", cookies=user_cookies)
        assert r.status_code == 200
        assert 'name="name"' in r.text
        assert 'name="provider_type"' in r.text
        assert "Step 1 of 5" in r.text

    def test_get_anonymous_redirects(self, client):
        r = client.get("/accounts/new", follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_post_creates_account_redirects_to_step2(
        self, client, regular_user, user_cookies, db,
    ):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "Test IMAP", "provider_type": "imap"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "step=2" in loc
        assert "account_id=" in loc

        # Account row created.
        rows = db.execute(
            "SELECT id, name, provider_type, user_id "
            "FROM email_accounts WHERE name = 'Test IMAP'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["provider_type"] == "imap"
        assert rows[0]["user_id"] == regular_user["id"]

    def test_post_missing_name_re_renders_with_error(
        self, client, regular_user, user_cookies,
    ):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "", "provider_type": "imap"},
            cookies=user_cookies,
        )
        # Re-render returns 200 with error banner.
        assert r.status_code == 200
        assert "required" in r.text.lower() or "Account name is required" in r.text


# ---------------------------------------------------------------------------
# Step 2 — IMAP
# ---------------------------------------------------------------------------


class TestWizardStep2Imap:
    def _create(self, client, user_cookies, ptype="imap"):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "T", "provider_type": ptype},
            cookies=user_cookies,
            follow_redirects=False,
        )
        loc = r.headers.get("location", "")
        # Parse account_id from redirect URL.
        import re
        m = re.search(r"account_id=(\d+)", loc)
        return int(m.group(1)) if m else 0

    def test_get_renders_imap_form(self, client, regular_user, user_cookies):
        aid = self._create(client, user_cookies, "imap")
        r = client.get(
            f"/accounts/new?step=2&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert 'name="host"' in r.text
        assert 'name="username"' in r.text
        assert 'name="password"' in r.text

    def test_post_persists_creds_redirects_step3(
        self, client, regular_user, user_cookies, db,
    ):
        aid = self._create(client, user_cookies, "imap")
        r = client.post(
            "/accounts/new/step2-imap",
            data={
                "account_id": str(aid),
                "host": "imap.example.com",
                "port": "993",
                "username": "u@example.com",
                "password": "secret",
                "use_ssl": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert f"step=3&account_id={aid}" in r.headers.get("location", "")

        # Config persisted.
        row = db.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()
        cfg = json.loads(row["config_json"])
        assert cfg["host"] == "imap.example.com"
        assert cfg["username"] == "u@example.com"
        assert cfg["use_ssl"] is True

    def test_cross_user_account_rejected(
        self, client, regular_user, admin_user, user_cookies, db,
    ):
        # Admin creates an account.
        from datetime import datetime, timezone
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, 'AdminAcct', 'imap', '{}', ?, ?)",
            (admin_user["id"],
             datetime.now(timezone.utc).isoformat(),
             datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
        admin_acct_id = cur.lastrowid

        # Regular user tries to advance the wizard against admin's
        # account_id. Should redirect back to step 1.
        r = client.post(
            "/accounts/new/step2-imap",
            data={
                "account_id": str(admin_acct_id),
                "host": "h", "port": "993",
                "username": "u", "password": "p",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "step=1" in r.headers.get("location", "")


# ---------------------------------------------------------------------------
# Step 3 — push/poll
# ---------------------------------------------------------------------------


class TestWizardStep3:
    def _build_acct(self, db, user_id, ptype="imap"):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, 'StepThree', ?, '{}', ?, ?)",
            (user_id, ptype, now, now),
        )
        db.commit()
        return cur.lastrowid

    def test_get_renders(self, client, regular_user, user_cookies, db):
        aid = self._build_acct(db, regular_user["id"])
        r = client.get(
            f"/accounts/new?step=3&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert 'name="push_enabled"' in r.text
        assert 'name="poll_enabled"' in r.text

    def test_post_persists_redirects_step4(
        self, client, regular_user, user_cookies, db,
    ):
        aid = self._build_acct(db, regular_user["id"])
        r = client.post(
            "/accounts/new/step3",
            data={
                "account_id": str(aid),
                "push_enabled": "1",
                "poll_enabled": "1",
                "poll_interval_minutes": "60",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert f"step=4&account_id={aid}" in r.headers.get("location", "")

        cfg = json.loads(db.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()["config_json"])
        assert cfg["push_enabled"] is True
        assert cfg["poll_enabled"] is True
        assert cfg["poll_interval_minutes"] == 60


# ---------------------------------------------------------------------------
# Step 4 — categories / routes
# ---------------------------------------------------------------------------


class TestWizardStep4:
    def _build_acct(self, db, user_id, name="StepFour"):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, ?, 'imap', '{}', ?, ?)",
            (user_id, name, now, now),
        )
        db.commit()
        return cur.lastrowid

    def test_get_no_other_accounts(
        self, client, regular_user, user_cookies, db,
    ):
        aid = self._build_acct(db, regular_user["id"])
        # With no other accounts AND no personal categories, the
        # step-4 skip heuristic fires and we 303 through to step 5.
        # See test_account_wizard_autochain.py for the explicit
        # skip-step coverage; here we just verify the redirect-or-
        # render contract: either way the operator never lands on
        # a step 4 with no choices to make.
        r = client.get(
            f"/accounts/new?step=4&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code in (200, 303)
        if r.status_code == 200:
            # Pre-skip behaviour: hidden fresh field rendered.
            assert 'value="fresh"' in r.text
        else:
            # Post-skip behaviour: redirect lands on step 5.
            assert "step=5" in r.headers.get("location", "")

    def test_post_fresh_redirects_step5(
        self, client, regular_user, user_cookies, db,
    ):
        aid = self._build_acct(db, regular_user["id"])
        r = client.post(
            "/accounts/new/step4",
            data={"account_id": str(aid), "route_source": "fresh"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert f"step=5&account_id={aid}" in r.headers.get("location", "")


# ---------------------------------------------------------------------------
# Step 5 — finish
# ---------------------------------------------------------------------------


class TestWizardStep5:
    def _build_acct(self, db, user_id):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, updated_at) "
            "VALUES (?, 'StepFive', 'imap', '{}', ?, ?)",
            (user_id, now, now),
        )
        db.commit()
        return cur.lastrowid

    def test_get_renders(self, client, regular_user, user_cookies, db):
        aid = self._build_acct(db, regular_user["id"])
        r = client.get(
            f"/accounts/new?step=5&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert 'name="recipient_digest_enabled"' in r.text

    def test_post_persists_redirects_accounts(
        self, client, regular_user, user_cookies, db,
    ):
        aid = self._build_acct(db, regular_user["id"])
        r = client.post(
            "/accounts/new/step5",
            data={
                "account_id": str(aid),
                "recipient_digest_enabled": "1",
                "recipient_digest_send_at": "07:10",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        # Wizard completion lands on /accounts with a success banner;
        # changed from /dashboard?wizard=done in the auto-chain pass.
        assert loc.startswith("/accounts?success=")

        cfg = json.loads(db.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()["config_json"])
        assert cfg["recipient_digest_enabled"] is True
        assert cfg["recipient_digest_send_at"] == "07:10"


# ---------------------------------------------------------------------------
# #120 — accounts disabled until wizard completes
# ---------------------------------------------------------------------------


class TestWizardDisabledUntilDone:
    """Item #120: new-account wizard creates rows with is_active=0
    so background pollers/watchers don't fire on the half-configured
    stub. Step-5 finish flips to is_active=1.
    """

    def test_step1_creates_account_disabled(
        self, client, regular_user, user_cookies, db,
    ):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "Disabled-on-create", "provider_type": "imap"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        row = db.execute(
            "SELECT is_active FROM email_accounts "
            "WHERE name = 'Disabled-on-create'"
        ).fetchone()
        assert row is not None
        # is_active = 0 — wizard step 1 stub does not get polled
        # until step 5 finishes.
        assert int(row["is_active"]) == 0

    def test_step5_flips_account_active(
        self, client, regular_user, user_cookies, db,
    ):
        # Build the account in the disabled state the wizard now
        # produces. Step 5 finish should flip is_active to 1.
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            " is_active, created_at, updated_at) "
            "VALUES (?, 'Step5Flip', 'imap', '{}', 0, ?, ?)",
            (regular_user["id"], now, now),
        )
        db.commit()
        aid = cur.lastrowid

        r = client.post(
            "/accounts/new/step5",
            data={
                "account_id": str(aid),
                "recipient_digest_enabled": "1",
                "recipient_digest_send_at": "08:10",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        row = db.execute(
            "SELECT is_active FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()
        assert int(row["is_active"]) == 1

    def test_manual_add_path_stays_active_by_default(self, db, regular_user):
        """Direct DB-helper smoke: manual-add (non-wizard) callers
        get is_active=True without explicitly passing the kwarg.
        Item #120 only changes the wizard path; full-form callers
        keep working as before."""
        from email_triage.web.db import create_email_account
        aid = create_email_account(
            db, regular_user["id"],
            "Manual-defaults-active", "imap", {"host": "example.com"},
            hipaa=False,
        )
        row = db.execute(
            "SELECT is_active FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()
        assert int(row["is_active"]) == 1

    def test_set_account_active_helper_flips_flag(
        self, db, regular_user,
    ):
        """``set_account_active`` flips ``is_active`` without touching
        name / provider_type / config (vs ``update_email_account``
        which requires all three)."""
        from email_triage.web.db import create_email_account, set_account_active
        aid = create_email_account(
            db, regular_user["id"],
            "FlipTarget", "imap", {"host": "h.example.com"},
            hipaa=False, is_active=False,
        )
        # Off → on
        assert set_account_active(db, aid, True) is True
        row = db.execute(
            "SELECT is_active, name, provider_type FROM email_accounts "
            "WHERE id = ?",
            (aid,),
        ).fetchone()
        assert int(row["is_active"]) == 1
        # Other fields untouched
        assert row["name"] == "FlipTarget"
        assert row["provider_type"] == "imap"
        # On → off
        assert set_account_active(db, aid, False) is True
        row = db.execute(
            "SELECT is_active FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()
        assert int(row["is_active"]) == 0

    def test_set_account_active_unknown_id_returns_false(self, db):
        from email_triage.web.db import set_account_active
        # Non-existent account → no rows updated.
        assert set_account_active(db, 99_999, True) is False

    def test_edit_page_disabled_banner_copy(
        self, client, regular_user, user_cookies, db,
    ):
        """Disabled (is_active=0) + wizard mid-flow → stronger
        "Setup not finished — paused" banner copy. Active + wizard
        mid-flow → existing "Pick up where you left off" copy."""
        from datetime import datetime, timezone
        from email_triage.web.db import set_setting
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            " is_active, created_at, updated_at) "
            "VALUES (?, 'BannerCheck', 'imap', '{}', 0, ?, ?)",
            (regular_user["id"], now, now),
        )
        db.commit()
        aid = cur.lastrowid
        # Stamp wizard mid-flow marker so the banner fires.
        set_setting(db, f"account_state:{aid}:wizard_step", {"step": 3})
        r = client.get(
            f"/accounts/{aid}/edit",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        # Disabled-account copy variants present.
        assert "Setup not finished" in r.text
        assert "this account is paused" in r.text
        # Existing-active copy NOT present in the disabled branch.
        assert "Pick up where you left off:" not in r.text
