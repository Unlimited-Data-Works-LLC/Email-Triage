"""Tests for  — per-account delegation."""

from email_triage.web.db import (
    add_account_delegate,
    can_administer_account,
    can_manage_account,
    create_email_account,
    is_account_delegate,
    list_account_delegates,
    list_email_accounts,
    remove_account_delegate,
)


class TestDelegateHelpers:
    def test_add_then_check_returns_true(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ADMIN_OWNS", "imap", {"host": "x.invalid"},
        )
        assert is_account_delegate(db, a, regular_user["id"]) is False
        added = add_account_delegate(
            db, a, regular_user["id"], granted_by=admin_user["id"],
        )
        assert added is True
        assert is_account_delegate(db, a, regular_user["id"]) is True

    def test_add_idempotent(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        first = add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        second = add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        assert first is True
        assert second is False

    def test_owner_cannot_be_own_delegate(self, db, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        # Punch 673: a witnessed refusal (falsy GrantRefused), not a raise.
        from email_triage.db.audit import DELEGATE_IS_OWNER, GrantRefused
        got = add_account_delegate(db, a, admin_user["id"], admin_user["id"])
        assert isinstance(got, GrantRefused) and got == DELEGATE_IS_OWNER
        assert is_account_delegate(db, a, admin_user["id"]) is False

    def test_remove(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        assert remove_account_delegate(db, a, regular_user["id"], revoked_by=admin_user["id"]) is True
        assert is_account_delegate(db, a, regular_user["id"]) is False

    def test_remove_returns_false_when_absent(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        assert remove_account_delegate(db, a, regular_user["id"], revoked_by=admin_user["id"]) is False

    def test_list_includes_email_and_grantor(
        self, db, regular_user, admin_user,
    ):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        rows = list_account_delegates(db, a)
        assert len(rows) == 1
        assert rows[0]["email"] == regular_user["email"]
        assert rows[0]["granted_by"] == admin_user["id"]
        assert rows[0]["granted_by_email"] == admin_user["email"]


class TestCanManageAccount:
    def test_admin_yes(self, db, admin_user, regular_user):
        a = create_email_account(
            db, regular_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": regular_user["id"]}
        assert can_manage_account(db, admin_user, acct) is True

    def test_owner_yes(self, db, regular_user):
        a = create_email_account(
            db, regular_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": regular_user["id"]}
        assert can_manage_account(db, regular_user, acct) is True

    def test_delegate_yes(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        acct = {"id": a, "user_id": admin_user["id"]}
        assert can_manage_account(db, regular_user, acct) is True

    def test_stranger_no(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": admin_user["id"]}
        assert can_manage_account(db, regular_user, acct) is False

    def test_revoked_delegate_no(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        remove_account_delegate(db, a, regular_user["id"], revoked_by=admin_user["id"])
        acct = {"id": a, "user_id": admin_user["id"]}
        assert can_manage_account(db, regular_user, acct) is False

    def test_none_user_no(self, db):
        assert can_manage_account(db, None, {"id": 1, "user_id": 1}) is False

    def test_none_acct_no(self, db, regular_user):
        assert can_manage_account(db, regular_user, None) is False


class TestCanAdministerAccount:
    """can_administer_account is STRICTLY STRONGER than can_manage_account:
    admin/owner YES, but a DELEGATE is NOT an administrator (the no-delegate
    sensitive-op gate — divergence census 2026-06-11, batch 4). The contrast
    with TestCanManageAccount::test_delegate_yes is the whole point."""

    def test_admin_yes(self, db, admin_user, regular_user):
        a = create_email_account(
            db, regular_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": regular_user["id"]}
        assert can_administer_account(db, admin_user, acct) is True

    def test_owner_yes(self, db, regular_user):
        a = create_email_account(
            db, regular_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": regular_user["id"]}
        assert can_administer_account(db, regular_user, acct) is True

    def test_delegate_NO(self, db, regular_user, admin_user):
        """The security-critical case: a delegate CAN manage but CANNOT
        administer — so the SAME (account, delegate) pair that is True for
        can_manage_account is False here."""
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        acct = {"id": a, "user_id": admin_user["id"]}
        assert can_manage_account(db, regular_user, acct) is True   # contrast
        assert can_administer_account(db, regular_user, acct) is False

    def test_stranger_no(self, db, regular_user, admin_user):
        a = create_email_account(
            db, admin_user["id"], "ACCT", "imap", {"host": "x.invalid"},
        )
        acct = {"id": a, "user_id": admin_user["id"]}
        assert can_administer_account(db, regular_user, acct) is False

    def test_none_user_no(self, db):
        assert can_administer_account(db, None, {"id": 1, "user_id": 1}) is False

    def test_none_acct_no(self, db, regular_user):
        assert can_administer_account(db, regular_user, None) is False


class TestListAccountsIncludesDelegated:
    def test_owned_only_when_no_delegations(self, db, regular_user):
        a = create_email_account(
            db, regular_user["id"], "MINE", "imap", {"host": "x.invalid"},
        )
        accts = list_email_accounts(db, user_id=regular_user["id"])
        assert len(accts) == 1
        assert accts[0]["id"] == a
        assert accts[0]["is_delegate"] == 0

    def test_owned_plus_delegated(self, db, regular_user, admin_user):
        owned = create_email_account(
            db, regular_user["id"], "MINE", "imap", {"host": "x.invalid"},
        )
        admin_owned = create_email_account(
            db, admin_user["id"], "ADMIN_OWNED", "imap", {"host": "y.invalid"},
        )
        add_account_delegate(
            db, admin_owned, regular_user["id"], admin_user["id"],
        )
        accts = list_email_accounts(db, user_id=regular_user["id"])
        ids = {a["id"]: a["is_delegate"] for a in accts}
        assert ids[owned] == 0
        assert ids[admin_owned] == 1

    def test_include_delegated_false_excludes(self, db, regular_user, admin_user):
        admin_owned = create_email_account(
            db, admin_user["id"], "ADMIN_OWNED", "imap", {"host": "y.invalid"},
        )
        add_account_delegate(
            db, admin_owned, regular_user["id"], admin_user["id"],
        )
        accts = list_email_accounts(
            db, user_id=regular_user["id"], include_delegated=False,
        )
        ids = [a["id"] for a in accts]
        assert admin_owned not in ids


class TestRouteAuthz:
    def test_delegate_can_view_edit_form(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        a = create_email_account(
            db, admin_user["id"], "DELEGATED", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(
            db, a, regular_user["id"], admin_user["id"],
        )
        resp = client.get(
            f"/accounts/{a}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200

    def test_stranger_cannot_view_edit_form(
        self, client, user_cookies, db, admin_user,
    ):
        a = create_email_account(
            db, admin_user["id"], "FOREIGN", "imap", {"host": "x.invalid"},
        )
        resp = client.get(
            f"/accounts/{a}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_delegate_cannot_delete(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        a = create_email_account(
            db, admin_user["id"], "DELEGATED", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(
            db, a, regular_user["id"], admin_user["id"],
        )
        resp = client.delete(
            f"/accounts/{a}", cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_delegate_cannot_revoke_delegate(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        """batch-4 edge: a delegate must NOT revoke delegation (the revoke
        route is owner-or-admin only — can_administer_account). A delegate
        trying to revoke even their OWN delegate row gets 403 and the row
        survives. (Complements the existing test_delegate_cannot_grant_further;
        delete is covered by test_delegate_cannot_delete.)"""
        a = create_email_account(
            db, admin_user["id"], "DELEGATED", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        resp = client.delete(
            f"/accounts/{a}/delegates/{regular_user['id']}",
            cookies=user_cookies,
        )
        assert resp.status_code == 403
        assert is_account_delegate(db, a, regular_user["id"]) is True

    def test_delegate_cannot_flip_hipaa_via_edit_form(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        """batch-4 edge — the highest-stakes op AND the most fragile: the
        HIPAA-flag flip is a 200-returning SUB-BLOCK of the edit save (not a
        dedicated 403 route), so its delegate-denial has no 403 to assert.
        A delegate FORGING ``hipaa_submitted`` in the PUT must NOT flip the
        flag — the save still applies for fields a delegate may edit (200),
        but can_administer_account gates the flag itself. (N-57: the
        structural reference pin needs this behavioural edge test.)"""
        from email_triage.web.db import get_email_account
        a = create_email_account(
            db, admin_user["id"], "DELEGATED", "imap",
            {"host": "old.invalid", "username": "u@old.com", "mailbox": "INBOX"},
        )
        add_account_delegate(db, a, regular_user["id"], admin_user["id"])
        assert bool(get_email_account(db, a)["hipaa"]) is False  # starts OFF

        resp = client.put(f"/accounts/{a}", data={
            "name": "DELEGATED",
            "provider_type": "imap",
            "host": "old.invalid",
            "port": "993",
            "username": "u@old.com",
            "mailbox": "INBOX",
            "use_ssl": "1",
            "is_active": "1",
            "hipaa_submitted": "1",
            "hipaa": "1",          # delegate tries to flip the flag ON
        }, cookies=user_cookies)

        assert resp.status_code == 200
        assert bool(get_email_account(db, a)["hipaa"]) is False, (
            "a delegate must NOT be able to flip the HIPAA flag via the edit "
            "form (can_administer_account is the no-delegate gate)"
        )


class TestDelegateGrantUI:
    def test_owner_can_add_delegate(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        a = create_email_account(
            db, admin_user["id"], "OWNED", "imap", {"host": "x.invalid"},
        )
        resp = client.post(
            f"/accounts/{a}/delegates/add",
            data={"user_email": regular_user["email"]},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert is_account_delegate(db, a, regular_user["id"]) is True

    def test_admin_grant_via_user_id(
        self, client, admin_cookies, db, admin_user, regular_user,
    ):
        """Admin dropdown posts user_id; server resolves to the user."""
        a = create_email_account(
            db, admin_user["id"], "OWNED", "imap", {"host": "x.invalid"},
        )
        resp = client.post(
            f"/accounts/{a}/delegates/add",
            data={"user_id": str(regular_user["id"])},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert is_account_delegate(db, a, regular_user["id"]) is True

    def test_admin_dropdown_renders_in_form(
        self, client, admin_cookies, db, admin_user,
    ):
        """The edit page shows a <select name='user_id'> for admins."""
        a = create_email_account(
            db, admin_user["id"], "ADMIN_OWNED", "imap", {"host": "x.invalid"},
        )
        resp = client.get(f"/accounts/{a}/edit", cookies=admin_cookies)
        assert resp.status_code == 200
        # Dropdown is rendered for admin.
        assert 'name="user_id"' in resp.text

    def test_owner_form_shows_email_input(
        self, client, user_cookies, db, regular_user,
    ):
        """Non-admin owner sees the free-text email input, no dropdown."""
        a = create_email_account(
            db, regular_user["id"], "OWNED", "imap", {"host": "x.invalid"},
        )
        resp = client.get(f"/accounts/{a}/edit", cookies=user_cookies)
        assert resp.status_code == 200
        # Free-text input renders, dropdown does NOT.
        assert 'name="user_email"' in resp.text
        assert 'name="user_id"' not in resp.text

    def test_delegate_cannot_grant_further(
        self, client, user_cookies, db, regular_user, admin_user,
    ):
        # Set up: regular_user is a delegate of ADMIN_OWNED.
        a = create_email_account(
            db, admin_user["id"], "ADMIN_OWNED", "imap", {"host": "x.invalid"},
        )
        add_account_delegate(
            db, a, regular_user["id"], admin_user["id"],
        )
        # regular_user tries to grant further delegation to admin.
        resp = client.post(
            f"/accounts/{a}/delegates/add",
            data={"user_email": admin_user["email"]},
            cookies=user_cookies,
        )
        assert resp.status_code == 403
