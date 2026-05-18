"""HTTP-level tests for the additional-addresses UI (#106).

Covers the round-trip of POST /accounts/{id}/aliases/add and POST
/accounts/{id}/aliases/remove. The handlers re-render the
``accounts/_aliases.html`` partial back into the HTMX target, so each
test asserts both the storage write AND the rendered surface.
"""

from __future__ import annotations


def _create_imap_account(db, user_id: int, name: str = "Primary"):
    from email_triage.web.db import create_email_account
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.test", "port": 993, "username": "user@example.com"},
    )


class TestAddAlias:
    def test_round_trip_add_then_read(
        self, client, user_cookies, db, regular_user,
    ):
        aid = _create_imap_account(db, regular_user["id"])

        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": "Work"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Partial re-renders with the new entry visible.
        assert "alias1@example.com" in resp.text
        assert "Work" in resp.text

        # Storage actually got the value.
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert acct["aliases"] == [
            {"address": "alias1@example.com", "label": "Work"},
        ]

    def test_rejects_malformed_address_with_inline_error(
        self, client, user_cookies, db, regular_user,
    ):
        aid = _create_imap_account(db, regular_user["id"])

        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "not-an-email", "label": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Error renders inline.
        assert "doesn&#39;t look like" in resp.text or \
               "doesn't look like" in resp.text

        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert acct["aliases"] == []

    def test_rejects_primary_address_as_alias(
        self, client, user_cookies, db, regular_user,
    ):
        """The primary is implicit-included; storing it explicitly as
        an alias would double-count it in the union."""
        aid = _create_imap_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "user@example.com", "label": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Inline error.
        assert "main address" in resp.text

    def test_rejects_duplicate_alias(
        self, client, user_cookies, db, regular_user,
    ):
        """A second add of the same address (after a successful first
        add) re-renders with the duplicate error inline."""
        aid = _create_imap_account(db, regular_user["id"])
        client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": ""},
            cookies=user_cookies,
        )
        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "listed twice" in resp.text


class TestRemoveAlias:
    def test_remove_drops_only_target(
        self, client, user_cookies, db, regular_user,
    ):
        aid = _create_imap_account(db, regular_user["id"])
        # Seed two aliases.
        client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": "A"},
            cookies=user_cookies,
        )
        client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias2@example.org", "label": "B"},
            cookies=user_cookies,
        )

        resp = client.post(
            f"/accounts/{aid}/aliases/remove",
            data={"address": "alias1@example.com"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # The kept entry stays in the rendered partial.
        assert "alias2@example.org" in resp.text

        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert [e["address"] for e in acct["aliases"]] == [
            "alias2@example.org",
        ]

    def test_remove_unknown_alias_is_idempotent(
        self, client, user_cookies, db, regular_user,
    ):
        aid = _create_imap_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{aid}/aliases/remove",
            data={"address": "ghost@example.com"},
            cookies=user_cookies,
        )
        # No 5xx, just re-render of the (still empty) partial.
        assert resp.status_code == 200
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, aid)
        assert acct["aliases"] == []


class TestAuthGates:
    def test_other_user_cannot_add_alias(
        self, client, user_cookies, db, admin_user,
    ):
        """A non-admin, non-delegate user can't manage someone else's
        account aliases. ``can_manage_account`` returns False ->
        403."""
        aid = _create_imap_account(db, admin_user["id"], name="Admin's")
        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_add_alias(self, client, db, regular_user):
        aid = _create_imap_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{aid}/aliases/add",
            data={"address": "alias1@example.com", "label": ""},
        )
        assert resp.status_code in (401, 303)


class TestEditPageRendersSection:
    def test_edit_page_includes_additional_addresses(
        self, client, user_cookies, db, regular_user,
    ):
        """The /accounts/{id}/edit page must surface the new section
        so operators can find + use it without prior knowledge."""
        aid = _create_imap_account(db, regular_user["id"])
        resp = client.get(
            f"/accounts/{aid}/edit",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Additional addresses" in resp.text
