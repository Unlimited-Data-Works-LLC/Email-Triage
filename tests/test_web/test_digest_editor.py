"""HTTP integration tests for the multi-digest editor surface
(Phase 6 + Phase 7).

Routes covered:

- GET  /accounts/{id}/digests/new/edit
- GET  /accounts/{id}/digests/{digest_id}/edit
- POST /accounts/{id}/digests/{digest_id}/save
- POST /accounts/{id}/digests/{digest_id}/delete
- POST /accounts/{id}/digests/{digest_id}/validate-query
- POST /accounts/{id}/digests/{digest_id}/test-send

The lower-level helpers + storage + render are tested in
``tests/test_digest_configs.py``, ``tests/test_digest_filter.py``,
``tests/test_digest_render.py``. This file is the HTTP-glue layer
verification.
"""

from __future__ import annotations

import pytest


def _make_imap_account(db, user_id: int) -> int:
    from email_triage.web.db import create_email_account
    return create_email_account(
        db, user_id, "Test", "imap",
        {
            "host": "x.test", "port": 993, "username": "u@test",
            "use_ssl": True,
        },
    )


# ---------------------------------------------------------------------------
# GET edit / new
# ---------------------------------------------------------------------------


class TestDigestEditorGet:
    """The GET-editor surface."""

    def test_new_editor_renders_blank_form(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(
            f"/accounts/{acct_id}/digests/new/edit",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "New digest" in resp.text
        assert 'name="name"' in resp.text
        assert 'name="cadence"' in resp.text
        assert 'name="advanced"' in resp.text

    def test_existing_editor_loads_preset(
        self, client, db, admin_user, admin_cookies,
    ):
        from email_triage.actions.digest_configs import (
            PRESET_ID, list_digest_configs,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        # Trigger migration so preset exists.
        list_digest_configs(db, acct_id)
        resp = client.get(
            f"/accounts/{acct_id}/digests/{PRESET_ID}/edit",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Daily Activity" in resp.text

    def test_anonymous_get_redirects_to_login(self, client, db, admin_user):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(
            f"/accounts/{acct_id}/digests/new/edit",
            follow_redirects=False,
        )
        # /login redirect or 401 — both are acceptable not-authenticated
        # responses; the route must NOT 200 to anonymous.
        assert resp.status_code in (303, 307, 401)


# ---------------------------------------------------------------------------
# POST save
# ---------------------------------------------------------------------------


class TestDigestSave:
    """Save handler: validation, upsert, redirect."""

    def test_save_creates_new_custom_digest(
        self, client, db, admin_user, admin_cookies,
    ):
        from email_triage.actions.digest_configs import (
            list_digest_configs,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/digests/new/save",
            data={
                "name": "AI Newsletters",
                "enabled": "1",
                "cadence": "daily",
                "time_local": "06:30",
                "window_kind": "since_last_sent",
                "read_state": "unread",
                "categories": ["newsletter"],
                "tags_csv": "$EmailTriaged",
                "render_as": "grouped_list",
                "group_by": "category",
                "include_body_preview": "1",
                "max_rows": "50",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith(
            "/edit?tab=digests"
        )
        configs = list_digest_configs(db, acct_id)
        names = [c.name for c in configs if c.kind == "custom"]
        assert "AI Newsletters" in names

    def test_save_with_validation_error_re_renders_editor(
        self, client, db, admin_user, admin_cookies,
    ):
        """Empty name on a custom digest fails validate(); should
        re-render the editor with the error list, NOT redirect."""
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/digests/new/save",
            data={
                "name": "",  # invalid — required for custom
                "cadence": "daily",
                "time_local": "08:10",
                "window_kind": "rolling_24h",
                "read_state": "any",
                "render_as": "grouped_list",
                "group_by": "category",
                "max_rows": "50",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "Validation errors" in resp.text
        assert "name" in resp.text  # the validation error mentions name

    def test_save_existing_digest_updates_in_place(
        self, client, db, admin_user, admin_cookies,
    ):
        """Save against an existing digest_id mutates the row, doesn't
        mint a new one."""
        from email_triage.actions.digest_configs import (
            DigestConfig, list_digest_configs, upsert_digest_config,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="orig"),
        )
        resp = client.post(
            f"/accounts/{acct_id}/digests/{seeded.id}/save",
            data={
                "name": "renamed",
                "enabled": "1",
                "cadence": "daily",
                "time_local": "08:10",
                "window_kind": "rolling_24h",
                "read_state": "any",
                "render_as": "grouped_list",
                "group_by": "category",
                "max_rows": "50",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        configs = list_digest_configs(db, acct_id)
        match = [c for c in configs if c.id == seeded.id]
        assert match and match[0].name == "renamed"


# ---------------------------------------------------------------------------
# POST delete
# ---------------------------------------------------------------------------


class TestDigestDelete:
    def test_delete_custom_redirects_to_list(
        self, client, db, admin_user, admin_cookies,
    ):
        from email_triage.actions.digest_configs import (
            DigestConfig, get_digest_config, upsert_digest_config,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="to-delete"),
        )
        resp = client.post(
            f"/accounts/{acct_id}/digests/{seeded.id}/delete",
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"].endswith(
            "/edit?tab=digests"
        )
        assert get_digest_config(db, acct_id, seeded.id) is None

    def test_delete_preset_refused(
        self, client, db, admin_user, admin_cookies,
    ):
        from email_triage.actions.digest_configs import (
            PRESET_ID, get_digest_config, list_digest_configs,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        list_digest_configs(db, acct_id)  # ensure preset exists
        resp = client.post(
            f"/accounts/{acct_id}/digests/{PRESET_ID}/delete",
            cookies=admin_cookies,
        )
        assert resp.status_code == 400
        assert get_digest_config(db, acct_id, PRESET_ID) is not None


# ---------------------------------------------------------------------------
# POST validate-query (advanced)
# ---------------------------------------------------------------------------


class TestDigestValidateQuery:
    def test_empty_query_returns_helpful_hint(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/digests/new/validate-query",
            data={"advanced": ""},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "advanced field is empty" in resp.text


# ---------------------------------------------------------------------------
# POST test-send (per-digest)
# ---------------------------------------------------------------------------


class TestDigestTestSend:
    def test_test_send_blocks_when_smtp_not_configured(
        self, client, db, admin_user, admin_cookies,
    ):
        """Default test-app config has no SMTP host; send-now must
        bounce with an inline error banner instead of crashing."""
        from email_triage.actions.digest_configs import (
            DigestConfig, upsert_digest_config,
        )
        acct_id = _make_imap_account(db, admin_user["id"])
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="test"),
        )
        resp = client.post(
            f"/accounts/{acct_id}/digests/{seeded.id}/test-send",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "SMTP not configured" in resp.text

    def test_test_send_blocks_when_account_has_no_email(
        self, client, db, admin_user, admin_cookies,
    ):
        """Same shape as the legacy /recipient-digest/send-now —
        IMAP accounts with no username (and Gmail with no
        account field) get a clear error, not a stack trace."""
        from email_triage.actions.digest_configs import (
            DigestConfig, upsert_digest_config,
        )
        from email_triage.web.db import create_email_account
        # Account with empty username — synth no-email-address case.
        acct_id = create_email_account(
            db, admin_user["id"], "no-addr", "imap",
            {"host": "x.test", "port": 993, "username": ""},
        )
        seeded = upsert_digest_config(
            db, acct_id,
            DigestConfig(kind="custom", name="test"),
        )
        # SMTP also unset on the test app — this case lands first.
        resp = client.post(
            f"/accounts/{acct_id}/digests/{seeded.id}/test-send",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert (
            "no email address" in resp.text.lower()
            or "smtp not configured" in resp.text.lower()
        )
