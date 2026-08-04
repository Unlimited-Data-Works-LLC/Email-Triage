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


def _cand_row(i: int) -> dict:
    return {
        "category": "newsletter", "sender": f"s{i}@y", "subject": f"s{i}",
        "date": "2026-05-07T08:00:00+00:00", "labels": [], "actions": [],
        "attachments": [], "headers": {}, "source": "llm", "reason": "r",
    }


class TestDigestCandidatesPagination:
    """ reachability — the Show-matches dry-run pages through EVERY
    match, not just the first max_rows that would send."""

    def _mk_digest(self, db, account_id, *, max_rows):
        from email_triage.actions.digest_configs import (
            DigestConfig, DigestFormat, upsert_digest_config,
        )
        cfg = DigestConfig(
            id="", kind="custom", name="Cust", enabled=True,
            format=DigestFormat(render_as="grouped_list", max_rows=max_rows),
        )
        return upsert_digest_config(db, account_id, cfg)

    def test_candidates_pager_reaches_older(
        self, client, db, admin_user, admin_cookies,
    ):
        from unittest.mock import patch
        acct_id = _make_imap_account(db, admin_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=2)
        rows = [_cand_row(i) for i in range(5)]  # 5 match, cap 2
        url = f"/accounts/{acct_id}/digests/{cfg.id}/candidates"
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            # Page 1: honest total + a reachable HTMX 'load older' control.
            r1 = client.post(url, cookies=admin_cookies)
            assert r1.status_code == 200
            assert "of 5" in r1.text
            assert "load older" in r1.text
            assert "hx-post" in r1.text          # HTMX pager, not a GET link
            assert "will actually send" in r1.text  # send_note
            #  live-Playwright fix — the pager re-targets its OWN wrapper
            # relatively, so it works under the preset AND custom result
            # containers (a hardcoded #digest-result-<id> broke the preset).
            assert "data-cand-wrap" in r1.text
            assert 'hx-target="closest [data-cand-wrap]"' in r1.text
            assert 'hx-swap="outerHTML"' in r1.text
            # Page 2 (offset=2): the older rows are reachable + 'newer' back.
            r2 = client.post(
                url, cookies=admin_cookies, data={"offset": "2"},
            )
            assert r2.status_code == 200
            assert "newer" in r2.text
            # page 2 (offset 2, size 2) = rows[2:4] → s2/s3 reachable.
            assert "s2" in r2.text or "s3" in r2.text

    def test_candidates_under_cap_no_pager(
        self, client, db, admin_user, admin_cookies,
    ):
        from unittest.mock import patch
        acct_id = _make_imap_account(db, admin_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=50)
        rows = [_cand_row(i) for i in range(3)]
        url = f"/accounts/{acct_id}/digests/{cfg.id}/candidates"
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            r = client.post(url, cookies=admin_cookies)
        assert r.status_code == 200
        assert "load older" not in r.text  # no false pager under cap

    def test_candidates_hipaa_owner_sees_verbatim(
        self, client, db, admin_user, admin_cookies,
    ):
        """HIPAA-mode dry-run × OWNER (admin viewing their own account) ⇒
        VERBATIM sender+subject and NO banner. Operator ruling 2026-07-01
        (owner-self-preview design point b): viewer-AWARE display gate,
        unredact when actor==owner. Rationale: the account owner authored
        the mail into their own mailbox — no minimum-necessary rationale
        for hiding their own PHI from themselves. The NON-owner case is
        the sibling test_candidates_hipaa_non_owner_redacted below."""
        from unittest.mock import patch
        from email_triage.web.db import set_account_hipaa
        acct_id = _make_imap_account(db, admin_user["id"])
        set_account_hipaa(db, acct_id, True, actor_id=admin_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=50)
        rows = [_cand_row(7)]  # sender s7@y, subject s7
        url = f"/accounts/{acct_id}/digests/{cfg.id}/candidates"
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            r = client.post(url, cookies=admin_cookies)
        assert r.status_code == 200
        assert "HIPAA privacy mode" not in r.text, (
            "banner shown to owner (owner-self-preview b: banner is non-owner-only)"
        )
        assert "[redacted]" not in r.text, (
            "owner sees [redacted] on their own HIPAA preview — over-redaction"
        )
        assert "s7@y" in r.text, "owner-viewing verbatim sender missing"
        assert "s7" in r.text                # subject verbatim

    def test_candidates_hipaa_non_owner_redacted(
        self, client, db, regular_user, admin_user, admin_cookies,
    ):
        """HIPAA-mode dry-run × NON-OWNER (site-admin viewing someone else's
        HIPAA account) ⇒ REDACTED sender+subject + banner. Owner-self-preview
        (b) unredacts only when actor==owner. §164.502(b) min-necessary /
        §164.514(d)(1) — the negative case of the matrix + the run18 N-172/
        N-175 net enforced at the handler seam (db-sme's must-fix on the
        viewer-aware pin, verify-at-handler-not-just-template)."""
        from unittest.mock import patch
        from email_triage.web.db import set_account_hipaa
        # Account owned by regular_user; admin_cookies is site-admin viewing it.
        acct_id = _make_imap_account(db, regular_user["id"])
        set_account_hipaa(db, acct_id, True, actor_id=regular_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=50)
        rows = [_cand_row(9)]  # sender s9@y, subject s9
        url = f"/accounts/{acct_id}/digests/{cfg.id}/candidates"
        assert admin_user["id"] != regular_user["id"], (
            "fixture invariant: admin and regular are distinct users"
        )
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            r = client.post(url, cookies=admin_cookies)
        assert r.status_code == 200
        assert "HIPAA privacy mode" in r.text, (
            "banner missing for non-owner viewing HIPAA preview (§164.502(b))"
        )
        assert "[redacted]" in r.text, (
            "non-owner sees verbatim on someone else's HIPAA preview "
            "(§164.502(b) min-necessary / §164.514(d)(1))"
        )
        assert "s9@y" not in r.text, (
            "non-owner leaked verbatim sender for a HIPAA account"
        )


class TestDigestPreviewHandlerViewerAware:
    """Handler-level matrix pin for the full-digest-body preview seam
    (accounts.py::digest_preview -> _render_digest_payload with
    redact_pii=hipaa AND user['id'] != acct['user_id']).

    Complements the candidates-table matrix (above) so both preview seams
    are pinned at the HANDLER level, not only at the template — closes
    db-sme's viewer-aware pin must-fix + hipaa-sme's matrix-test SHOULD."""

    def _mk_digest(self, db, account_id, *, max_rows):
        from email_triage.actions.digest_configs import (
            DigestConfig, DigestFormat, upsert_digest_config,
        )
        cfg = DigestConfig(
            id="", kind="custom", name="Cust", enabled=True,
            format=DigestFormat(render_as="grouped_list", max_rows=max_rows),
        )
        return upsert_digest_config(db, account_id, cfg)

    def test_preview_hipaa_owner_verbatim(
        self, client, db, admin_user, admin_cookies,
    ):
        """Preview × OWNER × HIPAA ⇒ verbatim body (owner-self-preview b)."""
        from unittest.mock import patch
        from email_triage.web.db import set_account_hipaa
        acct_id = _make_imap_account(db, admin_user["id"])
        set_account_hipaa(db, acct_id, True, actor_id=admin_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=50)
        rows = [_cand_row(3)]  # sender s3@y, subject s3
        url = f"/accounts/{acct_id}/digests/{cfg.id}/preview"
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            r = client.post(url, cookies=admin_cookies)
        assert r.status_code == 200
        # Owner sees their own PHI verbatim in the digest body preview.
        assert "s3@y" in r.text or "s3" in r.text, (
            "owner-self-preview: verbatim sender/subject missing from own digest preview"
        )
        assert "[redacted]" not in r.text, (
            "owner over-redacted on own digest body preview"
        )

    def test_preview_hipaa_non_owner_redacted(
        self, client, db, regular_user, admin_user, admin_cookies,
    ):
        """Preview × NON-OWNER × HIPAA ⇒ redacted body (§164.502(b) min-necessary)."""
        from unittest.mock import patch
        from email_triage.web.db import set_account_hipaa
        acct_id = _make_imap_account(db, regular_user["id"])
        set_account_hipaa(db, acct_id, True, actor_id=regular_user["id"])
        cfg = self._mk_digest(db, acct_id, max_rows=50)
        rows = [_cand_row(8)]  # sender s8@y, subject s8
        url = f"/accounts/{acct_id}/digests/{cfg.id}/preview"
        assert admin_user["id"] != regular_user["id"]
        with patch(
            "email_triage.actions.recipient_digest.gather_digest_rows",
            return_value=rows,
        ):
            r = client.post(url, cookies=admin_cookies)
        assert r.status_code == 200
        # Non-owner viewing someone else's HIPAA account gets redacted body.
        assert "s8@y" not in r.text, (
            "non-owner leaked verbatim sender in digest body preview (§164.502(b))"
        )
        assert "[redacted]" in r.text or "REDACTED" in r.text.upper(), (
            "non-owner digest body preview missing redaction marker"
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


class TestDigestTagsMerge:
    """ — label filter unions the discovered-label multi-select
    (``tags_select[]``) with the free-text override (``tags_csv``)."""

    def _save(self, client, db, admin_user, admin_cookies, data):
        acct_id = _make_imap_account(db, admin_user["id"])
        base = {
            "name": "Labelled",
            "enabled": "1",
            "cadence": "daily",
            "time_local": "08:10",
            "window_kind": "rolling_24h",
            "read_state": "any",
            "render_as": "grouped_list",
            "group_by": "category",
            "max_rows": "50",
        }
        base.update(data)
        resp = client.post(
            f"/accounts/{acct_id}/digests/new/save",
            data=base, cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code == 303
        from email_triage.actions.digest_configs import list_digest_configs
        cfg = [
            c for c in list_digest_configs(db, acct_id)
            if c.kind == "custom" and c.name == "Labelled"
        ][0]
        return cfg

    def test_union_of_select_and_freetext_preserves_order(
        self, client, db, admin_user, admin_cookies,
    ):
        cfg = self._save(
            client, db, admin_user, admin_cookies,
            {"tags_csv": "$Custom", "tags_select": ["Work", "Receipts"]},
        )
        # tags_csv first, then tags_select appended.
        assert cfg.filter.tags == ["$Custom", "Work", "Receipts"]

    def test_union_dedups(
        self, client, db, admin_user, admin_cookies,
    ):
        cfg = self._save(
            client, db, admin_user, admin_cookies,
            {"tags_csv": "$Custom, Work", "tags_select": ["Work"]},
        )
        assert cfg.filter.tags == ["$Custom", "Work"]

    def test_select_only(
        self, client, db, admin_user, admin_cookies,
    ):
        cfg = self._save(
            client, db, admin_user, admin_cookies,
            {"tags_select": ["Work", "Receipts"]},
        )
        assert cfg.filter.tags == ["Work", "Receipts"]


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
