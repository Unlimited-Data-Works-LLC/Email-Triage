"""Tests for #126 — easier O365 config flow / UX.

Covers three sub-items shipped in the same commit:

1. ``POST /accounts/{id}/o365/probe`` — pre-flight verifier that
   calls Microsoft Graph's ``/me`` endpoint with the saved tenant +
   client + secret combo and returns a green / red chip. Includes
   the AADSTS-prefixed error translator (``_aadsts_translate``)
   exercised directly + via the round-trip endpoint.

2. ``accounts/_o365_fields.html`` — shared field-block partial
   included by both the wizard step2-o365 form and the edit-page
   Integrations / Provider tab. Covers the inline numbered "How do
   I find these values?" guidance + tooltip example values.

3. AUDIENCE comment header present on the touched templates.

The Graph layer is patched at the provider so the suite never
reaches the real Microsoft service. Fixture pattern mirrors
``tests/test_web/test_o365_push_ui.py`` — same ``_seed_o365_account``
helper, same MSAL-availability shim.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.routers.ui import (
    _AADSTS_TRANSLATIONS,
    _aadsts_translate,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers — mirror tests/test_web/test_o365_push_ui.py.
# ---------------------------------------------------------------------------


def _seed_o365_account(db, *, user_id: int, name: str = "acct1") -> int:
    """Insert a minimal email_accounts row tagged provider_type='office365'.

    Mirrors the fixture in test_o365_push_ui.py — same shape so the
    probe and push tests share an account schema.
    """
    now = datetime.now(timezone.utc).isoformat()
    cfg = {
        "client_id": "test-client-id",
        "tenant_id": "common",
        "account": "user@example.com",
    }
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "office365", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


def _seed_gmail_account(db, *, user_id: int, name: str = "g-acct") -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "gmail_api",
            '{"account": "user@example.com"}', now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def force_msal_present():
    """Patch ``HAS_MSAL=True`` on the office365 provider module so the
    constructor doesn't bail in CI. Mirrors test_o365_push_ui.py."""
    from email_triage.providers import office365 as o365_mod

    original = getattr(o365_mod, "HAS_MSAL", False)
    o365_mod.HAS_MSAL = True
    try:
        yield
    finally:
        o365_mod.HAS_MSAL = original


# ---------------------------------------------------------------------------
# AADSTS translator — unit tests on the helper directly.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("aadsts_code", sorted(_AADSTS_TRANSLATIONS.keys()))
def test_aadsts_translate_known_code_returns_translation(aadsts_code):
    """Each AADSTS code in our table maps to its translated one-liner.

    The error_description Microsoft returns embeds the code in the
    body (``AADSTS65001: ...``). The translator must extract the
    code, look it up, and return the English sentence — not the bare
    code as the headline (per audience rule for end-user copy).
    """
    fake_err = (
        f"{aadsts_code}: The user or admin has not consented "
        f"to use the application with ID 'foo' named 'bar'."
    )
    code, msg = _aadsts_translate(fake_err)
    assert code == aadsts_code
    assert msg == _AADSTS_TRANSLATIONS[aadsts_code]
    # Translated message must NOT lead with the bare code (rule:
    # never surface AADSTS<n> as the operator-facing headline).
    assert not msg.startswith("AADSTS")


def test_aadsts_translate_unknown_code_falls_back_to_verbatim():
    """An AADSTS code we don't have a translation for still has its
    code returned (riding-along reference) but the message is the
    verbatim Graph error text (no fabricated translation)."""
    err = "AADSTS999999: Made-up error for testing."
    code, msg = _aadsts_translate(err)
    assert code == "AADSTS999999"
    assert "Made-up error for testing" in msg


def test_aadsts_translate_no_aadsts_returns_verbatim():
    """Non-AADSTS errors come through verbatim with code=None."""
    err = "Connection reset by peer."
    code, msg = _aadsts_translate(err)
    assert code is None
    assert msg == "Connection reset by peer."


def test_aadsts_translate_empty_input_handled():
    code, msg = _aadsts_translate("")
    assert code is None
    assert "Microsoft" in msg


def test_aadsts_translate_extracts_code_from_msal_dict_dump():
    """msal often surfaces error_description as a multi-line string —
    the translator must pull the code out regardless of position."""
    err = (
        "Failed to acquire token: AADSTS50011: The reply URL "
        "specified in the request does not match the reply URLs "
        "configured for the application."
    )
    code, msg = _aadsts_translate(err)
    assert code == "AADSTS50011"
    assert msg == _AADSTS_TRANSLATIONS["AADSTS50011"]


# ---------------------------------------------------------------------------
# /accounts/{id}/o365/probe endpoint — round-trip behaviour.
# ---------------------------------------------------------------------------


class TestO365ProbeEndpoint:
    def test_anonymous_redirects_to_login(self, client, db, admin_user):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/o365/probe",
            follow_redirects=False,
        )
        # OwnedAccount dep raises 401 → global handler redirects.
        assert resp.status_code in (303, 302, 401)

    def test_non_manager_returns_403(
        self, client, db, regular_user, admin_user, user_cookies,
    ):
        # Admin owns the account; regular_user has no delegate row.
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365/probe",
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_wrong_provider_type_returns_400(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _seed_gmail_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            f"/accounts/{acct_id}/o365/probe",
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_happy_path_returns_green_chip(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        """Success: /me responds, chip surfaces signed-in address +
        the diagnostic tooltip ('credentials valid; next step is
        push subscriptions')."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        graph_response = {
            "id": "user-id-1",
            "userPrincipalName": "alex@contoso.onmicrosoft.com",
            "mail": "alex@contoso.com",
            "displayName": "Alex Operator",
        }
        with patch(
            "email_triage.providers.office365.Office365Provider._request",
            new_callable=AsyncMock,
        ) as mock_req, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_req.return_value = graph_response
            resp = client.post(
                f"/accounts/{acct_id}/o365/probe",
                follow_redirects=False,
            )
        assert resp.status_code == 200, resp.text
        body = resp.text
        assert "credentials valid" in body
        # Prefer mail over UPN.
        assert "alex@contoso.com" in body
        # Diagnostic tooltip carries the next-step nudge — rendered
        # via the m.help() shape (data-tooltip + role=img).
        assert "data-tooltip" in body
        assert "Push tab" in body
        # /me was called with the canonical path.
        mock_req.assert_awaited_once()
        args, kwargs = mock_req.await_args
        assert args[0] == "GET"
        assert args[1] == "/me"

    def test_falls_back_to_upn_when_mail_blank(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        """Newer tenants sometimes leave 'mail' blank for
        license-restricted users; the chip falls back to UPN."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        graph_response = {
            "userPrincipalName": "svc@contoso.onmicrosoft.com",
            "mail": "",
        }
        with patch(
            "email_triage.providers.office365.Office365Provider._request",
            new_callable=AsyncMock,
        ) as mock_req, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_req.return_value = graph_response
            resp = client.post(
                f"/accounts/{acct_id}/o365/probe",
                follow_redirects=False,
            )
        assert resp.status_code == 200
        assert "svc@contoso.onmicrosoft.com" in resp.text

    @pytest.mark.parametrize("aadsts_code", sorted(_AADSTS_TRANSLATIONS.keys()))
    def test_each_aadsts_code_renders_translated_chip(
        self, client, db, admin_user, admin_cookies,
        force_msal_present, aadsts_code,
    ):
        """Each AADSTS code surfaces its translated one-liner
        through the round-trip — no bare code as the headline."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        # acquire_token raises a RuntimeError carrying the AADSTS
        # description — Office365Provider._request awaits
        # _get_client → acquire_token, so the RuntimeError surfaces
        # through the same except branch as a Graph error body.
        err_msg = (
            f"{aadsts_code}: Microsoft sample description text "
            f"for the {aadsts_code} condition."
        )
        with patch(
            "email_triage.providers.office365.Office365Provider._request",
            new_callable=AsyncMock,
        ) as mock_req, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_req.side_effect = RuntimeError(err_msg)
            resp = client.post(
                f"/accounts/{acct_id}/o365/probe",
                follow_redirects=False,
            )
        assert resp.status_code == 200
        body = resp.text
        # Translated one-liner present.
        # First few chars of the translation are unique enough.
        translation = _AADSTS_TRANSLATIONS[aadsts_code]
        # Strip HTML-encoded ampersands etc that the response may
        # have escaped — match a substring before any & char so
        # the assertion is robust to escaping.
        translation_substr = translation.split(" — ")[0][:30]
        assert translation_substr in body
        # The AADSTS code rides along as a reference small-text but
        # is NOT the headline — the failure status is.
        assert "sign-in failed" in body

    def test_unknown_aadsts_falls_back_to_verbatim(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        with patch(
            "email_triage.providers.office365.Office365Provider._request",
            new_callable=AsyncMock,
        ) as mock_req, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_req.side_effect = RuntimeError(
                "AADSTS999999: brand new code we haven't translated"
            )
            resp = client.post(
                f"/accounts/{acct_id}/o365/probe",
                follow_redirects=False,
            )
        assert resp.status_code == 200
        body = resp.text
        # Unknown AADSTS code surfaces verbatim with the code chip.
        assert "AADSTS999999" in body
        assert "brand new code we haven&#39;t translated" in body or \
               "brand new code we haven't translated" in body

    def test_graph_error_body_translated(
        self, client, db, admin_user, admin_cookies, force_msal_present,
    ):
        """A raised GraphError with a dict body containing an AADSTS
        code in error.message must surface the translated chip."""
        from email_triage.providers.office365 import GraphError

        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        graph_body = {
            "error": {
                "code": "Forbidden",
                "message": (
                    "AADSTS65001: The user or admin has not "
                    "consented to use the application."
                ),
            }
        }
        with patch(
            "email_triage.providers.office365.Office365Provider._request",
            new_callable=AsyncMock,
        ) as mock_req, patch(
            "email_triage.providers.office365.Office365Provider.close",
            new_callable=AsyncMock,
        ):
            mock_req.side_effect = GraphError(403, graph_body, "/me")
            resp = client.post(
                f"/accounts/{acct_id}/o365/probe",
                follow_redirects=False,
            )
        assert resp.status_code == 200
        body = resp.text
        assert "Admin consent needed" in body


# ---------------------------------------------------------------------------
# Shared partial — accounts/_o365_fields.html included by both the
# wizard step2-o365 form and the edit-page Integrations tab.
# ---------------------------------------------------------------------------


_TEMPLATES_ROOT = (
    Path(__file__).resolve().parent.parent.parent
    / "src" / "email_triage" / "web" / "templates"
)


class TestSharedPartialIncluded:
    def test_partial_file_exists_on_disk(self):
        partial = _TEMPLATES_ROOT / "accounts" / "_o365_fields.html"
        assert partial.is_file(), (
            "Shared O365 field-block partial must live at "
            "templates/accounts/_o365_fields.html so both the wizard "
            "step2-o365 form and the edit-page Integrations tab can "
            "include it. (#126)"
        )

    def test_edit_page_field_wrapper_includes_shared_partial(self):
        """templates/accounts/_fields_office365.html now delegates to
        the shared partial. Stops the wizard + edit page from
        drifting."""
        wrapper = (
            _TEMPLATES_ROOT / "accounts" / "_fields_office365.html"
        ).read_text(encoding="utf-8")
        assert 'include "accounts/_o365_fields.html"' in wrapper

    def test_wizard_step2_includes_shared_partial(self):
        step2 = (
            _TEMPLATES_ROOT / "account_wizard" / "step2.html"
        ).read_text(encoding="utf-8")
        assert 'include "accounts/_o365_fields.html"' in step2


class TestSharedPartialRendered:
    def test_edit_page_renders_partial_content(
        self, client, db, admin_user, admin_cookies,
    ):
        """Edit page on an O365 account renders the shared partial.

        2026-05-10: per-account client_id / tenant_id / client_secret
        inputs lifted to install-level. The partial now renders the
        Personal-MSA checkbox + Probe button only. The Azure-portal
        recipe moved to /config.
        """
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get(f"/accounts/{acct_id}/edit")
        assert resp.status_code == 200
        body = resp.text
        # Personal-MSA checkbox is the only operator-facing control
        # on the partial (besides Calendar + Probe).
        assert 'name="is_personal_msa"' in body
        assert "Personal Microsoft account" in body
        # Per-account credential inputs are gone.
        assert 'name="client_id"' not in body
        assert 'name="tenant_id"' not in body
        assert 'name="client_secret"' not in body
        # The Azure-portal recipe lives on /config now; not on the
        # per-account page.
        assert "How do I find these values?" not in body
        # Probe button (this surface enables show_probe by default).
        assert f"/accounts/{acct_id}/o365/probe" in body
        assert "Probe my config" in body

    def test_wizard_step2_renders_partial_content(
        self, client, db, regular_user, user_cookies,
    ):
        """Wizard step2-o365 renders the same simplified partial.

        Personal-MSA checkbox present; per-account credential inputs
        absent (lifted to install-level 2026-05-10). Probe button is
        suppressed (account isn't authenticated yet).
        """
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                regular_user["id"], "Operator A", "office365",
                "{}", now, now,
            ),
        )
        db.commit()
        aid = cur.lastrowid
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.get(f"/accounts/new?step=2&account_id={aid}")
        assert resp.status_code == 200
        body = resp.text
        # Personal-MSA checkbox renders in the wizard too.
        assert 'name="is_personal_msa"' in body
        # Per-account credential inputs are gone.
        assert 'name="client_id"' not in body
        assert 'name="tenant_id"' not in body
        # Probe button is suppressed in wizard mode (show_probe=false).
        assert f"/accounts/{aid}/o365/probe" not in body
        # Form action still posts to the wizard step.
        assert "/accounts/new/step2-o365" in body

    def test_help_macro_tooltips_render_on_new_controls(
        self, client, db, admin_user, admin_cookies,
    ):
        """Per pattern_tooltip_singleton_engine.md — every new control
        emits the m.help() shape (data-tooltip + role=img). Spot-check
        on the rendered edit page."""
        acct_id = _seed_o365_account(db, user_id=admin_user["id"])
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get(f"/accounts/{acct_id}/edit")
        assert resp.status_code == 200
        body = resp.text
        # The macro emits: <span data-tooltip="..." data-placement="..."
        # role="img" aria-label="Help: ...">. Multiple instances
        # expected (Tenant ID, Client ID, Client Secret, Probe button).
        assert body.count('data-tooltip=') >= 4
        assert 'role="img"' in body
        # No raw title= attributes on new tooltip-bearing controls
        # (rule from pattern_tooltip_singleton_engine.md). The wider
        # template has legacy title= on a sibling label (HIPAA toggle
        # banner) so we can't ban title= globally; just verify the
        # macro-emitted shape is what carries the new tooltips.
        assert 'aria-label="Help: ' in body


# ---------------------------------------------------------------------------
# AUDIENCE comment header on touched templates.
# ---------------------------------------------------------------------------


class TestAudienceHeaders:
    def test_o365_fields_partial_has_audience_header(self):
        text = (
            _TEMPLATES_ROOT / "accounts" / "_o365_fields.html"
        ).read_text(encoding="utf-8")
        assert "AUDIENCE:" in text
        assert "TECH-SKILL:" in text
        assert "COPY RULES:" in text

    def test_fields_office365_wrapper_has_audience_header(self):
        text = (
            _TEMPLATES_ROOT / "accounts" / "_fields_office365.html"
        ).read_text(encoding="utf-8")
        assert "AUDIENCE:" in text

    def test_wizard_step2_has_audience_header(self):
        text = (
            _TEMPLATES_ROOT / "account_wizard" / "step2.html"
        ).read_text(encoding="utf-8")
        assert "AUDIENCE" in text
