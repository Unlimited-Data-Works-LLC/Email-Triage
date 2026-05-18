"""Tests for #95 sub-A — auto-chained wizard flow.

The first wave of tests in test_account_wizard.py verified each
step's basic CRUD shape. This file covers the auto-chain
mechanics added in this commit:

* Each step's POST 303s straight to the next step's GET.
* Step 5 finish 303s to /accounts with a success banner.
* Skip-step heuristics fire on render: step 3 when only the inbox
  is selectable AND OAuth scopes are at default; step 4 when the
  user has no personal categories AND no other accounts to copy
  routes from. Skipped steps appear struck-through on the progress
  strip with a "skipped — defaults applied" tooltip.
* Auth completion polling: the step-2 panel polls
  /accounts/{id}/auth-status every 3 seconds. The wizard auto-
  advances when the status flips to authenticated.
* Resume-from-step: abandoning the wizard and revisiting
  /accounts/{id}/edit shows a "Resume setup" banner that links
  back to the step the operator left off at.
* Anonymous users 303 to /login on every step.
* Audience rule grep: no forbidden jargon in any wizard template
  fragment.

PII / fixture rule: every email is user@example.com / mailbox
labels are "Operator A" / "Test Mailbox". No real domains, names,
or OAuth tokens.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_account(db, user_id: int, *, ptype: str = "imap",
                   name: str = "Operator A") -> int:
    """Insert a fresh email_accounts row and return its id."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, ?, ?, '{}', ?, ?)",
        (user_id, name, ptype, now, now),
    )
    db.commit()
    return cur.lastrowid


def _build_route(db, account_id: int, slug: str = "newsletter") -> None:
    """Insert a single route row so the source-account becomes a
    valid copy-from candidate for the step 4 heuristic."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO account_routes "
        "(account_id, category, actions_json, created_at, updated_at) "
        "VALUES (?, ?, '[]', ?, ?)",
        (account_id, slug, now, now),
    )
    db.commit()


def _build_personal_category(db, user_id: int, slug: str = "myslug") -> None:
    """Insert a per-user category so the step-4 'has-default-set'
    heuristic returns False."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO categories "
        "(user_id, slug, description, sort_order, created_at, updated_at) "
        "VALUES (?, ?, ?, 999, ?, ?)",
        (user_id, slug, f"Personal category {slug}", now, now),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Step transitions — every POST 303s to the next step
# ---------------------------------------------------------------------------


class TestAutoChainStepTransitions:
    def test_step1_save_redirects_to_step2(
        self, client, regular_user, user_cookies,
    ):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "Operator A", "provider_type": "imap"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "step=2" in loc
        assert "account_id=" in loc

    def test_step2_imap_save_redirects_to_step3(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="imap")
        r = client.post(
            "/accounts/new/step2-imap",
            data={
                "account_id": str(aid),
                "host": "imap.example.com",
                "port": "993",
                "username": "user@example.com",
                "password": "redacted-secret-string",
                "use_ssl": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert f"step=3&account_id={aid}" in r.headers.get("location", "")

    def test_step3_save_redirects_to_step4(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
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

    def test_step4_save_redirects_to_step5(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        r = client.post(
            "/accounts/new/step4",
            data={"account_id": str(aid), "route_source": "fresh"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert f"step=5&account_id={aid}" in r.headers.get("location", "")

    def test_step5_finish_redirects_to_accounts_with_success(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
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
        loc = r.headers.get("location", "")
        # New auto-chain target: /accounts with a success flash.
        assert loc.startswith("/accounts?success=")
        # Banner mentions the account name so the operator confirms
        # the right mailbox was set up.
        assert "Operator+A" in loc or "Operator%20A" in loc


# ---------------------------------------------------------------------------
# Anonymous users — every step bounces to /login
# ---------------------------------------------------------------------------


class TestAnonymousRedirects:
    def test_anonymous_step1_get_redirects_login(self, client):
        r = client.get(
            "/accounts/new", follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_anonymous_step1_post_redirects_login(self, client):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "X", "provider_type": "imap"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_anonymous_step2_imap_redirects_login(self, client):
        r = client.post(
            "/accounts/new/step2-imap",
            data={"account_id": "1", "host": "h", "username": "u"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_anonymous_step3_redirects_login(self, client):
        r = client.post(
            "/accounts/new/step3", data={"account_id": "1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_anonymous_step4_redirects_login(self, client):
        r = client.post(
            "/accounts/new/step4", data={"account_id": "1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")

    def test_anonymous_step5_redirects_login(self, client):
        r = client.post(
            "/accounts/new/step5", data={"account_id": "1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/login" in r.headers.get("location", "")


# ---------------------------------------------------------------------------
# Skip-step heuristics
# ---------------------------------------------------------------------------


class TestSkipStep3:
    """Step 3 is auto-skipped when the operator has no real choice
    to make: only INBOX selectable AND OAuth scopes at default.

    For Gmail/O365 with no calendar opt-in, that's the typical
    case. IMAP always renders step 3 (the operator needs to set
    push vs poll cadence consciously).
    """

    def test_gmail_default_scopes_skips_step3(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        r = client.get(
            f"/accounts/new?step=3&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        # Skip fires → 303 to step 4 (or step 5 if step 4 also
        # skipped for this user).
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "step=4" in loc or "step=5" in loc

    def test_imap_renders_step3_no_skip(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="imap")
        r = client.get(
            f"/accounts/new?step=3&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert 'name="push_enabled"' in r.text

    def test_skipped_step3_marked_on_progress_strip(
        self, client, regular_user, user_cookies, db,
    ):
        # Land on step 5 directly so we can inspect the progress
        # strip after a skipped step 3 and step 4.
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        r = client.get(
            f"/accounts/new?step=5&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        # Skipped chip uses an em-dash glyph + "skipped — defaults
        # applied" tooltip per the progress-strip template.
        assert "skipped" in r.text.lower()
        assert "defaults applied" in r.text.lower()

    def test_skip_step3_persists_default_config(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        r = client.get(
            f"/accounts/new?step=3&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        # Defaults were laid down so the account isn't half-built.
        import json
        cfg = json.loads(db.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (aid,),
        ).fetchone()["config_json"])
        assert cfg.get("poll_enabled") is True
        assert cfg.get("poll_interval_minutes") == 60


class TestSkipStep4:
    """Step 4 is auto-skipped when the operator has no personal
    categories AND no other accounts whose routes they could copy.

    Either condition alone keeps step 4 live: a personal category
    means there's something to look at; another account means
    there's something to copy from.
    """

    def test_no_personal_cats_no_other_accounts_skips_step4(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        r = client.get(
            f"/accounts/new?step=4&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "step=5" in r.headers.get("location", "")

    def test_personal_cat_present_renders_step4(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        _build_personal_category(db, regular_user["id"], "personal-test")
        r = client.get(
            f"/accounts/new?step=4&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        # Form rendered, copy-from radios suppressed (no other
        # accounts) — the fresh hidden field is present.
        assert 'value="fresh"' in r.text

    def test_other_account_with_routes_renders_step4(
        self, client, regular_user, user_cookies, db,
    ):
        # Another account owned by the same user, with routes —
        # the copy-from radios become meaningful.
        other = _build_account(db, regular_user["id"], name="Old Mailbox")
        _build_route(db, other, "newsletter")
        aid = _build_account(db, regular_user["id"], name="New Mailbox")
        r = client.get(
            f"/accounts/new?step=4&account_id={aid}",
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        # Radio for the source account is rendered.
        assert f"copy:{other}" in r.text


# ---------------------------------------------------------------------------
# Auth completion polling
# ---------------------------------------------------------------------------


class TestAuthStatusPolling:
    def test_step2_gmail_panel_includes_polling_endpoint(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        r = client.get(
            f"/accounts/new?step=2&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        # Polling panel attaches to the auth-status endpoint with
        # an HTMX every-3s trigger.
        assert f"/accounts/{aid}/auth-status?wizard=1" in r.text
        assert "every 3s" in r.text

    def test_step2_o365_panel_includes_polling_endpoint(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="office365")
        r = client.get(
            f"/accounts/new?step=2&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert f"/accounts/{aid}/auth-status?wizard=1" in r.text
        assert "every 3s" in r.text

    def test_auth_status_unauthenticated_returns_polling_strip(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        # No secret stored → endpoint renders the waiting strip.
        r = client.get(
            f"/accounts/{aid}/auth-status?wizard=1",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert "auth-poll-panel" in r.text
        assert "Waiting for sign-in" in r.text
        # No HX-Redirect header on the waiting case.
        assert "HX-Redirect" not in r.headers

    def test_auth_status_authenticated_emits_hx_redirect(
        self, client, regular_user, user_cookies, db, app,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        # Mock the auth-status flip: drop a refresh-token-shaped
        # value into the in-memory secrets store under the key the
        # endpoint checks.
        from email_triage.web.routers.ui import _secret_key_for_account
        sk = _secret_key_for_account(aid, "gmail_api")
        app.state.secrets.set(sk, "mock-refresh-token-value")

        r = client.get(
            f"/accounts/{aid}/auth-status?wizard=1",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        # HTMX gets an HX-Redirect header → full-page navigation
        # to wizard step 3 with auth=ok flash.
        target = r.headers.get("HX-Redirect", "")
        assert target.startswith("/accounts/new?step=3")
        assert f"account_id={aid}" in target
        assert "auth=ok" in target

    def test_auth_status_anonymous_returns_401(
        self, client, regular_user, db,
    ):
        # Real user_id needed to satisfy the FK; the test itself
        # is about the anonymous-caller path (no cookies passed).
        aid = _build_account(db, regular_user["id"])
        r = client.get(f"/accounts/{aid}/auth-status?wizard=1")
        assert r.status_code == 401

    def test_auth_status_cross_user_returns_403(
        self, client, regular_user, admin_user, user_cookies, db,
    ):
        # Admin's account; regular user can't poll its auth status.
        aid = _build_account(db, admin_user["id"], name="Admin Mailbox")
        r = client.get(
            f"/accounts/{aid}/auth-status?wizard=1",
            cookies=user_cookies,
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Resume-from-step
# ---------------------------------------------------------------------------


class TestResumeFromStep:
    def test_no_wizard_state_no_resume_banner(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        r = client.get(
            f"/accounts/{aid}/edit", cookies=user_cookies,
        )
        assert r.status_code == 200
        assert "Resume setup" not in r.text
        assert "Pick up where you left off" not in r.text

    def test_abandoned_at_step3_shows_resume_banner(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        # Stamp the wizard-progress marker as if step 2 had just
        # been submitted.
        from email_triage.web.db import set_setting
        set_setting(db, f"account_state:{aid}:wizard_step", {"step": 2})

        r = client.get(
            f"/accounts/{aid}/edit", cookies=user_cookies,
        )
        assert r.status_code == 200
        assert "Pick up where you left off" in r.text
        # The resume button links back to the abandoned step.
        assert (
            f'href="/accounts/new?step=2&amp;account_id={aid}"' in r.text
            or f'href="/accounts/new?step=2&account_id={aid}"' in r.text
        )

    def test_completed_wizard_clears_resume_marker(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"])
        # Walk the operator through to step 5 finish.
        from email_triage.web.db import set_setting
        set_setting(db, f"account_state:{aid}:wizard_step", {"step": 4})

        r = client.post(
            "/accounts/new/step5",
            data={
                "account_id": str(aid),
                "recipient_digest_enabled": "1",
                "recipient_digest_send_at": "09:10",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303

        # Marker cleared → no banner on edit page.
        r2 = client.get(
            f"/accounts/{aid}/edit", cookies=user_cookies,
        )
        assert r2.status_code == 200
        assert "Pick up where you left off" not in r2.text

    def test_step1_post_stamps_resume_marker(
        self, client, regular_user, user_cookies, db,
    ):
        r = client.post(
            "/accounts/new/step1",
            data={"name": "Resume Test", "provider_type": "imap"},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303
        # Find the new account_id from the redirect URL.
        loc = r.headers.get("location", "")
        m = re.search(r"account_id=(\d+)", loc)
        assert m is not None
        aid = int(m.group(1))

        # Marker is in the settings table immediately after step 1.
        from email_triage.web.db import get_setting
        marker = get_setting(db, f"account_state:{aid}:wizard_step")
        assert marker is not None
        assert marker.get("step") == 1


# ---------------------------------------------------------------------------
# Progress indicator — all 5 steps + active distinct + skipped marked
# ---------------------------------------------------------------------------


class TestProgressIndicator:
    def test_all_five_steps_listed_on_step1(
        self, client, regular_user, user_cookies,
    ):
        r = client.get("/accounts/new", cookies=user_cookies)
        assert r.status_code == 200
        # Every step label appears in the progress strip.
        assert "Provider" in r.text
        assert "Sign in" in r.text
        assert "Real-time watch" in r.text
        assert "Categories" in r.text
        assert "Daily summary" in r.text
        assert "Step 1 of 5" in r.text

    def test_active_step_distinct_on_imap_step3(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="imap")
        r = client.get(
            f"/accounts/new?step=3&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        assert "Step 3 of 5" in r.text


# ---------------------------------------------------------------------------
# Audience grep — wizard templates use plain language
# ---------------------------------------------------------------------------


class TestAudienceCompliance:
    """The wizard is the operator's first impression of email-triage.
    Templates have to clear the audience-rule grep: no developer or
    protocol jargon, no "ask your administrator" copy. We compile a
    forbidden list per the standing rule (see project memory:
    feedback_audience_per_page) and assert zero hits.
    """

    WIZARD_TEMPLATE_DIR = (
        Path(__file__).resolve().parents[2]
        / "src" / "email_triage" / "web" / "templates" / "account_wizard"
    )

    # Forbidden tokens: developer jargon that doesn't belong on an
    # end-user page. Note "OAuth" is OK on step 2 specifically (the
    # operator needs to know what they're approving in the external
    # browser) but only inside m.help() tooltips — not as page
    # body copy headers.
    FORBIDDEN = [
        # Protocol citations
        "RFC ", "RFC2", "RFC3", "RFC4",
        "ISO 8601",
        "OData",
        # API / system internals
        "system log",
        "AND-combined",
        "substring match",
        # Admin-path leakage
        "ask your administrator",
        "ask the administrator",
        "/admin/",
        # AI plumbing leakage
        "language model",
        "language-model",
        # Unhelpful jargon
        "Pub/Sub topic",
        "device-code flow",
    ]

    def test_zero_forbidden_hits_in_wizard_templates(self):
        hits: list[tuple[str, str]] = []
        assert self.WIZARD_TEMPLATE_DIR.exists(), self.WIZARD_TEMPLATE_DIR
        # Strip Jinja comment blocks (`{# ... #}`) before grepping so
        # the AUDIENCE comment header itself — which legitimately
        # mentions the forbidden tokens as part of the rule list —
        # doesn't trigger a false positive. Operator-visible copy
        # never lives inside a {# ... #} block.
        comment_re = re.compile(r"\{#.*?#\}", re.DOTALL)
        for tmpl in sorted(self.WIZARD_TEMPLATE_DIR.glob("*.html")):
            raw = tmpl.read_text(encoding="utf-8")
            stripped = comment_re.sub("", raw)
            for needle in self.FORBIDDEN:
                if needle.lower() in stripped.lower():
                    hits.append((tmpl.name, needle))
        assert hits == [], (
            "Forbidden audience tokens found in wizard templates: "
            f"{hits}"
        )

    def test_audience_header_present_on_every_wizard_template(self):
        """Standing rule: every user-facing template declares its
        AUDIENCE + TECH-SKILL + COPY RULES via a top-of-file
        comment block (the '─── AUDIENCE ───' marker)."""
        for tmpl in sorted(self.WIZARD_TEMPLATE_DIR.glob("*.html")):
            text = tmpl.read_text(encoding="utf-8")
            assert "AUDIENCE" in text, (
                f"Missing AUDIENCE comment header in {tmpl.name}"
            )
            assert "TECH-SKILL" in text or "TECH" in text, (
                f"Missing TECH-SKILL declaration in {tmpl.name}"
            )

    def test_step2_gmail_panel_uses_plain_signin_language(
        self, client, regular_user, user_cookies, db,
    ):
        aid = _build_account(db, regular_user["id"], ptype="gmail_api")
        r = client.get(
            f"/accounts/new?step=2&account_id={aid}",
            cookies=user_cookies,
        )
        assert r.status_code == 200
        # Plain-language framing of OAuth.
        assert "Sign in with Google" in r.text
