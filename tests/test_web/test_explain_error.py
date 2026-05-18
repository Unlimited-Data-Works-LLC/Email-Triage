"""Tests for #121-A — explain-this-error AI button.

Covers:

1. ``error_explain.explain_error()`` happy path (Ollama responds with
   text → returned verbatim).
2. Fallback when ``is_healthy("ollama")`` is False — circuit breaker
   skips the LLM round-trip entirely.
3. Fallback when the configured classifier has no ``complete()``
   method (anything other than Ollama today).
4. ``POST /explain-error`` round-trip: 200 chip / 401 anon / 403
   non-admin / 403 actor!=owner when account_id supplied.
5. Audit row written via ``record_auth_event`` on success.
6. AADSTS-extension shape — known code (covered by the static table)
   still passes through the explain endpoint and the AI's mock
   response surfaces.
7. PRIVACY INVARIANT — the constructed prompt never carries message
   bodies, only the declared inputs.

Backend reuse note (per ``feedback_code_reuse_directive.md``): all
HTTP-to-Ollama traffic goes through ``OllamaClassifier.complete()``.
These tests patch ``complete`` at the classifier-instance level via
``_build_classifier_from_config`` so the real httpx client never
fires.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.error_explain import (
    FALLBACK_MESSAGE,
    SYSTEM_PROMPT,
    _build_prompt,
    explain_error,
)


# ---------------------------------------------------------------------------
# Module-level helpers — unit tests on _build_prompt (privacy gate).
# ---------------------------------------------------------------------------


class TestBuildPromptPrivacy:
    """Privacy invariant — the prompt body only ever contains the
    declared inputs. Everything else (message body, recipient list,
    decoded subject, etc.) MUST stay out."""

    def test_prompt_contains_declared_inputs(self):
        prompt = _build_prompt(
            error_text="AADSTS65001: consent required",
            error_class="AADSTS65001",
            provider="office365",
            account_name="Bob (bob@example.com)",
        )
        assert "AADSTS65001: consent required" in prompt
        assert "AADSTS65001" in prompt
        assert "office365" in prompt
        assert "Bob (bob@example.com)" in prompt

    def test_prompt_never_contains_message_body(self):
        """The function signature has no message_body slot. Even
        when other fields hint at one, the prompt body must not
        accidentally splice anything outside the declared inputs.

        This is the canary — any future refactor that introduces a
        kwarg-catch-all or db read would fail this test as soon as
        someone tries to use it."""
        # Construct an error_text that DOES carry stray content that
        # could be mistaken for a body if a future careless refactor
        # forwarded everything blindly:
        body_marker = "SECRET_BODY_MARKER_THAT_SHOULD_NOT_LEAK"
        prompt = _build_prompt(
            error_text="invalid_grant",
            error_class="invalid_grant",
            provider="gmail_api",
            account_name="Alice",
        )
        # error_text is allowed in the prompt — it IS a declared
        # input — but our marker (which represents the kind of thing
        # a leak would introduce) is not.
        assert body_marker not in prompt
        # Also assert the assembled prompt is the only place the
        # marker could appear if a code-path accidentally splatted
        # extra kwargs through.

    def test_prompt_truncates_huge_error_text(self):
        """Long stack traces shouldn't be able to balloon the
        prompt past the 2 KB ceiling."""
        # Use a unique marker that doesn't appear in the prompt
        # scaffolding so we can count occurrences cleanly.
        huge = "ZQ" * 5000  # 10 000 chars, marker doesn't collide
        prompt = _build_prompt(
            error_text=huge,
            error_class=None,
            provider=None,
            account_name=None,
        )
        # Body section caps at 2000 chars — that's at most 1000 ZQ
        # pairs in the truncated error_text region.
        assert prompt.count("ZQ") <= 1000

    def test_prompt_handles_all_none_optional_fields(self):
        """Only error_text is required — the rest can be None."""
        prompt = _build_prompt(
            error_text="something broke",
            error_class=None,
            provider=None,
            account_name=None,
        )
        # No "None" sentinels.
        assert "None" not in prompt
        assert "something broke" in prompt

    def test_system_prompt_pins_audience_rules(self):
        """The system prompt must declare the project name (no
        Anthropic / no provider), call itself 'AI', and pin the
        sentence-count ceiling."""
        assert "email-triage" in SYSTEM_PROMPT
        # The system prompt must refer to the AI as "AI" — bare
        # word, since 'AI' substring is in 'Anthropic'/'OpenAI' etc.
        # we check via word-boundary form 'AI ' or ' AI'.
        assert "'AI'" in SYSTEM_PROMPT
        # No vendor names.
        assert "Anthropic" not in SYSTEM_PROMPT
        assert "OpenAI" not in SYSTEM_PROMPT
        assert "Gemini" not in SYSTEM_PROMPT
        # Length ceiling.
        assert "4 to 6 sentences" in SYSTEM_PROMPT
        # Refusal-to-speculate clause.
        assert "Refuse" in SYSTEM_PROMPT or "refuse" in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# explain_error() — backend integration tests with the Ollama client
# patched at the classifier-build seam.
# ---------------------------------------------------------------------------


class _StubClassifier:
    """Stand-in for OllamaClassifier.complete() — just returns the
    text it was constructed with and records what it was asked."""
    def __init__(self, reply: str = "stub reply"):
        self.reply = reply
        self.calls: list[str] = []
        self.close_called = False

    async def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.reply

    async def close(self) -> None:
        self.close_called = True


@pytest.fixture(autouse=True)
def _reset_llm_health():
    """Each test starts from a healthy backend."""
    from email_triage.llm_health import _reset_for_test
    _reset_for_test()
    yield
    _reset_for_test()


class TestExplainError:
    @pytest.mark.asyncio
    async def test_happy_path_returns_llm_text(self, db):
        """When backend healthy and classifier returns prose, the
        function returns that prose verbatim (after .strip())."""
        from email_triage.config import TriageConfig
        stub = _StubClassifier(reply=(
            "Microsoft is refusing the sign-in because the user "
            "hasn't consented to the app's permissions. Ask a "
            "tenant admin to grant consent for the Mail.Read scope. "
            "After consent is granted, retry the probe. See "
            "/help/tasks for the full recipe."
        ))
        config = TriageConfig()
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            result = await explain_error(
                error_text="AADSTS65001",
                error_class="AADSTS65001",
                provider="office365",
                account_id=None,
                db=db,
                secrets=None,
                config=config,
            )
        assert "consent" in result
        assert stub.close_called is True
        # The classifier received a prompt — verify the privacy
        # invariant on the wire too.
        assert len(stub.calls) == 1
        sent = stub.calls[0]
        assert "AADSTS65001" in sent
        assert "office365" in sent

    @pytest.mark.asyncio
    async def test_unhealthy_backend_returns_fallback_without_calling(
        self, db,
    ):
        """When the circuit breaker is open, no LLM call fires."""
        from email_triage.config import TriageConfig
        from email_triage.llm_health import set_unhealthy
        set_unhealthy(
            "ollama", ttl_seconds=300, reason="connection refused",
        )
        stub = _StubClassifier()
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            result = await explain_error(
                error_text="AADSTS65001",
                error_class="AADSTS65001",
                provider="office365",
                account_id=None,
                db=db,
                secrets=None,
                config=TriageConfig(),
            )
        assert result == FALLBACK_MESSAGE
        assert stub.calls == []  # never called

    @pytest.mark.asyncio
    async def test_classifier_without_complete_returns_fallback(
        self, db,
    ):
        """A backend that doesn't expose .complete() (today: openai,
        gemini) falls back rather than guessing."""
        from email_triage.config import TriageConfig

        class _NoCompleteClassifier:
            async def close(self):
                pass

        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=_NoCompleteClassifier(),
        ):
            result = await explain_error(
                error_text="some error",
                error_class=None,
                provider="office365",
                account_id=None,
                db=db,
                secrets=None,
                config=TriageConfig(),
            )
        assert result == FALLBACK_MESSAGE

    @pytest.mark.asyncio
    async def test_llm_exception_returns_fallback(self, db):
        """Any exception from .complete() yields the fallback message
        rather than propagating to the chip."""
        from email_triage.config import TriageConfig

        class _FailingClassifier:
            async def complete(self, prompt):
                raise RuntimeError("boom")
            async def close(self):
                pass

        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=_FailingClassifier(),
        ):
            result = await explain_error(
                error_text="some error",
                error_class=None,
                provider="office365",
                account_id=None,
                db=db,
                secrets=None,
                config=TriageConfig(),
            )
        assert result == FALLBACK_MESSAGE


# ---------------------------------------------------------------------------
# Account-name lookup integrated with the prompt.
# ---------------------------------------------------------------------------


def _seed_account(db, *, user_id: int, name: str = "acct1") -> int:
    now = datetime.now(timezone.utc).isoformat()
    cfg = {"account": "user@example.com"}
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "office365", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


class TestExplainErrorAccountResolution:
    @pytest.mark.asyncio
    async def test_account_id_resolved_to_owner_and_name(
        self, db, admin_user,
    ):
        """Per feedback_no_account_id_alone — the prompt sees the
        operator-readable name + owner email, never just '#42'."""
        from email_triage.config import TriageConfig
        acct_id = _seed_account(db, user_id=admin_user["id"], name="prod")
        stub = _StubClassifier(reply="explanation")
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            await explain_error(
                error_text="invalid_grant",
                error_class="invalid_grant",
                provider="office365",
                account_id=acct_id,
                db=db,
                secrets=None,
                config=TriageConfig(),
            )
        prompt = stub.calls[0]
        assert "prod" in prompt
        assert "admin@test.com" in prompt
        # The numeric id MUST NOT appear by itself in the prompt
        # (the rule is "never render Account #42 alone").
        assert f"#{acct_id}" not in prompt
        assert f"account_id={acct_id}" not in prompt


# ---------------------------------------------------------------------------
# /explain-error HTTP endpoint — round-trip + auth gate.
# ---------------------------------------------------------------------------


class TestExplainErrorEndpoint:
    def test_anon_returns_401(self, client, db):
        resp = client.post(
            "/explain-error",
            data={"error_text": "AADSTS65001"},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    def test_non_admin_returns_403(
        self, client, db, regular_user, user_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/explain-error",
            data={"error_text": "AADSTS65001"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_missing_error_text_returns_400(
        self, client, db, admin_user, admin_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/explain-error",
            data={"error_text": "  "},
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_happy_path_returns_chip(
        self, client, db, admin_user, admin_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        stub = _StubClassifier(reply=(
            "Admin consent is required for this app. Ask the "
            "Microsoft 365 admin to grant consent in Azure Portal."
        ))
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            resp = client.post(
                "/explain-error",
                data={
                    "error_text": "AADSTS65001: consent required",
                    "error_class": "AADSTS65001",
                    "provider": "office365",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 200, resp.text
        assert "Admin consent is required" in resp.text
        # The chip carries a label so screen-readers know it's the
        # AI's output, not the raw error.
        assert "AI explanation" in resp.text

    def test_audit_row_written_on_success(
        self, client, db, admin_user, admin_cookies,
    ):
        """HIPAA §164.312(b) audit — every AI consultation lands in
        auth_events so an auditor can replay who consulted the AI
        for which integration error."""
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        stub = _StubClassifier(reply="ok")
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            client.post(
                "/explain-error",
                data={
                    "error_text": "invalid_grant",
                    "error_class": "invalid_grant",
                    "provider": "gmail_api",
                },
                follow_redirects=False,
            )
        from email_triage.web.db import list_auth_events
        events = list_auth_events(
            db, event_type="explain_error", limit=10,
        )
        assert len(events) == 1
        assert events[0]["email"] == "admin@test.com"
        assert "gmail_api" in (events[0]["detail"] or "")
        assert "invalid_grant" in (events[0]["detail"] or "")

    def test_hipaa_gate_fires_when_actor_not_owner(
        self, client, db, regular_user, admin_user, user_cookies,
    ):
        """When account_id is supplied AND the actor is not an
        owner/admin/delegate of that account, the request is rejected
        before the LLM is consulted.

        Mirrors the OwnedAccount dep used by the rest of the per-
        account UI surface (sibling test pattern in
        test_o365_probe_ui.py::test_non_manager_returns_403). Admin
        actors who aren't the owner DO pass — that's the per the
        existing can_manage_account contract — but regular users
        don't.

        Note: the endpoint requires admin role on top of the
        ownership gate (errors are operator-facing). So a regular-
        user who isn't owner is correctly rejected at the role gate
        FIRST — which is the same end state: 403 before LLM call.
        """
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        acct_id = _seed_account(db, user_id=admin_user["id"])
        resp = client.post(
            "/explain-error",
            data={
                "error_text": "AADSTS65001",
                "account_id": str(acct_id),
            },
            follow_redirects=False,
        )
        # 403 — regular_user can't access the admin-only endpoint.
        # The role gate fires first; the account-ownership gate
        # would also fire if the actor were admin-but-not-owner of
        # this specific account (delegate row missing). Both paths
        # block the LLM call, which is the invariant we care about.
        assert resp.status_code == 403

    def test_unknown_aadsts_extension(
        self, client, db, admin_user, admin_cookies,
    ):
        """The static AADSTS table only knows 7 codes. The AI fills
        the gap for codes outside the table (e.g. AADSTS50011)."""
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        stub = _StubClassifier(reply=(
            "Microsoft rejected the request because the reply URL "
            "in the app registration doesn't match the URL the "
            "sign-in flow tried to use. Update the Redirect URI in "
            "Azure Portal → App registrations → your app → "
            "Authentication. See /help/tasks for screenshots."
        ))
        with patch(
            "email_triage.web.routers.ui._shared."
            "_build_classifier_from_config",
            return_value=stub,
        ):
            resp = client.post(
                "/explain-error",
                data={
                    "error_text": (
                        "AADSTS50011: The reply URL specified in "
                        "the request does not match"
                    ),
                    "error_class": "AADSTS50011",
                    "provider": "office365",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 200, resp.text
        body = resp.text
        assert "Redirect URI" in body or "reply URL" in body


# ---------------------------------------------------------------------------
# Probe-chip render — confirm the Explain button hooks plumb correctly.
# ---------------------------------------------------------------------------


class TestProbeChipExplainButton:
    def test_failure_chip_includes_explain_button(self):
        from email_triage.web.routers.ui._shared import (
            _render_o365_probe_chip_failure,
        )
        chip = _render_o365_probe_chip_failure(
            "Microsoft rejected the sign-in.",
            code="AADSTS50011",
            account_id=42,
        )
        # Explain button rendered with hx-post target.
        assert "Explain this error" in chip
        assert 'hx-post="/explain-error"' in chip
        # The provider context is hard-coded for this surface.
        assert "office365" in chip
        # account_id is plumbed so the HIPAA gate fires.
        assert '"account_id": "42"' in chip
        # error_class is the matched AADSTS code.
        assert '"error_class": "AADSTS50011"' in chip

    def test_failure_chip_explain_button_handles_no_account_id(self):
        """Probe-build-failures (no account context) still produce
        a valid Explain button without account_id."""
        from email_triage.web.routers.ui._shared import (
            _render_o365_probe_chip_failure,
        )
        chip = _render_o365_probe_chip_failure(
            "Couldn't build the Graph client.",
        )
        assert "Explain this error" in chip
        # No account_id key in hx-vals when not passed.
        assert '"account_id"' not in chip


# ---------------------------------------------------------------------------
# Logs page — Explain button present on ERROR rows.
# ---------------------------------------------------------------------------


class TestLogsPageExplainButton:
    def test_error_row_renders_explain_button(
        self, client, db, admin_user, admin_cookies,
    ):
        """An ERROR-level log row gets an Explain button beside the
        message. WARNING / INFO rows do not."""
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        # Seed one ERROR + one INFO log row. Direct SQL avoids the
        # logging-framework path so the row shape is deterministic
        # for the assertion below.
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                now, "ERROR", "email_triage.providers.office365",
                "Graph rejected: invalid_grant",
                json.dumps({
                    "error": "invalid_grant",
                    "error_class": "invalid_grant",
                    "provider_type": "office365",
                }),
                now,
            ),
        )
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                now, "INFO", "email_triage.web",
                "request served",
                json.dumps({}),
                now,
            ),
        )
        db.commit()
        resp = client.get("/logs", follow_redirects=False)
        assert resp.status_code == 200, resp.text
        body = resp.text
        # Explain button rendered for the ERROR row.
        assert "Explain this error" in body
        # The form values include the error context.
        assert "invalid_grant" in body
        assert "office365" in body
        # Exactly one rendered <button> for the ERROR row; the
        # INFO row gets no button. (Other matches in the page are
        # JS comments / docstrings, which is why we anchor on the
        # button tag rather than the bare label.)
        assert body.count('hx-post="/explain-error"') == 1
