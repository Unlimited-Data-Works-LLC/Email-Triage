"""Tests for the Azure OpenAI adapter.

Covers the canonical W1-A ``chat_complete()`` contract + the
``Classifier``-ABC shim + the token-shape privacy invariants.

HTTP is mocked end-to-end; no real Azure calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from email_triage.ai_backends.azure_openai import (
    DEFAULT_API_VERSION,
    AzureOpenAIAdapter,
    AzureOpenAIAuthError,
    AzureOpenAIClassifier,
    AzureOpenAIError,
    _strip_sensitive_query_params,
)


# ---------------------------------------------------------------------------
# Helpers — match the pattern in tests/test_classify/test_openai_compat.py
# ---------------------------------------------------------------------------


def _azure_response(content: str) -> dict:
    """Render a successful Azure chat-completion response shape."""
    return {
        "id": "chatcmpl-abc",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 50, "completion_tokens": 12},
    }


def _patch_httpx(mock_resp):
    """Patch the adapter's httpx.AsyncClient to return ``mock_resp``."""
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    cls_patch = patch(
        "email_triage.ai_backends.azure_openai.httpx.AsyncClient",
        return_value=mock_client,
    )
    return cls_patch, mock_client


# ---------------------------------------------------------------------------
# Constructor + introspection
# ---------------------------------------------------------------------------


class TestAdapterConstruction:
    def test_minimal_construction(self):
        a = AzureOpenAIAdapter(
            endpoint="https://my-resource.openai.azure.com/",
            api_key="azkey",
            deployment="my-deployment",
        )
        # endpoint trailing-slash is normalised away.
        assert a.endpoint == "https://my-resource.openai.azure.com"
        assert a.deployment == "my-deployment"
        assert a.api_version == DEFAULT_API_VERSION
        assert a.model == ""
        # Azure is always external; HIPAA gate stays closed pre-BAA.
        assert a.is_local is False

    def test_empty_endpoint_rejected(self):
        with pytest.raises(ValueError, match="endpoint"):
            AzureOpenAIAdapter(
                endpoint="",
                api_key="azkey",
                deployment="d",
            )

    def test_empty_deployment_rejected(self):
        with pytest.raises(ValueError, match="deployment"):
            AzureOpenAIAdapter(
                endpoint="https://r.openai.azure.com",
                api_key="azkey",
                deployment="",
            )

    def test_explicit_api_version_overrides_default(self):
        a = AzureOpenAIAdapter(
            endpoint="https://r.openai.azure.com",
            api_key="k",
            deployment="d",
            api_version="2024-08-01-preview",
        )
        assert a.api_version == "2024-08-01-preview"

    def test_default_api_version_stable_choice(self):
        """The shipped default must be a GA stable, not a preview.

        Pins the deliberate choice in the module docstring against an
        accidental flip to a preview API version (preview surfaces
        rotate; GA does not).
        """
        assert "preview" not in DEFAULT_API_VERSION.lower()
        # Sanity: dated YYYY-MM-DD format.
        parts = DEFAULT_API_VERSION.split("-")
        assert len(parts) == 3
        assert parts[0].isdigit() and len(parts[0]) == 4


# ---------------------------------------------------------------------------
# chat_complete() — the canonical method
# ---------------------------------------------------------------------------


class TestChatComplete:
    @pytest.fixture
    def adapter(self):
        return AzureOpenAIAdapter(
            endpoint="https://my-resource.openai.azure.com",
            api_key="azkey-test",
            deployment="my-deployment",
            model="gpt-4o",
        )

    async def test_happy_path_returns_content(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("Hello world.")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        assert out == "Hello world."

    async def test_url_is_deployment_addressed(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        url = call.args[0] if call.args else call.kwargs.get("url", "")
        assert url == (
            "https://my-resource.openai.azure.com/openai/deployments/"
            "my-deployment/chat/completions"
        )

    async def test_api_version_is_query_param(self, adapter):
        """Azure's api-version belongs in the query string, NOT a header.

        The existing OpenAI-compat classifier puts it in a header
        because that's the only generic-extra-headers seam it has;
        the Azure-canonical adapter does it right.
        """
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        params = call.kwargs.get("params", {})
        assert params == {"api-version": DEFAULT_API_VERSION}

    async def test_sends_api_key_header_not_bearer(self, adapter):
        """Azure uses an ``api-key`` header, NOT ``Authorization: Bearer``.

        This is the auth-layer divergence from public OpenAI.
        """
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        headers = call.kwargs.get("headers", {})
        assert headers.get("api-key") == "azkey-test"
        # Belt-and-suspenders: never set a Bearer header on Azure.
        assert "Authorization" not in headers

    async def test_response_format_json_object(self, adapter):
        """``response_format={"type":"json_object"}`` propagates verbatim."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response('{"k":"v"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "give me json"}],
                response_format={"type": "json_object"},
            )
        # The caller parses; the adapter just passes back the string.
        assert out == '{"k":"v"}'
        assert json.loads(out) == {"k": "v"}
        call = mock_client.post.call_args
        body = call.kwargs.get("json", {})
        assert body["response_format"] == {"type": "json_object"}

    async def test_response_format_json_schema(self, adapter):
        """Strict schema-mode propagates verbatim.

        #152 phases 3-4 need this for describe-and-discard.
        """
        schema = {
            "type": "json_schema",
            "json_schema": {
                "name": "classification",
                "schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "confidence": {"type": "number"},
                    },
                    "required": ["category"],
                },
            },
        }
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response('{"category":"fyi"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "classify"}],
                response_format=schema,
            )
        call = mock_client.post.call_args
        body = call.kwargs.get("json", {})
        # Pass-through unchanged — adapter must not mangle the shape.
        assert body["response_format"] == schema

    async def test_max_tokens_and_temperature_override(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=512,
                temperature=0.0,
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["max_tokens"] == 512
        assert body["temperature"] == 0.0

    async def test_extra_kwargs_passthrough(self, adapter):
        """Additional OpenAI body fields propagate (top_p, seed, etc.)."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
                top_p=0.9,
                seed=42,
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["top_p"] == 0.9
        assert body["seed"] == 42

    async def test_extra_kwargs_cannot_clobber_messages(self, adapter):
        """A caller-supplied ``messages=`` kwarg cannot overwrite the
        validated ``messages`` positional arg — Python's calling
        convention raises ``TypeError`` before the function body runs.

        Defence-in-depth: even if a future refactor made ``messages``
        keyword-only, the in-body loop in ``chat_complete`` filters
        out any key already present in ``body`` so the validated
        ``messages`` list cannot be silently replaced.
        """
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(TypeError, match="messages"):
                await adapter.chat_complete(
                    [{"role": "user", "content": "real"}],
                    messages=[{"role": "user", "content": "shadow"}],
                )
        # And no HTTP call happened.
        assert mock_client.post.call_count == 0

    async def test_kwargs_cannot_clobber_model_key_set_from_adapter(self, adapter):
        """In-body protection: a kwargs entry whose name collides with
        a body field set above (e.g. ``model``, which the adapter
        injects when ``self._model`` is non-empty) must not silently
        overwrite. The ``adapter`` fixture has ``model='gpt-4o'``; a
        caller passing ``model='gpt-5-rogue'`` as **kwargs gets
        skipped by the in-body loop because ``model`` is already in
        ``body``.

        (``messages`` collision is prevented by Python's call
        convention at the call site; the in-body loop's job is to
        protect non-positional fields like ``model``.)
        """
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "real"}],
                model="gpt-5-rogue",  # kwargs — must NOT clobber.
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        # Adapter's configured model survived.
        assert body["model"] == "gpt-4o"

    async def test_empty_messages_raises_before_http(self, adapter):
        """An empty messages list must raise BEFORE the HTTP call —
        saves a round-trip on an obvious caller bug."""
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(ValueError, match="messages"):
                await adapter.chat_complete([])
        # And no HTTP call happened.
        assert mock_client.post.call_count == 0

    async def test_empty_api_key_raises_before_http(self):
        """No api_key → fail closed, never make an unauthenticated call."""
        adapter = AzureOpenAIAdapter(
            endpoint="https://r.openai.azure.com",
            api_key="",
            deployment="d",
        )
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(ValueError, match="api_key"):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert mock_client.post.call_count == 0

    async def test_complete_alias(self, adapter):
        """``.complete(prompt)`` wraps ``chat_complete`` with a user-role
        single-message — Classifier-ABC compatibility surface."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response("answered")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.complete("the prompt")
        assert out == "answered"
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["messages"] == [
            {"role": "user", "content": "the prompt"},
        ]


# ---------------------------------------------------------------------------
# Error handling — privacy-invariant + Auth vs generic split
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @pytest.fixture
    def adapter(self):
        return AzureOpenAIAdapter(
            endpoint="https://my-resource.openai.azure.com",
            api_key="azkey",
            deployment="d",
        )

    async def test_401_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": {
                "code": "401",
                "message": "Access denied due to invalid subscription key",
            }
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIAuthError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        # The wrapped exception is a subclass of the base error.
        assert isinstance(ei.value, AzureOpenAIError)
        assert ei.value.status == 401
        assert "Access denied" in str(ei.value)

    async def test_403_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {"code": "403", "message": "Forbidden"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIAuthError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )

    async def test_500_raises_generic_error_not_auth(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {
            "error": {"code": "500", "message": "Internal server error"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert not isinstance(ei.value, AzureOpenAIAuthError)
        assert ei.value.status == 500

    async def test_non_json_error_body_handled(self, adapter):
        """An upstream proxy / gateway error returns text, not JSON.

        The adapter must still raise a clean error without spilling
        the response or crashing on the json() decode.
        """
        mock_resp = Mock()
        mock_resp.status_code = 502
        # Simulate json() failure — proxy returned HTML.
        mock_resp.json.side_effect = ValueError("not json")
        mock_resp.text = "<html>bad gateway</html>"
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert ei.value.status == 502

    async def test_200_with_no_choices_raises(self, adapter):
        """Content-filter trip: 200 + empty choices = error, not silent ''."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "chatcmpl-abc",
            "choices": [],
            "prompt_filter_results": [{"content_filter_results": {}}],
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )

    async def test_200_with_non_json_body_raises(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("garbage")
        mock_resp.text = "garbage"
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(AzureOpenAIError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )


# ---------------------------------------------------------------------------
# Privacy invariants — token-shape scrub at exception construction time.
# Mirrors the GmailApiError #168 hardening pattern. The exception is the
# earliest place a leak can land in a log handler that captures exc_info.
# ---------------------------------------------------------------------------


# Sentinel values — visually distinct so a substring search is unambiguous.
# NEVER use real-shape tokens here; the static
# test_no_raw_jwt_in_source guard would flag them.
_TEST_ACCESS_TOKEN = "TEST_ACCESS_TOKEN_DO_NOT_LEAK_aa1111"
_TEST_REFRESH_TOKEN = "TEST_REFRESH_TOKEN_DO_NOT_LEAK_bb2222"
_TEST_ID_TOKEN = "TEST_ID_TOKEN_DO_NOT_LEAK_cc3333"
_TEST_API_KEY = "TEST_API_KEY_DO_NOT_LEAK_dd4444"
_TEST_CLIENT_SECRET = "TEST_CLIENT_SECRET_DO_NOT_LEAK_ee5555"
_TEST_PASSWORD = "TEST_PASSWORD_DO_NOT_LEAK_ff6666"
_TEST_SESSION_TOKEN = "TEST_SESSION_TOKEN_DO_NOT_LEAK_gg7777"


class TestPrivacyInvariants:
    def test_error_message_scrubs_token_shape_keys(self):
        """If a body dict carries any token-shape key, the rendered
        exception message must NOT include its value."""
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "id_token": _TEST_ID_TOKEN,
            "api_key": _TEST_API_KEY,
            "client_secret": _TEST_CLIENT_SECRET,
            "password": _TEST_PASSWORD,
            "session_token": _TEST_SESSION_TOKEN,
            # Operational fields that must SURVIVE the scrub:
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "openai/all",
        }
        err = AzureOpenAIError(500, body, "https://r.openai.azure.com/x")
        rendered = str(err)
        # Every sentinel must be absent.
        for sentinel in (
            _TEST_ACCESS_TOKEN, _TEST_REFRESH_TOKEN, _TEST_ID_TOKEN,
            _TEST_API_KEY, _TEST_CLIENT_SECRET, _TEST_PASSWORD,
            _TEST_SESSION_TOKEN,
        ):
            assert sentinel not in rendered, (
                f"Token-shape value '{sentinel}' leaked into exception "
                f"message: {rendered!r}"
            )
        # Operational fields survive for operator readability.
        assert "expires_in" in rendered
        assert "Bearer" in rendered

    def test_error_scrub_covers_all_canonical_token_keys(self):
        """Sweep every entry in TriageLogger._TOKEN_KEYS — any future
        addition to the canonical frozenset must inherit the scrub
        automatically because AzureOpenAIError references it by name."""
        from email_triage.triage_logging import TriageLogger
        for key in TriageLogger._TOKEN_KEYS:
            sentinel = f"SENTINEL_{key}_DO_NOT_LEAK_zzz"
            body = {key: sentinel}
            err = AzureOpenAIError(500, body, "")
            rendered = str(err)
            assert sentinel not in rendered, (
                f"Token-shape value for key '{key}' leaked into "
                f"exception message: {rendered!r}"
            )

    def test_auth_error_inherits_scrub(self):
        """``AzureOpenAIAuthError`` subclasses ``AzureOpenAIError`` and
        has no ``__init__`` override — pin that it inherits the scrub
        so a future refactor that adds an override doesn't silently
        strip the defence."""
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "error": {"message": "invalid key"},
        }
        err = AzureOpenAIAuthError(401, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        # Operator-actionable message still surfaces.
        assert "invalid key" in rendered

    def test_error_with_no_error_key_falls_back_to_safe_body(self):
        """When the body dict has no ``error`` key, the constructor
        falls back to ``str(safe_body)`` — pin that the safe_body
        version (not the raw body) is what gets stringified."""
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "model": "gpt-4o",
        }
        err = AzureOpenAIError(500, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert "gpt-4o" in rendered

    def test_error_with_non_dict_body_unchanged(self):
        """Non-dict bodies (string error, list) stringify unchanged.

        Tampering with string bodies would mask real upstream errors
        that aren't shaped like Azure's documented response. Only the
        dict path needs the scrub.
        """
        # Pure string body — no scrub applied; the test sentinel is
        # NOT a token-shape key, just an opaque error string.
        body = "Upstream proxy returned plain text"
        err = AzureOpenAIError(502, body, "")
        rendered = str(err)
        assert "Upstream proxy returned plain text" in rendered

    @pytest.mark.asyncio
    async def test_arbitrary_auth_response_dict_no_token_leak(self):
        """End-to-end privacy invariant: simulate Azure returning a
        success-shape OAuth token response (the kind of body that
        could leak if a future refactor wraps the error around the
        wrong payload). Construct from an arbitrary auth-response
        dict; rendered exception must scrub every token-shape value.

        Mirrors the sibling pattern in
        tests/test_security_token_logging.py.
        """
        # Build an "arbitrary auth-response dict" — every field on the
        # OAuth 2.0 RFC 6749 token-response surface plus the OpenID
        # Connect id_token field. Pure construction; no HTTP call.
        auth_response = {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "id_token": _TEST_ID_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
            "scope": "https://cognitiveservices.azure.com/.default",
        }
        # Even though this dict has no "error" key (i.e. it doesn't
        # look like an Azure error response), the adapter's defensive
        # constructor must still scrub.
        err = AzureOpenAIError(200, auth_response, "")
        rendered = str(err)
        for sentinel in (
            _TEST_ACCESS_TOKEN, _TEST_REFRESH_TOKEN, _TEST_ID_TOKEN,
        ):
            assert sentinel not in rendered, (
                f"Token leaked: {sentinel!r} in {rendered!r}"
            )

    def test_url_strips_sensitive_query_params(self):
        """If a future refactor ever puts the api-key in the URL
        query string, the rendered exception must redact it."""
        leaked_url = (
            "https://r.openai.azure.com/openai/deployments/d/"
            "chat/completions?api-key=SECRET_KEY_VALUE_NEVER_LOG&"
            "api-version=2024-10-21"
        )
        err = AzureOpenAIError(500, {"error": {"message": "boom"}}, leaked_url)
        rendered = str(err)
        assert "SECRET_KEY_VALUE_NEVER_LOG" not in rendered
        assert "REDACTED" in rendered
        # The non-sensitive query param survives.
        assert "api-version=2024-10-21" in rendered

    def test_strip_sensitive_query_params_handles_no_query(self):
        # Bare URL — no-op.
        url = "https://r.openai.azure.com/x"
        assert _strip_sensitive_query_params(url) == url

    def test_strip_sensitive_query_params_handles_empty(self):
        assert _strip_sensitive_query_params("") == ""

    def test_strip_sensitive_query_params_covers_alternates(self):
        """``api-key``, ``key``, ``token``, ``access_token``, ``code``
        all get redacted."""
        url = "https://x/?key=KKK&token=TTT&access_token=AAA&code=CCC&foo=bar"
        out = _strip_sensitive_query_params(url)
        assert "KKK" not in out
        assert "TTT" not in out
        assert "AAA" not in out
        assert "CCC" not in out
        assert "foo=bar" in out


# ---------------------------------------------------------------------------
# AzureOpenAIClassifier — Classifier-ABC shim sanity
# ---------------------------------------------------------------------------


class TestClassifierShim:
    """End-to-end: the shim should call the adapter and parse the JSON
    reply into a ``Classification``."""

    @pytest.fixture
    def classifier(self):
        return AzureOpenAIClassifier(
            endpoint="https://r.openai.azure.com",
            api_key="azkey",
            deployment="my-deployment",
        )

    def _make_email(self):
        from email_triage.engine.models import EmailMessage
        return EmailMessage(
            message_id="m1",
            provider="test",
            sender="alice@example.com",
            recipients=["bob@example.com"],
            subject="Test",
            body_text="Body.",
            date=datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc),
        )

    async def test_basic_classification(self, classifier):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response(json.dumps({
            "category": "fyi",
            "confidence": 0.7,
            "reason": "looks informational",
        }))
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            result = await classifier.classify(
                self._make_email(),
                {"fyi": "info", "to-respond": "needs reply"},
            )
        assert result.category == "fyi"
        assert result.confidence == 0.7
        assert result.source == "llm"

    async def test_shim_uses_api_key_header(self, classifier):
        """Pin that the shim still routes through the Azure-canonical
        api-key header (regression guard against future refactor that
        accidentally swaps in the Bearer pattern)."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _azure_response(json.dumps({
            "category": "fyi",
            "confidence": 0.5,
            "reason": "",
        }))
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await classifier.classify(
                self._make_email(),
                {"fyi": "info"},
            )
        headers = mock_client.post.call_args.kwargs.get("headers", {})
        assert headers.get("api-key") == "azkey"
        assert "Authorization" not in headers

    def test_shim_marks_is_local_false(self, classifier):
        """HIPAA gate posture — Azure is external, never local."""
        assert classifier.is_local is False
