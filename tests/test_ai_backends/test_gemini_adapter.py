"""Tests for the Gemini adapter (#171-A).

Covers the canonical W1-A ``chat_complete()`` contract + the OpenAI-
to-Gemini message translation + the :class:`Classifier`-ABC shim +
the token-shape privacy invariants.

HTTP is mocked end-to-end; no real Gemini calls.

Pattern mirrors ``tests/test_ai_backends/test_azure_openai.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from email_triage.ai_backends.gemini_adapter import (
    DEFAULT_GEMINI_BASE_URL,
    DEFAULT_GEMINI_MODEL,
    GeminiAdapter,
    GeminiAuthError,
    GeminiClassifierShim,
    GeminiError,
    _extract_gemini_text,
    _messages_to_gemini_contents,
    _strip_sensitive_query_params,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gemini_response(text: str) -> dict:
    """Render a successful Gemini generateContent response shape."""
    return {
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"text": text}],
            },
            "finishReason": "STOP",
        }],
        "usageMetadata": {"promptTokenCount": 50, "candidatesTokenCount": 12},
    }


def _patch_httpx(mock_resp):
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    cls_patch = patch(
        "email_triage.ai_backends.gemini_adapter.httpx.AsyncClient",
        return_value=mock_client,
    )
    return cls_patch, mock_client


# ---------------------------------------------------------------------------
# Constructor + introspection
# ---------------------------------------------------------------------------


class TestAdapterConstruction:
    def test_minimal_construction(self):
        a = GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            api_key="gemini-key",
        )
        assert a.endpoint == "https://generativelanguage.googleapis.com/v1beta"
        assert a.model == DEFAULT_GEMINI_MODEL
        # Gemini is always external; HIPAA gate stays closed pre-BAA.
        assert a.is_local is False
        assert a.backend_type == "gemini"

    def test_endpoint_trailing_slash_normalised(self):
        a = GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta/",
            api_key="gemini-key",
        )
        assert a.endpoint == "https://generativelanguage.googleapis.com/v1beta"

    def test_empty_endpoint_falls_back_to_default(self):
        a = GeminiAdapter(endpoint="", api_key="k")
        assert a.endpoint == DEFAULT_GEMINI_BASE_URL

    def test_none_endpoint_falls_back_to_default(self):
        a = GeminiAdapter(endpoint=None, api_key="k")
        assert a.endpoint == DEFAULT_GEMINI_BASE_URL

    def test_explicit_model_used(self):
        a = GeminiAdapter(api_key="k", model="gemini-2.5-pro")
        assert a.model == "gemini-2.5-pro"

    def test_default_model_is_stable_pick(self):
        assert DEFAULT_GEMINI_MODEL
        assert isinstance(DEFAULT_GEMINI_MODEL, str)

    def test_loader_signature_kwargs_accepted(self):
        """Loader passes ``endpoint`` / ``model`` / ``api_key`` /
        ``local_url_suffixes`` / ``backend_type`` — pin they're all
        accepted."""
        a = GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            model="gemini-2.0-flash",
            api_key="k",
            local_url_suffixes=[],
            backend_type="gemini",
        )
        assert a.model == "gemini-2.0-flash"


# ---------------------------------------------------------------------------
# Message translation — OpenAI → Gemini shape
# ---------------------------------------------------------------------------


class TestMessageTranslation:
    def test_user_message_to_user_role(self):
        sys, contents = _messages_to_gemini_contents([
            {"role": "user", "content": "hello"},
        ])
        assert sys is None
        assert contents == [
            {"role": "user", "parts": [{"text": "hello"}]},
        ]

    def test_assistant_role_becomes_model(self):
        """Gemini uses ``role=model`` for the assistant turn."""
        sys, contents = _messages_to_gemini_contents([
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": "a"},
        ])
        assert sys is None
        assert contents == [
            {"role": "user", "parts": [{"text": "q"}]},
            {"role": "model", "parts": [{"text": "a"}]},
        ]

    def test_system_message_folds_into_system_instruction(self):
        sys, contents = _messages_to_gemini_contents([
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "hi"},
        ])
        assert sys == {"parts": [{"text": "be brief"}]}
        assert contents == [
            {"role": "user", "parts": [{"text": "hi"}]},
        ]

    def test_multiple_system_messages_concatenate(self):
        """Rare but defensible — two system turns join with \\n\\n."""
        sys, contents = _messages_to_gemini_contents([
            {"role": "system", "content": "first rule"},
            {"role": "system", "content": "second rule"},
            {"role": "user", "content": "hi"},
        ])
        assert sys == {"parts": [{"text": "first rule\n\nsecond rule"}]}

    def test_empty_content_messages_skipped(self):
        """Empty content adds no value to the model — drop quietly."""
        sys, contents = _messages_to_gemini_contents([
            {"role": "system", "content": ""},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": ""},
        ])
        assert sys is None
        assert contents == [
            {"role": "user", "parts": [{"text": "hi"}]},
        ]

    def test_unknown_role_defaults_to_user(self):
        """Defensive — existing classifier paths don't produce unknown
        roles, but if a refactor ever did, treat as user."""
        sys, contents = _messages_to_gemini_contents([
            {"role": "tool", "content": "result"},
        ])
        assert sys is None
        assert contents == [
            {"role": "user", "parts": [{"text": "result"}]},
        ]


# ---------------------------------------------------------------------------
# _extract_gemini_text helper
# ---------------------------------------------------------------------------


class TestExtractText:
    def test_normal_response(self):
        body = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello!"}],
                    "role": "model",
                },
            }],
        }
        assert _extract_gemini_text(body) == "Hello!"

    def test_empty_candidates(self):
        assert _extract_gemini_text({"candidates": []}) == ""

    def test_no_candidates_key(self):
        assert _extract_gemini_text({}) == ""

    def test_empty_parts(self):
        body = {"candidates": [{"content": {"parts": []}}]}
        assert _extract_gemini_text(body) == ""

    def test_none_text(self):
        """A part with text=None coerces to '' rather than propagating None."""
        body = {"candidates": [{"content": {"parts": [{"text": None}]}}]}
        assert _extract_gemini_text(body) == ""


# ---------------------------------------------------------------------------
# chat_complete() — the canonical method
# ---------------------------------------------------------------------------


class TestChatComplete:
    @pytest.fixture
    def adapter(self):
        return GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            api_key="gemini-test-key",
            model="gemini-2.0-flash",
        )

    async def test_happy_path_returns_text(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("Hello world.")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        assert out == "Hello world."

    async def test_url_uses_model_generate_content(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        url = call.args[0] if call.args else call.kwargs.get("url", "")
        assert "gemini-2.0-flash" in url
        assert "generateContent" in url

    async def test_api_key_in_query_params(self, adapter):
        """Gemini auth is via ``?key=…``, NOT a header."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        params = mock_client.post.call_args.kwargs.get("params", {})
        assert params == {"key": "gemini-test-key"}
        # Belt-and-suspenders: never set a Bearer header on Gemini.
        headers = mock_client.post.call_args.kwargs.get("headers", {})
        assert "Authorization" not in headers
        assert "api-key" not in headers

    async def test_payload_uses_gemini_shape(self, adapter):
        """The OpenAI-style messages list translates to Gemini's
        ``contents`` + ``systemInstruction`` + ``generationConfig`` shape."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete([
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "hi"},
            ])
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert "contents" in body
        assert "systemInstruction" in body
        assert "generationConfig" in body
        assert body["contents"] == [
            {"role": "user", "parts": [{"text": "hi"}]},
        ]
        assert body["systemInstruction"] == {
            "parts": [{"text": "be brief"}],
        }

    async def test_no_system_instruction_when_no_system_msg(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete([
                {"role": "user", "content": "hi"},
            ])
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert "systemInstruction" not in body

    async def test_response_format_json_string_sets_mime_type(self, adapter):
        """``response_format='json'`` (portable string form) sets the
        Gemini-native ``responseMimeType`` knob."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response('{"k":"v"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "give me json"}],
                response_format="json",
            )
        assert out == '{"k":"v"}'
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["generationConfig"]["responseMimeType"] == "application/json"

    async def test_response_format_json_object_dict(self, adapter):
        """OpenAI-style ``{"type":"json_object"}`` translates to the
        Gemini ``responseMimeType`` knob."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response('{"k":"v"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "json"}],
                response_format={"type": "json_object"},
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["generationConfig"]["responseMimeType"] == "application/json"

    async def test_response_format_json_schema_unwrapped(self, adapter):
        """OpenAI-style ``{"type": "json_schema", "json_schema":
        {"schema": ...}}`` unwraps to Gemini's
        ``generationConfig.responseSchema``."""
        schema = {
            "type": "object",
            "properties": {
                "category": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["category"],
        }
        response_format = {
            "type": "json_schema",
            "json_schema": {"name": "classification", "schema": schema},
        }
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response('{"category":"fyi"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "classify"}],
                response_format=response_format,
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        # The inner schema lands in responseSchema; the mime type also
        # gets set so the model knows to produce JSON.
        assert body["generationConfig"]["responseSchema"] == schema
        assert body["generationConfig"]["responseMimeType"] == "application/json"

    async def test_max_tokens_and_temperature_override(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=512,
                temperature=0.0,
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        gc = body["generationConfig"]
        assert gc["maxOutputTokens"] == 512
        assert gc["temperature"] == 0.0

    async def test_extra_kwargs_passthrough_into_generation_config(self, adapter):
        """Additional Gemini generationConfig fields (topP, topK)
        pass-through under the right key."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
                topP=0.9,
                topK=40,
            )
        gc = mock_client.post.call_args.kwargs.get("json", {})["generationConfig"]
        assert gc["topP"] == 0.9
        assert gc["topK"] == 40

    async def test_empty_messages_raises_before_http(self, adapter):
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(ValueError, match="messages"):
                await adapter.chat_complete([])
        assert mock_client.post.call_count == 0

    async def test_empty_api_key_raises_before_http(self):
        adapter = GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            api_key="",
            model="gemini-2.0-flash",
        )
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(ValueError, match="api_key"):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert mock_client.post.call_count == 0

    async def test_complete_alias(self, adapter):
        """``.complete(prompt)`` wraps ``chat_complete`` with a single
        user-role message — Classifier-ABC compatibility surface."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response("answered")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.complete("the prompt")
        assert out == "answered"
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["contents"] == [
            {"role": "user", "parts": [{"text": "the prompt"}]},
        ]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @pytest.fixture
    def adapter(self):
        return GeminiAdapter(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            api_key="gemini-k",
            model="gemini-2.0-flash",
        )

    async def test_401_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": {"code": 401, "message": "Unauthorized"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiAuthError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert isinstance(ei.value, GeminiError)
        assert ei.value.status == 401

    async def test_403_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {"code": 403, "message": "PERMISSION_DENIED"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiAuthError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )

    async def test_400_invalid_key_treated_as_auth(self, adapter):
        """Google AI Studio returns 400 INVALID_ARGUMENT with message
        "API key not valid" for bad keys — treat as auth, not as a
        generic 400."""
        mock_resp = Mock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            "error": {
                "code": 400,
                "message": "API key not valid. Please pass a valid API key.",
                "status": "INVALID_ARGUMENT",
            }
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiAuthError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )

    async def test_400_other_message_is_generic_error(self, adapter):
        """A 400 with a non-auth message stays a generic error."""
        mock_resp = Mock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            "error": {
                "code": 400,
                "message": "Invalid argument: contents must be non-empty",
                "status": "INVALID_ARGUMENT",
            }
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert not isinstance(ei.value, GeminiAuthError)
        assert ei.value.status == 400

    async def test_500_raises_generic_error_not_auth(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {
            "error": {"code": 500, "message": "Internal server error"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert not isinstance(ei.value, GeminiAuthError)
        assert ei.value.status == 500

    async def test_non_json_error_body_handled(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 502
        mock_resp.json.side_effect = ValueError("not json")
        mock_resp.text = "<html>bad gateway</html>"
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert ei.value.status == 502

    async def test_200_with_no_candidates_raises(self, adapter):
        """Safety-filter trip: 200 + empty candidates = error, not silent ''."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [],
            "promptFeedback": {"blockReason": "SAFETY"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(GeminiError):
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
            with pytest.raises(GeminiError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )


# ---------------------------------------------------------------------------
# Privacy invariants — token-shape scrub + ``?key=…`` URL scrub
# ---------------------------------------------------------------------------


_TEST_ACCESS_TOKEN = "TEST_ACCESS_TOKEN_DO_NOT_LEAK_aa1111"
_TEST_REFRESH_TOKEN = "TEST_REFRESH_TOKEN_DO_NOT_LEAK_bb2222"
_TEST_ID_TOKEN = "TEST_ID_TOKEN_DO_NOT_LEAK_cc3333"
_TEST_API_KEY = "TEST_API_KEY_DO_NOT_LEAK_dd4444"
_TEST_CLIENT_SECRET = "TEST_CLIENT_SECRET_DO_NOT_LEAK_ee5555"
_TEST_PASSWORD = "TEST_PASSWORD_DO_NOT_LEAK_ff6666"
_TEST_SESSION_TOKEN = "TEST_SESSION_TOKEN_DO_NOT_LEAK_gg7777"


class TestPrivacyInvariants:
    def test_error_message_scrubs_token_shape_keys(self):
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "id_token": _TEST_ID_TOKEN,
            "api_key": _TEST_API_KEY,
            "client_secret": _TEST_CLIENT_SECRET,
            "password": _TEST_PASSWORD,
            "session_token": _TEST_SESSION_TOKEN,
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        err = GeminiError(
            500, body,
            "https://generativelanguage.googleapis.com/v1beta/x",
        )
        rendered = str(err)
        for sentinel in (
            _TEST_ACCESS_TOKEN, _TEST_REFRESH_TOKEN, _TEST_ID_TOKEN,
            _TEST_API_KEY, _TEST_CLIENT_SECRET, _TEST_PASSWORD,
            _TEST_SESSION_TOKEN,
        ):
            assert sentinel not in rendered, (
                f"Token-shape value '{sentinel}' leaked into exception "
                f"message: {rendered!r}"
            )
        assert "expires_in" in rendered
        assert "Bearer" in rendered

    def test_error_scrub_covers_all_canonical_token_keys(self):
        """Sweep every entry in TriageLogger._TOKEN_KEYS."""
        from email_triage.triage_logging import TriageLogger
        for key in TriageLogger._TOKEN_KEYS:
            sentinel = f"SENTINEL_{key}_DO_NOT_LEAK_zzz"
            body = {key: sentinel}
            err = GeminiError(500, body, "")
            rendered = str(err)
            assert sentinel not in rendered, (
                f"Token-shape value for key '{key}' leaked into "
                f"exception message: {rendered!r}"
            )

    def test_auth_error_inherits_scrub(self):
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "error": {"message": "API key not valid"},
        }
        err = GeminiAuthError(401, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert "API key not valid" in rendered

    def test_error_url_strips_api_key_query_param(self):
        """Gemini's auth is via ``?key=…`` — every real call carries
        the plaintext key in the URL. The rendered exception MUST
        scrub it; this is not defence-in-depth, it's the primary
        protection."""
        leaked_url = (
            "https://generativelanguage.googleapis.com/v1beta/"
            "models/gemini-2.0-flash:generateContent?"
            "key=SECRET_GEMINI_KEY_VALUE_NEVER_LOG"
        )
        err = GeminiError(500, {"error": {"message": "boom"}}, leaked_url)
        rendered = str(err)
        assert "SECRET_GEMINI_KEY_VALUE_NEVER_LOG" not in rendered
        assert "REDACTED" in rendered

    def test_error_with_no_error_key_falls_back_to_safe_body(self):
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "model": "gemini-2.0-flash",
        }
        err = GeminiError(500, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert "gemini-2.0-flash" in rendered

    def test_error_with_non_dict_body_unchanged(self):
        body = "Upstream proxy returned plain text"
        err = GeminiError(502, body, "")
        rendered = str(err)
        assert "Upstream proxy returned plain text" in rendered

    @pytest.mark.asyncio
    async def test_arbitrary_auth_response_dict_no_token_leak(self):
        """End-to-end privacy invariant."""
        auth_response = {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "id_token": _TEST_ID_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
        }
        err = GeminiError(200, auth_response, "")
        rendered = str(err)
        for sentinel in (
            _TEST_ACCESS_TOKEN, _TEST_REFRESH_TOKEN, _TEST_ID_TOKEN,
        ):
            assert sentinel not in rendered

    def test_strip_sensitive_query_params_handles_no_query(self):
        url = "https://x/y"
        assert _strip_sensitive_query_params(url) == url

    def test_strip_sensitive_query_params_handles_empty(self):
        assert _strip_sensitive_query_params("") == ""

    def test_strip_sensitive_query_params_covers_alternates(self):
        url = "https://x/?key=KKK&token=TTT&access_token=AAA&code=CCC&foo=bar"
        out = _strip_sensitive_query_params(url)
        assert "KKK" not in out
        assert "TTT" not in out
        assert "AAA" not in out
        assert "CCC" not in out
        assert "foo=bar" in out


# ---------------------------------------------------------------------------
# GeminiClassifierShim — Classifier-ABC shim sanity
# ---------------------------------------------------------------------------


class TestClassifierShim:
    @pytest.fixture
    def classifier(self):
        return GeminiClassifierShim(
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            api_key="gem-k",
            model="gemini-2.0-flash",
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
        mock_resp.json.return_value = _gemini_response(json.dumps({
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

    async def test_shim_uses_key_query_param(self, classifier):
        """Pin that the shim routes auth via the ``?key=…`` query
        param (regression guard against an accidental flip to Bearer
        or api-key header)."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _gemini_response(json.dumps({
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
        params = mock_client.post.call_args.kwargs.get("params", {})
        assert params.get("key") == "gem-k"
        headers = mock_client.post.call_args.kwargs.get("headers", {})
        assert "Authorization" not in headers

    def test_shim_marks_is_local_false(self, classifier):
        """Gemini is always external — HIPAA gate posture."""
        assert classifier.is_local is False
