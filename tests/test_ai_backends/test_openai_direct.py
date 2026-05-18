"""Tests for the OpenAI direct adapter (#171-A).

Covers the canonical W1-A ``chat_complete()`` contract + the
:class:`Classifier`-ABC shim + the token-shape privacy invariants.

HTTP is mocked end-to-end; no real OpenAI calls.

Pattern mirrors ``tests/test_ai_backends/test_azure_openai.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from email_triage.ai_backends.openai_direct import (
    DEFAULT_OPENAI_BASE_URL,
    DEFAULT_OPENAI_MODEL,
    OpenAIAdapter,
    OpenAIAuthError,
    OpenAIClassifier,
    OpenAIError,
    _strip_sensitive_query_params,
)


# ---------------------------------------------------------------------------
# Helpers — match the pattern in tests/test_ai_backends/test_azure_openai.py
# ---------------------------------------------------------------------------


def _openai_response(content: str) -> dict:
    """Render a successful OpenAI chat-completion response shape."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
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
        "email_triage.ai_backends.openai_direct.httpx.AsyncClient",
        return_value=mock_client,
    )
    return cls_patch, mock_client


# ---------------------------------------------------------------------------
# Constructor + introspection
# ---------------------------------------------------------------------------


class TestAdapterConstruction:
    def test_minimal_construction(self):
        a = OpenAIAdapter(
            endpoint="https://api.openai.com/v1",
            api_key="sk-test",
        )
        assert a.endpoint == "https://api.openai.com/v1"
        assert a.model == DEFAULT_OPENAI_MODEL
        # Public OpenAI is external; HIPAA gate stays closed pre-BAA.
        assert a.is_local is False
        # backend_type is set on the class (registry lookup key).
        assert a.backend_type == "openai"

    def test_endpoint_trailing_slash_normalised(self):
        a = OpenAIAdapter(
            endpoint="https://api.openai.com/v1/",
            api_key="sk-test",
        )
        assert a.endpoint == "https://api.openai.com/v1"

    def test_empty_endpoint_falls_back_to_default(self):
        """An empty endpoint legitimately falls through to public OpenAI.

        Lets an ``ai_backends`` row with NULL ``endpoint`` for the
        public service Just Work without operator wiring.
        """
        a = OpenAIAdapter(endpoint="", api_key="sk-x")
        assert a.endpoint == DEFAULT_OPENAI_BASE_URL

    def test_none_endpoint_falls_back_to_default(self):
        a = OpenAIAdapter(endpoint=None, api_key="sk-x")
        assert a.endpoint == DEFAULT_OPENAI_BASE_URL

    def test_local_endpoint_marks_is_local_true(self):
        """LAN proxy hits the local-host helper and lights up
        ``is_local`` so the HIPAA gate stays open."""
        a = OpenAIAdapter(
            endpoint="http://localhost:8000/v1",
            api_key="",
        )
        assert a.is_local is True

    def test_rfc1918_endpoint_marks_is_local_true(self):
        a = OpenAIAdapter(
            endpoint="http://192.168.1.10:8000/v1",
            api_key="",
        )
        assert a.is_local is True

    def test_extra_suffix_marks_is_local_true(self):
        a = OpenAIAdapter(
            endpoint="https://litellm.home.lan/v1",
            api_key="",
            local_url_suffixes=[".home.lan"],
        )
        assert a.is_local is True

    def test_default_model_is_stable_pick(self):
        """The shipped default must be a non-empty model name.

        Pins the deliberate choice in the module docstring against an
        accidental flip to a moving target.
        """
        assert DEFAULT_OPENAI_MODEL
        assert isinstance(DEFAULT_OPENAI_MODEL, str)

    def test_loader_signature_kwargs_accepted(self):
        """The loader hands the adapter constructor a uniform kwargs
        bundle (``endpoint``, ``model``, ``api_key``, ``local_url_suffixes``,
        ``backend_type``). Pin that the adapter accepts them all without
        raising on the ``backend_type`` extra."""
        a = OpenAIAdapter(
            endpoint="https://api.openai.com/v1",
            model="gpt-4o",
            api_key="sk-x",
            local_url_suffixes=[],
            backend_type="openai",  # extra from loader; must be accepted
        )
        assert a.model == "gpt-4o"


# ---------------------------------------------------------------------------
# chat_complete() — the canonical method
# ---------------------------------------------------------------------------


class TestChatComplete:
    @pytest.fixture
    def adapter(self):
        return OpenAIAdapter(
            endpoint="https://api.openai.com/v1",
            api_key="sk-test-key",
            model="gpt-4o-mini",
        )

    async def test_happy_path_returns_content(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("Hello world.")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        assert out == "Hello world."

    async def test_correct_endpoint(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        url = call.args[0] if call.args else call.kwargs.get("url", "")
        assert url == "https://api.openai.com/v1/chat/completions"

    async def test_sends_bearer_auth_header(self, adapter):
        """OpenAI uses ``Authorization: Bearer``; pin that the adapter
        forms the header correctly."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        call = mock_client.post.call_args
        headers = call.kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer sk-test-key"

    async def test_no_auth_header_when_api_key_empty(self):
        """LAN proxies that don't require auth: empty api_key → no
        Authorization header on the request.

        This is different from Azure (which requires a key); on OpenAI-
        compatible self-hosted servers the auth header is optional.
        """
        adapter = OpenAIAdapter(
            endpoint="http://localhost:8000/v1",
            api_key="",
        )
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        headers = mock_client.post.call_args.kwargs.get("headers", {})
        assert "Authorization" not in headers

    async def test_model_in_body(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "hi"}],
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["model"] == "gpt-4o-mini"

    async def test_response_format_json_object(self, adapter):
        """``response_format={"type":"json_object"}`` propagates verbatim."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response('{"k":"v"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            out = await adapter.chat_complete(
                [{"role": "user", "content": "give me json"}],
                response_format={"type": "json_object"},
            )
        assert out == '{"k":"v"}'
        assert json.loads(out) == {"k": "v"}
        call = mock_client.post.call_args
        body = call.kwargs.get("json", {})
        assert body["response_format"] == {"type": "json_object"}

    async def test_response_format_json_schema(self, adapter):
        """Strict schema-mode propagates verbatim."""
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
        mock_resp.json.return_value = _openai_response('{"category":"fyi"}')
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "classify"}],
                response_format=schema,
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        # Pass-through unchanged — adapter must not mangle the shape.
        assert body["response_format"] == schema

    async def test_max_tokens_and_temperature_override(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
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
        mock_resp.json.return_value = _openai_response("ok")
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
        convention raises ``TypeError`` before the function body runs."""
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(TypeError, match="messages"):
                await adapter.chat_complete(
                    [{"role": "user", "content": "real"}],
                    messages=[{"role": "user", "content": "shadow"}],
                )
        assert mock_client.post.call_count == 0

    async def test_kwargs_cannot_clobber_model_set_from_adapter(self, adapter):
        """The in-body loop filters out kwargs whose name matches a
        body field already populated from adapter state (``model``,
        ``temperature``, ``max_tokens``)."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("ok")
        cls_patch, mock_client = _patch_httpx(mock_resp)
        with cls_patch:
            await adapter.chat_complete(
                [{"role": "user", "content": "real"}],
                model="gpt-5-rogue",  # kwargs — must NOT clobber.
            )
        body = mock_client.post.call_args.kwargs.get("json", {})
        assert body["model"] == "gpt-4o-mini"

    async def test_empty_messages_raises_before_http(self, adapter):
        """An empty messages list must raise BEFORE the HTTP call."""
        cls_patch, mock_client = _patch_httpx(Mock())
        with cls_patch:
            with pytest.raises(ValueError, match="messages"):
                await adapter.chat_complete([])
        assert mock_client.post.call_count == 0

    async def test_complete_alias(self, adapter):
        """``.complete(prompt)`` wraps ``chat_complete`` with a single
        user-role message."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response("answered")
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
        return OpenAIAdapter(
            endpoint="https://api.openai.com/v1",
            api_key="sk-test",
        )

    async def test_401_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": {
                "code": "invalid_api_key",
                "message": "Incorrect API key provided",
                "type": "invalid_request_error",
            }
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(OpenAIAuthError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert isinstance(ei.value, OpenAIError)
        assert ei.value.status == 401
        assert "Incorrect API key" in str(ei.value)

    async def test_403_raises_auth_error(self, adapter):
        mock_resp = Mock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {"code": "403", "message": "Forbidden"},
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(OpenAIAuthError):
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
            with pytest.raises(OpenAIError) as ei:
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )
        assert not isinstance(ei.value, OpenAIAuthError)
        assert ei.value.status == 500

    async def test_non_json_error_body_handled(self, adapter):
        """An upstream proxy / gateway error returns text, not JSON."""
        mock_resp = Mock()
        mock_resp.status_code = 502
        mock_resp.json.side_effect = ValueError("not json")
        mock_resp.text = "<html>bad gateway</html>"
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(OpenAIError) as ei:
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
        }
        cls_patch, _ = _patch_httpx(mock_resp)
        with cls_patch:
            with pytest.raises(OpenAIError):
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
            with pytest.raises(OpenAIError):
                await adapter.chat_complete(
                    [{"role": "user", "content": "hi"}],
                )


# ---------------------------------------------------------------------------
# Privacy invariants — token-shape scrub at exception construction time.
# Mirrors the GmailApiError #168 hardening pattern + the
# AzureOpenAIError sibling tests.
# ---------------------------------------------------------------------------


# Sentinel values — visually distinct so a substring search is unambiguous.
# NEVER use real-shape tokens here.
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
        err = OpenAIError(500, body, "https://api.openai.com/v1/x")
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
        """Sweep every entry in TriageLogger._TOKEN_KEYS — any future
        addition to the canonical frozenset must inherit the scrub
        automatically."""
        from email_triage.triage_logging import TriageLogger
        for key in TriageLogger._TOKEN_KEYS:
            sentinel = f"SENTINEL_{key}_DO_NOT_LEAK_zzz"
            body = {key: sentinel}
            err = OpenAIError(500, body, "")
            rendered = str(err)
            assert sentinel not in rendered, (
                f"Token-shape value for key '{key}' leaked into "
                f"exception message: {rendered!r}"
            )

    def test_auth_error_inherits_scrub(self):
        """``OpenAIAuthError`` subclasses ``OpenAIError`` and has no
        ``__init__`` override — pin that it inherits the scrub so a
        future refactor that adds an override doesn't silently strip
        the defence."""
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "error": {"message": "invalid key"},
        }
        err = OpenAIAuthError(401, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert "invalid key" in rendered

    def test_error_with_no_error_key_falls_back_to_safe_body(self):
        """When the body dict has no ``error`` key, the constructor
        falls back to ``str(safe_body)`` — pin that the safe_body
        version (not the raw body) is what gets stringified."""
        body = {
            "access_token": _TEST_ACCESS_TOKEN,
            "model": "gpt-4o",
        }
        err = OpenAIError(500, body, "")
        rendered = str(err)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert "gpt-4o" in rendered

    def test_error_with_non_dict_body_unchanged(self):
        """Non-dict bodies (string error, list) stringify unchanged."""
        body = "Upstream proxy returned plain text"
        err = OpenAIError(502, body, "")
        rendered = str(err)
        assert "Upstream proxy returned plain text" in rendered

    @pytest.mark.asyncio
    async def test_arbitrary_auth_response_dict_no_token_leak(self):
        """End-to-end privacy invariant: simulate an OAuth token
        response landing in the error path. Construct from an
        arbitrary auth-response dict; rendered exception must scrub
        every token-shape value."""
        auth_response = {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "id_token": _TEST_ID_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
            "scope": "openai/all",
        }
        # No "error" key — adapter's defensive constructor must still scrub.
        err = OpenAIError(200, auth_response, "")
        rendered = str(err)
        for sentinel in (
            _TEST_ACCESS_TOKEN, _TEST_REFRESH_TOKEN, _TEST_ID_TOKEN,
        ):
            assert sentinel not in rendered, (
                f"Token leaked: {sentinel!r} in {rendered!r}"
            )

    def test_url_strips_sensitive_query_params(self):
        """If a future refactor ever puts the api-key in the URL query
        string, the rendered exception must redact it."""
        leaked_url = (
            "https://api.openai.com/v1/chat/completions?"
            "api-key=SECRET_KEY_VALUE_NEVER_LOG&model=gpt-4o"
        )
        err = OpenAIError(500, {"error": {"message": "boom"}}, leaked_url)
        rendered = str(err)
        assert "SECRET_KEY_VALUE_NEVER_LOG" not in rendered
        assert "REDACTED" in rendered
        # Non-sensitive query params survive.
        assert "model=gpt-4o" in rendered

    def test_strip_sensitive_query_params_handles_no_query(self):
        url = "https://api.openai.com/v1/x"
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
# OpenAIClassifier — Classifier-ABC shim sanity
# ---------------------------------------------------------------------------


class TestClassifierShim:
    """End-to-end: the shim should call the adapter and parse the JSON
    reply into a ``Classification``."""

    @pytest.fixture
    def classifier(self):
        return OpenAIClassifier(
            endpoint="https://api.openai.com/v1",
            api_key="sk-test",
            model="gpt-4o-mini",
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
        mock_resp.json.return_value = _openai_response(json.dumps({
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

    async def test_shim_uses_bearer_auth_header(self, classifier):
        """Pin that the shim routes through the OpenAI-canonical
        Authorization: Bearer header (regression guard against a
        future refactor that swaps in the Azure ``api-key`` shape)."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _openai_response(json.dumps({
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
        assert headers.get("Authorization") == "Bearer sk-test"
        # No Azure-style api-key header on a public-OpenAI shim.
        assert "api-key" not in headers

    def test_shim_marks_is_local_false_on_public_endpoint(self, classifier):
        """HIPAA gate posture — public OpenAI is external, never local."""
        assert classifier.is_local is False

    def test_shim_marks_is_local_true_on_lan_endpoint(self):
        """LAN proxy endpoints flip is_local True; HIPAA gate stays
        open without a BAA on file."""
        c = OpenAIClassifier(
            endpoint="http://localhost:8000/v1",
            api_key="",
        )
        assert c.is_local is True
