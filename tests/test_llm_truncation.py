"""Unit tests for the cross-backend LLM truncation SSOT."""

from __future__ import annotations

import logging

from email_triage.llm_truncation import (
    is_llm_truncated, llm_finish_reason, warn_if_llm_truncated,
)


class _CapLog:
    def __init__(self): self.msgs = []
    def warning(self, msg, *a, **k): self.msgs.append(str(msg))


class TestFinishReasonPerFamily:
    def test_openai_length_is_truncated(self):
        body = {"choices": [{"finish_reason": "length",
                             "message": {"content": "{partial"}}]}
        assert llm_finish_reason(body, "openai") == "length"
        assert is_llm_truncated(body, "openai") is True

    def test_openai_stop_is_clean(self):
        body = {"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}
        assert is_llm_truncated(body, "openai") is False

    def test_gemini_max_tokens_is_truncated(self):
        body = {"candidates": [{"finishReason": "MAX_TOKENS"}]}
        assert llm_finish_reason(body, "gemini") == "MAX_TOKENS"
        assert is_llm_truncated(body, "gemini") is True

    def test_gemini_stop_is_clean(self):
        body = {"candidates": [{"finishReason": "STOP"}]}
        assert is_llm_truncated(body, "gemini") is False

    def test_ollama_length_is_truncated(self):
        assert is_llm_truncated({"done_reason": "length"}, "ollama") is True
        assert is_llm_truncated({"done_reason": "stop"}, "ollama") is False

    def test_missing_or_malformed_is_not_truncated(self):
        assert is_llm_truncated({}, "openai") is False
        assert is_llm_truncated(None, "openai") is False
        assert is_llm_truncated({"choices": []}, "openai") is False
        assert llm_finish_reason("not a dict", "openai") is None
        assert is_llm_truncated({"done_reason": "x"}, "unknown-family") is False


class TestWarnIfTruncated:
    def test_logs_once_on_truncation_returns_true(self):
        lg = _CapLog()
        hit = warn_if_llm_truncated(
            {"choices": [{"finish_reason": "length"}]},
            family="openai", model="gpt-x", context="classify", logger=lg,
        )
        assert hit is True
        assert len(lg.msgs) == 1 and "did not finish cleanly" in lg.msgs[0]

    def test_clean_finish_no_log_returns_false(self):
        lg = _CapLog()
        hit = warn_if_llm_truncated(
            {"choices": [{"finish_reason": "stop"}]},
            family="openai", model="gpt-x", context="classify", logger=lg,
        )
        assert hit is False and lg.msgs == []

    def test_never_raises_on_bad_logger(self):
        class _Boom:
            def warning(self, *a, **k): raise RuntimeError("logger down")
        # A broken logger must not break the classify path.
        assert warn_if_llm_truncated(
            {"candidates": [{"finishReason": "MAX_TOKENS"}]},
            family="gemini", model="m", context="c", logger=_Boom(),
        ) is True

    def test_single_string_arg_safe_for_triagelogger(self):
        # The guard must call logger.warning(ONE string) — never a positional
        # 2nd arg (Prime Directive  TriageLogger exc_info trap).
        seen = {}
        class _Strict:
            def warning(self, msg, *args, **kwargs):
                seen["args"] = args; seen["kwargs"] = kwargs
        warn_if_llm_truncated(
            {"done_reason": "length"}, family="ollama", model="m",
            context="topic-match", logger=_Strict(),
        )
        assert seen["args"] == () and seen["kwargs"] == {}
