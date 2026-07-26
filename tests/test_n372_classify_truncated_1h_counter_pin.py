"""N-372 observability fold — classify_truncated_1h counter pin.

The 2026-07-05 incident (row 276 FedEx / Ollama upstream #15260 schema
bypass) went 2 days with `_warn_if_llm_truncated` firing at WARNING
unobserved. The fix folds a rolling 1-hour count of unclean-finish
events into `/health/detail`'s retry-queue block so a spike surfaces
via the monitoring system polling instead of only in raw log entries.

This pin protects the wire:

  (1) the counter SSOT lives at the truncation-detection layer
      (`email_triage.llm_truncation`) — one counter, all backends;
  (2) an unclean finish increments; a clean finish does not;
  (3) `/health/detail`'s `_compute_retry_queue_block` surfaces the
      counter under the `classify_truncated_1h` key.

Keep the pin count-agnostic on the shape (AST-scan the health.py source
for both the import and the return-dict key) so a rename anywhere fails
this pin cleanly.
"""
from __future__ import annotations

import ast
import threading
from pathlib import Path

import pytest

from email_triage import llm_truncation as _llm_trunc
from email_triage.llm_truncation import (
    _record_truncation,
    _reset_for_test,
    llm_truncated_1h,
    warn_if_llm_truncated,
)


class _NullLogger:
    """Minimal logger that swallows every call — the SSOT never raises."""

    def warning(self, *args, **kwargs) -> None:
        pass


@pytest.fixture(autouse=True)
def _reset_counter():
    _reset_for_test()
    yield
    _reset_for_test()


def test_counter_starts_at_zero_after_reset() -> None:
    assert llm_truncated_1h() == 0


def test_unclean_ollama_finish_increments_counter() -> None:
    body = {"done_reason": "length"}
    r = warn_if_llm_truncated(
        body, family="ollama", model="qwen3.6:35b",
        context="classify", logger=_NullLogger(),
    )
    assert r is True
    assert llm_truncated_1h() == 1


def test_clean_ollama_finish_does_not_increment() -> None:
    body = {"done_reason": "stop"}
    r = warn_if_llm_truncated(
        body, family="ollama", model="qwen3.6:35b",
        context="classify", logger=_NullLogger(),
    )
    assert r is False
    assert llm_truncated_1h() == 0


def test_multi_backend_share_counter() -> None:
    """Ollama + OpenAI + Gemini truncations all count into the SAME counter."""
    warn_if_llm_truncated(
        {"done_reason": "length"}, family="ollama",
        model="qwen3.6:35b", context="classify", logger=_NullLogger(),
    )
    warn_if_llm_truncated(
        {"choices": [{"finish_reason": "length"}]}, family="openai",
        model="gpt-4", context="classify", logger=_NullLogger(),
    )
    warn_if_llm_truncated(
        {"candidates": [{"finishReason": "MAX_TOKENS"}]}, family="gemini",
        model="gemini-2.0", context="classify", logger=_NullLogger(),
    )
    assert llm_truncated_1h() == 3


def test_thread_safety_bounded() -> None:
    """100 threads recording 1 event each yields exactly 100. Deque + lock."""
    N = 100
    barrier = threading.Barrier(N)

    def _worker() -> None:
        barrier.wait()
        _record_truncation()

    threads = [threading.Thread(target=_worker) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert llm_truncated_1h() == N


def test_reset_for_test_clears_counter() -> None:
    _record_truncation()
    _record_truncation()
    assert llm_truncated_1h() == 2
    _reset_for_test()
    assert llm_truncated_1h() == 0


def _health_source() -> str:
    p = (
        Path(__file__).resolve().parent.parent
        / "src" / "email_triage" / "web" / "routers" / "health.py"
    )
    return p.read_text(encoding="utf-8")


def test_health_module_imports_llm_truncated_1h() -> None:
    """Structural: health.py must import the counter at module scope."""
    tree = ast.parse(_health_source())
    imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "email_triage.llm_truncation":
                for alias in node.names:
                    if alias.name == "llm_truncated_1h":
                        imported = True
                        break
    assert imported, (
        "health.py must `from email_triage.llm_truncation import "
        "llm_truncated_1h` for the N-372 observability fold."
    )


def test_health_retry_queue_block_returns_classify_truncated_1h_key() -> None:
    """Structural: `_compute_retry_queue_block` must return a dict with the key."""
    tree = ast.parse(_health_source())
    found = False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == "_compute_retry_queue_block"
        ):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(
                    sub.value, ast.Dict,
                ):
                    keys = [
                        k.value for k in sub.value.keys
                        if isinstance(k, ast.Constant)
                    ]
                    if "classify_truncated_1h" in keys:
                        found = True
                        break
    assert found, (
        "_compute_retry_queue_block's return dict must include the key "
        "'classify_truncated_1h' for the N-372 observability fold."
    )
