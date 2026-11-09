"""Single source of truth for detecting + surfacing LLM output truncation.

Every LLM backend caps generation (``max_tokens`` / ``num_predict`` /
``maxOutputTokens``). A cap hit SILENTLY corrupts the output — a cut ``format:
json`` classify yields invalid JSON and the parse falls open (mis-classify, or a
multi-Topic ``topic_verdicts`` array overruns and the digest shows ZERO matches);
a cut draft/explanation ends mid-word — UNLESS the response's finish-reason is
checked. This was fixed for the Ollama backend but the audit (2026-06-12)
found the IDENTICAL pattern unfixed in every other backend (CIDI drift: openai-
compat, gemini, openai_direct, azure_openai). This module is the ONE truncation
check; the count-agnostic pin (``tests/test_llm_truncation_check_pin.py``) asserts
every capped backend routes its response through it, so the drift can't recur.

Per-family finish-reason shape:
  * openai  — ``body["choices"][0]["finish_reason"]``   truncated ⇒ ``"length"``
  * gemini  — ``body["candidates"][0]["finishReason"]`` truncated ⇒ ``"MAX_TOKENS"``
  * ollama  — ``body["done_reason"]``                    truncated ⇒ ``"length"``
A value NOT in the family's "clean" set (``stop`` / ``STOP`` / empty) is treated
as a non-clean finish worth surfacing (``length`` = truncated; ``load`` / ``SAFETY``
/ etc. = interrupted — the caller's answer is incomplete either way).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

# N-372 observability fold: in-process 1-hour rolling counter of unclean-finish
# events. Every backend routes truncation surfacing through this module, so ONE
# counter here covers ollama / openai / gemini uniformly. Surfaced at
# `/health/detail` via ``llm_truncated_1h()`` — see
# `web/routers/health.py::_compute_retry_queue_block`. The N-372 incident
# (2026-07-05) went 2 days with `_warn_if_llm_truncated` firing at WARNING
# UNOBSERVED; folding into /health closes that observability gap.

_TRUNCATION_LOCK = threading.Lock()
_TRUNCATION_EVENTS: deque[float] = deque()
_WINDOW_SEC = 3600.0


def _prune_expired(now_monotonic: float) -> None:
    """Drop events older than the window. Caller holds ``_TRUNCATION_LOCK``."""
    cutoff = now_monotonic - _WINDOW_SEC
    while _TRUNCATION_EVENTS and _TRUNCATION_EVENTS[0] < cutoff:
        _TRUNCATION_EVENTS.popleft()


def llm_truncated_1h() -> int:
    """Return the count of unclean-finish LLM events in the last 3600 seconds.

    Thread-safe. Prunes stale entries on read so the returned int is the
    live rolling-window count without a separate janitor task. Safe to call
    from the /health probe path (bounded work: at most ~N events per hour,
    single deque pass).
    """
    now = time.monotonic()
    with _TRUNCATION_LOCK:
        _prune_expired(now)
        return len(_TRUNCATION_EVENTS)


def _record_truncation() -> None:
    """Record one unclean-finish event at ``time.monotonic()``.

    Internal to :func:`warn_if_llm_truncated`; callers do not invoke directly.
    """
    now = time.monotonic()
    with _TRUNCATION_LOCK:
        _TRUNCATION_EVENTS.append(now)
        _prune_expired(now)


def _reset_for_test() -> None:
    """Clear the rolling-window state — test hook only."""
    with _TRUNCATION_LOCK:
        _TRUNCATION_EVENTS.clear()

#: family -> (path to the finish-reason in the response body, set of CLEAN values)
_FAMILY: dict[str, dict[str, Any]] = {
    "openai": {"path": ("choices", 0, "finish_reason"),
               "clean": {"stop", "tool_calls", "function_call", ""}},
    "gemini": {"path": ("candidates", 0, "finishReason"),
               "clean": {"STOP", ""}},
    "ollama": {"path": ("done_reason",),
               "clean": {"stop", ""}},
}


def _nav(body: Any, path: tuple) -> Any:
    cur = body
    for p in path:
        if isinstance(p, int):
            if isinstance(cur, (list, tuple)) and len(cur) > p:
                cur = cur[p]
            else:
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return None
    return cur


def llm_finish_reason(body: Any, family: str) -> str | None:
    """The response's finish-reason for ``family``, or ``None`` when absent."""
    spec = _FAMILY.get(family)
    if spec is None or not isinstance(body, dict):
        return None
    val = _nav(body, spec["path"])
    return str(val) if val else None


def is_llm_truncated(body: Any, family: str) -> bool:
    """True when the response did NOT finish cleanly (truncated / interrupted)."""
    spec = _FAMILY.get(family)
    if spec is None:
        return False
    r = llm_finish_reason(body, family)
    return bool(r) and r not in spec["clean"]


def warn_if_llm_truncated(
    body: Any, *, family: str, model: str, context: str, logger: Any,
) -> bool:
    """Surface a non-clean LLM finish — the  silent-truncation guard.

    Logs ONE WARNING (a single pre-formatted string — safe on both the stdlib
    ``logging`` logger AND the project ``TriageLogger``, per Prime Directive 
    no positional 2nd arg) when the finish-reason is not in the family's clean
    set. Returns True when unclean. Never raises into the caller.
    """
    r = llm_finish_reason(body, family)
    spec = _FAMILY.get(family) or {}
    clean = spec.get("clean") or {"stop", "STOP", ""}
    unclean = bool(r) and r not in clean
    if unclean:
        _record_truncation()  # N-372 observability fold — /health/detail signal
        msg = (
            f"LLM {context} did not finish cleanly (likely truncated) — "
            f"finish_reason={r}, model={model}, family={family}; "
            "the response may be incomplete"
        )
        try:
            logger.warning(msg)
        except Exception:  # noqa: BLE001 — never let logging break a classify
            pass
    return unclean
