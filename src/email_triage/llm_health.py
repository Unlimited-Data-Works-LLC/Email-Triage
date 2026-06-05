"""LLM backend health cache.

A small, in-process registry that records "this LLM backend is
unreachable" with a TTL. The classify path calls
:func:`set_unhealthy` when an :class:`LLMBackendUnreachableError`
fires, and watcher / triage entry points call :func:`is_healthy`
before paying for a classifier round-trip — when False, the
consolidated retry-queue drainer skips ``failure_kind='llm_unreachable'``
rows on that tick (``watcher_retry_queue``) instead of burning
connection-attempt latency repeatedly against a dead backend.

Process-memory only. We deliberately do NOT persist this state to
disk: a stuck-unhealthy state should never survive a restart. If
the operator bounces the process to fix something, the next probe
gets a fresh chance. Persisting would create a class of bug where
the cache outlives the cause.

Concurrency model: the dict is read-mostly. Multiple coroutines may
read concurrently; writes are infrequent (one per classifier failure
+ one per maintenance-window transition). The GIL plus the simple
dict mutation pattern ("set whole tuple under key") is enough — we
do not need a lock here.

Sibling drawer: ``feedback_no_anthropic.md`` (Anthropic API is not
a supported LLM backend on this install — same reasoning that this
module is provider-neutral; treat any future Anthropic backend the
same way Ollama is treated).
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Optional


_log = logging.getLogger("email_triage.llm_health")


@dataclass
class _UnhealthyEntry:
    """In-memory record of an LLM backend's circuit-breaker state."""
    unhealthy_since: float    # monotonic seconds
    unhealthy_until: float    # monotonic seconds
    reason: str               # operator-readable explanation
    wall_unhealthy_since: float  # time.time() epoch — for UI banner display


# ``_STATE`` is keyed by backend name (e.g. ``"ollama"``). Process
# memory only; never written to disk.
_STATE: dict[str, _UnhealthyEntry] = {}


# ---------------------------------------------------------------------------
# Typed exception raised by the classify wrapper
# ---------------------------------------------------------------------------

class LLMBackendUnreachableError(Exception):
    """The configured LLM backend could not be reached.

    Wraps the underlying ``httpx.ConnectError`` /
    ``"All connection attempts failed"`` shape so the watcher /
    triage path can distinguish "infrastructure weather" from a
    genuine classifier error (bad prompt / decode failure / etc).

    Carries enough context to render a clear operator-facing
    message: "Ollama unreachable: <host>:11434" instead of the
    generic httpx wording.
    """

    def __init__(
        self,
        backend: str,
        host: str,
        port: int,
        original: Exception | None = None,
    ):
        self.backend = backend
        self.host = host
        self.port = port
        self.original = original
        super().__init__(f"{backend} unreachable: {host}:{port}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_unhealthy(
    backend_name: str,
    *,
    ttl_seconds: float = 300.0,
    reason: str = "",
) -> None:
    """Mark ``backend_name`` unhealthy for ``ttl_seconds``.

    Subsequent :func:`is_healthy` calls return False until the TTL
    elapses. Repeated calls extend / reset the TTL — the most
    recent failure wins.
    """
    now_mono = time.monotonic()
    now_wall = time.time()
    existing = _STATE.get(backend_name)
    # Preserve the original ``unhealthy_since`` across re-marks so
    # the operator-facing banner can show "unreachable since HH:MM"
    # without the timestamp jumping every retry.
    since_mono = existing.unhealthy_since if existing else now_mono
    since_wall = existing.wall_unhealthy_since if existing else now_wall
    _STATE[backend_name] = _UnhealthyEntry(
        unhealthy_since=since_mono,
        unhealthy_until=now_mono + max(0.0, float(ttl_seconds)),
        reason=str(reason or ""),
        wall_unhealthy_since=since_wall,
    )
    _log.info(
        "LLM backend marked unhealthy",
        extra={"_extra": {
            "backend": backend_name,
            "ttl_seconds": ttl_seconds,
            "reason": (reason or "")[:200],
        }},
    )


def clear_unhealthy(backend_name: str) -> None:
    """Forget the unhealthy entry for ``backend_name`` (test helper +
    explicit recovery). Idempotent — no-op when no entry exists."""
    _STATE.pop(backend_name, None)


def is_healthy(backend_name: str) -> bool:
    """Return True if no active unhealthy entry exists for the backend.

    Performs lazy expiry — when the entry's TTL has elapsed, it
    gets evicted on read so the next ``set_unhealthy`` starts from
    scratch instead of inheriting a stale ``unhealthy_since``.
    """
    entry = _STATE.get(backend_name)
    if entry is None:
        return True
    if time.monotonic() >= entry.unhealthy_until:
        _STATE.pop(backend_name, None)
        return True
    return False


def health_status(backend_name: str) -> dict:
    """Return a serialisable dict describing the backend's state.

    Used by the dashboard banner partial. Shape is intentionally
    flat + jinja-friendly:

      {
        "healthy": bool,
        "unhealthy_since": ISO-8601 string or None,
        "unhealthy_until_monotonic": float | None,  # internal — for tests
        "remaining_seconds": int | None,  # 0 when expired-but-not-evicted
        "reason": str,                    # may be empty
      }
    """
    entry = _STATE.get(backend_name)
    if entry is None or time.monotonic() >= entry.unhealthy_until:
        return {
            "healthy": True,
            "unhealthy_since": None,
            "unhealthy_until_monotonic": None,
            "remaining_seconds": None,
            "reason": "",
        }
    # Render unhealthy_since as wall-clock ISO-8601 UTC. Monotonic
    # is great for elapsed math but worthless for the operator's
    # banner ("unreachable since 14:32").
    from datetime import datetime, timezone
    since_iso = datetime.fromtimestamp(
        entry.wall_unhealthy_since, tz=timezone.utc,
    ).isoformat()
    remaining = max(0, int(entry.unhealthy_until - time.monotonic()))
    return {
        "healthy": False,
        "unhealthy_since": since_iso,
        "unhealthy_until_monotonic": entry.unhealthy_until,
        "remaining_seconds": remaining,
        "reason": entry.reason,
    }


# ---------------------------------------------------------------------------
# Connection-error classification
# ---------------------------------------------------------------------------

def is_unreachable_error(exc: BaseException) -> bool:
    """Return True if ``exc`` looks like an LLM-backend-unreachable
    failure that should trigger the circuit breaker.

    We match by both type (``httpx.ConnectError`` and family) AND by
    message substring ("All connection attempts failed") to catch
    the case where a different transport raises the same connect
    failure under a different exception class.

    Kept narrow on purpose: a 429 / 500 / parse error is NOT an
    "unreachable" error — those mean the backend is up but
    misbehaving. We do not flip the breaker for those; the existing
    per-message error path handles them.
    """
    try:
        import httpx
    except ImportError:
        httpx = None  # type: ignore[assignment]

    if httpx is not None:
        # ``RemoteProtocolError`` is referenced directly — it has been
        # part of httpx's public API for years. A ``getattr(...,
        # httpx.HTTPError)`` fallback would be actively dangerous:
        # ``HTTPError`` is the base class of ``HTTPStatusError``, so an
        # activated fallback would classify every 4xx/5xx as
        # "unreachable" and wrongly trip the breaker on a backend that
        # is up but misbehaving.
        if isinstance(exc, (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.RemoteProtocolError,
        )):
            return True
    msg = str(exc).lower()
    if "all connection attempts failed" in msg:
        return True
    if "connection refused" in msg:
        return True
    return False


def host_port_from_url(url: str, *, default_port: int = 80) -> tuple[str, int]:
    """Pull ``(host, port)`` out of a URL for the typed exception's
    operator-readable message. Best-effort; returns ``("", 0)`` on
    parse failure rather than raising."""
    if not url:
        return ("", 0)
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or default_port
        return (host, int(port))
    except Exception:
        return ("", 0)


# ---------------------------------------------------------------------------
# Circuit-breaker translation — shared by every HTTP classifier backend
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def translate_unreachable(
    backend_name: str,
    base_url: str,
    *,
    default_port: int,
    ttl_seconds: float = 300.0,
) -> Iterator[None]:
    """Wrap a backend HTTP call so a connect-class failure trips the breaker.

    Every HTTP classifier backend (Ollama, OpenAI-compatible, Gemini)
    needs the identical "connect failure → ``set_unhealthy`` + raise
    :class:`LLMBackendUnreachableError`" translation around its POST.
    Before  that block was copy-pasted into ``OllamaClassifier``
    twice (``_chat`` + ``complete``) and absent from the cloud
    backends entirely — so a dead OpenAI / Gemini endpoint never
    flipped the breaker. This is the single source of truth.

    Usage::

        with translate_unreachable("ollama", base_url, default_port=11434):
            resp = await client.post(url, json=payload)
            resp.raise_for_status()

    On a connect-class error (``is_unreachable_error`` True) the
    backend is marked unhealthy for ``ttl_seconds`` and a typed
    :class:`LLMBackendUnreachableError` carrying host/port is raised.
    Any other exception (429 / 500 / parse error) propagates
    unchanged — those mean the backend is up but misbehaving and the
    per-message error path handles them.

    ``backend_name`` is the circuit-breaker key — it MUST match the
    name the :func:`is_healthy` gate resolves for this backend (the
    configured ``classifier.backend``: ``"ollama"`` / ``"openai"`` /
    ``"gemini"``), otherwise a tripped breaker would never be seen by
    the gate.
    """
    try:
        yield
    except Exception as exc:
        if is_unreachable_error(exc):
            host, port = host_port_from_url(base_url, default_port=default_port)
            set_unhealthy(
                backend_name, ttl_seconds=ttl_seconds, reason=str(exc)[:200],
            )
            raise LLMBackendUnreachableError(
                backend_name, host, port, original=exc,
            ) from exc
        raise


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------

def _reset_for_test() -> None:
    """Clear every backend's state. Used by pytest fixtures."""
    _STATE.clear()


__all__ = [
    "LLMBackendUnreachableError",
    "set_unhealthy",
    "clear_unhealthy",
    "is_healthy",
    "health_status",
    "is_unreachable_error",
    "host_port_from_url",
    "translate_unreachable",
    "_reset_for_test",
]
