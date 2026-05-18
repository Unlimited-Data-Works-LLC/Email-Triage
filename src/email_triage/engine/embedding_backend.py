"""Local-only embedding backend(s) for the M-4 RAG sent-mail index.

This module ships the runtime side of the M-4 ``EmbeddingBackend``
protocol declared in ``actions/sent_mail_index.py``. The protocol
specifies a tiny surface (``backend_type`` + ``async embed_text``);
this module supplies three concrete implementations:

* :class:`OllamaEmbeddingBackend` — calls a local-only Ollama instance
  over HTTP. Slow per-call when the model is large + GPU-busy; fast
  when the model is a dedicated 100-500MB embedder.
* :class:`SentenceTransformersBackend` — in-process CPU inference via
  the ``sentence-transformers`` library. Zero network hop, zero GPU
  contention, ~150ms per embedding on commodity CPU. Ideal when the
  install's primary chat model is overflowing the GPU VRAM (operator's
  case 2026-05-13: [local-llm-model] filling a 24 GB RTX 3090).
* :class:`FallbackEmbeddingBackend` — wraps a primary + a backup; the
  primary is tried first, the backup runs only if the primary raises.
  Use this when the install has a fast local embedder but also a
  slower Ollama model to fall through to on failure.

Why local-only
==============

Sending the user's sent mail to a remote embedding provider is a
privacy regression vs the rest of the style-learning ladder (M-3
sends one summary; the index would send every sent message). The
``actions/sent_mail_index.py`` module enforces a backend-type
allowlist at construction time; this module's factory mirrors that
allowlist so a misconfigured YAML can't slip a non-local backend
through. The allowed set is a tuple constant -- adding to it is a
privacy decision, not a config tweak.

Anthropic is intentionally omitted from the allowlist on top of
the local-only restriction (project standing rule).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Sequence

import httpx

from email_triage._http_client import LazyHttpClient
from email_triage.classify.base import _is_local_host
from email_triage.triage_logging import get_logger

log = get_logger("engine.embedding_backend")


class _BackendMetrics:
    """In-memory counter set shared by every concrete backend.

    Wraps the per-backend call / latency / error tallies so the
    ``/admin/stats`` page + ``/health/detail`` JSON can render the
    same shape across ``OllamaEmbeddingBackend``,
    ``SentenceTransformersBackend``, and the ``FallbackEmbeddingBackend``
    composite. Process-local tallies stay the live source of
    truth; a Redis-backed mirror (via
    :mod:`engine.persistent_counters`) accumulates across restarts
    when an install has the cache Redis URL configured —
    operator gets the same lifetime visibility as the cache
    counters under namespace ``embedding:<backend_type>``.
    """

    __slots__ = (
        "calls", "errors", "_latency_sum", "last_error",
        "last_error_at", "started_at", "_persist_namespace",
    )

    def __init__(self, persist_namespace: str = "") -> None:
        self.calls: int = 0
        self.errors: int = 0
        self._latency_sum: float = 0.0
        self.last_error: str = ""
        self.last_error_at: str = ""
        self.started_at: str = datetime.now(timezone.utc).isoformat()
        # Per-instance namespace for the Redis mirror. Empty string
        # disables persistence (test paths + tooling that don't want
        # to touch Redis pass "" or leave the default).
        self._persist_namespace: str = persist_namespace

    def _mirror(self, field: str, by: int = 1) -> None:
        """Best-effort HINCRBY to the install-level Redis backend.

        Lazy-imported so test paths without Redis wired skip the
        import overhead. Silent on failure — process-local counters
        stay authoritative.
        """
        if not self._persist_namespace:
            return
        try:
            from email_triage.engine.persistent_counters import (
                get_install_counter_backend,
            )
            be = get_install_counter_backend()
            if be is not None:
                be.incr(self._persist_namespace, field, by)
        except Exception:  # noqa: BLE001
            pass

    def record_success(self, latency_secs: float) -> None:
        self.calls += 1
        self._latency_sum += float(latency_secs)
        self._mirror("calls")
        # Persist latency in microseconds so the lifetime average
        # can be recomputed on read (sum_us / calls). Integer-only
        # because HINCRBY rejects floats.
        self._mirror("latency_us_sum", int(latency_secs * 1_000_000))

    def record_failure(self, exc: BaseException) -> None:
        self.errors += 1
        self.last_error = type(exc).__name__
        self.last_error_at = datetime.now(timezone.utc).isoformat()
        self._mirror("errors")

    @property
    def avg_latency_ms(self) -> int:
        if self.calls <= 0:
            return 0
        return int((self._latency_sum / self.calls) * 1000)

    def snapshot(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "errors": self.errors,
            "avg_latency_ms": self.avg_latency_ms,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
            "started_at": self.started_at,
        }


# Backends that may be returned from :func:`build_embedding_backend`.
# Mirrors :data:`email_triage.actions.sent_mail_index._LOCAL_BACKENDS`.
# Keep the two in lockstep -- if a future remote backend is reviewed
# and added, BOTH constants flip together. The composite "fallback"
# wrapper is listed because it can flow through the same allowlist
# check; the wrapper itself re-validates both wrapped members
# against this same tuple at construction, so the privacy guarantee
# survives wrapping.
_ALLOWED_EMBEDDING_BACKENDS: tuple[str, ...] = (
    "ollama",
    "sentence_transformers",
    "fallback",
)


class OllamaEmbeddingBackend:
    """Concrete Ollama embedding backend.

    Calls ``POST {base_url}/api/embeddings`` with ``{model, prompt}``
    and returns the resulting float vector. Failures bubble up to
    the caller -- :class:`SentMailIndex` catches them and degrades
    gracefully (the message is left un-indexed; retrieval returns
    the empty list for this query).
    """

    backend_type = "ollama"

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout: float = 30.0,
        local_url_suffixes: Sequence[str] = (),
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = float(timeout)
        # Persistence namespace: "embedding:ollama" — distinct from
        # SentenceTransformers so the operator can tell which member
        # of a fallback chain absorbed traffic over the long horizon.
        self._metrics = _BackendMetrics(
            persist_namespace="embedding:ollama",
        )
        # Long-lived httpx client (#139). The RAG indexer fires N
        # embed_text calls per index_recent batch + every draft-reply
        # retrieval — each previously paid a fresh TLS handshake.
        self._http = LazyHttpClient(timeout=self._timeout)
        # The sent-mail-index module's privacy guarantee depends on
        # the embedding backend speaking ONLY to a local Ollama
        # instance. Surface a hard error at construction when the
        # configured base_url is non-local; an operator who points
        # at a public Ollama-protocol endpoint should not have it
        # silently accepted. ``local_url_suffixes`` extends the
        # built-in detection (``.local``, RFC1918) with operator-
        # supplied private suffixes (e.g. ``.home.example.local``)
        # — same plumbing as the classifier path.
        if not _is_local_host(
            self._base_url,
            extra_suffixes=tuple(local_url_suffixes or ()),
        ):
            raise ValueError(
                f"OllamaEmbeddingBackend rejects non-local base_url "
                f"{self._base_url!r}. The M-4 RAG sent-mail index is "
                f"local-only by design; configure a local Ollama "
                f"endpoint, or add the hostname suffix to "
                f"``tls.local_url_suffixes`` in YAML if it's a private "
                f"LAN host."
            )

    async def embed_text(self, text: str) -> list[float]:
        """Embed ``text`` via Ollama and return the float vector."""
        start = time.monotonic()
        try:
            payload = {"model": self._model, "prompt": text}
            client = await self._http.get()
            resp = await client.post(
                f"{self._base_url}/api/embeddings", json=payload,
            )
            resp.raise_for_status()
            body = resp.json() or {}
            vec = body.get("embedding") or []
            if not isinstance(vec, list):
                self._metrics.record_success(time.monotonic() - start)
                return []
            # Coerce defensively -- Ollama returns plain floats but a
            # forked / proxied endpoint might leak ints or strings.
            out: list[float] = []
            for v in vec:
                try:
                    out.append(float(v))
                except (TypeError, ValueError):
                    self._metrics.record_success(time.monotonic() - start)
                    return []
            self._metrics.record_success(time.monotonic() - start)
            return out
        except Exception as e:
            self._metrics.record_failure(e)
            raise

    def metrics(self) -> dict[str, Any]:
        """Per-backend operational counters for /admin/stats + /health."""
        snap = self._metrics.snapshot()
        snap["backend_type"] = self.backend_type
        snap["model"] = self._model
        snap["base_url"] = self._base_url
        return snap

    async def close(self) -> None:
        """Drain the long-lived httpx client. Idempotent."""
        await self._http.aclose()


class SentenceTransformersBackend:
    """In-process CPU embedding via the sentence-transformers library.

    Runs entirely inside the email-triage process — no network hop,
    no GPU contention. Latency on commodity CPU is ~100-400 ms per
    embedding for a 80-300 MB model (``all-MiniLM-L6-v2``,
    ``all-mpnet-base-v2``, ``nomic-ai/nomic-embed-text-v1.5``).

    Local-only by construction: the model files are pulled once from
    HuggingFace on first use into the container's HF cache, then
    every subsequent call runs offline. No request data leaves the
    container.

    Lazy-loaded: the heavy ``sentence_transformers`` import + the
    model load happen on the first ``embed_text`` call so a container
    that's configured-but-never-uses the backend doesn't pay the
    one-time 1-2s import cost at boot.
    """

    backend_type = "sentence_transformers"

    def __init__(
        self,
        *,
        model: str = "all-MiniLM-L6-v2",
    ) -> None:
        self._model_name = model
        self._model: Any = None  # lazy-loaded
        self._metrics = _BackendMetrics(
            persist_namespace="embedding:sentence_transformers",
        )
        self._embedding_dimension: int | None = None

    def _load_model(self) -> Any:
        """Load the SentenceTransformer model on first use."""
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise RuntimeError(
                f"SentenceTransformersBackend requested but the "
                f"``sentence-transformers`` package is not installed. "
                f"Install via the ``embedding`` extra: "
                f"``pip install email-triage[embedding]``. "
                f"Underlying error: {e}"
            ) from e
        # Force CPU — the whole point of this backend is to skip GPU
        # contention with the chat model. ``device="cpu"`` overrides
        # any auto-detection that might pick the GPU if torch sees one.
        self._model = SentenceTransformer(
            self._model_name, device="cpu",
        )
        try:
            dim = self._model.get_sentence_embedding_dimension()
            self._embedding_dimension = (
                int(dim) if dim is not None else None
            )
        except Exception:
            self._embedding_dimension = None
        log.info(
            "SentenceTransformersBackend model loaded (CPU)",
            model=self._model_name,
            dimension=self._embedding_dimension,
        )
        return self._model

    async def embed_text(self, text: str) -> list[float]:
        """Embed ``text`` and return the float vector.

        The underlying ``model.encode`` is synchronous; wrap in
        ``asyncio.to_thread`` so we don't block the event loop on
        the ~100-400 ms inference call.
        """
        import asyncio
        start = time.monotonic()
        try:
            model = self._load_model()

            def _encode() -> list[float]:
                vec = model.encode(text, convert_to_numpy=True)
                # Numpy ndarray → plain Python floats so the downstream
                # JSON storage path doesn't see numpy types.
                return [float(v) for v in vec]

            result = await asyncio.to_thread(_encode)
            self._metrics.record_success(time.monotonic() - start)
            return result
        except Exception as e:
            self._metrics.record_failure(e)
            raise

    def metrics(self) -> dict[str, Any]:
        snap = self._metrics.snapshot()
        snap["backend_type"] = self.backend_type
        snap["model"] = self._model_name
        snap["dimension"] = self._embedding_dimension
        snap["loaded"] = self._model is not None
        return snap

    async def close(self) -> None:
        """No-op. The model stays loaded for process lifetime."""
        return


class FallbackEmbeddingBackend:
    """Try a primary backend; on any failure, fall back to a backup.

    Use case: install runs a fast in-process embedder (e.g. sentence-
    transformers) but ALSO has an Ollama instance available as a
    safety net. If the primary backend fails (import error, model
    download timeout, container-restart-in-progress, etc.) the
    backup absorbs the failure so the M-4 index keeps growing.

    Both backends MUST be local — the same allowlist gate applies
    at construction time. The factory builds this chain only when
    both wrapped backends individually pass the privacy gate.
    """

    backend_type = "fallback"

    def __init__(self, primary: Any, backup: Any) -> None:
        self._primary = primary
        self._backup = backup
        # Composite-level fallback-fire counter — tracks how often
        # the primary raised and the backup absorbed the failure.
        # Each wrapped backend keeps its own per-call counters in
        # its own ``metrics()`` dict; this counter is the operator-
        # facing signal that the safety net is doing work.
        self._fallback_fires: int = 0

    async def embed_text(self, text: str) -> list[float]:
        try:
            return await self._primary.embed_text(text)
        except Exception as exc:
            self._fallback_fires += 1
            # Persist the fire count under its own namespace so the
            # operator can see "the safety net absorbed N failures
            # over N months" — high-value tuning signal that would
            # otherwise reset on every container restart.
            try:
                from email_triage.engine.persistent_counters import (
                    get_install_counter_backend,
                )
                be = get_install_counter_backend()
                if be is not None:
                    be.incr("embedding:fallback", "fires")
            except Exception:  # noqa: BLE001
                pass
            log.warning(
                "Embedding primary backend failed; using backup",
                primary_type=getattr(
                    self._primary, "backend_type", "?",
                ),
                backup_type=getattr(
                    self._backup, "backend_type", "?",
                ),
                error=type(exc).__name__,
            )
            return await self._backup.embed_text(text)

    def metrics(self) -> dict[str, Any]:
        """Composite metrics surface — primary + backup + fire count."""
        primary_metrics = (
            self._primary.metrics()
            if hasattr(self._primary, "metrics")
            else {"backend_type": getattr(
                self._primary, "backend_type", "?",
            )}
        )
        backup_metrics = (
            self._backup.metrics()
            if hasattr(self._backup, "metrics")
            else {"backend_type": getattr(
                self._backup, "backend_type", "?",
            )}
        )
        return {
            "backend_type": self.backend_type,
            "fallback_fires": self._fallback_fires,
            "primary": primary_metrics,
            "backup": backup_metrics,
        }

    async def close(self) -> None:
        """Close both wrapped backends. Errors from either are swallowed."""
        for be in (self._primary, self._backup):
            try:
                close = getattr(be, "close", None)
                if close is not None:
                    await close()
            except Exception:
                pass


def _build_single_backend(
    backend: str,
    *,
    model: str,
    ollama_url: str,
    local_url_suffixes: Sequence[str],
) -> Any:
    """Construct one backend by name; reusable for primary + fallback."""
    if backend == "ollama":
        return OllamaEmbeddingBackend(
            model=model,
            base_url=ollama_url,
            local_url_suffixes=local_url_suffixes,
        )
    if backend == "sentence_transformers":
        return SentenceTransformersBackend(model=model)
    raise ValueError(
        f"Embedding backend {backend!r} is not in the local-only "
        f"allowlist {_ALLOWED_EMBEDDING_BACKENDS!r}. The M-4 RAG "
        f"sent-mail index is local-only by design; configure a "
        f"supported backend or remove the embedding section to "
        f"disable retrieval install-wide."
    )


def build_embedding_backend(config: Any) -> Any | None:
    """Construct the embedding backend from a config dataclass.

    Returns ``None`` when the operator hasn't configured an embedding
    section -- the caller treats absence as "RAG disabled even if the
    per-account toggle is on" (with a one-time INFO log surfacing the
    missing config).

    When ``embedding.fallback`` is also configured, returns a
    :class:`FallbackEmbeddingBackend` wrapping (primary, fallback).
    Both members must individually pass the local-only allowlist.

    Raises :class:`ValueError` when the config asks for a non-allowed
    backend (e.g. ``backend: openai`` / ``backend: anthropic``). The
    error names the rule and the rejected value so the operator's
    log surface tells them exactly what to change.
    """
    embedding_cfg = getattr(config, "embedding", None)
    if embedding_cfg is None:
        return None

    backend = str(getattr(embedding_cfg, "backend", "") or "").strip().lower()
    if not backend:
        # Operator left the section blank -- treat as "not configured"
        # rather than a hard error. RAG-enabled accounts will skip
        # retrieval (one-time log in draft_reply._should_use_rag).
        return None

    model = str(getattr(embedding_cfg, "model_name", "") or "").strip()
    if not model:
        log.warning(
            "Embedding backend declared but model_name is empty; "
            "RAG retrieval will be skipped",
            backend=backend,
        )
        return None

    ollama_url = str(
        getattr(embedding_cfg, "ollama_url", "")
        or "http://localhost:11434"
    )
    # Operator-defined LAN suffixes (e.g. ``.home.example.local``)
    # from ``tls.local_url_suffixes``. Plumbed through so the
    # privacy gate accepts the same hosts the classifier path
    # already trusts.
    local_suffixes = tuple(
        getattr(getattr(config, "tls", None), "local_url_suffixes", []) or ()
    )

    primary = _build_single_backend(
        backend, model=model, ollama_url=ollama_url,
        local_url_suffixes=local_suffixes,
    )

    # Optional fallback chain — only built when the YAML carries a
    # complete sub-section. Missing / partial fallback config silently
    # falls through to the primary-only behaviour.
    fb_cfg = getattr(embedding_cfg, "fallback", None)
    if fb_cfg is None:
        return primary
    fb_backend = str(
        getattr(fb_cfg, "backend", "") or "",
    ).strip().lower()
    fb_model = str(
        getattr(fb_cfg, "model_name", "") or "",
    ).strip()
    if not fb_backend or not fb_model:
        return primary
    fb_url = str(
        getattr(fb_cfg, "ollama_url", "")
        or ollama_url,
    )
    try:
        backup = _build_single_backend(
            fb_backend, model=fb_model, ollama_url=fb_url,
            local_url_suffixes=local_suffixes,
        )
    except ValueError as exc:
        log.warning(
            "Embedding fallback config rejected; primary-only",
            error=str(exc),
        )
        return primary
    log.info(
        "Embedding fallback chain configured",
        primary=backend, primary_model=model,
        fallback=fb_backend, fallback_model=fb_model,
    )
    return FallbackEmbeddingBackend(primary=primary, backup=backup)


__all__ = [
    "OllamaEmbeddingBackend",
    "SentenceTransformersBackend",
    "FallbackEmbeddingBackend",
    "build_embedding_backend",
    "_ALLOWED_EMBEDDING_BACKENDS",
]
