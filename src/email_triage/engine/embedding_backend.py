"""Local-only embedding backend(s) for the M-4 RAG sent-mail index.

This module ships the runtime side of the M-4 ``EmbeddingBackend``
protocol declared in ``actions/sent_mail_index.py``. The protocol
specifies a tiny surface (``backend_type`` + ``async embed_text``);
this module supplies two concrete implementations:

* :class:`OllamaEmbeddingBackend` — calls a local-only Ollama instance
  over HTTP. Slow per-call when the model is large + GPU-busy; fast
  when the model is a dedicated 100-500MB embedder.
* :class:`SentenceTransformersBackend` — in-process CPU inference via
  the ``sentence-transformers`` library. Zero network hop, zero GPU
  contention, ~150ms per embedding on commodity CPU. Ideal when the
  install's primary chat model is overflowing the GPU VRAM (operator's
  case 2026-05-13: qwen3.6:35b filling a 24 GB RTX 3090).

There is deliberately NO fallback chain (punch 552 / N-555). One existed
(``FallbackEmbeddingBackend`` + an ``embedding.fallback`` YAML section) and it
turned a broken embedder into a silent one: the backup was a DIFFERENT model,
so its vectors scored zero against the index the primary built, and on the deploy host it
was a chat model (qwen3.6:35b) that is not an embedder at all. A failed embed now
raises to its caller, which records it on the backend's metrics, logs it and
degrades that one message; the operator sees the error count and the style-
learning gate. Vectors from two models are never comparable, so "fall back to a
different embedder" has no correct form for a vector index.

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

AI provider is intentionally omitted from the allowlist on top of
the local-only restriction (project standing rule).
"""

from __future__ import annotations

import threading
import time
from email_triage._isotime import now_utc_iso
from typing import Any, Sequence

import httpx

from email_triage._http_client import Intent, LazyHttpClient
from email_triage.classify.base import _is_local_host
from email_triage.triage_logging import get_logger

log = get_logger("engine.embedding_backend")


# ---------------------------------------------------------------------------
#  — E5-family instruction-prefix + model-stamp helpers
# ---------------------------------------------------------------------------
# The intfloat E5 family (e.g. ``intfloat/multilingual-e5-base``) REQUIRES
# an instruction prefix — ``query: `` on search queries, ``passage: `` on
# indexed documents — applied SYMMETRICALLY at index + retrieve time.
# Skipping it, or applying it on only one side, silently drops recall
# ~5-10%. The other shipped models (all-MiniLM, nomic-embed, bge, gte) do
# NOT use a prefix, so the helpers no-op for them. The prefix scheme is
# encoded into the stored model STAMP (``<model>+e5prefix``) so toggling
# the model (or the scheme) invalidates old rows via the existing
# ``WHERE embedding_model = ?`` filter — write, retrieve, and reindex MUST
# all use ``embedding_stamp`` so the values match.

def is_e5_model(model: str) -> bool:
    """True if ``model`` is an intfloat E5-family embedding model that
    needs ``query:`` / ``passage:`` prefixes. ``e5`` must be a delimited
    TOKEN (split on ``/ _ - .``), NOT any substring — so a future model
    name containing a stray ``e5`` (e.g. ``...-v5e5-...``) can't
    false-trigger the prefix + stamp once the model picker lets operators
    type arbitrary names. Matches the curated fleet
    (``intfloat/multilingual-e5-base``, ``e5-small``, ``e5-large-v2``);
    the other shipped models (all-MiniLM, nomic-embed, bge, gte) have no
    ``e5`` token.
    """
    import re
    return any(
        tok == "e5"
        for tok in re.split(r"[/_.\-]", (model or "").lower())
    )


def e5_prefix(model: str, role: str) -> str:
    """E5 instruction prefix for ``role`` (``"query"`` | ``"passage"``) —
    e.g. ``"query: "`` — or ``""`` for non-E5 models. Prepend to the text
    BEFORE embedding. MUST be symmetric: ``passage: `` at index + reindex,
    ``query: `` at retrieve.
    """
    return f"{role}: " if is_e5_model(model) else ""


def embedding_stamp(model: str) -> str:
    """The value written to (and filtered on) ``sent_mail_index.
    embedding_model``. Encodes the E5 prefix scheme so a model/scheme
    change invalidates old rows. For non-E5 models the stamp == the bare
    model name, so existing rows + behaviour are unchanged.
    """
    m = model or ""  # always a str — a None model must not become a
    # SQL-NULL stamp that the retrieve filter binds + silently 0-matches.
    return f"{m}+e5prefix" if is_e5_model(m) else m


class _BackendMetrics:
    """In-memory counter set shared by every concrete backend.

    Wraps the per-backend call / latency / error tallies so the
    ``/admin/stats`` page + ``/health/detail`` JSON can render the
    same shape across ``OllamaEmbeddingBackend``,
    and ``SentenceTransformersBackend``. Process-local tallies stay the live source of
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
        self.started_at: str = now_utc_iso()
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
        # N-215 R23 (2026-07-02, census R23_9): clear stale last_error /
        # last_error_at on success — the pre-N-215 set-broad/clear-narrow
        # shape (record_failure sets both, record_success never cleared) left
        # /health reporting a stale error indefinitely for a backend that had
        # recovered. Pair edges through the SAME funnel.
        self.last_error = None
        self.last_error_at = None

    def record_failure(self, exc: BaseException) -> None:
        self.errors += 1
        self.last_error = type(exc).__name__
        self.last_error_at = now_utc_iso()
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
# and added, BOTH constants flip together (pinned equal by
# ``tests/test_privacy_invariants_m_series.py``). The composite
# "fallback" type was removed with the chain (punch 552 / N-555).
_ALLOWED_EMBEDDING_BACKENDS: tuple[str, ...] = (
    "ollama",
    "sentence_transformers",
)


class EmbeddingResponseInvalid(ValueError):
    """The embedder answered, but with no usable vector (punch 552 / N-555).

    Raised, never returned as ``[]``: an empty vector is indistinguishable
    from a real one to the index (it writes a norm-0 row that retrieval
    skips), so a malformed response must be a counted, logged failure. The
    class name is what the admin pages show as the backend's last error.
    """


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
        keep_alive: str | int = "10m",
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = float(timeout)
        # N-431 (2026-07-19) — Ollama ``keep_alive`` payload option, threaded
        # through /api/embeddings via the shared SSOT ``_ollama_reuse``.
        # Was previously absent; Ollama's default "5m" would evict a
        # Forever-pinned embedding model every 5 min silently.
        self._keep_alive: str | int = keep_alive
        # Persistence namespace: "embedding:ollama" — distinct from
        # SentenceTransformers so the long-horizon counters say which
        # backend served (or failed) the traffic.
        self._metrics = _BackendMetrics(
            persist_namespace="embedding:ollama",
        )
        # Long-lived httpx client. The RAG indexer fires N
        # embed_text calls per index_recent batch + every draft-reply
        # retrieval — each previously paid a fresh TLS handshake.
        self._http = LazyHttpClient(intent=Intent.LLM_PHI, timeout=self._timeout)
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
        """Embed ``text`` via Ollama and return the float vector.

        N-220 R22 (2026-07-02): the POST /api/embeddings is wrapped in the
        shared circuit-breaker helper :func:`llm_health.translate_unreachable`
        AND the :mod:`metrics` ``et_llm_embed_seconds`` timer. Prior to
        N-220 a dead Ollama on the M-4 sent-mail-index or draft-reply
        retrieval path raised a raw ``httpx.ConnectError`` — the fallback
        backend caught it silently, so the ``ollama`` circuit breaker never
        tripped and /metrics carried zero embedding latency for the
        Ollama path.
        """
        start = time.monotonic()
        # N-384 (2026-07-10 wf_69674c7e-c67, HIGH): emit the outcome-counter
        # twin — the timer records latency but was blind to the failure edge.
        # ``parse_failed`` covers the shape mismatch (a missing, empty or
        # non-list embedding, or an unfloatable element). Since punch 552 that
        # path RAISES ``EmbeddingResponseInvalid`` (recorded as a failure on the
        # backend's metrics) instead of returning ``[]`` after a success.
        from email_triage import metrics as _metrics
        outcome = "transport_error"
        try:
            payload = {"model": self._model, "prompt": text}
            from email_triage.llm_health import translate_unreachable
            from email_triage._ollama_reuse import merge_reuse_options
            with _metrics.timer("et_llm_embed_seconds", backend="ollama"), \
                    translate_unreachable(
                        "ollama", self._base_url, default_port=11434,
                    ):
                client = await self._http.get()
                # N-431 (2026-07-19) — SSOT injects ``keep_alive``. The
                # embedding backend was previously absent this field; a
                # long-running RAG index build would burn the model reload
                # cost every 5 min silently.
                await merge_reuse_options(
                    payload, self._base_url, self._model, client,
                    default_keep_alive=self._keep_alive,
                )
                resp = await client.post(
                    f"{self._base_url}/api/embeddings", json=payload,
                )
                resp.raise_for_status()
            body = resp.json() or {}
            vec = body.get("embedding") or []
            # Punch 552 / N-555 (panel B1 DA O4-F1): a response with no usable
            # vector RAISES. It used to return ``[]`` after record_SUCCESS, so
            # the backend's errors / last_error never moved, the caller saw
            # no exception, and the index wrote a norm-0 row that retrieval
            # skips: a silent failure on exactly the surfaces this change names
            # as the visible ones. The raise lands in the handler below
            # (record_failure) and in every caller's existing except
            # (WARNING log, that one message degraded).
            if not isinstance(vec, list) or not vec:
                outcome = "parse_failed"
                raise EmbeddingResponseInvalid(
                    "ollama /api/embeddings returned no vector list"
                )
            # Coerce defensively -- Ollama returns plain floats but a
            # forked / proxied endpoint might leak ints or strings.
            out: list[float] = []
            for v in vec:
                try:
                    out.append(float(v))
                except (TypeError, ValueError):
                    outcome = "parse_failed"
                    raise EmbeddingResponseInvalid(
                        "ollama /api/embeddings returned a non-numeric element"
                    ) from None
            self._metrics.record_success(time.monotonic() - start)
            outcome = "success"
            return out
        except Exception as e:
            self._metrics.record_failure(e)
            raise
        finally:
            _metrics.emit_llm_outcome("embed", "ollama", outcome)

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
        #  — Lock for the lazy-init guard. ``_load_model`` is
        # currently called only on the event loop (line ~325, before
        # ``await asyncio.to_thread(_encode)``), so concurrent async
        # callers don't race. The Lock is defensive depth against a
        # future refactor that moves ``_load_model`` into ``_encode``
        # or otherwise calls it from a background thread — without it,
        # concurrent threads would each pass the ``is not None`` check
        # and double-load the ~80-300 MB model. Empirically reproduced
        # (10/10 double-loads under threading.Barrier(10) across 5
        # stress runs); see ``tests/test_engine/test_embedding_backend
        # _load_model_thread_safety.py`` for the class-invariant guard.
        self._load_lock = threading.Lock()
        self._metrics = _BackendMetrics(
            persist_namespace="embedding:sentence_transformers",
        )
        self._embedding_dimension: int | None = None

    def _resolve_staged_model_path(self) -> str | None:
        """The local path to the embedding-bits-staged model dir, or ``None``.

        The offline installer stages a model at
        ``$HF_HOME/<hf_cache_dir_for_model(model_name)>/`` (a flat ST dir).
        Loading THAT path directly is the only air-gap-safe load (modern ST
        ignores the flat dir in its hub-cache resolution and would hit the
        network). ``hf_cache_dir_for_model`` is the shared SSOT used by the
        installer to choose the same dir. Returns ``None`` (→ bare-name
        hub-download fallback) when nothing is staged. The cache dir is DERIVED
        from the runtime-deps prefix — never ``$HF_HOME`` (punch 547: an env var
        chose which model files were loaded, outside the installer's verified
        dir).
        """
        from pathlib import Path
        try:
            from email_triage.embedding_bits import (
                HF_CACHE_DIRNAME, get_runtime_deps_path, hf_cache_dir_for_model,
            )
        except Exception:  # noqa: BLE001 — installer package not importable
            return None
        hf_home = get_runtime_deps_path() / HF_CACHE_DIRNAME  # one spelling (db-b1 F-O3-1)
        staged = Path(hf_home) / hf_cache_dir_for_model(self._model_name)
        # A real staged model dir carries at least config.json (the model card).
        if (staged / "config.json").is_file():
            return str(staged)
        return None

    def _load_model(self) -> Any:
        """Load the SentenceTransformer model on first use.

        Thread-safety: double-checked locking. The first check
        is the hot path — once ``self._model`` is set, every caller
        returns without ever touching the Lock. The Lock serialises
        only the cold path (first-load). The second check inside the
        Lock handles the race window where caller A passed the first
        check but caller B got the Lock first and already set the
        model: A re-checks and returns the value B installed.
        """
        # Hot path — no Lock acquisition once loaded.
        if self._model is not None:
            return self._model
        # Cold path — serialise the load.
        with self._load_lock:
            # Re-check inside the Lock: another thread may have
            # finished the load while we were waiting on it.
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
            # OFFLINE-SAFE LOAD. The embedding-
            # bits installer stages the model in a FLAT sentence-transformers
            # dir ``$HF_HOME/<hf_cache_dir_for_model(name)>/``. Modern ST does
            # NOT find a flat dir via its hub-cache resolution, so on a true
            # air-gap a bare-name load would reach for the network and FAIL
            # (proven: flat-only + offline → ST tries huggingface.co). If the
            # staged dir is present, load it by EXPLICIT PATH (ST loads a local
            # dir directly, no network); else fall back to the bare name so an
            # online/dev install still hub-downloads as before.
            model_arg = self._resolve_staged_model_path() or self._model_name
            # Force CPU — the whole point of this backend is to skip GPU
            # contention with the chat model. ``device="cpu"`` overrides
            # any auto-detection that might pick the GPU if torch sees one.
            self._model = SentenceTransformer(model_arg, device="cpu")
            try:
                # Punch 563: the 6.x name. ``get_sentence_embedding_dimension``
                # is a deprecated alias in 6.1.0 (FutureWarning on every load;
                # sentence_transformer/model.py:1263-1268). 6.1.0 is the floor.
                dim = self._model.get_embedding_dimension()
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
            # Punch 569 D4: after an update swapped the runtime under packages
            # this process had loaded, a lazy submodule import would come from
            # the NEW tree into the OLD package. Refuse (typed, counted below)
            # until the container restarts.
            from email_triage.embedding_bits import (
                RESTART_MESSAGE, RuntimeRestartRequired, restart_pending,
                wait_for_boot_update_decision,
            )
            if restart_pending():
                raise RuntimeRestartRequired(
                    f"the embedding runtime was updated; {RESTART_MESSAGE}"
                )
            # Panel T DA SHOULD-A1: at boot, with auto-update on and a stale_ok runtime,
            # the FIRST in-process load of the runtime waits (async, bounded) for the
            # first auto-update decision, so a non-security update is applied before
            # anything imports the old set. A no-op everywhere else.
            await wait_for_boot_update_decision()
            model = self._load_model()

            def _encode() -> list[float]:
                vec = model.encode(text, convert_to_numpy=True)
                # Numpy ndarray → plain Python floats so the downstream
                # JSON storage path doesn't see numpy types. ndarray.tolist()
                # yields native Python floats directly + is ~5x faster than a
                # per-element float() comprehension on a 768-dim vector
                #.
                return vec.tolist()

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


def _build_single_backend(
    backend: str,
    *,
    model: str,
    ollama_url: str,
    local_url_suffixes: Sequence[str],
    keep_alive: str | int = "10m",
) -> Any:
    """Construct one backend by name."""
    if backend == "ollama":
        return OllamaEmbeddingBackend(
            model=model,
            base_url=ollama_url,
            local_url_suffixes=local_url_suffixes,
            keep_alive=keep_alive,
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

    There is no fallback chain (punch 552 / N-555): one configured
    embedder, and its failures reach the caller. An ``embedding.fallback``
    YAML section is ignored with a WARNING at config load
    (``config._warn_embedding_fallback_ignored``).

    Raises :class:`ValueError` when the config asks for a non-allowed
    backend (e.g. ``backend: openai`` / ``backend: AI provider``). The
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
    # N-431 (2026-07-19) — read the SAME ``ollama_keep_alive`` knob the
    # classifier reads (``config.classifier.ollama_keep_alive``). The
    # embedding-config section carries no per-embed keep_alive override
    # today — one setting drives both paths so a Forever pin covers the
    # whole install.
    _keep_alive = str(getattr(
        getattr(config, "classifier", None), "ollama_keep_alive", "10m",
    ) or "10m")

    return _build_single_backend(
        backend, model=model, ollama_url=ollama_url,
        local_url_suffixes=local_suffixes,
        keep_alive=_keep_alive,
    )


__all__ = [
    "OllamaEmbeddingBackend",
    "SentenceTransformersBackend",
    "build_embedding_backend",
    "_ALLOWED_EMBEDDING_BACKENDS",
]
