"""N-431 (2026-07-19) — Ollama-reuse SSOT: shared /api/ps probe + payload
merge for ``keep_alive`` (mandatory wire field).

Story: audit 2026-07-19 found 3 of 5 Ollama call sites in ``src/email_triage/``
missing the ``keep_alive`` payload field. Absent the field, Ollama applies its
built-in default ``"5m"`` per call, silently overriding any operator TTL pin
(including a Forever pin ``-1``). Recurrence class of
``feedback_always_set_ollama_keep_alive_explicitly`` — SSOT is the wire field.

Design: probe ``/api/ps`` once per process, cache per base_url with a 30s TTL,
serialize probe hops via an ``asyncio.Lock`` per base_url (N concurrent
classifiers → 1 probe). Applies the ``pattern_smoke_test_capability_discovery``
§Step 4 Forever-pin rule:

* ``keep_alive`` — when the loaded model's ``expires_at`` encodes a Forever
  pin (year > 2100) the SSOT mirrors ``-1`` so a caller who didn't override
  never downgrades the operator's Forever intent. Otherwise the caller-
  supplied default is injected. Caller-set values ALWAYS win — never
  downgrade a Forever pin unilaterally.

**Deliberately NOT mirrored: ``num_ctx``.** An earlier draft mirrored the
loaded model's ``details.context_length`` when the caller hadn't pinned one.
That widened the §4.2.3 byte-identical-options invariant (topic-match Stage A
+ Stage B must send identical ``options`` dicts) to depend on a shared cache
window; if the cache flipped between Stage A and Stage B, ``num_ctx`` differed
across stages and the KV-prefix reuse would miss (devils-advocate panel MF-2,
2026-07-19). The audit finding was `keep_alive`-only; num_ctx mirroring was
scope-creep. Dropped — the SSOT touches ONLY ``keep_alive``.

The Ollama daemon has open bugs  +  where ``keep_alive`` is
occasionally ignored at ``sched.go`` and a Forever-pinned model can be
evicted every 30s. Wiring the field is our (caller's) honest attempt;
recovery on an unwanted eviction is the keep-alive cron re-pin. Ref:
``investigation_keepalive_drift_and_think_warn`` (mempalace).

Enforced count-agnostic + interprocedural by
``tests/test_n431_ollama_reuse_ssot_pin.py`` — every ``.post(*/api/(chat|
embeddings)...)`` in ``src/email_triage/`` MUST precede the ``.post`` with a
``merge_reuse_options(payload, ...)`` call in the same function body.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from email_triage.triage_logging import get_logger

logger = get_logger("email_triage._ollama_reuse")

# 30s matches the prior instance-scoped cache TTL in
# ``OllamaClassifier._resolve_model`` (which now consumes this shared
# module-level probe — see classify/ollama.py). Short enough that a fresh
# manual model swap is picked up within one classification cycle; long
# enough that a batched sweep of N emails costs one probe, not N.
CACHE_TTL_SECONDS: float = 30.0

# Forever-pin sentinel: an ``expires_at`` ISO year above this threshold is
# ollama's marker for ``keep_alive: -1`` (year 9999 in practice). Bounded
# generous — a legitimate normal expiry never approaches this.
FOREVER_PIN_YEAR_THRESHOLD: int = 2100


class _CachedProbe:
    """Cache entry for one ``base_url``.

    ``rows`` maps model-name → the raw ``/api/ps`` row dict as parsed
    (fields: ``model``/``name``, ``expires_at``, ``size_vram``,
    ``details``). Callers extract what they need.
    """

    __slots__ = ("cached_at", "rows")

    def __init__(self, cached_at: float, rows: dict[str, dict[str, Any]]):
        self.cached_at = cached_at
        self.rows = rows


class OllamaReuseProbe:
    """Shared /api/ps probe + payload merger.

    One instance per process (module-level singleton ``_PROBE``). Per-base_url
    cache with a 30s TTL and an ``asyncio.Lock`` around the network hop so
    N concurrent classifiers pointing at the same URL cost ONE probe.
    """

    def __init__(self) -> None:
        self._cache: dict[str, _CachedProbe] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, base_url: str) -> asyncio.Lock:
        """Return the ``asyncio.Lock`` for ``base_url``, recreating it on a
        cross-loop RuntimeError.

        Python 3.10+ binds a Lock to the event loop on first ``.acquire()``.
        If the same process runs multiple ``asyncio.run(...)`` calls (rare
        but possible on M-4 batch re-entries via the CLI shim), a Lock from
        run #1 raises ``RuntimeError: … different loop`` when reused in
        run #2. Catch that and recreate transparently — the probe cache
        is per-base_url + timestamped, so a fresh Lock only ever ordering
        the CURRENT loop's probes is exactly what we want (db-sme NTH-2,
        2026-07-19 panel).
        """
        lock = self._locks.get(base_url)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[base_url] = lock
            return lock
        # Cheap loop-affinity probe: locked() returns False on a Lock that
        # hasn't been acquired in the current loop yet, but Lock methods
        # bind to a loop on first acquire. The RuntimeError surface is
        # on acquire(), so we can't pre-check — but ``_recover_lock``
        # below is called by the acquire() failure path via callers.
        return lock

    def _recover_lock(self, base_url: str) -> asyncio.Lock:
        """Replace ``_locks[base_url]`` with a fresh Lock and return it.
        Called from the ``RuntimeError`` recovery path in :meth:`probe`."""
        lock = asyncio.Lock()
        self._locks[base_url] = lock
        return lock

    async def probe(
        self,
        base_url: str,
        client: Any,
        *,
        timeout: float = 5.0,
    ) -> dict[str, dict[str, Any]]:
        """Return ``{model_name: /api/ps row dict}`` for ``base_url``.

        Cached per-base_url for 30s. On any failure (non-200, transport
        error, unparseable body) returns an empty dict — callers fall
        through to their caller-supplied defaults. The probe is
        best-effort observability; a dead ``/api/ps`` must NEVER break a
        classification call.
        """
        base_url = base_url.rstrip("/")
        now = time.monotonic()
        cached = self._cache.get(base_url)
        if cached is not None and (now - cached.cached_at) < CACHE_TTL_SECONDS:
            return cached.rows

        lock = self._get_lock(base_url)
        try:
            await lock.acquire()
        except RuntimeError:
            # Cross-loop Lock — recover per db-sme NTH-2. See
            # :meth:`_recover_lock` docstring.
            lock = self._recover_lock(base_url)
            await lock.acquire()

        try:
            # Double-check under the lock — a concurrent caller may have
            # refreshed while we were waiting.
            cached = self._cache.get(base_url)
            now = time.monotonic()
            if cached is not None and (now - cached.cached_at) < CACHE_TTL_SECONDS:
                return cached.rows

            rows: dict[str, dict[str, Any]] = {}
            try:
                resp = await client.get(
                    f"{base_url}/api/ps", timeout=timeout,
                )
                if resp.status_code == 200:
                    body = resp.json() or {}
                    for row in body.get("models", []) or []:
                        name = row.get("name") or row.get("model") or ""
                        if name:
                            rows[name] = row
            except Exception as e:
                # Best-effort — a dead /api/ps means we fall back to
                # caller-supplied defaults. Debug-log only; the classify
                # path's own circuit-breaker owns the availability signal.
                logger.debug(
                    "Ollama /api/ps probe failed (reuse SSOT)",
                    extra={
                        "base_url": base_url,
                        "error_type": type(e).__name__,
                        "error_msg": str(e),
                    },
                )

            self._cache[base_url] = _CachedProbe(now, rows)
            return rows
        finally:
            lock.release()

    async def merge_reuse_options(
        self,
        payload: dict[str, Any],
        base_url: str,
        model_name: str,
        client: Any,
        *,
        default_keep_alive: str | int = "10m",
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Mutate + return ``payload`` with ``keep_alive`` (always).

        Caller-set values ALWAYS win — never overwrite. A caller that sent
        ``keep_alive: -1`` (Forever pin) does not get its choice
        downgraded by a stale probe.

        **No probe on this path.** An earlier draft mirrored the daemon's
        Forever-pin sentinel (year-9999 ``expires_at`` from ``/api/ps``)
        into ``-1`` so a caller who did NOT override the default never
        unintentionally downgraded a Forever-pinned model. That added an
        ``/api/ps`` hop on every ``.post`` (cached 30s per base_url, but
        still a shared-cache dependency + a mock-brittle seam). The
        operator's config knob ``classifier.ollama_keep_alive`` is the
        canonical seam — an operator running a Forever-pin cron who also
        wants classifier writes to reinforce that pin sets
        ``ollama_keep_alive: -1`` in YAML. The bug the SSOT closes is
        "absent field → silent 5m daemon default"; unconditional default
        injection closes that fully without a probe hop. The probe
        machinery below (``probe()``) still exists for ``_resolve_model``
        chat-name picking — that path already needed ``/api/ps``.

        Field is always present after this call (fixing the "silent 5m
        Ollama default" recurrence class).
        """
        # Signature preserves ``base_url``/``model_name``/``client``/``timeout``
        # so a future re-introduction of probe-based Forever-pin mirroring
        # (should the operator want defense-in-depth without a config
        # override) doesn't have to touch every wire site's call shape.
        _ = base_url, model_name, client, timeout  # currently unused
        if "keep_alive" not in payload:
            payload["keep_alive"] = default_keep_alive
        return payload


def _expires_at_is_forever_pin(expires_at: str) -> bool:
    """True if the ISO8601 expires_at string encodes a Forever-pin sentinel.

    Ollama emits year 9999 (or similar > 2100) when ``keep_alive: -1`` is
    active for a loaded model. A normal TTL never approaches this — the
    year-threshold check is a cheap string-prefix parse that tolerates
    any ISO offset shape.
    """
    if not expires_at or not isinstance(expires_at, str):
        return False
    if len(expires_at) < 4:
        return False
    year_str = expires_at[:4]
    if not year_str.isdigit():
        return False
    # ``.isdigit()`` on a 4-char slice guarantees ``int()`` succeeds —
    # no try/except needed (would trip the N-219 R23 hand-roll ratchet
    # and be dead-arm besides).
    return int(year_str) > FOREVER_PIN_YEAR_THRESHOLD


# Module-level singleton. Callers do NOT instantiate their own —
# the whole point is one shared probe cache across OllamaClassifier +
# OllamaEmbeddingBackend + the CLI embed shim.
_PROBE = OllamaReuseProbe()


async def merge_reuse_options(
    payload: dict[str, Any],
    base_url: str,
    model_name: str,
    client: Any,
    *,
    default_keep_alive: str | int = "10m",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Module-level shim over the singleton. This is the function the SSOT
    pin looks for by name at every /api/(chat|embeddings) call site."""
    return await _PROBE.merge_reuse_options(
        payload, base_url, model_name, client,
        default_keep_alive=default_keep_alive, timeout=timeout,
    )


async def probe(
    base_url: str, client: Any, *, timeout: float = 5.0,
) -> dict[str, dict[str, Any]]:
    """Module-level shim for callers that only need the /api/ps result
    (``OllamaClassifier._resolve_model`` in ``classify/ollama.py``
    consumes this to pick the resident chat model — DA panel MF-1
    close, 2026-07-19)."""
    return await _PROBE.probe(base_url, client, timeout=timeout)


# ---------------------------------------------------------------------------
# ``keep_alive`` format validator — shared by the config YAML parse + the
# admin form parse so both surfaces reject bad shapes uniformly (DA panel
# MF-3, 2026-07-19). Ollama's ``keep_alive`` accepts:
#   * integer seconds (``0`` = unload immediately, positive = TTL seconds,
#     ``-1`` = Forever pin);
#   * duration string ``<int><unit>`` where unit ∈ ``{s, m, h}`` (e.g.
#     ``"10m"``, ``"1h"``, ``"30s"``).
# The bare ``-1`` Forever-pin exception is allowed; other negatives are
# not. A typo like ``"1o"`` (letter O for minute) would reach Ollama,
# which 400s and falls back to its daemon default — the exact silent-5m
# bug we're closing. Reject at the config seam, not the wire.
# ---------------------------------------------------------------------------

import re as _re

_KEEP_ALIVE_ACCEPT = _re.compile(r"^(-1|0|[1-9][0-9]*[smh]?)$")


def is_valid_keep_alive(value: Any) -> bool:
    """True if ``value`` is a valid Ollama ``keep_alive`` shape.

    Accepts ``int`` (``-1``, ``0``, or positive) or ``str`` matching
    ``^(-1|0|<positive-int>[smh]?)$``. Anything else — a bool, a stray
    unit like ``"1o"``, a leading ``+``, whitespace — rejects.
    """
    if isinstance(value, bool):
        return False  # bool subclasses int but semantically wrong
    if isinstance(value, int):
        return value == -1 or value >= 0
    if isinstance(value, str):
        return bool(_KEEP_ALIVE_ACCEPT.match(value))
    return False


def _reset_for_tests() -> None:
    """Clear the singleton's per-base_url cache + locks. Tests only."""
    _PROBE._cache.clear()
    _PROBE._locks.clear()
