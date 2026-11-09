"""Ollama-reuse SSOT: shared /api/ps probe + the ``keep_alive`` decision.

Story, in two parts.

N-431 (2026-07-19): an audit found 3 of 5 Ollama call sites missing the
``keep_alive`` field. Absent the field the daemon applies ITS OWN default, so
the fix made the field mandatory and always injected.

2026-09-10: that fix was itself the bug on a host launched with
``OLLAMA_KEEP_ALIVE=-1``. A per-request ``keep_alive`` OVERRIDES the daemon
env, so injecting a finite default demoted the operator's Forever pin on EVERY
call — measured, a Topic-match call produced ``expires_at`` = now+10m to the
second. The rule is now the operator's (2026-08-18, verbatim): *"if the
keep_alive is forever -> send back -1 to keep it. If it is not, don't send a
keep_alive back at all and let ollama just reset the timeout on it's own."*

**Absence is NOT neutral, and this cuts both ways** — it hands the decision to
the daemon's own default. Where that default is ``-1`` (this deployment)
omission is exactly right. Where it is finite, omission RESETS the expiry, and
a probe miss or failure will quietly demote. This module is therefore correct
for a Forever-env daemon and deployment-specific in general; anyone reusing it
against a daemon they do not control must revisit the fail-open direction.

Design: probe ``/api/ps`` once per process, cache per base_url with a 30s TTL,
serialize probe hops via an ``asyncio.Lock`` per base_url (N concurrent
classifiers → 1 probe).

* ``keep_alive`` — a Forever pin (``expires_at`` year > 2100) is reinforced
  with the int ``-1``; anything else, INCLUDING an unreadable probe, sends no
  field at all. Unknown state fails toward omission, which can only decline to
  extend a pin rather than destroy one. Caller-set values still win, though no
  shipped call site sets one — see the caller pin in
  ``test_n431_ollama_reuse_ssot_pin.py``.

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
# ollama's marker for ``keep_alive: -1``. MEASURED on this deployment
# 2026-09-10: the daemon emits year **2318**, not 9999 — so this must stay a
# year THRESHOLD; an equality check on 9999 would read every Forever pin here
# as a normal TTL. Bounded generous — a legitimate expiry never approaches it.
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
        """Mutate + return ``payload``, honouring an existing Forever pin.

        Implements the operator's canonical caller policy (2026-08-18,
        verbatim): *"if the keep_alive is forever -> send back -1 to keep
        it. If it is not, don't send a keep_alive back at all and let
        ollama just reset the timeout on it's own."*

        Precedence, highest first:

        1. **Caller-set ``keep_alive`` wins** — never overwritten. A caller
           that sent ``-1`` does not get downgraded by a stale probe.
        2. **An explicit Forever default wins** — an operator who set
           ``classifier.ollama_keep_alive: -1`` in YAML is reinforcing a
           pin on purpose, so send it without spending a probe.
        3. **Otherwise probe** ``/api/ps`` (30s-cached per base_url): if the
           model's ``expires_at`` encodes a Forever pin, send ``-1`` to
           preserve it; if not — or if the probe could not tell us — send
           **no ``keep_alive`` field at all**.

        How ``keep_alive`` behaves on the daemon is defined in ONE place,
        the mempalace drawer
        ``decision_2026-08-18_ollama_keep_alive_canonical_policy``. Read it
        there; it is not restated here. The parts this method depends on:
        every request writes the model's host-global residency timer, and
        a request with NO ``keep_alive`` field is not neutral — it sets a
        fresh finite timeout. Only re-sending ``-1`` keeps a Forever pin.

        **Why the finite default is no longer injected unconditionally.**
        The previous shape always wrote ``default_keep_alive`` (``"10m"``)
        when the caller set nothing, which replaced any Forever pin with a
        10-minute timer on every classify call — measured 2026-09-10,
        where a Topic-match call at 20:16:50Z produced ``expires_at``
        20:26:50Z to the second. Re-pinning a 24 GB model after an eviction
        is expensive, so the demotion is not cosmetic.

        **What happens when the probe cannot tell (operator ruling 2026-10-10).**
        If ``/api/ps`` fails, times out, or does not list the model, this
        method sends no ``keep_alive`` field (case 3's else branch), so the
        server default applies. That is the intended fallback, not a gap:
        in practice the probe comes back empty only when no model is
        loaded, and then this call loads one with the server defaults,
        which is the load path the deployment is built around. Omission is
        still a write under the canonical mechanism (it sets a fresh finite
        timeout), so do not describe it as neutral; it is chosen, not
        harmless.
        """
        if "keep_alive" in payload:
            return payload

        if _is_forever_keep_alive(default_keep_alive):
            # NORMALISE to the int -1 — never the configured value verbatim.
            # The config seam always hands us a STRING (``config.py`` types
            # ``ollama_keep_alive: str`` and does ``str(_keep_alive)``), so
            # YAML ``-1`` arrives as ``"-1"`` — and Ollama REJECTS that at
            # duration-parse: measured against the daemon 2026-09-10,
            #   {"keep_alive": "-1"} -> 400 time: missing unit in duration "-1"
            #   {"keep_alive": -1}   -> accepted
            # A 400 is an HTTPStatusError, not connect-class, so
            # ``translate_unreachable`` does not convert it and the topic
            # path FALLS OPEN to zero verdicts, silently, on a PHI-classifying
            # call. ``scripts/llm_host_prepass.py`` had already documented that
            # the string form is rejected and int-only is required.
            payload["keep_alive"] = -1
            return payload

        rows = await self.probe(base_url, client, timeout=timeout)
        row = rows.get(model_name) or {}
        if _expires_at_is_forever_pin(str(row.get("expires_at") or "")):
            payload["keep_alive"] = -1
        # else: deliberately send NO keep_alive field — see docstring.
        return payload


def _is_forever_keep_alive(value: Any) -> bool:
    """True if ``value`` is the Forever-pin sentinel ``-1``.

    Accepts the int ``-1`` and its string spelling, since the config seam
    carries ``ollama_keep_alive`` as a ``str`` while callers may pass an
    int. Any other value — including other negatives, which
    :func:`is_valid_keep_alive` already rejects at the config seam — is
    not a Forever pin.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == -1
    if isinstance(value, str):
        return value.strip() == "-1"
    return False


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
