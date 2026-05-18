"""Optional Redis-backed cache for LLM classification results (#151).

The same inbound email — same sender, same subject, same body — passes
the classifier on every retry / poll / push wake. For installs that see
a lot of repeat traffic (Iperius backup mails, monitor alerts, list
mail), this means re-spending tokens on results we've already computed.
This module is the optional GET-before-LLM cache that short-circuits
that path.

Shape
-----
* **Optional** by design. Empty Redis URL = cache OFF, no behaviour
  change. Lazy initialise on first lookup; no connection at startup.
* **Key**: SHA-256 of
  ``(account_id, sender_norm, subject_norm, body_hash, classifier_model,
  prompt_version)``. Hashing the key is defence-in-depth: even though
  the cache is OFF for HIPAA accounts, the sender + subject shape is
  PHI-flavoured and we don't want it sitting in a Redis ``KEYS *``
  dump in cleartext.
* **Value**: JSON ``{category, reason, confidence, classified_at,
  model}``. Stored cleartext (server-side Redis isn't authenticated +
  the operator's responsibility to keep on a LAN-only host). The
  ``reason`` string is classifier free-text and could leak prompt
  fragments — see "Privacy invariants" below.
* **TTL**: configurable, default 30 days. Operator-tunable per install
  via ``/admin/integrations``.
* **HIPAA gate**: callers must skip ``lookup``/``store`` when the
  message is HIPAA-flagged. The cache module trusts the caller's gate;
  it doesn't re-check.

Server choice
-------------
The protocol is plain Redis 5+. The ``valkey`` fork (Linux Foundation,
2024-onward) speaks the identical wire protocol — an operator can
point the URL at a valkey-server instance instead of a Redis instance
and everything below works unchanged. The package name on PyPI is
``redis`` and stays that way; no library change is needed.

Privacy invariants
------------------
* This module NEVER logs the cached ``value`` dict in cleartext. The
  cache key is hashed; the cache value's ``reason`` field carries
  classifier free-text (in non-HIPAA mode this can name the sender /
  subject / topic — fine for the cache, NOT fine for the logs).
  Only counter-style + boolean facts ("hit" / "miss" / "error") are
  log-safe.
* The Redis URL is the credential — operators paste it into the
  YAML, not the secrets store. The URL itself is non-PHI metadata
  (host + port); the data it carries is what we gate via HIPAA.
* External-data-flow rule (project memory): the URL must point at
  the operator's audited LAN-host allowlist (e.g. an on-prem Redis
  instance). Default empty — opt-in only.

Circuit-breaker
---------------
On Redis-unreachable errors the lookup logs WARN once per breaker
window and returns ``None`` (cache miss). The next call retries.
Reuses :class:`LLMBackendUnreachableError` shape for symmetry with
the #149 Bundle B classifier-side breaker, but cache failures are
strictly best-effort — they NEVER raise into the caller. Live LLM
call always wins as the fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("email_triage.cache.classification")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Bumped when the prompt template changes in a way that would invalidate
#: every previously-cached result. Included in the cache key so old
#: entries simply stop matching (no manual flush needed).
PROMPT_VERSION = "v1"

#: Default TTL — 30 days. Matches the spec; operator-overrideable.
DEFAULT_TTL_SECS = 30 * 24 * 3600

#: Lower clamp on operator-supplied TTL — anything shorter than 1 hour
#: is pointless for a classification cache (re-poll cadences alone
#: would expire entries before they could be reused).
MIN_TTL_SECS = 3600

#: Upper clamp on operator-supplied TTL — 90 days. Past that the
#: cached classifier rationale stops resembling current taxonomy /
#: model output; a model-version bump or category-rename should
#: have rolled over the keyspace by then.
MAX_TTL_SECS = 90 * 24 * 3600

#: Key prefix. Lets an operator share a Redis DB with other services
#: and still scope a ``KEYS et:cls:*`` debug command. Used by the
#: manual-flush admin path to know which keys belong to us.
KEY_PREFIX = "et:cls:"


def clamp_ttl_secs(value: int | None, default: int = DEFAULT_TTL_SECS) -> int:
    """Clamp an operator-supplied TTL into the supported window.

    Spec: ``[3600, 7_776_000]`` (1 hour to 90 days). Anything below
    snaps up to the floor, anything above snaps down to the ceiling.
    ``None`` / non-int input falls back to ``default`` before clamping.
    """
    try:
        v = int(value) if value is not None else default
    except (TypeError, ValueError):
        v = default
    if v < MIN_TTL_SECS:
        return MIN_TTL_SECS
    if v > MAX_TTL_SECS:
        return MAX_TTL_SECS
    return v


# ---------------------------------------------------------------------------
# Per-process counters (surfaced on /health/detail)
# ---------------------------------------------------------------------------

class _Counters:
    """Thread-safe int counters for the health snapshot.

    Module-level singleton — :func:`get_counters` reads it. The health
    endpoint surfaces every counter so the operator can tell which
    branch of the two-level cache is doing work.

    Counter taxonomy (2026-05-13 two-level refactor):
      hits_exact         Branch 1 — outer + inner both matched; LLM skipped.
      hits_hint_topk     Branch 2 in C mode — outer matched, inner miss,
                         top-K hint passed to LLM, LLM ran.
      hits_hint_dominant Branch 2 in B mode — outer matched, dominant
                         category hint passed, LLM ran.
      hits_hint_skipped  Branch 2 in B mode — outer matched but no
                         category was dominant enough; LLM cold.
      misses_cold        No outer key — first-ever email from this
                         sender; LLM cold + store-back.
      errors             Redis-side failures (any layer).

    Legacy aliases (kept for back-compat with older /health consumers
    that read ``hits`` / ``misses``): ``hits = hits_exact``,
    ``misses = hits_hint_topk + hits_hint_dominant + hits_hint_skipped + misses_cold``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.hits_exact = 0
        self.hits_hint_topk = 0
        self.hits_hint_dominant = 0
        self.hits_hint_skipped = 0
        self.misses_cold = 0
        self.errors = 0

    # Namespace for the persistent (Redis-backed) mirror. Keeps the
    # cache counters separate from embedding / webhook namespaces so
    # the admin "reset lifetime" button can flush just one slice.
    _PERSIST_NAMESPACE = "classification_cache"

    def _mirror(self, field: str) -> None:
        """Best-effort HINCRBY to the install-level Redis backend.

        Lazy-imported so a cache write in a test without Redis wired
        doesn't pay the import. The backend itself silently no-ops
        when the URL is empty / Redis unreachable.
        """
        try:
            from email_triage.engine.persistent_counters import (
                get_install_counter_backend,
            )
            be = get_install_counter_backend()
            if be is not None:
                be.incr(self._PERSIST_NAMESPACE, field)
        except Exception:  # noqa: BLE001
            pass

    def incr_hit_exact(self) -> None:
        with self._lock:
            self.hits_exact += 1
        self._mirror("hits_exact")

    def incr_hit_hint_topk(self) -> None:
        with self._lock:
            self.hits_hint_topk += 1
        self._mirror("hits_hint_topk")

    def incr_hit_hint_dominant(self) -> None:
        with self._lock:
            self.hits_hint_dominant += 1
        self._mirror("hits_hint_dominant")

    def incr_hit_hint_skipped(self) -> None:
        with self._lock:
            self.hits_hint_skipped += 1
        self._mirror("hits_hint_skipped")

    def incr_miss_cold(self) -> None:
        with self._lock:
            self.misses_cold += 1
        self._mirror("misses_cold")

    def incr_error(self) -> None:
        with self._lock:
            self.errors += 1
        self._mirror("errors")

    # Legacy aliases — kept for back-compat with older code paths
    # that still call incr_hit / incr_miss. Maps to the new fields.
    def incr_hit(self) -> None:
        self.incr_hit_exact()

    def incr_miss(self) -> None:
        self.incr_miss_cold()

    @property
    def hits(self) -> int:
        """Legacy alias — number of LLM-skipping cache hits."""
        return self.hits_exact

    @property
    def misses(self) -> int:
        """Legacy alias — count of every non-Branch-1 outcome."""
        return (
            self.hits_hint_topk + self.hits_hint_dominant
            + self.hits_hint_skipped + self.misses_cold
        )

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "hits": self.hits_exact,
                "misses": (
                    self.hits_hint_topk + self.hits_hint_dominant
                    + self.hits_hint_skipped + self.misses_cold
                ),
                "hits_exact": self.hits_exact,
                "hits_hint_topk": self.hits_hint_topk,
                "hits_hint_dominant": self.hits_hint_dominant,
                "hits_hint_skipped": self.hits_hint_skipped,
                "misses_cold": self.misses_cold,
                "errors": self.errors,
            }


_counters = _Counters()


def get_counters() -> _Counters:
    """Return the process-level counter singleton."""
    return _counters


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")
# Case-insensitive leading "Re:" / "Fwd:" stripper. Repeated prefixes
# ("Re: Re: Fwd: ...") get collapsed in one pass via ``while`` in the
# normaliser below — single regex with ``^(re|fwd|fw):`` is the test
# substring + we keep applying it as long as it matches a leading run
# of those tokens. ``fw:`` is the Outlook variant; ``aw:`` German
# variant skipped (operator install is English-only).
_SUBJECT_PREFIX_RE = re.compile(r"^\s*(?:re|fwd|fw)\s*:\s*", re.IGNORECASE)


def _norm(s: str) -> str:
    """Whitespace-collapsed, lowercase normalisation for sender + subject.

    Same email triaged on two providers (Gmail vs Office365) often
    differs only in header casing / whitespace; normalising lets the
    cache hit across the no-op variations.
    """
    return _WS.sub(" ", (s or "").strip()).lower()


def normalise_subject(subject: str) -> str:
    """Strip leading ``Re:`` / ``Fwd:`` / ``Fw:`` (case-insensitive)
    + collapse whitespace + lowercase.

    2026-05-13 — added for the two-level cache so reply chains collapse
    to the same outer-sender / inner-subject discriminator. Operator
    chose to leave everything else (dates, ticket numbers, [Today]
    prefixes) untouched per the trade-off discussion: tighter normalise
    = more inner hits but more risk of conflating distinct messages.
    Today's call leaves those distinct.
    """
    s = subject or ""
    # Strip repeated leading Re:/Fwd: tokens (``Re: Fwd: Re: foo`` → ``foo``).
    while True:
        new = _SUBJECT_PREFIX_RE.sub("", s, count=1)
        if new == s:
            break
        s = new
    return _norm(s)


def compute_body_hash(body_text: str) -> str:
    """SHA-256 of the message body (normalised).

    The classifier sees ``body_text`` from the provider, not raw RFC822
    — providers already do MIME decode + HTML strip — so this is the
    right canonical form to hash. Whitespace is collapsed first so
    auto-replies that round-trip CR/LF don't break the cache.
    """
    canonical = _WS.sub(" ", (body_text or "").strip())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def make_outer_cache_key(
    *,
    account_id: int,
    sender: str,
    classifier_model: str,
    prompt_version: str = PROMPT_VERSION,
) -> str:
    """Outer Redis HASH key — one per (account, sender, model, prompt) triple.

    Drops subject + body from the key so all classifications from the
    same sender land in the SAME HASH. The inner field (per-message
    discriminator) holds (subject, body_hash). Cache hits split into
    two branches:
      * Branch 1 — inner exact match → return cached, skip LLM.
      * Branch 2 — outer match, inner miss → summarise sibling fields
        into a category-distribution hint that biases the LLM call.

    SHA-256 of the tuple (defence-in-depth — sender is PHI-shape; a
    Redis ``KEYS *`` dump shouldn't surface it cleartext).
    """
    payload = "|".join([
        str(account_id),
        _norm(sender),
        classifier_model.strip(),
        prompt_version.strip(),
    ])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{KEY_PREFIX}{digest}"


def make_inner_cache_field(
    *,
    subject: str,
    body_hash: str,
) -> str:
    """Inner HASH field — discriminates between distinct messages from
    the same sender. SHA-256 of (subject_norm, body_hash). The subject
    is normalised via :func:`normalise_subject` so reply-chain prefixes
    don't fragment a single conversation across multiple inner fields.
    """
    payload = "|".join([
        normalise_subject(subject),
        body_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_cache_key(
    *,
    account_id: int,
    sender: str,
    subject: str,
    body_hash: str,
    classifier_model: str,
    prompt_version: str = PROMPT_VERSION,
) -> str:
    """Legacy flat-key derivation — kept for back-compat with tests
    that pinned the pre-2026-05-13 shape. New code uses
    :func:`make_outer_cache_key` + :func:`make_inner_cache_field`.

    The flat key is no longer used by the live lookup / store path;
    operator's ``FLUSHDB`` on cutover wiped the prior 247 flat entries.
    """
    payload = "|".join([
        str(account_id),
        _norm(sender),
        _norm(subject),
        body_hash,
        classifier_model.strip(),
        prompt_version.strip(),
    ])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{KEY_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Cache class
# ---------------------------------------------------------------------------

@dataclass
class _BreakerState:
    """Lightweight circuit-breaker for Redis-unreachable errors.

    Mirrors the shape of ``email_triage.llm_health.set_unhealthy`` but
    stays local to the cache module — keeping the dependency surface
    minimal. When ``open_until`` is in the future, ``lookup`` returns
    ``None`` immediately without attempting a Redis round-trip.
    """
    open_until: float = 0.0  # monotonic deadline; 0 = closed
    last_reason: str = ""


class ClassificationCache:
    """Optional Redis-backed cache for classification results.

    Best-effort by design: every failure path returns ``None`` from
    ``lookup`` and is a no-op in ``store``. The caller never has to
    catch a Redis exception — failures fall through to the live LLM
    call, which is the safety net.

    Lazy connection — the ``redis`` client is built on first lookup,
    not at init. Empty URL = "cache disabled" sentinel; every method
    is a no-op until the operator pastes a URL into
    ``/admin/integrations``.

    Parameters
    ----------
    url:
        Redis URL, e.g. ``"redis://your-lan-host:6379/0"``.
        Empty string disables the cache.
    default_ttl_secs:
        Default TTL applied to ``store`` calls that don't pass an
        explicit ``ttl_secs`` override.
    breaker_ttl_secs:
        How long the circuit-breaker stays open after a Redis error.
        Short window (60 s default) — Redis is local-LAN, so reconnect
        is cheap and we want to recover quickly from a transient blip.
    """

    def __init__(
        self,
        url: str = "",
        default_ttl_secs: int = DEFAULT_TTL_SECS,
        breaker_ttl_secs: int = 60,
        *,
        inner_cap_per_sender: int = 250,
        hint_strategy: str = "top_k_with_freq",
        dominant_threshold_pct: int = 70,
    ) -> None:
        self._url = (url or "").strip()
        self._default_ttl = int(default_ttl_secs)
        self._breaker_ttl = int(breaker_ttl_secs)
        self._breaker = _BreakerState()
        self._client: Any = None  # lazily built
        self._client_lock = threading.Lock()
        # 2026-05-13 two-level cache tuning knobs (operator-configurable
        # on /config?tab=ai_backends).
        self.inner_cap_per_sender = max(1, int(inner_cap_per_sender))
        self.hint_strategy = (
            hint_strategy if hint_strategy in (
                "top_k_with_freq", "top_1_dominant",
            ) else "top_k_with_freq"
        )
        self.dominant_threshold_pct = max(50, min(100, int(dominant_threshold_pct)))

    # -- Properties ---------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """True when a non-empty Redis URL is configured."""
        return bool(self._url)

    # -- Lazy connect -------------------------------------------------------

    def _get_client(self) -> Any:
        """Build / return the synchronous Redis client.

        Sync (not async) because the classifier is already an async
        function whose LLM POST is the slow path. A round-trip to a
        LAN Redis is sub-millisecond — running it on the event loop
        directly is fine, no thread pool needed.

        Lazily imports ``redis`` so installs without the optional
        ``cache`` extra installed don't error at import time.
        """
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is not None:
                return self._client
            try:
                import redis  # type: ignore[import-not-found]
            except ImportError as exc:
                logger.warning(
                    "Classification cache: redis package not installed "
                    "(pip install email-triage[cache]); cache disabled "
                    "for this process",
                )
                self._open_breaker(f"import error: {exc}")
                return None
            try:
                # ``decode_responses=True`` gives us str in/out, which
                # plays nicely with json.dumps/loads. ``socket_timeout``
                # short — LAN-only, and we don't want to block the
                # classifier on a slow / stuck Redis.
                client = redis.Redis.from_url(
                    self._url,
                    decode_responses=True,
                    socket_timeout=2.0,
                    socket_connect_timeout=2.0,
                )
            except Exception as exc:  # noqa: BLE001 — Redis raises misc types
                logger.warning(
                    "Classification cache: client init failed; cache "
                    "disabled for this breaker window",
                )
                self._open_breaker(f"init error: {exc}")
                return None
            self._client = client
            return self._client

    # -- Breaker ------------------------------------------------------------

    def _breaker_open(self) -> bool:
        return self._breaker.open_until > time.monotonic()

    def _open_breaker(self, reason: str) -> None:
        self._breaker.open_until = time.monotonic() + self._breaker_ttl
        self._breaker.last_reason = reason[:200]
        # Drop the broken client so the next attempt rebuilds it.
        self._client = None

    # -- Public API ---------------------------------------------------------

    def lookup(self, key: str) -> dict[str, Any] | None:
        """Return the cached classification dict, or ``None`` on miss.

        Never raises — Redis errors, breaker-open, missing client all
        return ``None`` so the caller falls through to the live LLM
        path. Counter-side-effects: a clean miss bumps ``misses``; a
        Redis-side error bumps ``errors``; a hit bumps ``hits``.
        """
        if not self.enabled:
            return None
        if self._breaker_open():
            return None
        client = self._get_client()
        if client is None:
            return None
        try:
            raw = client.get(key)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: GET failed (%s); falling through "
                "to LLM. cache_hit=False breaker_open=True",
                type(exc).__name__,
            )
            self._open_breaker(f"GET: {exc}")
            _counters.incr_error()
            return None
        if raw is None:
            _counters.incr_miss()
            return None
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("cache value is not a JSON object")
        except Exception as exc:  # noqa: BLE001
            # Corrupted entry — drop it on the floor, count as miss
            # (NOT error — Redis itself is healthy).
            logger.warning(
                "Classification cache: corrupt JSON in %s.. (%s); "
                "treating as miss",
                key[:24], type(exc).__name__,
            )
            _counters.incr_miss()
            return None
        _counters.incr_hit()
        return parsed

    def store(
        self,
        key: str,
        value: dict[str, Any],
        ttl_secs: int | None = None,
    ) -> None:
        """Write a classification result to the cache. Never raises.

        ``value`` is JSON-serialised then SET with the configured TTL.
        On any Redis error the breaker opens and the call is a no-op;
        the live LLM result the caller is about to return remains
        unaffected.
        """
        if not self.enabled:
            return
        if self._breaker_open():
            return
        client = self._get_client()
        if client is None:
            return
        ttl = int(ttl_secs if ttl_secs is not None else self._default_ttl)
        try:
            payload = json.dumps(value, separators=(",", ":"))
        except (TypeError, ValueError):
            # Caller passed something non-JSON — don't poison the cache.
            logger.warning(
                "Classification cache: value not JSON-serialisable; "
                "skipping store",
            )
            return
        try:
            client.set(key, payload, ex=ttl)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: SET failed (%s); breaker open",
                type(exc).__name__,
            )
            self._open_breaker(f"SET: {exc}")
            _counters.incr_error()
            return

    def lookup_inner(
        self, outer_key: str, inner_field: str,
    ) -> dict[str, Any] | None:
        """Branch 1 — exact (outer, inner) match. Returns the cached
        payload dict or ``None`` on miss / error. Never raises.

        Does NOT bump counters here — the caller (cache_lookup_for_message)
        knows the branch context + bumps the right counter (hits_exact
        vs hits_hint_*). Keeps the counter logic centralised at the
        helper layer.
        """
        if not self.enabled or self._breaker_open():
            return None
        client = self._get_client()
        if client is None:
            return None
        try:
            raw = client.hget(outer_key, inner_field)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: HGET failed (%s); breaker open",
                type(exc).__name__,
            )
            self._open_breaker(f"HGET: {exc}")
            _counters.incr_error()
            return None
        if raw is None:
            return None
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("inner value not a JSON object")
            return parsed
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: corrupt inner JSON %s.. (%s)",
                outer_key[:24], type(exc).__name__,
            )
            return None

    def fetch_field_set(self, outer_key: str) -> list[dict[str, Any]]:
        """Branch 2 — pull every inner field's payload for an outer key.

        Returns a list of value-dicts (NOT the field names; caller only
        needs the category distribution for hint derivation). Empty
        list on outer-miss / error.

        ``HGETALL`` is O(N) where N is the HASH size — capped at
        ``inner_cap_per_sender`` (default 250) so the per-call cost
        stays bounded.
        """
        if not self.enabled or self._breaker_open():
            return []
        client = self._get_client()
        if client is None:
            return []
        try:
            raw_map = client.hgetall(outer_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: HGETALL failed (%s); breaker open",
                type(exc).__name__,
            )
            self._open_breaker(f"HGETALL: {exc}")
            _counters.incr_error()
            return []
        out: list[dict[str, Any]] = []
        for _field, raw in (raw_map or {}).items():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    out.append(parsed)
            except Exception:  # noqa: BLE001
                continue
        return out

    def store_inner(
        self,
        outer_key: str,
        inner_field: str,
        value: dict[str, Any],
        *,
        ttl_secs: int | None = None,
        cap: int = 250,
    ) -> None:
        """Write a per-message inner entry. LRU-evicts at ``cap``.

        When the outer HASH reaches ``cap`` fields, the oldest entry
        (by ``classified_at`` ISO timestamp in the payload) is HDEL'd
        before the new field is added. Bounds growth on heavy-traffic
        senders + keeps Branch 2's full-set summarise cost bounded.

        Resets the outer key's TTL on every write so a sender that
        keeps sending stays cached. Sender that goes silent for the
        full window TTL-expires the whole HASH at once.
        """
        if not self.enabled or self._breaker_open():
            return
        client = self._get_client()
        if client is None:
            return
        ttl = int(ttl_secs if ttl_secs is not None else self._default_ttl)
        try:
            payload = json.dumps(value, separators=(",", ":"))
        except (TypeError, ValueError):
            logger.warning(
                "Classification cache: inner value not JSON-serialisable; skipping",
            )
            return
        try:
            # LRU eviction — pull the field set + drop the oldest if
            # we'd exceed the cap. Skip the check when cap<=0 (defensive
            # bound) or when the current field already exists (overwrite,
            # not insert).
            if cap > 0:
                size = int(client.hlen(outer_key) or 0)
                already_present = bool(client.hexists(outer_key, inner_field))
                if size >= cap and not already_present:
                    # Find oldest by classified_at; HDEL it.
                    raw_map = client.hgetall(outer_key) or {}
                    oldest_field: str | None = None
                    oldest_ts: str = ""
                    for fld, raw in raw_map.items():
                        try:
                            ts = str(json.loads(raw).get("classified_at", ""))
                        except Exception:
                            ts = ""
                        if oldest_field is None or ts < oldest_ts:
                            oldest_field = fld
                            oldest_ts = ts
                    if oldest_field is not None:
                        try:
                            client.hdel(outer_key, oldest_field)
                        except Exception:  # noqa: BLE001
                            pass
            client.hset(outer_key, inner_field, payload)
            client.expire(outer_key, ttl)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: HSET failed (%s); breaker open",
                type(exc).__name__,
            )
            self._open_breaker(f"HSET: {exc}")
            _counters.incr_error()

    def flush_all(self) -> int:
        """Delete every classification-cache key in this Redis DB.

        Scoped via the module ``KEY_PREFIX`` so we don't touch keys
        belonging to other services sharing the Redis instance.
        Returns the number of keys deleted; ``0`` when the cache is
        disabled or the breaker is open.

        Iteration uses ``SCAN`` (cursor) over ``KEYS`` so a flush on a
        large cache doesn't block Redis. Deletes in batches of 500 to
        keep the per-DEL payload bounded.

        Best-effort: any Redis error opens the breaker and returns the
        partial count. Surfaced from the admin "Flush cache" button +
        an operator-callable for scripting.
        """
        if not self.enabled:
            return 0
        if self._breaker_open():
            return 0
        client = self._get_client()
        if client is None:
            return 0
        total = 0
        try:
            cursor = 0
            batch: list[str] = []
            while True:
                cursor, keys = client.scan(
                    cursor=cursor,
                    match=f"{KEY_PREFIX}*",
                    count=500,
                )
                if keys:
                    batch.extend(keys)
                    if len(batch) >= 500:
                        deleted = client.delete(*batch)
                        total += int(deleted or 0)
                        batch = []
                if cursor == 0:
                    break
            if batch:
                deleted = client.delete(*batch)
                total += int(deleted or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: flush_all failed (%s); breaker open",
                type(exc).__name__,
            )
            self._open_breaker(f"FLUSH: {exc}")
            _counters.incr_error()
            return total
        logger.info(
            "Classification cache: flushed %d keys via admin action",
            total,
        )
        return total

    def close(self) -> None:
        """Drop the underlying Redis client. Idempotent."""
        with self._client_lock:
            client = self._client
            self._client = None
        if client is None:
            return
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Install-level singleton (mirrors providers/factory.py pattern)
# ---------------------------------------------------------------------------

_install_classification_cache: ClassificationCache | None = None


def set_install_classification_cache(cache: ClassificationCache | None) -> None:
    """Register the install-level :class:`ClassificationCache` singleton.

    Called from ``web/app.py`` lifespan after the ``RedisCacheConfig``
    is read. Pass ``None`` to disable explicitly.
    """
    global _install_classification_cache
    _install_classification_cache = cache


def get_install_classification_cache() -> ClassificationCache | None:
    """Return the install-level cache singleton, or ``None`` when unset."""
    return _install_classification_cache


# ---------------------------------------------------------------------------
# Classifier helpers — shared lookup / store path used by every backend
# (ollama / gemini / openai_compat). Keeps the cache-aware logic in one
# place so a backend that adds cache support only has to call these
# two helpers, not re-implement the HIPAA gate + counter bookkeeping
# from scratch.
# ---------------------------------------------------------------------------


def cache_key_for_message(
    message: Any, classifier_model: str,
) -> str | None:
    """LEGACY flat-key helper kept for back-compat with tests pinned to
    the pre-2026-05-13 single-key shape. New live code uses
    :func:`cache_keys_for_message` (returns outer + inner pair).
    """
    if message is None:
        return None
    if bool(getattr(message, "hipaa", False)):
        return None
    raw_md = getattr(message, "raw_metadata", None) or {}
    if raw_md.get("force_reclassify"):
        return None
    cache = get_install_classification_cache()
    if cache is None or not cache.enabled:
        return None
    body_hash = compute_body_hash(getattr(message, "body_text", "") or "")
    return make_cache_key(
        account_id=int(raw_md.get("account_id", 0) or 0),
        sender=getattr(message, "sender", "") or "",
        subject=getattr(message, "subject", "") or "",
        body_hash=body_hash,
        classifier_model=classifier_model,
    )


def cache_keys_for_message(
    message: Any, classifier_model: str,
) -> tuple[str | None, str | None]:
    """Return (outer_key, inner_field) — both None when cache is skipped.

    HIPAA accounts: NOT skipped (revised 2026-05-13). The cache stores
    classifications for HIPAA accounts with the ``reason`` field
    stripped (cache_store_for_message handles the redaction).
    Force-reclassify still short-circuits.
    """
    if message is None:
        return None, None
    raw_md = getattr(message, "raw_metadata", None) or {}
    if raw_md.get("force_reclassify"):
        return None, None
    cache = get_install_classification_cache()
    if cache is None or not cache.enabled:
        return None, None
    outer = make_outer_cache_key(
        account_id=int(raw_md.get("account_id", 0) or 0),
        sender=getattr(message, "sender", "") or "",
        classifier_model=classifier_model,
    )
    inner = make_inner_cache_field(
        subject=getattr(message, "subject", "") or "",
        body_hash=compute_body_hash(getattr(message, "body_text", "") or ""),
    )
    return outer, inner


# Hint shape: (cached_classification | None, hint_text | None)
#   - cached_classification non-None → Branch 1 (LLM skipped)
#   - cached_classification None + hint_text non-None → Branch 2
#     (caller injects hint_text into the LLM prompt + runs LLM)
#   - both None → cold miss (LLM cold, no hint)
def cache_lookup_for_message(
    message: Any, classifier_model: str, categories: dict,
) -> tuple[str | None, str | None, Any | None, str | None]:
    """Two-level lookup for the (account, sender, model) triple.

    Returns ``(outer_key, inner_field, cached_classification, hint_text)``:

      * Both keys non-None when the cache is live; caller passes them
        through to :func:`cache_store_for_message` on Branch 2 LLM run.
      * ``cached_classification`` non-None on Branch 1 — exact inner
        match; caller skips the LLM call.
      * ``hint_text`` non-None on Branch 2 — outer matched, inner miss;
        caller prepends this text to the system prompt before the LLM
        call (single sentence, pre-rendered for direct injection).
      * Both ``cached_classification`` and ``hint_text`` None when
        cache is cold for this sender — caller runs LLM uninformed.

    Counter side-effects (one per call):
      * Branch 1 → ``hits_exact``
      * Branch 2 in C mode → ``hits_hint_topk``
      * Branch 2 in B mode (dominant) → ``hits_hint_dominant``
      * Branch 2 in B mode (ambiguous) → ``hits_hint_skipped``
      * Cold miss → ``misses_cold``
    """
    outer, inner = cache_keys_for_message(message, classifier_model)
    if outer is None or inner is None:
        return None, None, None, None
    cache = get_install_classification_cache()
    if cache is None:
        return outer, inner, None, None

    # Branch 1 — exact inner match.
    raw = cache.lookup_inner(outer, inner)
    if raw is not None:
        try:
            cat = str(raw.get("category", ""))
            if cat in categories:
                conf = max(0.0, min(1.0, float(raw.get("confidence", 0.5))))
                from email_triage.engine.models import Classification
                _counters.incr_hit_exact()
                return outer, inner, Classification(
                    category=cat,
                    confidence=conf,
                    reason=str(raw.get("reason", "")),
                    source="llm_cached",
                ), None
        except (TypeError, ValueError):
            pass  # Fall through to Branch 2.

    # Branch 2 — outer-set summarise to hint.
    field_set = cache.fetch_field_set(outer)
    if not field_set:
        _counters.incr_miss_cold()
        return outer, inner, None, None

    # Derive distribution + emit hint per strategy.
    distribution: dict[str, int] = {}
    for entry in field_set:
        cat = str(entry.get("category") or "")
        if cat and cat in categories:
            distribution[cat] = distribution.get(cat, 0) + 1
    if not distribution:
        # No usable history (every entry's category fell outside the
        # current taxonomy — taxonomy was edited). LLM cold.
        _counters.incr_miss_cold()
        return outer, inner, None, None

    # Strategy + threshold come from the cache singleton (set at
    # boot from RedisCacheConfig). Defaults survive misconfiguration.
    strategy = getattr(cache, "hint_strategy", "top_k_with_freq")
    dominant_pct = int(getattr(cache, "dominant_threshold_pct", 70))

    total = sum(distribution.values())
    sorted_dist = sorted(
        distribution.items(), key=lambda kv: (-kv[1], kv[0]),
    )

    if strategy == "top_1_dominant":
        top_cat, top_n = sorted_dist[0]
        pct = (top_n * 100) // max(1, total)
        if pct < dominant_pct:
            _counters.incr_hit_hint_skipped()
            return outer, inner, None, None
        hint_text = (
            f"Sender history: {top_n}/{total} prior emails from this "
            f"sender were classified as `{top_cat}`."
        )
        _counters.incr_hit_hint_dominant()
        return outer, inner, None, hint_text

    # Default — C mode: full distribution.
    pieces = [f"{n} {cat}" for cat, n in sorted_dist]
    hint_text = (
        f"Sender history ({total} prior emails from this sender, "
        f"by category): " + ", ".join(pieces) + "."
    )
    _counters.incr_hit_hint_topk()
    return outer, inner, None, hint_text


def cache_store_for_message(
    outer_key: str | None,
    inner_field: str | None,
    classifier_model: str,
    classification: Any,
    categories: dict,
    *,
    is_hipaa: bool = False,
) -> None:
    """Write a per-message inner entry. Best-effort; never raises.

    Strips the ``reason`` field when ``is_hipaa=True`` so the cache
    holds non-PHI shape (category + confidence + model + classified_at).
    Category + confidence are enum / float — not PHI; reason is the
    LLM free-text that could echo body fragments.

    Cap from install config (``redis_cache.inner_cap_per_sender``,
    default 250); ``ClassificationCache.store_inner`` LRU-evicts the
    oldest field on overflow before adding the new one.
    """
    if not outer_key or not inner_field:
        return
    cache = get_install_classification_cache()
    if cache is None or not cache.enabled:
        return
    cat = getattr(classification, "category", "")
    if cat not in categories:
        return
    cap = int(getattr(cache, "inner_cap_per_sender", 250))

    from datetime import datetime, timezone
    value: dict[str, Any] = {
        "category": cat,
        "confidence": float(getattr(classification, "confidence", 0.5)),
        "classified_at": datetime.now(timezone.utc).isoformat(),
        "model": classifier_model,
    }
    # HIPAA: omit reason (the PHI-shape free-text leak surface).
    # Non-HIPAA: include reason for debug + audit visibility.
    if not is_hipaa:
        value["reason"] = str(
            getattr(classification, "reason", "") or "",
        )
    try:
        cache.store_inner(outer_key, inner_field, value, cap=cap)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Classification cache store error: %s", exc)


def build_cache_from_config(redis_cache_cfg: Any) -> ClassificationCache | None:
    """Construct a :class:`ClassificationCache` from a ``RedisCacheConfig``.

    Returns ``None`` when the URL is empty (= operator hasn't opted in).
    """
    if redis_cache_cfg is None:
        return None
    url = (getattr(redis_cache_cfg, "url", "") or "").strip()
    if not url:
        return None
    raw_ttl = getattr(redis_cache_cfg, "ttl_secs", DEFAULT_TTL_SECS)
    ttl = clamp_ttl_secs(raw_ttl)
    cap = int(getattr(redis_cache_cfg, "inner_cap_per_sender", 250) or 250)
    strategy = str(
        getattr(redis_cache_cfg, "hint_strategy", "top_k_with_freq")
        or "top_k_with_freq",
    )
    dom_pct = int(
        getattr(redis_cache_cfg, "dominant_threshold_pct", 70) or 70,
    )
    return ClassificationCache(
        url=url, default_ttl_secs=ttl,
        inner_cap_per_sender=cap,
        hint_strategy=strategy,
        dominant_threshold_pct=dom_pct,
    )
