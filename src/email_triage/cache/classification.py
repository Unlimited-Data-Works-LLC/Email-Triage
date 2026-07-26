"""Optional Redis-backed cache for LLM classification results.

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
  prompt_version)``. Hashing the key is defence-in-depth: HIPAA
  accounts ARE cached (with ``reason`` stripped at store time per the
  HIPAA gate below), and the sender + subject shape is PHI-flavoured
  regardless, so we don't want it sitting in a Redis ``KEYS *``
  dump in cleartext.
* **Value**: JSON ``{category, reason, confidence, classified_at,
  model}``. Stored cleartext (server-side Redis isn't authenticated +
  the operator's responsibility to keep on a LAN-only host). The
  ``reason`` string is classifier free-text and could leak prompt
  fragments — see "Privacy invariants" below.
* **TTL**: configurable, default 30 days. Operator-tunable per install
  via ``/admin/integrations``.
* **HIPAA gate**: HIPAA-flagged messages ARE cached, with the
  classifier free-text ``reason`` stripped at store time
  (:func:`cache_store_for_message` handles the redaction when its
  ``is_hipaa`` kwarg is set — revised 2026-05-13; see
  :func:`cache_keys_for_message` docstring for the design rationale).
  The lookup path is unconditional. Pre-2026-05-13 the contract was
  "callers must skip lookup/store when HIPAA-flagged"; that contract
  is dropped. Callers pass ``is_hipaa=bool(message.hipaa)`` at store
  time and the cache module handles the redaction — see the live
  caller at ``classify/base.py:790``. Feature-report eval fold
  (2026-07-17) refreshed this line to end the site vs code drift; the
  actual runtime path has been store-with-redaction since 2026-05-13.

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
the  Bundle B classifier-side breaker, but cache failures are
strictly best-effort — they NEVER raise into the caller. Live LLM
call always wins as the fallback.
"""

from __future__ import annotations

from email_triage._int_utils import bounded_int, parse_int_or_none  # N-219c R23
from email_triage._isotime import now_utc_iso

import asyncio
import hashlib
import json
import logging
import re
import threading
from typing import Any

# run17 / — the Redis subsystem SSOT: the ``redis.Redis.from_url`` factory
# + the ONE shared fallback circuit-breaker. ``_redis`` imports nothing from
# ``email_triage`` (stdlib + lazy ``redis`` only), so it is a leaf — no cycle
# with the ``persistent_counters`` edge below.
from email_triage.cache._redis import RedisFallbackBreaker, build_redis_client

#  — hoisted from inside ``_Counters._mirror`` (was re-imported on
# every cache-counter bump). ``persistent_counters`` imports only
# ``triage_logging`` (and lazily ``redis``), so there is no circular
# import and no optional-dependency cost at module load.
from email_triage.engine.persistent_counters import (
    get_install_counter_backend,
)

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.cache.classification")  # N-196b R21_4


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

#:  — Lua script behind :meth:`ClassificationCache.store_inner`.
#: Redis runs a script atomically (no other command interleaves), so
#: the whole read-scan-evict-write is one indivisible step: the
#: per-sender ``cap`` holds under concurrent stores, the O(N) field
#: scan stays server-side, and the companion ``{category: count}``
#: distribution hash (KEYS[2]) is kept exactly in lockstep with the
#: inner hash — incremented on insert, decremented on evict /
#: category-changed overwrite. Branch 2 then reads that tiny hash
#: directly instead of HGETALL-ing every payload to recount.
#: ``EVAL`` + ``cjson`` are Redis 2.6+ (and valkey) — within the
#: module's documented Redis-5+ support.
#: KEYS[1]=inner hash, KEYS[2]=distribution hash;
#: ARGV=(inner_field, payload, cap, ttl_secs).
_STORE_INNER_LUA = """
local key = KEYS[1]
local distkey = KEYS[2]
local field = ARGV[1]
local payload = ARGV[2]
local cap = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local function cat_of(raw)
    if not raw then return nil end
    local ok, decoded = pcall(cjson.decode, raw)
    if ok and type(decoded) == 'table'
            and decoded.category ~= nil
            and decoded.category ~= cjson.null then
        return tostring(decoded.category)
    end
    return nil
end

-- Decrement a category's count; drop the field at <=0 so the dist
-- hash never carries a zero/negative row (also self-heals drift).
local function dist_dec(cat)
    if cat == nil or cat == '' then return end
    if redis.call('HINCRBY', distkey, cat, -1) <= 0 then
        redis.call('HDEL', distkey, cat)
    end
end

local function dist_inc(cat)
    if cat == nil or cat == '' then return end
    redis.call('HINCRBY', distkey, cat, 1)
end

local new_cat = cat_of(payload)
local existing = redis.call('HGET', key, field)

if existing then
    -- Overwrite — hash size is unchanged (no eviction). Adjust the
    -- distribution only when the category actually changed.
    local old_cat = cat_of(existing)
    if old_cat ~= new_cat then
        dist_dec(old_cat)
        dist_inc(new_cat)
    end
else
    -- New field — evict the oldest (by classified_at) first if the
    -- hash is already at/over cap. cap <= 0 disables eviction.
    if cap and cap > 0 and redis.call('HLEN', key) >= cap then
        local flat = redis.call('HGETALL', key)
        local oldest_field = nil
        local oldest_ts = nil
        local oldest_raw = nil
        for i = 1, #flat, 2 do
            local ts = ''
            local ok, decoded = pcall(cjson.decode, flat[i + 1])
            if ok and type(decoded) == 'table'
                    and decoded.classified_at ~= nil then
                ts = tostring(decoded.classified_at)
            end
            if oldest_field == nil or ts < oldest_ts then
                oldest_field = flat[i]
                oldest_ts = ts
                oldest_raw = flat[i + 1]
            end
        end
        if oldest_field ~= nil then
            redis.call('HDEL', key, oldest_field)
            dist_dec(cat_of(oldest_raw))
        end
    end
    dist_inc(new_cat)
end

redis.call('HSET', key, field, payload)
redis.call('EXPIRE', key, ttl)
redis.call('EXPIRE', distkey, ttl)
return 1
"""


def clamp_ttl_secs(value: int | None, default: int = DEFAULT_TTL_SECS) -> int:
    """Clamp an operator-supplied TTL into the supported window.

    Spec: ``[3600, 7_776_000]`` (1 hour to 90 days). Anything below
    snaps up to the floor, anything above snaps down to the ceiling.
    ``None`` / non-int input falls back to ``default`` before clamping.
    """
    # N-219c/44 R23: bounded_int SSOT — returns default on None + non-numeric.
    v = bounded_int(value, default=default) if value is not None else default
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

         — the ``persistent_counters`` import is hoisted to module
        scope (see top of file). It was previously imported inside this
        method on the theory of "don't pay the import in a no-Redis
        test", but every counter bump on the cache hot path re-ran the
        ``import`` statement (a ``sys.modules`` dict lookup — cheap, but
        needless per-call work). The module has no heavy / optional-dep
        import cost of its own, so hoisting is free. The backend itself
        still silently no-ops when the URL is empty / Redis unreachable.
        """
        try:
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
    # Strip repeated leading Re:/Fwd: tokens (``Re: Fwd: Re: foo`` → ``foo``)
    # via the mail_headers SSOT (census run13 ), then normalise.
    from email_triage.mail_headers import strip_reply_prefix
    return _norm(strip_reply_prefix(subject))


def compute_body_hash(body_text: str) -> str:
    """SHA-256 of the message body (normalised).

    The classifier sees ``body_text`` from the provider, not raw RFC822
    — providers already do MIME decode + HTML strip — so this is the
    right canonical form to hash. Whitespace is collapsed first so
    auto-replies that round-trip CR/LF don't break the cache.
    """
    canonical = _WS.sub(" ", (body_text or "").strip())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _categories_digest(categories: dict[str, str] | None) -> str:
    """Stable short digest of the category taxonomy.

    Folded into the outer cache key so that editing the taxonomy —
    adding, removing, renaming or re-describing a category — changes
    the key and naturally orphans classifications produced under the
    old prompt. ``PROMPT_VERSION`` is a hand-bumped constant; before
    this digest it was the *only* invalidation lever, so a taxonomy
    edit (which silently rewrites the LLM system prompt) served stale
    classifications until someone remembered to bump the constant.

    Canonicalised with ``sort_keys`` so dict ordering never perturbs
    the digest; truncated to 16 hex chars (64 bits) — ample against
    accidental collision for a per-install taxonomy.
    """
    if not categories:
        return ""
    canonical = json.dumps(
        categories, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def make_outer_cache_key(
    *,
    account_id: int,
    sender: str,
    classifier_model: str,
    categories: dict[str, str],
    prompt_version: str = PROMPT_VERSION,
) -> str:
    """Outer Redis HASH key — one per (account, sender, model, prompt,
    taxonomy) tuple.

    Drops subject + body from the key so all classifications from the
    same sender land in the SAME HASH. The inner field (per-message
    discriminator) holds (subject, body_hash). Cache hits split into
    two branches:
      * Branch 1 — inner exact match → return cached, skip LLM.
      * Branch 2 — outer match, inner miss → summarise sibling fields
        into a category-distribution hint that biases the LLM call.

    The taxonomy digest is part of the key: a category-set edit
    changes the LLM system prompt, so its cached results must not be
    served. ``prompt_version`` remains the manual lever for changes to
    the prompt *template* wording that ``categories`` cannot capture.

    SHA-256 of the tuple (defence-in-depth — sender is PHI-shape; a
    Redis ``KEYS *`` dump shouldn't surface it cleartext).
    """
    # census run17  — key the outer HASH on the BARE sender address
    # (display-name-independent) via the extract_bare_address SSOT, not the
    # whitespace-normalised raw header. ``_norm`` kept the display name, so
    # "Name <a@b>" and "Name via Service <a@b>" forked into two HASHes for
    # one sender — a silent cache-hit-rate loss on the hot path. The inner
    # field still discriminates the message (subject + body_hash), so merging
    # display-name variants of one address is strictly more correct. An
    # address-less sender degrades to the lowercased raw value (the SSOT
    # returns it unchanged when there is no ``<addr>``), matching the prior
    # bucketing for that degenerate case.
    from email_triage.mail_headers import extract_bare_address
    payload = "|".join([
        str(account_id),
        extract_bare_address(sender),
        classifier_model.strip(),
        prompt_version.strip(),
        _categories_digest(categories),
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
        inner_cap_per_sender: int = 128,
        hint_strategy: str = "top_k_with_freq",
        dominant_threshold_pct: int = 70,
    ) -> None:
        self._url = (url or "").strip()
        self._default_ttl = int(default_ttl_secs)
        self._breaker_ttl = int(breaker_ttl_secs)
        self._breaker = RedisFallbackBreaker(ttl_secs=self._breaker_ttl)
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

        Sync (not async) because the library underneath is sync — the
        async-reachable callers (``JsonChatClassifier.classify``,
        ``admin_integrations_cache_flush``) dispatch each Redis call
        off the event loop via the ``a*`` mirror methods on this class,
        which wrap the sync surface in ``asyncio.to_thread``. The
        original "no thread pool needed" assumption was wrong
        when measured: a Redis hiccup pinned by the 2.0 s
        ``socket_timeout`` would block the whole event loop for the
        full timeout, stalling watchers + web + every other in-flight
        classify. The fix preserves the sync surface (admin
        tooling, CLI, tests) and adds an ``a*`` mirror per Redis-
        touching method that async callers MUST use.

        Lazily imports ``redis`` so installs without the optional
        ``cache`` extra installed don't error at import time.
        """
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is not None:
                return self._client
            # run17  — build through the Redis-subsystem factory SSOT
            # (``cache/_redis.build_redis_client``), which owns the canonical
            # ``from_url`` params (decode_responses + short LAN socket/connect
            # timeouts). ``ImportError`` (optional ``cache`` extra missing) is
            # kept DISTINCT from a connection-build error so each keeps its own
            # operator log + breaker reason.
            try:
                client = build_redis_client(self._url)
            except ImportError as exc:
                logger.warning(
                    "Classification cache: redis package not installed "
                    "(pip install email-triage[cache]); cache disabled "
                    "for this process",
                )
                self._open_breaker(f"import error: {exc}")
                return None
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
        return self._breaker.is_open()

    def _open_breaker(self, reason: str) -> None:
        self._breaker.trip(reason)
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
                "Classification cache: GET failed; falling through to LLM. "
                "cache_hit=False breaker_open=True",
                extra={"error_type": type(exc).__name__},
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
                "Classification cache: corrupt JSON; treating as miss",
                extra={
                    "error_type": type(exc).__name__,
                    "error_msg": str(key[:24]) + "..",
                },
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
                "Classification cache: SET failed; breaker open",
                extra={"error_type": type(exc).__name__},
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
                "Classification cache: HGET failed; breaker open",
                extra={"error_type": type(exc).__name__},
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
                "Classification cache: corrupt inner JSON",
                extra={
                    "error_type": type(exc).__name__,
                    "error_msg": str(outer_key[:24]) + "..",
                },
            )
            return None

    def fetch_category_distribution(self, outer_key: str) -> dict[str, int]:
        """Branch 2 — return the ``{category: count}`` distribution for
        a sender.

        Reads the companion ``<outer_key>:dist`` hash that
        ``store_inner``'s Lua script maintains in lockstep with the
        inner hash. One ``HGETALL`` of a tiny hash — one field per
        distinct category, a few hundred bytes — instead of the prior
        ``HGETALL`` of every full payload only to recount categories.
        Empty dict on outer-miss / error.
        """
        if not self.enabled or self._breaker_open():
            return {}
        client = self._get_client()
        if client is None:
            return {}
        try:
            raw = client.hgetall(outer_key + ":dist")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: dist HGETALL failed; breaker open",
                extra={"error_type": type(exc).__name__},
            )
            self._open_breaker(f"dist HGETALL: {exc}")
            _counters.incr_error()
            return {}
        out: dict[str, int] = {}
        for cat, cnt in (raw or {}).items():
            n = parse_int_or_none(cnt)  # N-219c/10 R23: SSOT
            if n is None:
                continue
            if n > 0:
                out[str(cat)] = n
        return out

    def store_inner(
        self,
        outer_key: str,
        inner_field: str,
        value: dict[str, Any],
        *,
        ttl_secs: int | None = None,
        cap: int = 128,
    ) -> None:
        """Write a per-message inner entry. LRU-evicts at ``cap``.

        When the inner HASH reaches ``cap`` fields, the oldest entry
        (by ``classified_at`` ISO timestamp in the payload) is HDEL'd
        before the new field is added — bounds growth on heavy-traffic
        senders.

        A companion ``<outer_key>:dist`` hash holds the
        ``{category: count}`` distribution; the same Lua script keeps
        it in lockstep with the inner hash (incremented on insert,
        decremented on evict / category-changed overwrite) so Branch 2
        reads the aggregate directly rather than scanning payloads.

        Resets the TTL of both keys on every write so a sender that
        keeps sending stays cached; a sender that goes silent
        TTL-expires the whole pair at once.
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
            #  — atomic eviction + write + distribution update in
            # one server-side Lua EVAL. The whole read-scan-evict-write
            # runs without command interleaving, so the cap holds
            # under concurrent stores, the O(N) field scan never
            # crosses the wire, and the {category:count} dist hash
            # stays exactly consistent with the inner hash. See
            # _STORE_INNER_LUA.
            client.eval(
                _STORE_INNER_LUA, 2,
                outer_key, outer_key + ":dist",
                inner_field, payload, cap, ttl,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Classification cache: store EVAL failed; breaker open",
                extra={"error_type": type(exc).__name__},
            )
            self._open_breaker(f"store_inner EVAL: {exc}")
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
                "Classification cache: flush_all failed; breaker open",
                extra={"error_type": type(exc).__name__},
            )
            self._open_breaker(f"FLUSH: {exc}")
            _counters.incr_error()
            return total
        logger.info(
            "Classification cache: flushed keys via admin action",
            extra={"total": total},
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

    # -- Async mirrors ---------------------------------------------
    # Every Redis-touching public method has an ``a*`` mirror that
    # dispatches the sync call through ``asyncio.to_thread`` so the
    # 2.0 s ``socket_timeout`` worst case never blocks the event loop.
    # The async-reachable callers (`JsonChatClassifier.classify`,
    # `admin_integrations_cache_flush`) MUST use these mirrors; the
    # sync surface is kept for non-async callers (admin CLI, tests).
    #
    # The mirrors are intentionally one-liners — each one delegates
    # everything (breaker check, client lookup, counter bookkeeping,
    # error handling) to the sync method, so the two surfaces can
    # never disagree on semantics. A future refactor to a real async
    # Redis client (`redis.asyncio`) would replace these wrappers and
    # leave every caller untouched.

    async def alookup(self, key: str) -> dict[str, Any] | None:
        """Async mirror of :meth:`lookup` (legacy flat-key)."""
        return await asyncio.to_thread(self.lookup, key)

    async def astore(
        self,
        key: str,
        value: dict[str, Any],
        ttl_secs: int | None = None,
    ) -> None:
        """Async mirror of :meth:`store` (legacy flat-key)."""
        await asyncio.to_thread(self.store, key, value, ttl_secs)

    async def alookup_inner(
        self, outer_key: str, inner_field: str,
    ) -> dict[str, Any] | None:
        """Async mirror of :meth:`lookup_inner` — Branch 1 exact hit."""
        return await asyncio.to_thread(
            self.lookup_inner, outer_key, inner_field,
        )

    async def afetch_category_distribution(
        self, outer_key: str,
    ) -> dict[str, int]:
        """Async mirror of :meth:`fetch_category_distribution` — Branch 2."""
        return await asyncio.to_thread(
            self.fetch_category_distribution, outer_key,
        )

    async def astore_inner(
        self,
        outer_key: str,
        inner_field: str,
        value: dict[str, Any],
        *,
        ttl_secs: int | None = None,
        cap: int = 128,
    ) -> None:
        """Async mirror of :meth:`store_inner` — post-LLM write-back."""
        await asyncio.to_thread(
            self.store_inner, outer_key, inner_field, value,
            ttl_secs=ttl_secs, cap=cap,
        )

    async def aflush_all(self) -> int:
        """Async mirror of :meth:`flush_all` — admin SCAN+DELETE sweep."""
        return await asyncio.to_thread(self.flush_all)


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
    message: Any, classifier_model: str, categories: dict[str, str],
) -> tuple[str | None, str | None]:
    """Return (outer_key, inner_field) — both None when cache is skipped.

    HIPAA accounts: NOT skipped (revised 2026-05-13). The cache stores
    classifications for HIPAA accounts with the ``reason`` field
    stripped (cache_store_for_message handles the redaction).
    Force-reclassify still short-circuits.

    ``categories`` is the LLM's category taxonomy; its digest is part
    of the outer key so a taxonomy edit invalidates the cache.
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
        categories=categories,
    )
    inner = make_inner_cache_field(
        subject=getattr(message, "subject", "") or "",
        body_hash=compute_body_hash(getattr(message, "body_text", "") or ""),
    )
    return outer, inner


def _classification_from_inner_payload(
    raw: dict[str, Any], categories: dict,
) -> Any | None:
    """Build a :class:`Classification` from an inner-cache payload, or
    return ``None`` when the cached category fell outside the current
    taxonomy or the payload is malformed.

    Extracted from :func:`cache_lookup_for_message` so the sync and
    async lookup paths share one canonical shape — a future change to
    the Classification construction (extra field, defensive clamp)
    lands once and applies to both.
    """
    try:
        cat = str(raw.get("category", ""))
        if cat not in categories:
            return None
        conf = max(0.0, min(1.0, float(raw.get("confidence", 0.5))))
    except (TypeError, ValueError):
        return None
    from email_triage.engine.models import Classification
    return Classification(
        category=cat,
        confidence=conf,
        reason=str(raw.get("reason", "")),
        source="llm_cached",
    )


def _hint_from_distribution(
    raw_dist: dict[str, int], categories: dict, cache: Any,
) -> tuple[str | None, str]:
    """Process a Branch-2 distribution into (hint_text, counter_field).

    Returns ``(hint_text_or_none, name_of_counter_to_bump)``. The
    counter side-effect lives at the caller so the (sync, async)
    lookup helpers each fire it on their own thread/loop. Strategy +
    threshold come from the cache singleton (set at boot).

    Pure Python — no I/O. Extracted from
    :func:`cache_lookup_for_message` so both lookup paths produce
    bit-identical hint strings + counter bumps from the same
    distribution.
    """
    distribution = {
        cat: n for cat, n in raw_dist.items()
        if cat and cat in categories
    }
    if not distribution:
        return None, "incr_miss_cold"

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
            return None, "incr_hit_hint_skipped"
        hint_text = (
            f"Sender history: {top_n}/{total} prior emails from this "
            f"sender were classified as `{top_cat}`."
        )
        return hint_text, "incr_hit_hint_dominant"

    # Default — C mode: full distribution.
    pieces = [f"{n} {cat}" for cat, n in sorted_dist]
    hint_text = (
        f"Sender history ({total} prior emails from this sender, "
        f"by category): " + ", ".join(pieces) + "."
    )
    return hint_text, "incr_hit_hint_topk"


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
    outer, inner = cache_keys_for_message(
        message, classifier_model, categories,
    )
    if outer is None or inner is None:
        return None, None, None, None
    cache = get_install_classification_cache()
    if cache is None:
        return outer, inner, None, None

    # Branch 1 — exact inner match.
    raw = cache.lookup_inner(outer, inner)
    if raw is not None:
        cached = _classification_from_inner_payload(raw, categories)
        if cached is not None:
            _counters.incr_hit_exact()
            return outer, inner, cached, None
        # Fell through (taxonomy moved, malformed payload) → Branch 2.

    # Branch 2 — read the maintained {category:count} distribution.
    raw_dist = cache.fetch_category_distribution(outer)
    if not raw_dist:
        _counters.incr_miss_cold()
        return outer, inner, None, None

    hint_text, counter = _hint_from_distribution(
        raw_dist, categories, cache,
    )
    getattr(_counters, counter)()
    return outer, inner, None, hint_text


async def acache_lookup_for_message(
    message: Any, classifier_model: str, categories: dict,
) -> tuple[str | None, str | None, Any | None, str | None]:
    """ — async mirror of :func:`cache_lookup_for_message`.

    Same return shape, same counter side-effects, same HIPAA gate
    semantics — but every Redis round-trip is dispatched off the event
    loop via the ``ClassificationCache.a*`` methods, so a 2.0 s
    ``socket_timeout`` on a stuck Redis no longer pins the loop.

    Pure-Python key derivation + distribution-to-hint processing is
    shared with the sync helper via :func:`_classification_from_inner_payload`
    and :func:`_hint_from_distribution`, so the two paths emit
    bit-identical results from the same Redis state.
    """
    outer, inner = cache_keys_for_message(
        message, classifier_model, categories,
    )
    if outer is None or inner is None:
        return None, None, None, None
    cache = get_install_classification_cache()
    if cache is None:
        return outer, inner, None, None

    # Branch 1 — exact inner match.
    raw = await cache.alookup_inner(outer, inner)
    if raw is not None:
        cached = _classification_from_inner_payload(raw, categories)
        if cached is not None:
            _counters.incr_hit_exact()
            return outer, inner, cached, None

    # Branch 2 — read the maintained {category:count} distribution.
    raw_dist = await cache.afetch_category_distribution(outer)
    if not raw_dist:
        _counters.incr_miss_cold()
        return outer, inner, None, None

    hint_text, counter = _hint_from_distribution(
        raw_dist, categories, cache,
    )
    getattr(_counters, counter)()
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
    default 128); ``ClassificationCache.store_inner`` LRU-evicts the
    oldest field on overflow before adding the new one.
    """
    if not outer_key or not inner_field:
        return
    cache = get_install_classification_cache()
    if cache is None or not cache.enabled:
        return
    value = _build_inner_payload(
        classifier_model, classification, categories, is_hipaa=is_hipaa,
    )
    if value is None:
        return
    cap = int(getattr(cache, "inner_cap_per_sender", 128))
    try:
        cache.store_inner(outer_key, inner_field, value, cap=cap)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Classification cache store error",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
        )


def _build_inner_payload(
    classifier_model: str,
    classification: Any,
    categories: dict,
    *,
    is_hipaa: bool,
) -> dict[str, Any] | None:
    """Build the payload :func:`(a)cache_store_for_message` writes, or
    return ``None`` when the classification's category fell outside the
    current taxonomy and writing would poison the cache.

    Extracted from :func:`cache_store_for_message` so the sync and
    async store paths produce bit-identical payloads + HIPAA redaction
    from the same Classification.
    """
    cat = getattr(classification, "category", "")
    if cat not in categories:
        return None
    value: dict[str, Any] = {
        "category": cat,
        "confidence": float(getattr(classification, "confidence", 0.5)),
        "classified_at": now_utc_iso(),
        "model": classifier_model,
    }
    if not is_hipaa:
        value["reason"] = str(
            getattr(classification, "reason", "") or "",
        )
    return value


async def acache_store_for_message(
    outer_key: str | None,
    inner_field: str | None,
    classifier_model: str,
    classification: Any,
    categories: dict,
    *,
    is_hipaa: bool = False,
) -> None:
    """ — async mirror of :func:`cache_store_for_message`. Best-
    effort; never raises. Dispatches the Redis write off the event
    loop via :meth:`ClassificationCache.astore_inner`.
    """
    if not outer_key or not inner_field:
        return
    cache = get_install_classification_cache()
    if cache is None or not cache.enabled:
        return
    value = _build_inner_payload(
        classifier_model, classification, categories, is_hipaa=is_hipaa,
    )
    if value is None:
        return
    cap = int(getattr(cache, "inner_cap_per_sender", 128))
    try:
        await cache.astore_inner(outer_key, inner_field, value, cap=cap)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Classification cache async store error",
            extra={"error_type": type(exc).__name__, "error_msg": str(exc)},
        )


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
    cap = int(getattr(redis_cache_cfg, "inner_cap_per_sender", 128) or 128)
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
