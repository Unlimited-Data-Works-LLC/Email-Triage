"""JWT verification for Gmail Pub/Sub push deliveries.

Google Cloud Pub/Sub sends push notifications with an Authorization
header of the form ``Bearer <JWT>``. The JWT is signed RS256 by Google
and carries the service-account identity the subscription was created
with. We verify signature, issuer, audience, and SA email, and reject
anything that doesn't match.

This module intentionally does not depend on FastAPI or the rest of
the web package — it's a pure verification utility so tests can mint
JWTs with a generated RSA keypair and stub the public-cert fetch.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt

from email_triage._egress import EgressBlocked
from email_triage._http_client import Intent, LazyHttpClient
# N-219 R23: the sentinel-None int-parse SSOT. The header parsers below
# need exactly its semantic ("int if parseable, else None"), and the
# `test_n219_try_except_int_ratchet_pin` sweep caught the two hand-rolled
# `try: int(x) except (TypeError, ValueError)` copies this fold first
# shipped -- 12 against a baseline of 10. Fixed at the new code, not by
# raising the cap.
from email_triage._int_utils import parse_int_or_none

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.web.gmail_push_auth")  # N-196b R21_4

# Google publishes the OAuth2 signing certs here. The x509 variant is
# the one whose `kid` matches the `kid` in Pub/Sub push JWTs.
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"

VALID_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}


class GmailPushVerificationError(Exception):
    """Raised when the inbound JWT fails signature or claim checks."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class GmailPushTransientFetchError(Exception):
    """N-288 R30 — raised when the JWKS cert fetch fails for a
    TRANSIENT reason (DNS blip, connect timeout, upstream 5xx).

    Distinct from :class:`GmailPushVerificationError` so the webhook
    receiver can respond 503 (retry-able) instead of 500 (stack
    trace) — Google Pub/Sub retries hard on 5xx, so a brief infra
    blip used to flood the log with thousands of stack traces
    (2026-06-25 Tailscale MagicDNS outage — ~6,775 traces in a few
    hours). A 503 still tells Pub/Sub to retry but is the
    RFC-preferred response for a transient upstream dependency
    failure + suppresses the stack trace.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# -d (2026-07-11) — CONFIG-DRIVEN Gmail JWKS-fetch client timeout,
# per feedback_dynamic_over_hardcoding. Pre-fix ``timeout=10.0`` was
# a hardcoded float literal inside _CertCache.__init__. Now module-
# level with a boot-wired setter; a NEW _CertCache picks up the tuned
# value at construction. (Existing instances keep their captured
# timeout — call sites re-instantiate on app startup via
# app.state._gmail_cert_cache = _CertCache(), so a boot-time tune
# reaches the singleton.)
_GMAIL_CERT_TIMEOUT_SECS: float = 10.0

# --- punch 548 / N-544: the JWKS-fetch rate gate ---------------------------
# ``_CertCache.get_key`` used to refetch Google's JWKS on EVERY unknown
# ``kid``, and the Gmail push route is reachable WITHOUT authentication (the
# JWT header is read before the signature is checked), so N distinct random
# ``kid``s from an unauthenticated caller bought N outbound fetches to
# googleapis.com. That is the CVE-2026-101917 / GHSA-2gx3-rcp4-g85q
# amplification shape, reproduced in our own cache rather than in PyJWT's
# ``PyJWKClient`` -- which is deliberately NOT adopted here: its ``urllib``
# egress would route the JWKS fetch around the ``Intent.PROVIDER_API``
# ``LazyHttpClient`` funnel, a larger SSOT fork than the one it closes.
#
# MODULE CONSTANTS, deliberately NOT environment overrides: punch 547 forbids
# a new env override of a control value (a second store nothing reconciles).
# They are read at CALL time rather than captured at construction, so a test
# can monkeypatch them and a future boot-time tune reaches the live singleton
# (unlike ``_GMAIL_CERT_TIMEOUT_SECS``, which httpx captures on construction).
#
# 30 s, and the number moved DOWN from the 300 s this change first carried.
# Both bound the egress; they differ on the axis this row is actually about.
# The cost of the floor is that a key Google rotates to mid-TTL is refused
# for up to one floor -- so the floor length IS the worst-case ingestion
# outage per rotation. db-sme (DB-546-3) recommends upstream's shape with a
# 30 s default and measured what the unbounded path costs; 30 s cuts that
# outage window by 10x while still capping attacker-forced egress at ~120
# fetches/h (from unbounded: 1 per request, and db counted 25 concurrent
# requests producing 25 fetches with no coalescing). Google itself serves
# that URL with ``Cache-Control: public, max-age=23901, must-revalidate``
# (measured 2026-09-29), i.e. it considers the document good for ~6.6 h, so
# no honest client needs to refetch faster than this. A legitimate push
# signed by a ``kid`` we have not fetched yet is not lost either: Pub/Sub
# retries any non-2xx delivery with backoff, so that delivery returns after
# the floor lifts and verifies then.
_JWKS_MIN_REFRESH_INTERVAL_SECS: float = 30.0

# The STALENESS CAP on serving a past-TTL table (DB-548-7 / H548-2).
# ``get_key``'s expired arm keeps serving the table we already hold while
# a refresh fails, which is the right trade on an availability row -- but
# nothing bounded the TOTAL staleness before this cap: only the attempt
# SPACING was bounded by the floor above, so a sustained upstream failure
# served the SAME table indefinitely (db-sme measured the t=0 table still
# answering at 23.5 h, 24x past a 1 h ``ttl_seconds``, across 46 failed
# attempts).
#
# The bound with an EXTERNAL referent is Google's own: it serves the JWKS
# URL with ``Cache-Control: public, max-age=23901, must-revalidate``
# (measured 2026-09-29), i.e. it considers the document good for ~6.6 h.
#
# THIS CONSTANT IS A CEILING, NOT THE BOUND. The bound in force is the
# SHORTER of this ceiling and Google's OWN declared freshness on the last
# successful fetch (``max-age`` less ``Age``) -- see
# :meth:`_CertCache._effective_stale_cap`. The cap FOLLOWS THE OBSERVED
# HEADER; it does not rely on this constant's margin under 23901.
# Nothing here may be read as a claim that a STATIC value protects
# against a future shorter max-age -- it does not, and could not: drop
# max-age to 3600 and a fixed 21600 would exceed it 6x, silently.
# Reading the header is the whole of what makes the property real. The
# ceiling still does work -- it bounds the case where there is NO usable
# signal -- but it is our own conservative default, not a measurement.
# (The N-544 row carries the struck justification this replaced; the
# retained record is where that history belongs, not this comment.)
#
# Do NOT write that this implements Google's stated policy either. Per RFC
# 9111 (fetched, not recalled): ``must-revalidate`` engages only once a
# response has become STALE (Sec 5.2.2.2), and 'stale' is measured against
# ``current_age``, which incorporates ``Age`` (Sec 4.2, 4.2.3). Serving
# inside Google's declared lifetime is serving a FRESH response and the
# directive is not engaged at all.
#
# ``N x ttl_seconds`` was rejected as the
# unit: ``ttl_seconds`` is OUR refresh cadence -- how often we would like
# to re-check -- not a statement about how long the document stays valid,
# so N x cadence is a number with no external referent, which is how the
# floor above got a 300 it had to walk back.
#
# Past the cap the answer is the TRANSIENT error, NOT the verification
# one: 503 tells Pub/Sub to keep retrying, so recovery is automatic when
# Google returns and the cliff costs delay, not data (Pub/Sub message
# retention covers the gap). A 401 would tell Pub/Sub the token was bad.
_JWKS_MAX_STALE_SECS: float = 21600.0

# The plausibility gate on the DECLARED ``max-age``. Below this there is no
# usable SIGNAL rather than a small value, and the cap falls back to the
# ceiling above. The gate is on the DECLARED policy; the ``Age``
# SUBTRACTION is arithmetic and is honoured however small, so a
# legitimately near-stale document (``max-age=23901, Age=23890`` -> 11 s)
# correctly stops being served almost at once instead of being
# misclassified as no-signal.
#
# BE HONEST ABOUT WHICH WAY THIS FALLBACK CUTS, because the two triggers
# differ in KIND and only one of them is a deviation:
#   (a) ``Cache-Control`` ABSENT or UNPARSEABLE -- nothing was declared,
#       so there is no policy to deviate from and the ceiling is simply
#       our own conservative default. NO deviation. Logged at DEBUG.
#   (b) ``Cache-Control`` PRESENT and parseable below this floor -- a
#       policy WAS declared and we deliberately disregard it, exposing up
#       to the full ceiling of stale-serve against it. THIS IS A
#       DEVIATION, and the widest single-case exposure in this design.
#       Logged at WARNING with the parsed value, because it is the only
#       case that silently opens that window and the N-544 row names it.
# Accepted because a sub-60s policy on a ~6.6 h document is a prompt to
# revisit this constant rather than a credible declaration, and because
# honouring it would let ONE quirky response disable stale-serve for an
# entire outage with no successful fetch available to correct it.
_JWKS_MIN_PLAUSIBLE_MAX_AGE: float = 60.0

# The negative cache remembers ``kid``s a REAL refresh did not contain. Its
# TTL is the SAME constant as the interval on purpose: a longer negative TTL
# would refuse a ``kid`` Google has since published for longer than the rate
# gate itself requires -- the negative cache, not the gate, would become the
# thing delaying a rotation. Negatives are also CLEARED whenever a new table
# lands, because a refresh is what defines "unknown".
#
# BE PRECISE ABOUT WHAT THIS BUYS, because it is easy to over-credit: **the
# GATE is what bounds the fetch count, not this map.** Two rules above --
# "only remember after a REAL refresh" and "clear on every install" -- mean
# the shipped flow is always refresh -> clear -> remember(kid), so the map
# holds ONE ENTRY PER DISTINCT UNKNOWN KID THAT COALESCED ONTO THE LAST
# REFRESH -- normally one, and bounded at ``_JWKS_UNKNOWN_KID_MAX_ENTRIES``.
# It is NOT "at most one" (H548-4): N concurrent deliveries carrying N
# DISTINCT unknown kids coalesce on a single fetch and every one of them
# then reaches ``_remember_unknown_kid``, so the eviction loop below IS
# reachable in the shipped flow rather than defensive-only. The bounds
# hold either way; the sentence was the thing that was false.
# What the map actually contributes is a
# specific, cheap refusal for a repeat of that one kid, and a distinguishable
# reason string in the log. The caps are DEFENSIVE bounds on caller-controlled
# input for the day that coupling loosens -- a future change that remembered a
# kid without refreshing would need them, and a `kid` is attacker-chosen, so
# an unbounded map would answer the egress arm by opening a memory arm.
_JWKS_UNKNOWN_KID_MAX_ENTRIES: int = 256

# A ``kid`` is caller-controlled input, so only bounded-length ones are worth
# remembering (Google's are 40 hex chars). A longer one is still rate-gated;
# it is simply not stored. This is the memory half of the same finding --
# "unbounded work on unauthenticated input" includes unbounded retention.
_JWKS_KID_MAX_CACHEABLE_LEN: int = 128


def _parse_max_age(header: str | None) -> float | None:
    """The ``max-age`` seconds from a ``Cache-Control`` header, or None.

    TOTAL BY CONSTRUCTION -- it never raises. It runs on the SUCCESS path of
    :meth:`_CertCache._fetch_and_install`, after the key table has already
    installed, so an exception here would be a fresh untyped escape of
    exactly the class panel546 H-6 named, on the one arm that just
    succeeded. Anything unexpected -- no header, no ``max-age`` directive,
    a non-integer value, a negative -- returns None, which the caller reads
    as "no usable signal" and NOT as zero.
    """
    if not isinstance(header, str) or not header:
        return None
    for part in header.split(","):
        key, sep, value = part.strip().lower().partition("=")
        if key.strip() != "max-age" or not sep:
            continue
        parsed = parse_int_or_none(value.strip())
        if parsed is None:
            return None  # present but unparseable -> case (a), no signal
        return float(parsed) if parsed >= 0 else None
    return None


def _parse_age(header: str | None) -> float | None:
    """The ``Age`` header in seconds, or None. Total, like :func:`_parse_max_age`.

    HTTP freshness is measured from the origin and adjusted by ``Age``
    (RFC 9111 Sec 4.2.3), so a response an intermediary has held for 20000 s
    has that much less life left than its ``max-age`` suggests. Without this
    the cap would measure from OUR install time only and could serve well
    past the true freshness lifetime (hipaa-548 Sec 6.8, verified by db-548
    at the sha: the pre-fold ``_fetch_and_install`` read no headers at all).
    """
    if not isinstance(header, str) or not header:
        return None
    parsed = parse_int_or_none(header.strip())
    if parsed is None or parsed < 0:
        return None
    return float(parsed)


def configure_gmail_cert_timeout(timeout_secs: float) -> None:
    """-d — set the Gmail JWKS-fetch client timeout budget.

    Called at boot from ``load_config._wire_module_singletons`` with
    the resolved ``config.push.gmail_cert_timeout_secs`` value.
    Rejects non-positive values.
    """
    global _GMAIL_CERT_TIMEOUT_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _GMAIL_CERT_TIMEOUT_SECS = float(timeout_secs)


class _CertCache:
    """In-memory cache of Google's public signing certs, keyed by ``kid``."""

    def __init__(self, ttl_seconds: int = 3600):
        self._ttl = ttl_seconds
        # MONOTONIC clocks: both fields are duration bases, and
        # ``time.time()`` travels backwards under NTP correction -- on a rate
        # gate that means the gate opens EARLY. ``float("-inf")`` means
        # "never", and is not ``0.0`` on purpose: ``time.monotonic()`` is
        # time since boot on Linux, so a 0.0 base reads as "one refresh
        # interval ago" only once the host has been up for a full interval,
        # and would otherwise BLOCK the cold-start fetch. (This prose used
        # to say "5 minutes", which was the abandoned 300 s draft of the
        # floor, not the shipped value -- DA-548-12.)
        self._fetched_at: float = float("-inf")
        # Google's OWN declared freshness on the last SUCCESSFUL fetch
        # (``max-age`` less ``Age``), or None when that response carried no
        # usable signal. Consumed ONLY through ``_effective_stale_cap``.
        self._observed_freshness: float | None = None
        self._last_refresh_attempt: float = float("-inf")
        # punch 548 negative cache: kid -> monotonic deadline. Bounded in
        # both entry count and key length; see the module constants.
        self._unknown_kids: dict[str, float] = {}
        # DB-546-3: ONE lock across the refresh, so N concurrent deliveries
        # that all miss the cache produce ONE fetch and all of them get its
        # result -- db counted 25 concurrent requests producing 25 fetches
        # pre-fix. Built lazily (the same reasoning as ``LazyHttpClient``):
        # a _CertCache can be constructed before an event loop exists.
        self._refresh_lock: asyncio.Lock | None = None
        self._keys: dict[str, Any] = {}
        # Long-lived httpx client. The cache is a per-process
        # singleton on ``app.state._gmail_cert_cache``; the JWKS
        # refresh fires on cold-start + every ``ttl_seconds`` (1 h
        # default) + on an unknown ``kid`` NO MORE OFTEN than
        # ``_JWKS_MIN_REFRESH_INTERVAL_SECS`` (punch 548 -- it used to fire
        # on EVERY unknown kid, unauthenticated). Holding the connection
        # pool open trims the cold-path TLS handshake to once per
        # process. -d: timeout is now the module-level SSOT so a
        # config tune reaches the singleton on next startup.
        # `follow_redirects=False` is EXPLICIT (panel546 H-7,
        # §164.312(e)(1)): this is the trust-root retrieval for the
        # authentication check, so a redirected fetch substitutes the trust
        # root. httpx's default is already False -- the argument states it so
        # a shared-client or library-default flip cannot silently change it.
        # `LazyHttpClient` forwards remaining kwargs through
        # `egress_async_client` to `httpx.AsyncClient`; `cli.py:3488` is the
        # in-repo precedent for the same kwarg on the sync twin.
        self._http = LazyHttpClient(
            intent=Intent.PROVIDER_API, timeout=_GMAIL_CERT_TIMEOUT_SECS,
            follow_redirects=False,
        )

    def _stale_age(self) -> float:
        """Seconds since the last SUCCESSFUL fetch -- the table's age.

        The ONE spelling of that subtraction (PD-5): :meth:`_expired` and
        :meth:`_stale_serve_allowed` both ask about the table's age and must
        not compute it two ways that drift. ``_fetched_at`` is stamped only
        where a new table INSTALLS, so a run of failed refreshes cannot
        reset the age and a successful refresh does.
        """
        return time.monotonic() - self._fetched_at

    def _effective_stale_cap(self) -> tuple[float, str]:
        """The staleness cap in force right now, and where it came from.

        The ONE place ``_JWKS_MAX_STALE_SECS`` is consumed (PD-5): the serve
        gate, the cliff message and the WARN line all read this, so the
        ceiling and the observed value cannot be combined two ways that
        drift. ``"observed"`` means Google's own declared freshness from the
        last SUCCESSFUL fetch; ``"ceiling"`` means there was no usable
        signal and we fell back to our own default.

        ``is None`` and NOT ``or`` -- deliberately, and it is a correction to
        db-548's pseudocode, which reads
        ``self._observed_freshness or _JWKS_MAX_STALE_SECS``. A COMPUTED
        freshness of 0.0 (``max-age=100`` behind ``Age: 200``) is falsy, so
        ``or`` would send the most-stale case there is to the 6 h ceiling --
        the exact inversion of db's own stated intent ("honour it even if
        small") and of hipaa-548's 11 s worked example.
        """
        observed = self._observed_freshness
        if observed is None:
            return _JWKS_MAX_STALE_SECS, "ceiling"
        return min(_JWKS_MAX_STALE_SECS, observed), "observed"

    def _expired(self) -> bool:
        """True once the table must be refreshed before it is served again.

        ``ttl_seconds`` is OUR cadence, and it is NOT allowed to outlast
        GOOGLE'S declared freshness: when the observed value is SHORTER than
        the TTL, this fires at the observed value instead.

        THIS IS ONE STEP PAST db-548's PSEUDOCODE and the reason is the
        record, not taste. The N-544 row states that across the
        plausible-signal range "the deviation is zero". Without this line
        that sentence is false: a ``max-age=1800`` document on a 3600 s TTL
        is NOT expired between 1800 s and 3600 s, so it keeps being served
        with no refresh even attempted -- 1800 s past the lifetime Google
        declared, with no mitigation anywhere. Coherent with the cap: when
        this fires early and the refresh then fails,
        :meth:`_stale_serve_allowed` is ALREADY False (age >= cap =
        observed), so the answer is 503 at once and no stale serve happens.
        The ``_JWKS_MIN_REFRESH_INTERVAL_SECS`` floor still bounds the fetch
        rate, so a short freshness cannot become an egress arm.
        """
        observed = self._observed_freshness
        limit = self._ttl if observed is None else min(self._ttl, observed)
        return self._stale_age() >= limit

    def _stale_serve_allowed(self) -> bool:
        """True while a past-TTL table is still young enough to serve.

        Reads :meth:`_effective_stale_cap`, so the bound is the SHORTER of
        our ceiling and Google's declared freshness (DB-548-7, hipaa-548
        Sec 6.11).
        """
        cap, _source = self._effective_stale_cap()
        return self._stale_age() < cap

    def _get_refresh_lock(self) -> asyncio.Lock:
        """The single-flight lock, created on first use so construction does
        not require a running event loop."""
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        return self._refresh_lock

    def _refresh_allowed(self) -> bool:
        """True once the minimum-refresh-interval floor has lifted.

        The ONE predicate for that question (PD-5): both :meth:`_refresh`
        itself and the unknown-``kid`` arm of :meth:`get_key` consult it, so
        the floor cannot be spelled two ways that drift apart. Reads the
        module constant at call time so a tune (or a test) reaches a live
        instance.
        """
        return (
            time.monotonic() - self._last_refresh_attempt
        ) >= _JWKS_MIN_REFRESH_INTERVAL_SECS

    def _negative_cached(self, kid: str) -> bool:
        """True while ``kid`` is remembered as absent from Google's JWKS.

        Expired entries are dropped on read, so a stale negative can never
        outlive its deadline even if nothing else prunes.
        """
        deadline = self._unknown_kids.get(kid)
        if deadline is None:
            return False
        if time.monotonic() >= deadline:
            del self._unknown_kids[kid]
            return False
        return True

    def _remember_unknown_kid(self, kid: str) -> None:
        """Record that a REAL refresh did not contain ``kid``.

        Only ever called after a fetch actually happened -- a rate-gated
        refusal is not evidence about the kid, and caching it as one would
        turn the gate into a permanent denial for a legitimate rotation.
        That rule, together with the ``clear()`` every successful refresh
        performs, means the map holds ONE entry per DISTINCT unknown ``kid``
        that coalesced onto the last refresh -- normally one, but NOT "at
        most one" (H548-4): N concurrent deliveries with N distinct unknown
        kids share ONE fetch and all N land here, so the bounds below are
        reachable in the shipped flow rather than purely defensive.

        Bounded: expired entries are pruned, the oldest insertion is evicted
        at the entry cap (``dict`` preserves insertion order), and an
        over-long caller-supplied kid is not stored at all -- it is still
        refused and still rate-gated, it just does not get to consume memory.
        """
        if len(kid) > _JWKS_KID_MAX_CACHEABLE_LEN:
            return
        now = time.monotonic()
        for stale in [k for k, d in self._unknown_kids.items() if now >= d]:
            del self._unknown_kids[stale]
        while len(self._unknown_kids) >= _JWKS_UNKNOWN_KID_MAX_ENTRIES:
            del self._unknown_kids[next(iter(self._unknown_kids))]
        self._unknown_kids[kid] = now + _JWKS_MIN_REFRESH_INTERVAL_SECS

    async def get_key(self, kid: str) -> Any:
        """Return Google's public signing key for ``kid``.

        Every failure condition this module knows about leaves as
        :class:`GmailPushVerificationError` (the kid is not in the published
        set we hold, the refresh floor is down and the table we hold lacks it,
        or a refresh the COLD path needed was refused non-retryably -- by a
        non-retryable Google status or by the egress funnel) or
        :class:`GmailPushTransientFetchError` (we hold no usable table at all,
        the fetch failed transiently, the upstream body was unusable, or the
        table we hold is past ``_JWKS_MAX_STALE_SECS``). Both are caught by
        the webhook handler.

        That is an ENUMERATION, so it is not what makes the route safe: the
        guarantee "no failure of this path reaches the route as a 500" is
        carried by the seam in :func:`verify_pubsub_jwt`, which types anything
        this list has missed. Do not read the list as the control.
        """
        refreshed = False
        refresh_error: Exception | None = None
        if not self._keys:
            # Nothing to serve -- a cold start, or every previous fetch
            # failed. Gated like any other fetch; if the gate is shut this
            # raises the transient error and the route answers 503 (retry),
            # which is the honest answer: we cannot verify anything yet.
            await self._refresh()
            refreshed = True
        elif self._expired():
            # We DO hold Google's table. A transient upstream failure or a
            # shut gate must not cost the push path a full interval of 503s
            # on a one-second blip, so the stale-but-present table keeps
            # serving -- but ONLY while the table's AGE is under the
            # EFFECTIVE cap, which is the SHORTER of ``_JWKS_MAX_STALE_SECS``
            # and Google's own declared freshness on the last successful
            # fetch (``_effective_stale_cap``). Two halves of one change
            # (DB-548-1 + DB-548-7 / H548-2), which is why neither ships
            # alone:
            #
            # * BOTH typed refresh errors take this arm. Splitting on WHY
            #   the refresh failed cannot answer the question that governs
            #   serving a key we ALREADY hold, which is HOW OLD the table
            #   is -- a 404 from Google, or an ``EgressBlocked`` from a
            #   hand-edited funnel allowlist, says nothing about that, and
            #   refusing a push whose signing key is sitting in our warm
            #   table is an availability harm with no auth benefit.
            # * The CAP is what bounds trust, so the error taxonomy no
            #   longer has to carry that job. Broadening the arm WITHOUT
            #   the cap would have widened an already-unbounded staleness
            #   window to more failure modes.
            #
            # Past the cap: the TRANSIENT error, so the route answers 503
            # and Pub/Sub keeps retrying until Google returns.
            try:
                await self._refresh()
                refreshed = True
            except (GmailPushTransientFetchError,
                    GmailPushVerificationError) as e:
                if not self._stale_serve_allowed():
                    cap, source = self._effective_stale_cap()
                    raise GmailPushTransientFetchError(
                        "the Google JWKS refresh has kept failing past the "
                        f"{cap:.0f}s staleness cap (from the {source}; the "
                        f"key table we hold is {self._stale_age():.0f}s "
                        f"old); refusing to serve it: {e.reason}"
                    ) from e
                refresh_error = e
                cap, source = self._effective_stale_cap()
                logger.warning(
                    "Gmail JWKS refresh failed past TTL; still serving the "
                    "cached key table while its age stays under the "
                    "staleness cap, past which the answer becomes 503",
                    reason=e.reason,
                    table_age_secs=round(self._stale_age(), 1),
                    stale_cap_secs=cap,
                    stale_cap_source=source,
                )
        key = self._keys.get(kid)
        if key is not None:
            return key
        if not refreshed:
            # The amplification arm. Before punch 548 this was an
            # unconditional ``await self._refresh()``.
            if refresh_error is not None:
                # DA-548-7 / H548-5. A refresh WAS attempted on the expired
                # arm just above and failed upstream, so the gate is shut
                # because WE stamped it. Saying "rate-limited" here would
                # attribute an infrastructure fault to the caller's token on
                # the very log line an operator reads during that outage,
                # and ``gmail_push.auth_failed`` would be the counter they
                # watch. The STATUS CODE is deliberately unchanged -- 401 is
                # still right, we hold a table and this kid is not in it --
                # only the attributed CAUSE is corrected. Not
                # negative-cached either: no real refresh landed, so there
                # is no evidence about this kid to record.
                raise GmailPushVerificationError(
                    f"unknown signing key kid={kid} (the JWKS refresh that "
                    f"would have published it failed upstream: "
                    f"{refresh_error.reason})"
                )
            if self._negative_cached(kid):
                raise GmailPushVerificationError(
                    f"unknown signing key kid={kid} (negative-cached)"
                )
            if not self._refresh_allowed():
                # Refuse WITHOUT an outbound fetch. 401 is the right answer:
                # we hold Google's table and this kid is not in it. Pub/Sub
                # retries, so a real rotation verifies once the floor lifts.
                raise GmailPushVerificationError(
                    f"unknown signing key kid={kid} (JWKS refresh rate-limited)"
                )
            # Maybe the signing key rotated since our cache -- ONE gated
            # refresh, then the answer stands until the floor lifts again.
            await self._refresh()
            key = self._keys.get(kid)
            if key is not None:
                return key
        self._remember_unknown_kid(kid)
        raise GmailPushVerificationError(f"unknown signing key kid={kid}")

    async def _refresh(self) -> None:
        """Fetch Google's JWKS and install a new key table.

        RATE-GATED (punch 548): at most one outbound fetch per
        ``_JWKS_MIN_REFRESH_INTERVAL_SECS``. The gate is checked HERE, inside
        the only function in this module that performs the fetch, rather than
        at the call sites -- a gate at a call site is blind to the next call
        site somebody adds. A suppressed refresh RAISES rather than returning:
        a bare return would read to every caller exactly like a healthy
        refresh.

        Every failure leaves through :class:`GmailPushVerificationError` or
        :class:`GmailPushTransientFetchError`. The upstream-BODY failures --
        undecodable JSON, a non-object body, a non-list ``keys``, or members
        that all fail to parse -- take the TRANSIENT arm, because an upstream
        JWKS hiccup is a "retry later" condition and 503 is the arm this
        module already built for it (panel546 H-6: the pre-fix behaviour
        converted such a hiccup "into a 500 + retry amplification rather than
        the already-built 503/retry arm").
        """
        entered_with = self._fetched_at
        async with self._get_refresh_lock():
            if self._fetched_at != entered_with:
                # Someone else refreshed while we waited for the lock, so
                # their result IS ours and the caller re-reads a fresh table.
                # This return is a COALESCED SUCCESS, not a suppressed
                # refresh -- the two are distinguished by whether the table
                # actually moved, which is why the check is on
                # ``_fetched_at`` and not on the gate.
                return
            if not self._refresh_allowed():
                raise GmailPushTransientFetchError(
                    "Google JWKS refresh suppressed by the minimum refresh "
                    f"interval ({_JWKS_MIN_REFRESH_INTERVAL_SECS:.0f}s)"
                )
            # Consume the interval BEFORE the fetch: a FAILING fetch must
            # cost the interval too, or the failure path is itself an
            # unbounded-egress arm.
            self._last_refresh_attempt = time.monotonic()
            await self._fetch_and_install()

    async def _fetch_and_install(self) -> None:
        """The fetch itself. Split out ONLY so the lock/gate stay readable;
        it is called from :meth:`_refresh` under the lock and nowhere else,
        and it carries the same typed-error contract."""
        # N-288 R30: transient network failure (DNS blip, connect
        # timeout) during JWKS fetch used to escape uncaught → the
        # webhook receiver returned a 500 stack-trace, Google Pub/Sub
        # retried hard, producing thousands of error rows on a brief
        # infra blip (2026-06-25 Tailscale MagicDNS outage). Convert
        # to `GmailPushTransientFetchError` so the receiver can return
        # a 503 (transient/retry) instead of a 500.
        #
        # DA-548-8: the ``self._http.get()`` client CONSTRUCTION sits inside
        # the try as well. Be honest about what that does and does not buy:
        # neither handler below can catch what CONSTRUCTION raises --
        # ``EgressBlocked`` comes from the funnel's REQUEST hook so it
        # cannot originate here, and a construction failure is not an
        # ``httpx.RequestError`` -- so the ``verify_pubsub_jwt`` seam is
        # still what types it. The move keeps the enumeration honest about
        # where the await sits; the seam remains the control.
        try:
            client = await self._http.get()
            resp = await client.get(GOOGLE_JWKS_URL)
        except EgressBlocked as e:
            # A FOURTH untyped escape, found while reviewing the punch-548
            # change rather than in the panel: the `Intent.PROVIDER_API`
            # funnel raises this from its request event hook, and it is NOT
            # an `httpx.RequestError`, so it used to cross `_refresh`
            # untyped exactly like the other three. It is a policy refusal,
            # not a blip -- retrying will not fix a destination the funnel
            # declines -- so it takes the VERIFICATION arm (401) rather than
            # telling Pub/Sub to retry.
            from email_triage._errfmt import fmt_exc
            raise GmailPushVerificationError(
                "egress funnel refused the Google JWKS destination: "
                f"{fmt_exc(e, with_class=True)}"
            ) from e
        except httpx.RequestError as e:
            # N-298 R30 CI-red fix-forward: route through `fmt_exc` SSOT
            # (with_class=True keeps the ClassName: prefix while
            # PHI-scrubbing the message body) — the exc-render twin pin
            # caught the bare `f"{type(e).__name__}: {e}"` idiom.
            from email_triage._errfmt import fmt_exc
            raise GmailPushTransientFetchError(
                f"transient fetch failure for Google JWKS: "
                f"{fmt_exc(e, with_class=True)}"
            ) from e
        if resp.status_code != 200:
            # 5xx from Google itself is ALSO a transient case (retry-able);
            # 429 (rate-limit) is transient too — retrying after backoff is
            # correct per HTTP semantics. 4xx (except 429) is a real config
            # failure — raise the verification error.
            # N-297 R30 (DB-SME FU-3 on N-288): 429 added to the transient
            # set. Rare in practice for JWKS but easy to close.
            if 500 <= resp.status_code < 600 or resp.status_code == 429:
                raise GmailPushTransientFetchError(
                    f"Google JWKS transient upstream status: {resp.status_code}"
                )
            raise GmailPushVerificationError(
                f"failed to fetch Google JWKS: {resp.status_code}"
            )
        # panel546 H-6: `resp.json()`, `data.get` on a non-dict body and
        # `RSAAlgorithm.from_jwk` were THREE untyped escapes that reached the
        # route uncaught -> 500 -> Pub/Sub retry storm. Each is typed here,
        # and `verify_pubsub_jwt` additionally wraps the whole seam so the
        # net is complete by construction rather than by this enumeration.
        from email_triage._errfmt import fmt_exc
        try:
            data = resp.json()
        except Exception as e:  # noqa: BLE001 — any decoder failure is one condition
            raise GmailPushTransientFetchError(
                f"undecodable Google JWKS body: {fmt_exc(e, with_class=True)}"
            ) from e
        if not isinstance(data, dict):
            raise GmailPushTransientFetchError(
                f"Google JWKS body is not a JSON object: {type(data).__name__}"
            )
        members = data.get("keys")
        if not isinstance(members, list):
            raise GmailPushTransientFetchError(
                f"Google JWKS body has no `keys` list: {type(members).__name__}"
            )
        from jwt.algorithms import RSAAlgorithm  # lazy — uses cryptography
        new_keys: dict[str, Any] = {}
        for jwk in members:
            if not isinstance(jwk, dict):
                continue
            member_kid = jwk.get("kid")
            if not isinstance(member_kid, str) or not member_kid:
                continue
            try:
                new_keys[member_kid] = RSAAlgorithm.from_jwk(jwk)
            except Exception as e:  # noqa: BLE001 — tolerate ONE bad member
                # PyJWT 2.15.0's own shape: one malformed member must not
                # cost us every other key in the document.
                logger.warning(
                    "Skipping an unparseable member of Google's JWKS",
                    kid=member_kid, error=fmt_exc(e, with_class=True),
                )
        if not new_keys:
            # DB-546-5 + DA-546-16. A 200 whose body is `{}`, `{"keys": []}`,
            # or whose members all fail to parse must NOT become
            # `self._keys = {}`: that wipes a warm, working table and (if it
            # also stamped `_fetched_at`) leaves the TTL path with nothing to
            # refetch, so every delivery is refused until a restart. Upstream
            # guards exactly this -- "turning a transient outage into a cache
            # wipe that breaks legitimate auth". So: PRESERVE whatever we
            # hold, do NOT stamp, and raise the transient error. On a cold
            # cache that is a 503 and Pub/Sub retries; on a warm cache
            # `get_key`'s expired-arm catches it and keeps serving while
            # the table's age is under `_JWKS_MAX_STALE_SECS`.
            #
            # NOTE the interaction that makes this REQUIRED here rather than
            # optional: the accidental recovery path for a wiped cache used
            # to be the unconditional unknown-kid refresh, and the rate gate
            # in this same change removes it.
            raise GmailPushTransientFetchError(
                "Google JWKS yielded no usable key "
                f"({len(members)} members); keeping the previous key table"
            )
        self._keys = new_keys
        self._fetched_at = time.monotonic()
        # DB-548-7 / hipaa-548 Sec 6.8-6.11: capture Google's OWN declared
        # freshness so the staleness cap is bound to an external referent an
        # auditor can re-check by fetching a header, rather than to our
        # constant alone. Placed AFTER the install and the stamp on purpose:
        # nothing in this block may prevent a good key table from landing,
        # and both parsers are total so nothing here can raise.
        #
        # The two fallback cases are logged DISTINCTLY and at different
        # levels because they differ in KIND -- see
        # ``_JWKS_MIN_PLAUSIBLE_MAX_AGE``. Collapsing them would be the
        # self-sealing-control shape: the one condition the N-544 row
        # promises to have considered would be the one condition nothing
        # records.
        declared = _parse_max_age(resp.headers.get("Cache-Control"))
        if declared is None:
            # Case (a): nothing was declared, or it was unparseable. No
            # policy to deviate from; the ceiling is our own default.
            self._observed_freshness = None
            logger.debug(
                "Google JWKS response carried no usable Cache-Control "
                "max-age; the staleness cap falls back to our own ceiling",
                stale_cap_secs=_JWKS_MAX_STALE_SECS,
            )
        elif declared < _JWKS_MIN_PLAUSIBLE_MAX_AGE:
            # Case (b): a policy WAS declared and we disregard it. This is
            # a deviation and the widest single-case exposure in the design,
            # so it must never be silent.
            self._observed_freshness = None
            logger.warning(
                "Google JWKS declared an implausibly short Cache-Control "
                "max-age; DISREGARDING it in favour of our own ceiling, "
                "which exposes up to that ceiling of stale-serve against a "
                "declared policy",
                declared_max_age_secs=declared,
                min_plausible_max_age_secs=_JWKS_MIN_PLAUSIBLE_MAX_AGE,
                stale_cap_secs=_JWKS_MAX_STALE_SECS,
            )
        else:
            # Honour the ARITHMETIC however small (``is None`` in
            # ``_effective_stale_cap`` is what keeps a computed 0.0 from
            # being read as no-signal).
            age = _parse_age(resp.headers.get("Age")) or 0.0
            self._observed_freshness = max(0.0, declared - age)
        # A refresh is what defines "unknown": a kid absent from the PREVIOUS
        # table may well be present in this one.
        self._unknown_kids.clear()

    async def aclose(self) -> None:
        """Drain the long-lived httpx client. Idempotent."""
        await self._http.aclose()


async def verify_pubsub_jwt(
    token: str,
    *,
    audience: str,
    sa_email: str,
    cert_cache: _CertCache | None = None,
    leeway: int = 60,
) -> dict[str, Any]:
    """Verify a Google-signed Pub/Sub push JWT and return its claims.

    Raises :class:`GmailPushVerificationError` on any failure of the token
    itself — bad signature, wrong issuer, wrong audience, wrong SA email,
    expired, or a signing ``kid`` that is not in Google's published set — and
    :class:`GmailPushTransientFetchError` when the JWKS the check needs
    cannot be obtained right now (the caller answers that one 503/retry).
    No other exception type leaves this function: see the seam below.
    """
    if not token:
        raise GmailPushVerificationError("missing token")
    if not audience:
        raise GmailPushVerificationError("audience not configured")
    if not sa_email:
        raise GmailPushVerificationError("SA email not configured")

    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:  # noqa: BLE001 — PyJWT exposes many variants
        raise GmailPushVerificationError(f"malformed JWT header: {e}") from e

    kid = header.get("kid")
    if not kid:
        raise GmailPushVerificationError("JWT header missing kid")

    cache = cert_cache or _CertCache()
    # punch 548 / panel546 H-6 (PD-2, PD-8): the typed net around the JWKS
    # fetch is completed HERE, at the seam, not by enumerating `_refresh`'s
    # failure modes. Three untyped escapes used to cross this line uncaught
    # and the handler catches only the two typed errors, so the route
    # answered 500 and Pub/Sub retried hard. Those three are now typed at
    # the source AND this seam converts anything else -- including a failure
    # mode added later -- into the typed rejection the handler already
    # catches. The two typed errors re-raise UNCHANGED and FIRST, so the
    # transient arm keeps its 503 instead of being flattened into a 401.
    try:
        key = await cache.get_key(kid)
    except (GmailPushVerificationError, GmailPushTransientFetchError):
        raise
    except Exception as e:  # noqa: BLE001 — fail CLOSED on anything unforeseen
        from email_triage._errfmt import fmt_exc
        raise GmailPushVerificationError(
            f"JWKS key lookup failed: {fmt_exc(e, with_class=True)}"
        ) from e

    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=audience,
            leeway=leeway,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise GmailPushVerificationError("JWT expired") from e
    except jwt.InvalidAudienceError as e:
        raise GmailPushVerificationError("wrong audience") from e
    except jwt.InvalidSignatureError as e:
        raise GmailPushVerificationError("bad signature") from e
    except jwt.PyJWTError as e:
        raise GmailPushVerificationError(f"JWT decode failed: {e}") from e

    if claims.get("iss") not in VALID_ISSUERS:
        raise GmailPushVerificationError(f"unexpected issuer: {claims.get('iss')!r}")

    if claims.get("email") != sa_email:
        raise GmailPushVerificationError(
            f"unexpected SA email: {claims.get('email')!r}"
        )

    if claims.get("email_verified") is not True:
        raise GmailPushVerificationError("email_verified is not true")

    return claims
