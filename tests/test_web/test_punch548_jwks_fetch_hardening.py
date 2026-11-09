"""punch 548 / N-544 — behaviour of the hardened Gmail push JWKS fetch.

Four arms, one per finding in `panel546-hipaa.md`:

* **H-5 (amplification).** `/webhooks/gmail` is reachable unauthenticated and
  the `kid` is read from the UNVERIFIED header, so a storm of distinct `kid`s
  used to buy one outbound fetch to googleapis.com EACH. Fetches are counted
  through a stub transport here: N distinct unknown kids cost at most ONE
  fetch per `_JWKS_MIN_REFRESH_INTERVAL_SECS`, and the negative cache is
  bounded in entries and key length so closing the egress arm does not open a
  memory one.
* **H-6 (untyped escapes).** `resp.json()`, `data.get` on a non-dict body and
  `RSAAlgorithm.from_jwk` each used to escape `_refresh` untyped, cross
  `verify_pubsub_jwt` uncaught and reach the route as a 500 → Pub/Sub retry
  storm. Each now surfaces as one of the two typed errors, and the
  `verify_pubsub_jwt` seam converts anything else — including the handler
  ORDER, so the transient arm is not flattened into a 401.
* **H-7 (redirects).** The JWKS fetch is the trust-root retrieval for the
  authentication check, so a followed redirect substitutes the trust root.
  The test is BEHAVIOURAL, and its twin flips the kwarg to show that the
  argument is what stops it — asserting the kwarg is merely present would
  prove it was written, not that it has effect.
* **availability.** A failed refresh at the TTL boundary must NOT cost the
  push path a whole refresh interval of 503s: the stale-but-present table
  keeps serving, for BOTH typed refresh errors. That is the one way this fix
  could have regressed the availability finding it closes. Its counterweight
  is the staleness CAP (`_JWKS_MAX_STALE_SECS`): past it the table stops
  serving and the answer becomes 503, because nothing else in the code bounds
  the TOTAL trust window -- the floor bounds only the attempt SPACING.

Time is moved by rewinding the cache's own monotonic bases, never by patching
`time.monotonic` — a frozen process clock would also freeze the event loop's
and httpx's timers, which is a different test than the one intended.

Scope note: `_wire` installs a real `httpx.AsyncClient` over a
`MockTransport`, which means these tests exercise the CACHE's controls and not
the `Intent.PROVIDER_API` egress-policy hook (that hook is
`_egress`-owned and has its own tests). The redirect arm is therefore measured
in isolation from egress policy, which is the stricter reading.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx
import pytest

from email_triage.web import gmail_push_auth as gpa
from email_triage.web.gmail_push_auth import (
    GmailPushTransientFetchError,
    GmailPushVerificationError,
    _CertCache,
    verify_pubsub_jwt,
)

_AUDIENCE = "https://test.example.invalid/webhooks/gmail"
_SA_EMAIL = "pubsub-push@project.iam.gserviceaccount.com"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


def _lift_floor(cache: _CertCache) -> None:
    """Make the minimum-refresh-interval floor lift, as waiting would."""
    cache._last_refresh_attempt -= gpa._JWKS_MIN_REFRESH_INTERVAL_SECS + 1


def _expire_ttl(cache: _CertCache) -> None:
    """Age the cached table past `ttl_seconds` and lift the floor with it."""
    cache._fetched_at -= cache._ttl + 1
    _lift_floor(cache)


def _expire_negatives(cache: _CertCache) -> None:
    for k in list(cache._unknown_kids):
        cache._unknown_kids[k] -= gpa._JWKS_MIN_REFRESH_INTERVAL_SECS + 1


def _age_past_stale_cap(cache: _CertCache) -> None:
    """Age the cached table past `_JWKS_MAX_STALE_SECS` and lift the floor.

    Ages the table's own monotonic base rather than patching a clock, for the
    reason in the module docstring: a frozen process clock also freezes the
    event loop's and httpx's timers, which is a different test.
    """
    cache._fetched_at -= gpa._JWKS_MAX_STALE_SECS + 1
    _lift_floor(cache)


def _jwks_body(kids: list[str]) -> dict:
    """A JWKS whose members are STRUCTURALLY well-formed but not real RSA
    keys — `RSAAlgorithm.from_jwk` is stubbed per-test, so the bytes need not
    be valid for what these tests measure."""
    return {"keys": [{"kid": k, "kty": "RSA", "n": "AQAB", "e": "AQAB"}
                     for k in kids]}


class _Counter:
    """Counts outbound fetches and serves a scripted response per call."""

    def __init__(self, responder):
        self.n = 0
        self._responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.n += 1
        return self._responder(request, self.n)


def _wire(cache: _CertCache, counter: _Counter, **overrides) -> _Counter:
    """Install a real `httpx.AsyncClient` over a `MockTransport`, carrying the
    SAME constructor kwargs production passed — so `follow_redirects` is
    exercised as configured rather than as assumed."""
    kwargs = dict(cache._http._client_kwargs)
    kwargs.pop("event_hooks", None)
    kwargs.update(overrides)
    cache._http._client = httpx.AsyncClient(
        transport=httpx.MockTransport(counter), **kwargs
    )
    return counter


def _stub_from_jwk(monkeypatch, *, fail_kids: frozenset[str] = frozenset()):
    """Replace `RSAAlgorithm.from_jwk` with a stub that returns a marker.
    Members whose kid is in `fail_kids` raise — the only way to exercise the
    per-member tolerance arm without minting real keys."""
    from jwt.algorithms import RSAAlgorithm

    def _fake(jwk):
        kid = jwk.get("kid")
        if kid in fail_kids:
            raise ValueError(f"unparseable member {kid}")
        return f"key-for-{kid}"

    monkeypatch.setattr(RSAAlgorithm, "from_jwk", staticmethod(_fake))


def _ok(body):
    return lambda request, n: httpx.Response(200, json=body)


def _ok_with(body, headers: dict[str, str]):
    """A 200 carrying `body` AND response headers — the staleness cap reads
    `Cache-Control` and `Age` off the last successful fetch, so a responder
    that sets no headers exercises the no-signal fallback, not the cap."""
    return lambda request, n: httpx.Response(200, json=body, headers=headers)


def _token(kid: str = "unknown-kid") -> str:
    """A token whose HEADER is what matters: `verify_pubsub_jwt` reads the
    unverified `kid` and calls `get_key` before any signature check, which is
    exactly why the fetch is attacker-reachable."""
    import jwt as _jwt
    return _jwt.encode(
        {"iss": "https://accounts.google.com", "aud": _AUDIENCE},
        "secret", algorithm="HS256", headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# H-5 — the amplification arm
# ---------------------------------------------------------------------------


class TestUnknownKidStorm:
    @pytest.mark.asyncio
    async def test_storm_of_unknown_kids_costs_one_fetch(self, monkeypatch):
        """50 distinct unknown kids → at most ONE outbound fetch, and every
        one is refused with the typed verification error."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        for i in range(50):
            with pytest.raises(GmailPushVerificationError):
                await cache.get_key(f"attacker-kid-{i}")

        assert counter.n == 1, (
            f"punch 548: {counter.n} outbound JWKS fetches for 50 unknown "
            "kids — the refresh floor is not holding"
        )

    @pytest.mark.asyncio
    async def test_one_more_fetch_after_the_interval_lifts(self, monkeypatch):
        """The floor is a FLOOR, not a permanent stop: once it lifts, a
        rotated kid is picked up. The TTL is left fresh so this goes through
        the unknown-kid arm and not the expiry arm."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()

        def _responder(request, n):
            body = _jwks_body(["old-kid"] if n == 1 else ["old-kid", "new-kid"])
            return httpx.Response(200, json=body)

        counter = _wire(cache, _Counter(_responder))

        assert await cache.get_key("old-kid") == "key-for-old-kid"
        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("new-kid")
        assert counter.n == 1

        _lift_floor(cache)
        _expire_negatives(cache)
        assert await cache.get_key("new-kid") == "key-for-new-kid"
        assert counter.n == 2

    @pytest.mark.asyncio
    async def test_repeat_of_one_unknown_kid_is_negative_cached(
        self, monkeypatch,
    ):
        """The same unknown kid twice: the second refusal names the negative
        cache and costs no fetch."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("ghost")
        assert "ghost" in cache._unknown_kids

        with pytest.raises(GmailPushVerificationError) as ei:
            await cache.get_key("ghost")
        assert "negative-cached" in str(ei.value)
        assert counter.n == 1

    @pytest.mark.asyncio
    async def test_a_negative_never_outlives_the_floor(self, monkeypatch):
        """The negative TTL is the SAME constant as the interval on purpose:
        once the gate would permit a fetch, the negative must not still be
        refusing on its own authority."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("ghost")
        _expire_negatives(cache)
        assert cache._negative_cached("ghost") is False
        assert "ghost" not in cache._unknown_kids, "expired entry not pruned"

    @pytest.mark.asyncio
    async def test_a_gated_refusal_is_not_cached_as_evidence(
        self, monkeypatch,
    ):
        """A rate-limited refusal says nothing about the kid, so it must NOT
        become a negative-cache entry — otherwise the gate would turn into a
        denial that outlives itself."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("first")          # consumes the interval
        with pytest.raises(GmailPushVerificationError) as ei:
            await cache.get_key("second")         # gated: no fetch
        assert "rate-limited" in str(ei.value)
        assert "second" not in cache._unknown_kids
        assert counter.n == 1

    def test_negative_cache_eviction_bounds_the_map(self):
        """Closing the egress arm must not open a memory arm.

        This drives `_remember_unknown_kid` DIRECTLY, and that is the point:
        through `get_key` the map never exceeds ONE entry (every successful
        refresh clears it, and nothing is remembered without a refresh), so a
        storm-shaped test asserting `<= MAX` would pass without the eviction
        loop ever running -- green while measuring nothing. The caps are a
        defensive bound for the day that coupling loosens, so they are tested
        where they can actually fire.
        """
        cache = _CertCache()
        cap = gpa._JWKS_UNKNOWN_KID_MAX_ENTRIES
        for i in range(cap * 2 + 7):
            cache._remember_unknown_kid(f"k{i}")
        assert len(cache._unknown_kids) == cap
        assert "k0" not in cache._unknown_kids, "oldest insertion not evicted"
        assert f"k{cap * 2 + 6}" in cache._unknown_kids, "newest not retained"

    @pytest.mark.asyncio
    async def test_the_gate_not_the_negative_cache_is_what_bounds_fetches(
        self, monkeypatch,
    ):
        """The honest attribution, asserted so the prose cannot drift off it:
        after a 50-kid storm the negative cache holds ONE entry and the fetch
        count is 1 because of the refresh floor. If the negative cache were
        what bounded the storm, this map would hold 50."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        for i in range(50):
            with pytest.raises(GmailPushVerificationError):
                await cache.get_key(f"k{i}")
        assert counter.n == 1
        assert len(cache._unknown_kids) == 1
        assert "k0" in cache._unknown_kids

    @pytest.mark.asyncio
    async def test_overlong_kid_is_refused_but_not_stored(self, monkeypatch):
        """An over-long caller-supplied kid is still refused and still
        rate-gated; it simply does not get to consume memory."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(_ok(_jwks_body(["real-kid"]))))

        big = "z" * (gpa._JWKS_KID_MAX_CACHEABLE_LEN + 1)
        with pytest.raises(GmailPushVerificationError):
            await cache.get_key(big)
        assert big not in cache._unknown_kids
        assert counter.n == 1

    @pytest.mark.asyncio
    async def test_a_failing_fetch_also_consumes_the_interval(
        self, monkeypatch,
    ):
        """If only SUCCESSFUL fetches consumed the floor, the failure path
        would itself be an unbounded-egress arm."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        counter = _wire(cache, _Counter(lambda request, n: httpx.Response(503)))

        for _ in range(10):
            with pytest.raises(GmailPushTransientFetchError):
                await cache.get_key("anything")
        assert counter.n == 1

    @pytest.mark.asyncio
    async def test_a_successful_install_clears_the_negative_cache(
        self, monkeypatch,
    ):
        """DB-548-4: `_unknown_kids.clear()` on a successful install is a
        must-sentence asserted in three places -- the
        `_JWKS_UNKNOWN_KID_MAX_ENTRIES` comment ("negatives are also CLEARED
        whenever a new table lands"), `_remember_unknown_kid`'s docstring, and
        the N-544 row -- and db-sme's M7 mutation deleted it to `9 passed`.

        BE PRECISE ABOUT WHAT IS ASSERTED, because the obvious claim is not
        the true one: `get_key` reads `self._keys` BEFORE it consults the
        negative cache, so a kid present in the NEW table resolves whether or
        not the map was cleared -- there is no 401-on-rotation consequence to
        measure. What the clear actually buys is that the map stops holding
        evidence a later refresh has falsified, which is observable as the
        map's CONTENTS (and hence the refusal reason a still-absent kid gets).
        So the state is what this test asserts.
        """
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=3600)  # TTL never fires in this test

        def _responder(request, n):
            if n <= 2:
                return httpx.Response(200, json=_jwks_body(["k1"]))
            return httpx.Response(200, json=_jwks_body(["k1", "k2"]))

        counter = _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"  # fetch 1, cold

        _lift_floor(cache)
        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("k2")  # fetch 2: a REAL refresh without k2
        assert "k2" in cache._unknown_kids, (
            "the negative was never recorded, so this test cannot measure "
            "whether the install clears it"
        )

        _lift_floor(cache)
        with pytest.raises(GmailPushVerificationError):
            await cache.get_key("k9")  # fetch 3 installs k2, then k9 misses
        assert counter.n == 3
        assert set(cache._unknown_kids) == {"k9"}, (
            "the install did not clear the negative cache: `k2` is still "
            "recorded as absent by a refresh that published it"
        )
        # True either way (the table is read first) -- asserted as the
        # consequence, not as the detector.
        assert await cache.get_key("k2") == "key-for-k2"


# ---------------------------------------------------------------------------
# H-6 — the three untyped escapes, and the seam
# ---------------------------------------------------------------------------


class TestTypedNet:
    @pytest.mark.asyncio
    async def test_undecodable_body_is_typed(self, monkeypatch):
        """`resp.json()` — escape #1."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(
            lambda request, n: httpx.Response(200, content=b"<html>nope")))
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k")
        assert "undecodable" in str(ei.value)

    @pytest.mark.asyncio
    async def test_non_object_body_is_typed(self, monkeypatch):
        """`data.get` on a non-dict — escape #2 (a JSON list body)."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(_ok(["not", "a", "dict"])))
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k")
        assert "not a JSON object" in str(ei.value)

    @pytest.mark.asyncio
    async def test_keys_member_not_a_list_is_typed(self, monkeypatch):
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(_ok({"keys": {"kid": "x"}})))
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k")
        assert "`keys` list" in str(ei.value)

    @pytest.mark.asyncio
    async def test_one_bad_member_is_tolerated(self, monkeypatch):
        """`RSAAlgorithm.from_jwk` — escape #3. PyJWT 2.15.0's own shape: one
        malformed member must not cost every other key in the document."""
        _stub_from_jwk(monkeypatch, fail_kids=frozenset({"bad"}))
        cache = _CertCache()
        _wire(cache, _Counter(_ok(_jwks_body(["bad", "good"]))))
        assert await cache.get_key("good") == "key-for-good"

    @pytest.mark.asyncio
    async def test_all_members_bad_is_typed(self, monkeypatch):
        """Tolerance has a floor: members present and none parseable is an
        upstream document problem, so it takes the transient arm."""
        _stub_from_jwk(monkeypatch, fail_kids=frozenset({"a", "b"}))
        cache = _CertCache()
        _wire(cache, _Counter(_ok(_jwks_body(["a", "b"]))))
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("a")
        assert "no usable key" in str(ei.value)

    @pytest.mark.asyncio
    async def test_egress_refusal_is_typed(self, monkeypatch):
        """A FOURTH escape, found while reviewing this change rather than by
        the panel: the `Intent.PROVIDER_API` funnel raises `EgressBlocked`
        from its request event hook, and that is not an `httpx.RequestError`,
        so it used to cross `_refresh` untyped exactly like the other three.
        It is a policy refusal rather than a blip, so it takes the
        verification arm (401) instead of telling Pub/Sub to retry."""
        from email_triage._egress import EgressBlocked

        _stub_from_jwk(monkeypatch)
        cache = _CertCache()

        def _blocked(request, n):
            raise EgressBlocked("provider_api refused www.googleapis.com")

        _wire(cache, _Counter(_blocked))
        with pytest.raises(GmailPushVerificationError) as ei:
            await cache.get_key("k")
        assert "egress funnel refused" in str(ei.value)

    @pytest.mark.asyncio
    async def test_seam_converts_an_unforeseen_escape(self):
        """The PD-2 half: `verify_pubsub_jwt` types whatever `get_key` raises
        that is not already typed, so a NEW failure mode inside the cache
        cannot reach the route untyped."""

        class _Exploding(_CertCache):
            async def get_key(self, kid):
                raise RuntimeError("a failure mode nobody enumerated")

        with pytest.raises(GmailPushVerificationError) as ei:
            await verify_pubsub_jwt(
                _token(), audience=_AUDIENCE, sa_email=_SA_EMAIL,
                cert_cache=_Exploding(),
            )
        assert "JWKS key lookup failed" in str(ei.value)

    @pytest.mark.asyncio
    async def test_seam_does_not_flatten_the_transient_arm(self):
        """Handler ORDER: the transient error must re-raise unchanged, not be
        swallowed by the catch-all and answered 401."""

        class _Transient(_CertCache):
            async def get_key(self, kid):
                raise GmailPushTransientFetchError("upstream blip")

        with pytest.raises(GmailPushTransientFetchError):
            await verify_pubsub_jwt(
                _token(), audience=_AUDIENCE, sa_email=_SA_EMAIL,
                cert_cache=_Transient(),
            )


# ---------------------------------------------------------------------------
# availability — the TTL-boundary split
# ---------------------------------------------------------------------------


class TestStaleTableKeepsServing:
    @pytest.mark.asyncio
    async def test_blip_past_ttl_does_not_cost_the_interval(
        self, monkeypatch,
    ):
        """A populated table plus a failing refresh past TTL keeps serving.
        Gated strictly, a one-second upstream blip would have cost a full
        refresh interval of 503s on the mail-ingestion path — a regression of
        the availability finding this row exists to close."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)

        def _responder(request, n):
            if n == 1:
                return httpx.Response(200, json=_jwks_body(["k1"]))
            return httpx.Response(503)

        counter = _wire(cache, _Counter(_responder))

        assert await cache.get_key("k1") == "key-for-k1"
        _expire_ttl(cache)
        assert await cache.get_key("k1") == "key-for-k1"
        assert counter.n == 2, "the refresh was not even attempted"

    @pytest.mark.asyncio
    async def test_cold_start_with_no_table_fails_closed(self, monkeypatch):
        """The other half of the split: with NOTHING cached there is nothing
        honest to serve, so the transient error stands."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(lambda request, n: httpx.Response(500)))
        with pytest.raises(GmailPushTransientFetchError):
            await cache.get_key("k1")

    # --- the staleness cap: DB-548-7 + DB-548-1 + H548-2 ------------------
    #
    # Pre-cap, the expired arm re-served the cached table on EVERY failed
    # attempt and `_fetched_at` is stamped only on success, so `_expired()`
    # stayed true forever and the SAME table kept answering: db-sme measured
    # the t=0 table still serving at 23.5 h across 46 failed attempts. Only
    # the attempt SPACING was bounded. These three tests bound the trust
    # window itself, and the arm now takes BOTH typed errors -- the two halves
    # ship together because broadening alone would widen an unbounded window.

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status, kind",
        [(503, "a transient upstream failure"),
         (404, "a non-retryable verification failure")],
    )
    async def test_under_the_cap_both_error_kinds_serve_the_stale_table(
        self, monkeypatch, status, kind,
    ):
        """Under the cap the table we hold serves for BOTH typed refresh
        errors (DB-548-1).

        The 404 arm is the one that changed: it used to propagate
        `GmailPushVerificationError` out of `get_key` BEFORE `self._keys.get`
        was reached, so a push whose signing key was sitting in our warm table
        was refused 401. Splitting on WHY the refresh failed cannot answer the
        question that governs serving a key we already hold, which is how OLD
        the table is.
        """
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)

        def _responder(request, n):
            if n == 1:
                return httpx.Response(200, json=_jwks_body(["k1"]))
            return httpx.Response(status)

        counter = _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"
        _expire_ttl(cache)
        assert await cache.get_key("k1") == "key-for-k1", (
            f"{kind} past TTL refused a key that is in the table we hold"
        )
        assert counter.n == 2, "the refresh was not even attempted"
        assert cache._stale_serve_allowed()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [503, 404])
    async def test_a_table_past_the_cap_is_refused_with_the_transient_error(
        self, monkeypatch, status,
    ):
        """Past `_JWKS_MAX_STALE_SECS` the stale table stops serving, and the
        error is the TRANSIENT one so the route answers 503 and Pub/Sub keeps
        retrying until Google returns -- a 401 would tell Pub/Sub the token
        was bad and is the wrong signal for our own upstream outage.
        """
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)

        def _responder(request, n):
            if n == 1:
                return httpx.Response(200, json=_jwks_body(["k1"]))
            return httpx.Response(status)

        _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"
        _age_past_stale_cap(cache)
        assert not cache._stale_serve_allowed()
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k1")
        assert "staleness cap" in str(ei.value), (
            "past the cap the refusal must name the cap, not the upstream "
            "status -- that string is what an operator reads"
        )

    @pytest.mark.asyncio
    async def test_a_successful_refresh_resets_the_table_age(self, monkeypatch):
        """The cap is measured from the last SUCCESSFUL fetch, so a refresh
        that lands resets it. Without this, a long-lived healthy process would
        walk into the cliff on age alone -- which would be the cap answering a
        question about staleness with a question about uptime."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok(_jwks_body(["k1"]))))
        assert await cache.get_key("k1") == "key-for-k1"

        # Age the table to just INSIDE the cap, then let a refresh succeed.
        cache._fetched_at -= gpa._JWKS_MAX_STALE_SECS - 5.0
        _lift_floor(cache)
        assert cache._stale_age() > gpa._JWKS_MAX_STALE_SECS - 10.0
        assert cache._stale_serve_allowed()

        assert await cache.get_key("k1") == "key-for-k1"
        assert cache._stale_age() < 5.0, (
            "a successful refresh did not reset the table age, so the cap is "
            "measured from something other than the last install"
        )
        assert cache._stale_serve_allowed()

    @pytest.mark.asyncio
    async def test_a_failed_refresh_is_not_reported_as_rate_limiting(
        self, monkeypatch,
    ):
        """DA-548-7 / H548-5: on the expired arm a refresh that FAILED
        upstream leaves the gate shut because WE stamped it -- so the
        unknown-kid arm below used to answer "(JWKS refresh rate-limited)",
        attributing our own infrastructure fault to the caller's token on the
        `gmail_push.auth_failed` counter an operator watches during exactly
        that outage.

        The STATUS CODE is deliberately unchanged -- 401 is still right, we
        hold a table and this kid is not in it -- so what is asserted is the
        attributed CAUSE, and the exception class is asserted unchanged so
        this test cannot pass by having quietly moved the route to 503.
        """
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)

        def _responder(request, n):
            if n == 1:
                return httpx.Response(200, json=_jwks_body(["k1"]))
            return httpx.Response(503)

        _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"
        _expire_ttl(cache)

        with pytest.raises(GmailPushVerificationError) as ei:
            await cache.get_key("rotated-kid")
        msg = str(ei.value)
        assert "rate-limited" not in msg, (
            "an upstream refresh failure is still reported as rate limiting, "
            "which blames the caller for our outage: " + msg
        )
        assert "failed upstream" in msg, (
            "the refusal does not name the upstream failure it actually had "
            "in hand one branch earlier: " + msg
        )
        # No real refresh landed, so nothing was learned about this kid and
        # nothing may be recorded as evidence about it.
        assert "rotated-kid" not in cache._unknown_kids


_GPA_LOGGER = "email_triage.web.gmail_push_auth"


class TestObservedFreshnessCap:
    """DB-548-7 FINAL (`panel548-db.md`, revised) + hipaa-548 §6.8-§6.11.

    The staleness cap is the SHORTER of our own 6 h ceiling and GOOGLE'S
    declared freshness on the last SUCCESSFUL fetch (`max-age` less `Age`).
    The plausibility gate is on the DECLARED value; the subtraction is
    arithmetic and is honoured however small. Two fallbacks that differ in
    KIND are logged distinguishably: an absent/unparseable header is case (a)
    (nothing was declared -> no deviation -> DEBUG); a present-but-sub-60 s
    `max-age` is case (b) (a declared policy deliberately disregarded, up to
    the full ceiling of exposure -> WARNING with the parsed value).
    """

    @pytest.mark.asyncio
    async def test_a_plausible_max_age_is_honoured_exactly(self, monkeypatch):
        """Honoured EXACTLY, not floored: an earlier design clamped at
        `max(observed, ttl_seconds)`, which retained up to `ttl_seconds` of
        deviation in precisely the range this is supposed to close."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok_with(
            _jwks_body(["k1"]), {"Cache-Control": "public, max-age=1800"})))
        assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness == 1800.0
        assert cache._effective_stale_cap() == (1800.0, "observed")

    @pytest.mark.asyncio
    async def test_age_is_subtracted_from_the_declared_max_age(self, monkeypatch):
        """HTTP freshness counts from the origin, adjusted by `Age`
        (RFC 9111 §4.2.3). Google's real header behind an intermediary that
        has held the response for 20000 s leaves 3901 s of life, not 23901 --
        and the pre-fold `_fetch_and_install` read no headers at all."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok_with(_jwks_body(["k1"]), {
            "Cache-Control": "public, max-age=23901, must-revalidate",
            "Age": "20000",
        })))
        assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness == 3901.0
        assert cache._effective_stale_cap() == (3901.0, "observed")

    @pytest.mark.asyncio
    async def test_a_computed_zero_is_honoured_and_is_not_read_as_no_signal(
        self, monkeypatch,
    ):
        """`max-age=100` behind `Age: 200` computes to ZERO remaining
        freshness. 0.0 is falsy, so db-548's pseudocode
        (`self._observed_freshness or _JWKS_MAX_STALE_SECS`) would send the
        most-stale case there is to the 6 h ceiling -- the inversion of its
        own stated intent. `_effective_stale_cap` tests `is None` instead."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=3600)

        def _responder(request, n):
            if n == 1:
                return httpx.Response(
                    200, json=_jwks_body(["k1"]),
                    headers={"Cache-Control": "max-age=100", "Age": "200"},
                )
            return httpx.Response(503)

        _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness == 0.0
        assert cache._effective_stale_cap() == (0.0, "observed")
        assert cache._expired(), "zero remaining freshness is already expired"
        assert not cache._stale_serve_allowed(), "no stale serve is permitted"

        _lift_floor(cache)
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k1")
        assert "staleness cap" in str(ei.value)

    @pytest.mark.asyncio
    async def test_an_absent_cache_control_is_case_a_at_debug(
        self, monkeypatch, caplog,
    ):
        """Case (a): nothing was declared, so there is no policy to deviate
        from and the ceiling is our own conservative default. DEBUG, and NOT
        a WARNING -- the warning level is reserved for the deviation, and if
        both cases logged alike the deviation would be invisible."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok(_jwks_body(["k1"]))))
        with caplog.at_level(logging.DEBUG, logger=_GPA_LOGGER):
            assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness is None
        assert cache._effective_stale_cap() == (
            gpa._JWKS_MAX_STALE_SECS, "ceiling")
        hits = [r for r in caplog.records
                if "no usable Cache-Control" in r.getMessage()]
        assert len(hits) == 1, [r.getMessage() for r in caplog.records]
        assert hits[0].levelname == "DEBUG"
        assert not [r for r in caplog.records if r.levelname == "WARNING"], (
            "the routine no-signal case raised a WARNING, which is the level "
            "that must mean 'we disregarded a declared policy'"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "header", ["public, max-age=abc", "public, no-store", "max-age=-5"])
    async def test_an_unreadable_max_age_is_case_a_not_the_deviation(
        self, monkeypatch, caplog, header,
    ):
        """Present-but-unreadable is case (a), not case (b): we cannot
        deliberately disregard a policy we were never able to read."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok_with(
            _jwks_body(["k1"]), {"Cache-Control": header})))
        with caplog.at_level(logging.DEBUG, logger=_GPA_LOGGER):
            assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness is None
        assert cache._effective_stale_cap() == (
            gpa._JWKS_MAX_STALE_SECS, "ceiling")
        hits = [r for r in caplog.records
                if "no usable Cache-Control" in r.getMessage()]
        assert len(hits) == 1 and hits[0].levelname == "DEBUG"
        assert not [r for r in caplog.records if r.levelname == "WARNING"]

    @pytest.mark.asyncio
    async def test_an_implausibly_short_max_age_is_disregarded_at_warning(
        self, monkeypatch, caplog,
    ):
        """Case (b): a policy WAS declared and we deliberately disregard it,
        exposing up to the FULL ceiling of stale-serve against it. That is the
        widest single-case exposure in the capped design, so it logs at
        WARNING carrying the parsed value -- it must never be silent, and it
        must be distinguishable from case (a), or the one condition the N-544
        row promises to have considered is the one condition nothing
        records."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        _wire(cache, _Counter(_ok_with(
            _jwks_body(["k1"]), {"Cache-Control": "max-age=30"})))
        with caplog.at_level(logging.DEBUG, logger=_GPA_LOGGER):
            assert await cache.get_key("k1") == "key-for-k1"
        assert cache._observed_freshness is None
        assert cache._effective_stale_cap() == (
            gpa._JWKS_MAX_STALE_SECS, "ceiling")
        hits = [r for r in caplog.records
                if "implausibly short" in r.getMessage()]
        assert len(hits) == 1, [r.getMessage() for r in caplog.records]
        assert hits[0].levelname == "WARNING", (
            "the deviation case is not at WARNING, so a 6 h stale-serve "
            "window against a declared policy opens silently"
        )
        assert hits[0].declared_max_age_secs == 30.0, (
            "the WARNING does not carry the parsed value, so an operator "
            "cannot tell whether to revisit our constant"
        )

    @pytest.mark.asyncio
    async def test_a_short_freshness_expires_the_table_before_our_own_ttl(
        self, monkeypatch,
    ):
        """ONE STEP PAST db-548's pseudocode, and the N-544 row depends on it.

        The row records that across the plausible-signal range the deviation
        is ZERO. That is only true if a short-but-plausible freshness also
        shortens the FRESH-serve window: `_expired()` firing at `ttl_seconds`
        alone would keep a `max-age=120` document serving for 3480 s past the
        lifetime Google declared, with no refresh even attempted and no cap
        involved, because the cap only governs the arm after expiry.
        """
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=3600)
        counter = _wire(cache, _Counter(_ok_with(
            _jwks_body(["k1"]), {"Cache-Control": "max-age=120"})))
        assert await cache.get_key("k1") == "key-for-k1"
        assert counter.n == 1
        assert cache._observed_freshness == 120.0
        assert not cache._expired(), "still inside Google's declared 120 s"

        cache._fetched_at -= 121.0
        _lift_floor(cache)
        assert cache._expired(), (
            "our 3600 s TTL outlasted Google's declared 120 s freshness, so "
            "the table keeps serving past the lifetime its publisher gave it"
        )
        assert await cache.get_key("k1") == "key-for-k1"
        assert counter.n == 2, "no refresh was attempted past that lifetime"


# ---------------------------------------------------------------------------
# H-7 — the redirect refusal, behaviourally
# ---------------------------------------------------------------------------


def _redirect_responder(followed: list[str]):
    def _responder(request, n):
        if request.url.path.endswith("/v3/certs"):
            return httpx.Response(
                302, headers={"Location": "https://evil.example/jwks"})
        followed.append(str(request.url))
        return httpx.Response(200, json=_jwks_body(["evil-kid"]))
    return _responder


class TestRedirectNotFollowed:
    def test_constructor_states_it(self):
        assert _CertCache()._http._client_kwargs["follow_redirects"] is False

    @pytest.mark.asyncio
    async def test_a_302_is_not_followed(self, monkeypatch):
        """A redirected JWKS fetch would substitute the trust root for the
        authentication check. The Location handler must never be reached, and
        the refusal must be typed."""
        _stub_from_jwk(monkeypatch)
        followed: list[str] = []
        cache = _CertCache()
        _wire(cache, _Counter(_redirect_responder(followed)))

        with pytest.raises(GmailPushVerificationError) as ei:
            await cache.get_key("evil-kid")
        assert "302" in str(ei.value)
        assert followed == [], (
            "H-7: the JWKS fetch followed a redirect — the trust root for "
            f"the auth check was substituted by {followed}"
        )

    @pytest.mark.asyncio
    async def test_the_kwarg_is_what_stops_it(self, monkeypatch):
        """Prove the argument has EFFECT rather than merely being present:
        with it flipped, the same transport DOES follow the redirect."""
        _stub_from_jwk(monkeypatch)
        followed: list[str] = []
        cache = _CertCache()
        _wire(cache, _Counter(_redirect_responder(followed)),
              follow_redirects=True)

        assert await cache.get_key("evil-kid") == "key-for-evil-kid"
        assert followed == ["https://evil.example/jwks"]


# ---------------------------------------------------------------------------
# DB-546-4 / DB-546-5 / DB-546-3 — the three constraints the db seat placed
# on this fix. Each would be a REGRESSION introduced BY the rate gate if the
# fix had landed without it, which is why they are tested here and not in a
# later row.
# ---------------------------------------------------------------------------


class TestDbSeatConstraints:
    @pytest.mark.asyncio
    async def test_backward_wall_clock_step_does_not_freeze_the_ttl(
        self, monkeypatch,
    ):
        """DB-546-4. `_expired()` used `time.time()`, and db measured it
        returning False after a +2 h BACKWARD step -- on an ESXi VM, where
        suspend/resume and Tools time-sync are real sources. Pre-fix that
        staleness was masked by the unconditional unknown-kid refresh; the
        rate gate removes the mask, so a wall-clock TTL would have become a
        live auth outage. Every duration base is monotonic, so stepping the
        wall clock backward two hours changes nothing here."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)
        counter = _wire(cache, _Counter(_ok(_jwks_body(["k1"]))))
        assert await cache.get_key("k1") == "key-for-k1"

        real_time = time.time
        monkeypatch.setattr(gpa.time, "time", lambda: real_time() - 7200)

        # Still fresh by the monotonic TTL: no refetch, and no refusal.
        assert await cache.get_key("k1") == "key-for-k1"
        assert counter.n == 1
        assert cache._expired() is False

        # And the TTL still EXPIRES on schedule despite the lying wall clock.
        _expire_ttl(cache)
        assert cache._expired() is True
        assert await cache.get_key("k1") == "key-for-k1"
        assert counter.n == 2

    @pytest.mark.asyncio
    async def test_an_empty_jwks_does_not_wipe_a_warm_cache(self, monkeypatch):
        """DB-546-5. A 200 whose body is `{"keys": []}` used to install an
        empty table AND stamp `_fetched_at`, so the TTL path would not
        refetch and every delivery was refused until a restart. The previous
        table is preserved, `_fetched_at` is NOT advanced, and the refresh
        raises the transient error."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache(ttl_seconds=60)

        def _responder(request, n):
            body = _jwks_body(["k1"]) if n == 1 else {"keys": []}
            return httpx.Response(200, json=body)

        counter = _wire(cache, _Counter(_responder))
        assert await cache.get_key("k1") == "key-for-k1"

        _expire_ttl(cache)
        # Captured AFTER the rewind: the claim is that the FAILED refresh
        # does not advance the stamp, not that the test harness left it
        # alone.
        stamped = cache._fetched_at
        assert await cache.get_key("k1") == "key-for-k1", (
            "DB-546-5: the warm key table was wiped by an empty JWKS"
        )
        assert counter.n == 2
        assert cache._fetched_at == stamped, "_fetched_at advanced on a wipe"

    @pytest.mark.asyncio
    async def test_an_empty_jwks_on_a_cold_cache_is_transient(self, monkeypatch):
        """The other side of DB-546-5, per DA-546-16: with nothing to
        preserve, zero parsed keys is a 503 so Pub/Sub retries rather than a
        hard failure."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()
        _wire(cache, _Counter(_ok({"keys": []})))
        with pytest.raises(GmailPushTransientFetchError) as ei:
            await cache.get_key("k1")
        assert "no usable key" in str(ei.value)

    @pytest.mark.asyncio
    async def test_concurrent_cold_misses_coalesce_to_one_fetch(
        self, monkeypatch,
    ):
        """DB-546-3: db counted 25 concurrent requests producing 25 fetches
        with no coalescing. One `asyncio.Lock` across the refresh means they
        produce ONE, and every waiter gets that result rather than a 503 --
        without the lock the gate alone would refuse 24 of them."""
        _stub_from_jwk(monkeypatch)
        cache = _CertCache()

        async def _slow(request):
            counter.n += 1
            await asyncio.sleep(0.02)
            return httpx.Response(200, json=_jwks_body(["k1"]))

        counter = _Counter(lambda request, n: None)
        counter.n = 0
        kwargs = dict(cache._http._client_kwargs)
        kwargs.pop("event_hooks", None)
        cache._http._client = httpx.AsyncClient(
            transport=httpx.MockTransport(_slow), **kwargs
        )

        results = await asyncio.gather(
            *(cache.get_key("k1") for _ in range(25))
        )
        assert results == ["key-for-k1"] * 25
        assert counter.n == 1, (
            f"DB-546-3: 25 concurrent cold misses produced {counter.n} "
            "fetches; the single-flight lock is not coalescing"
        )


# ---------------------------------------------------------------------------
# route level — the typed rejection reaches the client, never a 500
# ---------------------------------------------------------------------------


@pytest.fixture
def push_cfg(client):
    """Push config on the shared test app. A local fixture on purpose:
    `test_webhooks.py`'s `push_app` also installs a stub cert cache whose
    `get_key` always succeeds, which is the opposite of what these tests
    measure."""
    import asyncio
    app = client.app
    app.state.config.push.gmail_subscription_sa_email = _SA_EMAIL
    app.state.config.push.gmail_audience = _AUDIENCE
    app.state.config.push.public_url = "https://test.example.invalid"
    app.state.push_queue = asyncio.Queue(maxsize=4)
    app.state.metrics = {}
    return app


class TestGmailPushRouteNever500:
    """The handler catches exactly the two typed errors, so an untyped escape
    is a 500 and a Pub/Sub retry storm. Both directions are asserted: 503 for
    an upstream-body problem (the arm panel546 H-6 names as "the already-built
    503/retry arm") and 401 for a kid problem."""

    @staticmethod
    def _install(app, monkeypatch, responder) -> _Counter:
        _stub_from_jwk(monkeypatch)
        cache = gpa._CertCache()
        counter = _wire(cache, _Counter(responder))
        app.state._gmail_cert_cache = cache
        return counter

    def test_malformed_jwks_body_is_503_not_500(
        self, push_cfg, client, db, monkeypatch,
    ):
        self._install(push_cfg, monkeypatch,
                      lambda request, n: httpx.Response(200, content=b"nope"))
        resp = client.post(
            "/webhooks/gmail", json={"message": {"data": ""}},
            headers={"Authorization": f"Bearer {_token()}"},
        )
        assert resp.status_code == 503, resp.text
        assert resp.json()["reason"] == "jwks_fetch_transient"

    def test_unknown_kid_is_401_not_500(
        self, push_cfg, client, db, monkeypatch,
    ):
        self._install(push_cfg, monkeypatch, _ok(_jwks_body(["other-kid"])))
        resp = client.post(
            "/webhooks/gmail", json={"message": {"data": ""}},
            headers={"Authorization": f"Bearer {_token()}"},
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["reason"] == "unauthorized"

    def test_kid_storm_through_the_route_costs_one_fetch(
        self, push_cfg, client, db, monkeypatch,
    ):
        """The finding as the attacker reaches it: unauthenticated POSTs with
        distinct kids, counted at the egress boundary."""
        counter = self._install(
            push_cfg, monkeypatch, _ok(_jwks_body(["other-kid"])))
        for i in range(25):
            resp = client.post(
                "/webhooks/gmail", json={"message": {"data": ""}},
                headers={"Authorization": f"Bearer {_token(f'storm-{i}')}"},
            )
            assert resp.status_code == 401, resp.text
        assert counter.n == 1, (
            f"N-544: 25 unauthenticated pushes forced {counter.n} outbound "
            "JWKS fetches"
        )
