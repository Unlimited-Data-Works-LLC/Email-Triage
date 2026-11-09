""" — ClinicalTrials.gov NCT resolver tests.

Exercises :func:`email_triage.actions.clinicaltrials.resolve_nct` with
the HTTP layer **mocked** — the real clinicaltrials.gov API is NEVER
hit in CI. httpx is mocked via ``unittest.mock.patch`` on the module's
``LazyHttpClient.get`` (the same project-wide pattern that
``test_watch_runner`` / ``test_events`` use: patch the client, don't add
a respx-style dep).

Coverage (per the build brief):
  (a) a valid NCT (NCT00000419 → SELENA lupus/HRT/Phase 3/TERMINATED/
      NYU Langone) returns the whitelisted dict;
  (b) a bad-format id returns None (no fetch attempted);
  (c) a 404 returns None;
  (d) the cache returns the SAME object without a second fetch;
  (e) ONLY whitelisted fields are present — no raw eligibility /
      locations / contact / PII fields leak through.

Plus: network-error → None (graceful), non-200 → None, normalisation,
and CommonMark stripping of free-text fields.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.actions import clinicaltrials as ct
from email_triage.actions.clinicaltrials import (
    normalize_nct,
    resolve_nct,
    strip_commonmark,
)


# ---------------------------------------------------------------------------
# Fixture — a realistic NCT00000419 v2 response.
#
# Modelled on the LIVE v2 API shape (verified against
# GET /api/v2/studies/NCT00000419?format=json). Deliberately carries
# MORE than the whitelist: eligibilityModule, contactsLocationsModule
# (investigator names + site addresses = PII-bearing), oversightModule,
# and extra identification fields. The whitelist test (e) asserts NONE
# of that crosses into the resolved dict.
# ---------------------------------------------------------------------------

SELENA_PAYLOAD = {
    "protocolSection": {
        "identificationModule": {
            "nctId": "NCT00000419",
            "orgStudyIdInfo": {"id": "NIAMS-019"},
            "briefTitle": "Safety of Estrogens in Lupus: HRT",
            "officialTitle": (
                "Safety of Estrogens in Lupus Erythematosus - National "
                "Assessment (SELENA): Hormone Replacement Therapy"
            ),
        },
        "statusModule": {
            "overallStatus": "TERMINATED",
            "whyStopped": "Some internal note that is NOT whitelisted",
        },
        "sponsorCollaboratorsModule": {
            "leadSponsor": {"name": "NYU Langone Health", "class": "OTHER"},
            "collaborators": [{"name": "NIAMS", "class": "NIH"}],
        },
        "descriptionModule": {
            "briefSummary": (
                "**SELENA** is a study to test whether postmenopausal women "
                "with systemic lupus erythematosus can safely use the hormone "
                "[estrogen](http://example.org/estrogen)."
            ),
            "detailedDescription": "A much longer detailed description block.",
        },
        "conditionsModule": {
            "conditions": ["Systemic Lupus Erythematosus"],
            "keywords": ["Lupus", "SLE"],
        },
        "designModule": {
            "studyType": "INTERVENTIONAL",
            "phases": ["PHASE3"],
            "enrollmentInfo": {"count": 351},
        },
        "armsInterventionsModule": {
            "interventions": [
                {
                    "type": "DRUG",
                    "name": "Premarin and Provera",
                    "description": "intervention detail not whitelisted",
                }
            ],
        },
        # ── PII-bearing modules that MUST NOT leak ──────────────────────
        "eligibilityModule": {
            "eligibilityCriteria": "Inclusion: women 18-65 with SLE...",
            "sex": "FEMALE",
            "minimumAge": "18 Years",
        },
        "contactsLocationsModule": {
            "overallOfficials": [
                {"name": "Dr. Jane Investigator", "affiliation": "NYU"}
            ],
            "locations": [
                {
                    "facility": "NYU Medical Center",
                    "city": "New York",
                    "state": "New York",
                    "contacts": [
                        {"name": "Study Coordinator", "phone": "555-1234"}
                    ],
                }
            ],
        },
    },
    "derivedSection": {"miscInfoModule": {"versionHolder": "2026-06-07"}},
}

#: The exact whitelist the resolver promises — used by test (e).
WHITELIST_KEYS = {
    "nct_id",
    "official_title",
    "brief_summary",
    "conditions",
    "interventions",
    "phase",
    "status",
    "lead_sponsor",
}


# ---------------------------------------------------------------------------
# httpx mock plumbing
# ---------------------------------------------------------------------------


def _make_response(status_code: int, payload: object | None = None) -> MagicMock:
    """A stand-in for an ``httpx.Response`` — only the bits the resolver
    touches (``status_code`` and ``.json()``)."""
    resp = MagicMock()
    resp.status_code = status_code
    if payload is None:
        resp.json.side_effect = json.JSONDecodeError("no body", "", 0)
    else:
        resp.json.return_value = payload
    return resp


def _patch_http(behaviour):
    """Patch ``clinicaltrials._http.get`` to hand back a fake client whose
    ``.get(url)`` is driven by ``behaviour``:

      * an ``async def`` / callable / Exception  -> ``side_effect``
        (per-call dynamic response, e.g. a sequence or a raise);
      * anything else (a response object / MagicMock) -> ``return_value``
        (the same response on every call).

    Note: ``_make_response`` returns a ``MagicMock`` which IS callable,
    so we test for an exception or a *coroutine function* explicitly —
    a plain response object must fall through to ``return_value``.

    Returns the patcher context manager AND the AsyncMock for the
    client's ``.get`` so a test can assert the call count.
    """
    # inspect, not asyncio: asyncio.iscoroutinefunction is deprecated in 3.14 (removal in
    # 3.16), and pyproject's error::DeprecationWarning makes the call fail on the 3.14 base.
    import inspect

    client = MagicMock()
    is_dynamic = (
        isinstance(behaviour, Exception)
        or inspect.iscoroutinefunction(behaviour)
        or (callable(behaviour) and not isinstance(behaviour, MagicMock))
    )
    if is_dynamic:
        client.get = AsyncMock(side_effect=behaviour)
    else:
        client.get = AsyncMock(return_value=behaviour)
    holder_get = patch.object(ct._http, "get", AsyncMock(return_value=client))
    return holder_get, client.get


@pytest.fixture(autouse=True)
def _clear_resolver_cache():
    """Each test starts with an empty resolver cache so cross-test state
    can't mask a missing fetch (or fake a cache hit)."""
    ct._clear_cache()
    yield
    ct._clear_cache()


# ---------------------------------------------------------------------------
# (a) valid NCT → whitelisted dict
# ---------------------------------------------------------------------------


class TestValidResolve:
    @pytest.mark.asyncio
    async def test_valid_nct_returns_whitelisted_dict(self):
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, client_get = _patch_http(ok)
        with holder_get:
            result = await resolve_nct("NCT00000419")

        assert result is not None
        assert result["nct_id"] == "NCT00000419"
        assert result["official_title"] == (
            "Safety of Estrogens in Lupus Erythematosus - National "
            "Assessment (SELENA): Hormone Replacement Therapy"
        )
        # CommonMark stripped from the summary (bold + link → plain text).
        assert "**" not in result["brief_summary"]
        assert "estrogen" in result["brief_summary"]
        assert "http://example.org" not in result["brief_summary"]
        assert "[estrogen]" not in result["brief_summary"]
        assert result["conditions"] == ["Systemic Lupus Erythematosus"]
        assert result["interventions"] == ["Premarin and Provera"]
        assert result["phase"] == ["PHASE3"]
        assert result["status"] == "TERMINATED"
        assert result["lead_sponsor"] == "NYU Langone Health"
        # Exactly one fetch.
        assert client_get.await_count == 1

    @pytest.mark.asyncio
    async def test_normalisation_before_fetch(self):
        """A messy-but-valid id (whitespace, lowercase) resolves and the
        fetched URL carries the canonical upper-case id."""
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, client_get = _patch_http(ok)
        with holder_get:
            result = await resolve_nct("  nct 0000 0419 ")

        assert result is not None
        assert result["nct_id"] == "NCT00000419"
        called_url = client_get.await_args.args[0]
        assert "NCT00000419" in called_url
        assert "format=json" in called_url


# ---------------------------------------------------------------------------
# (b) bad format → None (and no fetch)
# ---------------------------------------------------------------------------


class TestBadFormat:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad",
        [
            "NCT123",            # too few digits
            "NCT000004190",      # too many digits
            "ABC00000419",       # wrong prefix
            "00000419",          # no prefix
            "NCT0000041A",       # non-digit
            "",                  # empty
            "   ",               # whitespace only
            "DROP TABLE studies; NCT00000419",  # junk wrapper
        ],
    )
    async def test_bad_format_returns_none_without_fetch(self, bad):
        holder_get, client_get = _patch_http(_make_response(200, SELENA_PAYLOAD))
        with holder_get:
            result = await resolve_nct(bad)
        assert result is None
        # An invalid id must short-circuit BEFORE any network call.
        assert client_get.await_count == 0

    @pytest.mark.asyncio
    async def test_non_string_returns_none(self):
        holder_get, client_get = _patch_http(_make_response(200, SELENA_PAYLOAD))
        with holder_get:
            assert await resolve_nct(None) is None  # type: ignore[arg-type]
        assert client_get.await_count == 0


# ---------------------------------------------------------------------------
# (c) 404 → None
# ---------------------------------------------------------------------------


class TestNotFound:
    @pytest.mark.asyncio
    async def test_404_returns_none(self):
        not_found = _make_response(404, {"message": "not found"})
        holder_get, client_get = _patch_http(not_found)
        with holder_get:
            result = await resolve_nct("NCT99999999")
        assert result is None
        assert client_get.await_count == 1

    @pytest.mark.asyncio
    async def test_non_200_returns_none(self):
        server_err = _make_response(503, {"message": "down"})
        holder_get, _ = _patch_http(server_err)
        with holder_get:
            assert await resolve_nct("NCT00000419") is None

    @pytest.mark.asyncio
    async def test_404_is_not_cached(self):
        """A failed resolve must NOT poison the cache — a later success
        for the same id should still fetch + resolve."""
        not_found = _make_response(404, {"message": "not found"})
        ok = _make_response(200, SELENA_PAYLOAD)
        responses = [not_found, ok]

        async def _seq(url):
            return responses.pop(0)

        holder_get, client_get = _patch_http(_seq)
        with holder_get:
            assert await resolve_nct("NCT00000419") is None
            second = await resolve_nct("NCT00000419")
        assert second is not None
        assert second["status"] == "TERMINATED"
        assert client_get.await_count == 2


# ---------------------------------------------------------------------------
# Network error → None (graceful)
# ---------------------------------------------------------------------------


class TestNetworkError:
    @pytest.mark.asyncio
    async def test_network_error_returns_none(self):
        import httpx

        async def _boom(url):
            raise httpx.ConnectError("connection refused")

        holder_get, _ = _patch_http(_boom)
        with holder_get:
            result = await resolve_nct("NCT00000419")
        assert result is None

    @pytest.mark.asyncio
    async def test_unparseable_json_returns_none(self):
        bad_body = _make_response(200, None)  # .json() raises
        holder_get, _ = _patch_http(bad_body)
        with holder_get:
            assert await resolve_nct("NCT00000419") is None

    @pytest.mark.asyncio
    async def test_non_object_json_returns_none(self):
        weird = _make_response(200, ["not", "an", "object"])
        holder_get, _ = _patch_http(weird)
        with holder_get:
            assert await resolve_nct("NCT00000419") is None


# ---------------------------------------------------------------------------
# (d) cache returns the same object without a second fetch
# ---------------------------------------------------------------------------


class TestCache:
    @pytest.mark.asyncio
    async def test_cache_returns_same_object_no_second_fetch(self):
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, client_get = _patch_http(ok)
        with holder_get:
            first = await resolve_nct("NCT00000419")
            second = await resolve_nct("NCT00000419")

        assert first is not None
        # SAME object identity — served straight from the cache.
        assert first is second
        # Exactly ONE network call across two resolves.
        assert client_get.await_count == 1

    @pytest.mark.asyncio
    async def test_cache_keys_on_normalised_id(self):
        """A messy id and a clean id for the same study share one cache
        entry → one fetch."""
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, client_get = _patch_http(ok)
        with holder_get:
            a = await resolve_nct("NCT00000419")
            b = await resolve_nct("  nct00000419 ")
        assert a is b
        assert client_get.await_count == 1


# ---------------------------------------------------------------------------
# (e) ONLY whitelisted fields present — no PII leak
# ---------------------------------------------------------------------------


class TestWhitelistOnly:
    @pytest.mark.asyncio
    async def test_only_whitelisted_keys_present(self):
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, _ = _patch_http(ok)
        with holder_get:
            result = await resolve_nct("NCT00000419")

        assert result is not None
        assert set(result.keys()) == WHITELIST_KEYS

    @pytest.mark.asyncio
    async def test_no_pii_or_raw_modules_leak(self):
        """The PII-bearing fields in the fixture (eligibility criteria,
        investigator names, site addresses, phone numbers, why-stopped,
        detailedDescription) must appear NOWHERE in the resolved dict."""
        ok = _make_response(200, SELENA_PAYLOAD)
        holder_get, _ = _patch_http(ok)
        with holder_get:
            result = await resolve_nct("NCT00000419")

        assert result is not None
        blob = json.dumps(result).lower()
        forbidden = [
            "eligibility",
            "inclusion",
            "jane investigator",
            "study coordinator",
            "555-1234",
            "nyu medical center",
            "new york",
            "why",                      # whyStopped note
            "some internal note",
            "longer detailed description",
            "niams",                    # collaborator, not lead sponsor
            "keywords",
            "minimumage",
            "intervention detail",      # intervention.description
        ]
        for needle in forbidden:
            assert needle not in blob, f"leaked: {needle!r}"

    @pytest.mark.asyncio
    async def test_missing_optional_modules_degrade_gracefully(self):
        """A sparse record (only the title) still resolves — missing
        whitelist fields come back as empty, never KeyError."""
        sparse = {
            "protocolSection": {
                "identificationModule": {"officialTitle": "A Bare Study"}
            }
        }
        ok = _make_response(200, sparse)
        holder_get, _ = _patch_http(ok)
        with holder_get:
            result = await resolve_nct("NCT12345678")

        assert result is not None
        assert result["official_title"] == "A Bare Study"
        assert result["brief_summary"] == ""
        assert result["conditions"] == []
        assert result["interventions"] == []
        assert result["phase"] == []
        assert result["status"] == ""
        assert result["lead_sponsor"] == ""
        assert set(result.keys()) == WHITELIST_KEYS


# ---------------------------------------------------------------------------
# Unit coverage for the helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("NCT00000419", "NCT00000419"),
            ("nct00000419", "NCT00000419"),
            ("  NCT00000419  ", "NCT00000419"),
            ("NCT 0000 0419", "NCT00000419"),
            ("\tnct00000419\n", "NCT00000419"),
            ("NCT0000041", None),
            ("NCT000004190", None),
            ("XCT00000419", None),
            ("", None),
            (None, None),
            (12345678, None),
        ],
    )
    def test_normalize_nct(self, raw, expected):
        assert normalize_nct(raw) == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("plain text", "plain text"),
            ("**bold**", "bold"),
            ("_em_ and __strong__", "em and strong"),
            ("[link](http://x.com)", "link"),
            ("![alt](http://img.png)", "alt"),
            ("`code`", "code"),
            ("# Heading", "Heading"),
            ("> quote", "quote"),
            ("- bullet", "bullet"),
            ("1. numbered", "numbered"),
            (None, ""),
            ("", ""),
            (123, ""),
        ],
    )
    def test_strip_commonmark(self, raw, expected):
        assert strip_commonmark(raw) == expected
