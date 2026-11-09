""" — SearXNG free-text web-search provider tests.

Exercises :func:`email_triage.actions.web_search.web_search` with the HTTP
layer **mocked** — a real SearXNG is NEVER hit in CI. Mirrors the
boundary-patch pattern of ``test_clinicaltrials_resolver`` (patch the
module's ``_http.get``; the real parse / whitelist / cap logic runs).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.actions import web_search as ws
from email_triage.actions.web_search import web_search, web_search_bundle

# A realistic SearXNG JSON body. number_of_results is the unreliable
# counter (always 0 on this instance); `results` is the truth. Carries
# CommonMark (**, *), an over-long snippet, and an empty entry.
SEARX_BODY = {
    "query": "selena lupus",
    "number_of_results": 0,
    "results": [
        {
            "title": "**SELENA** trial — estrogen in lupus",
            "url": "https://example.invalid/selena",
            "content": "Safety of *Estrogen* in Lupus, a [Phase 3](u) study.",
            "engine": "duckduckgo",
        },
        {
            "title": "Second result",
            "url": "https://example.invalid/two",
            "content": "x" * 1000,  # over the per-result cap
        },
        {"title": "", "url": "", "content": ""},  # empty → dropped
    ],
}


def _mock_http(*, status_code, payload):
    """Patch ``web_search._http.get`` to yield a fake client whose ``.get``
    returns a response with the given status + JSON. Returns a patcher."""
    resp = MagicMock()
    resp.status_code = status_code
    if payload is None:
        resp.json.side_effect = json.JSONDecodeError("no body", "", 0)
    else:
        resp.json.return_value = payload
    fake_client = MagicMock()
    fake_client.get = AsyncMock(return_value=resp)
    return patch.object(ws._http, "get", AsyncMock(return_value=fake_client))


@pytest.mark.asyncio
async def test_returns_whitelisted_stripped_capped():
    with _mock_http(status_code=200, payload=SEARX_BODY):
        res = await web_search("selena lupus", base_url="http://lan.invalid:8080")
    assert res is not None
    # Only the three whitelisted keys, every entry.
    assert all(set(r.keys()) == {"title", "url", "content"} for r in res)
    # CommonMark stripped from title + content.
    assert "**" not in res[0]["title"] and "SELENA" in res[0]["title"]
    assert "*" not in res[0]["content"]
    assert "[Phase 3]" not in res[0]["content"] and "Phase 3" in res[0]["content"]
    # Over-long snippet capped.
    assert len(res[1]["content"]) <= 400
    # The empty entry was dropped.
    assert len(res) == 2


@pytest.mark.asyncio
async def test_top_n_caps_result_count():
    body = {"results": [
        {"title": f"r{i}", "url": f"https://e.invalid/{i}", "content": "c"}
        for i in range(20)
    ]}
    with _mock_http(status_code=200, payload=body):
        res = await web_search("q", base_url="http://lan.invalid:8080", top_n=5)
    assert res is not None and len(res) == 5


@pytest.mark.asyncio
async def test_non_200_returns_none():
    # e.g. SearXNG 403 when JSON format isn't enabled.
    with _mock_http(status_code=403, payload=None):
        assert await web_search("q", base_url="http://lan.invalid:8080") is None


@pytest.mark.asyncio
async def test_unparseable_json_returns_none():
    with _mock_http(status_code=200, payload=None):
        assert await web_search("q", base_url="http://lan.invalid:8080") is None


@pytest.mark.asyncio
async def test_no_results_returns_empty_list():
    with _mock_http(status_code=200, payload={"results": []}):
        res = await web_search("q", base_url="http://lan.invalid:8080")
    assert res == []


@pytest.mark.asyncio
async def test_network_error_returns_none():
    with patch.object(ws._http, "get", AsyncMock(side_effect=OSError("boom"))):
        assert await web_search("q", base_url="http://lan.invalid:8080") is None


@pytest.mark.asyncio
async def test_bundle_whitelists_signals():
    body = {
        "results": [{"title": "**T**", "url": "https://e.invalid/a", "content": "c"}],
        "corrections": ["lupus hrt", "x"],
        "suggestions": ["a", "b"],
        "answers": ["The SELENA trial studied estrogen safety."],
        "number_of_results": 0,
    }
    with _mock_http(status_code=200, payload=body):
        b = await web_search_bundle("q", base_url="http://lan.invalid:8080")
    assert b is not None
    assert b["results"][0]["title"] == "T"          # commonmark stripped
    assert b["corrections"] == ["lupus hrt", "x"]
    assert b["suggestions"] == ["a", "b"]
    assert b["answers"][0].startswith("The SELENA")


@pytest.mark.asyncio
async def test_bundle_none_on_non_200():
    with _mock_http(status_code=403, payload=None):
        assert await web_search_bundle("q", base_url="http://lan.invalid:8080") is None


@pytest.mark.asyncio
async def test_empty_query_or_host_returns_none_without_fetch():
    # No fetch should happen — guard before the network.
    with patch.object(ws._http, "get", AsyncMock()) as g:
        assert await web_search("", base_url="http://lan.invalid:8080") is None
        assert await web_search("q", base_url="") is None
        g.assert_not_called()
