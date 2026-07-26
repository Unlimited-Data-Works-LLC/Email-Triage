""" — SearXNG free-text web search (Internet-Search free-text path).

Implements the design's §3d "Free-text web path (non-HIPAA only, opt-in)"
from ``internal documentation``:

* The operator types free text (NOT a registry id) into the Topic editor's
  Internet-Search box; this resolver queries a **self-hosted SearXNG**
  instance and returns the top-N results as small, flat
  ``{title, url, content}`` dicts the topic-detail router renders **as
  data, not instructions** (confirm-before-replace, same as the NCT path).

Privacy / HIPAA posture (most-restrictive-wins, design §1a)
==========================================================

* **Non-HIPAA only.** The HTTP-layer route gates this path OFF for any
  Topic that includes a HIPAA-flagged mailbox (→ ClinicalTrials.gov
  registry-only). This module is the mechanism; the route owns the gate.
* **Server-side only.** The fetch runs in the install process; the browser
  never talks to SearXNG directly.
* **Single allow-listed destination.** ``base_url`` is the operator's OWN
  admin-configured SearXNG host (the ``web_search`` setting). The resolver
  only ever calls that host — a misconfig can't repoint egress at an
  arbitrary destination without admin access. The host is enumerated in
  the ``project_no_external_data_flow`` outbound inventory
  (``docs/privacy.md`` "What leaves the install").
* **Outbound payload is the operator's typed query.** On the non-HIPAA
  path the operator's free text is searched verbatim (per the operator
  ruling 2026-06-08: no query PHI-scrub on the non-HIPAA path — the
  HIPAA→registry-only gate is the control). No mailbox content is sent.
* **Whitelist + sanitize on the way back in.** Only ``title``/``url``/
  ``content`` are read from each result, CommonMark-stripped and
  length-capped. Web result text is an indirect-prompt-injection surface
  (design §6): callers that feed it to an LLM MUST wrap it with
  :func:`email_triage.llm_safety.fence_data`. (The editor flow shows
  results to the operator to Replace/Append into Details; Details is
  fenced when it later reaches the matching LLM.)

The resolver returns ``None`` on any failure (no host, network error,
non-200, unparseable JSON) and ``[]`` when SearXNG returns no results —
it **never raises**, so a slow/down backend degrades the HTMX fragment to
"no results" instead of 500-ing the editor.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from email_triage._errfmt import fmt_exc
from email_triage._http_client import Intent, LazyHttpClient
from email_triage.actions.clinicaltrials import strip_commonmark

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.actions.web_search")  # N-196b R21_4

# Short cap — this blocks an HTMX fragment swap; a slow/down SearXNG must
# not hang the editor (→ returns None → "no results / type by hand").
_TIMEOUT_S = 10.0
#: How many results to surface. The design says "top-N … ~1-2k tokens";
#: 8 snippets at ~400 chars each stays well under that.
DEFAULT_TOP_N = 8
#: Per-result snippet cap (chars). Keeps the rendered card + any future
#: fenced LLM context bounded.
_MAX_CONTENT_CHARS = 400
_MAX_TITLE_CHARS = 200
_MAX_URL_CHARS = 300

# One long-lived pool (per ), reused across queries. base_url is NOT
# baked in (it's operator-config and could change), so each call passes the
# full URL to ``client.get``.
_http = LazyHttpClient(intent=Intent.PUBLIC_FETCH, timeout=_TIMEOUT_S)


async def aclose() -> None:
    """Drain the shared client (call from app shutdown if wired)."""
    await _http.aclose()


def _clean_result(item: Any) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    title = strip_commonmark(item.get("title"))[:_MAX_TITLE_CHARS].strip()
    content = strip_commonmark(item.get("content"))[:_MAX_CONTENT_CHARS].strip()
    url = item.get("url")
    url = url[:_MAX_URL_CHARS] if isinstance(url, str) else ""
    # Drop entries with neither a title nor a snippet — nothing to show.
    if not title and not content:
        return None
    return {"title": title, "url": url, "content": content}


def _clean_strs(values: Any, *, limit: int, cap: int) -> list[str]:
    """Whitelist a SearXNG string-array signal (corrections / suggestions /
    answers) — strings only, CommonMark-stripped + capped, bounded count."""
    out: list[str] = []
    if not isinstance(values, list):
        return out
    for v in values:
        if isinstance(v, str) and v.strip():
            cleaned = strip_commonmark(v)[:cap].strip()
            if cleaned:
                out.append(cleaned)
        if len(out) >= limit:
            break
    return out


async def web_search_bundle(
    query: str, *, base_url: str, top_n: int = DEFAULT_TOP_N,
) -> dict | None:
    """Run a free-text SearXNG search and return the richer signal bundle.

    ``GET {base_url}/search?q=<query>&format=json``. Returns a dict
    ``{"results": [{title,url,content}…], "corrections": […],
    "suggestions": […], "answers": […]}`` — all whitelisted, CommonMark
    stripped, length + count capped. Returns ``None`` on a missing host /
    network error / non-200 / unparseable body (the caller falls back).
    Never raises. Server-side; ``base_url`` is the operator's
    admin-configured, allow-listed SearXNG host. This is the single fetch
    used by BOTH the raw-results path and the LLM-summary path.
    """
    q = (query or "").strip()
    host = (base_url or "").strip().rstrip("/")
    if not q or not host:
        return None

    # SearXNG's JSON API: enable `json` in search.formats or it 403s;
    # `number_of_results` is an unreliable counter — rely on `results`.
    url = f"{host}/search?" + urlencode({"q": q, "format": "json"})
    try:
        client = await _http.get()
        resp = await client.get(url)
    except Exception as e:  # network, DNS, TLS, timeout, …
        logger.warning(
            "web_search: network error",
            extra={"error_type": type(e).__name__, "error_msg": fmt_exc(e)},
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "web_search: SearXNG returned unexpected HTTP",
            extra={"status_code": resp.status_code},
        )
        return None

    try:
        payload = resp.json()
    except Exception as e:
        logger.warning(
            "web_search: unparseable JSON",
            extra={"error_type": type(e).__name__, "error_msg": fmt_exc(e)},
        )
        return None

    if not isinstance(payload, dict):
        return None

    raw = payload.get("results")
    results: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            cleaned = _clean_result(item)
            if cleaned is not None:
                results.append(cleaned)
            if len(results) >= top_n:
                break

    return {
        "results": results,
        "corrections": _clean_strs(
            payload.get("corrections"), limit=5, cap=100),
        "suggestions": _clean_strs(
            payload.get("suggestions"), limit=8, cap=100),
        "answers": _clean_strs(payload.get("answers"), limit=3, cap=300),
    }


async def web_search(
    query: str, *, base_url: str, top_n: int = DEFAULT_TOP_N,
) -> list[dict[str, str]] | None:
    """Top-N whitelisted ``{title, url, content}`` results, or ``None`` on
    failure / ``[]`` on no results. Thin wrapper over
    :func:`web_search_bundle` (back-compat for the raw-results path)."""
    bundle = await web_search_bundle(query, base_url=base_url, top_n=top_n)
    return None if bundle is None else bundle["results"]
