""" — ClinicalTrials.gov NCT resolver (Internet-Search NCT path).

Implements the design's §3 "Internet Search button — NCT path" from
``internal documentation``:

* Detect a registry ID matching ``^[Nn][Cc][Tt]\\d{8}$`` (normalise
  case + whitespace first).
* Fetch the public study record from the **v2** ClinicalTrials.gov API
  (``GET https://clinicaltrials.gov/api/v2/studies/{nctId}?format=json``)
  — no API key, no auth (v1 retired June 2024).
* Flatten **only** a fixed whitelist of fields into a small, flat dict
  that the topic-detail router renders **as data, not instructions**.
* Cache by NCT id so a repeated resolve of the same study does not hit
  the network twice.

Privacy / HIPAA posture
=======================

This egress is the **same class** as the existing embedding-bits
install fetch (a user-initiated, on-demand pull of a *public* artifact)
— see the design's egress note. Two properties keep it inside the
no-PHI-in-the-box guardrail:

* **Server-side only.** The fetch runs in the install process (the
  topic-detail ``search-details`` route awaits this resolver). The
  browser never talks to clinicaltrials.gov directly.
* **Outbound payload is a public registry ID, nothing else.** The
  request carries the NCT id (a public identifier printed on trial
  letterhead) — no mailbox content, no PHI, no operator free-text.
* **Whitelist-only on the way back in.** Only the eight fields below
  are read out of the (large) response. Raw ``eligibilityModule``,
  ``contactsLocationsModule`` (site addresses / investigator names),
  and every other module are never touched — so a future API addition
  cannot silently leak a PII-bearing field into the box.

This is a NEW outbound destination (``clinicaltrials.gov``). It needs a
``project_no_external_data_flow`` inventory row and a §164.316 register
note — those are Stage-4 / register tasks, flagged to the lead, **not**
added here.

The whitelist (design §3 → v2 API paths)
========================================

==================  ===================================================
Output key          v2 API source path (under ``protocolSection``)
==================  ===================================================
``nct_id``          (the normalised request id, echoed back)
``official_title``  ``identificationModule.officialTitle``
``brief_summary``   ``descriptionModule.briefSummary``
``conditions``      ``conditionsModule.conditions`` (list[str])
``interventions``   ``armsInterventionsModule.interventions`` →
                    each ``name`` (list[str])
``phase``           ``designModule.phases`` (list[str])
``status``          ``statusModule.overallStatus``
``lead_sponsor``    ``sponsorCollaboratorsModule.leadSponsor.name``
==================  ===================================================

All free-text fields have CommonMark stripped (the registry stores some
summaries with light markdown). The resolver returns ``None`` — never
raises — on an invalid id, a 404 / non-200, a network error, or a parse
failure; the router renders the "no public study found" copy.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage._http_client import Intent, LazyHttpClient

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger("email_triage.actions.clinicaltrials")  # N-196b R21_4

# ── Constants ──────────────────────────────────────────────────────────

#: v2 only — v1 retired June 2024. ``{nct_id}`` is interpolated.
_API_URL = "https://clinicaltrials.gov/api/v2/studies/{nct_id}?format=json"

#: NCT id shape: literal NCT (any case) + exactly 8 digits.
_NCT_RE = re.compile(r"^NCT\d{8}$")

#: Be conservative — the registry is usually fast, but this is a
#: user-initiated, blocking-on-the-fragment call. A short cap keeps the
#: HTMX swap from hanging if the registry is slow/down (→ returns None →
#: "no public study found").
_TIMEOUT_S = 10.0


def normalize_nct(raw: str | None) -> str | None:
    """Normalise an operator-typed NCT id, or ``None`` if it isn't one.

    Strips surrounding whitespace and any internal whitespace (operators
    paste ``NCT 0000 0419`` from a PDF), upper-cases, and validates the
    ``NCT`` + 8-digit shape. Returns the canonical ``NCTdddddddd`` form
    on success, ``None`` on anything that isn't a well-formed id.
    """
    if not isinstance(raw, str):
        return None
    # Remove ALL whitespace (leading/trailing + internal), then upcase.
    candidate = re.sub(r"\s+", "", raw).upper()
    if _NCT_RE.match(candidate):
        return candidate
    return None


# ── CommonMark stripping ───────────────────────────────────────────────
#
# The registry summaries are mostly plain text but occasionally carry
# light markdown (``**bold**``, ``[text](url)``, ``# heading``, list
# bullets). There is no markdown library in the dependency set, and
# adding one to strip a handful of summary fields would be over-built
# (and a new dep). A focused regex stripper covers the CommonMark
# constructs the registry actually emits. It only ever *removes*
# syntax — it never executes or interprets anything — and the result is
# rendered as data, so a missed construct degrades to a stray ``*``,
# not an injection.

_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")        # [text](url) -> text
_MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")      # ![alt](url) -> alt
_MD_EMPHASIS_RE = re.compile(r"(\*\*|__|\*|_|~~)")        # **, __, *, _, ~~
_MD_CODE_RE = re.compile(r"`+")                            # ``code`` / `code`
_MD_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*", re.MULTILINE)   # # heading
_MD_BLOCKQUOTE_RE = re.compile(r"^\s{0,3}>\s?", re.MULTILINE)     # > quote
_MD_BULLET_RE = re.compile(r"^\s{0,3}([*+-]|\d+\.)\s+", re.MULTILINE)  # list
_MD_HR_RE = re.compile(r"^\s{0,3}([-*_])\s*(?:\1\s*){2,}$", re.MULTILINE)  # ---


def strip_commonmark(text: Any) -> str:
    """Strip light CommonMark syntax, returning plain text.

    Non-string input (``None``, missing field) collapses to ``""`` so
    callers get a uniform string. Only removes syntax — never runs it.
    """
    if not isinstance(text, str) or not text:
        return ""
    out = text
    out = _MD_IMAGE_RE.sub(r"\1", out)
    out = _MD_LINK_RE.sub(r"\1", out)
    out = _MD_HR_RE.sub("", out)
    out = _MD_HEADING_RE.sub("", out)
    out = _MD_BLOCKQUOTE_RE.sub("", out)
    out = _MD_BULLET_RE.sub("", out)
    out = _MD_EMPHASIS_RE.sub("", out)
    out = _MD_CODE_RE.sub("", out)
    # Collapse the whitespace the strips can leave behind, but keep it a
    # single clean line of text (the field is rendered in a compact UI).
    out = re.sub(r"[ \t]+", " ", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


# ── Module-level pieces: HTTP client + cache ──────────────────────────
#
# One long-lived async client for the whole process (the  pattern).
# Resolver calls are infrequent (operator clicks a button), but reusing
# the pooled client matches every other HTTP call site and avoids a
# per-call TLS handshake.
_http = LazyHttpClient(intent=Intent.PUBLIC_FETCH, timeout=_TIMEOUT_S)

#: In-memory cache: normalised nct_id -> resolved whitelist dict.
#: MVP scope (per the build brief): a process-local dict is fine. A
#: study record is immutable enough over a session that a re-resolve
#: returning the cached object (same identity) is correct, and lets the
#: cache test assert "no second fetch".
_cache: dict[str, dict[str, Any]] = {}


def _flatten_whitelist(nct_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Pull ONLY the whitelisted fields out of a v2 study payload.

    Reads each field defensively (the registry omits optional modules on
    some records) and strips CommonMark from the free-text ones. Never
    touches ``eligibilityModule`` / ``contactsLocationsModule`` / any
    other module — the whitelist is the privacy boundary.
    """
    protocol = payload.get("protocolSection") or {}

    ident = protocol.get("identificationModule") or {}
    desc = protocol.get("descriptionModule") or {}
    cond_mod = protocol.get("conditionsModule") or {}
    arms_mod = protocol.get("armsInterventionsModule") or {}
    design_mod = protocol.get("designModule") or {}
    status_mod = protocol.get("statusModule") or {}
    sponsor_mod = protocol.get("sponsorCollaboratorsModule") or {}

    # conditions: list[str]
    conditions = [
        c for c in (cond_mod.get("conditions") or []) if isinstance(c, str)
    ]

    # interventions: list of objects -> keep the human-readable name only
    # (drop type/description/other-names — name is what a reader needs,
    # and it keeps the whitelist tight).
    interventions: list[str] = []
    for iv in arms_mod.get("interventions") or []:
        if isinstance(iv, dict):
            name = iv.get("name")
            if isinstance(name, str) and name.strip():
                interventions.append(name.strip())

    # phases: list[str]
    phase = [p for p in (design_mod.get("phases") or []) if isinstance(p, str)]

    lead = sponsor_mod.get("leadSponsor") or {}
    lead_sponsor = lead.get("name") if isinstance(lead, dict) else None

    return {
        "nct_id": nct_id,
        "official_title": strip_commonmark(ident.get("officialTitle")),
        "brief_summary": strip_commonmark(desc.get("briefSummary")),
        "conditions": conditions,
        "interventions": interventions,
        "phase": phase,
        "status": status_mod.get("overallStatus") or "",
        "lead_sponsor": lead_sponsor or "",
    }


async def resolve_nct(nct_id: str) -> dict[str, Any] | None:
    """Resolve a public ClinicalTrials.gov study by NCT id.

    Returns a flat dict of the eight whitelisted fields on success, or
    ``None`` on an invalid id, a 404 / non-200 response, a network
    error, or a parse failure. **Never raises** — the topic-detail
    router treats ``None`` as "no public study found" and keeps the
    operator's Details text untouched.

    The fetch is **server-side** (runs in the install process) and the
    result is **cached** by normalised id, so a repeated resolve of the
    same study returns the same object without a second network call.
    """
    canonical = normalize_nct(nct_id)
    if canonical is None:
        logger.info(
            "resolve_nct: invalid NCT id — returning None",
            extra={"external_id": nct_id},
        )
        return None

    # Cache hit -> return the SAME object (the cache test relies on this
    # and on the absence of a second fetch).
    cached = _cache.get(canonical)
    if cached is not None:
        logger.debug("resolve_nct: cache hit", extra={"external_id": canonical})
        return cached

    url = _API_URL.format(nct_id=canonical)
    try:
        client = await _http.get()
        resp = await client.get(url)
    except Exception as e:  # network error, DNS, TLS, timeout, …
        logger.warning(
            "resolve_nct: network error fetching study",
            extra={
                "external_id": canonical,
                "error_type": type(e).__name__,
                "error_msg": fmt_exc(e),
            },
        )
        return None

    if resp.status_code == 404:
        logger.info(
            "resolve_nct: study not found (404)",
            extra={"external_id": canonical},
        )
        return None
    if resp.status_code != 200:
        logger.warning(
            "resolve_nct: unexpected HTTP status",
            extra={
                "external_id": canonical,
                "status_code": resp.status_code,
            },
        )
        return None

    try:
        payload = resp.json()
    except Exception as e:
        logger.warning(
            "resolve_nct: unparseable JSON",
            extra={
                "external_id": canonical,
                "error_type": type(e).__name__,
                "error_msg": fmt_exc(e),
            },
        )
        return None

    if not isinstance(payload, dict):
        logger.warning(
            "resolve_nct: non-object JSON",
            extra={"external_id": canonical},
        )
        return None

    try:
        result = _flatten_whitelist(canonical, payload)
    except Exception as e:
        logger.warning(
            "resolve_nct: flatten/parse failure",
            extra={
                "external_id": canonical,
                "error_type": type(e).__name__,
                "error_msg": fmt_exc(e),
            },
        )
        return None

    _cache[canonical] = result
    logger.info("resolve_nct: resolved", extra={"external_id": canonical})
    return result


def _clear_cache() -> None:
    """Drop the in-memory cache. Test seam (and a future admin hook)."""
    _cache.clear()


async def aclose() -> None:
    """Drain the long-lived HTTP client. Idempotent (shutdown hook)."""
    await _http.aclose()


__all__ = [
    "resolve_nct",
    "normalize_nct",
    "strip_commonmark",
    "aclose",
]
