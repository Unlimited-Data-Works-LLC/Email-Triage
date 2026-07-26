"""Outbound-egress chokepoint SSOT (divergence-census run11 §2 — "Outbound
egress funnel").

Before this, every outbound HTTP call constructed its own ``httpx.AsyncClient``
with no central locality / allowlist enforcement — ~10 construction sites across
the Gmail / O365 / Calendar providers + the CLI. The weakest variant: the **Gmail**
OAuth token-refresh POSTs ship ``refresh_token`` + ``client_secret`` to a URL with
NO check that the URL is actually Google's token endpoint. A single misdirected
(or, in a future bug, attacker-influenced) URL would exfiltrate the highest-trust
secret in the system.

SCOPE HONESTY (per the SME panel): the OAuth-secret chokepoint covers the **Gmail**
provider's httpx refresh POSTs (the raw ``httpx.AsyncClient`` sites this funnel
replaced). **O365** hands its ``client_secret`` to MSAL, which makes its own HTTP
calls this request hook cannot see — so O365's token egress is NOT funnelled here.
That is not a regression (MSAL was never a raw httpx client we owned); it is a
boundary of what an httpx-level funnel can reach, stated plainly so the control's
coverage is not overclaimed.

This module is the ONE place an egress client is built. Each call site declares
its :class:`Intent`; the returned client carries an httpx ``request`` event hook
that, on EVERY request, classifies the destination and **fails closed** per the
intent's policy:

* ``OAUTH_TOKEN`` — refresh_token/client_secret POSTs may ONLY reach the
  enumerated Google / Microsoft token hosts. Anything else raises
  :class:`EgressBlocked` (the secret never leaves). Live coverage = Gmail's
  httpx refresh POSTs; O365 is MSAL-owned (see SCOPE HONESTY above).
* ``PROVIDER_API`` — Gmail / Graph / Calendar data APIs: the provider host
  allowlist (token hosts included, since providers refresh inline).
* ``LOCAL_ONLY`` — must be a local destination (loopback / RFC1918 / .local).
* ``PUBLIC_FETCH`` / ``LLM_PHI`` / ``WEBHOOK`` — SSRF-guard-only pass-through.
  The funnel does NOT make the locality / PHI / external decision for these,
  because that decision is per-request and already lives at an UPSTREAM SSOT that
  the shared egress *client* cannot see: PUBLIC_FETCH the operator owns the URL
  (SearXNG on the LAN, clinicaltrials.gov on the net); LLM_PHI the per-MESSAGE
  PHI gate is ``classify.baa_gate`` (a HIPAA message reaches the classifier only
  if local-or-BAA'd — but the same client also carries non-HIPAA mail, so
  re-gating here would wrongly block legitimate non-HIPAA external-LLM traffic);
  WEBHOOK the per-TARGET gate is ``web.events.is_local_webhook_url`` +
  ``config.webhooks_allow_external`` at the dispatcher. All three are still
  SSRF-guarded (no non-http(s), no link-local / cloud-metadata IP).

Reuses :func:`email_triage._netloc.is_local_destination` (locality) — no new
classifier. The count-agnostic pin ``tests/test_egress_funnel_pin.py`` bans any
``httpx.AsyncClient(`` / ``httpx.Client(`` / ``smtplib.SMTP(`` construction
outside this module (+ ``_http_client.py`` holder + ``web/smtp_send.py``).
"""
from __future__ import annotations

import enum
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx

from ._netloc import is_local_destination, is_ssrf_blocked_ip


class Intent(enum.Enum):
    """Why an egress client is talking out — selects the fail-closed policy."""

    OAUTH_TOKEN = "oauth_token"      # refresh_token/client_secret POSTs
    PROVIDER_API = "provider_api"    # Gmail / Graph / Calendar data APIs
    WEBHOOK = "webhook"              # operator-configured webhook targets
    LLM_PHI = "llm_phi"              # PHI -> classifier / embedding backend
    LOCAL_ONLY = "local_only"        # must be a local destination
    PUBLIC_FETCH = "public_fetch"    # operator-configured public endpoints


class EgressBlocked(RuntimeError):
    """Raised (fail-closed) when a request's destination violates its Intent's
    egress policy — e.g. an OAuth-secret POST aimed anywhere but the enumerated
    token hosts, or a LOCAL_ONLY request to an internet host."""


# Where OAuth refresh_token/client_secret POSTs may go — Google + Microsoft
# token endpoints. Mirrors providers.gmail_api.OAUTH_TOKEN_URL
# (oauth2.googleapis.com) + providers.office365 authority (login.microsoftonline.com).
# Hardcoded (not imported) on purpose: the providers import THIS module, so an
# import back into them would cycle. test_egress_funnel_pin asserts these stay a
# superset of the real provider host constants, so the copy cannot silently drift.
_OAUTH_TOKEN_HOSTS = frozenset({
    "oauth2.googleapis.com",            # the live Gmail token-POST host (OAUTH_TOKEN_URL)
    "accounts.google.com",              # legacy Google token endpoint + JWT issuer — defence-in-depth, not used by our POSTs today
    "login.microsoftonline.com",        # O365 authority (MSAL-owned today; covered for a future httpx path)
})
# Provider data-API hosts (token hosts included — providers refresh inline).
# Mirrors GMAIL_BASE / CAL_BASE / GRAPH_BASE.
_PROVIDER_API_HOSTS = _OAUTH_TOKEN_HOSTS | frozenset({
    "gmail.googleapis.com",
    "www.googleapis.com",
    "graph.microsoft.com",
})


def _host(url: str | httpx.URL) -> str:
    return (urlsplit(str(url)).hostname or "").lower()


def _ssrf_guard(s: str, host: str) -> None:
    """Reject the SSRF / cloud-metadata shapes that even an operator-owned or
    upstream-gated URL must never take: a non-http(s) scheme, or a link-local /
    metadata / reserved / multicast IP literal (``169.254.169.254`` & friends, via
    the ``_netloc.is_ssrf_blocked_ip`` SSOT — NO ipaddress attribute here, the
    classification lives in the locality SSOT). Shared by the pass-through intents
    (PUBLIC_FETCH / LLM_PHI / WEBHOOK); RFC1918 LAN literals (SearXNG, local Ollama)
    are intentionally NOT blocked."""
    scheme = urlsplit(s).scheme.lower()
    if scheme not in ("http", "https"):
        raise EgressBlocked(f"egress scheme {scheme!r} is not http(s).")
    if is_ssrf_blocked_ip(host):
        raise EgressBlocked(
            f"egress to link-local/reserved IP {host!r} refused "
            "(SSRF / cloud-metadata guard)."
        )


def _enforce(intent: Intent, url: str | httpx.URL, *,
             extra_local_suffixes: tuple[str, ...] = ()) -> None:
    """Fail closed if ``url`` violates ``intent``'s egress policy. Pure + sync so
    both the async and sync client hooks share it (and it's unit-testable without
    a live request). Two enforcement shapes:

    * HARD ALLOWLIST / LOCALITY (the funnel IS the SSOT — no upstream gate
      existed): OAUTH_TOKEN, PROVIDER_API, LOCAL_ONLY.
    * SSRF-GUARD-ONLY pass-through (the per-message / per-target decision lives at
      an UPSTREAM SSOT, and the egress *client* is shared across requests so it
      cannot make that decision): PUBLIC_FETCH (operator owns the URL), LLM_PHI
      (the per-message PHI gate is ``classify.baa_gate`` — a HIPAA message reaches
      the classifier only if local-or-BAA'd; the client also carries non-HIPAA
      mail, so re-gating here would wrongly block legitimate non-HIPAA external-LLM
      traffic), WEBHOOK (the per-target gate is ``web.events.is_local_webhook_url``
      + ``config.webhooks_allow_external`` at the dispatcher). These are still
      SSRF-guarded so an operator/config URL can't become a metadata probe.
    """
    s = str(url)
    host = _host(url)

    if intent is Intent.OAUTH_TOKEN:
        if host not in _OAUTH_TOKEN_HOSTS:
            raise EgressBlocked(
                f"OAUTH_TOKEN egress to {host!r} is not an enumerated token host "
                f"{sorted(_OAUTH_TOKEN_HOSTS)} — refusing to send refresh_token/"
                "client_secret off the trusted endpoints."
            )
    elif intent is Intent.PROVIDER_API:
        if not (is_local_destination(s, extra_suffixes=extra_local_suffixes)
                or host in _PROVIDER_API_HOSTS):
            raise EgressBlocked(
                f"PROVIDER_API egress to {host!r} is not an allowed provider host "
                f"{sorted(_PROVIDER_API_HOSTS)}."
            )
    elif intent is Intent.LOCAL_ONLY:
        if not is_local_destination(s, extra_suffixes=extra_local_suffixes):
            raise EgressBlocked(
                f"LOCAL_ONLY egress to {host!r} is not a local destination."
            )
    elif intent in (Intent.PUBLIC_FETCH, Intent.LLM_PHI, Intent.WEBHOOK):
        _ssrf_guard(s, host)


def _make_request_hook(intent: Intent, *, extra_local_suffixes: tuple[str, ...]):
    async def _async_hook(request: httpx.Request) -> None:
        _enforce(intent, request.url, extra_local_suffixes=extra_local_suffixes)
    return _async_hook


def _make_sync_request_hook(intent: Intent, *, extra_local_suffixes: tuple[str, ...]):
    def _sync_hook(request: httpx.Request) -> None:
        _enforce(intent, request.url, extra_local_suffixes=extra_local_suffixes)
    return _sync_hook


def _merged_event_hooks(hook, kwargs: dict[str, Any]) -> dict[str, list]:
    existing = dict(kwargs.pop("event_hooks", {}) or {})
    req = list(existing.get("request", []))
    req.insert(0, hook)  # policy hook runs FIRST — before any caller hook.
    existing["request"] = req
    return existing


def egress_async_client(*, intent: Intent,
                        extra_local_suffixes: Iterable[str] = (),
                        **client_kwargs: Any) -> httpx.AsyncClient:
    """The ONE constructor for an outbound :class:`httpx.AsyncClient`. Every
    request through it is policy-checked per ``intent`` (fail-closed). Remaining
    kwargs (``base_url``, ``timeout``, ``headers``, …) pass through to httpx.
    ``extra_local_suffixes`` widens what counts as a local destination for the
    locality intents (sourced from ``config.tls.local_url_suffixes``)."""
    suffixes = tuple(extra_local_suffixes)
    hook = _make_request_hook(intent, extra_local_suffixes=suffixes)
    client_kwargs["event_hooks"] = _merged_event_hooks(hook, client_kwargs)
    return httpx.AsyncClient(**client_kwargs)


def egress_client(*, intent: Intent,
                  extra_local_suffixes: Iterable[str] = (),
                  **client_kwargs: Any) -> httpx.Client:
    """Synchronous counterpart of :func:`egress_async_client` (the CLI fetch)."""
    suffixes = tuple(extra_local_suffixes)
    hook = _make_sync_request_hook(intent, extra_local_suffixes=suffixes)
    client_kwargs["event_hooks"] = _merged_event_hooks(hook, client_kwargs)
    return httpx.Client(**client_kwargs)


__all__ = [
    "Intent", "EgressBlocked", "egress_async_client", "egress_client",
]
