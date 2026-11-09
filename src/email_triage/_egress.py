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
from dataclasses import dataclass
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


# ---------------------------------------------------------------------------
# Certificate-check modes + environment / proxy / CA bundle (operator rulings
# 2026-10-21, A3). Reverses in part punch 547 (fa8cfb80: httpx trust_env off)
# and panel B1 (01c777e4: the requests sessions' trust_env off). The well-known
# variables are honoured again: HTTPS_PROXY / HTTP_PROXY / ALL_PROXY / NO_PROXY,
# SSL_CERT_FILE / SSL_CERT_DIR, REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE. The config
# (``outbound_tls``) overrides them: ``proxy_url`` + ``no_proxy``, ``ca_bundle``
# and ``ignore_env`` (read none of them). The certificate check follows
# ``outbound_tls.cert_check`` / ``cert_enforce`` (``email_triage.tls``): off,
# validate-and-log, or validate-and-refuse. A caller that passes its own
# ``verify=`` (the CLI's ``--insecure`` and the loopback ops trigger) keeps it.
# ---------------------------------------------------------------------------

_UNSET: Any = object()


@dataclass(frozen=True)
class EgressTrust:
    """Where HTTPS egress takes its proxy and CA bundle from, resolved from
    ``outbound_tls`` over the environment. ``source`` says which."""

    trust_env: bool = True
    proxy: str | None = None
    no_proxy: str | None = None
    cafile: str | None = None
    capath: str | None = None
    source: str = "default"


def resolve_egress_trust() -> EgressTrust:
    """The proxy / CA-bundle settings for HTTPS egress. Never raises: a missing
    bundle path is logged by ``tls.client_tls_context`` and the default store
    is used."""
    import os

    from email_triage.tls import bound_config

    out = getattr(bound_config(), "outbound_tls", None)
    trust_env = not bool(getattr(out, "ignore_env", False))
    proxy = (str(getattr(out, "proxy_url", "") or "").strip() or None)
    no_proxy = (str(getattr(out, "no_proxy", "") or "").strip() or None)
    bundle = (str(getattr(out, "ca_bundle", "") or "").strip() or None)
    cafile = capath = None
    source = "config" if (proxy or bundle) else ("env" if trust_env else "ignore_env")
    if bundle:
        if os.path.isdir(bundle):
            capath = bundle
        else:
            cafile = bundle
    elif trust_env:
        # Most specific first: OpenSSL's own pair (what httpx read with
        # trust_env), then the requests / curl ones.
        cafile = (os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
                  or os.environ.get("CURL_CA_BUNDLE") or None)
        if cafile is None:
            capath = os.environ.get("SSL_CERT_DIR") or None
    return EgressTrust(trust_env=trust_env, proxy=proxy, no_proxy=no_proxy,
                       cafile=cafile, capath=capath, source=source)


def proxy_for(url: str | httpx.URL, trust: EgressTrust) -> str | None:
    """The proxy for ``url``: the configured one unless ``no_proxy`` (config,
    else the environment's NO_PROXY) bypasses it; else, when the environment is
    trusted, HTTPS_PROXY / HTTP_PROXY / ALL_PROXY per the stdlib's reading."""
    import urllib.request

    parts = urlsplit(str(url))
    host = parts.hostname or ""
    scheme = (parts.scheme or "https").lower()
    env = urllib.request.getproxies_environment() if trust.trust_env else {}
    no_proxy = trust.no_proxy if trust.no_proxy is not None else env.get("no")
    if no_proxy and urllib.request.proxy_bypass_environment(host, {"no": no_proxy}):
        return None
    if trust.proxy:
        return trust.proxy
    return env.get(scheme) or env.get("all") or None


class _ModeLegs:
    """Shared by the sync and async transports: one inner httpx transport per
    (proxy, leg), built lazily. Legs: ``verified`` / ``unverified`` (from the
    policy) or ``caller`` (the caller's own ``verify=``)."""

    def __init__(self, factory, *, intent: Intent, caller_verify: Any,
                 transport_kwargs: dict[str, Any]) -> None:
        self._factory = factory
        self._intent = intent
        self._caller_verify = caller_verify
        self._kw = transport_kwargs
        self._inner: dict[tuple, Any] = {}

    def inner(self, proxy: str | None, leg: str, trust: EgressTrust):
        from email_triage.tls import (
            current_cert_policy, guard_caller_tls, guard_verifying_context, mode_context,
        )

        key = (proxy, leg, trust.cafile, trust.capath, trust.trust_env)
        t = self._inner.get(key)
        if t is None:
            if leg == "caller":
                # The caller's own context or CA path, guarded like every leg (cycle P
                # DA P4-1): before, it reached httpx as given and skipped the punch 776
                # chain check. verify=False stays False (nothing is verified).
                verify = guard_caller_tls(self._caller_verify)
            elif leg == "verified" and not (trust.cafile or trust.capath):
                # httpx's own default store (certifi), as before, in a context that also
                # judges the verified chain against the distrusted-key list (punch 776)
                verify = guard_verifying_context(
                    httpx.create_ssl_context(trust_env=trust.trust_env))
            else:
                verify = mode_context(
                    current_cert_policy(), verified=(leg == "verified"),
                    cafile=trust.cafile, capath=trust.capath,
                )
            # The leg transport's own trust_env defaults to True, and httpx then
            # reads SSL_CERT_FILE / SSL_CERT_DIR itself whenever verify is True,
            # so ignore_env must reach it too (panel M, M-DA-6). When env is
            # honoured this keeps httpx's env reads exactly as before.
            t = self._factory(verify=verify, proxy=proxy,
                              trust_env=trust.trust_env, **self._kw)
            self._inner[key] = t
        return t

    def plan(self, request: httpx.Request):
        """(trust, proxy, policy-or-None). None policy = the caller's verify."""
        from email_triage.tls import current_cert_policy

        trust = resolve_egress_trust()
        proxy = proxy_for(request.url, trust)
        if self._caller_verify is not _UNSET:
            return trust, proxy, None
        return trust, proxy, current_cert_policy()

    def on_cert_failure(self, exc: Exception, request: httpx.Request, policy) -> None:
        from email_triage.tls import log_cert_check_failure

        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        log_cert_check_failure(host=request.url.host, port=port,
                               protocol=f"https/{self._intent.value}",
                               exc=exc, policy=policy)
        if policy.enforce:
            raise httpx.ConnectError(
                f"https certificate check failed for {request.url.host}:{port} and "
                f"certificate enforcement is on ({policy.source}.cert_enforce), so "
                f"the connection was refused: {exc}",
                request=request,
            ) from exc

    def all(self):
        return list(self._inner.values())


class _CertModeTransport(httpx.BaseTransport):
    """Sync egress transport: proxy per request, certificate mode per request
    (verifying handshake first; on a verification failure log, then refuse
    under enforce or retry on the unverified leg)."""

    def __init__(self, **kw: Any) -> None:
        self._legs = _ModeLegs(httpx.HTTPTransport, **kw)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        from email_triage.tls import cert_verify_error

        trust, proxy, policy = self._legs.plan(request)
        if policy is None:
            return self._legs.inner(proxy, "caller", trust).handle_request(request)
        if not policy.check:
            return self._legs.inner(proxy, "unverified", trust).handle_request(request)
        try:
            return self._legs.inner(proxy, "verified", trust).handle_request(request)
        except httpx.ConnectError as exc:
            if cert_verify_error(exc) is None:
                raise
            self._legs.on_cert_failure(exc, request, policy)
        return self._legs.inner(proxy, "unverified", trust).handle_request(request)

    def close(self) -> None:
        for t in self._legs.all():
            t.close()


class _AsyncCertModeTransport(httpx.AsyncBaseTransport):
    """Async counterpart of :class:`_CertModeTransport`."""

    def __init__(self, **kw: Any) -> None:
        self._legs = _ModeLegs(httpx.AsyncHTTPTransport, **kw)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        from email_triage.tls import cert_verify_error

        trust, proxy, policy = self._legs.plan(request)
        if policy is None:
            return await self._legs.inner(proxy, "caller", trust).handle_async_request(request)
        if not policy.check:
            return await self._legs.inner(proxy, "unverified", trust).handle_async_request(request)
        try:
            return await self._legs.inner(proxy, "verified", trust).handle_async_request(request)
        except httpx.ConnectError as exc:
            if cert_verify_error(exc) is None:
                raise
            self._legs.on_cert_failure(exc, request, policy)
        return await self._legs.inner(proxy, "unverified", trust).handle_async_request(request)

    async def aclose(self) -> None:
        for t in self._legs.all():
            await t.aclose()


#: httpx client kwargs that configure the transport, moved onto the inner legs.
_TRANSPORT_KWARGS = ("cert", "http1", "http2", "limits")


def _with_mode_transport(intent: Intent, client_kwargs: dict[str, Any], cls) -> None:
    """Install the mode transport unless the caller brought its own transport.
    ``trust_env`` follows ``outbound_tls.ignore_env`` (the transport resolves
    the proxy itself, so httpx's own env-proxy path is never the one used)."""
    client_kwargs["trust_env"] = resolve_egress_trust().trust_env
    if "transport" in client_kwargs or "mounts" in client_kwargs:
        return
    caller_verify = client_kwargs.pop("verify", _UNSET)
    if caller_verify is True:  # the default spelled out: the mode applies
        caller_verify = _UNSET
    tkw = {k: client_kwargs.pop(k) for k in _TRANSPORT_KWARGS if k in client_kwargs}
    client_kwargs["transport"] = cls(intent=intent, caller_verify=caller_verify,
                                     transport_kwargs=tkw)


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
    # DA-546-15 (PD-6): the funnel STATES the redirect policy rather than
    # inheriting httpx's. The value is httpx's own current default, so this
    # changes no caller's behaviour today -- it is a declaration, so a future
    # httpx default flip cannot silently start following redirects on a
    # trust-root fetch. ``setdefault`` is the right verb because a CONSTRUCTOR
    # caller that passes the kwarg explicitly keeps it (``cli.py:3488``,
    # ``False``).
    #
    # DA-548-9 -- what this does NOT do, stated because the comment used to
    # claim it in two mirrored copies: it does not "keep the two callers that
    # pass ``follow_redirects=True`` working as before", because neither of
    # those two passes it to a CONSTRUCTOR at all.
    # ``embedding_bits/__init__.py`` passes it to ``client.stream("GET", ...)``
    # and ``web/daily_health.py`` to ``c.get(url, ...)`` -- both PER REQUEST,
    # so this line never touches them and what preserves them is httpx's
    # per-request override. The OUTCOME (no caller's behaviour changes) is
    # unchanged and was verified; only the mechanism given for it was wrong.
    client_kwargs.setdefault("follow_redirects", False)
    # Operator rulings 2026-10-21 (A3), reversing punch 547's trust_env=False:
    # proxy and CA bundle come from outbound_tls over the environment, and the
    # certificate mode applies per request (see _with_mode_transport). The
    # Intent hook above still checks every request's destination, proxied or not.
    _with_mode_transport(intent, client_kwargs, _AsyncCertModeTransport)
    return httpx.AsyncClient(**client_kwargs)


def egress_client(*, intent: Intent,
                  extra_local_suffixes: Iterable[str] = (),
                  **client_kwargs: Any) -> httpx.Client:
    """Synchronous counterpart of :func:`egress_async_client` (the CLI fetch)."""
    suffixes = tuple(extra_local_suffixes)
    hook = _make_sync_request_hook(intent, extra_local_suffixes=suffixes)
    client_kwargs["event_hooks"] = _merged_event_hooks(hook, client_kwargs)
    # DA-546-15 (PD-6): the funnel STATES the redirect policy rather than
    # inheriting httpx's. The value is httpx's own current default, so this
    # changes no caller's behaviour today -- it is a declaration, so a future
    # httpx default flip cannot silently start following redirects on a
    # trust-root fetch. ``setdefault`` is the right verb because a CONSTRUCTOR
    # caller that passes the kwarg explicitly keeps it (``cli.py:3488``,
    # ``False``).
    #
    # DA-548-9 -- what this does NOT do, stated because the comment used to
    # claim it in two mirrored copies: it does not "keep the two callers that
    # pass ``follow_redirects=True`` working as before", because neither of
    # those two passes it to a CONSTRUCTOR at all.
    # ``embedding_bits/__init__.py`` passes it to ``client.stream("GET", ...)``
    # and ``web/daily_health.py`` to ``c.get(url, ...)`` -- both PER REQUEST,
    # so this line never touches them and what preserves them is httpx's
    # per-request override. The OUTCOME (no caller's behaviour changes) is
    # unchanged and was verified; only the mechanism given for it was wrong.
    client_kwargs.setdefault("follow_redirects", False)
    _with_mode_transport(intent, client_kwargs, _CertModeTransport)  # see egress_async_client
    return httpx.Client(**client_kwargs)


def egress_requests_session():
    """The ``requests.Session`` for a library that only accepts a requests-style
    client (msal's ``http_client`` on the Office 365 OAuth token path). Built
    through :func:`configure_requests_session`. NOT enforced here: the Intent
    policy hook (requests has no httpx event hooks); msal's destination is the
    fixed ``login.microsoftonline.com/<tenant>`` authority, and the callers are
    pinned to a declared set (``tests/test_requests_session_trust_env_pin.py``).
    msal skips its own ``HTTPAdapter(max_retries=1)`` when handed a client, so
    the single connect retry is kept here (panel B1 round 2, db R1 / hipaa OF-3).
    """
    import requests

    return configure_requests_session(requests.Session(), max_retries=1)


def configure_requests_session(session, *, max_retries: int = 0):
    """Apply the A3 egress settings to a ``requests.Session`` (ours, or acme's
    ``ClientNetwork.session``): ``trust_env`` follows ``outbound_tls.ignore_env``
    (requests then reads HTTPS_PROXY / HTTP_PROXY / NO_PROXY and
    REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE itself); a configured ``proxy_url`` /
    ``no_proxy`` / ``ca_bundle`` overrides them; and a certificate-mode adapter
    on both schemes applies ``outbound_tls.cert_check`` / ``cert_enforce``."""
    session.trust_env = resolve_egress_trust().trust_env
    adapter = _cert_mode_adapter(max_retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def requests_overrides(url: str, verify: Any, proxies: Any) -> tuple[Any, Any]:
    """The configured proxy / CA bundle over what requests merged from the
    environment. requests lets a request-level (environment) proxy or
    REQUESTS_CA_BUNDLE beat a session-level setting, so the config override is
    applied here, per request, in the adapter."""
    trust = resolve_egress_trust()
    if trust.proxy:
        p = proxy_for(url, trust)
        proxies = {"http": p, "https": p} if p else {}
    elif not trust.trust_env:
        proxies = {}
    out = getattr(_bound_config_of_tls(), "outbound_tls", None)
    bundle = str(getattr(out, "ca_bundle", "") or "").strip()
    if bundle and verify is not False:
        verify = bundle
    return verify, proxies


def _bound_config_of_tls() -> Any:
    from email_triage.tls import bound_config
    return bound_config()


def _cert_mode_adapter(max_retries: int):
    from requests.adapters import HTTPAdapter
    from requests.exceptions import SSLError

    class _CertModeAdapter(HTTPAdapter):
        """``outbound_tls.cert_check`` / ``cert_enforce`` for requests: check
        off sends unverified; check on sends verified and, on a certificate
        failure, logs, then refuses under enforce or resends unverified.

        Every VERIFIED request also carries a context that judges the verified chain
        against the distrusted-key list (punch 776 (a)), one context per ``verify``
        value so a CA bundle's certificates never widen another bundle's trust. An
        unverified request (``verify=False``) is given urllib3's own context."""

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            from email_triage.tls import guard_verifying_context

            host_params, pool_kwargs = super().build_connection_pool_key_attributes(
                request, verify, cert)
            if verify is not False:
                contexts = self.__dict__.setdefault("_guarded_contexts", {})
                ctx = contexts.get(verify)
                if ctx is None:
                    from urllib3.util.ssl_ import create_urllib3_context

                    ctx = contexts.setdefault(
                        verify, guard_verifying_context(create_urllib3_context()))
                pool_kwargs["ssl_context"] = ctx
            return host_params, pool_kwargs

        def send(self, request, stream=False, timeout=None, verify=True,
                 cert=None, proxies=None):
            from urllib.parse import urlsplit as _split

            from email_triage.tls import (
                cert_verify_error, current_cert_policy, log_cert_check_failure,
            )

            verify, proxies = requests_overrides(request.url, verify, proxies)
            policy = current_cert_policy()
            unverified = (not policy.check) or verify is False
            if not unverified:
                try:
                    return super().send(request, stream=stream, timeout=timeout,
                                        verify=verify, cert=cert, proxies=proxies)
                except SSLError as exc:
                    if cert_verify_error(exc) is None:
                        raise
                    parts = _split(request.url)
                    port = parts.port or (443 if parts.scheme == "https" else 80)
                    log_cert_check_failure(host=parts.hostname or "", port=port,
                                           protocol="https/requests", exc=exc,
                                           policy=policy)
                    if policy.enforce:
                        raise SSLError(
                            f"https certificate check failed for {parts.hostname}:{port} "
                            f"and certificate enforcement is on "
                            f"({policy.source}.cert_enforce), so the connection was "
                            f"refused: {exc}", request=request,
                        ) from exc
            # Operator certificate mode: cert_check off, or the non-enforce
            # fallback after a logged failure (email_triage.tls.CertPolicy).
            return super().send(request, stream=stream, timeout=timeout,
                                verify=False, cert=cert, proxies=proxies)

    return _CertModeAdapter(max_retries=max_retries)


__all__ = [
    "Intent", "EgressBlocked", "egress_async_client", "egress_client",
    "egress_requests_session", "configure_requests_session", "resolve_egress_trust",
]
