"""Count-agnostic interprocedural pin for the outbound-egress funnel
(divergence-census run11 §2; SSOT = ``src/email_triage/_egress.py``).

Every outbound HTTP/SMTP client MUST be constructed through the egress funnel
(``egress_async_client`` / ``egress_client`` in ``_egress.py``, or the SMTP
chokepoint ``web/smtp_send.py``) so each call site declares an :class:`Intent`
and the per-intent fail-closed policy runs. The motivating weakness: the OAuth
token-refresh POSTs shipped ``refresh_token`` + ``client_secret`` on a raw
``httpx.AsyncClient`` with NO allowlist — a misdirected URL would exfiltrate the
system's highest-trust secret.

This pin is a PROPERTY over EVERY source file (``_pin_harness.walk_src`` —
``ast`` over all of ``src/email_triage``), never ``len(sites) == N``. It is
MECHANISM-AGNOSTIC (census run12 #3 — the old httpx/smtplib-only net was blind to
the rest; widened again census run17 #5 for the 3 below): it bans any raw
egress-client construction — ``httpx.AsyncClient`` / ``httpx.Client`` AND the
module-level one-shots (``httpx.get`` / ``httpx.post`` / ``httpx.stream`` /
``httpx.request`` / …) / ``smtplib.SMTP(_SSL)`` / ``imaplib.IMAP4(_SSL)`` /
``aioimaplib.IMAP4(_SSL)`` / ``requests.*`` / ``aiohttp.ClientSession`` /
``urllib.request.urlopen`` / ``http.client.HTTP(S)Connection`` /
``dns.query.udp/tcp/...`` (dnspython DNS-protocol egress) / a network
``subprocess`` (``subprocess.run([curl/wget/pip/tailscale, ...])`` — inline
literal command only) — outside:

* ``_ALLOWED`` — the funnel SSOTs themselves (``_egress.py``, ``web/smtp_send.py``);
* ``_PENDING_MIGRATION`` — a DOCUMENTED, SHRINKING allow-list of sites not yet
  routed through the funnel, each with the reason + intended Intent. The
  companion ``test_pending_migration_entries_are_live`` FAILS if a pending entry
  no longer constructs a raw client — so the list cannot rot: migrating a site
  forces its removal here, shrinking the debt toward ∅ (drained at run17 #5);
* ``_ACKNOWLEDGED_BOUNDARY`` — sites that egress by a mechanism the funnel CANNOT
  reach by design (raw DNS, a network subprocess, a library-internal client) and
  will NOT migrate, each with a non-PHI + why-unfunnelable justification. Also
  liveness-checked (``test_acknowledged_boundary_entries_are_live``) so a stale
  whole-file exemption can't mask a future raw client.

Interprocedural by construction: the pin keys on the construction SITE (the
``httpx.AsyncClient(...)`` expression), wherever it sits — a holder class, a
factory method, a dispatcher — not on who calls it. It also catches a future
``from httpx import AsyncClient`` bare-alias evasion (per-module import scan).
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    parse_source,
    relpath,
    walk_src,
)

# The egress-client constructors, keyed by the single-Name module they live on.
# Mechanism-agnostic (census run12 #3): not just httpx/smtplib — a raw IMAP
# (imaplib/aioimaplib), requests, or aiohttp client construction is egress too,
# and was invisible to the old httpx/smtplib-only net.
_TARGETS: dict[str, frozenset[str]] = {
    # httpx: the Client/AsyncClient constructors AND the module-level one-shot
    # helpers (census run17 #5). ``httpx.get(url)`` / ``httpx.post(...)`` /
    # ``httpx.stream(...)`` / ``httpx.request(...)`` each open a throwaway client
    # for the call — egress that bypasses the funnel exactly as a raw ``Client()``
    # would, and was invisible to the AsyncClient/Client-only net.
    "httpx": frozenset({
        "AsyncClient", "Client",
        "get", "post", "put", "patch", "delete", "head", "options",
        "request", "stream",
    }),
    "smtplib": frozenset({"SMTP", "SMTP_SSL"}),
    "imaplib": frozenset({"IMAP4", "IMAP4_SSL"}),
    "aioimaplib": frozenset({"IMAP4", "IMAP4_SSL"}),
    "requests": frozenset({"Session", "request", "get", "post", "put", "patch", "delete"}),
    "aiohttp": frozenset({"ClientSession"}),
    # N-188 R20_18: MSAL + ACME clients — library-internal HTTP egress that
    # can't route through the httpx funnel. Detection lets a NEW MSAL/ACME
    # site fail the pin (forcing an explicit _ACKNOWLEDGED_BOUNDARY entry
    # w/ justification) rather than escape silently.
    "msal": frozenset({"ConfidentialClientApplication", "PublicClientApplication"}),
    "acme_client": frozenset({"ClientNetwork", "ClientV2"}),
}

# Dotted-module constructors — the receiver is ``mod1.mod2`` (an Attribute, not a
# Name), so they need the 2-level match in :func:`_find_constructions`.
_DOTTED_TARGETS: dict[tuple[str, str], frozenset[str]] = {
    ("urllib", "request"): frozenset({"urlopen", "Request"}),
    ("http", "client"): frozenset({"HTTPConnection", "HTTPSConnection"}),
    # dnspython low-level egress (census run17 #5): ``dns.query.udp/tcp/tls/...``
    # send a DNS message straight over UDP/TCP/TLS — real network egress that
    # CANNOT route through an httpx funnel (it isn't HTTP). ``web/acme_renewer.py``
    # uses it for RFC2136 dynamic-DNS updates (an ACKNOWLEDGED_BOUNDARY below).
    ("dns", "query"): frozenset(
        {"udp", "tcp", "tls", "udp_with_fallback", "https", "xfr"}
    ),
}

# Network subprocess egress (census run17 #5): a subprocess that shells out to a
# network tool (tailscale cert provisioning, a pip/curl/wget fetch) egresses
# outside any in-process funnel. CONSERVATIVE by design — flagged ONLY when the
# subprocess's FIRST argv element is a STRING LITERAL we can read that names one
# of these tools. A variable argv (``subprocess.run(cmd, ...)``) or a non-literal
# argv[0] (``[sys.executable, "-m", "pip", ...]`` — pip is argv[2], not argv[0])
# is NOT flagged: we never guess through a variable. The two real in-tree network
# subprocesses (``tls.py`` tailscale-cert, ``embedding_bits`` pip-install) BOTH
# build a ``cmd`` list bound to a variable, so neither is flagged today — these
# teeth guard a FUTURE inline-literal network subprocess (and the two variable
# sites are documented residuals in the run17 #5 report, not silent passes).
_SUBPROCESS_FNS: frozenset[str] = frozenset(
    {"run", "Popen", "call", "check_output", "check_call"}
)
_NETWORK_COMMANDS: frozenset[str] = frozenset(
    {"tailscale", "curl", "wget", "pip", "pip3"}
)

# The funnel SSOTs — the ONLY places a raw client may be constructed.
_ALLOWED: frozenset[str] = frozenset({
    "_egress.py",                          # the egress funnel — egress_async_client / egress_client
    "web/smtp_send.py",                    # the SMTP chokepoint SSOT (its own funnel)
    "providers/imap_fetch_transport.py",   # the IMAP fetch-transport SSOT (imap_connect / aioimaplib_connect)
})

# Sites not yet routed through the funnel — DOCUMENTED + SHRINKING. Each entry:
# relpath -> why-not-yet. Removing an entry is REQUIRED the moment its site is
# migrated (test_pending_migration_entries_are_live enforces). DRAINED TO ∅: the
# LazyHttpClient holder (_http_client.py) now builds via egress_async_client so
# all ~12 of its callers funnel through one seam, and the 2 cli.py fetches use
# egress_async_client / egress_client. A new raw client anywhere now FAILS the pin.
# NB this pin guarantees every client is CONSTRUCTED THROUGH the funnel — it does
# NOT mean every egress is hard-gated: the funnel's policy is per-intent. Only
# OAUTH_TOKEN/PROVIDER_API/LOCAL_ONLY are hard allowlist/locality gates; PUBLIC_FETCH
# /LLM_PHI/WEBHOOK are SSRF-guard-only and DEFER their locality/PHI/external decision
# to upstream SSOTs (classify.baa_gate, the webhook dispatcher). See _egress._enforce.
# Mechanism-agnostic widening (census run12 #3): the non-httpx/smtplib egress
# sites, ALL verified NO-LIVE-LEAK (loopback / non-PHI-external / operator-trusted
# IMAP) — the funnel is mechanism-agnostic-blind, not that PHI leaks today. These
# are the SHRINKING migration list (test_pending_migration_entries_are_live keeps
# it honest); the IMAP-transport SSOT build + urllib→egress_client are the tracked
# convergence (no hole is open while they wait).
_PENDING_MIGRATION: dict[str, str] = {
    # DRAINED TO ∅ (census run17 #5): the 3 urllib sites are now routed through
    # the egress funnel —
    #   * cli.py            → egress_client(intent=Intent.LOCAL_ONLY, verify=False)
    #   * web/daily_health.py → egress_client(intent=Intent.PUBLIC_FETCH)
    #   * embedding_bits/__init__.py (binary download) → egress_client(PUBLIC_FETCH)
    # — so no urllib.request.urlopen construction remains. The IMAP transport
    # converged earlier (2026-06-21) onto providers/imap_fetch_transport.py. A new
    # raw client anywhere now FAILS test_no_raw_egress_client_outside_funnel; an
    # entry re-added here MUST name a live raw construction (the companion
    # test_pending_migration_entries_are_live enforces the list stays at ∅ / honest).
}

# Sites that egress by a mechanism the funnel CANNOT reach — by DESIGN, NOT a
# "not-yet-migrated" debt. SEMANTICALLY DISTINCT from _PENDING_MIGRATION:
# _PENDING_MIGRATION = "will migrate to egress_client, just not yet" (shrinks → ∅);
# _ACKNOWLEDGED_BOUNDARY = "egresses by a mechanism that cannot route through
# egress_client (an httpx client) at all — will NOT migrate." Each entry carries a
# one-line non-PHI + why-unfunnelable justification. Like the pending list it is
# liveness-checked (test_acknowledged_boundary_entries_are_live) so a boundary
# entry can't rot into a stale whole-file exemption masking a future raw client.
# MECHANISM-SCOPED (run17 #5 3-SME, DA must-fix): each entry permits ONLY the named
# unfunnelable mechanism(s) in that file — a future raw ``httpx.Client`` added to a
# boundary file is STILL flagged (the whole-file exemption masking-hole the DA caught).
# value = (frozenset of permitted mechanism tags, non-PHI + why-unfunnelable reason).
_ACKNOWLEDGED_BOUNDARY: dict[str, tuple[frozenset[str], str]] = {
    # RFC2136 dynamic-DNS write-egress to the operator's OWN authoritative DNS, via
    # dnspython's ``dns.query.udp/tcp`` (a raw DNS message over UDP/TCP — NOT HTTP,
    # so it cannot be an httpx egress_client). Non-PHI: ACME dns-01 challenge TXT
    # records + SOA/NS lookups for a hostname, no message content. The ACME client
    # library (``acme`` / ``josepy``) also makes its OWN internal ``requests`` HTTP
    # calls to the CA directory — those are library-internal (not a first-party
    # construction site in our src) so the detector never sees them; they reach an
    # operator-configured CA, non-PHI. ONLY ``dns.query`` is exempted here — a raw
    # ``httpx`` added to this file later is still a pin offender.
    "web/acme_renewer.py": (
        frozenset({"dns.query", "acme_client"}),
        "RFC2136 dnspython dns.query.* DNS-protocol egress to operator DNS + "
        "acme-library-internal CA requests; non-PHI, not HTTP-funnel-able. "
        "N-188 R20_18: `acme_client.ClientNetwork`/`ClientV2` are the ACME "
        "library's OWN HTTP client (constructed here + then handed to the "
        "library); the library owns the transport and can't accept an "
        "external egress_client.",
    ),
    # N-188 R20_18: MSAL library owns its OWN HTTP transport internally — a
    # `ConfidentialClientApplication` / `PublicClientApplication` is the OAuth
    # token-acquisition client; passing httpx to msal isn't supported by the
    # library. Egress is to the OAuth token endpoint (Microsoft), non-PHI (a
    # token request carries client_id + client_secret + tenant_id, not user
    # mail content), and constructed once per O365 account provider.
    "providers/office365.py": (
        frozenset({"msal"}),
        "MSAL library-internal OAuth token acquisition to Microsoft's OAuth "
        "endpoint. Non-PHI (client credentials only); MSAL owns the transport "
        "so the httpx funnel is not reachable.",
    ),
    # HTTP-01 loopback self-check (2026-07-18): the standalone listener stands
    # in the SAME process; ``poll_local`` performs a 127.0.0.1 GET against the
    # ACME challenge path to confirm the token surfaced before letting the CA
    # attempt external validation. The request stays on loopback (never leaves
    # the host); the body is the ACME key-authorization for a challenge we
    # just published (non-PHI, non-secret — it's a challenge value LE is about
    # to publicly validate). urllib.request is used deliberately: the funnel's
    # httpx path adds no policy value on a loopback self-check + would require
    # a new Intent for a same-process validation, which conflates real egress
    # with a self-probe.
    "web/acme_http01.py": (
        frozenset({"urllib.request"}),
        "HTTP-01 loopback self-check to 127.0.0.1 challenge path; same-process "
        "listener, non-PHI (ACME key-authorization), never leaves the host.",
    ),
}


def _bound_evasion_aliases(tree: ast.AST) -> dict[str, str]:
    """Map any name bound via ``from httpx import AsyncClient [as X]`` /
    ``from urllib.request import urlopen`` to its module — so a bare ``X(...)``
    call is caught even though it isn't written ``httpx.AsyncClient(...)``. Covers
    single-Name modules (``_TARGETS``) AND dotted ones (``_DOTTED_TARGETS``)."""
    _dotted = {".".join(k): v for k, v in _DOTTED_TARGETS.items()}
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        names = _TARGETS.get(node.module) or _dotted.get(node.module)
        if names:
            for a in node.names:
                if a.name in names:
                    aliases[a.asname or a.name] = node.module
    return aliases


def _network_subprocess_command(call: ast.Call) -> str | None:
    """The network-tool name if ``call``'s FIRST argv element is a readable
    STRING LITERAL naming one of :data:`_NETWORK_COMMANDS` — else ``None``.

    Conservative on purpose (census run17 #5): only an inline literal is read —
    a ``str`` command (``subprocess.run("curl …", shell=True)`` → first word) or a
    list/tuple literal whose ``[0]`` is a string. A variable argv
    (``subprocess.run(cmd, …)``) or an argv[0] that isn't a string literal
    (``[sys.executable, "-m", "pip", …]`` — pip is argv[2]) returns ``None``: we
    never guess the command through a variable. Path-qualified tools are matched
    on their basename (``/usr/bin/curl`` → ``curl``)."""
    if not call.args:
        return None
    arg0 = call.args[0]
    token: str | None = None
    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
        head = arg0.value.strip().split()
        token = head[0] if head else None
    elif isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts:
        first = arg0.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            token = first.value
    if token is None:
        return None
    base = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]  # /usr/bin/curl -> curl
    if base.lower().endswith((".exe", ".bat", ".cmd", ".com")):
        base = base.rsplit(".", 1)[0]  # curl.exe -> curl (Windows; cavecrew run17 #5)
    return base if base in _NETWORK_COMMANDS else None


def _find_constructions(tree: ast.AST) -> list[ast.Call]:
    """Every ``Call`` node constructing an egress client — the qualified
    ``httpx.AsyncClient(...)`` / dotted ``urllib.request.urlopen(...)`` /
    ``dns.query.udp(...)`` forms, any bare-import alias, and a network
    subprocess (``subprocess.run([net-tool, ...])``) with a readable literal
    command."""
    aliases = _bound_evasion_aliases(tree)
    # Bare-import aliases for subprocess fns (``from subprocess import run``) — so
    # a network ``run([...])`` is caught even without the ``subprocess.`` receiver.
    sp_aliases = {
        (a.asname or a.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for a in node.names if a.name in _SUBPROCESS_FNS
    }
    hits: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        # qualified: <module>.<Attr>(...) — single-Name module receiver
        if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id in _TARGETS and f.attr in _TARGETS[f.value.id]):
            hits.append(node)
        # dotted: <mod1>.<mod2>.<fn>(...) — e.g. urllib.request.urlopen(...)
        elif (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute)
                and isinstance(f.value.value, ast.Name)
                and (f.value.value.id, f.value.attr) in _DOTTED_TARGETS
                and f.attr in _DOTTED_TARGETS[(f.value.value.id, f.value.attr)]):
            hits.append(node)
        # network subprocess: subprocess.<fn>([net-tool, ...]) — qualified receiver
        elif (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id == "subprocess" and f.attr in _SUBPROCESS_FNS
                and _network_subprocess_command(node) is not None):
            hits.append(node)
        # network subprocess via bare alias: run([net-tool, ...])
        elif (isinstance(f, ast.Name) and f.id in sp_aliases
                and _network_subprocess_command(node) is not None):
            hits.append(node)
        # bare alias: X(...) where X came from `from httpx import AsyncClient`
        elif isinstance(f, ast.Name) and f.id in aliases:
            hits.append(node)
    return hits


def _subprocess_aliases(tree: ast.AST) -> set[str]:
    """Names bound via ``from subprocess import run`` etc."""
    return {
        (a.asname or a.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for a in node.names if a.name in _SUBPROCESS_FNS
    }


def _construction_mechanism(call: ast.Call, aliases: dict[str, str],
                            sp_aliases: set[str]) -> str:
    """The egress MECHANISM tag of a flagged construction (``httpx`` / ``smtplib`` /
    ``dns.query`` / ``urllib.request`` / ``http.client`` / ``subprocess:<cmd>`` /
    an aliased module) — so :data:`_ACKNOWLEDGED_BOUNDARY` can exempt ONE mechanism
    per file, never the whole file (run17 #5 DA must-fix)."""
    f = call.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        if f.value.id in _TARGETS and f.attr in _TARGETS[f.value.id]:
            return f.value.id
        if f.value.id == "subprocess" and f.attr in _SUBPROCESS_FNS:
            cmd = _network_subprocess_command(call)
            if cmd:
                return f"subprocess:{cmd}"
    if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute)
            and isinstance(f.value.value, ast.Name)):
        key = (f.value.value.id, f.value.attr)
        if key in _DOTTED_TARGETS and f.attr in _DOTTED_TARGETS[key]:
            return f"{key[0]}.{key[1]}"
    if isinstance(f, ast.Name):
        if f.id in sp_aliases:
            cmd = _network_subprocess_command(call)
            if cmd:
                return f"subprocess:{cmd}"
        if f.id in aliases:
            return aliases[f.id]
    return "?"


def _modules_with_raw_construction() -> dict[str, list[tuple[str, str]]]:
    """relpath -> [(enclosing_fn, mechanism), ...] for every src file that still
    constructs a raw egress client. Mechanism-tagged so the boundary exemption is
    per-mechanism, not whole-file."""
    out: dict[str, list[tuple[str, str]]] = {}
    for _path, rel, tree in walk_src():
        hits = _find_constructions(tree)
        if not hits:
            continue
        aliases = _bound_evasion_aliases(tree)
        sp_aliases = _subprocess_aliases(tree)
        out[rel] = [(enclosing_fn(h), _construction_mechanism(h, aliases, sp_aliases))
                    for h in hits]
    return out


def _offenders(found: dict[str, list[tuple[str, str]]]) -> dict[str, list[tuple[str, str]]]:
    """Raw constructions NOT permitted: outside _ALLOWED/_PENDING_MIGRATION, and —
    for an _ACKNOWLEDGED_BOUNDARY file — any hit whose mechanism is NOT the exempted
    one (so a future raw httpx in a boundary file is still flagged)."""
    offenders: dict[str, list[tuple[str, str]]] = {}
    for rel, hits in found.items():
        if rel in _ALLOWED or rel in _PENDING_MIGRATION:
            continue
        if rel in _ACKNOWLEDGED_BOUNDARY:
            allowed = _ACKNOWLEDGED_BOUNDARY[rel][0]
            bad = [(fn, m) for fn, m in hits if m not in allowed]
            if bad:
                offenders[rel] = bad
            continue
        offenders[rel] = hits
    return offenders


def test_no_raw_egress_client_outside_funnel():
    """Every httpx/smtplib client construction lives in the funnel SSOT or a
    documented pending-migration site — never a fresh raw client elsewhere."""
    offenders = _offenders(_modules_with_raw_construction())
    assert not offenders, (
        "Raw egress client (httpx — incl. one-shot get/post/stream/... — / "
        "smtplib/imaplib/aioimaplib/urllib/requests/aiohttp/http.client/dns.query "
        "/ network subprocess) constructed outside the egress funnel "
        f"({_ALLOWED}, _PENDING_MIGRATION, or _ACKNOWLEDGED_BOUNDARY): {offenders}. "
        "Route HTTP through email_triage._egress.egress_async_client(intent="
        "Intent.<...>) (or egress_client for sync), declaring the destination's "
        "Intent so the fail-closed policy runs; route IMAP through the "
        "imap-transport SSOT. If it is a legitimate not-yet-migrated site, add it "
        "to _PENDING_MIGRATION with its intended Intent/SSOT + reason; if it "
        "egresses by a mechanism that CANNOT route through egress_client (raw DNS, "
        "a network subprocess, a library-internal client), add it to "
        "_ACKNOWLEDGED_BOUNDARY with a non-PHI + why-unfunnelable justification."
    )


def test_pending_migration_entries_are_live():
    """The pending-migration allow-list cannot rot: every entry must STILL have a
    raw construction. A migrated site that lingers here is a stale exemption that
    would silently re-permit a future raw client — remove it the moment you
    migrate the site (this is what forces the list to shrink toward ∅)."""
    found = _modules_with_raw_construction()
    stale = [rel for rel in _PENDING_MIGRATION if rel not in found]
    assert not stale, (
        f"_PENDING_MIGRATION names sites with NO raw egress construction: {stale}. "
        "They've been migrated (or moved) — delete the stale entries so the "
        "exemption shrinks and can't mask a future regression."
    )


def test_acknowledged_boundary_entries_are_live():
    """The boundary allow-list cannot rot either (census run17 #5 — "census the
    censusers"): every _ACKNOWLEDGED_BOUNDARY entry must STILL flag a raw egress
    construction. A boundary entry is a WHOLE-FILE exemption; if the file no
    longer egresses by the unfunnelable mechanism, the lingering entry would
    silently re-permit a future raw httpx client in that file — so a stale
    boundary entry is a defect, just like a stale pending one. Remove (or
    re-justify) the entry the moment its file stops constructing."""
    found = _modules_with_raw_construction()
    stale = []
    for rel, (allowed, _reason) in _ACKNOWLEDGED_BOUNDARY.items():
        mechs = {m for _fn, m in found.get(rel, [])}
        if not (mechs & allowed):  # file no longer egresses by the exempted mechanism
            stale.append(rel)
    assert not stale, (
        f"_ACKNOWLEDGED_BOUNDARY names sites no longer egressing by the exempted "
        f"mechanism: {stale}. The unfunnelable mechanism is gone — delete the stale "
        "exemption so it can't mask a future raw client."
    )


def test_boundary_is_mechanism_scoped_not_whole_file():
    """run17 #5 DA must-fix: an _ACKNOWLEDGED_BOUNDARY file exempts ONLY its named
    mechanism — a future raw httpx added to that file is STILL an offender, closing
    the whole-file masking hole."""
    rel = next(iter(_ACKNOWLEDGED_BOUNDARY))                 # web/acme_renewer.py
    allowed_mech = next(iter(_ACKNOWLEDGED_BOUNDARY[rel][0]))  # dns.query
    # only the exempted mechanism -> clean
    assert _offenders({rel: [("f", allowed_mech)]}) == {}
    # a raw httpx snuck into the same boundary file -> STILL flagged
    assert _offenders({rel: [("f", allowed_mech), ("g", "httpx")]}) == {rel: [("g", "httpx")]}
    # a non-boundary file with any raw construction -> flagged
    assert _offenders({"web/other.py": [("h", "httpx")]}) == {"web/other.py": [("h", "httpx")]}


def test_funnel_ssots_actually_construct():
    """Sanity: the funnel SSOTs really are where construction happens (guards
    against the pin passing vacuously if _egress.py were renamed/emptied)."""
    found = _modules_with_raw_construction()
    assert "_egress.py" in found, (
        "_egress.py constructs no httpx client — the funnel SSOT is missing; "
        "this pin would be vacuously green."
    )


def test_detector_catches_all_mechanisms():
    """Teeth for the mechanism-agnostic widening (census run12 #3): the detector
    flags a raw construction of EACH mechanism — qualified, dotted, and bare-alias
    — not just httpx/smtplib; and does NOT flag a same-named non-egress call."""
    for src in (
        "import imaplib\nc = imaplib.IMAP4_SSL('h', 993)\n",
        "import aioimaplib\nc = aioimaplib.IMAP4_SSL('h', 993)\n",
        "import urllib.request\nr = urllib.request.urlopen('https://x')\n",     # dotted
        "import http.client\nc = http.client.HTTPSConnection('h')\n",          # dotted
        "import requests\nr = requests.get('https://x')\n",
        "import aiohttp\ns = aiohttp.ClientSession()\n",
        "from imaplib import IMAP4_SSL\nc = IMAP4_SSL('h', 993)\n",            # bare alias
        "from urllib.request import urlopen\nr = urlopen('https://x')\n",       # dotted bare alias
        # httpx module-level one-shots (run17 #5) — throwaway-client egress.
        "import httpx\nr = httpx.get('https://x')\n",
        "import httpx\nr = httpx.post('https://x', json={})\n",
        "import httpx\nwith httpx.stream('GET', 'https://x') as r:\n    pass\n",
        "import httpx\nr = httpx.request('GET', 'https://x')\n",
        # dnspython low-level DNS egress (run17 #5) — dotted dns.query.*
        "import dns.query\nr = dns.query.udp(q, '1.2.3.4')\n",
        "import dns.query\nr = dns.query.tcp(q, '1.2.3.4')\n",
    ):
        assert _find_constructions(ast.parse(src)), f"detector missed: {src!r}"
    # A same-named non-egress call is NOT flagged (no false positive).
    assert not _find_constructions(ast.parse("d = {}\nx = d.get('k')\n"))
    assert not _find_constructions(ast.parse("import os\nos.getcwd()\n"))
    assert not _find_constructions(ast.parse("s = sess.request('GET', u)\n"))
    # dns.* OTHER than dns.query.* (e.g. dns.resolver name lookup) is NOT an
    # egress-client construction — no false positive on the unrelated submodule.
    assert not _find_constructions(ast.parse("import dns.resolver\ndns.resolver.resolve('x')\n"))


def test_detector_catches_network_subprocess():
    """Teeth for the network-subprocess detector (census run17 #5): an inline
    LITERAL ``subprocess.run([net-tool, ...])`` (or str command, or bare-alias
    ``run``) IS flagged; a non-network tool, a VARIABLE argv, or a non-literal
    argv[0] is NOT — matching the conservative "never guess through a variable"
    rule (which is exactly why the two real in-tree network subprocesses,
    ``tls.py`` tailscale-cert and ``embedding_bits`` pip-install, are documented
    residuals rather than flagged)."""
    flagged = (
        "import subprocess\nsubprocess.run(['tailscale', 'cert', h])\n",
        "import subprocess\nsubprocess.Popen(['curl', '-s', u])\n",
        "import subprocess\nsubprocess.check_call(['wget', url])\n",
        "import subprocess\nsubprocess.run('curl https://x', shell=True)\n",     # str command
        "import subprocess\nsubprocess.run(['/usr/bin/curl', '-s', u])\n",       # path-qualified
        "from subprocess import run\nrun(['pip', 'install', 'x'])\n",            # bare alias
    )
    for src in flagged:
        assert _find_constructions(ast.parse(src)), f"subprocess detector missed: {src!r}"
    not_flagged = (
        "import subprocess\nsubprocess.run(['ls', '-la'])\n",                    # non-network tool
        "import subprocess\nsubprocess.run(['git', 'status'])\n",               # non-network tool
        "import subprocess\nsubprocess.run(cmd, check=True)\n",                  # variable argv (tls.py shape)
        "import subprocess\nimport sys\nsubprocess.run([sys.executable, '-m', 'pip', 'install'])\n",  # pip is argv[2] (embedding_bits shape)
        "import subprocess\nsubprocess.run([prog, 'cert'])\n",                   # non-literal argv[0]
    )
    for src in not_flagged:
        assert not _find_constructions(ast.parse(src)), f"subprocess false positive: {src!r}"


def test_allowlist_covers_real_provider_hosts():
    """The hardcoded host allowlists in _egress.py are a deliberate copy (the
    providers import _egress, so importing back would cycle). This pin asserts the
    copy stays a SUPERSET of the real provider host constants — so if a provider
    ever changes its base/token host, the allowlist drift is caught here, not in
    prod by a silently-blocked request (style-guide rule 5 — no forked lists that
    drift)."""
    from email_triage._egress import _OAUTH_TOKEN_HOSTS, _PROVIDER_API_HOSTS, _host
    from email_triage.providers.gmail_api import GMAIL_BASE, OAUTH_TOKEN_URL
    from email_triage.providers.gmail_calendar import CAL_BASE
    from email_triage.providers.office365 import GRAPH_BASE

    assert _host(OAUTH_TOKEN_URL) in _OAUTH_TOKEN_HOSTS, (
        f"Gmail token-POST host {_host(OAUTH_TOKEN_URL)!r} is not in the "
        f"OAUTH_TOKEN allowlist {sorted(_OAUTH_TOKEN_HOSTS)} — prod token refresh "
        "would be blocked. Update _OAUTH_TOKEN_HOSTS."
    )
    for base in (GMAIL_BASE, CAL_BASE, GRAPH_BASE):
        assert _host(base) in _PROVIDER_API_HOSTS, (
            f"Provider data host {_host(base)!r} ({base}) is not in the "
            f"PROVIDER_API allowlist {sorted(_PROVIDER_API_HOSTS)} — prod calls "
            "would be blocked. Update _PROVIDER_API_HOSTS."
        )


def test_enforce_policy_matrix():
    """The security core: _enforce fails closed per intent. Locks the verified
    behaviour as a permanent regression. Two shapes: HARD allowlist/locality
    (OAUTH_TOKEN/PROVIDER_API/LOCAL_ONLY — the funnel is the SSOT) and SSRF-guard
    -only pass-through (PUBLIC_FETCH/LLM_PHI/WEBHOOK — the per-message/per-target
    gate is upstream: baa_gate / the webhook dispatcher / the operator URL)."""
    from email_triage._egress import Intent, EgressBlocked, _enforce

    def allowed(intent, url):
        try:
            _enforce(intent, url, extra_local_suffixes=())
            return True
        except EgressBlocked:
            return False

    # OAUTH_TOKEN — secrets ONLY to the enumerated token hosts (not evil, not even local)
    assert allowed(Intent.OAUTH_TOKEN, "https://oauth2.googleapis.com/token")
    assert allowed(Intent.OAUTH_TOKEN, "https://login.microsoftonline.com/t/oauth2/v2.0/token")
    assert not allowed(Intent.OAUTH_TOKEN, "https://evil.example.com/token")
    assert not allowed(Intent.OAUTH_TOKEN, "http://127.0.0.1/token")
    # PROVIDER_API — provider hosts or local; nothing else
    assert allowed(Intent.PROVIDER_API, "https://gmail.googleapis.com/gmail/v1/x")
    assert not allowed(Intent.PROVIDER_API, "https://evil.example.com/x")
    # LOCAL_ONLY
    assert allowed(Intent.LOCAL_ONLY, "http://127.0.0.1:8080")
    assert not allowed(Intent.LOCAL_ONLY, "https://google.com")
    # SSRF-guard-only intents: external http(s) is ALLOWED (gated upstream), but
    # a non-http scheme or a link-local/metadata IP is refused for all three.
    for intent in (Intent.PUBLIC_FETCH, Intent.LLM_PHI, Intent.WEBHOOK):
        assert allowed(intent, "https://example.com/x")           # external — upstream-gated
        assert allowed(intent, "http://192.168.1.9:8080/x")       # LAN (SearXNG/Ollama/webhook)
        assert allowed(intent, "http://127.0.0.1:11434/api/chat") # loopback
        assert not allowed(intent, "http://169.254.169.254/latest/meta-data/")  # cloud-metadata
        assert not allowed(intent, "http://[::ffff:169.254.169.254]/")  # v4-mapped metadata
        assert not allowed(intent, "file:///etc/passwd")          # non-http scheme
        assert not allowed(intent, "gopher://x/_")


def test_ssrf_blocked_ip_ssot():
    """The SSRF-IP predicate lives in the _netloc SSOT (explicit nets, NOT the
    banned ipaddress attributes). Blocks the metadata/link-local/invalid ranges;
    does NOT block loopback/RFC1918 (legitimate LAN) or hostnames."""
    from email_triage._netloc import is_ssrf_blocked_ip
    for blocked in ("169.254.169.254", "::ffff:169.254.169.254", "fe80::1",
                    "0.0.0.0", "224.0.0.1"):
        assert is_ssrf_blocked_ip(blocked), f"{blocked} should be SSRF-blocked"
    for ok in ("127.0.0.1", "192.168.1.5", "10.0.0.3", "::1",
               "93.184.216.34", "example.com", "gmail.googleapis.com"):
        assert not is_ssrf_blocked_ip(ok), f"{ok} should NOT be SSRF-blocked"


def test_pin_has_teeth():
    """Detector flags a planted raw construction (qualified + bare-alias) and
    does NOT flag the funnel call."""
    assert_pin_has_teeth(
        lambda tree: bool(_find_constructions(tree)),
        bad_source="import httpx\nasync def f():\n    return httpx.AsyncClient(timeout=1)\n",
        good_source=(
            "from email_triage._egress import egress_async_client, Intent\n"
            "async def f():\n"
            "    return egress_async_client(intent=Intent.PROVIDER_API, timeout=1)\n"
        ),
    )
    # bare-alias evasion is caught too
    bare = parse_source(
        "from httpx import AsyncClient\nasync def f():\n    return AsyncClient(timeout=1)\n"
    )
    assert _find_constructions(bare), "bare-import alias evaded the detector"
    # smtplib.SMTP_SSL is in scope
    smtp = parse_source("import smtplib\ndef f():\n    return smtplib.SMTP_SSL('h', 465)\n")
    assert _find_constructions(smtp), "smtplib.SMTP_SSL not detected"
