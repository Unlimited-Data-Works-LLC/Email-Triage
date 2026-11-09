"""Pin — every requests-based HTTP client in src/ takes its proxy, trust store and certificate mode
through the egress settings (punch 547 / panel B1; operator ruling A3, 2026-10-21).

2026-10-21 (operator ruling A3): the well-known variables are HONOURED again
(HTTPS_PROXY / HTTP_PROXY / NO_PROXY, REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE,
SSL_CERT_FILE / SSL_CERT_DIR), with ``outbound_tls`` config overriding them
(``proxy_url``, ``no_proxy``, ``ca_bundle``, ``ignore_env``) and the certificate
mode (``cert_check`` / ``cert_enforce``) applied by an adapter. The pin's job is
unchanged in shape: no requests session escapes the ONE place that applies those
settings (``_egress.configure_requests_session``). Arm 4 and arm 6 below are
restated for that; the history follows.

db-sme F-O3-2 / hipaa O3-H6 (2026-10-01): punch 547 forced ``trust_env=False``
on the httpx clients in ``_egress.py``, but two egress paths built a plain
``requests.Session`` that still read HTTPS_PROXY and REQUESTS_CA_BUNDLE /
CURL_CA_BUNDLE from the environment:

* msal's default http_client on the Office 365 OAuth token path;
* acme's ``ClientNetwork`` session on the certificate-renewal path.

Round 2 (panel B1 fold-check of 7c478e87): the first version checked that msal
got SOME ``http_client=`` (``None`` passed, and msal tests ``if http_client:``,
so ``None`` is its env-trusting default) and saw only a ``requests.Session()``
bound to a bare name (DA OF-1/OF-2, hipaa OF-1). The HTTP-01 self-check's
``urllib.request.urlopen`` also followed HTTP_PROXY (DA OF-3).

INVARIANT (count-agnostic, over every module under src/email_triage; keys are
repo-relative paths; imports are resolved, function-local ones included):

1. REQUESTS: outside ``_egress.py`` no module touches the ``requests``
   package's Session / session / request / get / post / put / patch / delete /
   head / options, or its ``sessions`` / ``api`` submodules, whatever the
   import spelling (``import requests as r``, ``from requests import Session``,
   ``import requests.sessions``, a module-level or ``self.``-bound session, a
   ``requests.get(url)`` one-shot). ``requests.exceptions`` etc. stay legal.
2. FACTORY CALLERS: the modules (other than ``_egress.py``) that reference
   ``egress_requests_session`` are exactly ``_FACTORY_CALLERS``. The factory has
   no Intent hook, so a new caller is a reviewed decision, not a free call.
3. MSAL: every msal ClientApplication / ConfidentialClientApplication /
   PublicClientApplication / ManagedIdentityClient is CALLED (not passed around)
   with ``http_client=`` as a keyword whose value is a call to
   ``egress_requests_session()``, or a name every binding of which in the same
   scope is such a call.
4. ACME: every ``ClientNetwork(...)`` is bound to a name, and the very next
   statement in the same block is ``configure_requests_session(<name>.session)``
   (was ``<name>.session.trust_env = False`` until 2026-10-21).
5. URLLIB: no reference to ``urllib.request.urlopen`` / ``urlretrieve`` (both
   use the global opener, whose default ProxyHandler reads *_PROXY), and every
   ``build_opener(...)`` passes ``ProxyHandler({})``.
6. RUNTIME: ``egress_requests_session()`` follows the environment unless
   ``outbound_tls.ignore_env``; a configured proxy / CA bundle overrides it; and
   it mounts the certificate-mode ``HTTPAdapter`` with ``max_retries=1`` on
   http:// and https:// (msal's own single connect retry, which a supplied
   http_client otherwise loses; db R1 / hipaa OF-3).

SCOPE (not covered): a session or opener built inside a library this walk does
not see (acme's own ``requests`` use rides the session arm 4 switches off);
``install_opener``. RECORDED RESIDUAL, not fixed (panel B1 DA O3F2-1, LOW,
fail-open on this pin only; no instance in src): dynamic access escapes all
three import-resolving arms (1 requests, 3 msal, 5 urllib), which see only
static ``import`` / ``from ... import`` bindings and attribute chains rooted at
them. Not seen: ``getattr(requests, name)`` / ``getattr(msal, name)``;
``importlib.import_module("requests")`` and ``__import__("requests")``; a
module bound to a variable and used through it (``mod = requests;
mod.Session()``); a vendored copy (``from pip._vendor import requests``); a
hand-assembled ``urllib.request.OpenerDirector()``.
The REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE keys were RETIRED (refused at start)
until 2026-10-21; they are honoured again (``test_ca_bundle_keys_are_honoured``).
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    docstring_constant_ids,
    innermost_fn_at_lineno,
    parse_source,
    walk_src,
)
from email_triage._env_registry import RETIRED

_FACTORY = "egress_requests_session"
_FACTORY_HOME = "_egress.py"
# Repo-relative. Equality, not subset: a removed caller fails too (stale entry).
_FACTORY_CALLERS: frozenset[str] = frozenset({
    "providers/office365.py",  # msal http_client for the O365 OAuth token path
})
_REQUESTS_BANNED: frozenset[str] = frozenset({
    "Session", "session", "request", "get", "post", "put", "patch", "delete",
    "head", "options", "sessions", "api",
})
_MSAL_CONSTRUCTORS: frozenset[str] = frozenset({
    "ClientApplication", "ConfidentialClientApplication",
    "PublicClientApplication", "ManagedIdentityClient",
})
_URLOPEN_GLOBAL: frozenset[str] = frozenset({
    "urllib.request.urlopen", "urllib.request.urlretrieve",
})
_BLOCKS = ("body", "orelse", "finalbody")


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> the dotted thing it is bound to, from every import in the
    tree. A relative import keeps its leading dots (``.._egress.x``)."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    out[top] = top
        elif isinstance(node, ast.ImportFrom):
            mod = "." * node.level + (node.module or "")
            for a in node.names:
                out[a.asname or a.name] = f"{mod}.{a.name}" if node.module else f"{mod}{a.name}"
    return out


def _qualify(node: ast.AST, aliases: dict[str, str]) -> str | None:
    chain: list[str] = []
    while isinstance(node, ast.Attribute):
        chain.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(chain)])


def _is_outermost_ref(node: ast.AST) -> bool:
    parent = getattr(node, "_ph_parent", None)
    return (isinstance(node, (ast.Name, ast.Attribute))
            and not (isinstance(parent, ast.Attribute) and parent.value is node))


def _is_called(node: ast.AST) -> bool:
    parent = getattr(node, "_ph_parent", None)
    return isinstance(parent, ast.Call) and parent.func is node


def _is_factory_call(node: ast.AST, aliases: dict[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    q = _qualify(node.func, aliases)
    return q is not None and (q == f"_egress.{_FACTORY}" or q.endswith(f"._egress.{_FACTORY}"))


def _is_factory_value(value: ast.AST, tree: ast.AST, aliases: dict[str, str]) -> bool:
    if _is_factory_call(value, aliases):
        return True
    if not isinstance(value, ast.Name):
        return False
    scope = innermost_fn_at_lineno(tree, value.lineno) or tree
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = scope.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]
        if any(p is not None and p.arg == value.id for p in params):
            return False
    bound = 0
    for node in ast.walk(scope):
        if isinstance(node, ast.Name) and node.id == value.id and isinstance(node.ctx, ast.Store):
            parent = getattr(node, "_ph_parent", None)
            if not (isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                    and _is_factory_call(parent.value, aliases)):
                return False
            bound += 1
    return bound > 0


def _next_statement(stmt: ast.stmt) -> ast.stmt | None:
    parent = getattr(stmt, "_ph_parent", None)
    for field in _BLOCKS:
        block = getattr(parent, field, None)
        if isinstance(block, list) and stmt in block:
            i = block.index(stmt)
            return block[i + 1] if i + 1 < len(block) else None
    return None


def _configures_session(stmt: ast.stmt | None, name: str) -> bool:
    """``configure_requests_session(<name>.session)`` as its own statement."""
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return False
    call = stmt.value
    fn = call.func
    fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
    if fname != "configure_requests_session" or not call.args:
        return False
    a = call.args[0]
    return (isinstance(a, ast.Attribute) and a.attr == "session"
            and isinstance(a.value, ast.Name) and a.value.id == name)


def _is_empty_dict(node: ast.AST) -> bool:
    return isinstance(node, ast.Dict) and not node.keys


def _passes_no_proxy_handler(call: ast.Call, aliases: dict[str, str]) -> bool:
    for arg in call.args:
        if (isinstance(arg, ast.Call)
                and _qualify(arg.func, aliases) == "urllib.request.ProxyHandler"
                and ((arg.args and _is_empty_dict(arg.args[0]))
                     or any(k.arg == "proxies" and _is_empty_dict(k.value)
                            for k in arg.keywords))):
            return True
    return False


def _scan(tree: ast.AST, rel: str) -> tuple[set[str], list[str]]:
    """(site kinds seen, offenders) for one module. Kinds: msal / acme / opener."""
    aliases = _aliases(tree)
    seen: set[str] = set()
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and rel != _FACTORY_HOME:
            mod = getattr(node, "module", None) or ""
            names = [a.name for a in node.names]
            dotted = names if isinstance(node, ast.Import) else [f"{mod}.{n}" for n in names]
            for d in dotted:
                parts = d.split(".")
                if parts[0] == "requests" and _REQUESTS_BANNED & set(parts[1:]):
                    out.append(f"{rel}:{node.lineno} imports {d} (only _egress builds a requests session)")
        if not _is_outermost_ref(node):
            if isinstance(node, ast.Call):
                q = _qualify(node.func, aliases) or ""
                if q.endswith("ClientNetwork") or (isinstance(node.func, ast.Attribute)
                                                   and node.func.attr == "ClientNetwork"):
                    seen.add("acme")
                    parent = getattr(node, "_ph_parent", None)
                    if not (isinstance(parent, ast.Assign) and len(parent.targets) == 1
                            and isinstance(parent.targets[0], ast.Name)
                            and _configures_session(_next_statement(parent),
                                                    parent.targets[0].id)):
                        out.append(f"{rel}:{node.lineno} ClientNetwork(...) not bound and "
                                   "immediately followed by "
                                   "configure_requests_session(<name>.session)")
            continue
        q = _qualify(node, aliases)
        if q is None:
            continue
        parts = q.split(".")
        if rel != _FACTORY_HOME and parts[0] == "requests" and _REQUESTS_BANNED & set(parts[1:]):
            out.append(f"{rel}:{node.lineno} uses {q} (only _egress builds a requests session)")
        if parts[0] == "msal" and parts[-1] in _MSAL_CONSTRUCTORS:
            seen.add("msal")
            call = getattr(node, "_ph_parent", None)
            if not _is_called(node):
                out.append(f"{rel}:{node.lineno} {q} referenced but not called here (http_client unverifiable)")
                continue
            kw = next((k for k in call.keywords if k.arg == "http_client"), None)
            if kw is None:
                out.append(f"{rel}:{node.lineno} {q}(...) without an http_client= keyword")
            elif not _is_factory_value(kw.value, tree, aliases):
                out.append(f"{rel}:{node.lineno} {q}(http_client=...) is not egress_requests_session()")
        if q in _URLOPEN_GLOBAL:
            out.append(f"{rel}:{node.lineno} {q} uses the global opener (its ProxyHandler reads *_PROXY)")
        if q == "urllib.request.build_opener":
            seen.add("opener")
            if not (_is_called(node) and _passes_no_proxy_handler(node._ph_parent, aliases)):
                out.append(f"{rel}:{node.lineno} build_opener without ProxyHandler({{}})")
    return seen, out


def _references_factory(tree: ast.AST) -> bool:
    docs = docstring_constant_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == _FACTORY:
            return True
        if isinstance(node, ast.Attribute) and node.attr == _FACTORY:
            return True
        if isinstance(node, ast.ImportFrom) and any(a.name == _FACTORY for a in node.names):
            return True
        if (isinstance(node, ast.Constant) and node.value == _FACTORY
                and id(node) not in docs):
            return True
    return False


def _detector(tree: ast.AST) -> list[str]:
    return _scan(tree, "m.py")[1]


def test_no_http_client_in_src_trusts_the_environment():
    offenders = [o for _p, rel, tree in walk_src() for o in _scan(tree, rel)[1]]
    assert offenders == []


def test_egress_requests_session_callers_are_the_declared_set():
    callers = {rel for _p, rel, tree in walk_src()
               if rel != _FACTORY_HOME and _references_factory(tree)}
    assert callers == set(_FACTORY_CALLERS)


def test_the_pin_sees_the_known_sites():
    # Proves the input is in the set the control acts on.
    seen = {(rel, kind) for _p, rel, tree in walk_src() for kind in _scan(tree, rel)[0]}
    assert ("providers/office365.py", "msal") in seen, seen
    assert ("web/acme_renewer.py", "acme") in seen, seen
    assert ("web/acme_http01.py", "opener") in seen, seen


def _bind_outbound(monkeypatch, **fields):
    from email_triage import tls
    from email_triage.config import OutboundTLSConfig, TriageConfig

    cfg = TriageConfig()
    cfg.outbound_tls = OutboundTLSConfig(**fields)
    monkeypatch.setattr(tls, "_bound_config", cfg)


def test_egress_requests_session_honours_env_and_retries_once(monkeypatch):
    # Operator ruling A3: with HTTPS_PROXY and REQUESTS_CA_BUNDLE set and no
    # config override, the session resolves both (requests reads them itself);
    # both schemes carry msal's single connect retry (db R1 / hipaa OF-3).
    from requests.adapters import HTTPAdapter

    from email_triage._egress import egress_requests_session
    _bind_outbound(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/private-ca.pem")
    s = egress_requests_session()
    assert s.trust_env is True
    settings = s.merge_environment_settings(
        "https://login.microsoftonline.invalid/x", {}, None, None, None)
    assert settings["proxies"].get("https") == "http://10.9.9.9:3128"
    assert settings["verify"] == "/tmp/private-ca.pem"
    for url in ("https://login.microsoftonline.invalid/x", "http://example.invalid/"):
        adapter = s.get_adapter(url)
        assert isinstance(adapter, HTTPAdapter)
        assert adapter.max_retries.total == 1, url


def test_ignore_env_switches_the_environment_off(monkeypatch):
    from email_triage._egress import egress_requests_session
    _bind_outbound(monkeypatch, ignore_env=True)
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/private-ca.pem")
    s = egress_requests_session()
    assert s.trust_env is False
    settings = s.merge_environment_settings(
        "https://login.microsoftonline.invalid/x", {}, None, None, None)
    assert not settings.get("proxies")
    assert settings.get("verify") in (True, None)


def test_config_proxy_and_ca_bundle_override_the_environment(monkeypatch):
    # requests lets the environment beat session-level settings, so the config
    # override is applied per request in the adapter (requests_overrides).
    from email_triage._egress import egress_requests_session, requests_overrides
    _bind_outbound(monkeypatch, proxy_url="http://proxy.invalid:8080",
                   no_proxy="internal.example", ca_bundle="/etc/cfg-ca.pem")
    monkeypatch.setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/private-ca.pem")
    s = egress_requests_session()
    url = "https://login.microsoftonline.invalid/x"
    merged = s.merge_environment_settings(url, {}, None, None, None)
    verify, proxies = requests_overrides(url, merged["verify"], merged["proxies"])
    assert proxies == {"http": "http://proxy.invalid:8080", "https": "http://proxy.invalid:8080"}
    assert verify == "/etc/cfg-ca.pem"
    assert requests_overrides("https://internal.example/", True, merged["proxies"])[1] == {}
    assert requests_overrides(url, False, {})[0] is False  # a caller's verify=False stays


def test_ca_bundle_keys_are_honoured():
    for key in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        assert key not in RETIRED, key


_GOOD_MSAL = (
    "def f():\n"
    "    from email_triage._egress import egress_requests_session\n"
    "    http_client = egress_requests_session()\n"
    "    return msal.ConfidentialClientApplication('id', http_client=http_client)\n"
    "import msal\n"
)


def test_pin_has_teeth_msal():
    # DA OF-1's measured-GREEN shapes, each now RED.
    for bad in (
        "import msal\ndef f():\n    return msal.ConfidentialClientApplication('id', token_cache=c)\n",
        "import msal\ndef f():\n    return msal.ConfidentialClientApplication('id', http_client=None)\n",
        "import msal\ndef f():\n    return msal.PublicClientApplication('id', http_client=object())\n",
        "import msal, requests\ndef f():\n"
        "    return msal.ConfidentialClientApplication('id', http_client=requests.Session())\n",
        "from msal import ConfidentialClientApplication\n"
        "def f():\n    return ConfidentialClientApplication('id', http_client=None)\n",
        "from msal import PublicClientApplication as P\ndef f():\n    return P('id')\n",
        "import msal\ndef f(s):\n    return msal.ManagedIdentityClient(m, http_client=s)\n",
        "import msal\ndef f():\n    from email_triage._egress import egress_requests_session\n"
        "    c = egress_requests_session()\n    c = None\n"
        "    return msal.PublicClientApplication('id', http_client=c)\n",
        "import msal\nmake = msal.PublicClientApplication\n",
        "import msal as m\nAPP = m.ClientApplication('id')\n",
    ):
        assert_pin_has_teeth(_detector, bad, _GOOD_MSAL)


def test_pin_has_teeth_requests():
    # DA OF-2 / hipaa OF-1's measured-GREEN shapes, each now RED.
    for bad in (
        "def f():\n    import requests\n    s = requests.Session()\n    s.trust_env = False\n",
        "from requests import Session\ndef f():\n    return Session()\n",
        "import requests as r\ndef f():\n    return r.Session()\n",
        "import requests\ndef f():\n    return requests.session()\n",
        "import requests\nSESSION = requests.Session()\n",
        "import requests\nclass C:\n    def __init__(self):\n        self.s = requests.Session()\n",
        "import requests\ndef f(url):\n    return requests.get(url)\n",
        "import requests.sessions\ndef f():\n    return requests.sessions.Session()\n",
        "from requests.api import post\n",
    ):
        assert_pin_has_teeth(
            _detector, bad,
            "import requests\ndef f():\n    try:\n        pass\n"
            "    except requests.exceptions.HTTPError:\n        pass\n",
        )


def test_pin_has_teeth_acme():
    good = ("def f():\n    net = acme_client.ClientNetwork(k)\n"
            "    configure_requests_session(net.session)\n    return net\n")
    for bad in (
        "def f():\n    net = acme_client.ClientNetwork(k)\n    return net\n",
        "def f():\n    return acme_client.ClientV2(d, net=acme_client.ClientNetwork(k))\n",
        "def f():\n    net = acme_client.ClientNetwork(k)\n    if x:\n"
        "        configure_requests_session(net.session)\n    return net\n",
        "def f():\n    net = acme_client.ClientNetwork(k)\n    use(net)\n"
        "    configure_requests_session(net.session)\n",
        "def f():\n    net = acme_client.ClientNetwork(k)\n"
        "    configure_requests_session(other.session)\n",
        "def f():\n    net = acme_client.ClientNetwork(k)\n"
        "    net.session.trust_env = False\n",
        "from acme.client import ClientNetwork as CN\ndef f():\n    net = CN(k)\n",
    ):
        assert_pin_has_teeth(_detector, bad, good)


def test_pin_has_teeth_urllib():
    good = ("import urllib.request\ndef f(req):\n"
            "    o = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
            "    return o.open(req)\n")
    for bad in (
        "import urllib.request\ndef f(req):\n    return urllib.request.urlopen(req)\n",
        "from urllib.request import urlopen as u\ndef f(req):\n    return u(req)\n",
        "from urllib import request\ndef f(u):\n    return request.urlretrieve(u)\n",
        "import urllib.request\ndef f(req):\n    return urllib.request.build_opener().open(req)\n",
        "import urllib.request as ur\ndef f(req):\n"
        "    return ur.build_opener(ur.ProxyHandler()).open(req)\n",
        "import urllib.request\ndef f(req):\n"
        "    return urllib.request.build_opener(urllib.request.ProxyHandler({'http': p})).open(req)\n",
    ):
        assert_pin_has_teeth(_detector, bad, good)


def test_pin_has_teeth_factory_callers():
    assert_pin_has_teeth(
        _references_factory,
        "from email_triage._egress import egress_requests_session as mk\n",
        '"""egress_requests_session"""\n',  # a docstring is prose, not a caller
    )
    assert _references_factory(parse_source(
        "from email_triage import _egress\ns = _egress.egress_requests_session()\n"))


def test_pin_goes_red_on_the_real_sites_mutated():
    # The real sources, mutated in memory: each mutation must turn the arm RED.
    def red(rel: str, old: str, new: str) -> None:
        src = (SRC_ROOT / rel).read_text(encoding="utf-8")
        assert old in src, (rel, old)  # the mutation is not vacuous
        assert _scan(parse_source(src), rel)[1] == [], rel
        assert _scan(parse_source(src.replace(old, new)), rel)[1], (rel, new)

    red("providers/office365.py", "http_client=http_client", "http_client=None")
    red("providers/office365.py", "http_client = egress_requests_session()",
        "http_client = object()")
    red("web/acme_renewer.py", "configure_requests_session(net.session)", "pass")
    red("web/acme_http01.py", "ProxyHandler({})", "ProxyHandler()")
