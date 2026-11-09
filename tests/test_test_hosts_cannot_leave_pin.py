"""Pin (t20, operator directive 2026-10-26): no test names a host that can leave the machine
as a connect target.

A fixture host like ``x.com`` is a leak, not only a slow test: the edit-page render resolved it
in public DNS and opened TCP to the internet on 993. Fixture hosts use names that cannot leave
the machine even with ``tests/_network_guard.py`` off; the guard is the second layer.

ALLOWED hosts: loopback and the unspecified address, the RFC 5737 documentation networks,
``localhost`` / ``*.localhost``, ``testserver`` (Starlette's TestClient: an in-process ASGI
transport that never opens a socket), and the RFC 6761 / RFC 2606 special-use TLDs ``.invalid``,
``.test``, ``.example``. NOT allowed: ``example.com`` / ``.net`` / ``.org`` (reserved, but they
resolve publicly to IANA hosts), ``.lan`` / ``.local`` / ``.internal`` / ``.ts.net`` names, and
single-label names (a resolver appends the search domain and the query leaves).

POSITIONS (a connect target): the value of a dict key, keyword argument or assignment target
named like a host (``host``, ``hostname``, ``server``, ``netloc``, ``*_host``, ``*_server``, ...)
or a URL (``url``, ``endpoint``, ``*_url``, ``*_uri``, ...; the value must contain ``://``); the
first argument of an IMAP / SMTP / socket connector; a ``://`` URL argument of
``urlopen`` / ``Request`` / ``get`` / ``post`` / ``request`` / ``stream`` and the other HTTP verbs.

EXEMPT: a single-label name in a test file the publish step strips (``operator_only``): the
operator-tooling LLM routing tests key on the operator's own LAN host-map names, those files never
ship, and the guard refuses the connect. ``ALLOW`` (keyed ``(repo-relative path, host)``, never by
line, each with its reason) is for a product constant a test is ABOUT; a stale
entry fails.

SCOPE CAVEAT (what a green run does NOT prove): a host inside a comparison, an SQL string, a
docstring or a computed value is not seen here; ``tests/_network_guard.py`` refuses those at run
time. Private (RFC 1918 / link-local) IP literals are out of scope: they are the subjects of the
SSRF and locality refusal tests, the operator's own ranges, and the guard refuses a connect to
them.
"""

from __future__ import annotations

import ast
import fnmatch
import functools
import ipaddress
import re
import sys
from urllib.parse import urlsplit

from _pin_harness import (
    REPO_ROOT, assert_pin_has_teeth, iter_files, parse_module, parse_source, relpath,
)

TESTS_ROOT = REPO_ROOT / "tests"

HOST_KEYS = re.compile(r"^(host|hostname|server|netloc|.*_host|.*_hostname|.*_server|.*_netloc)$",
                       re.I)
URL_KEYS = re.compile(r"^(endpoint|url|uri|.*_url|.*_uri|.*_endpoint)$", re.I)
HOST_CALLS = frozenset({"create_connection", "open_connection", "IMAP4", "IMAP4_SSL", "SMTP",
                        "SMTP_SSL", "aioimaplib_connect", "imap_connect", "getaddrinfo"})
URL_CALLS = frozenset({"urlopen", "Request", "get", "post", "put", "patch", "delete", "head",
                       "options", "request", "stream"})
ALLOWED_TLDS = frozenset({"invalid", "test", "example"})
IN_PROCESS = frozenset({"localhost", "testserver"})
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_NAME = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*")

ALLOW: dict[tuple[str, str], str] = {
    ("tests/test_privacy_invariants_no_embedding_telemetry.py", "files.pythonhosted.org"): (
        "product constant: the privacy allowlist of hosts the embedding installer may reach; the "
        "test checks the installer's URLs against that exact host and opens no connection"),
    ("tests/test_web/test_update_check_553_web.py", "api.github.com"): (
        "product constant: the update check's default release endpoint, named in its "
        "disclosure id and on the rendered page; the fetch is faked and the guard refuses any "
        "connect"),
}


@functools.lru_cache(maxsize=1)
def _strip_globs() -> tuple[str, ...]:
    """The publish strip list, read through the ship-set funnel (PD-6). Empty on the mirror."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import publish_shipset
    except ImportError:
        # The mirror ships no publish tooling. No strip list means no file is operator-only, so
        # every single-label host is flagged: the pin gets stricter, never looser.
        return ()
    finally:
        sys.path.pop(0)
    return tuple(publish_shipset.load_rules(str(REPO_ROOT))[1])


def operator_only(rel: str, host: str) -> bool:
    """A single-label name in a test file the publish step strips: an operator LAN host-map key
    (the LLM routing tests key on the name), never shipped, and refused at run time by the
    guard. A dotted name in such a file is still flagged."""
    return "." not in host and any(fnmatch.fnmatch(rel, g) for g in _strip_globs())


def host_of(value: str) -> str | None:
    """The host a connect-target string names, or None when it names none."""
    v = value.strip()
    if "://" in v:
        try:
            host = urlsplit(v).hostname
        except ValueError:
            return None
        return host or None
    if not v or any(c in v for c in " /@{}*?#") or v.startswith("."):
        return None
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v.lower() or None


def can_leave(host: str) -> bool:
    """True when a lookup or a connect for ``host`` could leave this machine."""
    h = host.lower().strip("[]").rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified or any(ip in n for n in _DOC_NETS):
            return False
        return not (ip.is_private or ip.is_link_local)  # out of scope: see SCOPE CAVEAT
    if h in IN_PROCESS or h.endswith(".localhost") or not _NAME.fullmatch(h):
        return False
    return not ("." in h and h.rsplit(".", 1)[1] in ALLOWED_TLDS)


def _name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _first_str(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node
    if isinstance(node, ast.Tuple) and node.elts:
        return _first_str(node.elts[0])
    return None


def connect_targets(tree: ast.AST) -> list[tuple[int, str, str]]:
    """``(line, position, host)`` for every host literal in a connect-target position."""
    return [(const.lineno, position, host) for const, position, host in target_nodes(tree)]


def target_nodes(tree: ast.AST) -> list[tuple[ast.Constant, str, str]]:
    """``(string node, position, host)`` for every host literal in a connect-target position."""
    pairs: list[tuple[str, ast.AST, bool]] = []  # (position, value, url_only)
    for node in ast.walk(tree):
        named: list[tuple[str | None, ast.AST | None]] = []
        if isinstance(node, ast.Dict):
            named = [(_name(k), v) for k, v in zip(node.keys, node.values) if k is not None]
        elif isinstance(node, ast.keyword):
            named = [(node.arg, node.value)]
        elif isinstance(node, ast.Assign):
            named = [(_name(t), node.value) for t in node.targets]
        elif isinstance(node, ast.AnnAssign):
            named = [(_name(node.target), node.value)]
        elif isinstance(node, ast.Call):
            fn = _name(node.func)
            if fn in HOST_CALLS and node.args:
                pairs.append((f"{fn}()", node.args[0], False))
            elif fn in URL_CALLS:
                pairs += [(f"{fn}()", a, True) for a in node.args[:2]]
        for name, value in named:
            if not name or value is None:
                continue
            if HOST_KEYS.match(name):
                pairs.append((name, value, False))
            elif URL_KEYS.match(name):
                pairs.append((name, value, True))
    out = []
    for position, value, url_only in pairs:
        const = _first_str(value)
        if const is None or (url_only and "://" not in const.value):
            continue
        host = host_of(const.value)
        if host:
            out.append((const, position, host))
    return out


def leaking_targets(tree: ast.AST) -> list[tuple[int, str, str]]:
    return [t for t in connect_targets(tree) if can_leave(t[2])]


def _scan() -> dict[tuple[str, str], list[str]]:
    hits: dict[tuple[str, str], list[str]] = {}
    for path in iter_files(TESTS_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path, REPO_ROOT)
        for line, position, host in leaking_targets(tree):
            if not operator_only(rel, host):
                hits.setdefault((rel, host), []).append(f"{rel}:{line} {position}={host}")
    return hits


def test_no_test_names_a_host_that_can_leave():
    offenders = [s for key, sites in _scan().items() if key not in ALLOW for s in sites]
    assert not offenders, (
        "A test names a host that can leave this machine as a connect target. Use a name under "
        ".invalid / .test / .example, 127.0.0.1, or a 192.0.2.x documentation address "
        "(tests/test_test_hosts_cannot_leave_pin.py):\n  " + "\n  ".join(offenders))


def test_allow_entries_are_live_and_reasoned():
    live = set(_scan())
    stale = [k for k in ALLOW if k not in live]
    assert not stale, f"stale ALLOW entry (site gone or no longer flagged): {stale}"
    assert all(reason.strip() for reason in ALLOW.values())


_BAD = (
    "acct = {'host': 'imap.gmail.com'}\n"
    "connect(host='x')\n"
    "client.post('https://api.vendor.com/v1')\n"
    "base_url = 'http://mail.example.com:8080'\n"
)


def test_detector_has_teeth():
    assert_pin_has_teeth(
        leaking_targets,
        bad_source=_BAD,
        good_source=(
            "acct = {'host': 'imap.example.invalid', 'port': 993}\n"
            "connect(host='127.0.0.1', url='stub')\n"
            "client.post('http://testserver/accounts')\n"
            "base_url = 'http://llm.test:11434'\n"
            "assert cfg['host'] == 'imap.gmail.com'\n"
        ),
    )
    found = sorted(h for _, _, h in leaking_targets(parse_source(_BAD)))
    assert found == ["api.vendor.com", "imap.gmail.com", "mail.example.com", "x"], found
