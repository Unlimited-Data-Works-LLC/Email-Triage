"""Pin (panel U hipaa NOTE-H2, 2026-10-26): every login failure routes through the lockout funnel.

``check_login_allowed`` counts ``auth_events`` rows whose ``outcome`` is ``'failure'`` AND
whose ``event_type`` starts with ``LOCKOUT_EVENT_PREFIX`` (the SQL ``LIKE 'login\\_%'``).
This pin binds the outcome half; ``tests/test_lockout_event_prefix_pin.py`` is the
companion pin for the event-type half. ``record_login_failure`` (``web/login_guard.py``)
is the one funnel that writes that row for a failed login, and ``record_login_lockout`` writes the row for a refused one. A login
handler that records its failure any other way, for example
``record_auth_event(event_type='login_otp', outcome='denied:bad_code')``, writes a row the
counter never sees: the guess is free and the lockout fails OPEN on brute force
(§164.308(a)(5)(ii)(C)). A prefix pin on ``event_type`` cannot see this; the outcome is
the other half of the counting predicate, so this pin binds the ROUTE, not the name.

INVARIANTS (count-agnostic, PD-1; interprocedural, PD-2):

(A) Route. Login scope is every def that calls ``check_login_allowed`` (directly, in a
    nested def or lambda, handed to a dispatcher, or through another top-level def of its
    module), every route handler on ``/login`` or ``/auth``, and every def those reach by
    name, in the same module or through a ``from email_triage... import`` binding. In that
    scope, every ``record_auth_event`` / ``record_auth_event_txn`` write (direct, in a
    lambda, or handed to a dispatcher such as ``db_call(record_auth_event, ...)``) whose
    ``outcome`` is not the literal ``'success'`` is inside the funnels, or is a reviewed
    non-guessable denial in ``_NON_GUESSABLE``. A non-static ``outcome`` fails: the pin
    cannot prove it. An f-string whose head is ``success`` is not the literal.
(B) Inverse net. Every write anywhere in src whose static ``event_type`` starts with
    ``LOCKOUT_EVENT_PREFIX`` is inside a gated def, inside the funnels, or in
    ``_UNGATED_LOGIN_WRITERS``. This is what makes (A)'s scope a proof, not a sample.
(C) Every gated surface reaches ``record_login_failure``, so a gated surface cannot reject
    every guess with no counted row.
(D) Behaviour: a row written by the funnel counts toward the lockout.

The event prefix is ``login_guard.LOCKOUT_EVENT_PREFIX``, the constant the counter's SQL
``LIKE`` is built from (PD-5), never re-typed here; the funnel's own ``event_type=``
f-string head must equal it. Allow-list keys are ``(relpath, enclosing def chain,
outcome)``: line-stable, and unambiguous where two handlers each nest a ``_consume``.

Scope limit: a login surface with no gate, no ``/login`` or ``/auth`` route and no
``login_`` event name is outside every net. Cross-module hops resolve only through
``from email_triage... import`` names, not through a module attribute (``wa.verify``).
(C) proves that a gated surface reaches ``record_login_failure``, not that every reject
branch does: a future branch that rejects silently stays green. Reviewed out of scope as
non-guessable (panel X): ``auth.verify_api_key`` (``token_urlsafe(32)``), the loopback ops
token (``web/routers/health.py``, ``compare_digest``), the webhook HMAC
(``web/events.py``), the O365 clientState (``web/routers/webhooks.py``).
"""

from __future__ import annotations

import ast
import copy
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from _pin_harness import parse_source, walk_src

from email_triage.web import login_guard, mfa

_WRITERS = frozenset({"record_auth_event", "record_auth_event_txn"})
_GUARD_MODULE = "web/login_guard.py"
_FAILURE_FUNNEL = "record_login_failure"
_FUNNELS = frozenset({_FAILURE_FUNNEL, "record_login_lockout"})
_GATE = "check_login_allowed"
_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "api_route"})
_LOGIN_ROUTE = re.compile(r"^/(login|auth)(/|$)")

# (relpath, enclosing def chain, static outcome) -> why a guess cannot reach this row.
# Reviewed by panel U hipaa NOTE-H2. A new entry is a security decision.
_NON_GUESSABLE = {
    ("web/routers/auth_keys.py", "login_webauthn_finish._verify_webauthn", "denied:stale_challenge"):
        "a pre-v53 challenge row (NULL stored UV requirement; WebAuthnStaleChallengeError); "
        "no client can author one, and it lives at most one challenge TTL after the upgrade. "
        "An absent or EXPIRED challenge is a different, attacker-reachable class and must keep "
        "counting (panel X db-sme X2 SHOULD-2)",
    ("web/routers/auth_keys.py", "login_passkey_finish._verify_passkey", "denied:stale_challenge"):
        "same as login_webauthn_finish: only a pre-v53 challenge row, never an expired one",
    ("web/routers/ui/users.py", "login_verify._login_verify_db_work._login_witness",
     "denied:otp_already_used"):
        "written only when the code MATCHED (classify_otp read it unused) and a concurrent "
        "write spent it first: another verify, a fresh OTP request "
        "(web/auth.py::store_otp) or the expiry purge "
        "(web/auth.py::cleanup_expired_otps); so reaching it needs the valid OTP; a later "
        "replay of a "
        "spent code no longer matches and keeps its counting failure row (s2h-order, "
        "hipaa-sme 2026-11-06)",
    ("web/routers/ui/users.py", "login_verify._login_verify_db_work", "denied:mfa_required"):
        "written only after verify_otp accepted the code; reaching it needs the valid OTP",
    ("web/routers/ui/users.py", "login_verify._login_verify_db_work", "denied:user_not_found"):
        "written only after verify_otp accepted the code (punch 687, panel Z MUST-Z1-2)",
    ("web/routers/ui/users.py", "login_verify._login_verify_db_work", "denied:account_disabled"):
        "written only after verify_otp accepted the code (punch 687, panel Z MUST-Z1-2)",
    ("web/routers/auth_keys.py", "_consume_operator_recovery._consume", "denied:token_invalid_or_expired"):
        "single-use operator token, secrets.token_hex(OPERATOR_RECOVERY_TOKEN_BYTES), "
        "pinned >= 16 bytes = 128 bits below; outside the funnel by design "
        "(record_login_failure docstring)",
    ("web/routers/auth_keys.py", "_consume_operator_recovery._consume", "denied:user_disabled_or_missing"):
        "reached only after a valid operator token was consumed",
    ("web/dependencies.py", "_audit_bearer_refusal", "denied:"):
        "punch 420: a refused api-key Bearer or route-fence attempt (event_type api_key_auth / "
        "api_key_scope / role_route_fence, none starting with the lockout prefix 'login_', so no "
        "row here is counted or countable toward a login lockout). The credential is a 256-bit "
        "generate_api_key token, not a guessable secret, and the write rate is bounded per source "
        "by _route_scope.refusal_audit_verdict. Reached from get_current_user, so the closure "
        "from a login route sees it; the reason slug after 'denied:' is a closed set, and "
        "_CLOSED_REASON_SETS below makes that a code fact the scan checks (key_not_accepted, "
        "the ScopeRefused reasons, audit_rate_capped; anything else is 'unclassified')",
}

# An f-string-headed ``_NON_GUESSABLE`` entry (``f"denied:{reason}"``) waives the rule that a
# non-static outcome fails, for EVERY value of the interpolation. It is admitted only while the
# interpolated name is provably confined to a closed set (cycle Q DA S2): the entry's key maps to
# (interpolated name, module-level literal frozenset, fallback constant). The scan checks that
# the outcome is exactly f"<head>{name}", that the set is a literal frozenset of strings, that the
# enclosing def maps a name outside the set to the fallback BEFORE the write, and that no other
# assignment to the name can leave the set. A new prefix-keyed entry with no row here fails.
_CLOSED_REASON_SETS = {
    ("web/dependencies.py", "_audit_bearer_refusal", "denied:"):
        ("reason", "_BEARER_REFUSAL_REASONS", "unclassified"),
}

# (relpath, enclosing def chain) -> why this login_* writer needs no lockout gate.
_UNGATED_LOGIN_WRITERS = {
    ("web/routers/auth_keys.py", "_consume_operator_recovery._consume"):
        "128-bit single-use operator token; not a brute-forceable surface "
        "(record_login_failure docstring)",
}

_FuncDef = (ast.FunctionDef, ast.AsyncFunctionDef)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _static(node: ast.expr | None) -> str | None:
    """A string literal, or the leading literal part of an f-string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        head = node.values[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return head.value
    return None


def _kw(call: ast.Call, arg: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == arg), None)


def _writer_sites(root: ast.AST):
    """Every auth-event write under ``root``: a direct call, or a call that hands a
    writer to a dispatcher (``db_call(record_auth_event, db, outcome=...)``). The
    returned call carries the writer's keywords either way."""
    for c in ast.walk(root):
        if not isinstance(c, ast.Call):
            continue
        if _name(c.func) in _WRITERS:
            yield c
        elif any(isinstance(a, (ast.Name, ast.Attribute)) and _name(a) in _WRITERS for a in c.args):
            yield c


def _called_names(fn: ast.AST) -> set[str]:
    """Names called under ``fn``, plus names handed to a dispatcher (``db_call(f, ...)``)."""
    out: set[str] = set()
    for c in ast.walk(fn):
        if isinstance(c, ast.Call):
            out.add(_name(c.func))
            out |= {_name(a) for a in c.args if isinstance(a, (ast.Name, ast.Attribute))}
    return out


def _reaching(tree: ast.AST, target: str) -> set[int]:
    """ids of the defs that call ``target`` (nested defs, lambdas and dispatcher hand-offs
    included), or that call a top-level def of this module that does, to a fixpoint.
    Keyed by node, not by name: the harness ``reachers_of`` keys by name, so two nested
    ``_consume`` defs would share one verdict and an ungated one would read as gated."""
    fns = [f for f in ast.walk(tree) if isinstance(f, _FuncDef)]
    top = {f.name: f for f in getattr(tree, "body", ()) if isinstance(f, _FuncDef)}
    called = {id(f): _called_names(f) for f in fns}
    reach = {id(f) for f in fns if target in called[id(f)]}
    changed = True
    while changed:
        changed = False
        for f in fns:
            if id(f) not in reach and any(id(top[n]) in reach for n in called[id(f)] if n in top):
                reach.add(id(f))
                changed = True
    return reach


def _enclosing_defs(node: ast.AST):
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, _FuncDef):
            yield cur
        cur = getattr(cur, "_ph_parent", None)


def _def_path(node: ast.AST) -> str:
    """Line-stable key: the enclosing def chain, outermost first (``login_verify._work``)."""
    return ".".join(reversed([d.name for d in _enclosing_defs(node)])) or "<module>"


def _module_dotted(rel: str) -> str:
    return "email_triage." + rel[:-3].replace("/", ".").removesuffix(".__init__")


def _is_login_route(fn: ast.AST) -> bool:
    for d in getattr(fn, "decorator_list", ()):
        if isinstance(d, ast.Call) and _name(d.func) in _ROUTE_METHODS and d.args:
            path = _static(d.args[0])
            if path is not None and _LOGIN_ROUTE.match(path):
                return True
    return False


def _funnel_event_prefix(modules: dict[str, ast.AST]) -> str:
    tree = modules[_GUARD_MODULE]
    fn = next(f for f in ast.walk(tree) if isinstance(f, _FuncDef) and f.name == _FAILURE_FUNNEL)
    prefixes = {_static(_kw(c, "event_type")) for c in _writer_sites(fn)}
    assert len(prefixes) == 1 and None not in prefixes, (
        f"{_FAILURE_FUNNEL} must write one static event_type prefix; got {prefixes}"
    )
    return prefixes.pop()


def _literal_str_frozenset(tree: ast.AST, set_name: str) -> set[str] | None:
    """The members of module-level ``set_name = frozenset({"a", "b"})``, or ``None`` when it
    is not exactly that (a computed set, a set built from a variable, an empty set)."""
    members = None
    for stmt in getattr(tree, "body", ()):
        if isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == set_name for t in stmt.targets
        ):
            value = stmt.value
        elif (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
              and stmt.target.id == set_name):
            value = stmt.value
        else:
            continue
        if (isinstance(value, ast.Call) and _name(value.func) == "frozenset"
                and len(value.args) == 1 and not value.keywords
                and isinstance(value.args[0], ast.Set) and value.args[0].elts
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                        for e in value.args[0].elts)):
            members = {e.value for e in value.args[0].elts}
        else:
            return None
    return members


def _closed_set_problem(tree: ast.AST, site: ast.Call, spec: tuple[str, str, str]) -> str | None:
    """Why an f-string-headed outcome is not confined to a closed set; ``None`` when it is."""
    var, set_name, fallback = spec
    node = _kw(site, "outcome")
    fmt = node.values[1] if isinstance(node, ast.JoinedStr) and len(node.values) == 2 else None
    if not (isinstance(fmt, ast.FormattedValue) and isinstance(fmt.value, ast.Name)
            and fmt.value.id == var and fmt.conversion == -1 and fmt.format_spec is None):
        return f"the outcome is not exactly f'<head>{{{var}}}'"
    members = _literal_str_frozenset(tree, set_name)
    if members is None:
        return f"{set_name} is not a module-level literal frozenset of strings"
    fn = next(_enclosing_defs(site), None)
    if fn is None:
        return "the write is not inside a def"
    guarded = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.If) and n.lineno < site.lineno
                and isinstance(n.test, ast.Compare) and len(n.test.ops) == 1
                and isinstance(n.test.ops[0], ast.NotIn)
                and isinstance(n.test.left, ast.Name) and n.test.left.id == var
                and isinstance(n.test.comparators[0], ast.Name)
                and n.test.comparators[0].id == set_name
                and any(isinstance(s, ast.Assign) and isinstance(s.value, ast.Constant)
                        and s.value.value == fallback
                        and any(isinstance(t, ast.Name) and t.id == var for t in s.targets)
                        for s in n.body)):
            guarded = True
    if not guarded:
        return f"no `if {var} not in {set_name}: {var} = {fallback!r}` guard before the write"
    for n in ast.walk(fn):
        targets = (n.targets if isinstance(n, ast.Assign)
                   else [n.target] if isinstance(n, (ast.AugAssign, ast.AnnAssign)) else [])
        if not any(isinstance(t, ast.Name) and t.id == var for t in targets):
            continue
        ok = (isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              and isinstance(n.value.value, str) and (n.value.value in members
                                                      or n.value.value == fallback))
        if not ok:
            return f"line {n.lineno} assigns {var} something that may leave {set_name}"
    return None


@dataclass
class Scan:
    route_hits: int = 0
    route_bad: list[str] = field(default_factory=list)
    ungated_bad: list[str] = field(default_factory=list)
    unrouted: list[str] = field(default_factory=list)
    allow_used: set = field(default_factory=set)
    ungated_used: set = field(default_factory=set)
    gated_roots: int = 0


def scan(modules: dict[str, ast.AST]) -> Scan:
    """Run invariants (A), (B) and (C) over ``{relpath: annotated tree}``."""
    prefix = login_guard.LOCKOUT_EVENT_PREFIX
    funnel_prefix = _funnel_event_prefix(modules)
    assert funnel_prefix == prefix, (
        f"{_FAILURE_FUNNEL} writes event_type prefix {funnel_prefix!r}, but the lockout "
        f"counter counts LOCKOUT_EVENT_PREFIX {prefix!r}"
    )
    defs: dict[tuple[str, str], list[ast.AST]] = {}
    for rel, tree in modules.items():
        for fn in ast.walk(tree):
            if isinstance(fn, _FuncDef):
                defs.setdefault((rel, fn.name), []).append(fn)
    by_dotted = {_module_dotted(rel): rel for rel in modules}

    def funnel(rel: str, fn: ast.AST) -> bool:
        return rel == _GUARD_MODULE and fn.name in _FUNNELS

    def bindings(rel: str, tree: ast.AST) -> dict[str, tuple[str, str]]:
        """Local name -> (relpath, def name) for every call target this module can
        reach by name: its own defs, and ``from email_triage... import`` names."""
        out = {name: (r, name) for (r, name) in defs if r == rel}
        for imp in ast.walk(tree):
            if isinstance(imp, ast.ImportFrom) and imp.module in by_dotted:
                target = by_dotted[imp.module]
                for a in imp.names:
                    if (target, a.name) in defs:
                        out[a.asname or a.name] = (target, a.name)
        return out

    gated: set[int] = set()
    roots: list[tuple[str, ast.AST]] = []
    result = Scan()
    for rel, tree in modules.items():
        reach = _reaching(tree, _GATE)
        gated |= reach
        for fn in ast.walk(tree):
            if isinstance(fn, _FuncDef) and (id(fn) in reach or _is_login_route(fn)):
                roots.append((rel, fn))

    # Down-closure over call targets reachable by name (PD-2: the hop through a helper).
    scope: dict[int, tuple[str, ast.AST]] = {}
    stack = list(roots)
    while stack:
        rel, fn = stack.pop()
        if id(fn) in scope or funnel(rel, fn) or fn.name in _WRITERS:
            continue
        scope[id(fn)] = (rel, fn)
        bound = bindings(rel, modules[rel])
        for n in _called_names(fn) & set(bound):
            stack += [(bound[n][0], d) for d in defs[bound[n]]]

    # (A) route.
    seen: set[int] = set()
    for rel, fn in scope.values():
        for site in _writer_sites(fn):
            if id(site) in seen:
                continue
            seen.add(id(site))
            result.route_hits += 1
            node = _kw(site, "outcome")
            if isinstance(node, ast.Constant) and node.value == "success":
                continue
            outcome = _static(node)
            key = (rel, _def_path(site), outcome)
            if key in _NON_GUESSABLE:
                result.allow_used.add(key)
                if isinstance(node, ast.JoinedStr):
                    spec = _CLOSED_REASON_SETS.get(key)
                    problem = (
                        "an f-string-headed _NON_GUESSABLE entry names no closed set in "
                        "_CLOSED_REASON_SETS" if spec is None
                        else _closed_set_problem(modules[rel], site, spec)
                    )
                    if problem:
                        result.route_bad.append(
                            f"{rel}:{site.lineno} in {key[1]} outcome={ast.unparse(node)}: {problem}"
                        )
                continue
            shown = ast.unparse(node) if node is not None else "<missing>"
            result.route_bad.append(f"{rel}:{site.lineno} in {key[1]} outcome={shown}")

    # (B) inverse net.
    for rel, tree in modules.items():
        for site in _writer_sites(tree):
            et = _static(_kw(site, "event_type"))
            if et is None or not et.startswith(prefix):
                continue
            chain = list(_enclosing_defs(site))
            if any(funnel(rel, d) for d in chain) or any(id(d) in gated for d in chain):
                continue
            key = (rel, _def_path(site))
            if key in _UNGATED_LOGIN_WRITERS:
                result.ungated_used.add(key)
                continue
            result.ungated_bad.append(f"{rel}:{site.lineno} in {key[1]} event_type={et!r}")

    # (C) every gated surface reaches the failure funnel.
    for rel, tree in modules.items():
        routed = _reaching(tree, _FAILURE_FUNNEL)
        for fn in ast.walk(tree):
            if not isinstance(fn, _FuncDef) or id(fn) not in gated:
                continue
            if any(id(d) in gated for d in _enclosing_defs(fn)):
                continue  # judged with its outermost gated def
            result.gated_roots += 1
            if id(fn) not in routed:
                result.unrouted.append(f"{rel}:{fn.lineno} {fn.name}")
    return result


def _live_modules() -> dict[str, ast.AST]:
    return {rel: tree for _path, rel, tree in walk_src()}


def test_every_login_failure_routes_through_the_lockout_funnel():
    res = scan(_live_modules())
    assert res.route_hits and res.gated_roots, "the scan found no login scope: the net is broken"
    assert not res.route_bad, (
        "login-scope auth events with a non-success outcome outside record_login_failure / "
        "record_login_lockout never count toward a lockout. Route the failure through "
        "record_login_failure, or add a reviewed _NON_GUESSABLE entry:\n" + "\n".join(res.route_bad)
    )
    assert not res.ungated_bad, (
        "login_* auth events written outside any check_login_allowed def: an ungated login "
        "surface. Gate it, or add a reviewed _UNGATED_LOGIN_WRITERS entry:\n"
        + "\n".join(res.ungated_bad)
    )
    assert not res.unrouted, (
        "gated login surfaces that never reach record_login_failure:\n" + "\n".join(res.unrouted)
    )


def test_allow_lists_are_not_stale():
    res = scan(_live_modules())
    assert set(_NON_GUESSABLE) - res.allow_used == set(), "stale _NON_GUESSABLE entries"
    assert set(_UNGATED_LOGIN_WRITERS) - res.ungated_used == set(), "stale _UNGATED_LOGIN_WRITERS entries"


def test_the_operator_token_behind_the_allow_lists_stays_128_bits():
    """The two ``_consume_operator_recovery`` rows are non-guessable only while the token
    has at least 128 bits. Lowering the constant makes them a free guess (panel X DA-X2-2)."""
    assert mfa.OPERATOR_RECOVERY_TOKEN_BYTES >= 16, (
        f"OPERATOR_RECOVERY_TOKEN_BYTES={mfa.OPERATOR_RECOVERY_TOKEN_BYTES} < 16: the "
        "operator-token _NON_GUESSABLE and _UNGATED_LOGIN_WRITERS entries no longer hold"
    )


def test_teeth_a_short_operator_token_is_caught(monkeypatch):
    monkeypatch.setattr(mfa, "OPERATOR_RECOVERY_TOKEN_BYTES", 8)
    with pytest.raises(AssertionError, match="OPERATOR_RECOVERY_TOKEN_BYTES=8"):
        test_the_operator_token_behind_the_allow_lists_stays_128_bits()


def test_a_funnel_row_counts_toward_the_lockout():
    from email_triage.config import AuthConfig, TriageConfig
    from email_triage.web.db import init_db
    from email_triage.web.login_guard import LoginLocked, check_login_allowed, record_login_failure

    db = init_db(":memory:")
    try:
        cfg = TriageConfig()
        cfg.auth = AuthConfig(login_per_email_max=2, login_per_ip_max=0)
        for _ in range(2):
            record_login_failure(
                db, surface="otp", email="a@example.com", ip="10.0.0.1",
                user_agent="pytest", reason="invalid_code",
            )
        with pytest.raises(LoginLocked):
            check_login_allowed(
                db, email="a@example.com", ip="10.0.0.1", config=cfg,
                now=datetime.now(timezone.utc),
            )
    finally:
        db.close()


_GUARD_STUB = (
    "def record_login_failure(db, *, surface, reason):\n"
    "    record_auth_event(db, event_type=f'login_{surface}', outcome='failure')\n"
    "def record_login_lockout(db, *, surface):\n"
    "    record_auth_event(db, event_type='login_lockout', outcome='failure')\n"
)


def _planted(handler: str) -> dict[str, ast.AST]:
    return {_GUARD_MODULE: parse_source(_GUARD_STUB), "web/routers/x.py": parse_source(handler)}


def test_teeth_a_denied_login_failure_is_caught_and_the_funnel_is_clean():
    bad = scan(_planted(
        "def login_x(db):\n"
        "    check_login_allowed(db)\n"
        "    record_auth_event(db, event_type='login_x', outcome='denied:bad_code')\n"
    ))
    assert len(bad.route_bad) == 1 and "denied:bad_code" in bad.route_bad[0]
    good = scan(_planted(
        "def login_x(db):\n"
        "    check_login_allowed(db)\n"
        "    record_login_failure(db, surface='x', reason='bad_code')\n"
        "    record_auth_event(db, event_type='login_x', outcome='success')\n"
    ))
    assert not (good.route_bad or good.ungated_bad or good.unrouted)


def test_teeth_hops_through_a_helper_a_dispatcher_and_a_route():
    res = scan(_planted(
        "def _deny(db, why):\n"
        "    db_call(record_auth_event, db, event_type='sso', outcome=f'denied:{why}')\n"
        "def login_x(db):\n"
        "    check_login_allowed(db)\n"
        "    record_login_failure(db, surface='x', reason='r')\n"
        "    _deny(db, 'r')\n"
        "@router.post('/auth/sso')\n"
        "def sso(db, out):\n"
        "    safe_audit_write(lambda: record_auth_event(db, event_type='sso', outcome=out))\n"
    ))
    assert len(res.route_bad) == 2
    assert any("_deny" in b for b in res.route_bad) and any("outcome=out" in b for b in res.route_bad)


def test_teeth_an_ungated_login_writer_and_a_row_less_gated_surface():
    res = scan(_planted(
        "def magic_link(db):\n"
        "    record_auth_event(db, event_type='login_magic', outcome='success')\n"
        "def login_y(db):\n"
        "    check_login_allowed(db)\n"
        "    raise PermissionError('bad code')\n"
    ))
    assert len(res.ungated_bad) == 1 and "magic_link" in res.ungated_bad[0]
    assert len(res.unrouted) == 1 and "login_y" in res.unrouted[0]


def test_teeth_a_same_named_nested_def_does_not_borrow_the_gate():
    res = scan(_planted(
        "def gated(db):\n"
        "    def _consume():\n"
        "        check_login_allowed(db)\n"
        "        record_login_failure(db, surface='x', reason='r')\n"
        "    return db_call(_consume)\n"
        "def ungated(db):\n"
        "    def _consume():\n"
        "        record_auth_event(db, event_type='login_y', outcome='success')\n"
        "    return db_call(_consume)\n"
    ))
    assert len(res.ungated_bad) == 1 and "ungated._consume" in res.ungated_bad[0]


def test_teeth_an_f_string_headed_success_is_not_a_success():
    res = scan(_planted(
        "def login_x(db, why):\n"
        "    check_login_allowed(db)\n"
        "    record_login_failure(db, surface='x', reason='r')\n"
        "    record_auth_event(db, event_type='login_x', outcome=f'success{why}')\n"
    ))
    assert len(res.route_bad) == 1 and "success{why}" in res.route_bad[0], res.route_bad


def test_teeth_a_funnel_prefix_off_the_counter_constant_is_caught():
    stub = _GUARD_STUB.replace("f'login_{surface}'", "f'signin_{surface}'")
    modules = {_GUARD_MODULE: parse_source(stub), "web/routers/x.py": parse_source("")}
    with pytest.raises(AssertionError, match="LOCKOUT_EVENT_PREFIX 'login_'"):
        scan(modules)


def test_mutation_the_real_otp_failure_rewritten_as_a_denial_is_caught():
    """Mutate the live tree: the OTP ``invalid_code`` funnel call becomes a direct
    ``denied:`` write. The scan must report exactly that one site."""
    modules = _live_modules()
    rel = "web/routers/ui/users.py"
    tree = copy.deepcopy(modules[rel])
    target = next(
        c for c in ast.walk(tree)
        if isinstance(c, ast.Call) and _name(c.func) == _FAILURE_FUNNEL
        and _static(_kw(c, "reason")) == "invalid_code"
    )
    target.func = ast.Name(id="record_auth_event", ctx=ast.Load())
    target.keywords = [k for k in target.keywords if k.arg not in {"surface", "reason"}] + [
        ast.keyword(arg="event_type", value=ast.Constant("login_otp")),
        ast.keyword(arg="outcome", value=ast.Constant("denied:invalid_code")),
    ]
    modules[rel] = parse_source(ast.unparse(tree))
    res = scan(modules)
    assert len(res.route_bad) == 1 and "denied:invalid_code" in res.route_bad[0], res.route_bad


# ---------------------------------------------------------------------------
# the closed reason set behind the f-string-headed ``denied:`` entry (cycle Q DA S2)
# ---------------------------------------------------------------------------

_BEARER_MODULE = "web/dependencies.py"
_BEARER_GUARD = (
    "    if reason not in _BEARER_REFUSAL_REASONS:\n"
    "        reason = 'unclassified'\n"
)


def _bearer(*, sets="frozenset({'a', 'b'})", guard=_BEARER_GUARD, after="", outcome="f'denied:{reason}'"):
    """A planted dependencies module: a gated login def that reaches ``_audit_bearer_refusal``."""
    src = (
        f"_BEARER_REFUSAL_REASONS = {sets}\n"
        "def login_x(db):\n"
        "    check_login_allowed(db)\n"
        "    record_login_failure(db, surface='x', reason='r')\n"
        "    _audit_bearer_refusal(db, reason='a')\n"
        "def _audit_bearer_refusal(db, *, reason):\n"
        f"{guard}"
        f"{after}"
        "    safe_audit_write(lambda: record_auth_event(\n"
        f"        db, event_type='api_key_auth', outcome={outcome}))\n"
    )
    return {_GUARD_MODULE: parse_source(_GUARD_STUB), _BEARER_MODULE: parse_source(src)}


def test_the_live_denied_entry_is_confined_to_its_closed_set():
    res = scan(_live_modules())
    assert not res.route_bad, res.route_bad
    assert set(_CLOSED_REASON_SETS) <= set(_NON_GUESSABLE), "a closed-set row with no entry"
    assert set(_CLOSED_REASON_SETS) <= res.allow_used, "a closed-set row nothing uses"


def test_teeth_the_closed_set_is_checked_not_assumed():
    assert not scan(_bearer()).route_bad
    # No guard: any reason string reaches the outcome.
    bad = scan(_bearer(guard="")).route_bad
    assert len(bad) == 1 and "guard" in bad[0], bad
    # The guard tests membership in a set that is not a literal.
    bad = scan(_bearer(sets="frozenset(compute())")).route_bad
    assert len(bad) == 1 and "literal frozenset" in bad[0], bad
    # The guard maps to something other than the fallback.
    bad = scan(_bearer(guard=_BEARER_GUARD.replace("'unclassified'", "'a'"))).route_bad
    assert len(bad) == 1 and "guard" in bad[0], bad
    # The name is reassigned from outside the set after the guard.
    bad = scan(_bearer(after="    reason = lookup(db)\n")).route_bad
    assert len(bad) == 1 and "may leave" in bad[0], bad
    # ... but a reassignment to a member of the set is fine.
    assert not scan(_bearer(after="    reason = 'b'\n")).route_bad
    # The outcome interpolates something other than the guarded name.
    bad = scan(_bearer(outcome="f'denied:{reason.upper()}'")).route_bad
    assert len(bad) == 1 and "not exactly" in bad[0], bad
    bad = scan(_bearer(outcome="f'denied:{reason}x'")).route_bad
    assert len(bad) == 1 and "not exactly" in bad[0], bad


def test_teeth_a_prefix_keyed_entry_with_no_closed_set_row_fails(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "_CLOSED_REASON_SETS", {})
    bad = scan(_live_modules()).route_bad
    assert len(bad) == 1 and "names no closed set" in bad[0], bad


def test_mutation_the_real_bearer_guard_removed_is_caught():
    """Mutate the live tree: delete the ``reason not in _BEARER_REFUSAL_REASONS`` guard from
    the real ``_audit_bearer_refusal``. The scan must report exactly that one site."""
    modules = _live_modules()
    tree = copy.deepcopy(modules[_BEARER_MODULE])
    fn = next(f for f in ast.walk(tree)
              if isinstance(f, _FuncDef) and f.name == "_audit_bearer_refusal")
    kept = [s for s in fn.body if not (
        isinstance(s, ast.If) and isinstance(s.test, ast.Compare)
        and isinstance(s.test.ops[0], ast.NotIn))]
    assert len(kept) == len(fn.body) - 1, "the real guard was not found: the mutation is vacuous"
    fn.body = kept
    modules[_BEARER_MODULE] = parse_source(ast.unparse(tree))
    bad = scan(modules).route_bad
    assert len(bad) == 1 and "_audit_bearer_refusal" in bad[0] and "guard" in bad[0], bad
