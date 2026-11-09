"""PD#1/#2/#6 pin (N-535..N-537, punch ): a credential's route scope and the
``health_ro`` role allowlist are enforced at the ONE auth seam, for EVERY route.

WHAT THE THREE ARMS PROVE, AND WHY THREE
========================================
The claim is "a scoped key / a ``health_ro`` principal cannot reach any route
outside its scope, **including a route added next year**". No single arm proves
that, so the pin is a conjunction and each arm names what it cannot see:

* **Arm A — structural (``test_bearer_seam_*``).** The bearer-resolution chain is
  single-caller at every hop and the ONE funnel routes through the fence. This is
  the arm that makes the claim hold for a route that does not exist yet: the fence
  is not per-route, so there is nothing for a future author to forget. It cannot
  see whether the fence's *logic* is right.
* **Arm B — the decision walk (``test_*_refuses_every_route_outside_*``).** Walks
  EVERY ``(method, path)`` in the live route table (310 at time of writing) and
  asserts the fence's own decision function refuses each one outside the grant.
  Count-agnostic: the route table is enumerated, never a hand-listed sample, and
  no count is asserted. It calls the decision function directly, so it can run on
  mutating methods with zero side effects — it cannot see whether the decision is
  actually WIRED into the request path.
* **Arm C — live HTTP (``test_live_*``).** Real requests through the real app, so
  the wiring is proved end to end.

**SCOPE CAVEAT (R38) — what a green run does NOT prove.**
Arm C covers **GET routes only**. Firing 90+ real POST/DELETE/PUT requests at a
live app to prove a *negative* would exercise handlers like
``POST /ops/db-backup`` and the admin restart path; if the fence ever regressed,
the "proof" run would be the thing that triggered them. Mutating methods are
covered by Arm B (every method, no side effects) plus Arm A (the wiring is
method-agnostic by construction). If you widen Arm C to mutating methods, gate it
behind a fixture that proves CSRF enforcement is ON first, so the request cannot
reach a handler.
Arm B's route walk sees only routes registered on the app under test; a route
added by a plugin/mount at runtime is outside it.
Nothing here pins the CONTENT of ``HEALTH_RO_ALLOWED_ROUTES`` beyond the two
exclusions asserted in ``test_allowlist_excludes_*`` — widening that constant is a
deliberate act and the SME panel is the gate on it, not this pin.
"""

from __future__ import annotations

import ast
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from _pin_harness import (
    SRC_ROOT,
    enclosing_fn,
    iter_app_routes,
    parse_module,
    relpath,
    walk_src,
)
from email_triage._isotime import to_utc_iso
from email_triage.engine.models import UserRole
from email_triage.web._route_scope import (
    API_ONLY_ROLES,
    HEALTH_RO_ALLOWED_ROUTES,
    ScopeRefused,
    SessionMintRefused,
    check_principal_fences,
    parse_key_scope,
    route_key,
    scope_permits,
)
from email_triage.web.auth import (
    create_session_token,
    generate_api_key,
    hash_api_key,
    store_api_key as _store_api_key,
    verify_api_key,
)


def store_api_key(db, *args, **kwargs):
    """The grant funnel refuses an unattributed mint (punch 710, N-644), so every
    fixture grant in this pin names an actor, as the real CLI and UI callers do."""
    kwargs.setdefault("actor_email", "test:n535-pin")
    kwargs.setdefault("source", "test")
    return _store_api_key(db, *args, **kwargs)


_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")

# The scope the cve-arc monitoring credential will carry. Used as the
# REPRESENTATIVE scoped grant throughout; the arms assert over the route table's
# complement of it, so the choice of grant does not weaken any assertion.
_MONITOR_SCOPE = ("GET /health/build", "GET /health/runtime-deps")


def _fill_params(path: str) -> str:
    """Substitute ``{id}``-style path params with a dummy ``1``.

    The fence fires before any handler business logic, so the dummy never reaches
    it. Mirrors the CSRF route-coverage pin's helper.
    """
    return _PATH_PARAM_RE.sub("1", path)


class _StubURL:
    def __init__(self, path: str) -> None:
        self.path = path


class _StubRequest:
    """The minimum surface ``check_principal_fences`` reads: method, url.path, scope.

    Deliberately NOT a real ``Request``: Arm B must be able to ask the decision
    "would you refuse DELETE /accounts/1?" without a DELETE ever happening.
    """

    def __init__(self, method: str, path: str) -> None:
        self.method = method
        self.url = _StubURL(path)
        self.scope = {}


def _scoped_principal(scope_entries) -> dict:
    return {
        "id": 42,
        "email": "monitor@test.com",
        "role": UserRole.USER.value,
        "auth_method": "api_key",
        "key_name": "cve-arc-monitor",
        "api_key_id": 7,
        "api_key_scope": json.dumps(list(scope_entries)),
    }


def _health_ro_principal(auth_method: str = "api_key") -> dict:
    return {
        "id": 43,
        "email": "health-ro@test.com",
        "role": UserRole.HEALTH_RO.value,
        "auth_method": auth_method,
        "key_name": "cve-arc-monitor",
        "api_key_id": 8,
        "api_key_scope": None,
    }


def _refuses(user: dict, method: str, path: str) -> bool:
    try:
        check_principal_fences(_StubRequest(method, _fill_params(path)), user)
    except ScopeRefused:
        return True
    return False


# ===========================================================================
# Arm A — structural: ONE bearer seam, and it routes through the fence
# ===========================================================================

def _calls_in_function(tree, funcname: str) -> set[str]:
    """Every called NAME (``f()`` and ``a.f()``) inside ``funcname``'s body."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if enclosing_fn(node) != funcname:
            continue
        fn = node.func
        if isinstance(fn, ast.Name):
            out.add(fn.id)
        elif isinstance(fn, ast.Attribute):
            out.add(fn.attr)
    return out


def test_bearer_seam_is_single_caller_at_every_hop():
    """``verify_api_key`` has exactly ONE call site in src, and so does
    ``_check_bearer_token``.

    This is what makes the fence universal: if a second module ever resolves a
    Bearer api key on its own, it bypasses ``get_current_user`` and therefore the
    fence — and the new route would be unfenced with nothing else objecting.
    Count-agnostic: the property is "exactly one call site", asserted by scanning
    EVERY module, not by checking a named list of files.
    """
    callers: dict[str, list[str]] = {"verify_api_key": [], "_check_bearer_token": []}
    for path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None
            )
            if name in callers:
                callers[name].append(f"{rel}:{node.lineno} in {enclosing_fn(node)}")

    assert len(callers["verify_api_key"]) == 1, (
        "verify_api_key must have EXACTLY ONE call site. Found: "
        f"{callers['verify_api_key']}. A second bearer-resolution site bypasses "
        "get_current_user and therefore the #420 route-scope fence — and the "
        "route it serves would be unfenced with nothing else objecting."
    )
    assert callers["verify_api_key"][0].startswith("web/dependencies.py:"), (
        f"verify_api_key's one call site moved out of web/dependencies.py: "
        f"{callers['verify_api_key']}"
    )
    assert callers["verify_api_key"][0].endswith("in _check_bearer_token"), (
        f"verify_api_key is no longer called from _check_bearer_token: "
        f"{callers['verify_api_key']}"
    )
    assert len(callers["_check_bearer_token"]) == 1, (
        "_check_bearer_token must have EXACTLY ONE call site (get_current_user). "
        f"Found: {callers['_check_bearer_token']}"
    )
    assert callers["_check_bearer_token"][0].endswith("in get_current_user"), (
        f"_check_bearer_token is no longer called from get_current_user — the "
        f"fence's funnel changed: {callers['_check_bearer_token']}"
    )


def test_get_current_user_routes_both_auth_paths_through_the_fence():
    """Both ``return`` paths of ``get_current_user`` go through ``_fence_or_403``.

    The bearer arm and the session-cookie arm each return a resolved principal, so
    a fence applied to only one of them leaves the other unguarded — the exact
    half-applied shape R37 says to widen. Asserted on the AST rather than by
    behaviour so a future third auth arm fails HERE instead of shipping unfenced.
    """
    tree = parse_module(SRC_ROOT / "web" / "dependencies.py")
    assert tree is not None
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "get_current_user":
            target = node
    assert target is not None, "get_current_user not found in web/dependencies.py"

    returns = [
        n for n in ast.walk(target)
        if isinstance(n, ast.Return) and n.value is not None
        and not (isinstance(n.value, ast.Constant) and n.value.value is None)
    ]
    assert returns, "get_current_user returns nothing but None — pin is vacuous"
    for ret in returns:
        assert isinstance(ret.value, ast.Call) and getattr(
            ret.value.func, "id", None
        ) == "_fence_or_403", (
            f"web/dependencies.py:{ret.lineno} — get_current_user returns a "
            "principal WITHOUT routing it through _fence_or_403. Every non-None "
            "return must pass the #420 fence, or that auth path is unfenced."
        )


def test_create_session_token_refuses_an_api_only_role():
    """The WRITE edge of the API-only-role predicate (R42's "both edges")."""
    with pytest.raises(SessionMintRefused):
        create_session_token("s" * 32, "health-ro@test.com", UserRole.HEALTH_RO.value)
    # A normal role still mints — the pin is not vacuously refusing everything.
    assert create_session_token("s" * 32, "a@test.com", UserRole.ADMIN.value)


def test_session_mint_refusal_is_mapped_to_403_not_a_500(app):
    """The refusal must READ as policy, and that is a measurement, not an intent.

    ``create_session_token`` raising is only half the story: with no handler
    registered, the exception escapes a login route as an unhandled error and the
    operator sees a 500 stack trace instead of a refusal. Asserted on the live
    app's handler registry rather than on the source, so removing the
    ``add_exception_handler`` call fails HERE.
    """
    handler = app.exception_handlers.get(SessionMintRefused)
    assert handler is not None, (
        "SessionMintRefused has no exception handler on the app — an API-only "
        "role's login attempt would surface as a 500, not a 403"
    )


def test_cli_audit_allowlist_carries_the_credential_fence_args():
    """The CLI audit row must actually CONTAIN the scope and the lifetime.

    ``_emit_cli_audit_event`` filters the argparse Namespace through a
    ``_SAFE_ARG_KEYS`` allowlist and DROPS anything unlisted, so the chained
    ``log_entries`` row for ``apikey create`` would otherwise record that a key
    was minted while omitting the two fields that say what it can reach and for
    how long. Sourced from the function's own constant rather than re-typed, so a
    rename fails here instead of silently emptying the row.
    """
    import ast as _ast
    import inspect

    from email_triage import cli as cli_mod

    tree = _ast.parse(inspect.getsource(cli_mod._emit_cli_audit_event))
    literals = {
        n.value for n in _ast.walk(tree)
        if isinstance(n, _ast.Constant) and isinstance(n.value, str)
    }
    for field in ("scope", "expires_days"):
        assert field in literals, (
            f"{field!r} is not in _emit_cli_audit_event's _SAFE_ARG_KEYS — the "
            "CLI audit row would drop it, leaving no chained record of what the "
            "minted credential could reach"
        )


# ===========================================================================
# Arm B — the decision walk over EVERY route in the live table
# ===========================================================================

def test_scoped_key_refuses_every_route_outside_its_scope(app):
    """A scoped key is refused on EVERY route in the table except its scope.

    Count-agnostic over the whole route table (PD#1) and interprocedural (PD#2):
    the decision is the seam's, so a route added later is covered without being
    named here.
    """
    user = _scoped_principal(_MONITOR_SCOPE)
    granted = {route_key(*e.split(" ", 1)) for e in _MONITOR_SCOPE}
    leaks: list[str] = []
    checked = 0
    for method, path, _mod, _name in iter_app_routes(app):
        key = route_key(method, _fill_params(path))
        if key in granted:
            continue
        checked += 1
        if not _refuses(user, method, path):
            leaks.append(key)
    assert checked > 0, "route walk found nothing — the pin would pass vacuously"
    assert leaks == [], (
        f"a key scoped to {sorted(granted)} was NOT refused on "
        f"{len(leaks)} route(s): {leaks[:20]}"
    )


def test_scoped_key_is_admitted_on_its_own_scope():
    """The good-variant half of the teeth (R38): the fence is not refuse-everything."""
    user = _scoped_principal(_MONITOR_SCOPE)
    for entry in _MONITOR_SCOPE:
        method, path = entry.split(" ", 1)
        assert not _refuses(user, method, path), f"{entry} should be admitted"


def test_health_ro_refuses_every_route_outside_the_allowlist(app):
    """A ``health_ro`` principal reaches ONLY :data:`HEALTH_RO_ALLOWED_ROUTES`."""
    user = _health_ro_principal()
    leaks: list[str] = []
    checked = 0
    for method, path, _mod, _name in iter_app_routes(app):
        key = route_key(method, _fill_params(path))
        if key in HEALTH_RO_ALLOWED_ROUTES:
            continue
        checked += 1
        if not _refuses(user, method, path):
            leaks.append(key)
    assert checked > 0, "route walk found nothing — the pin would pass vacuously"
    assert leaks == [], (
        f"a health_ro principal was NOT refused on {len(leaks)} route(s) outside "
        f"the allowlist: {leaks[:20]}"
    )


def test_every_api_only_role_has_a_route_allowlist_entry():
    """db-sme 2026-11-07: ``role_route_allowed`` returns True for a role ABSENT
    from ``ROLE_ROUTE_ALLOWLISTS`` (the fence only subtracts), so deleting the
    HEALTH_RO entry would fail OPEN while the arm-B walk above still reads the
    constant directly. Pin the map entry itself, for every API-only role
    (count-agnostic over ``API_ONLY_ROLES``), and prove absence would widen."""
    from email_triage.web._route_scope import (
        ROLE_ROUTE_ALLOWLISTS,
        role_route_allowed,
    )
    assert API_ONLY_ROLES, "API_ONLY_ROLES is empty: the scan would be vacuous"
    for role in API_ONLY_ROLES:
        assert role in ROLE_ROUTE_ALLOWLISTS, (
            f"{role!r} is API-only but has no ROLE_ROUTE_ALLOWLISTS entry: "
            "role_route_allowed would admit it to EVERY route"
        )
        allowed = ROLE_ROUTE_ALLOWLISTS[role]
        assert allowed, f"{role!r} allowlist is empty"
        assert not role_route_allowed(role, "GET", "/health/detail")
    assert ROLE_ROUTE_ALLOWLISTS[UserRole.HEALTH_RO.value] is HEALTH_RO_ALLOWED_ROUTES
    # A non-fenced role missing from the map is unrestricted here (the fence
    # only subtracts)...
    assert role_route_allowed("no-such-role", "GET", "/health/detail")


def test_an_api_only_role_missing_from_the_map_fails_closed(monkeypatch):
    """db-sme r14 SHOULD 2: if an API-only role's map entry is ever deleted,
    the fence refuses every route for it instead of admitting all (PD#8)."""
    import email_triage.web._route_scope as rs
    for role in API_ONLY_ROLES:
        trimmed = {k: v for k, v in rs.ROLE_ROUTE_ALLOWLISTS.items() if k != role}
        monkeypatch.setattr(rs, "ROLE_ROUTE_ALLOWLISTS", trimmed)
        assert not rs.role_route_allowed(role, "GET", "/health")
        assert not rs.role_route_allowed(role, "GET", "/health/detail")


def test_health_ro_is_admitted_on_the_allowlist():
    user = _health_ro_principal()
    for entry in sorted(HEALTH_RO_ALLOWED_ROUTES):
        method, path = entry.split(" ", 1)
        assert not _refuses(user, method, path), f"{entry} should be admitted"


def test_health_ro_cannot_ride_a_session_cookie():
    """The READ edge of the API-only-role predicate, on an ALLOW-LISTED route.

    Choosing an allow-listed route is the point: a refusal on
    ``GET /health/build`` can only come from the session-vs-key check, so this
    cannot pass for the wrong reason.
    """
    user = _health_ro_principal(auth_method="session")
    assert _refuses(user, "GET", "/health/build")
    assert not _refuses(_health_ro_principal("api_key"), "GET", "/health/build")


def test_allowlist_excludes_health_detail_and_every_ops_path(app):
    """``/health/detail`` and EVERY ``/ops/*`` path are outside the allowlist.

    ``/health/detail`` is the object the 2026-06-13 two-token review returned
    NO-GO on (``30b503ad``): a one-bit oracle over ~16 OR-terms plus the
    operational footprint  stripped from the unauthenticated tier. The
    ``/ops/*`` half is derived from the live route table, not a literal, so a
    SECOND ops route added later is covered without editing this test.
    """
    assert not any(
        e.endswith(" /health/detail") for e in HEALTH_RO_ALLOWED_ROUTES
    ), "/health/detail must never be in the health_ro allowlist"

    ops_routes = [
        (m, p) for m, p, _mod, _n in iter_app_routes(app) if p.startswith("/ops/")
    ]
    assert ops_routes, "no /ops/* route found — this assertion would be vacuous"
    for method, path in ops_routes:
        assert route_key(method, path) not in HEALTH_RO_ALLOWED_ROUTES
        assert _refuses(_health_ro_principal(), method, path)


def test_null_scope_grants_exactly_what_it_granted_before(app):
    """The migration's load-bearing claim: NULL scope = unchanged behaviour.

    Walks EVERY route and asserts the fence refuses NONE of them for an unscoped
    key held by an unrestricted role — i.e. adding the column changed nothing for
    every key already in the table.
    """
    user = dict(_scoped_principal(()), api_key_scope=None)
    refused = [
        route_key(method, path)
        for method, path, _mod, _name in iter_app_routes(app)
        if _refuses(user, method, path)
    ]
    assert refused == [], (
        "an UNSCOPED key was refused on "
        f"{len(refused)} route(s) — the #420 migration is not meaning-preserving: "
        f"{refused[:20]}"
    )


@pytest.mark.parametrize("bad", [
    "not json at all",
    "{}",
    "null",
    '"GET /health/build"',          # a bare string, not a list
    '["GET /health/build", 7]',     # mixed types
    '["nomethodorpath"]',           # no space separator
    '["GET nopathslash"]',          # path without a leading /
    '["GET /a", "bad entry here"]',  # ONE bad member invalidates the whole scope
    "[]",                           # deliberately inert
    "   ",
])
def test_malformed_scope_grants_nothing(app, bad):
    """PD#8: an unreadable scope grants NOTHING, never full authority.

    ``"   "`` is in the list on purpose: a whitespace-only column must read as
    UNSCOPED (it is an empty value, not a corrupt grant) — so that case is
    asserted separately below rather than lumped in with corruption.
    """
    user = dict(_scoped_principal(()), api_key_scope=bad)
    if not bad.strip():
        # Empty/whitespace = NULL-equivalent = unscoped, by design.
        assert parse_key_scope(bad) is None
        return
    assert parse_key_scope(bad) == frozenset(), f"{bad!r} must decode to no grant"
    leaks = [
        route_key(m, p)
        for m, p, _mod, _n in iter_app_routes(app)
        if not _refuses(user, m, p)
    ]
    assert leaks == [], f"scope {bad!r} granted {len(leaks)} route(s): {leaks[:10]}"


def test_scope_matching_is_exact_with_no_globs():
    """No glob may re-admit ``/health/detail`` under a ``/health`` grant."""
    globbed = parse_key_scope('["GET /health/*"]')
    assert globbed is not None
    # The literal is stored (it is a well-formed entry) but matches no real path.
    assert not scope_permits(globbed, "GET", "/health/detail")
    assert not scope_permits(globbed, "GET", "/health/build")
    # Starlette auto-adds HEAD to a GET route; a GET grant must not cover it.
    exact = parse_key_scope('["GET /health/build"]')
    assert scope_permits(exact, "GET", "/health/build")
    assert not scope_permits(exact, "HEAD", "/health/build")
    # Trailing-slash normalization is the ONE tolerance, applied on both sides.
    assert scope_permits(parse_key_scope('["GET /health/build/"]'), "GET", "/health/build")


def test_expired_key_is_refused(db, admin_user):
    """Expiry is ENFORCED, not merely stored — and the CLI can now WRITE it.

    ``verify_api_key`` already refused an expired key at `2eb3328e` (VERIFIED, not
    changed by ); what  adds is the missing writer. This pin locks the
    enforcement so a later "simplify" cannot drop it while the flag keeps
    promising a lifetime.
    """
    past = to_utc_iso(datetime.now(timezone.utc) - timedelta(days=1))
    future = to_utc_iso(datetime.now(timezone.utc) + timedelta(days=1))

    expired_raw = generate_api_key()
    store_api_key(db, hash_api_key(expired_raw), "expired", admin_user["id"], past)
    assert verify_api_key(db, expired_raw) is None, "an expired key must be refused"

    live_raw = generate_api_key()
    store_api_key(db, hash_api_key(live_raw), "live", admin_user["id"], future)
    assert verify_api_key(db, live_raw) is not None, (
        "a NOT-yet-expired key must still authenticate — otherwise the assertion "
        "above passes for the wrong reason"
    )

    corrupt_raw = generate_api_key()
    store_api_key(db, hash_api_key(corrupt_raw), "corrupt", admin_user["id"], "not-a-date")
    assert verify_api_key(db, corrupt_raw) is None, (
        "an UNPARSEABLE expiry must fail CLOSED (PD#8)"
    )


def test_stored_scope_round_trips_from_the_mint_path(db, admin_user):
    """A key minted WITH a scope resolves carrying that scope."""
    raw = generate_api_key()
    scope_json = json.dumps(sorted(_MONITOR_SCOPE))
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None, scope=scope_json,
    )
    resolved = verify_api_key(db, raw)
    assert resolved is not None
    assert parse_key_scope(resolved["api_key_scope"]) == {
        route_key(*e.split(" ", 1)) for e in _MONITOR_SCOPE
    }


# ===========================================================================
# Arm C — live HTTP, GET routes only (see the SCOPE CAVEAT in the module docstring)
# ===========================================================================

def _live_get_routes(app):
    return [
        (m, p) for m, p, _mod, _n in iter_app_routes(app) if m == "GET"
    ]


def test_live_scoped_key_never_outranks_anonymous_on_any_get_route(
    raw_client, app, db, admin_user,
):
    """End-to-end: the fence is WIRED, not merely callable.

    For every GET route, an off-scope scoped key must either be refused
    (401/403) or get exactly what an anonymous caller gets — i.e. the credential
    confers NO authority outside its scope. Comparing against the anonymous
    response is what makes this correct on the genuinely public routes
    (``/health``, ``/login``, static) without hand-listing them.
    """
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    headers = {"Authorization": f"Bearer {raw}"}

    leaks: list[str] = []
    checked = 0
    for method, path in _live_get_routes(app):
        url = _fill_params(path)
        if url == "/health/build":
            continue
        checked += 1
        keyed = raw_client.get(url, headers=headers)
        if keyed.status_code in (401, 403):
            continue
        anon = raw_client.get(url)
        if keyed.status_code != anon.status_code:
            leaks.append(f"GET {url} keyed={keyed.status_code} anon={anon.status_code}")
    assert checked > 0, "no GET routes walked — the pin would pass vacuously"
    assert leaks == [], (
        f"an off-scope key outranked anonymous on {len(leaks)} GET route(s): "
        f"{leaks[:15]}"
    )


def test_live_scoped_key_reaches_its_own_route(raw_client, db, admin_user):
    """The good-variant half: the scoped key DOES work where it is scoped.

    Without this, ``test_live_scoped_key_never_outranks_anonymous_*`` would pass
    just as well if the fence refused everything, including the one route the
    credential exists for.
    """
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    resp = raw_client.get("/health/build", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200, resp.text
    assert "build_sha" in resp.json()


def test_live_off_scope_use_is_403_not_401(raw_client, db, admin_user):
    """403, not 401: the caller IS authenticated, just not authorised here.

    A 401 would tell a monitor "your token is wrong" and send a browser to
    /login — hiding an authorisation refusal behind an authentication one.
    """
    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    resp = raw_client.get(
        "/health/detail", headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 403, resp.status_code


def _newest_403_row(db, after_id: int):
    """The newest 403 ``access_log`` row with ``id > after_id``, or None.

    Scoping by id matters: the ``db`` fixture's rows outlive a single test, so an
    unscoped ``ORDER BY id DESC`` can hand a later arm the PREVIOUS arm's row —
    which is how a teeth test passes on evidence it did not produce.
    """
    rows = db.execute(
        "SELECT id, actor_user_id, status_code, detail FROM access_log "
        "WHERE status_code = 403 AND id > ? ORDER BY id DESC LIMIT 1",
        (after_id,),
    ).fetchall()
    return rows[0] if rows else None


def _max_access_log_id(db) -> int:
    return db.execute(
        "SELECT COALESCE(MAX(id), 0) FROM access_log",
    ).fetchone()[0]


def test_live_refused_phi_access_is_attributed_to_the_principal(
    raw_client, db, admin_user, monkeypatch,
):
    """§164.312(b): a REFUSED access on a PHI path names WHO was turned away.

    The failure mode this closes is subtle and was found by reading the
    middleware, not by any test failing. ``AccessAuditMiddleware`` runs AFTER
    ``call_next``; nothing in ``src/`` ever sets ``request.state.user`` (the
    "cached user" branch is dead), so it falls back to calling
    ``get_current_user`` itself — which, for a fenced principal, now RAISES, into
    its own ``except Exception: pass``. The ``access_log`` row for a refused
    scoped-key request would therefore have carried ``actor_user_id = NULL``: a
    row saying someone was turned away from PHI without saying who. The fence
    stamps the resolved id before raising and the middleware reads it.
    """
    # The middleware's audit write is fire-and-forget and the TestClient's
    # request scope ends before it runs, so it is routinely CANCELLED in this
    # harness (`audit_write_cancelled_shielded`). Strict-audit mode makes the
    # middleware `await` the write instead, which is the difference between an
    # arm that measures and an arm that skips.
    monkeypatch.setenv("EMAIL_TRIAGE_AUDIT_STRICT", "1")

    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after_id = _max_access_log_id(db)

    # A PHI path per `access_audit._PHI_ROUTE_PREFIXES` — and off-scope.
    resp = raw_client.get(
        "/api/v1/accounts/1/messages",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 403, resp.status_code

    row = _newest_403_row(db, after_id)
    assert row is not None, (
        "no NEW 403 access_log row landed for the refused request — this arm "
        "cannot measure attribution without its own row, so it fails rather "
        "than skipping or reading a neighbour's row"
    )
    actor = row["actor_user_id"]
    detail = row["detail"] or ""

    # Two admissible shapes, and the second one is a PRE-EXISTING behaviour this
    # test measured rather than assumed. `record_access_event` catches a
    # `sqlite3.IntegrityError` on an FK violation and — because sqlite3 does not
    # say WHICH column — NULLs `account_id` AND `actor_user_id` together, stashing
    # both originals in `detail`. This request's path carries `account_id=1`,
    # which has no `email_accounts` row in this fixture, so the coercion fires and
    # takes the (correct) actor with it. The attribution still SURVIVES, in
    # `detail`. Accepting both shapes is what makes this arm about the fence's
    # stamp rather than about the fixture's account table.
    stash = f"stale_actor_user_id={admin_user['id']}"
    assert actor == admin_user["id"] or stash in detail, (
        "a refused PHI access is not attributable to the principal that was "
        f"turned away: actor_user_id={actor!r}, detail={detail!r}. Expected "
        f"user {admin_user['id']} in the column or {stash!r} in detail. Without "
        "the fence's stamp this row reads as an anonymous denial — §164.312(b) "
        "attribution lost."
    )


def test_teeth_attribution_arm_sees_the_missing_stamp(
    raw_client, db, admin_user, monkeypatch,
):
    """Remove the fence's stamp and prove the attribution arm goes RED.

    Without this, ``test_live_refused_phi_access_is_attributed_to_the_principal``
    could be passing because something ELSE happened to put the id in the row.
    Here the fence's `check_principal_fences` still refuses (so the request is
    still a 403 on a PHI path) but the seam records nothing, which is exactly the
    pre-fix state: the audit row must then name nobody.
    """
    import email_triage.web.dependencies as deps

    original = deps._fence_or_403

    def _fence_without_the_stamp(request, user):
        # The refusal, minus the `request.state.fenced_principal_id` line.
        from email_triage.web._route_scope import (
            ScopeRefused, check_principal_fences,
        )
        from email_triage.web.error_surface import raise_api_error
        try:
            check_principal_fences(request, user)
        except ScopeRefused as refused:
            raise raise_api_error(
                "Insufficient permissions", status_code=403, purpose="misc",
            ) from refused
        return user

    monkeypatch.setenv("EMAIL_TRIAGE_AUDIT_STRICT", "1")
    monkeypatch.setattr(deps, "_fence_or_403", _fence_without_the_stamp)
    assert deps._fence_or_403 is not original

    raw = generate_api_key()
    store_api_key(
        db, hash_api_key(raw), "monitor", admin_user["id"], None,
        scope=json.dumps(["GET /health/build"]),
    )
    after_id = _max_access_log_id(db)
    resp = raw_client.get(
        "/api/v1/accounts/1/messages",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 403, resp.status_code

    row = _newest_403_row(db, after_id)
    assert row is not None, (
        "no NEW 403 access_log row landed — the teeth arm cannot measure, and "
        "must not fall back to a neighbouring test's row"
    )
    stash = f"stale_actor_user_id={admin_user['id']}"
    assert row["actor_user_id"] is None and stash not in (row["detail"] or ""), (
        "TEETH FAILURE: with the fence's stamp removed the refused access was "
        "STILL attributed — the attribution arm is not measuring the stamp. Got "
        f"actor_user_id={row['actor_user_id']!r}, detail={row['detail']!r}"
    )


def test_live_health_ro_key_reaches_build_but_not_detail(raw_client, db):
    """The (E) fence, end to end, on the two routes that define it."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("health-ro@test.com", "Monitor", UserRole.HEALTH_RO.value, now),
    )
    db.commit()
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), "cve-arc", cur.lastrowid)
    headers = {"Authorization": f"Bearer {raw}"}

    assert raw_client.get("/health/build", headers=headers).status_code == 200
    assert raw_client.get("/health/detail", headers=headers).status_code == 403
    assert raw_client.get("/api/status", headers=headers).status_code == 403


# ===========================================================================
# TEETH (R38) — the detector FLAGS a planted regression and CLEARS a good shape
# ===========================================================================

def test_teeth_fence_removal_is_caught(app, monkeypatch):
    """Plant the regression "the fence grants everything" and prove Arm B fails.

    Patched at the site where the decision is LOOKED UP
    (``_route_scope.scope_permits`` / ``role_route_allowed``), not at the importer,
    because ``check_principal_fences`` resolves both by module attribute.
    """
    import email_triage.web._route_scope as rs

    monkeypatch.setattr(rs, "scope_permits", lambda *a, **k: True)
    monkeypatch.setattr(rs, "role_route_allowed", lambda *a, **k: True)

    user = _scoped_principal(_MONITOR_SCOPE)
    leaked = [
        route_key(m, p)
        for m, p, _mod, _n in iter_app_routes(app)
        if not _refuses(user, m, p)
    ]
    assert leaked, (
        "TEETH FAILURE: with the scope check neutered, Arm B still found no leak "
        "— it is not actually measuring the fence."
    )

    ro = _health_ro_principal()
    ro_leaked = [
        route_key(m, p)
        for m, p, _mod, _n in iter_app_routes(app)
        if route_key(m, p) not in HEALTH_RO_ALLOWED_ROUTES and not _refuses(ro, m, p)
    ]
    assert ro_leaked, (
        "TEETH FAILURE: with the role allowlist neutered, the health_ro arm still "
        "found no leak."
    )


def test_teeth_structural_arm_flags_an_unfenced_return():
    """Plant a ``get_current_user`` whose bearer arm skips the fence."""
    planted = ast.parse(
        "def get_current_user(request):\n"
        "    user = _check_bearer_token(request)\n"
        "    if user is not None:\n"
        "        return user\n"          # <- the regression
        "    return _fence_or_403(request, user)\n"
    )
    target = planted.body[0]
    bad = [
        n for n in ast.walk(target)
        if isinstance(n, ast.Return) and n.value is not None
        and not (isinstance(n.value, ast.Call)
                 and getattr(n.value.func, "id", None) == "_fence_or_403")
        and not (isinstance(n.value, ast.Constant) and n.value.value is None)
    ]
    assert bad, "TEETH FAILURE: the unfenced-return detector did not flag it"

    good = ast.parse(
        "def get_current_user(request):\n"
        "    user = _check_bearer_token(request)\n"
        "    if user is not None:\n"
        "        return _fence_or_403(request, user)\n"
        "    return None\n"
    )
    still_bad = [
        n for n in ast.walk(good.body[0])
        if isinstance(n, ast.Return) and n.value is not None
        and not (isinstance(n.value, ast.Call)
                 and getattr(n.value.func, "id", None) == "_fence_or_403")
        and not (isinstance(n.value, ast.Constant) and n.value.value is None)
    ]
    assert still_bad == [], (
        "TEETH FAILURE: the detector flags a CORRECT shape (false positive)"
    )


def test_teeth_expiry_removal_is_caught(db, admin_user, monkeypatch):
    """Neuter the expiry parse and prove the expiry pin would fail."""
    import email_triage.web.auth as auth_mod

    past = to_utc_iso(datetime.now(timezone.utc) - timedelta(days=1))
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), "expired", admin_user["id"], past)

    # A parser that reads every expiry as far-future is the "expired keys still
    # work" regression.
    monkeypatch.setattr(
        auth_mod, "parse_iso_aware",
        lambda v: datetime.now(timezone.utc) + timedelta(days=3650),
    )
    assert verify_api_key(db, raw) is not None, (
        "TEETH FAILURE: with expiry parsing neutered the expired key was STILL "
        "refused — test_expired_key_is_refused is not measuring the expiry check."
    )


def test_teeth_api_only_role_removal_is_caught(monkeypatch):
    """Empty :data:`API_ONLY_ROLES` and prove the session-mint refusal stops."""
    import email_triage.web._route_scope as rs

    monkeypatch.setattr(rs, "API_ONLY_ROLES", frozenset())
    token = create_session_token(
        "s" * 32, "health-ro@test.com", UserRole.HEALTH_RO.value,
    )
    assert token, (
        "TEETH FAILURE: with API_ONLY_ROLES emptied, minting was still refused — "
        "the refusal is not keyed on that constant."
    )


def test_api_only_roles_is_not_empty():
    """A non-stale guard: an emptied constant makes every role-fence arm vacuous."""
    assert API_ONLY_ROLES == frozenset({UserRole.HEALTH_RO.value})
    assert UserRole.HEALTH_RO.value in {r.value for r in UserRole}


# ===========================================================================
# The CLI glue — the flags exist, parse, validate and reach the column
# ===========================================================================

def test_cli_flags_parse_into_the_expected_attributes():
    """``--scope`` accumulates; ``--expires-days`` lands on ``expires_days``.

    Cheap, but it is the layer nothing else covers: a flag renamed or declared
    without ``action="append"`` breaks the mint path with the rest of the feature
    still green, and the only symptom is a key that reaches everything.
    """
    from email_triage.cli import build_parser

    args = build_parser().parse_args([
        "apikey", "create", "--name", "m", "--user", "m@test.com",
        "--scope", "GET /health/build",
        "--scope", "GET /health/runtime-deps",
        "--expires-days", "365",
    ])
    assert args.scope == ["GET /health/build", "GET /health/runtime-deps"]
    assert args.expires_days == 365

    bare = build_parser().parse_args([
        "apikey", "create", "--name", "m", "--user", "m@test.com",
    ])
    assert bare.scope is None and bare.expires_days is None, (
        "omitting the flags must leave an UNSCOPED, never-expiring key — the "
        "pre-#420 behaviour"
    )


def test_cli_role_choices_come_from_the_enum():
    """``user create --role health_ro`` is accepted, and the choices ARE the enum."""
    from email_triage.cli import build_parser

    args = build_parser().parse_args([
        "user", "create", "--email", "m@test.com", "--role", "health_ro",
    ])
    assert args.role == UserRole.HEALTH_RO.value
    action = next(
        a for a in build_parser()._subparsers._group_actions[0]  # type: ignore[attr-defined]
        .choices["user"]._subparsers._group_actions[0].choices["create"]._actions
        if a.dest == "role"
    )
    assert set(action.choices) == {r.value for r in UserRole}, (
        "the --role choices list has diverged from the UserRole SSOT"
    )


def _cli_apikey(monkeypatch, tmp_path, argv):
    """Run ``cmd_apikey`` against a throwaway DB, mocking only the BOUNDARIES.

    ``load_config`` / ``_cli_open_config_db`` / ``setup_logging`` are the external
    boundary (R41 — mock the lowest boundary, never the seam under test); the
    scope-validation, JSON serialization, expiry computation and ``store_api_key``
    call are the real code paths. A file DB of its own, so ``cmd_apikey``'s
    ``db.close()`` cannot close the session fixture's connection.
    """
    import sqlite3 as _sqlite3
    import types

    from email_triage import cli as cli_mod
    from email_triage.web.db import init_db
    from email_triage.web.migrations import run_migrations

    db_file = tmp_path / "cli.db"
    seed = init_db(db_file)
    run_migrations(seed)
    seed.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("m@test.com", "Monitor", UserRole.HEALTH_RO.value,
         datetime.now(timezone.utc).isoformat()),
    )
    seed.commit()
    seed.close()

    cfg = types.SimpleNamespace(
        persistence=types.SimpleNamespace(db_path=str(db_file)),
        logging=None,
    )
    monkeypatch.setattr(cli_mod, "load_config", lambda _p: cfg)
    monkeypatch.setattr(cli_mod, "setup_logging", lambda _c: None)
    monkeypatch.setattr(cli_mod, "_cli_open_config_db", lambda _c: init_db(db_file))
    # The bare cfg has no secrets store; the autouse conftest key is already in
    # the registry. The real wiring is covered by test_cli_grant_wires_audit_hmac.py.
    monkeypatch.setattr(cli_mod, "_cli_wire_audit_keys", lambda *_a, **_k: None)

    args = cli_mod.build_parser().parse_args(argv)
    rc = cli_mod.cmd_apikey(args)

    conn = _sqlite3.connect(db_file)
    conn.row_factory = _sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM api_keys").fetchall()]
    conn.close()
    return rc, rows


def test_cli_create_writes_the_scope_and_expiry(monkeypatch, tmp_path):
    rc, rows = _cli_apikey(monkeypatch, tmp_path, [
        "apikey", "create", "--name", "cve-arc", "--user", "m@test.com",
        "--scope", "GET /health/runtime-deps",
        "--scope", "GET /health/build",
        "--expires-days", "365",
    ])
    assert rc == 0
    assert len(rows) == 1
    # Stored canonical: sorted + de-duplicated, so two equivalent invocations
    # produce the same column value.
    assert json.loads(rows[0]["scope"]) == [
        "GET /health/build", "GET /health/runtime-deps",
    ]
    assert parse_key_scope(rows[0]["scope"]) == {
        "GET /health/build", "GET /health/runtime-deps",
    }
    expiry = rows[0]["expires_at"]
    assert expiry, "--expires-days wrote no expires_at"
    from email_triage._isotime import parse_iso_aware
    parsed = parse_iso_aware(expiry)
    assert parsed is not None, (
        f"the stored expiry {expiry!r} is not readable by the SAME parser "
        "verify_api_key uses — the key would be refused as corrupt"
    )
    assert parsed > datetime.now(timezone.utc) + timedelta(days=364)


def test_cli_create_refuses_a_malformed_scope_and_mints_nothing(monkeypatch, tmp_path):
    """A typo must refuse LOUDLY at mint, not produce an inert credential."""
    rc, rows = _cli_apikey(monkeypatch, tmp_path, [
        "apikey", "create", "--name", "typo", "--user", "m@test.com",
        "--scope", "GET/health/build",       # missing the separating space
    ])
    assert rc == 1
    assert rows == [], "a key was created despite the invalid --scope"


def test_cli_create_refuses_a_non_positive_expiry(monkeypatch, tmp_path):
    rc, rows = _cli_apikey(monkeypatch, tmp_path, [
        "apikey", "create", "--name", "zero", "--user", "m@test.com",
        "--expires-days", "0",
    ])
    assert rc == 1
    assert rows == [], "a key was created despite --expires-days 0"


def test_cli_create_without_flags_leaves_the_column_null(monkeypatch, tmp_path):
    """The migration's meaning-preservation claim, at the MINT surface."""
    rc, rows = _cli_apikey(monkeypatch, tmp_path, [
        "apikey", "create", "--name", "plain", "--user", "m@test.com",
    ])
    assert rc == 0
    assert rows[0]["scope"] is None
    assert rows[0]["expires_at"] is None
    assert parse_key_scope(rows[0]["scope"]) is None, "NULL must read as UNSCOPED"


# ===========================================================================
# PD#17 — the RENDERED view, not just the model
# ===========================================================================

def test_users_manage_page_renders_the_new_role(raw_client, admin_cookies, db):
    """The admin users page still renders, and its role ``<select>`` grew a 4th option.

    ``routers/ui/users.py`` builds ``roles`` from ``[r.value for r in UserRole]`` and
    ``templates/users/manage.html`` loops it into two ``<select name="role">``
    blocks (the Add-User form and each row's Edit form). Adding an enum member
    therefore changes a rendered page, and PD#17 is explicit that unit tests +
    structural pins + py_compile all pass while a route 500s — only the rendered
    view catches it. No new UI was added; this asserts what the existing,
    SSOT-driven UI now shows.
    """
    resp = raw_client.get("/users", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text
    body = resp.text
    for role in (r.value for r in UserRole):
        assert f'value="{role}"' in body, (
            f"the role <select> does not offer {role!r} — the users page and the "
            "UserRole SSOT have diverged"
        )
