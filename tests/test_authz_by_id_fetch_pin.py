"""N-74 authz by-id-fetch FUNCTION-keyed interprocedural pin (drift-prevention).

Verify-don't-accept (run17 #2 re-census, 2026-06-27) confirmed: every by-id
account-scope HTTP handler IS gated at HEAD (0 live IDOR / enum-oracle). This
pin guards against a FUTURE regression — a new ``@router`` handler that resolves
an account by a client-submitted id without reaching an authz gate.

run17 #2 RE-KEY (was the kernel of the finding):
  * The old pin was **MODULE-keyed** — a gate imported ANYWHERE in a file
    green-lit EVERY handler in it, incl. a future ungated one. Now keyed at the
    **FUNCTION** level (per top-level ``@router`` handler), cloning the proven
    ``test_account_administer_gate_pin.py`` per-top-level-function + seam-aware
    walk. A handler's source segment includes its nested ``db_call`` closures,
    so a gate in a sibling closure is in scope.
  * The old ``_GATE_NAMES`` net was **incomplete** (6 names) — it missed most of
    the gate family. The net below is the complete account-scope + admin +
    list-rule + DI-alias + per-handler-resolver union.
  * The old ``_ALLOWED_RELPATHS`` **masked** the gap by wholesale-exempting
    ``agent_api.py`` + ``labels.py``. With the function-level @router scoping +
    the complete net, those modules pass on their REAL gates
    (``_scope_to_user`` / ``can_manage_account``); the wholesale masks are gone,
    so a future ungated by-id handler in either is now CAUGHT.

Scope is the @router HTTP entry points: a non-handler helper that fetches by-id
(e.g. a ``_shared.py`` render helper) is caller-gated and intentionally NOT
required to gate here — that would false-positive. Count-agnostic: a property
over every top-level @router handler (never ``len(X)==N``).

SCOPE CAVEAT (honest, R55): asserts the gate is REFERENCED in the same top-level
handler (incl. nested closures) as the by-id fetch — it does NOT prove the gate
dominates the fetch on every path, nor does it follow a fetch DELEGATED to a
cross-module helper (the interprocedural residual; a handler that hands the
fetch to another module's helper, with no gate in its own segment, is not seen —
the companion behavioural tests in tests/test_web/test_account_scope.py /
test_accounts.py cover the access edge; the helper itself, if it ever becomes a
handler, is then caught here).
"""

from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, walk_src, iter_files, parse_module

SRC = SRC_ROOT

# By-id account-fetch triggers.
_FETCH_NAMES = frozenset({"get_email_account"})
#: A raw-SQL by-id account fetch (bypasses get_email_account). Census run13 #3,
#: WIDENED run18 #8 to be ALIAS-TOLERANT. The old net was the literal substring
#: ``"from email_accounts where id"`` — an aliased fetch
#: (``FROM email_accounts ea ... WHERE ea.id = ?``) EVADED it (the run18-recurring
#: "membership predicate narrower than the class" shape). It's an alias-tolerant
#: PAIR now — BOTH must match across the function's JOINED string-constant corpus:
#:   * ``_RAW_BYID_FROM`` — the FROM clause names the ``email_accounts`` table
#:     (optional ``ea`` alias). The trailing ``\b`` REJECTS ``email_accounts_archive``
#:     (a different table — the ``_archive`` would have to start at a word boundary).
#:   * ``_RAW_BYID_WHERE`` — a WHERE keys on a (optionally alias-qualified) ``id``
#:     column. The ``id\s*=`` requirement means ``WHERE ea.user_id = ?`` (by-USER_id,
#:     NOT by-id) does NOT match — preserving the by-id vs by-user_id distinction.
#: Matched over the JOINED corpus (NOT per single ``ast.Constant``) because SQL is
#: split across ``+``/f-string literals (``"...FROM email_accounts ea " f"WHERE
#: ea.id = ?{_active}"``); requiring both patterns in ONE node would inherit a NEW
#: split-FROM/WHERE blind spot. Count-agnostic (a property over every handler).
_RAW_BYID_FROM = re.compile(r"from\s+email_accounts(\s+\w+)?\b")
_RAW_BYID_WHERE = re.compile(r"where\s+(\w+\.)?id\s*=")

# Off-loop seam wrappers whose FIRST positional is the callee (PD#2) — a by-id
# fetch / a gate frequently lands through these (db_call(get_email_account, …),
# db_call(_require_webhook_account, …)).
_SEAM_WRAPPERS = frozenset({"db_call", "db_call_async", "run_in_threadpool"})

# The COMPLETE authz gate-name net (run17 #2 — the old 6-name net missed most).
_GATE_NAMES = frozenset({
    # account-scope SSOTs (web/account_scope.py + db/accounts.py)
    "can_manage_account", "can_administer_account", "is_manageable",
    "is_account_owner", "same_owner", "is_account_delegate",
    "manageable_account_ids", "filter_to_manageable", "intersect_ids",
    # admin SSOTs (web/dependencies.py)
    "require_admin_ui", "_require_admin", "admin_gate_response", "assert_admin",
    # list-rule SSOTs (web/_list_authz.py) — the test_list_rule_authz_pin family
    "is_list_writable_by", "is_list_readable_by", "is_list_deletable_by",
    # resource-ownership SSOT (web/_resource_authz.py)
    "can_modify_owned_resource",
    # DI dep functions (the underlying resolvers behind the Annotated aliases)
    "_require_owned_account", "_require_owned_account_or_login",
    # per-handler resolver-gates: a handler that DELEGATES its gate to a
    # module-level resolver references the resolver name, not a gate name.
    #
    # N-286 R30: hand-listed BASELINE. Additional resolvers get admitted
    # via `_structural_resolver_names(SRC_ROOT)` below — any function whose
    # body transitively references a CANONICAL scope-primitive earns the
    # gate-name role structurally. The hand-list stays as a safety net for
    # cases the AST predicate misses (e.g. resolvers that delegate through
    # a helper the AST walk can't easily follow).
    "_require_webhook_account", "_scope_to_user", "_provider_op",
    "_calendar_op", "_wizard_fetch_and_auth", "_resolve_clock_def_account",
    "_gate_provider_labels",
})


# N-286 R30: canonical scope-primitives — a function whose body
# transitively calls one of these is a scope-gate resolver. The
# structural detector uses this set as the "seed" — any def with one
# in its body earns the resolver-gate role even if the hand-list above
# is stale.
_CANONICAL_SCOPE_PRIMITIVES = frozenset({
    "can_manage_account", "can_administer_account",
    "is_account_owner", "is_manageable", "is_account_delegate",
    "manageable_account_ids", "filter_to_manageable",
    "require_admin_ui", "_require_admin",
})


def _module_level_primitive_aliases(tree: ast.AST) -> set[str]:
    """the backlog  R32 — collect module-level aliases for canonical
    scope-primitives so the resolver detector doesn't miss a body call
    that goes through an alias name.

    Two shapes covered (both keep the SAME sema as calling the primitive
    directly, so a resolver body calling the alias earns the gate role):

    * ``alias = manageable_account_ids`` — a module-level ``ast.Assign``
      whose target is a bare ``Name`` and whose value is a bare ``Name``
      matching a canonical primitive.
    * ``from x import manageable_account_ids as alias`` — a module-level
      ``ast.ImportFrom`` whose ``name`` matches a primitive and whose
      ``asname`` is a distinct alias.

    Bounded to module scope on purpose: a per-function ``alias = prim``
    hides more than it reveals (the alias is the actual review site)
    and admits complexity the detector doesn't need.
    """
    aliases: set[str] = set()
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Name)
                and value.id in _CANONICAL_SCOPE_PRIMITIVES
                and target.id not in _CANONICAL_SCOPE_PRIMITIVES
            ):
                aliases.add(target.id)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (
                    alias.name in _CANONICAL_SCOPE_PRIMITIVES
                    and alias.asname
                    and alias.asname not in _CANONICAL_SCOPE_PRIMITIVES
                ):
                    aliases.add(alias.asname)
    return aliases


def _structural_resolver_names(src_root) -> set[str]:
    """N-286 R30 — walk `src/` for every `FunctionDef` /
    `AsyncFunctionDef` whose body transitively references one of the
    `_CANONICAL_SCOPE_PRIMITIVES` (directly OR via a module-level alias
    per :func:`_module_level_primitive_aliases`, the backlog  R32).
    Return the set of function NAMES.

    Replaces the R30 census concern about the hand-listed `_GATE_NAMES`
    per-handler resolvers — a NEW / RENAMED resolver whose body IS a
    scope check auto-admits via structural detection instead of relying
    on the hand-list being kept current."""
    resolvers: set[str] = set()
    for path in iter_files(src_root):
        tree = parse_module(path)
        if tree is None:
            continue
        # the backlog  R32: per-MODULE alias set widens the canonical
        # gate-name net for THIS module's scope only. An alias defined in
        # module A doesn't bleed into module B — the detector's per-file
        # scoping matches Python's real name-resolution boundary.
        _module_aliases = _module_level_primitive_aliases(tree)
        _module_gate_names = _CANONICAL_SCOPE_PRIMITIVES | _module_aliases
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Skip the primitives themselves — a primitive doesn't gate
            # ITSELF.
            if node.name in _CANONICAL_SCOPE_PRIMITIVES:
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                f = sub.func
                fname = (f.id if isinstance(f, ast.Name)
                         else f.attr if isinstance(f, ast.Attribute) else None)
                if fname in _module_gate_names:
                    resolvers.add(node.name)
                    break
    return resolvers


# Module-level compute — done ONCE per test run. Any function whose
# body calls a canonical scope-primitive earns the gate-name role,
# closing the R30 PD#4 (v–vi) trap without touching `_GATE_NAMES` on
# every new resolver.
_STRUCTURAL_RESOLVERS: frozenset = frozenset(_structural_resolver_names(SRC_ROOT))

# DI-dependency ANNOTATION alias names — a handler gates via an
# ``owned: OwnedAccount`` parameter ANNOTATION (FastAPI Depends), not a body
# call. These are matched in the signature, not the body.
_DI_ALIAS_NAMES = frozenset({
    "OwnedAccount", "OwnedAccountOrLogin", "OwnedGmailApiAccount",
    "OwnedAccountForProvider",
})

# FastAPI route-decorator HTTP methods: ``@router.get(...)`` / ``@app.post(...)``.
_HTTP_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options",
})
# FastAPI also registers routes via the GENERIC ``@<router>.api_route(path,
# methods=[...])`` form (live at agent_api.py) + the websocket decorators — a
# by-id handler could use any of these, so they count as route handlers too.
# (devils-advocate run17 #2 review: an HTTP-method-only set silently missed a
# future ``.api_route`` by-id handler — the pin's future-regression blind spot.)
_ROUTE_REGISTRARS = frozenset({"api_route", "websocket", "websocket_route"})

# ``rel::funcname`` exemptions — a specific @router handler that fetches an
# account by id WITHOUT a net-recognized gate but is verifiably NOT an IDOR.
# FUNCTION-level (NOT file-level) so an exemption can't mask a SIBLING handler in
# the same module — the masking bug this re-key fixed. Each needs a reason.
_ALLOWED: frozenset[str] = frozenset({
    # CREATE handler: fetches the JUST-CREATED account by its server-generated
    # new id (accounts.py ~:376, to render fresh state) — NEVER a client-
    # submitted id; owner_id is forced to the requester (you can only create
    # accounts you own). Sibling accounts_edit_form (gated by can_manage_account)
    # is NOT exempted — that's the point of keying per-function.
    "web/routers/ui/accounts.py::accounts_create",
})


def _is_router_handler(node: ast.AST) -> bool:
    """True if decorated as a FastAPI route — ``@<name>.<http-method>(...)`` OR
    the generic ``@<name>.api_route(...)`` / websocket registration forms."""
    for dec in getattr(node, "decorator_list", []):
        call = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(call, ast.Attribute) and (
            call.attr in _HTTP_METHODS or call.attr in _ROUTE_REGISTRARS
        ):
            return True
    return False


def _sql_corpus(node: ast.AST) -> str:
    """The JOINED, lowercased string-constant corpus of a function (incl. nested
    closures + f-string literal parts — ``ast.walk`` descends into ``JoinedStr``).

    SQL is split across ``+``/implicit-concat/f-string literals
    (``"SELECT ... " "FROM email_accounts ea " f"WHERE ea.id = ?{_active}"``), so
    the alias-tolerant FROM/WHERE pair (run18 #8) is matched over the JOINED text
    — a per-``ast.Constant`` test would inherit a NEW split-FROM/WHERE blind spot
    (one fragment carries the FROM, another the WHERE; neither matches both).
    Joined with a SPACE so two adjacent fragments can't word-weld
    (``"...email_accounts"`` + ``"ea ..."`` → ``"email_accountsea"``, which the
    ``\\b`` would then reject)."""
    parts: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value)
    return " ".join(parts).lower()


def _does_byid_fetch(node: ast.AST) -> bool:
    """True if the function (incl. nested closures) resolves an account by id:
    a ``get_email_account`` call (direct OR ``db_call``-seam) OR a raw,
    ALIAS-TOLERANT ``FROM email_accounts [ea] ... WHERE [ea.]id = ?`` SQL fetch
    (run18 #8 — both the :data:`_RAW_BYID_FROM` and :data:`_RAW_BYID_WHERE`
    patterns must match over the function's JOINED string-constant corpus)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id in _FETCH_NAMES:
                return True
            if isinstance(fn, ast.Attribute) and fn.attr in _FETCH_NAMES:
                return True
            if isinstance(fn, ast.Name) and fn.id in _SEAM_WRAPPERS:
                for arg in n.args:
                    if isinstance(arg, ast.Name) and arg.id in _FETCH_NAMES:
                        return True
    corpus = _sql_corpus(node)
    return bool(_RAW_BYID_FROM.search(corpus) and _RAW_BYID_WHERE.search(corpus))


def _module_gate_aliases(tree: ast.AST) -> frozenset[str]:
    """N-207 R22 (2026-07-02): resolve `from x import gate as alias` shapes.
    Census run22 R22_9 discovered the detector had an aliasing gap: a module
    that imports `manageable_account_ids as _manageable_account_ids` uses the
    aliased name in its function bodies — the pre-widening `_references_gate`
    only checked against `_GATE_NAMES` verbatim, so the aliased use was
    invisible + the pin over-reported handler defects (a false-positive shape
    from the pin's perspective; a false-CORRECTNESS signal from the operator's).

    Walk the module's top-level `ImportFrom` nodes; for every `alias.name in
    _GATE_NAMES` AND `alias.asname` set, add `alias.asname` to the aliased-gate
    set. `_references_gate(fn, gate_names)` then treats aliased names as gates
    too — the correct semantics.
    """
    aliases: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name in _GATE_NAMES and alias.asname:
                aliases.add(alias.asname)
    return frozenset(aliases)


def _references_gate(node: ast.AST, extra_gate_names: frozenset[str] = frozenset()) -> bool:
    """True if the function references a gate — a gate NAME anywhere in the body
    (incl. nested closures + ``db_call(<resolver>, …)`` seam, since walk sees the
    Name) OR a DI-dependency gate ANNOTATION in its signature.

    N-207 R22 (2026-07-02): `extra_gate_names` accepts module-scoped aliases so
    an `import x as _y` shape is recognised alongside the canonical names.
    """
    # N-286 R30: fold in structurally-detected resolvers so a NEW /
    # RENAMED resolver whose body IS a scope check auto-admits — no
    # need to touch `_GATE_NAMES` for every new handler-gate resolver.
    effective_gates = _GATE_NAMES | extra_gate_names | _STRUCTURAL_RESOLVERS
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in effective_gates:
            return True
        if isinstance(n, ast.Attribute) and n.attr in effective_gates:
            return True
    args = getattr(node, "args", None)
    if args is not None:
        for a in (list(args.posonlyargs) + list(args.args)
                  + list(args.kwonlyargs)):
            ann = a.annotation
            if ann is None:
                continue
            for n in ast.walk(ann):
                if isinstance(n, ast.Name) and n.id in _DI_ALIAS_NAMES:
                    return True
                if isinstance(n, ast.Attribute) and n.attr in _DI_ALIAS_NAMES:
                    return True
    return False


def _find_violations() -> list[str]:
    violations: list[str] = []
    for _path, rel, tree in walk_src():
        # N-207 R22: precompute per-module gate aliases so a handler using
        # `_manageable_account_ids` (an alias of `manageable_account_ids`)
        # is correctly recognised as gated.
        module_aliases = _module_gate_aliases(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if f"{rel}::{node.name}" in _ALLOWED:
                continue
            if not _is_router_handler(node):
                continue
            if not _does_byid_fetch(node):
                continue
            if not _references_gate(node, extra_gate_names=module_aliases):
                violations.append(
                    f"{rel}:{node.lineno} ({node.name!r} fetches an account "
                    "by id without referencing an authz gate)"
                )
    return violations


def test_every_byid_router_handler_has_an_authz_gate():
    """Every ``@router`` HTTP handler that resolves an account by a
    client-submitted id references an authz gate (account-scope / admin /
    list-rule / a DI ``Owned*`` annotation / a per-handler resolver) in the
    SAME top-level handler. FUNCTION-keyed (run17 #2 re-key)."""
    offenders = _find_violations()
    assert offenders == [], (
        "An @router handler resolves an account by id WITHOUT an authz gate "
        f"(IDOR / HIPAA-enum-oracle):\n  " + "\n  ".join(offenders)
        + "\nGate it (can_manage_account / is_account_owner / a Owned* DI dep / "
        "the module's resolver) on the request path, OR — if it legitimately "
        "fetches by id without a gate the net recognizes — add a justified "
        "_ALLOWED entry."
    )


def test_gate_helpers_still_exist():
    """Guard the pin itself: the load-bearing gate SSOTs must still exist."""
    accounts_py = (SRC / "db" / "accounts.py").read_text(encoding="utf-8")
    deps_py = (SRC / "web" / "dependencies.py").read_text(encoding="utf-8")
    scope_py = (SRC / "web" / "account_scope.py").read_text(encoding="utf-8")
    assert "can_manage_account" in accounts_py, "can_manage_account SSOT gone"
    assert "_require_owned_account" in deps_py, "_require_owned_account gone"
    assert "is_account_owner" in scope_py, "is_account_owner SSOT gone"


def test_pin_is_function_keyed_not_module_keyed():
    """run17 #2 regression guard: an ungated @router handler in a module that
    ALSO contains a SEPARATE gated handler must be FLAGGED (a module-keyed pin
    would pass it because the gate name appears elsewhere in the file)."""
    src = (
        "from email_triage.web.db import get_email_account\n"
        "@router.get('/gated/{account_id}')\n"
        "async def gated(account_id: int, db, user):\n"
        "    acct = get_email_account(db, account_id)\n"
        "    if not can_manage_account(db, user, acct):\n"
        "        raise Exception('forbidden')\n"
        "    return acct\n"
        "@router.get('/ungated/{account_id}')\n"
        "async def ungated(account_id: int, db):\n"
        "    return get_email_account(db, account_id)\n"
    )
    tree = ast.parse(src)
    handlers = {n.name: n for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    # gated handler: fetch + gate -> NOT flagged
    g = handlers["gated"]
    assert _is_router_handler(g) and _does_byid_fetch(g) and _references_gate(g)
    # ungated handler IN THE SAME MODULE: fetch, NO gate -> FLAGGED
    u = handlers["ungated"]
    assert _is_router_handler(u) and _does_byid_fetch(u)
    assert not _references_gate(u), (
        "the ungated sibling must NOT see the gated sibling's gate — that was "
        "the module-keyed bug this re-key fixes"
    )


def test_pin_has_teeth_di_annotation_and_seam():
    """A handler gating via the ``owned: OwnedAccount`` DI ANNOTATION passes;
    a fetch/gate via the ``db_call`` seam is recognized."""
    # DI-annotation gate (no body gate call) -> passes
    di = ast.parse(
        "@router.get('/x/{account_id}')\n"
        "async def h(account_id: int, owned: OwnedAccount):\n"
        "    return get_email_account(owned.db, account_id)\n"
    ).body[0]
    assert _is_router_handler(di) and _does_byid_fetch(di)
    assert _references_gate(di), "DI-annotation gate not recognized"
    # seam fetch + seam gate in a nested closure -> recognized + passes
    seam = ast.parse(
        "@router.post('/y/{account_id}')\n"
        "async def h(account_id: int, db, user):\n"
        "    def _work(db, account_id):\n"
        "        acct = db_call(get_email_account, db, account_id)\n"
        "        if not is_account_owner(acct, user['id']):\n"
        "            return 'forbidden'\n"
        "        return acct\n"
        "    return await db_call(_work, db, account_id)\n"
    ).body[0]
    assert _does_byid_fetch(seam), "db_call-seam fetch not detected"
    assert _references_gate(seam), "nested-closure gate not recognized"
    # a NON-handler helper that fetches by id is NOT required to gate (excluded)
    helper = ast.parse(
        "def _render_snapshot(db, account_id):\n"
        "    return get_email_account(db, account_id)\n"
    ).body[0]
    assert not _is_router_handler(helper), (
        "a non-@router helper must be out of scope (caller-gated)"
    )
    # the GENERIC @router.api_route(...) registration IS a route handler
    # (devils-advocate run17 #2 — the HTTP-method-only set missed it).
    apir = ast.parse(
        "@router.api_route('/x/{account_id}', methods=['POST'])\n"
        "async def h(account_id: int, db):\n"
        "    return get_email_account(db, account_id)\n"
    ).body[0]
    assert _is_router_handler(apir), "@router.api_route handler not recognized"
    assert _does_byid_fetch(apir) and not _references_gate(apir)


def test_pin_teeth_aliased_raw_sql_byid():
    """run18 #8: the raw-SQL by-id net is ALIAS-TOLERANT and split-corpus-aware.

    A FUTURE ``@router`` handler that inlines an aliased
    ``FROM email_accounts ea ... WHERE ea.id = ?`` fetch with no gate is FLAGGED
    — the old literal ``"from email_accounts where id"`` substring EVADED the
    alias. A by-``user_id`` fetch and an ``email_accounts_archive`` fetch are NOT
    (preserve by-id vs by-user_id; ``_archive`` is a different table)."""
    # (a) aliased by-id fetch — SQL SPLIT across two string fragments + an
    # f-string WHERE (the split-FROM/WHERE corpus case the old per-Constant net
    # would miss), inside an @router handler with NO gate -> FLAGGED.
    aliased = ast.parse(
        "@router.get('/x/{account_id}')\n"
        "async def h(account_id: int, db):\n"
        "    return db.execute(\n"
        "        'SELECT ea.* '\n"
        "        'FROM email_accounts ea JOIN users u ON ea.user_id = u.id '\n"
        "        f'WHERE ea.id = ?{_tail}',\n"
        "        (account_id,),\n"
        "    ).fetchone()\n"
    ).body[0]
    assert _is_router_handler(aliased)
    assert _does_byid_fetch(aliased), (
        "aliased FROM email_accounts ea ... WHERE ea.id (split across "
        "fragments + an f-string) not detected — the literal-substring net "
        "would have missed it"
    )
    assert not _references_gate(aliased), (
        "the planted handler has no gate — it must be an offender"
    )
    # (b) a by-USER_id fetch is NOT a by-id fetch — the ``id\\s*=`` requirement
    # means ``WHERE ea.user_id = ?`` must NOT match (preserve the distinction).
    by_user = ast.parse(
        "@router.get('/y')\n"
        "async def h(user_id: int, db):\n"
        "    return db.execute(\n"
        "        'SELECT ea.* FROM email_accounts ea '\n"
        "        'WHERE ea.user_id = ?',\n"
        "        (user_id,),\n"
        "    ).fetchall()\n"
    ).body[0]
    assert not _does_byid_fetch(by_user), (
        "WHERE ea.user_id = ? is a by-USER fetch — must NOT match the by-id net"
    )
    # (c) ``email_accounts_archive`` is a DIFFERENT table — the FROM-clause
    # ``\\b`` must reject it even with a ``WHERE id = ?``.
    archive = ast.parse(
        "@router.get('/z/{account_id}')\n"
        "async def h(account_id: int, db):\n"
        "    return db.execute(\n"
        "        'SELECT * FROM email_accounts_archive WHERE id = ?',\n"
        "        (account_id,),\n"
        "    ).fetchone()\n"
    ).body[0]
    assert not _does_byid_fetch(archive), (
        "email_accounts_archive is a DIFFERENT table — must NOT match"
    )
    # (d) the non-aliased legacy form (the ORIGINAL run13 #3 shape) still matches.
    legacy = ast.parse(
        "@router.get('/w/{account_id}')\n"
        "async def h(account_id: int, db):\n"
        "    return db.execute(\n"
        "        'SELECT * FROM email_accounts WHERE id = ?',\n"
        "        (account_id,),\n"
        "    ).fetchone()\n"
    ).body[0]
    assert _does_byid_fetch(legacy), (
        "the legacy un-aliased FROM email_accounts WHERE id form regressed"
    )


def test_allow_list_entries_are_real_and_still_offend():
    """PD#7 non-staleness: every _ALLOWED ``rel::funcname`` must still EXIST, be
    an @router handler that does a by-id fetch, and NOT reference a net gate —
    else the handler was gated/refactored/removed and the exemption is dead."""
    by_file: dict[str, set[str]] = {}
    for entry in _ALLOWED:
        rel, _, fn = entry.partition("::")
        assert fn, f"_ALLOWED entry {entry!r} must be 'rel::funcname'"
        by_file.setdefault(rel, set()).add(fn)
    seen: set[str] = set()
    for _path, rel, tree in walk_src():
        if rel not in by_file:
            continue
        funcs = {n.name: n for n in tree.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for fn in by_file[rel]:
            node = funcs.get(fn)
            assert node is not None, (
                f"_ALLOWED handler {rel}::{fn} no longer exists — drop it"
            )
            assert (_is_router_handler(node) and _does_byid_fetch(node)
                    and not _references_gate(node)), (
                f"_ALLOWED {rel}::{fn} is no longer an ungated by-id @router "
                "handler (gated/refactored) — drop the stale exemption"
            )
            seen.add(f"{rel}::{fn}")
    assert seen == set(_ALLOWED), f"_ALLOWED entries not found: {set(_ALLOWED) - seen}"
