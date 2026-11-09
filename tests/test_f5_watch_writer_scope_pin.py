"""N-564 (punch F5) — every email_watches write, creator stamp, watch route
and fire is scope-gated at the actuator (PD-9).

Main ``d305d4bb`` and before: the agent API gated only the PATH account
(``_require_webhook_account``) and then honoured a body ``account_id`` and any
``watch_id``; ``watch_runner`` fired a watch without checking that its creator
may manage the account. This pin holds the structural half of the fix. The
runtime half, one test per arm, is ``tests/test_web/test_f5_watch_scope.py``.

ARMS (each a property over every parseable file under ``src/email_triage``,
``walk_src``; count-agnostic; each with teeth):

1. **Writers, in the same hop.** Every reference to an ``email_watches`` writer
   outside the home module ``web/email_watches.py`` is either
   * a DIRECT call whose INNERMOST enclosing def references a requester gate
     (the gate and the write run in one hop), or
   * a reasoned ``ALLOW`` entry.
   A writer passed as a ``db_call(<writer>, …)`` argument is never gated by its
   enclosing function: the hop it starts runs only the writer, so any gate in
   the route ran in a different hop (db-sme F1). The writer set is DERIVED:
   N-539's ``watch_writers()`` (every home def holding write SQL on
   ``email_watches``, closed under same-module callers) PLUS every
   ``@audit_emitter``-module def that references one (today the two N-539
   funnels). The funnels are followed, not exempted (PD-2): the gate is then
   required of THEIR callers. "Reference" is N-539's ``writer_references`` plus
   a ``getattr(x, "<writer>")`` literal. ALLOW is keyed on
   ``(relpath, enclosing qualified name)`` (R38).
2. **Raw SQL.** No string literal outside the home module and
   ``web/migrations.py`` matches N-539's ``_WATCH_SQL``.
3. **Watch routes.** Every route handler whose path holds ``{watch_id}`` and
   reads, fires or writes a watch resolves it with ``_get_watch_on_account``
   and never the unscoped global ``get_watch`` (R15). Every route handler whose
   path holds ``/watches`` and lists watches (``list_watches``) does so in a
   def that references a requester gate. Known-member guards keep a green run
   from being a run over nothing.
4. **Creator stamps.** Every store to ``<x>.created_by_user_id`` or
   ``<x>["created_by_user_id"]`` sits in an INNERMOST def that references a
   requester gate. A stamped creator decides whether the watch fires and whose
   group listing shows it, so a stamp is a grant (hipaa-sme 543b landing L-4).
5. **Fire actuator.** ``watch_fire_refusal`` is the one gate: it calls
   ``account_scope.user_id_may_manage_account`` (which checks
   ``is_user_disabled``, hipaa-sme B1), ``account_hipaa_effective`` and
   ``account_scope.is_account_owner`` (punch 578: on a HIPAA-effective account
   only the owner's watches fire). ``fire_one_watch``,
   ``resolve_watches_for_account``, ``watch_creator_may_fire`` and the display
   form ``watch_row_refusal`` each read it, so the fire paths, the owner's
   "Not firing" line and the admin alert cannot disagree (PD-18).
6. **One delivery funnel.** Every reference to ``_send_escalate`` /
   ``_post_webhook`` sits inside ``fire_one_watch``.
7. **No per-watch recipient.** Nothing reads ``<x>.escalate.notify_email``.

GATES (requester gates), DERIVED, never listed: every public top-level def of
``web/account_scope.py`` that takes a requester (a ``user``, ``user_id``,
``requester_id`` or ``manageable_set`` parameter); then, to a fixpoint, every
module-level def anywhere under src that takes a requester AND references a
gate (today ``_scoped_watch_account``, ``_get_watch_on_account`` and
``_upsert_watch_on_account`` in the agent API). A def that takes no requester,
such as the body validator ``_refuse_body_account_other_than_path``, is never a
gate however it binds the path (db-sme F1). ``_require_webhook_account`` ALONE
is not a gate: that was the bug.

WHAT A GREEN RUN DOES NOT PROVE (each fail-OPEN, stated so it is not read as
more):

* Arms 1, 3 and 4 check that the def references a gate, not that the gated id
  is the id written, nor that the requester passed is the key holder (no
  dataflow). The runtime tests carry that (``TestRouteScopeForgotten``).
* A derived gate is any requester-taking def that references a gate; it is not
  proven to refuse anything. Its refusal is runtime-tested.
* A writer reached through a variable, a dict of callables, a module-level alias
  (``f = upsert_watch``) or a re-export under a new name in another module is
  not followed (N-539's ``writer_references`` limits).
* Arm 4 sees attribute and subscript STORES only. A creator passed as a
  constructor keyword (``EmailWatch(created_by_user_id=…)``) is not checked; the
  one such site, ``save_watch_group_txn``'s insert arm, takes its targets from a
  caller that must already have intersected them (N-539's documented
  caller-side invariant, and this pin's ALLOW on the profile routes).
* Rows written by an FK cascade (``email_watches.account_id … ON DELETE
  CASCADE``, creator ``ON DELETE SET NULL``) are named by no SQL.
"""

from __future__ import annotations

import ast
from functools import lru_cache

from _pin_harness import (
    AUDIT_EMITTER_MODULES, SRC_ROOT, assert_pin_has_teeth, enclosing_qualified_name,
    enclosing_scope_chain, innermost_fn_at_lineno, iter_string_literals,
    parse_module, parse_source, walk_src,
)
from test_n539_n540_witnessed_write_funnel_pin import (  # N-539's derivations (PD-6)
    _WATCH_SQL, watch_writers, writer_references,
)

_HOME = "web/email_watches.py"
_RAW_SQL_EXEMPT = {_HOME, "web/migrations.py"}
_ACCOUNT_SCOPE = "web/account_scope.py"
_REQUESTER_PARAMS = {"user", "user_id", "requester_id", "manageable_set"}

#: Routes that must be found by arm 3 (a subset check, not a count).
_KNOWN_BY_ID_ROUTES = frozenset({
    "webhook_watches_update", "webhook_watches_delete", "webhook_watches_test_fire",
})
_KNOWN_LIST_ROUTES = frozenset({"webhook_watches_list"})

#: Funnels and gates that must be derived (subset checks, not counts).
_KNOWN_FUNNELS = frozenset({"record_watch_group_save", "record_watch_group_delete"})
_KNOWN_GATES = frozenset({
    "user_id_may_manage_account", "is_manageable", "filter_to_manageable",
    "_scoped_watch_account", "_get_watch_on_account", "_upsert_watch_on_account",
    "get_watch_group",
})

#: Gates added to the derivation BASE by name, because ``requester_defs()``
#: reads only ``web/account_scope.py``. ``name -> reason``. Each is also a
#: RESOLVER (see ``_RESOLVER_GATES``): its protection is its return value.
_EXTRA_GATE_BASE: dict[str, str] = {
    "get_watch_group": (
        "allow-list step 2, B4 (s2 panel condition (a)): the actor-scoped "
        "watch-group resolver in web/email_watches.py. It returns None for a "
        "group the requester owns no row in, which the caller answers 404, so "
        "the rows it names are the requester's own. It is a reader, not a "
        "writer: save_watch_group_txn, which references it, is a watch sink "
        "and never joins the gate set (condition (b), held by "
        "test_derived_sets_hold_their_known_members)."
    ),
}

#: Gates whose protection is the object they RETURN, not a yes/no answer. A
#: def gated only by one of these must pass the resolved object to the sink,
#: and the funnel it calls must not resolve it again (s2 panel condition (c)):
#: otherwise the gate is a result-ignored reference, an uninvoked control.
_RESOLVER_GATES = frozenset(_EXTRA_GATE_BASE)
_KNOWN_NOT_GATES = frozenset({"same_owner", "_refuse_body_account_other_than_path"})

#: ``(repo-relative path, enclosing qualified name) -> reason`` for a writer
#: reference with no gate in its hop. A stale entry fails
#: ``test_allow_entries_are_live``.
ALLOW: dict[tuple[str, str], str] = {
    # profile_watches_save_new._save_and_audit and
    # profile_watches_save_existing._save were cut 2026-11-05 (allow-list
    # step 2, B4): each now intersects its targets with filter_to_manageable
    # in its own hop before record_watch_group_save.
    # profile_watches_delete._delete was cut 2026-11-06 (allow-list step 2,
    # B4 fold): it resolves get_watch_group(group_id, actor) in its own hop and
    # passes the resolved group to record_watch_group_delete
    # (test_resolver_gated_sites_pass_the_resolved_object).
    ("web/watch_runner.py", "fire_watches_for_message"): (
        "the #48 auto-retire (db_call(maybe_auto_retire_watch, …)) on a watch "
        "that just fired. No client input: the system is the actor, and the "
        "watch came from resolve_watches_for_account, which drops any watch "
        "whose creator may not manage the account (arm 5)."
    ),
}


# ---------------------------------------------------------------------------
# Derivations
# ---------------------------------------------------------------------------


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _module_defs(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        n.name: n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _takes_requester(fn: ast.AST) -> bool:
    return bool({a.arg for a in fn.args.args + fn.args.kwonlyargs} & _REQUESTER_PARAMS)


def requester_defs(tree: ast.AST) -> frozenset[str]:
    """Public top-level defs of ``tree`` that take a requester parameter."""
    return frozenset(
        name for name, fn in _module_defs(tree).items()
        if not name.startswith("_") and _takes_requester(fn)
    )


def _references_any(fn: ast.AST, names: frozenset[str]) -> bool:
    """A Load reference (a call, or a value passed to ``db_call``) to any name."""
    return any(
        isinstance(n, (ast.Name, ast.Attribute))
        and isinstance(getattr(n, "ctx", None), ast.Load)
        and _name_of(n) in names
        for n in ast.walk(fn)
    )


def derive_gates(
    base: frozenset[str], trees: list[ast.AST], *, exclude: frozenset[str] = frozenset(),
) -> frozenset[str]:
    """``base`` closed under: a module-level def that takes a requester and
    references a gate is a gate. ``exclude`` (the writer set) never joins."""
    gates = set(base)
    defs = [
        (name, fn) for tree in trees for name, fn in _module_defs(tree).items()
        if name not in exclude and _takes_requester(fn)
    ]
    changed = True
    while changed:
        changed = False
        for name, fn in defs:
            if name not in gates and _references_any(fn, frozenset(gates)):
                gates.add(name)
                changed = True
    return frozenset(gates)


@lru_cache(maxsize=1)
def watch_funnels() -> frozenset[str]:
    """``@audit_emitter``-module defs that reference a watch writer."""
    writers = watch_writers()
    out: set[str] = set()
    for rel in AUDIT_EMITTER_MODULES:
        for name, fn in _module_defs(parse_module(SRC_ROOT / rel)).items():
            if writer_references(fn, writers):
                out.add(name)
    return frozenset(out)


@lru_cache(maxsize=1)
def watch_sinks() -> frozenset[str]:
    return watch_writers() | watch_funnels()


@lru_cache(maxsize=1)
def scope_gates() -> frozenset[str]:
    """The requester gates (see the module docstring)."""
    base = requester_defs(parse_module(SRC_ROOT / _ACCOUNT_SCOPE)) | frozenset(_EXTRA_GATE_BASE)
    trees = [tree for _p, _rel, tree in walk_src()]
    return derive_gates(base, trees, exclude=watch_sinks())


# ---------------------------------------------------------------------------
# Detectors (each takes a parsed tree so the teeth tests can plant shapes)
# ---------------------------------------------------------------------------


def _getattr_refs(tree: ast.AST, sinks: frozenset[str]) -> list[ast.Call]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _name_of(n.func) == "getattr"
        and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
        and n.args[1].value in sinks
    ]


def ungated_writer_sites(
    tree: ast.AST, *, sinks: frozenset[str], gates: frozenset[str],
    funnels: frozenset[str] = frozenset(),
) -> list[tuple[str, int]]:
    """``(enclosing qualified name, line)`` for every sink reference that is a
    ``db_call`` seam, or a direct call whose innermost def references no gate.
    A reference in a funnel's own body is skipped; the funnel is itself a sink,
    so its callers are checked instead."""
    out: list[tuple[str, int]] = []
    for ref in writer_references(tree, sinks) + _getattr_refs(tree, sinks):
        fn = innermost_fn_at_lineno(tree, ref.lineno)
        if fn is not None and fn.name in funnels:
            continue
        seam = _name_of(ref.func) not in sinks and _name_of(ref.func) != "getattr"
        if seam or fn is None or not _references_any(fn, gates):
            out.append((enclosing_qualified_name(ref), ref.lineno))
    return out


def resolver_gated_sites(
    tree: ast.AST, *, sinks: frozenset[str], gates: frozenset[str],
    resolvers: frozenset[str],
) -> list[tuple[str, int, str]]:
    """``(enclosing qualified name, line, sink name)`` for every DIRECT sink
    call whose innermost def references a resolver gate and no other gate."""
    out: list[tuple[str, int, str]] = []
    for ref in writer_references(tree, sinks):
        fn = innermost_fn_at_lineno(tree, ref.lineno)
        if fn is None or not _references_any(fn, resolvers):
            continue
        if _references_any(fn, gates - resolvers):
            continue
        out.append((enclosing_qualified_name(ref), ref.lineno, _name_of(ref.func)))
    return out


def ignored_resolver_results(
    tree: ast.AST, *, sinks: frozenset[str], gates: frozenset[str],
    resolvers: frozenset[str],
) -> list[tuple[str, int]]:
    """Resolver-gated sink calls that do not pass the resolver's RESULT in:
    the result of a resolver call must be bound to a name that the sink call
    reads. A resolver whose result is dropped is a decorative gate."""
    out: list[tuple[str, int]] = []
    for ref in writer_references(tree, sinks):
        fn = innermost_fn_at_lineno(tree, ref.lineno)
        if fn is None or not _references_any(fn, resolvers):
            continue
        if _references_any(fn, gates - resolvers):
            continue
        bound = {
            t.id for n in ast.walk(fn)
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
            and _name_of(n.value.func) in resolvers
            for t in n.targets if isinstance(t, ast.Name)
        }
        read = {n.id for n in ast.walk(ref) if isinstance(n, ast.Name)
                and isinstance(n.ctx, ast.Load)}
        if not bound & read:
            out.append((enclosing_qualified_name(ref), ref.lineno))
    return out


def re_resolving_funnels(
    tree: ast.AST, *, funnels: frozenset[str], resolvers: frozenset[str],
) -> list[str]:
    """Funnels (module-level defs named in ``funnels``) whose own body
    references a resolver: the caller's resolution would then be ignored."""
    return sorted(
        name for name, fn in _module_defs(tree).items()
        if name in funnels and _references_any(fn, resolvers)
    )


def raw_watch_sql(tree: ast.AST) -> list[str]:
    return [s[:60] for s in iter_string_literals(tree) if _WATCH_SQL.search(s)]


def _route_path(fn: ast.AST) -> str | None:
    """The path template of a ``@router.<verb>("<path>", …)`` decorator."""
    for d in fn.decorator_list:
        if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                and d.args and isinstance(d.args[0], ast.Constant)
                and isinstance(d.args[0].value, str)):
            return d.args[0].value
    return None


_WATCH_ACTORS = frozenset({"get_watch", "fire_one_watch"})


def watch_route_violations(
    tree: ast.AST, *, sinks: frozenset[str], gates: frozenset[str],
) -> tuple[list[str], list[str], list[str]]:
    """``(by_id_found, list_found, violations)`` over route handlers whose path
    holds ``/watches``. A ``{watch_id}`` handler that reads, fires or writes a
    watch must resolve it with ``_get_watch_on_account`` and never ``get_watch``;
    one that touches no watch (a redirect) owes nothing. A handler that lists
    watches does so in a def that references a gate."""
    by_id: list[str] = []
    listed: list[str] = []
    bad: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        path = _route_path(fn)
        if path is None or "/watches" not in path:
            continue
        if "{watch_id}" in path:
            by_id.append(fn.name)
            if _references_any(fn, frozenset({"get_watch"})):
                bad.append(f"{fn.name}: resolves the watch through the unscoped get_watch")
            if (_references_any(fn, _WATCH_ACTORS | sinks)
                    and not _references_any(fn, frozenset({"_get_watch_on_account"}))):
                bad.append(f"{fn.name}: never resolves the watch on the path account")
        for n in ast.walk(fn):
            if (isinstance(n, ast.Call) and _name_of(n.func) == "list_watches"):
                listed.append(fn.name)
                inner = innermost_fn_at_lineno(tree, n.lineno)
                if inner is None or not _references_any(inner, gates):
                    bad.append(f"{fn.name}: lists watches with no requester gate in that hop")
    return by_id, listed, bad


def ungated_creator_stamps(
    tree: ast.AST, *, gates: frozenset[str],
) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for n in ast.walk(tree):
        if not isinstance(getattr(n, "ctx", None), ast.Store):
            continue
        stamp = (
            (isinstance(n, ast.Attribute) and n.attr == "created_by_user_id")
            or (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
                and n.slice.value == "created_by_user_id")
        )
        if not stamp:
            continue
        fn = innermost_fn_at_lineno(tree, n.lineno)
        if fn is None or not _references_any(fn, gates):
            out.append((fn.name if fn is not None else "<module>", n.lineno))
    return out


_SENDERS = frozenset({"_send_escalate", "_post_webhook"})
_FIRE_FUNNEL = "fire_one_watch"


def sender_refs_outside_funnel(tree: ast.AST) -> list[int]:
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, (ast.Name, ast.Attribute))
                and isinstance(getattr(n, "ctx", None), ast.Load)
                and _name_of(n) in _SENDERS):
            names = {f.name for f in enclosing_scope_chain(tree, n.lineno)[:-1]}
            if _FIRE_FUNNEL not in names:
                out.append(n.lineno)
    return out


def per_watch_recipient_reads(tree: ast.AST) -> list[int]:
    """``<x>.escalate.notify_email`` loads (a store, e.g. clearing it, is fine)."""
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "notify_email"
        and isinstance(n.ctx, ast.Load)
        and isinstance(n.value, ast.Attribute) and n.value.attr == "escalate"
    ]


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def _scan_writers() -> dict[tuple[str, str], list[int]]:
    sinks, gates, funnels = watch_sinks(), scope_gates(), watch_funnels()
    flagged: dict[tuple[str, str], list[int]] = {}
    for _p, rel, tree in walk_src():
        if rel == _HOME:
            continue
        for qual, lineno in ungated_writer_sites(
                tree, sinks=sinks, gates=gates,
                funnels=funnels if rel in AUDIT_EMITTER_MODULES else frozenset()):
            flagged.setdefault((rel, qual), []).append(lineno)
    return flagged


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_derived_sets_hold_their_known_members():
    sinks = watch_sinks()
    for name in ("upsert_watch", "upsert_watch_txn", "delete_watch",
                 "delete_watch_txn", "save_watch_group_txn"):
        assert name in sinks, f"writer derivation missed {name}: {sorted(sinks)}"
    assert _KNOWN_FUNNELS <= watch_funnels(), sorted(watch_funnels())
    gates = scope_gates()
    missing = _KNOWN_GATES - gates
    assert not missing, f"gate derivation missed {sorted(missing)}"
    wrong = _KNOWN_NOT_GATES & gates
    assert not wrong, f"{sorted(wrong)} take no requester and are not gates"


def test_every_watch_writer_routes_through_a_scope_gate():
    offenders = {k: v for k, v in _scan_writers().items() if k not in ALLOW}
    assert not offenders, (
        f"email_watches writer reference(s) with no requester gate in the same "
        f"hop: {offenders}. PD-9 (N-564): the def that calls the writer must "
        "itself check the requester (an account_scope gate, or an actuator such "
        "as _upsert_watch_on_account); a db_call(<writer>, …) seam is never gated."
    )


def test_allow_entries_are_live():
    flagged = _scan_writers()
    stale = [k for k in ALLOW if k not in flagged]
    assert not stale, f"ALLOW entries that no longer match an ungated site: {stale}"


def test_resolver_gated_sites_pass_the_resolved_object():
    """s2 panel condition (c), allow-list step 2 B4: a writer site gated ONLY by
    a resolver (``get_watch_group``) must hand the resolver's result to the
    sink, and every funnel it calls must not resolve again. Otherwise the
    route-side resolution is a decorative gate that arm 1 cannot tell apart
    from a real one (arm 1 checks a reference, not a data flow)."""
    sinks, gates, funnels = watch_sinks(), scope_gates(), watch_funnels()
    sites: list[tuple[str, str, int, str]] = []
    ignored: list[tuple[str, str, int]] = []
    for _p, rel, tree in walk_src():
        if rel == _HOME:
            continue
        sites += [(rel, q, ln, s) for q, ln, s in resolver_gated_sites(
            tree, sinks=sinks, gates=gates, resolvers=_RESOLVER_GATES)]
        ignored += [(rel, q, ln) for q, ln in ignored_resolver_results(
            tree, sinks=sinks, gates=gates, resolvers=_RESOLVER_GATES)]
    assert ("web/routers/ui/profile.py", "profile_watches_delete._delete") in {
        (rel, q) for rel, q, _ln, _s in sites}, (
        f"known resolver-gated site not found (a green run over nothing): {sites}")
    assert not ignored, (
        f"resolver-gated writer site(s) that drop the resolver's result: {ignored}. "
        "Pass the resolved object (not its id) into the sink.")
    called = frozenset(s for *_x, s in sites) & funnels
    re_resolving = [
        (rel, name) for rel in AUDIT_EMITTER_MODULES
        for name in re_resolving_funnels(
            parse_module(SRC_ROOT / rel), funnels=called, resolvers=_RESOLVER_GATES)
    ]
    assert not re_resolving, (
        f"funnel(s) {re_resolving} resolve the object again although their "
        "caller is gated only by resolving it: the caller's gate is then ignored. "
        "Take the resolved object from the caller.")


def test_resolver_arm_has_teeth():
    sinks = frozenset({"record_watch_group_delete"})
    gates = frozenset({"get_watch_group", "filter_to_manageable"})
    resolvers = frozenset({"get_watch_group"})

    def detector(tree):
        return ignored_resolver_results(tree, sinks=sinks, gates=gates, resolvers=resolvers)

    assert_pin_has_teeth(
        detector,
        # The gate is called, but only the id reaches the funnel.
        "def _delete(db, user, group_id):\n"
        "    if get_watch_group(db, group_id, user['id']) is None:\n"
        "        return 0\n"
        "    return record_watch_group_delete(db, group_id=group_id)\n",
        "def _delete(db, user, group_id):\n"
        "    group = get_watch_group(db, group_id, user['id'])\n"
        "    if group is None:\n"
        "        return 0\n"
        "    return record_watch_group_delete(db, group=group)\n",
    )
    # A site gated by a non-resolver gate owes no data flow.
    assert not detector(parse_source(
        "def _save(db, user, ids, group_id):\n"
        "    ok = filter_to_manageable(ids, db, user)\n"
        "    get_watch_group(db, group_id, user['id'])\n"
        "    return record_watch_group_delete(db, ids=ok)\n"))
    funnel = (
        "def record_watch_group_delete(conn, *, group_id):\n"
        "    group = get_watch_group(conn, group_id, 1)\n"
        "    return group\n")
    assert re_resolving_funnels(parse_source(funnel), funnels=sinks, resolvers=resolvers)
    assert not re_resolving_funnels(
        parse_source("def record_watch_group_delete(conn, *, group):\n    return group\n"),
        funnels=sinks, resolvers=resolvers)


def test_extra_gate_base_entries_are_live_and_reasoned():
    """Each by-name base gate exists as a module-level def under src, takes a
    requester, carries a reason, and is not a watch sink (condition (b))."""
    defs = {name: fn for _p, _rel, tree in walk_src()
            for name, fn in _module_defs(tree).items()}
    for name, reason in _EXTRA_GATE_BASE.items():
        assert name in defs, f"_EXTRA_GATE_BASE names a def that no longer exists: {name}"
        assert _takes_requester(defs[name]), f"{name} takes no requester"
        assert len(reason) > 40, f"{name} needs a stated reason"
        assert name not in watch_sinks(), f"{name} is a watch sink and cannot be a gate"


def test_no_raw_email_watches_write_sql_outside_the_home_module():
    raw = [
        f"{rel}: {hits}" for _p, rel, tree in walk_src()
        if rel not in _RAW_SQL_EXEMPT and (hits := raw_watch_sql(tree))
    ]
    assert not raw, f"email_watches write SQL outside {_HOME}: {raw}"


def test_every_watch_route_resolves_through_a_requester_gate():
    by_id: list[str] = []
    listed: list[str] = []
    bad: list[str] = []
    sinks, gates = watch_sinks(), scope_gates()
    for _p, rel, tree in walk_src():
        f, lf, b = watch_route_violations(tree, sinks=sinks, gates=gates)
        by_id += f
        listed += lf
        bad += [f"{rel}: {x}" for x in b]
    assert _KNOWN_BY_ID_ROUTES <= set(by_id), (
        f"by-id route scan found {sorted(by_id)}; expected at least "
        f"{sorted(_KNOWN_BY_ID_ROUTES)} (a green run over nothing is not a pass)")
    assert _KNOWN_LIST_ROUTES <= set(listed), (
        f"list route scan found {sorted(listed)}; expected {sorted(_KNOWN_LIST_ROUTES)}")
    assert not bad, f"watch routes not gated on the requester: {bad}"


def test_every_creator_stamp_is_in_a_gated_function():
    gates = scope_gates()
    bad = [
        f"{rel}: {hits}" for _p, rel, tree in walk_src()
        if (hits := ungated_creator_stamps(tree, gates=gates))
    ]
    assert not bad, (
        f"created_by_user_id stamped outside a scope-gated def: {bad}. The "
        "creator decides whether a watch fires (N-564)."
    )


_FIRE_GATE = "watch_fire_refusal"
#: What the gate must call: the manageable set (N-564), the HIPAA-effective
#: SSOT and the strict owner predicate (punch 578).
_FIRE_GATE_CALLS = ("user_id_may_manage_account", "account_hipaa_effective",
                    "is_account_owner")
#: Every def that decides whether a watch fires or shows as firing.
_FIRE_GATE_READERS = ("fire_one_watch", "resolve_watches_for_account",
                      "watch_creator_may_fire", "watch_row_refusal")


def fire_gate_violations(tree: ast.AST) -> list[str]:
    defs = {
        n.name: n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    gate = defs.get(_FIRE_GATE)
    if gate is None:
        return [f"{_FIRE_GATE} is missing"]
    called = {_name_of(n.func) for n in ast.walk(gate) if isinstance(n, ast.Call)}
    out = [f"{_FIRE_GATE} does not call {c}" for c in _FIRE_GATE_CALLS
           if c not in called]
    for reader in _FIRE_GATE_READERS:
        if reader not in defs:
            out.append(f"{reader} is missing")
        elif not _references_any(defs[reader], frozenset({_FIRE_GATE})):
            out.append(f"{reader} does not read {_FIRE_GATE}")
    return out


def test_fire_actuator_checks_the_creator():
    bad = fire_gate_violations(parse_module(SRC_ROOT / "web/watch_runner.py"))
    assert not bad, (
        f"fire gate: {bad}. Every fire path and every 'Not firing' surface must "
        f"read {_FIRE_GATE}, which checks the creator's scope (N-564) and, on a "
        "HIPAA-effective account, that the creator is the owner (punch 578).")
    scope = _module_defs(parse_module(SRC_ROOT / _ACCOUNT_SCOPE))
    assert _references_any(scope["user_id_may_manage_account"],
                           frozenset({"is_user_disabled"})), (
        "user_id_may_manage_account must refuse a disabled user (hipaa-sme B1)")


def test_delivery_only_through_the_gated_fire_funnel():
    bad = [
        f"{rel}: {hits}" for _p, rel, tree in walk_src()
        if (hits := sender_refs_outside_funnel(tree))
    ]
    assert not bad, (
        f"watch delivery reachable outside {_FIRE_FUNNEL}: {bad}. Every escalate / "
        f"webhook send must pass the creator gate at the top of {_FIRE_FUNNEL}."
    )


def test_no_per_watch_recipient_is_read():
    bad = [
        f"{rel}: {hits}" for _p, rel, tree in walk_src()
        if (hits := per_watch_recipient_reads(tree))
    ]
    assert not bad, (
        f"per-watch escalate.notify_email read at {bad}. The recipient comes only "
        "from watch_runner.resolve_escalate_recipient (N-564): the per-watch value "
        "was client-settable with no allowlist."
    )


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------

_T_SINKS = frozenset({"upsert_watch", "record_watch_group_save"})
_T_GATES = frozenset({"filter_to_manageable", "user_id_may_manage_account",
                      "_get_watch_on_account", "_upsert_on"})


def test_writer_arm_has_teeth():
    def detector(tree):
        return ungated_writer_sites(tree, sinks=_T_SINKS, gates=_T_GATES)

    assert_pin_has_teeth(
        detector,
        # The pre-fold good_source, now BAD (db-sme F1): a scoped read in one
        # hop, then the raw writer in another.
        "async def update(request, account_id, watch_id):\n"
        "    w = await db_call(_get_watch_on_account, db, watch_id, account_id, uid)\n"
        "    return await db_call(_watches.upsert_watch, db, w)\n",
        # A requester-taking actuator holds the gate in the write's own hop.
        "def _upsert_on(db, w, user_id, account_id):\n"
        "    if not user_id_may_manage_account(db, user_id, account_id):\n"
        "        return None\n"
        "    return _watches.upsert_watch(db, w)\n"
        "async def create(request, account_id):\n"
        "    return await db_call(_upsert_on, db, w, user['id'], account_id)\n",
    )
    # A route that only binds the path, then writes raw: flagged.
    assert detector(parse_source(
        "async def create(request, account_id):\n"
        "    _refuse_body_account_other_than_path(body, account_id)\n"
        "    return await db_call(_watches.upsert_watch, db, w)\n"))
    # A closure whose OUTER function holds the gate is a different hop: flagged.
    assert detector(parse_source(
        "async def h(db, user, ids):\n"
        "    ok = filter_to_manageable(ids, db, user)\n"
        "    def _save(db):\n"
        "        return record_watch_group_save(db, target_account_ids=ok)\n"
        "    return await db_call(_save, db)\n"))
    # The same closure holding the gate itself is clean.
    assert not detector(parse_source(
        "async def h(db, user, ids):\n"
        "    def _save(db):\n"
        "        ok = filter_to_manageable(ids, db, user)\n"
        "        return record_watch_group_save(db, target_account_ids=ok)\n"
        "    return await db_call(_save, db)\n"))
    # Keyed on the qualified name of the enclosing def.
    assert detector(parse_source(
        "def route(db, ids):\n"
        "    def _inner(db):\n        return upsert_watch(db, ids)\n"
        "    return _inner(db)\n")) == [("route._inner", 3)]
    # getattr and module scope are caught.
    assert detector(parse_source("def f(db, w):\n    getattr(m, 'upsert_watch')(db, w)\n"))
    assert detector(parse_source("upsert_watch(db, w)\n"))
    # The funnel's own body is skipped only when named as a funnel.
    funnel = "def record_watch_group_save(db, ids):\n    return upsert_watch(db, ids)\n"
    assert detector(parse_source(funnel))
    assert not ungated_writer_sites(
        parse_source(funnel), sinks=_T_SINKS, gates=_T_GATES,
        funnels=frozenset({"record_watch_group_save"}))


def test_gate_derivation_has_teeth():
    tree = parse_source(
        "def _scoped(db, user_id, account_id):\n"
        "    return user_id_may_manage_account(db, user_id, account_id)\n"
        "def _get_on(db, watch_id, account_id, user_id):\n"
        "    return _scoped(db, user_id, account_id)\n"
        "def _binder(db, watch_id, account_id):\n"
        "    return _scoped(db, None, account_id)\n"
        "def _refuse_body(body, account_id):\n"
        "    return body.get('account_id') == account_id\n"
        "def _liar(db, user_id):\n"
        "    return True\n")
    gates = derive_gates(frozenset({"user_id_may_manage_account"}), [tree])
    assert {"_scoped", "_get_on"} <= gates
    assert not {"_binder", "_refuse_body", "_liar"} & gates
    assert "upsert_watch" not in derive_gates(
        frozenset({"g"}),
        [parse_source("def upsert_watch(db, user_id):\n    return g(db)\n")],
        exclude=frozenset({"upsert_watch"}))


def test_sql_and_route_arms_have_teeth():
    assert raw_watch_sql(parse_source(
        "def f(db):\n    db.execute('UPDATE email_watches SET account_id = 2')\n"))
    assert not raw_watch_sql(parse_source(
        "def f(db):\n    db.execute('SELECT * FROM email_watches')\n"))
    _f, _l, bad = watch_route_violations(parse_source(
        "@router.patch('/accounts/{account_id}/watches/{watch_id}')\n"
        "async def upd(request, account_id, watch_id):\n"
        "    return await db_call(_watches.get_watch, db, watch_id)\n"),
        sinks=_T_SINKS, gates=_T_GATES)
    assert len([b for b in bad if "unscoped" in b]) == 1
    assert len([b for b in bad if "never resolves" in b]) == 1
    _f, _l, bad = watch_route_violations(parse_source(
        "@router.post('/accounts/{account_id}/watches/{watch_id}/test-fire')\n"
        "async def tf(request, account_id, watch_id, w):\n"
        "    return await fire_one_watch(watch=w)\n"), sinks=_T_SINKS, gates=_T_GATES)
    assert bad == ["tf: never resolves the watch on the path account"]
    found, _l, bad = watch_route_violations(parse_source(
        "@router.delete('/accounts/{account_id}/watches/{watch_id}')\n"
        "async def rm(request, account_id, watch_id):\n"
        "    def _d(db):\n"
        "        return _get_watch_on_account(db, watch_id, account_id, uid)\n"
        "    return await db_call(_d, db)\n"
        "@router.get('/accounts/{account_id}/watches/{watch_id}/edit')\n"
        "async def legacy(request, account_id, watch_id):\n"
        "    return RedirectResponse('/profile/watches', status_code=303)\n"),
        sinks=_T_SINKS, gates=_T_GATES)
    assert found == ["rm", "legacy"] and bad == []
    _f, listed, bad = watch_route_violations(parse_source(
        "@router.get('/accounts/{account_id}/watches')\n"
        "async def ls(request, account_id):\n"
        "    def _l(db):\n        return list_watches(db, account_id=account_id)\n"
        "    return await db_call(_l, db)\n"), sinks=_T_SINKS, gates=_T_GATES)
    assert listed == ["ls"] and bad == ["ls: lists watches with no requester gate in that hop"]
    _f, listed, bad = watch_route_violations(parse_source(
        "@router.get('/accounts/{account_id}/watches')\n"
        "async def ls(request, account_id):\n"
        "    def _l(db, uid):\n"
        "        if not user_id_may_manage_account(db, uid, account_id):\n"
        "            return None\n"
        "        return list_watches(db, account_id=account_id)\n"
        "    return await db_call(_l, db, uid)\n"), sinks=_T_SINKS, gates=_T_GATES)
    assert listed == ["ls"] and bad == []


def test_creator_stamp_arm_has_teeth():
    def detector(tree):
        return ungated_creator_stamps(tree, gates=_T_GATES)

    assert_pin_has_teeth(
        detector,
        "def save(db, w, user_id):\n"
        "    if w.created_by_user_id is None:\n"
        "        w.created_by_user_id = user_id\n",
        "def save(db, w, user_id, ids, user):\n"
        "    ok = filter_to_manageable(ids, db, user)\n"
        "    w.created_by_user_id = user_id\n",
    )
    assert detector(parse_source("def c(body, user):\n    body['created_by_user_id'] = user['id']\n"))
    assert not detector(parse_source("def r(w):\n    return w.created_by_user_id\n"))


def test_fire_gate_arm_has_teeth():
    readers = "".join(
        f"def {r}(db, w, a):\n    return watch_fire_refusal(db, w, a)\n"
        for r in _FIRE_GATE_READERS)
    good = (
        "def watch_fire_refusal(db, w, a):\n"
        "    if not user_id_may_manage_account(db, w.c, a['id']):\n"
        "        return 'out'\n"
        "    if account_hipaa_effective(account=a) and not is_account_owner(a, w.c):\n"
        "        return 'hipaa'\n"
        "    return None\n" + readers)
    assert fire_gate_violations(parse_source(good)) == []
    # Punch 578 reverted: the gate no longer asks who owns a HIPAA account.
    assert fire_gate_violations(parse_source(
        good.replace(" and not is_account_owner(a, w.c)", ""))) == [
        "watch_fire_refusal does not call is_account_owner"]
    # A reader that decides on its own (a second predicate) is flagged.
    assert fire_gate_violations(parse_source(good.replace(
        "def watch_row_refusal(db, w, a):\n    return watch_fire_refusal(db, w, a)",
        "def watch_row_refusal(db, w, a):\n    return w.c is None"))) == [
        "watch_row_refusal does not read watch_fire_refusal"]
    assert fire_gate_violations(parse_source(readers)) == ["watch_fire_refusal is missing"]


def test_fire_funnel_and_recipient_arms_have_teeth():
    assert sender_refs_outside_funnel(parse_source(
        "async def replay(w):\n    await _send_escalate(notify_email='x')\n"))
    assert not sender_refs_outside_funnel(parse_source(
        "async def fire_one_watch(w):\n"
        "    async def inner():\n        return await _post_webhook(url='u')\n"
        "    return await inner()\n"))
    assert per_watch_recipient_reads(parse_source(
        "def f(w):\n    return w.actions.escalate.notify_email or 'x'\n"))
    assert not per_watch_recipient_reads(parse_source(
        "def f(w):\n    w.actions.escalate.notify_email = ''\n"))


def test_requester_param_set_is_the_gate_predicate():
    """A requester-less helper added to account_scope does not become a gate by
    living there, and a private helper is not a BASE gate either."""
    tree = parse_source(
        "def is_manageable(account_id, db, user):\n    pass\n"
        "def same_owner(a, b):\n    pass\n"
        "def _cache(db, user):\n    pass\n"
        "def by_kw(db, *, user_id):\n    pass\n")
    assert requester_defs(tree) == {"is_manageable", "by_kw"}
