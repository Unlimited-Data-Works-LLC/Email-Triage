"""N-520 — the commit-before-witness operation class, count-agnostic structural pin.

THE CLASS (the ONE operation class this pin owns, PD#4): a durable state change is
committed by a **self-committing** write (a helper whose own body reaches
``conn.commit()``, directly or through another self-committing helper) BEFORE the
audit row that witnesses that state change is written. Because the chain writer
``_chain_insert`` is fail-closed BY DESIGN on an HMAC-key gap (PD#12), a failure in
the window between the two leaves a committed, safeguard-relevant state change with
**no** durable audit row — §164.312(b) has nothing to reconcile against and
§164.308(a)(1)(ii)(D) review sees nothing.

Enumerated at ``a7e31ae0`` on ``feat/422-v020``. The enumeration signature, the full
triage of every candidate and the completeness argument live in
``~/.internal-config/scripts/et-v020-fresh/422-commit-before-witness-census.md``; the 19 sites
the census left UNTRIAGED were triaged at the object in
``~/.internal-config/scripts/et-v020-fresh/543-triage.md`` (10 MEMBER · 9 CLEARED, four census
reasons corrected), and the fix design for the whole class is ``543-design.md``.
Register rows: **N-520** (the class), N-514 (``_classifier_change_clear``), N-466
(``admin_security_save`` — FIXED via ``record_system_hipaa_flip``,
which is the reference fix shape this pin steers callers toward).

WHY A PIN AND NOT A FIX (see the report's "Fix decision"): the reference shape needs
a ``*_txn`` (non-committing) sibling for **every** writer plus the emitter, inside one
``*_atomic`` funnel. At this HEAD ``record_auth_event`` has **no** ``_txn`` sibling,
and neither do the four ``unpause_*_style_distill_*`` helpers, ``set_baa_ack`` or
``revoke_baa_ack``. That is ~6 new audit/DB primitives plus a funnel — not a bounded
fold under the v0.2.0 pre-release freeze. The pin is the R1 down-payment: it freezes
today's known-good and any NEW commit-before-witness site fails CI.

SCOPE CAVEAT — what a green run does NOT prove:
- Per-function-body, plus ONE interprocedural hop: ``db_call``/``db_call_async``/
  ``run_in_threadpool``/``to_thread`` resolve to their first positional argument
  (PD#2 — the dominant ``await db_call(_helper_db_work, …)`` idiom). It does NOT
  follow a helper smuggled through a dict/list, a ``functools.partial``, a lambda,
  a bound method, or a second hop.
- Callees are resolved through per-module name bindings (module-level and
  function-local ``import``/``from … import``, plus re-export chains such as
  ``web/db.py`` re-exporting ``db/style.py``). An unresolvable callee — a method on
  an object, a dynamically-dispatched attribute — is IGNORED on the state-change
  side, so a state change that commits behind such a call is invisible here.
- **That state-side blindness is LOAD-BEARING, not theoretical — measured at 4 of
  19 sites (2026-09-29 triage, ``543-triage.md`` §4.3).** At
  ``_verify_webauthn``, ``_consume_recovery_code._consume``,
  ``login_verify._login_verify_db_work`` and ``_run_hipaa_counter_for_account`` the
  callee this scan flagged is **not** the state change at all (three flag an audit
  writer with no durable write; one flags the ``auth_stale`` chip clear), while the
  real state change — a single-use credential burn behind
  ``wa.finish_authentication``, or ``loop.scan_recent()`` — sits behind a method
  call the resolver cannot follow. Every one of those four is a MEMBER anyway, and
  the ratchet still HOLDS them because ``BASELINE`` is keyed on
  ``(path, qualified fn)`` rather than on the callee pair. **So read a finding's
  ``state_callee`` as "the earliest committing callee this scan could resolve",
  never as "the state change at risk"** — the corrected mechanism for each of the
  four is in its own ``BASELINE`` reason. A widening that resolves method calls on
  the state side is the measurement that would bound the class; until then
  ``enumeration_complete=false`` stays.
- Ordering is textual (lineno), so two calls on mutually exclusive branches read as
  a sequence. That is an over-approximation (a triaged false positive), not a miss.
- It does not prove the witness is the CORRECT witness for the change, only that a
  self-committed state change does not precede one.
- **Witness-hood is NOT propagated to callers.** `web/routers/ui/admin.py::config_save`
  was recorded here as a member this pin cannot see; triage C-4 (2026-09-29) showed it
  was a different class. Its only `record_auth_event` sat in `_classifier_change_clear`,
  which runs only when the classifier changes and witnesses the classifier swap, so the
  `runtime_settings` write (which carries `dry_run`) had **no audit row on any path**:
  no witness, not a late one, register **N-540** / punch 545. Punch 545 routes that
  write through `db/audit.record_runtime_settings_change` (blob + witness in one
  transaction), pinned by `tests/test_n539_n540_witnessed_write_funnel_pin.py`.
  Measured before accepting the non-propagation: adding ONE hop of witness transitivity
  (a function that directly calls a witness becomes a witness) takes the witness set
  from 18 to **106** of 3365 functions and floods the result with authorization-resolver
  hits (`require_admin_ui`, `_require_login`, `get_current_user` preceding a handler's
  audit closure) — a strictly worse instrument, so that transitivity is NOT adopted
  generally. The one narrow exception is the module-scoped third arm,
  ``WITNESS_FUNNEL_MODULES`` (`web/login_guard.py` only), which IS applied — see its
  comment for the measured effect. A future widening must re-census.

THE REGISTER CHECK LIVES IN A SIBLING. ``tests/test_n520_register_row_agrees_with_baseline_pin.py``
reads N-520's row out of ``internal documentation``, which is refused from the
public mirror (N-504), so it is publish-stripped while this src ratchet ships (the N-543
pin imports this module's walker, so stripping this file would break it there too).

TWO STRUCTURAL EXCLUSIONS, each measured at the object rather than assumed:
- **A ``with <committing cm>(…):`` whose body holds the witness is the CORRECT
  shape, not the defect.** ``db/regulatory_clock._clock_txn`` is a
  ``@contextmanager`` that commits on clean exit, i.e. AFTER the
  ``emit_clock_event_txn`` inside its body. Ten ``regulatory_clock`` lifecycle
  transitions use it; counting the ``_clock_txn(conn)`` call as a preceding commit
  inverted the meaning of the one atomic SSOT the class wants callers to use.
- **A witness function's OWN body is out of scope.** ``record_access_event`` commits
  its chain row in the ``try`` and re-chains in the ``except sqlite3.IntegrityError``
  branch, which textual order reads as commit-then-witness. The emitter primitives'
  internals are PD#3/PD#12 territory (``TestAuditEmitterRedactionPin``, the
  fail-closed chain tests); this class is about CALLERS composing a state change with
  a witness.
- **A ``record_hipaa_access_event`` → ``update_hipaa_access_event`` bracket opened
  BEFORE the state change is the INVERSE of this class.** Per
  ``update_hipaa_access_event``'s own docstring the row is emitted at op-START with
  ``outcome="in_progress"`` and the UPDATE finalises that same row, so the witness is
  already durable by the time the state commits (``distill_hipaa_style``,
  ``run_triage``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from _pin_harness import (  # type: ignore[import-not-found]
    HOP_DISPATCHERS,
    SRC_ROOT,
    annotate_parents,
    audit_emitter_names,
    chain_writer_names,
    enclosing_qualified_name,
    hop_target,
    iter_src_files,
    parse_source,
    relpath,
    walk_src,
)

# ---------------------------------------------------------------------------
# The enumeration signature, in code so the census cannot drift from the
# detector (PD#6 — one scanner, consumed by the census note AND by this pin).
# ---------------------------------------------------------------------------

#: Off-loop dispatchers whose FIRST POSITIONAL ARG is the real callee: the
#: interprocedural hop PD#2 requires. Defined once in `_pin_harness` (punch 672) and
#: imported above, so the name stays importable from here for N-543 and the others.

#: The top-level package every src module lives under.
_PKG = "email_triage"

#: Modules in which a function that CALLS a witness is itself a witness (the third
#: arm of :func:`witnesses`).
#:
#: **Why a module scope and not a name list.** ``web/login_guard.py``'s
#: ``record_login_failure`` (`:159`) and ``record_login_lockout`` (`:273`) are pure
#: audit funnels — each body is a swallowed Prometheus increment plus
#: ``safe_audit_write(lambda: record_auth_event(...))`` and nothing else — so a
#: caller that commits state before them is the same defect as one that commits
#: before ``record_auth_event`` directly. A hardcoded two-name tuple would be
#: ``len(X)==N`` in disguise (R1 disguise (b)), blind to a third funnel added to
#: that module tomorrow. Keying on "in this module, and calls a witness" is a
#: property over every site in the module, so a new login-failure funnel joins
#: automatically. ``test_login_guard_witness_funnels_are_in_the_set`` is the teeth
#: arm that stops it resolving to nothing.
#:
#: **Why this module and no other.** General one-hop witness transitivity was
#: MEASURED and rejected: it takes the witness set from 18 to 106 of 3365 and floods
#: with authorization-resolver hits (``require_admin_ui`` / ``_require_login`` /
#: ``get_current_user`` preceding a handler's audit closure) — a strictly worse
#: instrument. ``web/login_guard.py`` contains no authorization resolvers, which is
#: what makes the restriction safe. Adding a module here is a coverage change and
#: needs the same before/after measurement (see below) recorded with it.
#:
#: **Measured effect of adding this arm** (at `693b11e3` + the four new ``*_txn``
#: siblings): witness set 22 → 24, findings **37 → 37**, zero sites dropped, zero
#: added — so it costs NO coverage. What it buys is that four login sites re-pair
#: onto their TRUE mechanism instead of onto an audit-writer that commits nothing:
#: ``_consume_recovery_code._consume`` onto ``consume_recovery_code``,
#: ``login_verify._login_verify_db_work`` onto ``verify_otp``,
#: ``login_webauthn_finish._verify_webauthn`` onto ``finish_authentication``, and
#: ``login_dev_keypair_verify._verify_dev_keypair`` onto the ``mark_dev_key_used``
#: display stamp. The scanner thereby finds the three single-use credential burns the
#: hand triage found by reading the code — mechanical corroboration of the triage.
#:
#: **Probing this is a trap.** ``scan()`` memoises on ``id(idx)`` in
#: ``_DERIVED_CACHE``, so a before/after probe that reuses one index gets the CACHED
#: before-result back and reports "0 dropped" for the wrong reason. Any such probe
#: must clear ``_DERIVED_CACHE`` / ``_WITNESS_CACHE`` / ``_COMMIT_CACHE`` /
#: ``_INDEX_CACHE`` and rebuild the index between runs.
WITNESS_FUNNEL_MODULES: frozenset[str] = frozenset({"web/login_guard.py"})

#: The audit-chain primitives. They are the WITNESS, never the state change, so
#: they are excluded from the state side even though they reach a commit.
_CHAIN_PRIMITIVE_NAMES: frozenset[str] = frozenset(chain_writer_names())

#: FnKey = (repo-relative module path, dotted qualified function name).
FnKey = tuple[str, str]

#: Process-wide caches. The full-src walk + fixpoint costs ~50s; every test in this
#: module needs the same answer, so it is computed once. ``build_index()`` is the
#: only entry point that seeds them.
_CALLS_CACHE: dict[tuple[str, int], list[tuple[int, "FnKey"]]] = {}
_INDEX_CACHE: list["SrcIndex"] = []
_DERIVED_CACHE: dict[int, tuple[set["FnKey"], set["FnKey"], list["Finding"]]] = {}


def _qualname(node: ast.AST) -> str:
    """Dotted qualified name of a def node (``config_save._classifier_change_clear``).

    ``enclosing_qualified_name`` returns the PARENT chain, so the node's own name is
    appended here.
    """
    parent = enclosing_qualified_name(node)
    own = getattr(node, "name", "<anon>")
    return own if parent == "<module>" else f"{parent}.{own}"


def _rel_to_dotted(rel: str) -> str:
    """``web/db.py`` -> ``email_triage.web.db``; ``db/__init__.py`` -> ``email_triage.db``."""
    # ``rel`` is already the harness's canonical forward-slash form (every producer
    # here is ``_pin_harness.relpath``), so no path normalisation belongs in this
    # module — N-224 R22 harness contract #5.
    parts = rel.removesuffix(".py").split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join([_PKG, *parts])


def _dotted_to_rel(dotted: str, known: dict[str, str]) -> str | None:
    """Reverse of :func:`_rel_to_dotted`, via the module index."""
    return known.get(dotted)


def _callee_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _own_body_nodes(fn: ast.AST):
    """Every node inside ``fn`` EXCEPT the bodies of nested ``def``s.

    A nested ``def`` is graded as its own function (so ``_baa_ack_db_work`` is graded
    on its own body); the enclosing handler sees only ``db_call(_baa_ack_db_work)``,
    which the hop resolver maps back to the closure — so neither grain is blind.

    A ``lambda`` body is NOT excluded, and that is load-bearing: the
    ``safe_audit_write_async(lambda: db_call(record_hipaa_access_event, …))`` idiom
    puts the START-side witness inside a lambda in five src functions, and skipping
    lambda bodies hid every one of them — which made three call sites read as
    "state commits before the witness" when their witness is emitted first. A
    lambda handed to an audit wrapper is invoked in place, so counting it in the
    enclosing body's sequence is both simpler and the direction that sees more.
    """
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _own_body_commits(fn: ast.AST) -> list[int]:
    """Linenos of raw ``<expr>.commit()`` calls in ``fn``'s own body."""
    return sorted(
        node.lineno
        for node in _own_body_nodes(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "commit"
    )


# ---------------------------------------------------------------------------
# The structural index: modules, their defs, and their name bindings.
# ---------------------------------------------------------------------------


@dataclass
class SrcIndex:
    #: dotted module name -> repo-relative path
    modules: dict[str, str] = field(default_factory=dict)
    #: rel -> {bare def name -> FnKey} (module-level AND nested defs)
    defs: dict[str, dict[str, FnKey]] = field(default_factory=dict)
    #: rel -> {local name -> ("fn", source rel, source bare name)}
    name_imports: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)
    #: rel -> {local alias -> source rel} for module imports
    mod_imports: dict[str, dict[str, str]] = field(default_factory=dict)
    #: FnKey -> ast node
    nodes: dict[FnKey, ast.AST] = field(default_factory=dict)
    #: FnKey -> True if its OWN body reaches ``.commit()``
    direct_commit: set[FnKey] = field(default_factory=set)
    #: the relpaths actually parsed
    parsed: set[str] = field(default_factory=set)


def _import_targets(rel: str, node: ast.ImportFrom | ast.Import, modules: dict[str, str]):
    """Yield ``("fn", local, (src_rel, name))`` / ``("mod", local, src_rel)`` bindings.

    Collected from EVERY ``import`` in the module — module-level and function-local
    alike (this codebase does most of its DB-helper imports inside the handler body
    to break the ``web/app.py`` cycle). A function-local import therefore binds
    module-wide here: an over-approximation, documented in the SCOPE CAVEAT.
    """
    if isinstance(node, ast.Import):
        for alias in node.names:
            src = modules.get(alias.name)
            if src:
                yield "mod", (alias.asname or alias.name.split(".")[-1]), src
        return
    base = node.module or ""
    if node.level:
        here = _rel_to_dotted(rel).split(".")
        # ``from . import x`` inside ``a/b.py`` is package ``a``.
        pkg = here[: len(here) - node.level]
        base = ".".join([*pkg, base]) if base else ".".join(pkg)
    for alias in node.names:
        local = alias.asname or alias.name
        sub = f"{base}.{alias.name}"
        if sub in modules:  # ``from email_triage.db import style``
            yield "mod", local, modules[sub]
        elif base in modules:  # ``from email_triage.web.db import set_setting``
            yield "fn", local, (modules[base], alias.name)


def build_index() -> SrcIndex:
    """Walk every parseable file under ``src/`` once and index it (cached)."""
    if _INDEX_CACHE:
        return _INDEX_CACHE[0]
    idx = SrcIndex()
    trees: list[tuple[str, ast.AST]] = []
    for _path, rel, tree in walk_src():
        idx.parsed.add(rel)
        idx.modules[_rel_to_dotted(rel)] = rel
        trees.append((rel, tree))
    for rel, tree in trees:
        annotate_parents(tree)
        dmap: dict[str, FnKey] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key: FnKey = (rel, _qualname(node))
                idx.nodes[key] = node
                dmap.setdefault(node.name, key)
                if _own_body_commits(node):
                    idx.direct_commit.add(key)
        idx.defs[rel] = dmap
        names: dict[str, tuple[str, str]] = {}
        mods: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for kind, local, target in _import_targets(rel, node, idx.modules):
                    if kind == "fn":
                        names.setdefault(local, target)  # type: ignore[arg-type]
                    else:
                        mods.setdefault(local, target)  # type: ignore[arg-type]
        idx.name_imports[rel] = names
        idx.mod_imports[rel] = mods
    _INDEX_CACHE.append(idx)
    return idx


def resolve(idx: SrcIndex, rel: str, node: ast.Call, *, depth: int = 0) -> FnKey | None:
    """The FnKey a call in module ``rel`` targets, or None when unresolvable.

    Resolution order: a hop dispatcher's first positional argument; a local name
    bound by an ``import``; a def in this module; a ``module.attr`` where ``module``
    is a bound src module. Re-export chains (``web/db.py`` re-exporting
    ``db/style.py``) are followed through :func:`_follow`.
    """
    func = node.func
    name = _callee_name(node)
    hop = hop_target(node)
    if hop is not None:
        # punch 672: Name, Attribute, `lambda: f(..)`, `partial(f, ..)`, run_in_executor
        return _follow(idx, rel, hop.name) if hop.name else None
    if name in HOP_DISPATCHERS and node.args:
        return None  # a hop whose callee is no name (a call result, a subscript)
    if isinstance(func, ast.Attribute):
        base = func.value
        alias = (base.id if isinstance(base, ast.Name)
                 else base.attr if isinstance(base, ast.Attribute) else None)
        src = idx.mod_imports.get(rel, {}).get(alias or "")
        if src:
            return _follow(idx, src, func.attr)
        return None  # a method on an object — not a module-level helper
    if isinstance(func, ast.Name):
        return _follow(idx, rel, func.id)
    return None


def _follow(idx: SrcIndex, rel: str, name: str, *, depth: int = 0) -> FnKey | None:
    """Resolve ``name`` as bound in module ``rel``, following re-exports."""
    if depth > 6:  # pragma: no cover - re-export chains here are 1-2 deep
        return None
    own = idx.defs.get(rel, {}).get(name)
    if own:
        return own
    imported = idx.name_imports.get(rel, {}).get(name)
    if imported:
        src_rel, src_name = imported
        if (src_rel, src_name) != (rel, name):
            return _follow(idx, src_rel, src_name, depth=depth + 1)
    return None


def _own_body_resolved_calls(idx: SrcIndex, rel: str, fn: ast.AST) -> list[tuple[int, FnKey]]:
    cached = _CALLS_CACHE.get((rel, id(fn)))
    if cached is not None:
        return cached
    out: list[tuple[int, FnKey]] = []
    for node in _own_body_nodes(fn):
        if isinstance(node, ast.Call):
            key = resolve(idx, rel, node)
            if key:
                out.append((node.lineno, key))
    out.sort()
    _CALLS_CACHE[(rel, id(fn))] = out
    return out


def _with_context_spans(fn: ast.AST) -> dict[int, tuple[int, int]]:
    """``{context-expr call lineno: (with start, with end)}`` for ``fn``'s own body.

    A ``with _clock_txn(conn):`` commits at clean EXIT, so a witness written INSIDE
    the body precedes that commit. Without this the one atomic SSOT for the ten
    ``regulatory_clock`` transitions reads as the defect it prevents.
    """
    spans: dict[int, tuple[int, int]] = {}
    for node in _own_body_nodes(fn):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            end = node.end_lineno or node.lineno
            for item in node.items:
                expr = item.context_expr
                if isinstance(expr, ast.Call):
                    spans[expr.lineno] = (node.lineno, end)
    return spans


_COMMIT_CACHE: dict[int, set[FnKey]] = {}
_WITNESS_CACHE: dict[int, set[FnKey]] = {}


def self_committing(idx: SrcIndex) -> set[FnKey]:
    """Fixpoint closure: every FnKey that commits, directly or through a callee.

    Count-agnostic by construction — a closure over the AST, never a curated list
    (R1: "a hardcoded name list is ``len(X)==N`` in disguise").
    """
    hit = _COMMIT_CACHE.get(id(idx))
    if hit is not None:
        return hit
    committers = set(idx.direct_commit)
    edges: dict[FnKey, set[FnKey]] = {}
    for key, node in idx.nodes.items():
        edges[key] = {k for _ln, k in _own_body_resolved_calls(idx, key[0], node)}
    changed = True
    while changed:
        changed = False
        for key, callees in edges.items():
            if key not in committers and callees & committers:
                committers.add(key)
                changed = True
    _COMMIT_CACHE[id(idx)] = committers
    return committers


def witnesses(idx: SrcIndex) -> set[FnKey]:
    """Every audit-witness writer.

    The ``@audit_emitter`` family + the chain primitives + every function whose own
    body calls a chain primitive. The last arm is what pulls in the NON-committing
    ``*_txn`` siblings (``record_hipaa_boundary_txn``, ``emit_clock_event_txn``) and
    the in-transaction emitters (``set_user_disabled``, ``set_account_hipaa``): they
    are witnesses too, so a state change committed before them is the same defect
    even though the witness itself joins the caller's transaction.
    """
    hit = _WITNESS_CACHE.get(id(idx))
    if hit is not None:
        return hit
    out: set[FnKey] = set()
    for name in set(audit_emitter_names()) | set(_CHAIN_PRIMITIVE_NAMES):
        for rel in ("db/audit.py", "db/style.py"):
            key = idx.defs.get(rel, {}).get(name)
            if key:
                out.add(key)
    prim = {k for k in out if k[1] in _CHAIN_PRIMITIVE_NAMES}
    for key, node in idx.nodes.items():
        if {k for _ln, k in _own_body_resolved_calls(idx, key[0], node)} & prim:
            out.add(key)
    # Third arm — a witness FUNNEL, scoped to the modules in
    # ``WITNESS_FUNNEL_MODULES``: a function whose own body calls something already
    # in the witness set. Exactly ONE hop, tested against a frozen snapshot of the
    # set so the arm cannot quietly become transitive within the module.
    base = frozenset(out)
    for key, node in idx.nodes.items():
        if key[0] not in WITNESS_FUNNEL_MODULES:
            continue
        if {k for _ln, k in _own_body_resolved_calls(idx, key[0], node)} & base:
            out.add(key)
    _WITNESS_CACHE[id(idx)] = out
    return out


@dataclass(frozen=True)
class Finding:
    relpath: str
    qualname: str
    state_line: int
    state_callee: str
    witness_line: int
    witness_callee: str

    @property
    def key(self) -> FnKey:
        """Allow-list key — (repo-relative path, qualified fn), NEVER a lineno
        (R38: a line-keyed exemption breaks fail-CLOSED on an unrelated edit)."""
        return (self.relpath, self.qualname)


def scan(idx: SrcIndex | None = None) -> list[Finding]:
    """Every commit-before-witness site in ``src/``.

    THE PREDICATE: within ONE function's own body, a resolved call to a
    self-committing non-witness helper (or a raw ``.commit()``) at line L1, and a
    resolved call to an audit-witness writer at line L2 > L1 — EXCLUDING (a)
    functions that are themselves witnesses, and (b) a state call that is the
    context-expression of a ``with`` whose body holds the witness (the commit there
    happens at exit, i.e. after the witness). Both exclusions are argued in the
    module docstring.
    """
    idx = idx or build_index()
    cached = _DERIVED_CACHE.get(id(idx))
    if cached is not None:
        return cached[2]
    committers = self_committing(idx)
    wits = witnesses(idx)
    findings = [
        f for key, node in idx.nodes.items()
        if (f := evaluate(idx, key, node, committers, wits)) is not None
    ]
    findings.sort(key=lambda f: (f.relpath, f.state_line))
    _DERIVED_CACHE[id(idx)] = (committers, wits, findings)
    return findings


def evaluate(
    idx: SrcIndex,
    key: FnKey,
    node: ast.AST,
    committers: set[FnKey],
    wits: set[FnKey],
) -> Finding | None:
    """THE predicate, for ONE function. :func:`scan` and the teeth share it, so the
    teeth cannot pass against a second, kinder copy of the rule (PD#6)."""
    rel, qual = key
    if key in wits:
        return None  # exclusion (b): an emitter primitive's own body
    calls = _own_body_resolved_calls(idx, rel, node)
    wit_hits = [(ln, k) for ln, k in calls if k in wits]
    if not wit_hits:
        return None
    spans = _with_context_spans(node)
    state: list[tuple[int, str]] = [
        (ln, k[1]) for ln, k in calls if k in committers and k not in wits
    ]
    state += [(ln, "<conn>.commit()") for ln in _own_body_commits(node)]
    state.sort()
    opened = [ln for ln, k in calls if k[1] == "record_hipaa_access_event"]
    for w_ln, w_key in wit_hits:
        earlier = [
            (ln, nm) for ln, nm in state
            if ln < w_ln
            # exclusion (a): a committing context manager whose body holds this
            # witness commits AFTER it.
            and not (ln in spans and spans[ln][0] <= w_ln <= spans[ln][1])
        ]
        if not earlier:
            continue
        # exclusion (c): the explicit start/finalise bracket.
        # ``update_hipaa_access_event``'s own docstring: the row is emitted at
        # op-START by ``record_hipaa_access_event`` with outcome="in_progress"
        # and this UPDATE finalises the SAME row. When the start-emit precedes
        # the state change, the witness is already durable before the state
        # commits — the inverse of this class — so the finalise is not a witness
        # at risk here.
        if (w_key[1] == "update_hipaa_access_event"
                and opened and min(opened) < earlier[0][0]):
            continue
        s_ln, s_nm = earlier[0]
        return Finding(rel, qual, s_ln, s_nm, w_ln, w_key[1])
    return None


# ---------------------------------------------------------------------------
# The ratchet baseline. Keyed by (repo-relative path, qualified fn) — stable under
# an unrelated edit (R38). Every entry names its register row and its reason.
#
# TRIAGE STATE (2026-09-29, ``543-triage.md``): all 37 entries carry a MEMBER or
# CLEARED label; the UNTRIAGED bucket is EMPTY. 24 MEMBER · 13 CLEARED. The class is
# **24 members, not the 15 the register first recorded** — 14 verified by the census,
# 10 added by the triage — and 24 is a LOWER BOUND, not a count, because 4 of the 19
# triaged sites were members via a state change this predicate structurally cannot see
# (SCOPE CAVEAT, state-side blindness). ``enumeration_complete=false`` stays for all
# five declared directions. Since then punch 544 FIXED triage row 8
# (``profile_watches_save_new._save_and_audit``, now through
# ``db/audit.record_watch_group_save``) and its entry was deleted; the counts above
# are the 2026-09-29 triage's, not a live total. Punch  (2026-10-12) added TWO
# entries (``finish_registration`` and ``profile_hw_register_finish._finish_reg``),
# filed UNTRIAGED by their author because an author clearing his own new site through
# this allow-list is the self-sealing shape. hipaa-sme labelled both CLEARED at panel E
# (2026-10-13); register N-608 carries the same two labels.
#
# A CLEARED reason carries the code that cleared it, so rows stay comparable:
#   (i)   the witness is written first (including a witness hidden in a ``lambda``)
#   (ii)  both writes are already in one transaction
#   (iii) the state is not durable / not security- or audit-relevant
#   (iv)  the two calls sit on mutually exclusive branches (a textual-order artifact)
#   (v)   the flagged callee is not the state change this witness describes
#
# The ``web/login_guard.py`` witness-set arm (``543-design.md`` §7.2) IS applied, as
# ``WITNESS_FUNNEL_MODULES``. An earlier note here said to hold it until the family-1
# funnels land, because adding ``record_login_failure`` / ``record_login_lockout`` to
# :func:`witnesses` was measured to drop 4 findings (37 -> 33) and three of those were
# live MEMBERs. That figure was not re-measured for the module-scoped arm on this
# tree; what holds on this tree is ``test_known_members_are_actually_detected``:
# ``_verify_webauthn``, ``_consume_recovery_code._consume`` and
# ``login_verify._login_verify_db_work`` are all still detected with the arm in place.
# If a change to the arm ever makes that test name one of them, the arm is wrong, not
# the entry: do NOT delete a live MEMBER to make the ratchet green.
# ---------------------------------------------------------------------------

BASELINE: dict[FnKey, str] = {
    ("cli.py", "_emit_cli_audit_event"): (
        "N-520 CLEARED — the flagged state call is _cli_open_config_db — "
        "opening/bootstrapping the config DB, which transitively commits. It "
        "is not the state change record_cli_admin_op witnesses; resolver "
        "precision limit, not the class. "
    ),
    ("cli.py", "_cmd_user_renormalize_emails"): (
        "N-520 CLEARED (panel Z clsAD, 2026-10-27) — the flagged state call is "
        "_cli_open_config_db, the same bootstrap commit as _emit_cli_audit_event. "
        "The change the witness covers (the renormalize-emails users.email "
        "rewrite) commits inside record_user_update in the same transaction as "
        "its user_email_changed witness (MUST-Z1-1). Resolver precision limit, "
        "not the class. Keyed on this helper alone, never on cmd_user, so every "
        "other user subcommand stays fail-closed (hipaa MUST-Z1-R4). "
    ),
    ("jobs/topic_backscan.py", "run_topic_backscan_job"): (
        (
        "N-520 CLEARED (iv) — triage row 14. Read end to end: at :545-551 the \"if "
        "topic_id is None:\" branch commits finish_triage_job(status=\"failed\") and "
        "then RETURNS at :551, so the start-side record_hipaa_access_event at "
        ":602 is reachable only when topic_id is not None. The two calls sit on "
        "mutually exclusive branches — the textual-order over-approximation this "
        "pin declares, not the class. Census prediction confirmed. "
    )
    ),
    ("web/app.py", "create_app.lifespan"): (
        "N-520 CLEARED — init_db_encrypted at boot, and 600 lines later a "
        "boot-posture reconciliation (record_hipaa_boundary fires only when "
        "the last recorded direction differs). The boundary event does not "
        "witness the DB open. "
    ),
    ("web/background_sweepers.py", "_run_sent_mail_capture_sweep"): (
        (
        "N-520 CLEARED (v)+(iv) — triage row 19. "
        "_run_hipaa_counter_for_account@1853 (itself the row-10 member) sits in a "
        "try whose handler is \"except Exception as hipaa_err:\" at :1856, while "
        "the witness at :1904 is in a DIFFERENT handler — "
        "record_auth_event(sent_mail_capture, outcome=\"failure\", "
        "detail=f\"provider_build: ...\"), the provider-build failure edge on a "
        "different loop iteration -> (v)+(iv). The outer grain adds nothing the "
        "row-10 entry does not already carry. "
    )
    ),
    ("web/background_sweepers.py", "_run_hipaa_counter_for_account"): (
        (
        "N-520 CLEARED — ACCEPT-WITH-RECORD (s2 panel hipaa-sme ruling, "
        "2026-11-06): the HIPAA sent-counter state is SELF-WITNESSING. Each dedup "
        "row in record_hipaa_sent_message_if_new (web/db.py) commits atomically "
        "with its counter bump, so the per-message row is the durable record of "
        "the state, and the tick hipaa_sent_counter auth_event is only a summary "
        "of it. Holding one transaction across the provider awaits in "
        "scan_recent() would block every writer on the shared connection. Not an "
        "N-520 gap; §164.316 register row filed with this change. Prior triage "
        "text follows. triage row 10 and C-3. THE FLAGGED CALLEE IS NOT THE "
        "STATE CHANGE: the census named record_provider_outcome@2134 (the "
        "auth_stale chip clear), which reason (v) would clear. The real state "
        "change is loop.scan_recent() -> record_hipaa_sent_message_if_new at "
        ":2111 — web/db.py:4003, whose docstring at :4028/:4033 says it commits "
        "the dedup INSERT and every counter bump as ONE commit — before "
        "record_auth_event(hipaa_sent_counter, detail=f\"recorded={new_count}\") at "
        ":2148, which describes precisely that recording. A method call on an "
        "object, so invisible to this predicate (see the SCOPE CAVEAT). "
    )
    ),
    ("web/digest.py", "_fire_one_digest"): (
        (
        "N-520 CLEARED (v)+(iv) — triage row 18. :693-702 is the shared render "
        "helper the preview and show-matches routes also call (\"the render shape "
        "is bit-identical across all three paths\", :693-695), so "
        "_render_digest_payload@698's transitive commit is incidental to a render "
        "and is not the state change the access event describes -> (v). The \"if "
        "not rows:\" empty-window branch at :704-706 stamps last_sent and returns, "
        "mutually exclusive with the send the witness at :779 covers -> (iv). The "
        "genuine member in this family is the already-verified "
        "recipient_digest_send_now._digest_sent_db_work. "
    )
    ),
    ("web/routers/agent_api.py", "webhook_watches_create"): (
        "N-520 CLEARED — the flagged state call is _require_webhook_account — "
        "an authorization resolver that transitively commits (session touch), "
        "not the state change record_hmac_clobber_bypass_consumed witnesses. "
    ),
    ("web/routers/auth_keys.py", "login_dev_keypair_verify._verify_dev_keypair"): (
        (
        "N-520 CLEARED (v)+(iii) — triage row 11 and C-3. The flagged callee "
        "record_login_failure@580 writes only an auth_events row; there is no "
        "durable lockout counter, so the census reason was false and the flagged "
        "pair is witness-then-witness -> (v). The success path's only writes are "
        "mark_dev_key_used@604 and update_last_login@607, which stamp "
        "last_used_at / last_login for the admin UI's \"last used N min ago\" "
        "display (db/audit.py:1099-1101) -> (iii). Checked explicitly for a "
        "single-use burn — the check that flipped rows 3, 4 and 5 — and this "
        "surface burns nothing: it is a detached-signature check over a stored "
        "fingerprint (find_dev_key_by_fingerprint@576). "
    )
    ),
    ("web/routers/auth_keys.py", "admin_system_restart"): (
        "N-520 CLEARED — the flagged state call is the _require_admin "
        "authorization check; the record_auth_event row is written BEFORE the "
        "restart timer fires, which is the stated intent of the handler. "
    ),
    ("web/routers/ui/profile.py", "profile_watches_save_new"): (
        (
        "N-520 CLEARED (v) — triage row 12. The outer grain. "
        "db_call(_save_and_audit)@3590 (line numbers at 5f56b6af) commits the watch rows, but the witness at "
        ":3631 is record_hmac_clobber_bypass_consumed, which sits inside the "
        "per-watch HMAC secret mint (:3594-3631, the get_or_mint_secret SSOT) and "
        "witnesses consumption of an HMAC-clobber bypass — a different operation "
        "from the watch save. The watch save's own witness is in the inner "
        "closure, which was the triage-row-8 MEMBER until punch 544 routed it "
        "through db/audit.record_watch_group_save (rows + access events in one "
        "transaction) and its entry was deleted here. "
    )
    ),
    ("web/routers/ui/profile.py", "profile_watches_save_existing"): (
        (
        "N-520 CLEARED (v) — triage row 13. Same argument as the save_new outer "
        "grain: db_call(_save)@3733 (line numbers at 5f56b6af) commits the watch rows and the witness at "
        ":3775 is the HMAC-clobber-bypass consume, a different operation. BUT "
        "reading this row at the object surfaced punch 544 / register N-539, "
        "which is NOT this class: the _save closure called save_watch_group "
        "and nothing else, so an EDIT that fanned out to a delegate's HIPAA "
        "account emitted no 164.312(b) access-event row at all. No-witness, "
        "not late-witness; fixed by punch 544 through the same "
        "record_watch_group_save funnel as save_new. "
    )
    ),
    ("web/topic_digest_sender.py", "_fire_topic_digest"): (
        (
        "N-520 CLEARED (iv) — triage row 15. Read end to end: at :548-555 the \"if "
        "not hits:\" branch stamps mark_topic_digest_sent (watermark=None) and "
        "then \"return 0\", while the witness at :641 is inside \"if hipaa_topic:\" "
        "on the send path, reachable only when hits is non-empty. Mutually "
        "exclusive branches. Census prediction confirmed. "
    )
    ),
    ("web/triage_runner_bulk.py", "run_style_mine_job"): (
        (
        "N-520 CLEARED (iv) — triage row 16. At :360-370 the HIPAA-opt-in refusal "
        "commits finish_triage_job(status=\"failed\") and returns None, None, "
        "False; the caller at :371-374 does \"if acct is None: return\". REASON "
        "REFINEMENT on the census: it correctly noted that exclusion (c) does not "
        "apply because the bracket opens AFTER the validation write — true, and "
        "irrelevant, because the validation write only happens on a branch that "
        "returns. Cleared on (iv), not on (c). "
    )
    ),
    ("web/triage_runner_bulk.py", "run_triage_all"): (
        (
        "N-520 CLEARED (iv) — triage row 17. Verified independently rather than "
        "accepted as \"same shape as run_style_mine_job\": at :844-857 EVERY "
        "finish_triage_job in the _validate_bulk_job closure is followed by "
        "\"return None, None, None, None\", and :860-862 is \"if acct is None: "
        "return\". Mutually exclusive branches, same (iv) as run_style_mine_job. "
    )
    ),
    ("web/webauthn_auth.py", "finish_registration"): (
        "N-520 CLEARED (ii)+(v) — punch #525, labelled by hipaa-sme at panel E "
        "2026-10-13 (register N-608). The flagged state is consume_webauthn_challenge @289 (db/users.py:458 "
        "@_db_write, commit :520) burning the single-use REGISTRATION challenge "
        "before the record_hardware_key_registration witness @341. That witness "
        "describes the GRANT, and the grant (add_hardware_key_txn) is in ONE "
        "transaction with it (ii) — no key can land unwitnessed. The burn is not the "
        "state this witness describes (v): it grants nothing, and a burn whose grant "
        "then rolls back leaves the user with no credential and a retry. Contrast "
        "the login twins (_verify_webauthn / _verify_passkey, MEMBER): there the "
        "witness describes the authentication the burn completes. Pre-#525 this "
        "function burned the challenge and committed the key with NO witness at all. "
        "Every WebAuthnAuthError raise precedes @341; a failed witness rolls the grant "
        "back and @audit_emitter writes a gap row. "
    ),
    ("web/routers/auth_keys.py", "profile_hw_register_finish._finish_reg"): (
        "N-520 CLEARED (iv)+(v) — punch #525, labelled by hipaa-sme at panel E "
        "2026-10-13 (register N-608). The flagged pair is wa.finish_registration @1318 then the record_auth_event "
        "@1328 — but @1328 is the REFUSED-enrolment row inside "
        "``except wa.WebAuthnAuthError``, reached only when finish_registration "
        "raised, i.e. when NO grant committed (iv: the grant and this witness are "
        "mutually exclusive; the grant's own witness is atomic inside the funnel). "
        "The only durable residue on that edge is the challenge burn, which grants "
        "nothing (v). The refused row is safe_audit_write (degrade-and-proceed): a "
        "chain failure there loses the record of a refusal, never of a grant. A "
        "non-WebAuthn failure inside the funnel propagates as a 500 with a gap row, "
        "not as a refused row. "
    ),
}

#: The three triage labels a BASELINE value may carry.
LABELS: tuple[str, ...] = ("MEMBER", "CLEARED", "UNTRIAGED")


def _fmt(f: Finding) -> str:
    return (
        f"{f.relpath}::{f.qualname} — {f.state_callee} @{f.state_line} commits "
        f"before the {f.witness_callee} witness @{f.witness_line}"
    )


class TestCommitBeforeWitnessPin:
    """N-520. Count-agnostic: the scan is the primary invariant, ``BASELINE`` is the
    belt (R1 — never ``len(X)==N``)."""

    def test_no_new_commit_before_witness_site(self) -> None:
        new = [f for f in scan() if f.key not in BASELINE]
        assert not new, (
            "NEW commit-before-witness site(s): a durable state change commits "
            "before the audit row that witnesses it, so a failure in between (the "
            "fail-closed HMAC chain on a key gap) loses the witness for a change "
            "that is already durable. Route both halves through ONE transaction via "
            "*_txn siblings, per "
            "db/audit.py::record_system_hipaa_flip (N-466):\n  "
            + "\n  ".join(_fmt(f) for f in new)
        )

    def test_allowlists_are_not_stale(self) -> None:
        """Every ``BASELINE`` entry still matches a live site (R38 guard 2)."""
        live = {f.key for f in scan()}
        stale = sorted(k for k in BASELINE if k not in live)
        assert not stale, (
            "allow-list entr(ies) no longer match a live site — the site was fixed "
            "or moved; delete the entry (and close its register row) so the pin "
            "cannot silently allow-list nothing: " + repr(stale)
        )

    def test_known_members_are_actually_detected(self) -> None:
        """``pattern_prove_the_input_is_in_the_set_the_control_acts_on``: a PASS on
        the ratchet means nothing unless the class's known members are in the set the
        scan produces."""
        live = {f.key for f in scan()}
        for key in BASELINE:
            assert key in live, f"detector does not see enumerated member {key}"

    def test_reference_fix_shape_is_not_flagged(self) -> None:
        """The N-466 fix and the in-transaction emitters must NOT be findings, or the
        pin would push callers away from the correct shape."""
        flagged = {f.qualname for f in scan()}
        # Each name must EXIST in the scanned index: a name the scan never sees can
        # never be flagged, so without this the arm passes vacuously (it did, for a
        # nonexistent symbol, until 2026-09-29; design-543 caught it).
        indexed = {q for (_r, q) in build_index().nodes}
        for good in (
            "record_system_hipaa_flip",
            "set_user_disabled",
            "set_account_hipaa",
            "record_hipaa_boundary",
            "record_auth_event",
            "record_hardware_key_registration",  # punch  grant funnel
        ):
            assert good in indexed, f"{good} is not in the scanned index; this arm would be vacuous"
            assert good not in flagged, (
                f"{good} is the correct atomic shape (or a witness primitive) and "
                "must not be flagged"
            )

    def test_the_interprocedural_hop_is_live(self) -> None:
        """PD#2: ``db_call(helper, …)`` must resolve to ``helper``; without it the pin
        is keyed on the seam and blind to the dominant idiom here."""
        idx = build_index()
        rel = "web/routers/ui/admin.py"
        node = idx.nodes[(rel, "config_baa_ack")]
        resolved = {q for _ln, (_r, q) in _own_body_resolved_calls(idx, rel, node)}
        assert "config_baa_ack._baa_ack_db_work" in resolved, (
            "db_call's first positional arg did not resolve to the closure"
        )

    def test_witness_set_includes_the_txn_siblings(self) -> None:
        """A non-committing ``*_txn`` witness is still a witness — otherwise a handler
        that own-commits state and then writes its audit row through a ``*_txn``
        sibling in a later transaction reads clean."""
        names = {q for _r, q in witnesses(build_index())}
        for expected in ("record_hipaa_boundary_txn", "record_auth_event",
                         "_chain_insert", "emit_clock_event_txn"):
            assert expected in names, f"{expected} missing from the witness set"

    def test_login_guard_witness_funnels_are_in_the_set(self) -> None:
        """The teeth arm for ``WITNESS_FUNNEL_MODULES`` — without it the module-scoped
        third arm could resolve to NOTHING and still read as a live control
        (``pattern_an_uninvoked_control_is_indistinguishable_from_no_control``).

        Both names must be found AND the scoped module must exist in the parsed set,
        so a rename of ``web/login_guard.py`` fails here rather than silently
        emptying the arm.
        """
        idx = build_index()
        for rel in WITNESS_FUNNEL_MODULES:
            assert rel in idx.parsed, (
                f"{rel} is in WITNESS_FUNNEL_MODULES but was not parsed, so that "
                "arm of the witness set resolves to nothing"
            )
        names = {q for _r, q in witnesses(idx)}
        for expected in ("record_login_failure", "record_login_lockout"):
            assert expected in names, (
                f"{expected} is a pure audit funnel in web/login_guard.py (its whole "
                "body is a swallowed counter bump plus safe_audit_write(lambda: "
                "record_auth_event(...))) and must be a witness, or a handler that "
                "commits state before it reads clean"
            )

    def test_the_witness_funnel_arm_is_one_hop_and_stays_scoped(self) -> None:
        """The arm must not become general transitivity by accident.

        General one-hop transitivity was measured and rejected: 18 -> 106 of 3365,
        flooded with authorization resolvers. Two guards: nothing outside the scoped
        modules joined via this arm, and the set stays far away from the flood size.
        """
        idx = build_index()
        wits = witnesses(idx)
        assert len(wits) < 40, (
            f"witness set is {len(wits)} — the scoped arm has leaked into general "
            "transitivity (the measured flood was 106)"
        )
        for bad in ("require_admin_ui", "_require_login", "get_current_user"):
            assert bad not in {q for _r, q in wits}, (
                f"{bad} is an authorization resolver, not a witness — the arm has "
                "stopped being module-scoped"
            )

    def test_committer_closure_is_transitive_and_excludes_txn(self) -> None:
        """The state side follows a helper that commits via ANOTHER helper; the
        non-committing ``*_txn`` siblings stay out of it."""
        idx = build_index()
        names = {q for _r, q in self_committing(idx)}
        for expected in ("unpause_baa_paused_style_distill_accounts",
                         "unpause_scrubber_fail_style_distill_accounts",
                         "set_setting", "record_auth_event"):
            assert expected in names, f"{expected} should be self-committing"
        for excluded in ("set_setting_txn", "record_hipaa_boundary_txn",
                         "emit_clock_event_txn", "_chain_insert"):
            assert excluded not in names, (
                f"{excluded} is a non-committing *_txn/primitive and must stay out "
                "of the state-change set, or the reference fix shape self-flags"
            )

    def test_resolution_is_not_bare_name_matching(self) -> None:
        """The state side resolves through module bindings, not bare names.

        A bare-name scanner makes every ``x.get(...)`` a commit as soon as ANY
        function named ``get`` commits — measured 2112 of 3365 src functions before
        this was tightened. The guard: an unbound method call resolves to None.
        """
        idx = build_index()
        tree = parse_source("def f(x):\n    x.get('k')\n    x.execute('UPDATE t')\n")
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        assert not _own_body_resolved_calls(idx, "web/db.py", fn), (
            "a method call on an object resolved to a module-level helper"
        )
        committers = self_committing(idx)
        assert len(committers) < len(idx.nodes) // 2, (
            f"self-committing closure is implausibly wide: {len(committers)} of "
            f"{len(idx.nodes)} — the resolver has lost precision"
        )

    def test_every_src_file_was_parsed(self) -> None:
        """The net covered the whole tree — an unparseable file silently shrinks the
        denominator (``pattern_a_silently_partial_verification_rig``)."""
        idx = build_index()
        on_disk = {relpath(p) for p in iter_src_files()}
        assert on_disk == idx.parsed, (
            "file(s) under src/ did not parse, so the scan did not cover them: "
            + repr(sorted(on_disk - idx.parsed))
        )
        assert len(idx.parsed) > 100, f"suspiciously small src walk: {len(idx.parsed)}"


class TestPinHasTeeth:
    """R38 guard 1 — plant the bad shape and assert it is caught; plant the good
    shapes and assert they are not. Both arms present, because a one-armed teeth
    suite cannot see a gate that blocks everything."""

    BAD = (
        "from email_triage.web.db import ("
        "unpause_baa_paused_style_distill_accounts, record_auth_event)\n"
        "def handler(db):\n"
        "    unpause_baa_paused_style_distill_accounts(db)\n"
        "    record_auth_event(db, event_type='x')\n"
    )
    # The state change lives in a SEPARATE helper, reachable from the flagged
    # function ONLY through the off-loop dispatcher. `run_in_threadpool` and not
    # `db_call`, deliberately: `db_call` is ITSELF in the self-committing closure
    # (it calls the helper it is handed), so with the hop disabled a
    # `db_call(_write, …)` call still resolves to `db_call` -> still a committer ->
    # the site still flags, and the arm could not discriminate. Asserted in
    # `test_db_call_is_itself_a_committer_so_it_cannot_be_the_hop_probe`.
    # `run_in_threadpool` is imported from starlette, which is not a src module, so
    # with the hop disabled it resolves to nothing at all.
    BAD_VIA_HOP = (
        "from starlette.concurrency import run_in_threadpool\n"
        "from email_triage.web.db import ("
        "unpause_baa_paused_style_distill_accounts, record_auth_event)\n"
        "def _write(db):\n"
        "    unpause_baa_paused_style_distill_accounts(db)\n"
        "async def route(db):\n"
        "    await run_in_threadpool(_write, db)\n"
        "    record_auth_event(db, event_type='x')\n"
    )
    # The dominant idiom, kept as a COVERAGE arm — it proves the `db_call` form is
    # caught; it does NOT prove the hop is what caught it (see the comment above).
    BAD_VIA_DB_CALL = (
        "from email_triage.web.db_threadpool import db_call\n"
        "from email_triage.web.db import ("
        "unpause_baa_paused_style_distill_accounts, record_auth_event)\n"
        "def _write(db):\n"
        "    unpause_baa_paused_style_distill_accounts(db)\n"
        "async def route(db):\n"
        "    await db_call(_write, db)\n"
        "    record_auth_event(db, event_type='x')\n"
    )
    GOOD_TXN = (
        "from email_triage.web.db import set_setting_txn\n"
        "from email_triage.db.audit import record_hipaa_boundary_txn\n"
        "def handler(conn):\n"
        "    set_setting_txn(conn, 'k', 'v')\n"
        "    record_hipaa_boundary_txn(conn, 'system', 'on')\n"
    )
    GOOD_WITNESS_FIRST = (
        "from email_triage.web.db import ("
        "unpause_baa_paused_style_distill_accounts, record_auth_event)\n"
        "def handler(db):\n"
        "    record_auth_event(db, event_type='x')\n"
        "    unpause_baa_paused_style_distill_accounts(db)\n"
    )

    REL = "_planted_teeth.py"

    @classmethod
    def _detect(cls, source: str) -> bool:
        """Run the REAL predicate over a planted module, wired into the REAL index.

        The planted source is registered under a synthetic relpath so its imports
        resolve against the live src tree through the same resolver — never a
        parallel, kinder copy of the rule. The synthetic entries are removed again so
        the shared index and its caches stay clean for the other tests.
        """
        idx = build_index()
        rel = cls.REL
        dotted = _rel_to_dotted(rel)
        tree = parse_source(source)
        annotate_parents(tree)
        planted: list[FnKey] = []
        dmap: dict[str, FnKey] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key: FnKey = (rel, _qualname(node))
                planted.append(key)
                dmap.setdefault(node.name, key)
        names: dict[str, tuple[str, str]] = {}
        mods: dict[str, str] = {}
        idx.modules[dotted] = rel
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for kind, local, target in _import_targets(rel, node, idx.modules):
                    (names if kind == "fn" else mods).setdefault(
                        local, target)  # type: ignore[arg-type]
        idx.defs[rel] = dmap
        idx.name_imports[rel] = names
        idx.mod_imports[rel] = mods
        try:
            committers = set(self_committing(idx))
            wits = witnesses(idx)
            nodes = {
                (rel, _qualname(n)): n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            # Promote the PLANTED defs into the committer closure the same way
            # `self_committing` does — a planted helper that calls a real
            # self-committing helper is itself self-committing. Without this a
            # planted two-function shape (state in a helper, witness in the caller)
            # could never flag, and a teeth arm that cannot flag proves nothing.
            changed = True
            while changed:
                changed = False
                for key, node in nodes.items():
                    if key in committers:
                        continue
                    callees = {k for _ln, k in _own_body_resolved_calls(idx, rel, node)}
                    if _own_body_commits(node) or (callees & committers):
                        committers.add(key)
                        changed = True
            return any(
                evaluate(idx, key, node, committers, wits) is not None
                for key, node in nodes.items()
            )
        finally:
            idx.modules.pop(dotted, None)
            idx.defs.pop(rel, None)
            idx.name_imports.pop(rel, None)
            idx.mod_imports.pop(rel, None)
            for cache_key in [k for k in _CALLS_CACHE if k[0] == rel]:
                _CALLS_CACHE.pop(cache_key, None)

    def test_teeth_flag_the_planted_bad_shape(self) -> None:
        assert self._detect(self.BAD), "detector missed a planted bad shape"

    def test_teeth_flag_the_bad_shape_reached_only_through_the_hop(self) -> None:
        """The DISCRIMINATING hop arm: the state change is in a separate helper that
        the flagged function reaches ONLY through the off-loop dispatcher, so this
        fails if the hop resolution is removed."""
        assert self._detect(self.BAD_VIA_HOP), (
            "detector missed a state change reachable only through the off-loop "
            "dispatcher — the interprocedural hop (PD#2) is not working"
        )

    def test_teeth_flag_the_bad_shape_reached_through_db_call(self) -> None:
        """COVERAGE arm for the dominant idiom. It does NOT prove the hop is what
        caught it — see `BAD_VIA_HOP`'s comment and
        `test_db_call_is_itself_a_committer_so_it_cannot_be_the_hop_probe`."""
        assert self._detect(self.BAD_VIA_DB_CALL), (
            "detector missed a bad shape inside a helper handed to db_call"
        )

    def test_db_call_is_itself_a_committer_so_it_cannot_be_the_hop_probe(self) -> None:
        """Records WHY the discriminating arm uses `run_in_threadpool`.

        `db_call` runs the helper it is handed, so it lands in the self-committing
        closure. A `db_call`-based teeth arm therefore still flags with the hop
        disabled — it resolves to `db_call`, which is a committer — and so cannot
        tell a working hop from a broken one. If this ever becomes False the
        discriminating arm may be simplified onto `db_call`.
        """
        assert ("web/db_threadpool.py", "db_call") in self_committing(build_index())

    def test_teeth_clear_the_txn_shape(self) -> None:
        assert not self._detect(self.GOOD_TXN), (
            "the reference *_txn fix shape was flagged — the pin would push callers "
            "away from the correct shape"
        )

    def test_teeth_clear_a_witness_first_shape(self) -> None:
        assert not self._detect(self.GOOD_WITNESS_FIRST), (
            "a witness written BEFORE the state commit was flagged"
        )


class TestEnumerationSignatureIsRecorded:
    """PD#4 — the enumeration signature is the FIRST deliverable, so it has to be
    discoverable from the code, not only from a working note."""

    def test_predicate_and_scope_caveat_are_documented(self) -> None:
        assert HOP_DISPATCHERS, "the interprocedural hop set is empty"
        assert scan.__doc__ and "THE PREDICATE" in scan.__doc__
        assert __doc__ and "SCOPE CAVEAT" in __doc__

    def test_allowlist_entries_carry_a_register_row_and_a_reason(self) -> None:
        for key, reason in BASELINE.items():
            assert len(reason) > 40, f"{key} has no real reason recorded"
            assert "N-520" in reason, f"{key} does not name its register row"

    def test_every_entry_carries_one_of_the_three_triage_labels(self) -> None:
        """An entry with no label is an untracked exemption: the reader cannot tell a
        verified member from an over-approximation nobody has looked at yet."""
        for key, reason in BASELINE.items():
            labels = [lb for lb in LABELS if reason.startswith(f"N-520 {lb} ")]
            assert len(labels) == 1, (
                f"{key} must start with exactly one of {LABELS}; got {reason[:40]!r}"
            )

    def test_the_two_panel_named_sites_write_their_witness_in_the_same_txn(self) -> None:
        """DB-422D-1 and N-514, successor of the old "labelled members" check.

        Both sites were VERIFIED members; N-520 step 2 fixed them in code by
        routing the unpauses (+ the ACK) and the witness through
        ``db/audit.record_witnessed_state_change``. They may never come back as
        commit-before-witness sites, and an allow-list entry may not hide one:

        * neither is a finding of :func:`scan`, AND neither is in ``BASELINE``;
        * each still calls a witness (the funnel), so the absence of a finding
          is not the vacuous kind a deleted audit call would also produce;
        * each calls NO self-committing non-witness helper, so the unpauses
          really go through their non-committing ``*_txn`` siblings.
        """
        idx = build_index()
        committers = self_committing(idx)
        wits = witnesses(idx)
        flagged = {f.key for f in scan()}
        for qual in ("config_baa_ack._baa_ack_db_work",
                     "config_save._classifier_change_clear"):
            key = ("web/routers/ui/admin.py", qual)
            assert key in idx.nodes, f"{qual} is not in the scanned index"
            assert key not in flagged, (
                f"{qual} commits state before its witness again (N-520 DB-422D-1/N-514)"
            )
            assert key not in BASELINE, f"{qual} must not be allow-listed"
            calls = {k for _ln, k in _own_body_resolved_calls(idx, key[0], idx.nodes[key])}
            assert calls & wits, f"{qual} no longer calls a witness"
            own_commits = sorted(k[1] for k in calls if k in committers and k not in wits)
            assert not own_commits, (
                f"{qual} calls self-committing helper(s) outside the funnel: {own_commits}"
            )


# ---------------------------------------------------------------------------
# The ``state_txn`` arm (s2 panel DA MUST-N1).
#
# ``record_witnessed_state_change`` is itself a witness, and its ``state_txn``
# lambda opens on the SAME line as (or after) the funnel call, so the line-order
# predicate above can never see a self-committing helper smuggled into
# ``state_txn`` as "before" the witness; a ``state_txn`` that names a nested def
# is graded as its own function, which has no witness at all. Both shapes were
# blind (probe_n520_blind.py). This arm closes it: at EVERY funnel call in src,
# the resolved calls inside the ``state_txn`` argument (a lambda body, or the
# def it names) and any raw ``.commit()`` there must contain no key in
# ``self_committing - witnesses``. An argument the arm cannot resolve to a
# lambda or a def is itself a finding (fail closed).
# ---------------------------------------------------------------------------

_FUNNEL_KEY: FnKey = ("db/audit.py", "record_witnessed_state_change")


def _state_txn_body(fn: ast.AST, arg: ast.AST) -> ast.AST | None:
    """The node whose calls ``state_txn`` makes: a lambda, or the def it names."""
    if isinstance(arg, ast.Lambda):
        return arg
    if isinstance(arg, ast.Name):
        for node in ast.walk(fn):
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == arg.id and node is not fn):
                return node
    return None


def state_txn_offenders(
    idx: SrcIndex, rel: str, fn: ast.AST, committers: set[FnKey], wits: set[FnKey],
) -> list[str]:
    """Every self-committing call reachable from a funnel ``state_txn`` in ``fn``'s
    own body, as ``"<line>: <callee>"`` strings (empty means clean)."""
    out: list[str] = []
    for node in _own_body_nodes(fn):
        if not isinstance(node, ast.Call) or resolve(idx, rel, node) != _FUNNEL_KEY:
            continue
        arg = next((kw.value for kw in node.keywords if kw.arg == "state_txn"), None)
        if arg is None:
            out.append(f"{node.lineno}: funnel call without a state_txn keyword")
            continue
        body = _state_txn_body(fn, arg)
        if body is None:
            out.append(f"{node.lineno}: state_txn is neither a lambda nor a local def")
            continue
        nodes = (list(ast.walk(body.body)) if isinstance(body, ast.Lambda)
                 else list(_own_body_nodes(body)))
        for inner in nodes:
            if not isinstance(inner, ast.Call):
                continue
            if isinstance(inner.func, ast.Attribute) and inner.func.attr == "commit":
                out.append(f"{inner.lineno}: <conn>.commit() inside state_txn")
                continue
            key = resolve(idx, rel, inner)
            if key and key in committers and key not in wits:
                out.append(f"{inner.lineno}: {key[1]} self-commits inside state_txn")
    return out


class TestStateTxnArm:
    """s2 panel DA MUST-N1: the funnel's ``state_txn`` may reach no self-committing helper."""

    def test_no_state_txn_reaches_a_self_committing_helper(self) -> None:
        idx = build_index()
        committers = self_committing(idx)
        wits = witnesses(idx)
        bad: list[str] = []
        callers = 0
        for (rel, qual), node in idx.nodes.items():
            hits = state_txn_offenders(idx, rel, node, committers, wits)
            if any(resolve(idx, rel, n) == _FUNNEL_KEY for n in _own_body_nodes(node)
                   if isinstance(n, ast.Call)):
                callers += 1
            bad += [f"{rel}::{qual} {h}" for h in hits]
        # Non-vacuous: the funnel has real callers to check (count-agnostic floor).
        assert callers > 0, "no record_witnessed_state_change caller was found"
        assert not bad, "state_txn reaches a self-committing helper:\n" + "\n".join(bad)

    @staticmethod
    def _mutant_offenders(old: str, new: str) -> list[str]:
        rel = "web/routers/auth_keys.py"
        src = (SRC_ROOT / rel).read_text(encoding="utf-8")
        assert src.count(old) == 1, "teeth anchor moved; re-point the mutant"
        tree = parse_source(src.replace(old, new))
        annotate_parents(tree)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_revoke_dev_key")
        idx = build_index()
        try:
            return state_txn_offenders(idx, rel, fn, self_committing(idx), witnesses(idx))
        finally:
            for cache_key in [k for k in _CALLS_CACHE if k == (rel, id(fn))]:
                _CALLS_CACHE.pop(cache_key, None)

    _ANCHOR = 'state_txn=lambda c: revoke_dev_key_txn(c, key_id, actor["id"]),'

    def test_teeth_flag_a_self_committing_helper_in_a_state_txn_lambda(self) -> None:
        """The DA probe's mutant (probe_n520_blind.py): red without this arm."""
        hits = self._mutant_offenders(
            self._ANCHOR,
            'state_txn=lambda c: db_revoke_dev_key(c, key_id, actor["id"]),',
        )
        assert any("revoke_dev_key self-commits" in h for h in hits), hits

    def test_teeth_flag_a_raw_commit_in_a_state_txn_lambda(self) -> None:
        hits = self._mutant_offenders(
            self._ANCHOR,
            'state_txn=lambda c: (revoke_dev_key_txn(c, key_id, actor["id"]), c.commit()),',
        )
        assert any("commit() inside state_txn" in h for h in hits), hits

    def test_teeth_clear_the_real_txn_shape(self) -> None:
        assert self._mutant_offenders(self._ANCHOR, self._ANCHOR) == []

    def test_the_funnel_clears_the_settings_cache_unconditionally_in_finally(self) -> None:
        """s2 panel db N1-M1 / hipaa M-N4 + DA final verdict. ``set_setting_txn``
        requires a cache invalidation on EVERY exit edge; the funnel owns it so no
        caller can forget it. Pin: ``record_witnessed_state_change`` has a ``try``
        whose ``finally`` calls ``invalidate_setting_cache`` with no ``if`` around
        it, and no ``on_exit`` opt-in hook comes back."""
        src = (SRC_ROOT / "db" / "audit.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(parse_source(src))
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "record_witnessed_state_change")
        assert not any(a.arg == "on_exit" for a in fn.args.kwonlyargs + fn.args.args), (
            "the cache clear is the funnel's job, not a caller hook")

        def _clears(stmts: list[ast.stmt]) -> bool:
            # Only straight-line statements and a guarding try body count; a
            # clear under an ``if`` is conditional and does not.
            for st in stmts:
                if isinstance(st, ast.Try) and _clears(st.body):
                    return True
                if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                    f = st.value.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                    if name == "invalidate_setting_cache":
                        return True
            return False
        finals = [st.finalbody for st in fn.body if isinstance(st, ast.Try) and st.finalbody]
        assert finals, "record_witnessed_state_change lost its try/finally"
        assert any(_clears(fb) for fb in finals), (
            "the funnel's finally must call invalidate_setting_cache unconditionally")



# ---------------------------------------------------------------------------
# s2 panel db S3: the ``*_txn`` naming contract. A ``*_txn`` writer is the
# non-committing form a caller-owned transaction (the N-520 funnel above all)
# composes; one that commits, directly or through any callee, would commit the
# funnel's state before its witness and the state_txn arm would only see it at
# the sites that happen to be funnel calls. Count-agnostic: every def in src
# whose name ends in ``_txn`` is outside ``self_committing``. A ``@contextmanager``
# so named is a transaction SCOPE that owns its commit (``_clock_txn``: BEGIN,
# the caller's body, commit or rollback), not a writer anyone composes, so it is
# out of the contract by its shape; no def is exempted by name.
# ---------------------------------------------------------------------------


def _is_context_manager(fn: ast.AST) -> bool:
    for dec in getattr(fn, "decorator_list", []):
        name = dec.attr if isinstance(dec, ast.Attribute) else getattr(dec, "id", "")
        if name in {"contextmanager", "asynccontextmanager"}:
            return True
    return False


def txn_named_committers(
    committers: set[FnKey], nodes: dict[FnKey, ast.AST] | None = None,
) -> list[str]:
    nodes = nodes or {}
    return sorted(
        f"{rel}::{qual}" for rel, qual in committers
        if qual.rsplit(".", 1)[-1].endswith("_txn")
        and not _is_context_manager(nodes.get((rel, qual)))
    )


class TestTxnNamedWritersNeverCommit:
    def test_no_txn_named_function_commits(self) -> None:
        idx = build_index()
        named = [k for k in idx.nodes if k[1].rsplit(".", 1)[-1].endswith("_txn")]
        assert len(named) > 0, "no *_txn function found in src; the arm is vacuous"
        bad = txn_named_committers(self_committing(idx), idx.nodes)
        assert not bad, (
            "a *_txn function commits (directly or through a callee); a caller-owned "
            "transaction cannot compose it:\n" + "\n".join(bad))

    def test_teeth_a_planted_committing_txn_is_flagged(self) -> None:
        planted = parse_source(
            "def planted_write_txn(conn):\n"
            "    conn.execute('UPDATE t SET x = 1')\n"
            "    conn.commit()\n"
        )
        fn = next(n for n in ast.walk(planted) if isinstance(n, ast.FunctionDef))
        assert _own_body_commits(fn), "the commit detector misses a raw commit"
        assert txn_named_committers({("web/planted.py", "planted_write_txn")}) == [
            "web/planted.py::planted_write_txn"]
        assert txn_named_committers({("web/planted.py", "planted_write")}) == []
        # The scope exclusion is by decorator shape: the SAME body under a
        # @contextmanager is a scope, and without it is flagged.
        scoped = parse_source(
            "from contextlib import contextmanager\n"
            "@contextmanager\n"
            "def planted_scope_txn(conn):\n"
            "    yield\n"
            "    conn.commit()\n"
        )
        sfn = next(n for n in ast.walk(scoped) if isinstance(n, ast.FunctionDef))
        key = ("web/planted.py", "planted_scope_txn")
        assert txn_named_committers({key}, {key: sfn}) == []
        sfn.decorator_list = []
        assert txn_named_committers({key}, {key: sfn}) == ["web/planted.py::planted_scope_txn"]


if __name__ == "__main__":  # pragma: no cover - census driver
    for finding in scan():
        print(_fmt(finding))
