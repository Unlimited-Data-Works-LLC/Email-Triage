"""N-543: no filesystem DELETE before the audit witness in the same handler (punch 539 fold-check).

THE DEFECT (hipaa H539FC-3, db DB-539FC-3, da DA-C1). The admin
``POST /config/ai-backends/embedding-remove`` called
``embedding_bits.remove_install`` first — which ``shutil.rmtree``s the runtime
prefix and resets the install-state row through the self-committing
``_update_state`` — and only then wrote its one, best-effort ``auth_events`` row.
A failed audit write left a destructive admin action with no row naming who did
it. The fix (this change) writes a fail-closed INTENT row before the delete.

WHAT THIS PIN ASSERTS, over every function the shared harness walks
(count-agnostic, PD-1):

* **Arm A (order).** In any function scope that both DELETES and WITNESSES, the
  first delete must not come before the first witness.
* **Arm B (admin reach).** A function that calls an admin gate
  (``require_admin*`` / its ``_require_admin`` alias) and reaches a delete must
  have a witness BEFORE it — a destructive admin handler with no witness at all
  is the same defect with the late row removed.

A scope is a function body plus the lambdas in it; a ``db_call`` /
``db_call_async`` / ``run_in_threadpool`` / ``to_thread`` hop to a helper defined
in the same module (nested or module-level) is followed ONE level, with the
helper's events placed at the hop's line (PD-2).

DELETE = a call to ``shutil.rmtree`` / ``os.remove`` / ``os.unlink`` /
``os.rmdir`` / ``<path>.unlink()`` / ``<path>.rmdir()``, OR a call to a function
defined anywhere under ``src/email_triage/`` whose OWN body makes such a call
(``remove_install`` is one) — one level, keyed by name. A scope that calls
``tempfile.*`` is a temp-file cleanup and is not examined: the object it deletes
is one it created.

TLS-MATERIAL WRITE (N-550, punch 539 fold-check round 3) = a call to a function
defined in a module :func:`tls_material_modules` DERIVES (any module naming the
cert/key path SSOT, ``_TLS_PATH_SSOT_NAMES``) whose own body writes a file
(:func:`_is_file_write`: ``atomic_write_*`` / ``write_bytes`` / ``write_text``,
a one-argument or ``target=`` ``Path.replace`` / ``rename``, ``os.replace`` /
``rename`` / ``renames`` / ``write``, the ``shutil`` move/copy family, or a
write-mode open, whose mode is read per receiver since round 8, see
:func:`_is_write_open`) or, transitively inside those modules, calls one that
does; or that deletes (the unlink arm above). It is counted exactly like a
delete: the N-543 delete arm could see ``cancel_pending``'s unlink but not
``import_signed_cert`` writing the ACTIVE certificate (``tls_csr.py:341``),
which changes the certificate the service presents. The scope is derived from
NAMES, not behaviour: a module that writes a certificate without naming
``CERT_FILENAME`` / ``KEY_FILENAME`` / ``cert_paths`` / ``write_cert_files`` is
outside it by construction, and an unscoped write arm would flag every config
save and backup. NOT seen by the write predicate: an ``open`` imported under
another name (``from gzip import open as gzopen``).

WRITER-PATH ARM (N-543 residual, rounds 4-7) = no UNBOUNDED delete reached
from a function or lambda handed to ``db_call`` / ``db_call_async`` (directly
or through ``partial``). It does NOT flag every delete at every depth; it
follows exactly this:

* the SEED (:func:`_is_tree_delete`, round 7): ``rmtree`` on any receiver;
  ``tempfile.TemporaryDirectory``; ``shutil.move``; ``os.removedirs`` (each of
  these also under a ``from`` import name or alias); a ``subprocess.<runner>``
  whose argv is a literal starting ``rm``, or ``os.system`` with a literal
  ``rm …``; and a
  single-file ``unlink`` / ``remove`` / ``rmdir`` inside a loop over an
  UNBOUNDED iterable (a NON-EMPTY tuple/list literal with no ``*starred``
  element, or a module-level name bound once to one and never mutated,
  rebound, ``global``-rebound or shadowed by a local, is a fixed registry and
  bounded; round 8, DA-F8-1). An O(1) delete outside such a loop is
  out of scope by design (an all-deleter seed floods 28 -> 488 through
  ``atomic_write_*``);
* the CLOSURE (:func:`module_tree_deleter_closure`): per module, a fixpoint of
  bare-name calls and hop hand-offs from the seed, carried across modules
  through ``from X import`` names (name-keyed) until stable
  (:func:`src_module_closures`); beyond the seed functions themselves, only
  module-level functions are exported;
* the CHECK (:func:`writer_path_deletes`): the handed helper (a module-level
  def or one nested in the caller, resolved by name, or a lambda) is examined
  in its own body for a seed call, a bare-name call into its module's closure,
  or an attribute call (``eb.f()``) whose name is an exported closure member;
  a closure member handed straight to the writer is a hit.

NOT SEEN by the writer-path arm: a helper that reaches a deleter only through
an ATTRIBUTE call (``x.helper()`` / ``self.m()``) is not added to the closure
(``attributes=False``: a name-keyed walk through attribute calls flooded
28 -> 2145 on ``x.get`` / ``x.execute``), so it is seen only when that
attribute call sits directly in the handed helper; a method or nested function
that reaches a deleter indirectly is not exported to other modules; a helper
handed by attribute (``db_call(self._work)``) is matched by name against the
closure, never read; a helper passed other than as the first positional
argument; a hand walk written as recursion with no loop around the delete; a
delete through ``getattr`` or a variable-held callable; an ``rm`` argv built at
run time; a literal-iterable loop over computed paths; a delete in C or a
shell script.

WITNESS = a call to an ``@audit_emitter`` (derived from the decorator by the
harness, never listed here) or a chain primitive (``chain_writer_names``), or to
a SAME-MODULE PURE WRAPPER: a function whose body is one statement that calls an
emitter, directly or as ``[return] [await] safe_audit_write[_async](lambda:
<emitter>(...) | db_call(<emitter>, ...)) [is not None]``. The
module-local ``_audit`` helpers qualify; ``require_admin_ui`` does not. In the
live scan, also any call N-520's resolver maps into N-520's witness set (below).

WHAT IT DOES NOT SEE (the scope caveat): a delete more than one call below the
handler (``a`` calls ``b`` calls ``remove_install``); a delete reached through
``functools.partial`` / a keyword argument / an attribute receiver on the hop; a
witness behind a wrapper defined in another module; a deleter function whose
NAME collides with an unrelated method (the name key over-approximates, so that
one fails closed); and whether the witness actually REFUSES the delete on failure
— that is behaviour, pinned by ``tests/test_web/test_n527_runtime_deps_route_pin.py``
(``test_a_failed_intent_write_refuses_the_removal``).

SHARED WITH N-520 (re-keyed after 422 landed, PD-6): the off-loop hop set is
N-520's ``HOP_DISPATCHERS``, and in the live scan a call is also a witness when
N-520's ``resolve`` maps it to a (path, qualname) in N-520's ``witnesses(idx)``.
That adds the in-transaction witnesses N-520 derives (a function whose own body
calls a chain primitive: ``record_hipaa_boundary_txn``, ``emit_clock_event_txn``)
without widening by bare name. STILL LOCAL, stated: the name-keyed emitter set
and the same-module pure-wrapper rule, because N-520's witness set does not see
through ``safe_audit_write(lambda: <emitter>(...))`` (db-sme measured it; that is
how N-543 was invisible to N-520); the delete / TLS-write predicates and the event
collector, which N-520 has no equivalent of; and the own-body iterator, which
differs from N-520's only in skipping class bodies. A synthetic teeth tree is not
in N-520's index, so the teeth run on the name rules alone.

ENUMERATION SIGNATURE (PD-4, recorded 2026-09-30 at ``574ee262`` + this fold):
raw primitive delete calls under ``src/email_triage/`` —
``rmtree|os\\.remove|os\\.unlink|os\\.rmdir|\\.unlink\\(|\\.rmdir\\(`` matches 38
lines (comments included; db-sme counted 33 raw at ``574ee262``). The AST
detector finds 31 primitive delete calls in 11 modules and 28 deleter functions,
and its first run flagged exactly the 3 ``BASELINE`` sites. The numbers are a
dated record, not an assertion: ``test_enumeration_signature_is_live`` only
checks the population has not vanished (a broken detector).
"""

from __future__ import annotations

import ast
from functools import lru_cache

from _pin_harness import (
    module_ssot_imports,
    assert_pin_has_teeth,
    audit_emitter_names,
    chain_writer_names,
    hop_target,
    parse_source,
    walk_src,
)
from test_n520_commit_before_witness_ratchet_pin import (  # N-520's walker (PD-6)
    HOP_DISPATCHERS,
    build_index,
    resolve,
    witnesses as n520_witnesses,
)

_OS_DELETERS = frozenset({"remove", "unlink", "rmdir"})
_PATH_DELETERS = frozenset({"unlink", "rmdir"})
#: ONE definition of the off-loop hops, N-520's (was a local copy of the same set).
_HOPS = HOP_DISPATCHERS

#: The modules that hold TLS key / certificate material writers (package-
#: relative, R38). ``test_tls_material_modules_are_live`` fails if one stops
#: existing or stops defining a writer, so the list cannot go stale silently.
#: The names that locate TLS key/certificate material: ``tls_csr.CERT_FILENAME``
#: / ``KEY_FILENAME``, the renewer's ``cert_paths`` and ``tls.write_cert_files``.
_TLS_PATH_SSOT_NAMES = frozenset({"CERT_FILENAME", "KEY_FILENAME", "cert_paths", "write_cert_files"})
#: A floor, not the list: these three must be IN the derived set, or the
#: derivation broke (devils-advocate round 5: a hand list cannot catch a missing
#: module, so the scope is derived and this only proves the derivation works).
_TLS_MODULE_FLOOR = frozenset({"tls_csr.py", "tls.py", "web/acme_renewer.py"})


def _references_tls_ssot(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in _TLS_PATH_SSOT_NAMES:
            return True
        if isinstance(n, ast.Attribute) and n.attr in _TLS_PATH_SSOT_NAMES:
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in _TLS_PATH_SSOT_NAMES:
            return True
        if isinstance(n, ast.alias) and n.name in _TLS_PATH_SSOT_NAMES:
            return True
    return False


@lru_cache(maxsize=1)
def tls_material_modules() -> frozenset[str]:
    """Every src module that references the TLS cert/key path SSOT (derived)."""
    return frozenset(rel for _p, rel, tree in walk_src() if _references_tls_ssot(tree))
_SHUTIL_WRITES = frozenset({"move", "copy", "copy2", "copyfile", "copytree", "copyfileobj"})
_OS_WRITES = frozenset({"replace", "rename", "write", "renames"})
_FILE_WRITES = frozenset({
    "atomic_write_bytes", "atomic_write_text", "write_bytes", "write_text",
})
_RENAMES = frozenset({"replace", "rename"})
_AUDIT_SSOT_WRAPPERS = frozenset({"safe_audit_write", "safe_audit_write_async"})


def _call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def is_primitive_delete(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id == "rmtree"
    if not isinstance(f, ast.Attribute):
        return False
    recv = f.value.id if isinstance(f.value, ast.Name) else ""
    if f.attr == "rmtree":
        return True
    if recv == "os" and f.attr in _OS_DELETERS:
        return True
    # ``<path>.unlink()`` / ``<path>.rmdir()`` on a non-``os`` receiver
    return recv != "os" and f.attr in _PATH_DELETERS


def _own_nodes(fn: ast.AST):
    """Nodes of ``fn``'s own body: lambdas included, nested defs excluded."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


@lru_cache(maxsize=1)
def src_deleter_functions() -> frozenset[str]:
    """Names of functions under src whose OWN body makes a primitive delete."""
    names: set[str] = set()
    for _p, _rel, tree in walk_src():
        names |= deleter_functions_in(tree)
    return frozenset(names)


def deleter_functions_in(tree: ast.AST) -> set[str]:
    out: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(n, ast.Call) and is_primitive_delete(n) for n in _own_nodes(fn)):
                out.add(fn.name)
    return out


#: Modules whose ``open(file, mode)`` takes the mode SECOND, like the builtin.
_MODE_SECOND_OPEN_MODULES = ("io", "codecs", "gzip", "bz2", "lzma")
_OS_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"})


def _mode_is_write(mode: ast.AST | None) -> bool:
    """No mode is a read; a string literal is a write if it holds w, a, x or +;
    anything else (a variable, ``*args``, ``**kw``) is a write (fail closed)."""
    if mode is None:
        return False
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(c in mode.value for c in "wax+")
    return True


def _os_flags_are_write(flags: ast.AST | None, os_names) -> bool:
    """``os.open(p, flags)``: a write if the flags name ``O_WRONLY`` / ``O_RDWR``
    / ``O_CREAT`` / ``O_TRUNC`` / ``O_APPEND``. A READ only when every name in
    the expression is another ``O_*`` flag (or the ``os`` module holding it) and
    every literal is 0; a variable or a call is a write (fail closed)."""
    if flags is None:
        return True
    for n in ast.walk(flags):
        if isinstance(n, ast.Attribute) and (n.attr in _OS_WRITE_FLAGS or not n.attr.startswith("O_")):
            return True
        if isinstance(n, ast.Name) and (
            n.id in _OS_WRITE_FLAGS or not (n.id.startswith("O_") or n.id in os_names)
        ):
            return True
        if isinstance(n, ast.Constant) and n.value != 0:
            return True
        if isinstance(n, (ast.Call, ast.Starred)):
            return True
    return False


def _is_write_open(call: ast.Call, os_names=frozenset({"os"}),
                   mode_second=frozenset(_MODE_SECOND_OPEN_MODULES)) -> bool:
    """A write-mode open, with the mode read where the receiver takes it (round 8,
    devils-advocate DA-F6: the old reader took ``args[0]`` for ANY ``x.open``, so
    ``io.open(p, "wb")`` read the PATH as the mode):

    * builtin ``open`` and ``io`` / ``codecs`` / ``gzip`` / ``bz2`` / ``lzma``
      ``.open`` (``mode_second``: their names in this module): positional 1 or
      ``mode=``;
    * ``os.open`` (a receiver or a ``from os import open`` name in ``os_names``):
      its flags, by :func:`_os_flags_are_write`;
    * ``os.fdopen``: always a write (fail closed: the fd was opened elsewhere);
    * any other ``x.open(...)`` (a ``Path``): positional 0 or ``mode=``.

    The mode itself is judged by :func:`_mode_is_write`."""
    f = call.func
    name = _call_name(call)
    if isinstance(f, ast.Name):
        is_os = f.id in os_names
        recv = ""
    elif isinstance(f, ast.Attribute):
        recv = f.value.id if isinstance(f.value, ast.Name) else ""
        is_os = recv in os_names
    else:
        return False
    if is_os and name == "fdopen":
        return True
    if name != "open":
        return False
    if is_os:
        flags = call.args[1] if len(call.args) > 1 else next(
            (kw.value for kw in call.keywords if kw.arg == "flags"), None)
        return _os_flags_are_write(flags, os_names)
    if any(kw.arg is None for kw in call.keywords):
        return True  # ``open(p, **kw)``: the mode may be in there
    mode = next((kw.value for kw in call.keywords if kw.arg == "mode"), None)
    if mode is None:
        idx = 1 if isinstance(f, ast.Name) or recv in mode_second else 0
        mode = call.args[idx] if len(call.args) > idx else None
    return _mode_is_write(mode)


def _is_file_write(call: ast.Call, os_names=frozenset({"os"}), shutil_names=frozenset({"shutil"}),
                   mode_second=frozenset(_MODE_SECOND_OPEN_MODULES)) -> bool:
    """A call that writes, replaces or copies a file. ``os_names`` /
    ``shutil_names`` / ``mode_second`` are the names the module binds to ``os`` /
    ``shutil`` / the :data:`_MODE_SECOND_OPEN_MODULES` (or imports from them),
    resolved by the harness's ``module_ssot_imports``."""
    name = _call_name(call)
    if name in _FILE_WRITES or _is_write_open(call, os_names, mode_second):
        return True
    f = call.func
    if isinstance(f, ast.Name):
        # ``from os import replace`` / ``from shutil import move``
        return (f.id in os_names and f.id in _OS_WRITES) or (
            f.id in shutil_names and f.id in _SHUTIL_WRITES
        )
    if not isinstance(f, ast.Attribute):
        return False
    recv = f.value.id if isinstance(f.value, ast.Name) else ""
    if recv in shutil_names and f.attr in _SHUTIL_WRITES:
        return True
    if recv in os_names and f.attr in _OS_WRITES:
        return True
    if f.attr in _RENAMES:
        # ``<path>.replace(target)`` / ``.replace(target=x)``: one argument or the
        # keyword. ``str.replace(old, new)`` takes two, which tells them apart.
        return (len(call.args) == 1 and not call.keywords) or any(
            kw.arg == "target" for kw in call.keywords
        )
    return False


def module_file_writers(tree: ast.AST) -> set[str]:
    """Functions in ONE module whose own body writes a file or deletes."""
    os_names = frozenset(module_ssot_imports(tree, "os") | {"os"})
    shutil_names = frozenset(module_ssot_imports(tree, "shutil") | {"shutil"})
    mode_second = frozenset().union(
        *(module_ssot_imports(tree, m) | {m} for m in _MODE_SECOND_OPEN_MODULES)
    )
    return {
        fn.name for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(n, ast.Call)
            and (_is_file_write(n, os_names, shutil_names, mode_second) or is_primitive_delete(n))
            for n in _own_nodes(fn)
        )
    }


def _reaches(fn, targets, *, attributes: bool = True) -> bool:
    # attributes=False follows bare-name calls only: a src-wide NAME-keyed
    # fixpoint through attribute calls floods (measured 28 -> 2145 deleters,
    # because x.get / x.execute collide with deleter names).
    """``fn``'s own body calls a function in ``targets``, directly or handed to a
    hop (``to_thread(self.issue_now)``, ``db_call(purge)``)."""
    for n in _own_nodes(fn):
        if not isinstance(n, ast.Call):
            continue
        if (attributes or isinstance(n.func, ast.Name)) and _call_name(n) in targets:
            return True
        hop = hop_target(n, _HOPS)  # punch 672: one hop resolver
        if hop is not None and hop.name in targets:
            return True
    return False


def _fixpoint(fns, seed: set[str], *, attributes: bool = True) -> frozenset[str]:
    names = set(seed)
    changed = True
    while changed:
        changed = False
        for fn in fns:
            if fn.name not in names and _reaches(fn, names, attributes=attributes):
                names.add(fn.name)
                changed = True
    return frozenset(names)


@lru_cache(maxsize=1)
def tls_material_writers() -> frozenset[str]:
    """Functions in the DERIVED :func:`tls_material_modules` that write or delete
    TLS files, directly or by reaching another such function (fixpoint)."""
    scope = tls_material_modules()
    fns: list[ast.AST] = []
    seed: set[str] = set()
    for _p, rel, tree in walk_src():
        if rel in scope:
            fns.extend(n for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
            seed |= module_file_writers(tree)
    return _fixpoint(fns, seed)


_SUBPROCESS_RUNNERS = frozenset({"run", "call", "check_call", "check_output", "Popen"})


def _tree_delete_ctx(tree: ast.AST) -> dict[str, set[str]]:
    """Names this module binds to the modules and functions the seed matches,
    resolved through the harness's ``module_ssot_imports`` plus the specific
    ``from X import f as g`` aliases (db 539fc LAST CONFIRM, round 7)."""
    ctx = {
        "os": set(module_ssot_imports(tree, "os")) | {"os"},
        "shutil": set(module_ssot_imports(tree, "shutil")) | {"shutil"},
        "tempfile": set(module_ssot_imports(tree, "tempfile")) | {"tempfile"},
        "subprocess": set(module_ssot_imports(tree, "subprocess")) | {"subprocess"},
        "rmtree": {"rmtree"}, "move": set(), "removedirs": set(), "TemporaryDirectory": set(),
        "loop_ids": _unbounded_loop_call_ids(tree),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("shutil", "os", "tempfile"):
            for a in node.names:
                if a.name in ("rmtree", "move", "removedirs", "TemporaryDirectory"):
                    ctx[a.name].add(a.asname or a.name)
    return ctx


_LIST_MUTATORS = frozenset({"append", "extend", "insert", "__iadd__", "__setitem__"})


def _is_bounded_literal(node: ast.AST) -> bool:
    """A NON-EMPTY tuple/list literal with no ``*starred`` element (devils-advocate
    DA-F8-1: ``[]`` is an accumulator and ``[*d.rglob("*")]`` is a walk)."""
    return isinstance(node, (ast.Tuple, ast.List)) and bool(node.elts) and not any(
        isinstance(e, ast.Starred) for e in node.elts
    )


def _bounded_module_names(tree: ast.AST) -> set[str]:
    """Module-level names bound ONCE to a bounded literal and never mutated
    (``.append`` / ``.extend`` / ``.insert``, ``+=``, item assignment) or rebound
    (a second module-level binding, or a ``global`` declaration) anywhere in the
    module (DA-F8-1)."""
    binds: dict[str, int] = {}
    literal: set[str] = set()
    for n in getattr(tree, "body", []):
        targets = n.targets if isinstance(n, ast.Assign) else (
            [n.target] if isinstance(n, (ast.AnnAssign, ast.AugAssign)) else [])
        for t in targets:
            if isinstance(t, ast.Name):
                binds[t.id] = binds.get(t.id, 0) + 1
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and _is_bounded_literal(n.value):
                    literal.add(t.id)
    touched: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Global):
            touched |= set(n.names)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
            touched.add(n.target.id)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr in _LIST_MUTATORS and isinstance(n.func.value, ast.Name):
            touched.add(n.func.value.id)
        elif isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)) \
                and isinstance(n.value, ast.Name):
            touched.add(n.value.id)
    return {name for name in literal if binds.get(name) == 1 and name not in touched}


def _local_names(fn: ast.AST) -> frozenset[str]:
    """Every name a function (or lambda) binds: its parameters and every Store
    name in its body, nested scopes included (over-approximates toward
    "shadowed", which is the fail-closed direction)."""
    a = fn.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs, *(x for x in (a.vararg, a.kwarg) if x)]
    stores = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    return frozenset({p.arg for p in params} | stores)


def _unbounded_loop_call_ids(tree: ast.AST) -> set[int]:
    """ids of every call lexically inside a for/while/comprehension whose iterable
    is NOT bounded. Bounded = a non-empty, unstarred tuple/list literal, or a
    module-level name :func:`_bounded_module_names` admits that no local binding
    in the loop's function SHADOWS (``for b in _BUILDERS`` where
    ``_BUILDERS = [f]``): a fixed registry, not a walk. A ``while`` has no
    iterable and always counts. Each loop is judged in the module scope and again
    in every function containing it; a call counts if ANY judgement is
    unbounded. Computed downward, so no parent-climb (harness contract #8)."""
    names = _bounded_module_names(tree)

    def bounded(it: ast.AST, shadow: frozenset[str]) -> bool:
        return _is_bounded_literal(it) or (
            isinstance(it, ast.Name) and it.id in names and it.id not in shadow
        )

    scopes = [(tree, frozenset())] + [
        (fn, _local_names(fn)) for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    ]
    ids: set[int] = set()
    for scope, shadow in scopes:
        for node in ast.walk(scope):
            unbounded = (
                (isinstance(node, (ast.For, ast.AsyncFor)) and not bounded(node.iter, shadow))
                or isinstance(node, ast.While)
                or (isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                    and any(not bounded(g.iter, shadow) for g in node.generators))
            )
            if unbounded:
                ids |= {id(c) for c in ast.walk(node) if isinstance(c, ast.Call)}
    return ids


def _is_tree_delete(call: ast.Call, ctx: dict[str, set[str]] | None = None) -> bool:
    """An UNBOUNDED delete (db 539fc LAST CONFIRM, round 7): ``rmtree`` and its
    aliases; ``tempfile.TemporaryDirectory`` (its exit or ``cleanup`` removes the
    tree); ``shutil.move`` (a cross-device move is copy + rmtree); ``os.removedirs``;
    a ``subprocess`` call running ``rm``; or a single-file ``unlink``/``remove``/
    ``rmdir`` inside a loop over a NON-literal iterable (a hand-written walk).
    ``atomic_write_*``'s one temp unlink and the snapshot's
    ``for _ext in ("-wal", "-shm")`` stay clear."""
    ctx = ctx or {"os": {"os"}, "shutil": {"shutil"}, "tempfile": {"tempfile"},
                  "subprocess": {"subprocess"}, "rmtree": {"rmtree"}, "move": set(),
                  "removedirs": set(), "TemporaryDirectory": set()}
    f = call.func
    name = _call_name(call)
    recv = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
    if isinstance(f, ast.Name):
        if f.id in ctx["rmtree"] or f.id in ctx["move"] or f.id in ctx["removedirs"] \
                or f.id in ctx["TemporaryDirectory"]:
            return True
    elif isinstance(f, ast.Attribute):
        if f.attr == "rmtree":
            return True
        if recv in ctx["shutil"] and f.attr == "move":
            return True
        if recv in ctx["os"] and f.attr == "removedirs":
            return True
        if recv in ctx["tempfile"] and f.attr == "TemporaryDirectory":
            return True
        if recv in ctx["subprocess"] and f.attr in _SUBPROCESS_RUNNERS and call.args:
            first = call.args[0]
            if isinstance(first, (ast.List, ast.Tuple)) and first.elts and isinstance(
                first.elts[0], ast.Constant
            ) and first.elts[0].value == "rm":
                return True
            if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                    and first.value.strip().startswith("rm "):
                return True
        if recv in ctx["os"] and f.attr == "system" and call.args and isinstance(
            call.args[0], ast.Constant
        ) and str(call.args[0].value).strip().startswith("rm "):
            return True
    return is_primitive_delete(call) and id(call) in ctx.get("loop_ids", ())


def module_tree_deleter_closure(tree: ast.AST, global_seed) -> frozenset[str]:
    """The tree-deleter closure of ONE module: its own functions that rmtree,
    names it imports from a module where they rmtree, and every function of THIS
    module that reaches one of those by a bare-name call, at any depth. Module-
    scoped because a src-wide name-keyed closure collides across modules (every
    module has an ``_audit``; measured round 6). A src-wide closure seeded with
    EVERY deleter floods (28 -> 488 functions through ``atomic_write_*``'s O(1)
    temp unlink), so the seed is UNBOUNDED deletes only (:func:`_is_tree_delete`,
    widened in round 7 to db's named set, incl. a single-file delete inside a
    loop over an unbounded iterable). ``attributes=False``: a function that
    reaches a deleter only through an attribute call is NOT added. What the arm
    does not see is listed ONCE, in the module docstring (WRITER-PATH ARM)."""
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    ctx = _tree_delete_ctx(tree)
    seed = {fn.name for fn in fns
            if any(isinstance(c, ast.Call) and _is_tree_delete(c, ctx) for c in _own_nodes(fn))}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in global_seed:
                    seed.add(alias.asname or alias.name)
    return _fixpoint(fns, seed, attributes=False)


@lru_cache(maxsize=1)
def src_tree_deleters() -> frozenset[str]:
    """Functions whose OWN body makes an unbounded delete (the closure's seed)."""
    out: set[str] = set()
    for _p, _rel, tree in walk_src():
        ctx = _tree_delete_ctx(tree)
        out |= {
            n.name for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(isinstance(c, ast.Call) and _is_tree_delete(c, ctx) for c in _own_nodes(n))
        }
    return frozenset(out)


def _emitters() -> frozenset[str]:
    return frozenset(audit_emitter_names() | chain_writer_names())


def _is_emitter_call(node: ast.AST, emitters) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) in emitters


def _references_emitter(node: ast.AST, emitters) -> bool:
    """An emitter called directly, or passed to a hop (``db_call(record_x, …)``)."""
    for sub in ast.walk(node):
        if _is_emitter_call(sub, emitters):
            return True
        hop = hop_target(sub, _HOPS)
        if hop is not None and hop.name in emitters:
            return True
    return False


def _unwrap(expr: ast.AST) -> ast.AST:
    """``await X`` / ``X is not None`` -> ``X``."""
    while True:
        if isinstance(expr, ast.Await):
            expr = expr.value
        elif isinstance(expr, ast.Compare):
            expr = expr.left
        else:
            return expr


def pure_wrappers_in(tree: ast.AST, emitters) -> set[str]:
    """Module-level functions whose body (docstring aside) is ONE statement that
    calls an emitter, directly or as ``safe_audit_write(lambda: <emitter>(...))``."""
    out: set[str] = set()
    for fn in getattr(tree, "body", []):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = fn.body
        if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant
        ) and isinstance(body[0].value.value, str):
            body = body[1:]
        if len(body) != 1 or not isinstance(body[0], (ast.Expr, ast.Return)):
            continue
        top = _unwrap(body[0].value)
        if not isinstance(top, ast.Call):
            continue
        if _is_emitter_call(top, emitters):
            out.add(fn.name)
        elif _call_name(top) in _AUDIT_SSOT_WRAPPERS and top.args and isinstance(
            top.args[0], ast.Lambda
        ) and _references_emitter(top.args[0], emitters):
            out.add(fn.name)
    return out


def _is_admin_gate(name: str) -> bool:
    return name.startswith("require_admin") or name == "_require_admin"


def _events(fn, defs, deleters, witnesses, *, depth=0, is_n520_witness=None):
    """(line, kind) for every delete / witness / admin-gate in ``fn``'s own body,
    following one same-module hop. ``is_n520_witness(call)`` (the live scan only)
    resolves a call through N-520's index and asks whether it is in N-520's
    witness set; a synthetic tree has no module in that index, so it passes None."""
    evs: list[tuple[int, str]] = []
    for node in _own_nodes(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if is_primitive_delete(node) or name in deleters:
            evs.append((node.lineno, "delete"))
        elif name in witnesses or (is_n520_witness is not None and is_n520_witness(node)):
            evs.append((node.lineno, "witness"))
        elif _is_admin_gate(name):
            evs.append((node.lineno, "admin"))
        hop = hop_target(node, _HOPS)
        if hop is not None and hop.name and _is_admin_gate(hop.name):
            # ``await db_call(_require_admin, request)`` — the gate rides the hop
            evs.append((node.lineno, "admin"))
        if name == "tempfile" or (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "tempfile"
        ):
            evs.append((node.lineno, "tempfile"))
        hop = hop_target(node, _HOPS) if depth == 0 else None  # punch 672
        if hop is not None and hop.name:
            helper = defs.get(hop.name)
            if helper is not None and helper is not fn:
                for _ln, kind in _events(helper, defs, deleters, witnesses, depth=1,
                                         is_n520_witness=is_n520_witness):
                    evs.append((node.lineno, kind))
    return sorted(evs)


def _n520_witness_resolver(rel: str):
    """A call in module ``rel`` is a witness when N-520's resolver maps it to a
    FnKey in N-520's witness set: keyed by (path, qualname), never by bare name."""
    idx = build_index()
    wit = n520_witnesses(idx)
    return lambda call: resolve(idx, rel, call) in wit


def violations(tree: ast.AST, extra_deleters: frozenset[str] = frozenset(),
               rel: str | None = None) -> list[str]:
    emitters = _emitters()
    witnesses = set(emitters) | pure_wrappers_in(tree, emitters)
    is_n520_witness = _n520_witness_resolver(rel) if rel is not None else None
    deleters = set(extra_deleters) | deleter_functions_in(tree)
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    out: list[str] = []
    for fn in fns:
        # a hop resolves to a def nested in this function, else a module-level def
        defs = {n.name: n for n in getattr(tree, "body", [])
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        defs.update({n.name: n for n in _own_nodes_defs(fn)})
        evs = _events(fn, defs, deleters, witnesses, is_n520_witness=is_n520_witness)
        kinds = [k for _l, k in evs]
        if "delete" not in kinds or "tempfile" in kinds:
            continue
        first_delete = min(ln for ln, k in evs if k == "delete")
        wit = [ln for ln, k in evs if k == "witness"]
        if wit and first_delete < min(wit):
            out.append(f"{fn.name}: delete at line {first_delete} precedes the first witness at {min(wit)}")
        elif not wit and "admin" in kinds:
            out.append(f"{fn.name}: an admin handler reaches a delete at line {first_delete} with no witness")
    return out


def _own_nodes_defs(fn):
    for node in ast.iter_child_nodes(fn):
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield sub


#: Triaged live members, keyed by ``(relpath, function)`` (line-shift-stable,
#: R38). EMPTY: the three TLS-CSR handlers the first run found (N-550) are
#: witness-first since punch 539 fold-check round 3, and the write arm now also
#: holds ``admin_tls_csr_self_sign`` to the same order. A new entry needs a
#: register row and a direction of failure; ``test_baseline_is_not_stale``
#: removes one the moment its site is fixed.
BASELINE: dict[tuple[str, str], str] = {}


@lru_cache(maxsize=1)
def _live_violations() -> dict[tuple[str, str], str]:
    deleters = src_deleter_functions() | tls_material_writers()
    out: dict[tuple[str, str], str] = {}
    for _p, rel, tree in walk_src():
        for v in violations(tree, deleters, rel):
            out[(rel, v.split(":", 1)[0])] = v
    return out


def test_no_delete_before_its_witness_in_src():
    deleters = src_deleter_functions()
    assert "purge_removal_tombstones" in deleters, (
        "the deleter fixpoint no longer finds purge_removal_tombstones — the "
        "detector or the funnel moved, so a clean result would mean nothing"
    )
    live = _live_violations()
    found = {k: v for k, v in live.items() if k not in BASELINE}
    assert not found, (
        f"{found}: a filesystem delete runs before the audit witness in the same "
        f"handler, or an admin handler deletes with no witness at all. Write the "
        f"intent row FIRST, fail-closed (N-543, the cli.py N-157 shape)."
    )


def test_baseline_is_not_stale():
    """Every BASELINE entry must still be a live violation: a fixed site leaves
    the list in the same change, so the list never over-states the backlog."""
    live = _live_violations()
    stale = sorted(k for k in BASELINE if k not in live)
    assert not stale, f"fixed or moved; remove from BASELINE: {stale}"


def test_the_removal_route_is_in_the_scanned_set():
    """Prove the probe is in the set the control acts on. Since the N-543
    tombstone fix the removal's writer work (``_remove_db_work``) WITNESSES and
    RENAMES but deletes nothing; the delete (``purge_removal_tombstones``) is a
    deleter the fixpoint finds, and it is reached only through ``to_thread``."""
    from _pin_harness import SRC_ROOT, parse_module

    tree = parse_module(SRC_ROOT / "web/routers/ui/embedding_install.py")
    emitters = _emitters()
    witnesses = set(emitters) | pure_wrappers_in(tree, emitters)
    assert "_audit" in witnesses, "the module-local _audit wrapper must count as a witness"
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_remove_db_work")
    kinds = [k for _l, k in _events(fn, {}, set(src_deleter_functions()), witnesses)]
    assert "witness" in kinds and "delete" not in kinds, kinds
    assert "purge_removal_tombstones" in src_deleter_functions()
    assert writer_path_deletes(tree, src_deleter_functions()) == []


# ---------------------------------------------------------------------------
# Writer-path arm (N-543 residual, db 539fc re-check (3)): no delete on the DB
# writer. An rmtree inside a ``db_call`` helper holds the single writer thread
# while the bounded queue fills; ``submit_write`` then SHEDS, and other users'
# ``@audit_emitter`` rows become gap-events.
# ---------------------------------------------------------------------------

_WRITER_HOPS = frozenset({"db_call", "db_call_async"})


def writer_path_deletes(tree: ast.AST, deleters, attr_deleters=None) -> list[str]:
    """``helper:line`` for every delete reached inside a function (or lambda)
    handed to ``db_call``/``db_call_async`` in ``tree``: a primitive delete in its
    own body, or a call to a function in ``deleters`` (a fixpoint closure; bare-name
    calls). Attribute calls (``eb.purge_…``) match only ``attr_deleters`` (in
    the live scan, the exported module-level closure members of
    :func:`src_module_closures`), never the local closure: a closure name like
    ``execute`` must not match ``db.execute`` (measured round 6). Only the
    handed helper's OWN body is read here; depth comes from the closure."""
    attr_deleters = deleters if attr_deleters is None else attr_deleters
    ctx = _tree_delete_ctx(tree)
    module_defs = {n.name: n for n in getattr(tree, "body", [])
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    out: list[str] = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        local = dict(module_defs)
        local.update({n.name: n for n in _own_nodes_defs(fn)})
        for node in _own_nodes(fn):
            if not (isinstance(node, ast.Call) and _call_name(node) in _WRITER_HOPS and node.args):
                continue
            arg = node.args[0]
            # ``functools.partial(f, …)`` handed to the writer: look at ``f``
            if isinstance(arg, ast.Call) and _call_name(arg) == "partial" and arg.args:
                arg = arg.args[0]
            # an imported deleter handed STRAIGHT to the writer
            # (``db_call(purge_removal_tombstones)`` / ``db_call(eb.purge_…)``)
            direct = arg.id if isinstance(arg, ast.Name) else (
                arg.attr if isinstance(arg, ast.Attribute) else ""
            )
            if (isinstance(arg, ast.Name) and direct in deleters) or (
                isinstance(arg, ast.Attribute) and direct in attr_deleters
            ):
                out.append(f"{direct}:{node.lineno}")
                continue
            helper = local.get(arg.id) if isinstance(arg, ast.Name) else (
                arg if isinstance(arg, ast.Lambda) else None
            )
            if helper is None:
                continue
            nodes = ast.walk(helper.body) if isinstance(helper, ast.Lambda) else _own_nodes(helper)
            for call in nodes:
                if isinstance(call, ast.Call) and (
                    _is_tree_delete(call, ctx)
                    or (isinstance(call.func, ast.Name) and call.func.id in deleters)
                    or (isinstance(call.func, ast.Attribute) and call.func.attr in attr_deleters)
                ):
                    out.append(f"{getattr(helper, 'name', '<lambda>')}:{call.lineno}")
    return sorted(set(out))


#: Triaged writer-path deletes, keyed ``(relpath, helper)`` (R38). Not N-543's
#: class: an O(1) unlink, not a tree delete, in a helper that must run on the
#: writer. ``test_writer_path_baseline_is_not_stale`` drops a fixed entry.
WRITER_PATH_BASELINE: dict[tuple[str, str], str] = {}
# EMPTY since round 6. The round-4 entry (``web/background_sweepers.py``,
# ``snapshot_db_to_path``, keyed (path, qualname)) was CLEARED because it unlinks
# <=3 named temp files of a failed snapshot; once the arm was scoped to TREE
# deletes (``src_deleter_closure``) it no longer matches, and a stale entry fails
# ``test_writer_path_baseline_is_not_stale``.


@lru_cache(maxsize=1)
def src_module_closures() -> tuple[dict[str, frozenset[str]], frozenset[str]]:
    """Per-module tree-deleter closures, carried ACROSS ``from X import`` until
    stable (devils-advocate DA-R6-1: an imported function that reaches an rmtree
    in its own module, e.g. ``remove_install`` calling ``purge_…``, must count in
    the importer). Returns ``(closure by module, exported module-level names)``.
    """
    modules = [(rel, tree) for _p, rel, tree in walk_src()]
    exported = set(src_tree_deleters())
    while True:
        per: dict[str, frozenset[str]] = {}
        grown: set[str] = set()
        for rel, tree in modules:
            closure = module_tree_deleter_closure(tree, exported)
            per[rel] = closure
            grown |= {
                n.name for n in getattr(tree, "body", [])
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in closure
            }
        if grown <= exported:
            return per, frozenset(exported)
        exported |= grown


def _writer_path_live() -> dict[tuple[str, str], list[str]]:
    per, exported = src_module_closures()
    out: dict[tuple[str, str], list[str]] = {}
    for _p, rel, tree in walk_src():
        for hit in writer_path_deletes(tree, per[rel], exported):
            out.setdefault((rel, hit.split(":", 1)[0]), []).append(hit)
    return out


def test_writer_path_baseline_is_not_stale():
    live = _writer_path_live()
    stale = sorted(k for k in WRITER_PATH_BASELINE if k not in live)
    assert not stale, f"fixed or moved; remove from WRITER_PATH_BASELINE: {stale}"


def test_no_delete_runs_on_the_db_writer_path():
    found = {k: v for k, v in _writer_path_live().items() if k not in WRITER_PATH_BASELINE}
    assert not found, (
        f"{found}: a filesystem delete runs inside a db_call helper, on the single "
        f"DB writer thread. Rename there if you must (O(1)), and delete afterwards "
        f"in a worker thread (N-543: purge_removal_tombstones via to_thread)."
    )


def test_the_writer_path_arm_has_teeth():
    """The eccc3125 shape (rmtree inside the db_call helper, through the funnel)
    is flagged; the tombstone shape (rename in the helper, purge via to_thread)
    is not; a lambda handed to db_call is examined too."""
    prelude = (
        'import shutil\n'
        'def remove_install(conn):\n'
        '    shutil.rmtree("/x", ignore_errors=True)\n'
    )
    deleters = frozenset({"remove_install", "purge_removal_tombstones"})
    bad = prelude + (
        'async def route(request):\n'
        '    def _work():\n'
        '        remove_install(conn=db)\n'
        '    await db_call(_work)\n'
    )
    bad_lambda = 'async def route(r):\n    await db_call(lambda: shutil.rmtree(p))\n'
    good = (
        'async def route(request):\n'
        '    def _work():\n'
        '        os.replace(a, b)\n'
        '    await db_call(_work)\n'
        '    await asyncio.to_thread(purge_removal_tombstones)\n'
    )
    assert writer_path_deletes(parse_source(bad), deleters)
    assert writer_path_deletes(parse_source(bad_lambda), deleters)
    # the direct and wrapped hand-offs the devils-advocate named (round 4)
    for direct in (
        'async def r(q):\n    await db_call(purge_removal_tombstones)\n',
        'async def r(q):\n    await db_call(eb.purge_removal_tombstones, p)\n',
        'async def r(q):\n    await db_call(functools.partial(purge_removal_tombstones, p))\n',
    ):
        assert writer_path_deletes(parse_source(direct), deleters), direct
    assert not writer_path_deletes(parse_source(good), deleters)


def test_the_detector_has_teeth():
    """The pre-fold shape of ``embedding_remove`` is flagged (both arms), and the
    fixed shape is not."""
    prelude = (
        'import shutil\n'
        'def remove_install(conn):\n'
        '    shutil.rmtree("/x", ignore_errors=True)\n'
        'def _audit(db, user, **kw):\n'
        '    """Best-effort."""\n'
        '    safe_audit_write(lambda: record_auth_event(db, **kw), description="d")\n'
    )
    pre_fold = prelude + (
        'async def embedding_remove(request):\n'
        '    user, err = await db_call(_require_admin, request)\n'
        '    def _remove_db_work():\n'
        '        summary = remove_install(conn=db)\n'
        '        _audit(db, user, event_type="x")\n'
        '        db.commit()\n'
        '    await db_call(_remove_db_work)\n'
    )
    fixed = prelude + (
        'async def embedding_remove(request):\n'
        '    user, err = await db_call(_require_admin, request)\n'
        '    def _remove_db_work():\n'
        '        ok = safe_audit_write(lambda: record_auth_event(db, outcome="attempt"), description="i")\n'
        '        if ok is None:\n'
        '            return {}\n'
        '        summary = remove_install(conn=db)\n'
        '        _audit(db, user, event_type="x")\n'
        '    await db_call(_remove_db_work)\n'
    )
    no_witness_admin = prelude + (
        'async def wipe(request):\n'
        '    user, err = await db_call(_require_admin, request)\n'
        '    remove_install(conn=None)\n'
    )
    primitive_late = (
        'import os\n'
        'def f(p, db):\n'
        '    os.remove(p)\n'
        '    record_auth_event(db, event_type="x")\n'
    )
    for bad in (pre_fold, no_witness_admin, primitive_late):
        assert_pin_has_teeth(violations, bad, fixed)
    # a temp-file cleanup is not examined
    assert violations(parse_source(
        'import os, tempfile\n'
        'def f(db):\n'
        '    fd, p = tempfile.mkstemp()\n'
        '    os.remove(p)\n'
        '    record_auth_event(db, event_type="x")\n'
    )) == []


def test_the_write_arm_has_teeth():
    """The pre-fold shape of ``admin_tls_csr_import`` — the ACTIVE certificate is
    written, THEN the best-effort witness — is flagged; the witness-first shape
    is not. ``import_signed_cert`` here is a writer by the same rule the src
    scan uses (its own body calls ``atomic_write_bytes``)."""
    prelude = (
        'def import_signed_cert(cert_dir, raw):\n'
        '    atomic_write_bytes(cert_dir / "server.crt", raw)\n'
        'async def _audit(db, **kw):\n'
        '    """One statement."""\n'
        '    return await safe_audit_write_async(\n'
        '        lambda: db_call(record_auth_event, db, **kw), description="d") is not None\n'
    )
    late = prelude + (
        'async def admin_tls_csr_import(request):\n'
        '    user, err = await db_call(_require_admin, request)\n'
        '    crt = import_signed_cert(cd, raw)\n'
        '    await _audit(db, outcome="success")\n'
    )
    first = prelude + (
        'async def admin_tls_csr_import(request):\n'
        '    user, err = await db_call(_require_admin, request)\n'
        '    if not await _audit(db, outcome="attempt"):\n'
        '        return None\n'
        '    crt = import_signed_cert(cd, raw)\n'
        '    await _audit(db, outcome="success")\n'
    )
    writers = frozenset({"import_signed_cert"})
    assert violations(parse_source(late), writers)
    assert not violations(parse_source(first), writers)
    # the async one-statement wrapper is recognised as a witness
    tree = parse_source(prelude)
    assert "_audit" in pure_wrappers_in(tree, _emitters())


def test_the_tls_routes_are_in_the_scanned_set():
    """Prove the probe is in the set the control acts on: every TLS-CSR handler
    that changes key or certificate material produces a write event AND a
    witness event, witness first."""
    from _pin_harness import SRC_ROOT, parse_module

    tree = parse_module(SRC_ROOT / "web/routers/tls_csr.py")
    witnesses = set(_emitters()) | pure_wrappers_in(tree, _emitters())
    assert "_audit" in witnesses, "the TLS router's _audit must count as a witness"
    writers = set(tls_material_writers())
    for needed in ("make_csr", "cancel_pending", "import_signed_cert", "self_sign_now",
                   "issue_now", "issue_now_async"):
        assert needed in writers, needed
    for handler in ("admin_tls_csr_make", "admin_tls_csr_cancel",
                    "admin_tls_csr_import", "admin_tls_csr_self_sign"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef) and n.name == handler)
        kinds = [k for _l, k in _events(fn, {}, writers, witnesses)]
        assert "delete" in kinds and "witness" in kinds, (handler, kinds)
        assert kinds.index("witness") < kinds.index("delete"), (handler, kinds)


def test_the_acme_issue_route_is_in_the_scanned_set():
    """N-550 widened (round 4): the admin ACME issue route reaches the ACTIVE
    certificate write through ``issue_now_async`` -> ``to_thread(self.issue_now)``
    -> ``_atomic_write_cert``. It must produce a write event and a witness first."""
    from _pin_harness import SRC_ROOT, parse_module

    tree = parse_module(SRC_ROOT / "web/routers/auth_keys.py")
    witnesses = set(_emitters()) | pure_wrappers_in(tree, _emitters())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "admin_acme_issue_now")
    kinds = [k for _l, k in _events(fn, {}, set(tls_material_writers()), witnesses)]
    assert "delete" in kinds and "witness" in kinds, kinds
    assert kinds.index("witness") < kinds.index("delete"), kinds


def test_tls_material_modules_are_live():
    assert _TLS_MODULE_FLOOR <= tls_material_modules()
    assert tls_material_writers(), "no TLS writer found; the write arm is blind"


def test_enumeration_signature_is_live():
    """PD-4: record the raw population the arms were measured against, so a
    reader can judge net-completeness. A floor, not a count pin: it fails only if
    the primitive population VANISHES (the detector broke), never on growth."""
    total = 0
    for _p, _rel, tree in walk_src():
        total += sum(
            1 for n in ast.walk(tree)
            if isinstance(n, ast.Call) and is_primitive_delete(n)
        )
    assert total >= 10, f"only {total} primitive delete calls under src; detector broken?"


# ---------------------------------------------------------------------------
# Round 6 teeth (devils-advocate 539-fold3-da.md, db 539fc final)
# ---------------------------------------------------------------------------

import pytest  # noqa: E402


@pytest.mark.parametrize("body", [
    'def f(p):\n    with open(p, "wb") as fh:\n        fh.write(b"k")\n',
    'def f(p):\n    with p.open("wb") as fh:\n        fh.write(b"k")\n',
    'import shutil\ndef f(a, b):\n    shutil.move(a, b)\n',
    'import shutil\ndef f(a, b):\n    shutil.copy2(a, b)\n',
    'import os as _os\ndef f(a, b):\n    _os.replace(a, b)\n',
    'from os import replace\ndef f(a, b):\n    replace(a, b)\n',
    'import os\ndef f(fd):\n    os.write(fd, b"k")\n',
    'def f(p, x):\n    p.replace(target=x)\n',
], ids=["open-wb", "path-open-wb", "shutil-move", "shutil-copy2",
        "aliased-os", "from-os-import", "os-write", "replace-keyword"])
def test_the_write_predicate_sees_each_shape(body):
    assert "f" in module_file_writers(parse_source(body)), body


def test_the_write_predicate_does_not_see_reads():
    clean = (
        'def f(p, s):\n'
        '    with open(p) as fh:\n        fh.read()\n'
        '    with p.open("rb") as fh:\n        fh.read()\n'
        '    return s.replace("a", "b")\n'
    )
    assert module_file_writers(parse_source(clean)) == set()


def test_the_tls_scope_is_derived_and_covers_the_floor():
    derived = tls_material_modules()
    missing = _TLS_MODULE_FLOOR - derived
    assert not missing, f"the derivation lost {sorted(missing)}; check _TLS_PATH_SSOT_NAMES"
    # every module that references the cert/key path SSOT is in the scanned scope
    for _p, rel, tree in walk_src():
        if _references_tls_ssot(tree):
            assert rel in derived, rel


def test_the_writer_path_arm_sees_a_delete_two_helpers_deep():
    src = (
        'import shutil\n'
        'def _inner(p):\n    shutil.rmtree(p)\n'
        'def _middle(p):\n    _inner(p)\n'
        'async def route(r):\n'
        '    def _work():\n        _middle(x)\n'
        '    await db_call(_work)\n'
    )
    tree = parse_source(src)
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    closure = _fixpoint(fns, set(deleter_functions_in(tree)), attributes=False)
    assert {"_inner", "_middle"} <= closure
    assert writer_path_deletes(tree, closure), "two-deep delete on the writer path missed"
    assert not writer_path_deletes(tree, frozenset(deleter_functions_in(tree))), (
        "precondition: the one-level set alone must MISS it, or this teeth proves nothing"
    )


def test_the_writer_path_arm_follows_an_import_and_an_alias():
    """DA-R6-1: ``remove_install`` (another module) reaching ``purge_…`` must make
    the importer's db_call helper a hit. DA-R6-2: an aliased rmtree is an rmtree."""
    lib = parse_source(
        'import shutil\n'
        'def purge(p):\n    shutil.rmtree(p)\n'
        'def remove_install(conn):\n    purge(x)\n'
    )
    route = parse_source(
        'from lib import remove_install\n'
        'async def r(q):\n'
        '    def _work():\n        remove_install(db)\n'
        '    await db_call(_work)\n'
    )
    exported = set(module_tree_deleter_closure(lib, frozenset()))
    assert "remove_install" in exported
    assert writer_path_deletes(route, module_tree_deleter_closure(route, frozenset(exported)), exported)
    aliased = parse_source(
        'from shutil import rmtree as _rm\n'
        'async def r(q):\n'
        '    def _work():\n        _zap(p)\n'
        '    await db_call(_work)\n'
        'def _zap(p):\n    _rm(p)\n'
    )
    assert writer_path_deletes(aliased, module_tree_deleter_closure(aliased, frozenset()))


def test_the_install_routes_status_write_runs_on_the_writer():
    """db 539fc final (3): the install routes flip status to ``downloading``
    inside a helper handed to ``db_call``, so remove's in-flight check + rename
    (also one ``db_call``) and the install's flip are serialized on the writer."""
    from _pin_harness import SRC_ROOT, parse_module

    tree = parse_module(SRC_ROOT / "web/routers/ui/embedding_install.py")
    helpers = {"_install_db_work", "_sideload_db_work"}
    for route in ("embedding_install", "embedding_sideload"):
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == route)
        hopped = {
            c.args[0].id for c in _own_nodes(fn)
            if isinstance(c, ast.Call) and _call_name(c) == "db_call" and c.args
            and isinstance(c.args[0], ast.Name)
        }
        assert hopped & helpers, (route, hopped)
        helper = next(n for n in ast.walk(fn) if isinstance(n, ast.FunctionDef) and n.name in hopped & helpers)
        assert any(
            isinstance(k, ast.keyword) and k.arg == "status"
            and isinstance(k.value, ast.Constant) and k.value.value == "downloading"
            for k in ast.walk(helper)
        ), route
    # the removal side (DA-R6-4): the route hands ONE helper to db_call, and the
    # funnel it calls does the in-flight read and the rename in its own body
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "embedding_remove")
    hopped = [c.args[0].id for c in _own_nodes(fn)
              if isinstance(c, ast.Call) and _call_name(c) == "db_call" and c.args
              and isinstance(c.args[0], ast.Name)]
    assert [h for h in hopped if h != "_require_admin"] == ["_remove_db_work"], hopped
    eb_tree = parse_module(SRC_ROOT / "embedding_bits/__init__.py")
    remove = next(n for n in eb_tree.body if isinstance(n, ast.FunctionDef) and n.name == "remove_install")
    calls = [_call_name(c) for c in _own_nodes(remove) if isinstance(c, ast.Call)]
    assert "get_install_status" in calls and "replace" in calls, calls



# ---------------------------------------------------------------------------
# Round 7 (db 539fc LAST CONFIRM): the widened unbounded-delete seed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    'from shutil import rmtree as _rm\ndef f(p):\n    _rm(p)\n',
    'import tempfile\ndef f():\n    with tempfile.TemporaryDirectory() as d:\n        pass\n',
    'from tempfile import TemporaryDirectory\ndef f():\n    TemporaryDirectory().cleanup()\n',
    'import shutil\ndef f(a, b):\n    shutil.move(a, b)\n',
    'import os\ndef f(p):\n    os.removedirs(p)\n',
    'import subprocess\ndef f(p):\n    subprocess.run(["rm", "-rf", p])\n',
    'import os\ndef f():\n    os.system("rm -rf /tmp/x")\n',
    'def f(d):\n    for p in d.rglob("*"):\n        p.unlink()\n',
    'import os\ndef f(d):\n    while d:\n        os.remove(d.pop())\n',
    'def f(d):\n    [p.unlink() for p in d.iterdir()]\n',
], ids=["rmtree-alias", "tempdir-with", "tempdir-cleanup", "shutil-move", "os-removedirs",
        "subprocess-rm", "os-system-rm", "for-walk-unlink", "while-remove", "comprehension-unlink"])
def test_each_unbounded_delete_shape_seeds_the_closure(body):
    tree = parse_source(body)
    assert "f" in module_tree_deleter_closure(tree, frozenset()), body


def test_bounded_deletes_stay_clear():
    """``atomic_write_*``'s single temp unlink and the snapshot's literal-tuple
    loop must NOT seed, or the closure floods again (28 -> 488, round 6)."""
    atomic = (
        'import os\n'
        'def atomic_write_bytes(path, data):\n'
        '    try:\n        os.replace(tmp, path)\n'
        '    except Exception:\n        os.unlink(tmp)\n        raise\n'
    )
    snapshot = (
        'from pathlib import Path\n'
        'def _verify_then_swap(tmp):\n'
        '    for _ext in ("-wal", "-shm"):\n'
        '        Path(str(tmp) + _ext).unlink(missing_ok=True)\n'
    )
    for src in (atomic, snapshot):
        assert module_tree_deleter_closure(parse_source(src), frozenset()) == frozenset(), src


def test_the_real_bounded_helpers_stay_clear_in_src():
    """The same, against the REAL code: ``atomic_write_bytes``/``_text`` and
    ``backup.snapshot_db_to_path`` are not unbounded deleters."""
    seeds = src_tree_deleters()
    for name in ("atomic_write_bytes", "atomic_write_text", "snapshot_db_to_path"):
        assert name not in seeds, name
    assert "purge_removal_tombstones" in seeds, "the real unbounded deleter must still seed"


def test_a_fixed_module_registry_loop_is_bounded():
    """``for b in _BUILDERS`` over a module-level list literal is a registry, not a
    walk (the real ``dispose_all_per_account_artifacts``); a loop over a call
    result is a walk."""
    registry = (
        '_BUILDERS = [f]\n'
        'def dispose(a):\n    for b in _BUILDERS:\n        b(a).unlink()\n'
    )
    walk = 'def dispose(d):\n    for p in d.glob("*"):\n        p.unlink()\n'
    assert module_tree_deleter_closure(parse_source(registry), frozenset()) == frozenset()
    assert "dispose" in module_tree_deleter_closure(parse_source(walk), frozenset())


# ---------------------------------------------------------------------------
# Round 8 (devils-advocate DA-F6): the mode is read where the receiver takes it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    'import io\ndef f(p):\n    with io.open(p, "wb") as fh:\n        fh.write(b"k")\n',
    'import codecs\ndef f(p):\n    codecs.open(p, "w", "utf-8").write("k")\n',
    'import gzip\ndef f(p):\n    with gzip.open(p, "wb") as fh:\n        fh.write(b"k")\n',
    'import gzip as gz\ndef f(p):\n    gz.open(p, "ab")\n',
    'import os\ndef f(p):\n    os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)\n',
    'from os import open, O_TRUNC\ndef f(p):\n    open(p, O_TRUNC)\n',
    'import os\ndef f(p, flags):\n    os.open(p, flags)\n',
    'import os\ndef f(fd):\n    with os.fdopen(fd, "wb") as fh:\n        fh.write(b"k")\n',
    'def f(p, mode):\n    open(p, mode)\n',
    'def f(p, mode):\n    p.open(mode)\n',
    'def f(p, **kw):\n    open(p, **kw)\n',
], ids=["io-open", "codecs-open", "gzip-open", "gzip-alias", "os-open-flags",
        "from-os-open", "os-open-var-flags", "os-fdopen", "open-var-mode",
        "path-open-var-mode", "open-kwargs"])
def test_the_write_open_reads_the_mode_per_receiver(body):
    """Each of these was MISSED by the round-7 reader (it read the PATH as the
    mode for any ``x.open``, never looked at ``os.open`` flags or ``fdopen``,
    and passed any non-literal mode); each is a write now."""
    assert "f" in module_file_writers(parse_source(body)), body


@pytest.mark.parametrize("body", [
    'def f(p):\n    open(p)\n    open(p, "r")\n    open(p, mode="rb")\n',
    'import io, codecs, gzip\ndef f(p):\n    io.open(p, "rb")\n'
    '    codecs.open(p, "r", "utf-8")\n    gzip.open(p)\n    gzip.open(p, "rt")\n',
    'import io\ndef f():\n    io.open("/etc/wax+", "r")\n',
    'import os\ndef f(p):\n    os.open(p, os.O_RDONLY)\n    os.open(p, os.O_RDONLY | os.O_CLOEXEC)\n',
    'def f(p):\n    p.open()\n    p.open("rb")\n    p.open(mode="r")\n',
], ids=["builtin-reads", "module-reads", "literal-path-is-not-the-mode", "os-open-rdonly",
        "path-reads"])
def test_a_read_open_stays_clear(body):
    """Reads stay clear on every receiver. ``literal-path-is-not-the-mode`` was a
    FALSE write before round 8: the path ``/etc/wax+`` was read as the mode."""
    assert module_file_writers(parse_source(body)) == set(), body


def test_an_attribute_call_is_seen_only_in_the_handed_helper():
    """da round 6 asked whether ``eb.f()`` INSIDE a helper is covered. In the
    handed helper's own body: yes (``attr_deleters``). One helper further down:
    no (``attributes=False``). The second assert pins the blind spot the module
    docstring states, so widening the arm forces the docstring to change too."""
    exported = frozenset({"purge"})
    direct = parse_source(
        'import eb\n'
        'async def r(q):\n'
        '    def _work():\n        eb.purge(p)\n'
        '    await db_call(_work)\n'
    )
    assert writer_path_deletes(direct, module_tree_deleter_closure(direct, exported), exported)
    deeper = parse_source(
        'import eb\n'
        'def _mid(p):\n    eb.purge(p)\n'
        'async def r(q):\n'
        '    def _work():\n        _mid(p)\n'
        '    await db_call(_work)\n'
    )
    assert not writer_path_deletes(deeper, module_tree_deleter_closure(deeper, exported), exported)


def test_the_live_scan_uses_n520s_witness_set():
    """The re-key has teeth: ``record_hipaa_boundary_txn`` is a witness only in
    N-520's set (its own body calls a chain primitive; it is not an
    ``@audit_emitter`` name). Resolved as a call in ``db/audit.py``, a delete
    before it is flagged; on the name rules alone the same tree has no witness,
    so Arm A cannot fire."""
    tree = parse_source(
        'import os\n'
        'def f(conn, p):\n'
        '    os.remove(p)\n'
        '    record_hipaa_boundary_txn(conn)\n'
    )
    assert "record_hipaa_boundary_txn" not in _emitters(), "precondition: N-520-only"
    assert violations(tree, rel="db/audit.py"), "N-520's witness set was not consulted"
    assert violations(tree) == [], "precondition: the name rules alone see no witness"


@pytest.mark.parametrize("body", [
    'from shutil import move as _mv\ndef f(a, b):\n    _mv(a, b)\n',
    'from os import removedirs\ndef f(p):\n    removedirs(p)\n',
], ids=["from-shutil-move-alias", "from-os-removedirs"])
def test_a_from_imported_tree_deleter_seeds_the_closure(body):
    """The module docstring says ``move`` and ``removedirs`` seed "also under a
    ``from`` import name or alias"; round 7's fixtures covered only ``rmtree``
    and ``TemporaryDirectory`` that way (round 8 named the gap)."""
    assert "f" in module_tree_deleter_closure(parse_source(body), frozenset()), body


def test_a_module_level_helper_handed_by_name_is_read():
    """The module docstring says the handed helper may be a MODULE-LEVEL def, and
    that its own body is read. Every earlier helper fixture was nested in the
    caller. Here ``_work`` is module-level and NOT in the closure (its only
    delete is an attribute call, which the closure does not follow), so only
    reading its body finds ``eb.purge``."""
    exported = frozenset({"purge"})
    tree = parse_source(
        'import eb\n'
        'def _work(p):\n    eb.purge(p)\n'
        'async def r(q):\n    await db_call(_work, p)\n'
    )
    closure = module_tree_deleter_closure(tree, exported)
    assert "_work" not in closure, "precondition: the hit must come from the body read"
    assert writer_path_deletes(tree, closure, exported) == ["_work:3"]


def test_a_module_level_rmtree_helper_handed_by_name_is_flagged():
    """devils-advocate DA-F8-2 (blocking): 90 real ``db_call`` sites hand a
    MODULE-LEVEL def by name, resolved through ``local = dict(module_defs)``. The
    closure is passed EMPTY here so only that resolution plus the body read can
    find the rmtree (in the live scan the closure hand-off would catch it too);
    the same helper with no delete must stay clear."""
    bad = parse_source(
        'import shutil\n'
        'def _wipe_db_work():\n    shutil.rmtree(p)\n'
        'async def route():\n    await db_call(_wipe_db_work)\n'
    )
    good = parse_source(
        'def _flag_db_work():\n    conn.execute("UPDATE t SET x = 1")\n'
        'async def route():\n    await db_call(_flag_db_work)\n'
    )
    assert writer_path_deletes(bad, frozenset(), frozenset()) == ["_wipe_db_work:3"]
    assert writer_path_deletes(good, frozenset(), frozenset()) == []


@pytest.mark.parametrize("body", [
    '_P = []\ndef fill(d):\n    _P.extend(d.rglob("*"))\ndef f():\n    for p in _P:\n        p.unlink()\n',
    '_P: list = []\ndef f():\n    for p in _P:\n        p.unlink()\n',
    '_P = [a]\ndef fill(x):\n    _P.append(x)\ndef f():\n    for p in _P:\n        p.unlink()\n',
    'def f(d):\n    for p in [*d.rglob("*")]:\n        p.unlink()\n',
    '_B = [a]\ndef f(d):\n    _B = list(d.rglob("*"))\n    for p in _B:\n        p.unlink()\n',
    '_B = [a]\ndef g(d):\n    global _B\n    _B = list(d.rglob("*"))\ndef f():\n    for p in _B:\n        p.unlink()\n',
], ids=["empty-filled-later", "empty-filled-elsewhere", "appended", "starred-literal",
        "shadowing-local", "global-rebind"])
def test_a_literal_that_is_not_a_fixed_registry_is_unbounded(body):
    """DA-F8-1: an empty accumulator, a mutated list, a ``*starred`` literal, a
    local that shadows the module name, and a ``global`` rebind are walks, not
    registries. Each was BOUNDED (so missed) under the round-7 rule."""
    assert "f" in module_tree_deleter_closure(parse_source(body), frozenset()), body
