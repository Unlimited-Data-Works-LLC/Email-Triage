"""N-338c R31 — AST name-resolution walker pin (operator directive).

Trust-repair fix-forward per operator directive 2026-07-05 + the backlog
 (TASK ). Replaces the false-comfort N-295 py_compile pin (which
only catches SyntaxError, not runtime NameError). Walks every function
body in `src/email_triage/*.py`; for each `Name.Load` node, verifies
the name resolves against one of:

  * function-local scope (params + `Name.Store` assigns inside the fn),
  * module-scope names (imports + module-level defs + module-level
    Assign targets),
  * Python builtins,
  * an explicit `_ALLOWLIST_UNRESOLVED` (baseline for known dynamic-name
    sites — grep-loaded, `dir(x)`-checked, etc.).

An unresolved name is a runtime NameError waiting to fire (the class
N-295's py_compile pin was designed to catch but could not, because
py_compile is a syntax-only check that does not execute the module
body).

The pin uses a **file-scope allow-list** at first landing: every file
carrying at least one currently-unresolved name is baselined. New
files (not in the allow-list) MUST resolve every Name.Load. As
migrations shrink the unresolved set within an allow-listed file, the
file's entry can be removed. Ratchets monotonically.
"""
from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

import pytest

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# Files with baseline-known unresolved names at N-338c landing
# (2026-07-05). Each entry is a MIGRATION IOU — the walker's initial
# implementation over-flags on some legitimate patterns (nested
# annotation strings, FastAPI Depends() parameter binding via
# annotation, conditional-import scopes, generator-expression scope
# handling) so the baseline is generous. Migration cycle shrinks this
# set monotonically as (a) the walker gets more precise (tracked as
# N-338d), (b) real unresolved names get fixed in-tree.
#
# NEW files (not in this set) MUST resolve every Name.Load. Adding
# a file to this baseline requires an explanatory comment in the
# migration commit.
_ALLOWLIST_UNRESOLVED_FILES: frozenset[str] = frozenset({
    # N-338d ratchet 2026-07-06: baseline shrunk 76 → 66 after the walker
    # gained nested-fn + lambda param awareness (decorator wrappers +
    # inline callback patterns no longer over-flag).
    "_egress.py", "actions/add_label.py", "actions/base.py",
    "actions/digest.py",
    "actions/hipaa_style_distill.py", "actions/label.py",
    "actions/move.py", "actions/regulatory_clock.py",
    "actions/sent_mail_index.py", "actions/style_profile.py",
    "actions/topic_configs.py", "actions/topic_prefilter.py",
    "ai_backends/base.py",
    "cli.py",
    "db/_engine.py", "db/accounts.py", "db/regulatory_clock.py",
    "engine/embedding_backend.py",
    "jobs/embedding_reindex.py", "jobs/topic_backscan.py",
    "providers/_aioimaplib_patch.py", "providers/gmail_api.py",
    "providers/imap.py",
    "single_flight.py", "style_learning/distill_hipaa.py",
    "style_learning/per_contact_hipaa.py",
    "style_learning/phi_scrubber.py", "web/acme_renewer.py",
    "web/app.py", "web/background_sweepers.py", "web/csrf.py",
    "web/daily_health.py", "web/db_threadpool.py",
    "web/db_writelock.py", "web/dependencies.py", "web/digest.py",
    "web/ingestion_push.py", "web/migrations.py",
    "web/routers/agent_api.py",
    "web/routers/auth_keys.py", "web/routers/backup.py",
    "web/routers/help.py", "web/routers/ui/_shared.py",
    "web/routers/ui/accounts.py", "web/routers/ui/admin.py",
    "web/routers/ui/ai_backends_crud.py",
    "web/routers/ui/calendars.py", "web/routers/ui/categories.py",
    "web/routers/ui/embedding_install.py",
    "web/routers/ui/labels.py", "web/routers/ui/oauth.py",
    "web/routers/ui/webhook.py", "web/routers/ui/profile.py",
    "web/routers/ui/push.py", "web/routers/ui/retry_queue.py",
    "web/routers/ui/routes.py", "web/routers/ui/triage_classify.py",
    "web/routers/ui/users.py", "web/routers/ui/wizard.py",
    "web/topic_digest_sender.py", "web/triage_one.py",
    "web/triage_runner.py", "web/triage_runner_bulk.py",
    "web/watcher.py",
    "providers/office365.py", "web/o365_renewer.py",
    # the backlog  landing 2026-07-11 — nested closure ``_cb``
    # inside ``attach_audit_done_callback`` accesses enclosing-fn
    # params ``signal`` + ``description``. Walker's per-fn scope
    # resolution doesn't chain enclosing-fn params (docstring §46-52
    # documents this false-positive class). Same class as N-338d
    # follow-up hint for nested-fn awareness.
    "web/_audit.py",
})

# Names that are conventionally dynamic (available via runtime import,
# `if TYPE_CHECKING`, protocol-only forward references, etc.). These
# are project-wide legitimate unresolved names.
_ALLOWLIST_NAMES: frozenset[str] = frozenset({
    # Type-only forward references from `if TYPE_CHECKING:` blocks.
    # (The walker below is not TYPE_CHECKING-aware; these are the
    # names that appear as bare annotation strings.)
    "TYPE_CHECKING",
    # Common test / pytest fixtures accessed via string-name lookup.
    "monkeypatch", "capsys", "caplog", "tmp_path",
    # Star-imported implementation details (rare in the codebase; a
    # future migration should replace star imports).
    "_",
})


_BUILTINS: frozenset[str] = frozenset(dir(builtins))


def _module_scope_names(tree: ast.AST) -> set[str]:
    """Collect names bound at module scope: imports, def/class defs,
    top-level Assign targets, top-level AnnAssign targets."""
    names: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import foo.bar` binds `foo` at module scope.
                bound = alias.asname or alias.name.split(".")[0]
                names.add(bound)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                _collect_names_from_target(target, names)
        elif isinstance(node, ast.AnnAssign):
            _collect_names_from_target(node.target, names)
        elif isinstance(node, ast.If) or isinstance(node, ast.Try):
            # Inside if / try at module scope — walk one level down for
            # imports + assigns (common pattern for conditional imports).
            for sub in ast.walk(node):
                if isinstance(sub, ast.Import):
                    for alias in sub.names:
                        bound = alias.asname or alias.name.split(".")[0]
                        names.add(bound)
                elif isinstance(sub, ast.ImportFrom):
                    for alias in sub.names:
                        names.add(alias.asname or alias.name)
                elif isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        _collect_names_from_target(target, names)
                elif isinstance(sub, ast.AnnAssign):
                    _collect_names_from_target(sub.target, names)
                elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(sub.name)
    return names


def _collect_names_from_target(target: ast.AST, out: set[str]) -> None:
    """Recursively collect Name.Store ids from an assignment target."""
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_names_from_target(elt, out)
    elif isinstance(target, ast.Starred):
        _collect_names_from_target(target.value, out)
    # Attribute / Subscript targets don't BIND a new name.


def _fn_scope_names(fn: ast.AST, module_names: set[str]) -> set[str]:
    """Collect names bound within a function scope: params, local
    assigns, comprehension iter targets, exception-as bindings, walrus
    targets, nested fn/class defs. Includes `global` + `nonlocal`
    declarations (which reference module or enclosing scope).
    """
    names: set[str] = set()
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    # Parameters.
    if isinstance(fn, ast.Lambda):
        args = fn.args
    else:
        args = fn.args
    for a in args.args + args.posonlyargs + args.kwonlyargs:
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    # Walk body.
    body_iter = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else [fn.body]
    for stmt in body_iter:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    _collect_names_from_target(target, names)
            elif isinstance(sub, ast.AnnAssign):
                _collect_names_from_target(sub.target, names)
            elif isinstance(sub, ast.AugAssign):
                if isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
            elif isinstance(sub, ast.NamedExpr):
                if isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
            elif isinstance(sub, (ast.For, ast.AsyncFor)):
                _collect_names_from_target(sub.target, names)
            elif isinstance(sub, ast.With):
                for item in sub.items:
                    if item.optional_vars is not None:
                        _collect_names_from_target(item.optional_vars, names)
            elif isinstance(sub, ast.AsyncWith):
                for item in sub.items:
                    if item.optional_vars is not None:
                        _collect_names_from_target(item.optional_vars, names)
            elif isinstance(sub, ast.ExceptHandler):
                if sub.name is not None:
                    names.add(sub.name)
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(sub.name)
                # N-338d precision (2026-07-06): also harvest nested-fn
                # parameter names so uses inside the nested fn body don't
                # trip the OUTER fn's recursive body walk. The nested fn
                # is walked separately by the pin's ast.walk(tree) pass;
                # this only prevents the outer's recursion from flagging
                # the inner's params. Slight over-binding at outer scope
                # is per the pin's stated tolerance.
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nested_args = sub.args
                    for a in (nested_args.args + nested_args.posonlyargs
                              + nested_args.kwonlyargs):
                        names.add(a.arg)
                    if nested_args.vararg:
                        names.add(nested_args.vararg.arg)
                    if nested_args.kwarg:
                        names.add(nested_args.kwarg.arg)
            elif isinstance(sub, ast.Lambda):
                # N-338d: same treatment for lambdas — a lambda's params
                # are bound in its own scope; outer's walk sees the body's
                # Name refs and must not flag them.
                for a in (sub.args.args + sub.args.posonlyargs
                          + sub.args.kwonlyargs):
                    names.add(a.arg)
                if sub.args.vararg:
                    names.add(sub.args.vararg.arg)
                if sub.args.kwarg:
                    names.add(sub.args.kwarg.arg)
            elif isinstance(sub, ast.Import):
                for alias in sub.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(sub, ast.ImportFrom):
                for alias in sub.names:
                    names.add(alias.asname or alias.name)
            elif isinstance(sub, ast.Global) or isinstance(sub, ast.Nonlocal):
                # Declared names are visible in fn scope.
                for n in sub.names:
                    names.add(n)
            elif isinstance(sub, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                # Comprehension iter targets bind names in the
                # comprehension scope. For simplicity we surface them
                # at fn scope (the pin's false-positive tolerance is
                # OK with slight over-binding).
                for gen in sub.generators:
                    _collect_names_from_target(gen.target, names)
    return names


def _unresolved_names_in_fn(
    fn: ast.AST,
    module_names: set[str],
) -> list[tuple[str, int]]:
    """Return a list of (name, lineno) for every Name.Load in `fn`'s
    body that does NOT resolve against fn_scope | module_names |
    builtins | _ALLOWLIST_NAMES."""
    fn_names = _fn_scope_names(fn, module_names)
    resolvable = fn_names | module_names | _BUILTINS | _ALLOWLIST_NAMES
    unresolved: list[tuple[str, int]] = []
    body_iter = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else [fn.body]
    for stmt in body_iter:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id not in resolvable:
                    unresolved.append((sub.id, sub.lineno))
    return unresolved


@pytest.mark.parametrize("skip_file_scope_walk", [False])
def test_no_unresolved_names_in_new_files(skip_file_scope_walk: bool):
    """Anti-vacuity: every source file NOT in the baseline allow-list
    MUST have zero unresolved Name.Load references. New files that
    would fail this check must EITHER fix the missing binding OR add
    a file-scope allowlist entry with rationale.
    """
    violations: list[str] = []
    baseline_hits: dict[str, list[tuple[str, int]]] = {}
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        module_names = _module_scope_names(tree)
        unresolved_in_file: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                unresolved_in_file.extend(
                    _unresolved_names_in_fn(node, module_names)
                )
        if not unresolved_in_file:
            continue
        if rel in _ALLOWLIST_UNRESOLVED_FILES:
            baseline_hits[rel] = unresolved_in_file
        else:
            preview = ", ".join(
                f"{name}@{lineno}" for name, lineno in unresolved_in_file[:5]
            )
            violations.append(
                f"{rel}: {len(unresolved_in_file)} unresolved name(s) — "
                f"first {min(5, len(unresolved_in_file))}: {preview}"
            )
    if violations:
        pytest.fail(
            "N-338c: unresolved Name.Load reference(s) in file(s) not "
            "in `_ALLOWLIST_UNRESOLVED_FILES`. Either fix the missing "
            "binding (usually a forgotten import / typo / dead code) "
            "OR add the file to the baseline allow-list with an "
            "explanatory comment.\n\nViolations:\n  "
            + "\n  ".join(violations)
        )
    # Monotone shrink guard: allow-listed file with ZERO unresolved
    # names should be REMOVED from the allow-list (ratchet stays live).
    stale = _ALLOWLIST_UNRESOLVED_FILES - baseline_hits.keys()
    if stale:
        pytest.fail(
            "N-338c ratchet-shrink: allow-list files with ZERO remaining "
            "unresolved names — remove them from "
            "`_ALLOWLIST_UNRESOLVED_FILES` so the ratchet keeps shrinking "
            "monotonically.\n\nStale allow-list entries:\n  "
            + "\n  ".join(sorted(stale))
        )
