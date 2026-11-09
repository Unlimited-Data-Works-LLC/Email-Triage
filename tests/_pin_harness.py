"""Shared harness for the count-agnostic structural pins (R5b / R5c).

The ~40 structural-drift pins (``test_*_pin.py`` and friends) each hand-rolled
the SAME boilerplate — locate ``src/email_triage``, ``rglob("*.py")``, skip
``__pycache__``, parse the module, compute a repo-relative path, resolve a
node's enclosing function — and they HAD ALREADY DRIFTED in that boilerplate:

* the SRC root was spelled ``parents[1]/"src"/"email_triage"`` in tests/ but
  ``parents[2]/...`` in tests/test_web/ (off-by-one waiting to happen);
* the relpath BASE diverged three ways — ``relative_to(SRC)`` → ``web/db.py``,
  ``relative_to(SRC.parent)`` → ``email_triage/web/db.py``,
  ``relative_to(parents[1])`` → ``src/email_triage/web/db.py`` — so an
  allow-list entry copied between two pins silently missed (R38: the
  `auth_stale` basename-vs-relpath bug was this class);
* the forward-slash idiom split between ``.replace("\\\\", "/")`` and
  ``.as_posix()``.

A pin that drifts in its SCOPING is blind by construction, and nothing catches
it (the pins don't pin themselves). This module is the ONE home for that
boilerplate so a pin **cannot** drift in it. Detection logic + teeth stay
per-pin; only the walk / relpath / parse / enclosing-fn scaffolding converges.

The companion meta-pin ``test_pin_harness_adoption.py`` asserts every
src-walking structural pin imports this module (R5b *Enforce*), and the
divergence census seeds a "pin harness" class so a true-up re-measures it
(R5c — "census the censusers").

CANONICAL CHOICES (do not re-litigate per pin):
* ``SRC_ROOT`` = ``src/email_triage`` (the package root), computed ONCE here.
* ``relpath(p)`` is relative to ``SRC_ROOT`` → ``web/db.py`` form, forward-slash.
  This is the most-common existing base; a pin migrating off a different base
  must update its allow-list keys to this form (the migration's one real care).
"""

from __future__ import annotations

import ast
import os
from functools import lru_cache
from pathlib import Path

# The package root — computed ONCE, regardless of where the importing pin lives
# (tests/ or tests/test_web/). This file is tests/_pin_harness.py, so parents[1]
# is the repo root.
SRC_ROOT: Path = Path(__file__).resolve().parents[1] / "src" / "email_triage"

# The REPO root — for the structural pins that audit REPO-LEVEL files (Containerfile,
# pyproject.toml, requirements-*, docs/, the test tree itself) rather than
# ``src/*.py``. They were each re-rolling ``Path(__file__).resolve().parents[N]`` /
# ``.parent.parent`` (census run15 #3 — a fragile per-file root the meta-pin was
# blind to: an off-by-one on a file MOVE silently resolves to the wrong dir, and a
# ``.exists()``/read pin then fails-loud OR — worse for a walk pin — passes
# vacuously). Computed ONCE off SRC_ROOT so it can't drift independently.
REPO_ROOT: Path = SRC_ROOT.parents[1]

# The FULL DEV TREE, detected by a publish-config file that the publish curator itself
# strips from the public mirror: True in the dev repo, False in the curated public tree.
# The ONE definition (PD#5); five test files each re-rolled it before punch 629, and
# test_pin_harness_adoption.py::test_the_dev_tree_detector_has_one_definition fails on
# any other assignment.
_FULL_DEV_TREE: bool = (REPO_ROOT / "scripts" / "publish-strip-paths.txt").exists()

def tree_src_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """``os.environ`` plus ``extra``, with ``PYTHONPATH`` putting THIS tree's ``src`` first (ahead of
    an inherited ``PYTHONPATH``), for a test that starts a child python which must import this
    tree's ``email_triage``
    (punch 771). The package is installed editable from the MAIN checkout, so in a git worktree a
    child without this imports the main checkout's code and the test measures a tree other than
    the one under test (the alembic baseline test did exactly that in class AH). The ONE copy of
    the idiom: ``test_child_python_gets_this_trees_src_pin`` refuses a hand-built one.

    The twin in ``scripts/verified-test.py`` (``_pin_src``) is a script, not a test, and cannot
    import this module; it is deliberately a separate copy of the same three lines."""
    env = {**os.environ, **(extra or {})}
    rest = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC_ROOT.parent) + (os.pathsep + rest if rest else "")
    return env


# The Jinja templates root — for the pins that audit ``web/templates/*.html``
# (not ``src/*.py``); they were re-rolling their OWN root + rglob + relpath
# (R5c). Computed off SRC_ROOT so it can't drift independently.
TEMPLATES_ROOT: Path = SRC_ROOT / "web" / "templates"

# The recognized ``import json [as X]`` alias names for the json-column pins
# (test_load_json_col_pin / test_json_col_naming_pin). Hoisted here (run17 #7
# 3-SME — PD#5/#6) so the alias set lives in ONE place: the three pins each
# hard-coded ``("json", "_json")`` and so were BLIND to the ``json_mod`` /
# ``_json_decode`` aliases that hid 2 of the 6 routed sites. Closing an
# alias-evasion gap is now a one-line change covering all three pins.
JSON_DECODE_ALIASES: tuple[str, ...] = ("json", "_json", "json_mod", "_json_decode")

# The SSOT home for the secret-read family — the ONE module where a raw
# ``provider.get`` / ``provider.require`` is legitimate (that IS the funnel).
# Both structural pins in the class use this — the funnel pin
# (``test_secret_read_funnel_pin.py``, historically ``_EXEMPT_FILES``) and the
# collapse pin (``test_web/test_secret_read_collapse_pin_a5.py``, historically
# ``_SECRET_GET_SSOT_FILES``). Hoisted here (N-349 R31 tightening, census
# wf_69674c7e-c67 recommended widening B — 2026-07-11) so a future ``secrets.py``
# → ``secrets/`` package split can't leave one pin still exempting the old
# single-file basename while the other is widened. ONE constant, both pins
# import it. Same PD#6/#7 pattern as ``JSON_DECODE_ALIASES`` above.
SECRETS_SSOT_HOME: frozenset[str] = frozenset({"secrets.py"})


def is_bare_json_loads(node: ast.AST) -> bool:
    """True if ``node`` is a ``<alias>.loads(...)`` call for a recognized json
    alias (:data:`JSON_DECODE_ALIASES`) — the bare-decode shape the json-column
    pins forbid outside ``load_json_col``."""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "loads"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in JSON_DECODE_ALIASES)


def carries_only_own_splats(args, keywords, fn: ast.AST) -> bool:
    """True when a call's ``args`` / ``keywords`` are non-empty and carry NOTHING but ``fn``'s own
    ``*args`` / ``**kwargs`` (``g(*args, **kwargs)`` inside ``def f(*args, **kwargs)``). The ONE
    pass-through predicate: :func:`pass_through_calls` and :func:`forwarder_edges` both ask it
    (punch census-r2 B6, PD#5). A call that adds an explicit argument beside the splats, or splats
    a name ``fn`` does not own, is not a pass-through."""
    if not (args or keywords):
        return False
    var = fn.args.vararg.arg if fn.args.vararg else None  # type: ignore[attr-defined]
    kws = fn.args.kwarg.arg if fn.args.kwarg else None  # type: ignore[attr-defined]
    return (all(isinstance(a, ast.Starred) and isinstance(a.value, ast.Name)
                and a.value.id == var for a in args)
            and all(k.arg is None and isinstance(k.value, ast.Name)
                    and k.value.id == kws for k in keywords))


def pass_through_calls(tree: ast.AST, forwarder_name: str) -> set[int]:
    """``id()`` of every Call that carries NOTHING but its enclosing function's own
    ``*args`` / ``**kwargs`` (``def f(*args, **kwargs): return g(*args, **kwargs)``), where that
    enclosing function is NAMED ``forwarder_name``. A forwarder passes its caller's arguments on
    unchanged, so there is nothing to check at that site; the check lands on the forwarder's
    callers. That holds only when those callers are bound by name, so a pin that keys on the
    callee name ``call_ollama`` exempts only a forwarder that is itself named ``call_ollama``
    (the funnel's): a forwarder under any other name would hide its callers from the pin. A call
    that adds an explicit argument beside the splats, or splats names the function does not own,
    is NOT a pass-through.

    SCOPE: direct calls only; a forwarder that hands the splats to a dispatcher
    (``db_call(g, *args, **kwargs)``) is not exempted here. To find the forwarders of a funnel
    under ANY name, ask :func:`forwarder_edges` / ``reach_closure(.., forwarders_only=True)``."""
    out: set[int] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name != forwarder_name:
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and carries_only_own_splats(n.args, n.keywords, fn):
                out.add(id(n))
    return out


# Retired scripts (punch 749/750) sit under this one directory. No pin audits them: the
# scope is applied HERE, once, so a pin cannot forget it or copy the filter. Its
# companion check is test_llm_host_consumers_scaffold.test_nothing_outside_the_archive_names_a_path_under_it
# (nothing live reaches into the directory), so the exclusion cannot hide a live script.
#
# Stated as path PARTS, not a path: this shipped module only compares against it and never reads
# the directory (which does not ship), so no repo path is formed here.
RETIRED_SCRIPTS_PARTS: tuple[str, ...] = ("scripts", "archive")


def is_retired_script(path: Path) -> bool:
    """True for a file under the retired-scripts directory of THIS checkout."""
    root = REPO_ROOT.parts
    return path.parts[:len(root)] == root and path.parts[len(root):len(root) + 2] == RETIRED_SCRIPTS_PARTS


def iter_files(root: Path, pattern: str = "*.py", subdir: str | None = None):
    """Yield every file matching ``pattern`` under ``root`` (or ``root/subdir``),
    sorted, skipping ``__pycache__`` and the retired-scripts directory (``is_retired_script``) — the GENERIC
    walker. ``iter_src_files`` / ``iter_template_files`` are thin wrappers. A pin
    that audits a non-``.py`` tree (templates) or a different glob routes through
    HERE instead of re-rolling ``Path(...).rglob(...)`` + the ``__pycache__`` skip
    (R5c)."""
    base = root if subdir is None else root / subdir
    for path in sorted(base.rglob(pattern)):
        if "__pycache__" in path.parts or is_retired_script(path):
            continue
        yield path


def iter_workflow_files(workflows_dir: Path | None = None):
    """Every GitHub Actions workflow under ``workflows_dir`` (default
    ``.github/workflows``), ``*.yml`` AND ``*.yaml``, sorted: the ONE workflow
    walker. A pin that globbed ``*.yml`` alone let a ``.yaml`` workflow escape it
    (db-sme panel D F-2)."""
    base = workflows_dir if workflows_dir is not None else REPO_ROOT / ".github" / "workflows"
    yield from sorted({*iter_files(base, "*.yml"), *iter_files(base, "*.yaml")})


def workflow_texts(workflows_dir: Path | None = None) -> dict[str, str]:
    """``{".github/workflows/<file>": text}`` for every workflow ``iter_workflow_files`` yields."""
    base = workflows_dir if workflows_dir is not None else REPO_ROOT / ".github" / "workflows"
    return {relpath(p, base.parent.parent): p.read_text(encoding="utf-8") for p in iter_workflow_files(base)}


def iter_src_files(subdir: str | None = None):
    """Yield every ``*.py`` under ``SRC_ROOT`` (or ``SRC_ROOT/subdir``), sorted,
    skipping ``__pycache__``. The ONE source-file walk for every structural pin.

    ``subdir`` scopes a pin that only audits a subtree (e.g. ``"web/routers"``).
    """
    yield from iter_files(SRC_ROOT, "*.py", subdir)


def iter_template_files(subdir: str | None = None, pattern: str = "*.html"):
    """Yield every template (``*.html`` by default) under ``TEMPLATES_ROOT``
    (or a subdir), sorted, skipping ``__pycache__`` — the template-tree walk for
    pins that audit rendered markup (e.g. no inline admin link, audience header).
    """
    yield from iter_files(TEMPLATES_ROOT, pattern, subdir)


def relpath(path: Path, base: Path | None = None) -> str:
    """Repo-package-relative, forward-slash path (``web/db.py``) — the CANONICAL
    allow-list / violation key. Relative to ``SRC_ROOT`` by default; never
    basename (R38), never a divergent ``SRC.parent`` / repo-root base.

    ``base`` overrides the root for a pin scoped to a subtree (e.g. a
    routers-dir-relative key, or a ``TEMPLATES_ROOT``-relative one) — so the
    forward-slash + ``relative_to`` idiom still lives in ONE place instead of a
    re-rolled ``str(p.relative_to(other)).replace("\\", "/")`` (R5c)."""
    return str(path.relative_to(base if base is not None else SRC_ROOT)).replace("\\", "/")


def parse_module(path: Path) -> ast.AST | None:
    """Parse a source file to an AST, or ``None`` on a syntax/decode error
    (a pin skips an unparseable file rather than crash). Annotates parents so
    :func:`enclosing_fn` works on any walked node."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
        return None
    annotate_parents(tree)
    return tree


def parse_source(source: str, **parse_kwargs) -> ast.AST:
    """Parse a source STRING (for teeth tests / planted shapes), with parents
    annotated so :func:`enclosing_fn` works. Extra kwargs (e.g. ``filename=``)
    forward to ``ast.parse`` so callers migrating from ``ast.parse(text,
    filename=...)`` keep the error-message hint intact (N-388 R33 wave 2)."""
    tree = ast.parse(source, **parse_kwargs)
    annotate_parents(tree)
    return tree


def annotate_parents(tree: ast.AST) -> None:
    """Annotate every node with ``._ph_parent`` so a violation node can resolve
    its enclosing function. Idempotent."""
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._ph_parent = parent  # type: ignore[attr-defined]


def enclosing_fn(node: ast.AST) -> str:
    """Nearest enclosing function name (or ``"<module>"``). The LINE-STABLE key
    component (R38): an allow-list keyed on ``(relpath, enclosing_fn, payload)``
    survives an unrelated line shift, where ``(relpath, lineno)`` breaks
    fail-closed. Requires the tree to have been parsed via :func:`parse_module`
    / :func:`parse_source` (or :func:`annotate_parents`)."""
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = getattr(cur, "_ph_parent", None)
    return "<module>"


def enclosing_qualified_name(node: ast.AST) -> str:
    """Class-qualified enclosing function name (e.g. ``"SQLiteLogHandler.emit"``,
    or bare ``"insert_log_entry"`` at module scope, or ``"<module>"``). Walks the
    parent chain collecting every ``ClassDef`` + ``FunctionDef``/``AsyncFunctionDef``
    name and joins them with ``.`` so an allow-list keyed on this survives an
    unrelated line shift AND disambiguates same-named methods in the same file.

    Strictly stronger than :func:`enclosing_fn` for N-260-shape pins: two
    classes in one module both defining ``def emit`` would COLLIDE under bare
    ``enclosing_fn`` (a raw INSERT inside either would match the same
    ``(path, "emit")`` allow-list entry), but ``SQLiteLogHandler.emit`` vs
    ``_HipaaChainHandler.emit`` disambiguates.

    Requires the tree to have been parsed via :func:`parse_module` /
    :func:`parse_source` (or :func:`annotate_parents`)."""
    parts: list[str] = []
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parts.append(cur.name)
        cur = getattr(cur, "_ph_parent", None)
    if not parts:
        return "<module>"
    return ".".join(reversed(parts))


def enclosing_scope_chain(tree: ast.AST, lineno: int) -> list[ast.AST]:
    """The chain of scopes containing ``lineno``, INNERMOST FIRST, ending
    with ``tree`` (the module). Each element is a ``FunctionDef`` /
    ``AsyncFunctionDef`` node whose source span contains ``lineno``, plus
    ``tree`` appended last as the module fallback.

    Use this when a pin's Name-resolution check must honor Python's LEGB
    binding rule — a name assigned in an OUTER function is visible in an
    inner closure's set_cookie call, but a peer-function same-name assign
    is NOT. Iterating the chain innermost→module + unioning per-scope
    assigns gives the correct available-name set at ``lineno``.

    N-383 R32 (2026-07-10 post-deploy census wf_69674c7e-c67 close):
    this seam replaces every pin's hand-rolled parent-walk-for-scope
    idiom. Prime Directive #6 (pins obey the SSOT rule; the pins'
    parent-walk drifts too) — this helper is the one home for the shape."""
    fns: list[ast.AST] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo = n.lineno
            hi = getattr(n, "end_lineno", n.lineno) or n.lineno
            if lo <= lineno <= hi:
                fns.append(n)
    # Innermost first — larger start-line = more nested.
    fns.sort(key=lambda f: f.lineno, reverse=True)
    return fns + [tree]


def innermost_fn_at_lineno(tree: ast.AST, lineno: int):
    """The INNERMOST (most-nested) ``FunctionDef``/``AsyncFunctionDef`` NODE whose
    source span (``lineno``..``end_lineno``) contains ``lineno``, or ``None`` at
    module scope. Complements :func:`enclosing_fn`: use THIS when you hold a LINE
    NUMBER (a scan result, a node whose parent chain you didn't keep) rather than
    an annotated node. Innermost = the largest start-line among the containing
    functions (most nested). Does NOT need :func:`annotate_parents`."""
    candidates = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo = n.lineno
            hi = getattr(n, "end_lineno", n.lineno) or n.lineno
            if lo <= lineno <= hi:
                candidates.append(n)
    if not candidates:
        return None
    return max(candidates, key=lambda f: f.lineno)


def walk_src(subdir: str | None = None):
    """Convenience: yield ``(path, relpath, tree)`` for every parseable src
    file — the dominant pin loop in one call. Skips unparseable files."""
    for path in iter_src_files(subdir):
        tree = parse_module(path)
        if tree is not None:
            yield path, relpath(path), tree


# The two modules that HOME the ``@audit_emitter`` family (``db/audit.py`` +
# ``db/style.py``). Hoisted here (run18 #2, PD#5/#6) so the emitter MODULE list
# lives in ONE place: the N-36 redaction-map pin and the audit-emit-swallow pin
# both consume :func:`audit_emitter_defs`, and a second module list would be the
# exact CIDI the guide forbids.
AUDIT_EMITTER_MODULES: tuple[str, ...] = ("db/audit.py", "db/style.py")


def _is_audit_emitter_decorator(d: ast.expr) -> bool:
    """True if decorator node ``d`` is the ``@audit_emitter`` marker — a bare
    ``ast.Name`` (``@audit_emitter``) or an ``ast.Attribute``
    (``@db.audit_emitter``). The ONE decorator predicate (PD#6) — both
    :func:`audit_emitter_defs` (the 2-module fast path) and
    :func:`discover_audit_emitter_modules` (the full-src drift-guard walk) route
    through it, so the emitter-family scanner cannot fork into two divergent
    matchers. A bare-text ``"@audit_emitter"`` grep is NOT equivalent: four src
    files only MENTION the decorator (its definition, comments, the runtime
    ``_is_audit_emitter`` checks) without applying it — AST is the only reliable
    enumerator."""
    nm = (d.id if isinstance(d, ast.Name)
          else d.attr if isinstance(d, ast.Attribute) else None)
    return nm == "audit_emitter"


def audit_emitter_defs(modules: tuple[str, ...] = AUDIT_EMITTER_MODULES):
    """``(relpath, funcname)`` for every ``@audit_emitter``-decorated def across
    the emitter-home modules — the ONE shared walker for the ``@audit_emitter``
    family (PD#6: never fork a second emitter scanner).

    Detects the decorator via :func:`_is_audit_emitter_decorator`; the runtime
    ``_is_audit_emitter`` marker is closure-hidden behind ``@db_write``'s
    ``functools.wraps``, so AST is the only reliable enumerator. ``relpath`` is
    the SRC_ROOT-relative form (``db/audit.py``). Reads only ``modules`` (the
    2-module fast path by default — NOT a full-src walk; the
    :func:`discover_audit_emitter_modules` drift-guard proves that tuple stays
    complete). Consumed by ``TestAuditEmitterRedactionPin._emitter_defs`` (N-36
    forward + inverse pins) AND ``test_audit_emit_swallow_pin`` (run18 #2)."""
    for rel in modules:
        tree = parse_module(SRC_ROOT / rel)
        if tree is None:  # pragma: no cover - emitter modules always parse
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(_is_audit_emitter_decorator(d) for d in node.decorator_list):
                yield rel, node.name


def chain_writer_names() -> set[str]:
    """N-182 R20_7: chain-primitive helpers that write to a chained audit table
    but are NOT ``@audit_emitter``-decorated (they compose ``_chain_insert`` /
    log_entries HMAC-chain machinery differently). Currently
    ``{insert_log_entry, _chain_insert}`` — the log_entries chain primitive
    plus the transactional-atomic audit-events primitive (hipaa-sme N-182
    must-fix: `_chain_insert` is called directly by in-txn writers like
    `set_user_disabled` / `set_account_hipaa` that are NOT `@audit_emitter`
    decorated).

    **Drift caveat (PD#6 acknowledgment):** this is a small hardcoded set,
    which reintroduces the N-135 "hardcoded name list" trap at a smaller
    grain. Full structural discovery would walk the SRC for `INSERT INTO
    log_entries` calls + `_chain_insert` callers and reconcile against
    `@audit_emitter`-decorated funcs. Deferred — currently the set has ONE
    member and a companion drift-guard (see :func:`discover_chain_writers`)
    catches a new chain primitive by failing the swallow pin loudly rather
    than silently under-catching. **N-182b (allow-list step 2, B2):**
    ``SQLiteLogHandler.emit`` is a THIRD log_entries chain writer, and it is
    deliberately NOT declared here. The bare name ``emit`` collides with every
    ``logging.Handler.emit``, and the n543 witness net (via
    :func:`audit_emitter_names`) keys on the call NAME, so declaring it would
    make any ``x.emit(...)`` read as an audit witness (s2 panel MUST-B1). Its
    failure arms bump the /health audit-failure counter through
    ``triage_logging._bump_chain_write_failure``; the swallow pin carries it
    on ``_CHAIN_WRITER_ALLOW``, and the enforcement is the runtime test
    ``tests/test_n182b_chain_write_failure_counter.py``."""
    return {"insert_log_entry", "_chain_insert"}


def discover_chain_writers() -> set[str]:
    """N-182 companion drift-guard for :func:`chain_writer_names` — walk the
    SRC AST to find every function whose body contains a call to
    ``get_last_log_row_hash`` (the log_entries HMAC-chain primitive read) OR
    ``compute_log_row_hash`` (the chain-hash compute). A NEW chain-primitive
    added tomorrow would use those calls too, and the pin harness's
    companion test asserts ``set(discover_chain_writers()) ==
    chain_writer_names() ∪ {non-writer_helpers}`` so a 3rd chain primitive
    fails LOUDLY rather than escaping the swallow pin."""
    HMAC_CHAIN_HELPERS = {"get_last_log_row_hash", "compute_log_row_hash"}
    writers: set[str] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Call):
                    called = None
                    if isinstance(sub.func, ast.Name):
                        called = sub.func.id
                    elif isinstance(sub.func, ast.Attribute):
                        called = sub.func.attr
                    if called in HMAC_CHAIN_HELPERS:
                        writers.add(fn.name)
                        break
    return writers


def audit_emitter_names(modules: tuple[str, ...] = AUDIT_EMITTER_MODULES) -> set[str]:
    """The SET of ``@audit_emitter`` funcnames PLUS chain-primitive writers —
    the count-agnostic emitter net for the audit-emit-swallow pin (PD#1/#2).
    Derived structurally from the decorator via :func:`audit_emitter_defs`;
    N-182 R20_7 unions in :func:`chain_writer_names` so a chain-primitive
    (``insert_log_entry`` for log_entries) that isn't ``@audit_emitter``
    decorated is still caught by the swallow pin."""
    return {fn for _, fn in audit_emitter_defs(modules)} | chain_writer_names()


def discover_audit_emitter_modules() -> tuple[str, ...]:
    """The STRUCTURAL set of ``relpath`` modules that home at least one
    ``@audit_emitter``-decorated def — discovered by walking ALL of
    ``src/email_triage`` (NOT a hardcoded list). This is the DRIFT-GUARD for
    :data:`AUDIT_EMITTER_MODULES`: that 2-module tuple is a deliberate fast path
    (so the hot emitter walk parses 2 files, not 216), but a future
    ``@audit_emitter`` added in a THIRD module would otherwise silently escape
    BOTH the audit-emit-swallow pin AND the N-36 redaction pin — exactly N-135's
    hardcoded-NAME-list trap lifted to the MODULE grain. The companion guard test
    asserts ``set(discover_audit_emitter_modules()) == set(AUDIT_EMITTER_MODULES)``
    so a 3rd module FAILS loudly (forcing a human to add it to the tuple AND
    review its redaction-map + swallow-routing) rather than being silently
    absorbed. Reuses :func:`_is_audit_emitter_decorator` (PD#6 — same matcher as
    the fast path). The full-src walk runs only inside that guard test, never at
    import — so the hot path stays cheap."""
    mods: set[str] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover - all src parses on HEAD
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(_is_audit_emitter_decorator(d) for d in node.decorator_list):
                mods.add(relpath(path))
                break
    return tuple(sorted(mods))


def module_declares_function(tree: ast.AST, name: str, *, module_scope_only: bool = True) -> bool:
    """PD#6 hoist (N-409 Drive-4): does ``tree`` declare a
    ``FunctionDef``/``AsyncFunctionDef`` named ``name``?

    By default ``module_scope_only=True`` (db-sme Drive-2 non-blocking note #3
    — a nested inner-fn same-name is NOT a competing SSOT twin, so the SSOT
    declaration-side pins should ignore it; ``ast.walk`` would flag it). Pass
    ``module_scope_only=False`` for the legacy behaviour where any nested def
    counts."""
    if module_scope_only:
        if not isinstance(tree, ast.Module):
            return False
        return any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
            for n in tree.body
        )
    return any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
        for n in ast.walk(tree)
    )


def iter_string_literals(tree: ast.AST):
    """PD#6 hoist (N-409 Drive-4): yield every string-value node in ``tree``,
    reconstructing the string where the AST forks it:

      * ``ast.Constant`` with a ``str`` value → yields the value verbatim.
      * ``ast.JoinedStr`` (an f-string) → yields the concatenation of its
        literal ``Constant(str)`` parts (formatted-value slots become empty
        string so a needle spanning the literal segments is still detected).
      * ``ast.BinOp(BitAnd/…)`` with ``+`` operator over two string-valued
        operands → yields the concatenation of both operands' string values
        (either side may itself be a Constant, JoinedStr, or nested BinOp+).
        Closes db-sme Drive-2 non-blocking note #2 for N-413: a
        ``"prefix" + suffix_var`` fork would otherwise slip a substring
        check that reads only ``Constant``/``JoinedStr``.

    Non-string nodes yield nothing. A BinOp+ whose operand is a Name (a
    variable reference) contributes only what the other operand contributes
    — the runtime-only piece stays out of the yielded string. Consumers
    perform their own needle-match against the yielded strings."""

    def _string_value(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append("")
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = _string_value(node.left) or ""
            right = _string_value(node.right) or ""
            if left or right:
                return left + right
        return None

    for node in ast.walk(tree):
        s = _string_value(node)
        if s is not None:
            yield s


def docstring_constant_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of every module / class / function DOCSTRING ``Constant`` in ``tree``.

    A pin that asks what the CODE does must let prose name the thing the code
    may not do ("this module never builds an FTS index"). Exclude these ids
    from an ``ast.walk`` over ``ast.Constant`` nodes to get code-only strings.
    One home, so two pins cannot disagree about what counts as a docstring
    (PD#6)."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                out.add(id(body[0].value))
    return frozenset(out)


#: The assignment node types that bind a plain name to a value (``X = ..``, ``X: T = ..``, ``(X := ..)``).
_NAME_BINDING_ASSIGNS = frozenset({ast.Assign, ast.AnnAssign, ast.NamedExpr})


def _dynamic_import_bindings(tree: ast.AST, wanted, assigns, import_calls, libs) -> set[str]:
    """What ``importlib.import_module(<module name>)`` calls in ``tree`` bind, for module names where
    ``wanted(<module name>)``. The module name is a string literal or a module-level string constant.
    A call that is the value of a plain-name assignment binds those names; a call anywhere else (a
    ``return``, an argument, an attribute target) yields ``"*"``: resolved, names unknown, as the
    star-import does. ``module_ssot_imports`` makes the ONE walk of the tree (it runs once per node in
    some pins, so a second pass cost +45% on ``test_no_shipped_test_reads_an_unshipped_docs_path``) and
    hands in ``assigns`` (name-binding assignments whose value is a call), ``import_calls`` (calls whose
    callee may be ``import_module``) and ``libs`` (the names ``importlib`` is bound to)."""
    out: set[str] = set()
    consts = None
    assigned = {id(a.value): a for a in assigns}
    for call in import_calls:
        if not call.args:
            continue
        f = call.func
        if isinstance(f, ast.Attribute) and not (isinstance(f.value, ast.Name) and f.value.id in libs):
            continue
        arg = call.args[0]
        if isinstance(arg, ast.Name):
            if consts is None:
                consts = module_str_consts(tree)
            module = consts.get(arg.id)
        else:
            module = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None
        if module is None or not wanted(module):
            continue
        a = assigned.get(id(call))
        targets = () if a is None else (a.targets if isinstance(a, ast.Assign) else [a.target])
        out.update(t.id for t in targets if isinstance(t, ast.Name))
        if a is None or not any(isinstance(t, ast.Name) for t in targets):
            out.add("*")
    return out


def module_ssot_imports(tree: ast.AST, ssot_module: str) -> set[str]:
    """PD#6 hoist (N-409 Drive-4): return the set of NAMES bound in ``tree``
    that resolve to ``ssot_module`` (or a submodule) — importable aliases
    included. Closes db-sme Drive-2 non-blocking note #1 for N-412: a
    ``import ...classify.baa_gate as bg`` + ``bg.baa_ack_key(...)`` should
    resolve to the SSOT even though the receiver name is ``bg``, not
    ``baa_gate``.

    ``ssot_module`` is a fully-qualified module path, e.g.
    ``"email_triage.classify.baa_gate"``; the check is prefix-based so a
    submodule import (``from email_triage.classify.baa_gate.child import ...``)
    still resolves.

    Returns the union of:
      * ``import X`` / ``import X.Y as Z`` — where ``X`` (or ``Z``) resolves
        to ``ssot_module`` or a descendant → the bound name is added.
      * ``from X import Y`` / ``from X import Y as Z`` — where ``X`` resolves
        to ``ssot_module`` or a descendant → the bound name (``Z`` if aliased,
        else ``Y``) is added; a bare ``from ssot_module import *`` yields the
        singleton ``{"*"}`` to signal caller-side "resolved but names
        unknown".
      * ``from <ancestor> import <trailing>`` — where ``<ancestor>`` is a
        proper ancestor of ``ssot_module`` and ``<trailing>`` is the first
        segment beneath that ancestor along the SSOT path (e.g. `from
        email_triage.classify import baa_gate` — a sibling `from
        email_triage.classify import other_mod` is NOT SSOT-imported).
        db-sme fix db-1 (N-409 close-out): the ancestor branch previously
        added every alias in the ImportFrom, over-attributing sibling
        modules; the correct filter is only the alias whose ``name``
        matches the trailing SSOT segment relative to ``<ancestor>``.

      * ``X = importlib.import_module("<ssot or descendant>")`` (census-r2 B7) —
        ``X`` is added. The module name is a string literal or a module-level
        string constant (``tls.py`` passes ``_SPKI_MODULE``); ``importlib`` may
        be aliased (``import importlib as il``) and ``import_module`` imported by
        name (``from importlib import import_module as im``). The target is a
        plain name (``X = ..``, ``X: T = ..``, ``(X := ..)``); a call anywhere else (``return
        importlib.import_module(_SPKI_MODULE)`` at ``tls.py:410``, an argument, ``self.bg = ..``) yields
        ``"*"``, resolved with the names unknown, as the star-import does.

    **Residual (documented per DA hedge da-fix-2, `feedback_just_be_honest`):**
    ``__import__("..")``, a computed or relative module name
    (``import_module(f"{pkg}.baa_gate")``, ``import_module(".baa_gate", __package__)``)
    and a ``getattr(<parent package>, "baa_gate")`` of an already-imported package are
    not resolved; a dynamic import stored on an attribute (``self.bg = ..``) is ``"*"``, never a
    receiver name. The ``getattr`` shape is left out on purpose: it needs the
    parent package's own binding tracked first (a two-step chain), and of the
    760 constant-name ``getattr`` calls in ``src/`` (measured 2026-11-05) one reads a
    name off an imported module: ``getattr(os, "geteuid")``, not an SSOT."""
    out: set[str] = set()
    prefix = ssot_module + "."
    libs, funcs, assigns, import_calls = {"importlib"}, set(), [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod == ssot_module or mod.startswith(prefix):
                    out.add(alias.asname or mod.split(".")[0])
                if mod == "importlib":
                    libs.add(alias.asname or mod)
        elif isinstance(node, ast.ImportFrom):
            src = node.module or ""
            if src == "importlib" and not node.level:
                funcs.update(a.asname or a.name for a in node.names if a.name == "import_module")
            if src == ssot_module or src.startswith(prefix):
                # `from ssot_module import X` or `from ssot_module.child import X`
                for alias in node.names:
                    if alias.name == "*":
                        out.add("*")
                    else:
                        out.add(alias.asname or alias.name)
            elif ssot_module.startswith(src + "."):
                # `from <ancestor> import <trailing>` — filter to the alias
                # whose name is the next path segment toward the SSOT (fix
                # db-1: was iterating all aliases, over-attributing siblings).
                trailing_first = ssot_module[len(src) + 1:].split(".")[0]
                for alias in node.names:
                    if alias.name == trailing_first:
                        out.add(alias.asname or alias.name)
                    elif alias.name == "*":
                        # `from <ancestor> import *` — the SSOT module MAY
                        # be re-exported by the ancestor; conservatively
                        # flag as "resolved but names unknown".
                        out.add("*")
        elif type(node) in _NAME_BINDING_ASSIGNS:
            if isinstance(node.value, ast.Call):
                assigns.append(node)
        elif type(node) is ast.Call:
            if type(node.func) is ast.Attribute and node.func.attr == "import_module":
                import_calls.append(node)
    if funcs:  # `from importlib import import_module [as im]`: calls by that bare name
        import_calls.extend(n for n in ast.walk(tree)
                            if type(n) is ast.Call and type(n.func) is ast.Name and n.func.id in funcs)
    if import_calls:
        out |= _dynamic_import_bindings(
            tree, lambda m: m == ssot_module or m.startswith(prefix), assigns, import_calls, libs)
    return out


# ---------------------------------------------------------------------------
# Containerfile readers (punch 538, 2026-09-29 — PD#6).
#
# Two pins now audit the Containerfile: the N-432 Path-3 arch pin and the
# source-built declaration pin. Both need "the non-comment text" and the second
# needs "per BUILD STAGE, in instruction order". The comment filter already
# existed, hand-rolled, inside ``test_arch_encryption_build_pin.py`` as
# ``_CF_CODE``; a second copy in the new pin is exactly the divergence the pins
# exist to catch (a widened filter in one, a stale one in the other, and the
# weaker of the two silently becomes the real coverage). One home, both import.
# ---------------------------------------------------------------------------

#: The repo-root Containerfile — the one spelling, computed off REPO_ROOT.
CONTAINERFILE: Path = REPO_ROOT / "Containerfile"


def load_repo_script(relpath: str, module_name: str | None = None):
    """Import a ``scripts/…py`` helper BY PATH and return the module.

    ``scripts/`` is not a package and is not on ``sys.path``, so a pin that
    wants to reuse a build helper's logic — rather than re-implement it, and
    then drift from it — needs this. Two pins now import
    ``scripts/source_built.py``; the loader boilerplate lives here so it is not
    the thing that forks (PD#6)."""
    import importlib.util
    import sys

    name = module_name or ("_repo_script_" + relpath.replace("/", "_").removesuffix(".py"))
    if name in sys.modules:
        return sys.modules[name]
    path = REPO_ROOT / relpath
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - path typo
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def dockerfile_code(text: str) -> str:
    """``text`` with every whole-line ``#`` comment dropped.

    A comment that NAMES a forbidden shape ("sqlcipher3-binary was the
    pre-Path-3 wheel", "the old check was a 3.53.x range") must not trip a pin
    that cares about what the build RUNS. Docker's own parser drops these lines
    before joining continuations, so this is also what the daemon sees."""
    return "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
    )


def dockerfile_instructions(text: str) -> list[tuple[int, str]]:
    """``(1-based start line, joined instruction text)`` for every instruction.

    Backslash continuations are joined into ONE logical instruction and
    comments are dropped, which is the only way to ask ordering questions
    ("is the COPY before the RUN that reads it") without a line-number
    heuristic that a reformat would break."""
    out: list[tuple[int, str]] = []
    current: list[str] = []
    start = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        stripped = raw.rstrip()
        if not current:
            if not stripped.strip():
                continue
            start = lineno
        current.append(stripped[:-1] if stripped.endswith("\\") else stripped)
        if not stripped.endswith("\\"):
            out.append((start, "\n".join(current)))
            current = []
    if current:
        out.append((start, "\n".join(current)))
    return out


def dockerfile_stages(text: str) -> list[tuple[str, list[tuple[int, str]]]]:
    """``(stage name, its instructions)`` per ``FROM`` — build-stage scoped.

    A COPY in the builder stage says nothing about whether the runtime stage
    has the file it reads: every stage is a fresh filesystem except for what it
    explicitly copies. A pin that asks "is the file present before the RUN that
    reads it" is wrong unless it asks it per stage, so the split lives here.
    The stage name is the ``AS <name>`` alias when present, else the image."""
    stages: list[tuple[str, list[tuple[int, str]]]] = []
    for lineno, instr in dockerfile_instructions(text):
        head = instr.split(None, 1)
        if head and head[0].upper() == "FROM":
            parts = instr.split()
            name = parts[-1] if len(parts) >= 4 and parts[-2].upper() == "AS" else parts[1]
            stages.append((name, []))
            continue
        if stages:
            stages[-1][1].append((lineno, instr))
    return stages


def dockerfile_shell_text(instr: str) -> str:
    """One :func:`dockerfile_instructions` entry as the daemon hands it to the shell.

    Docker removes each ``\\``-newline continuation and concatenates the lines
    with NO newline (comment lines inside it are already dropped). The ``"\\n"``
    joints that :func:`dockerfile_instructions` keeps serve ordering questions
    only; a pin that parses what a ``RUN`` executes must use this form, because a
    ``#`` inside a ``python -c`` body comments out every statement after it, not
    just the rest of its source row (punch 652)."""
    return "".join(instr.split("\n"))


# PHI-free payload predicate (container health-endpoint standard, 2026-09-29).
#
# The cross-container standard `pattern_container_health_endpoint_standard`
# requires, for every service handling regulated data, "a machine-checked test
# asserting the detail/deps payloads contain no owner-name / email / subject /
# message-content key — so a non-session reader can never *silently* become a
# PHI surface as fields are added later."
#
# It lives HERE because the obligation is per-PAYLOAD, not per-route: the
# structural arm (does the handler EMIT such a key) and the behavioural arm (does
# the live response CARRY one) are two files, and a needle list copied into both
# is the mirrored-copy drift this harness exists to stop (PD-5). One list, every
# consumer imports it.
#
# SCOPE — the kind this predicate is canonical for (PD-5's precondition). It
# judges CONTRACT KEY NAMES: the enumerated keys a handler is written to return.
# It is NOT canonical for data-derived keys. Do not point it at a map whose keys
# come from the environment — a dist-info scan yields real PyPI names like
# `email-validator`, `user-agents` and `names`, so this would flag a legitimate
# dependency, someone would allow-list it, and the pin would end up weaker than
# if it had never been written. Assert those by SHAPE instead.
# ---------------------------------------------------------------------------

#: Substrings that mean a contract key names a person, a mailbox or mail content.
#: Deliberately broad: a false positive is a short conversation, a false negative
#: is a PHI disclosure on a route an external scanner polls.
PHI_KEY_NEEDLES: tuple[str, ...] = (
    "owner", "email", "subject", "message", "sender", "recipient",
    "account", "mailbox", "body", "addr", "patient", "mrn", "dob",
    "phi", "display_name", "user",
)


def phi_shaped_keys(keys) -> list[str]:
    """The CONTRACT keys in ``keys`` whose name is PHI/identity-shaped.

    Returns a list of ``"<key> (matched '<needle>')"`` strings — empty means
    clean. Each entry names the needle so a reviewer can judge a borderline hit
    instead of re-deriving why it fired.
    """
    out: list[str] = []
    for key in keys:
        low = str(key).lower()
        for needle in PHI_KEY_NEEDLES:
            if needle in low:
                out.append(f"{key} (matched {needle!r})")
                break
    return out


def returned_dict_keys(fn: ast.AST) -> list[str]:
    """Every string key of every dict literal ``fn`` RETURNS.

    Structural companion to :func:`phi_shaped_keys`: it reads what a handler is
    WRITTEN to emit, so a new key is caught at the source even on a branch no
    test exercises. An empty result from a handler that plainly returns a dict is
    itself a finding — a payload assembled by mutation cannot be pinned this way,
    and a caller should assert non-empty before trusting a clean sweep.
    """
    keys: list[str] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.append(key.value)
    return keys


def assert_pin_has_teeth(detector, bad_source: str, good_source: str | None = None) -> None:
    """Assert a pin's detector has TEETH: it FLAGS a planted bad shape, and
    (optionally) does NOT flag a good one. ``detector`` takes a parsed+annotated
    tree and returns a truthy "violations" value. Raises AssertionError on
    failure (use inside a ``test_*_has_teeth`` body)."""
    bad_tree = parse_source(bad_source)
    assert detector(bad_tree), "pin missed a planted bad shape (no teeth)"
    if good_source is not None:
        good_tree = parse_source(good_source)
        assert not detector(good_tree), "pin flagged a good shape (false positive)"


# ---------------------------------------------------------------------------
# SecretsProvider receiver-TYPE predicate (run18 #5/#6, §7d / PD#6).
#
# Two pins — the config-store disjointness pin (#5,
# ``test_config_store_disjoint_pin.py``) and the secret-read funnel pin (#6,
# ``test_secret_read_funnel_pin.py``) — classified a call's receiver as "a
# secrets handle" by a NAME SUBSTRING (``secret``/``provider``) / a hand-listed
# name set. A renamed handle (``bootstrap = create_secrets_provider(...)``) or a
# future alias slips that net — the §7-recurring failure mode where the
# membership predicate is *narrower than the class it names* (a pin green-and-
# wrong). These helpers classify the receiver by its resolved static TYPE
# instead, and are the ONE shared predicate BOTH pins consume (PD#6: never fork a
# second receiver scanner; reuse the harness walk).
#
# STATIC-RESOLUTION CAVEAT (honest — the residual): only receivers whose type is
# recoverable from the AST are resolved — a param / assignment ANNOTATION
# (``x: SecretsProvider`` / ``def f(x: DbSecrets)``), a family-CONSTRUCTOR call
# (``x = DbSecrets(...)``), or a family-RETURN-annotated FACTORY call
# (``x = create_secrets_provider(...)``, whose ``-> SecretsProvider`` annotation
# is resolved src-wide). A receiver typed only at RUNTIME — an UNANNOTATED param,
# or a value smuggled through a dict / an instance attribute (``self.secrets``) —
# is NOT in the type table; that residual is why each consuming pin keeps its own
# receiver-NAME fallback as a documented backstop (a strict UNION → the net only
# ever widens, never regresses).
# ---------------------------------------------------------------------------

_SECRETS_ROOT_TYPE = "SecretsProvider"


@lru_cache(maxsize=1)
def secrets_provider_type_names() -> frozenset[str]:
    """Class names that are :data:`_SECRETS_ROOT_TYPE` or a (transitive) subclass,
    discovered structurally across ``src/email_triage`` — NEVER a hardcoded list,
    so a new provider subclass (``class FooSecrets(SecretsProvider)``) is covered
    automatically (PD#1: the type SET is a property of the class hierarchy).
    Fixpoint over every ``class X(Base, …)`` so a subclass-of-a-subclass resolves
    even across module boundaries."""
    bases: dict[str, set[str]] = {}
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover - all src parses on HEAD
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                names = {b.id for b in node.bases if isinstance(b, ast.Name)}
                names |= {b.attr for b in node.bases if isinstance(b, ast.Attribute)}
                bases.setdefault(node.name, set()).update(names)
    fam = {_SECRETS_ROOT_TYPE}
    changed = True
    while changed:
        changed = False
        for cls, bs in bases.items():
            if cls not in fam and (bs & fam):
                fam.add(cls)
                changed = True
    return frozenset(fam)


def _is_direct_family_annotation(node: ast.AST | None, fam: frozenset[str]) -> bool:
    """True when annotation ``node`` denotes a value that *is itself* a
    SecretsProvider-family handle — ``X``, ``X | None``, ``Optional[X]``, and the
    PEP-563 string forward-ref of those. Deliberately NOT true for a CONTAINER
    that merely holds one (``tuple[..., SecretsProvider]`` — the
    ``_require_owned_account`` shape): a name bound to that tuple is not a secrets
    handle, so flagging it would be a false positive."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in fam
    if isinstance(node, ast.Attribute):  # e.g. secrets.SecretsProvider
        return node.attr in fam
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        operands = [node.left, node.right]
        non_none = [
            o for o in operands
            if not (isinstance(o, ast.Constant) and o.value is None)
            and not (isinstance(o, ast.Name) and o.id == "None")
        ]
        return bool(non_none) and all(
            _is_direct_family_annotation(o, fam) for o in non_none
        )
    if isinstance(node, ast.Subscript):  # Optional[X] yes; tuple[..]/list[..] no
        val = node.value
        head = (val.id if isinstance(val, ast.Name)
                else val.attr if isinstance(val, ast.Attribute) else None)
        if head == "Optional":
            return _is_direct_family_annotation(node.slice, fam)
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return _is_direct_family_annotation(
                ast.parse(node.value, mode="eval").body, fam
            )
        except SyntaxError:  # not a type expression
            return False
    return False


@lru_cache(maxsize=1)
def _secrets_factory_return_names() -> frozenset[str]:
    """Module-level function names across src whose RETURN annotation is
    *directly* a SecretsProvider-family type — so ``x = create_secrets_provider(...)``
    / ``x = bootstrap_secrets_from_config(...)`` resolves ``x`` to the family even
    though the RHS is a call, not a constructor. Discovered structurally (PD#1). A
    factory returning a TUPLE that merely contains a provider
    (``_require_owned_account``) is excluded — its result is unpacked, never a
    single secrets handle."""
    fam = secrets_provider_type_names()
    out: set[str] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_direct_family_annotation(node.returns, fam):
                    out.add(node.name)
    return frozenset(out)


def secret_receiver_type_table(tree: ast.AST) -> set[str]:
    """Names in ``tree`` statically resolvable to a SecretsProvider-family
    receiver — the §7d type table consumed by
    :func:`is_secrets_provider_typed_receiver`. See the module-level caveat for
    exactly what is (and is NOT) resolvable. Resolves from: param / kw-only /
    var-arg ANNOTATIONS, annotated assignments, family-CONSTRUCTOR calls, and
    family-RETURN-annotated FACTORY calls."""
    fam = secrets_provider_type_names()
    factories = _secrets_factory_return_names()
    table: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            allargs = (
                list(getattr(a, "posonlyargs", []))
                + list(a.args)
                + list(a.kwonlyargs)
            )
            if a.vararg is not None:
                allargs.append(a.vararg)
            if a.kwarg is not None:
                allargs.append(a.kwarg)
            for arg in allargs:
                if _is_direct_family_annotation(getattr(arg, "annotation", None), fam):
                    table.add(arg.arg)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if _is_direct_family_annotation(node.annotation, fam):
                table.add(node.target.id)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            callee = (
                f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None
            )
            if callee and (callee in fam or callee in factories):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        table.add(tgt.id)
    return table


def is_secrets_provider_typed_receiver(func: ast.Attribute, type_table) -> bool:
    """True when the receiver of attribute-call ``func`` (e.g. the ``x`` in
    ``x.set(...)`` / ``x.get(...)``) resolves by STATIC TYPE — via ``type_table``
    from :func:`secret_receiver_type_table` — to a SecretsProvider-family handle.
    The §7d receiver-TYPE predicate: keyed on the resolved type, not a name
    substring. The ONE shared receiver classifier both the #5 disjoint pin and
    the #6 funnel pin consume (PD#6). Only a bare ``ast.Name`` receiver can be
    type-resolved here; an attribute receiver (``self.secrets``) is left to the
    caller's name fallback (the documented residual)."""
    v = func.value
    return isinstance(v, ast.Name) and v.id in type_table


# ---------------------------------------------------------------------------
# Bash block depth (punch , 2026-09-24).
#
# A pin that asks "is this call reachable only through some `if`?" cannot answer
# by indentation: bash does not require it, and a column-0 call under
# `if [ "$SKIP_VALIDATE" = 0 ]; then` is still nested. This walker tracks block
# depth outside quotes, comments and heredoc bodies. It is deliberately small; it
# raises instead of guessing when a script does not end balanced, so a script it
# cannot parse fails the pin loudly rather than reading as "depth 0 everywhere".
# ---------------------------------------------------------------------------

_SH_OPENERS = frozenset({"if", "case", "while", "until", "for", "select", "{"})
_SH_CLOSERS = frozenset({"fi", "esac", "done", "}"})
_SH_DELIMS = frozenset(" \t;&|()<>")


def shell_block_depths(text: str) -> list[tuple[int, bool]]:
    """Per line of a bash script: ``(block_depth, starts_in_code)`` at the start
    of that line. ``starts_in_code`` is False when the line begins inside a
    quoted string or a heredoc body. Openers are ``if case while until for
    select``, a standalone ``{`` and a top-level subshell ``(``; closers are
    ``fi esac done``, a standalone ``}`` and that subshell's ``)``. Only
    unquoted words count, so ``log "... if ..."`` does not, and an opener glued
    to a command substitution (``X=$(if ...; fi)``) counts like any other.

    A top-level ``(`` opens a subshell block when it starts a word (punch 526:
    ``exit`` inside ``( )`` returns to the parent, so a call inside one is not
    at depth 0). A ``(`` glued to a word (``f()``, ``arr=(``) is tracked but adds
    no depth. A ``)`` closes the innermost ``(`` only when no block opened after
    it is still open; otherwise it is a ``case`` pattern and is ignored. Parens
    inside ``$(...)`` keep the substitution's own count and add no depth.

    Raises ``ValueError`` if the script ends unbalanced or inside a quote."""
    out: list[tuple[int, bool]] = []
    depth = 0
    frames: list[list] = []  # ["S"] | ["D"] | ["C", paren_count]
    parens: list[tuple[bool, int]] = []  # (is_subshell, depth its ")" must see)
    heredoc_end: str | None = None
    heredoc_strip = False

    def in_code() -> bool:
        return not frames or frames[-1][0] == "C"

    for line in text.split("\n"):
        if heredoc_end is not None:
            out.append((depth, False))
            check = line.lstrip("\t") if heredoc_strip else line
            if check == heredoc_end:
                heredoc_end = None
            continue
        out.append((depth, in_code()))
        word = ""
        pending_heredoc: tuple[str, bool] | None = None
        i = 0
        n = len(line)

        def flush() -> None:
            nonlocal depth, word
            if word in _SH_OPENERS:
                depth += 1
            elif word in _SH_CLOSERS:
                depth -= 1
            word = ""

        while i < n:
            ch = line[i]
            top = frames[-1][0] if frames else "N"
            if top == "S":
                if ch == "'":
                    frames.pop()
                i += 1
                continue
            if top == "D":
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    frames.pop()
                elif line.startswith("$(", i):
                    flush()
                    frames.append(["C", 1])
                    i += 2
                    continue
                i += 1
                continue
            # code: top-level ("N") or inside a command substitution ("C")
            if ch == "\\":
                word += line[i:i + 2]
                i += 2
                continue
            if ch == "#" and word == "":
                break  # comment to end of line
            if ch == "'":
                frames.append(["S"])
                word += "'"
                i += 1
                continue
            if ch == '"':
                frames.append(["D"])
                word += '"'
                i += 1
                continue
            if line.startswith("$(", i):
                # The substitution's first word starts fresh (punch 526(c)):
                # gluing it to the prefix hid ``X=$(if`` while its ``fi`` counted.
                flush()
                frames.append(["C", 1])
                i += 2
                continue
            if top == "N" and ch == "(":
                subshell = word == ""
                flush()
                if subshell:
                    depth += 1
                parens.append((subshell, depth))
                i += 1
                continue
            if top == "N" and ch == ")":
                flush()
                if parens and parens[-1][1] == depth:
                    if parens.pop()[0]:
                        depth -= 1
                i += 1
                continue
            if top == "C" and ch == "(":
                frames[-1][1] += 1
            if top == "C" and ch == ")":
                frames[-1][1] -= 1
                if frames[-1][1] == 0:
                    flush()
                    frames.pop()
                    i += 1
                    continue
            if line.startswith("<<<", i):
                # A here-string, never a heredoc. Consume all three characters:
                # stepping one at a time left `<<"$1"` at i+1, which read as a
                # heredoc tagged `$1` that never closed (panel F r6, 2026-10-19).
                flush()
                i += 3
                continue
            if line.startswith("<<", i):
                flush()
                j = i + 2
                strip = j < n and line[j] == "-"
                if strip:
                    j += 1
                while j < n and line[j] in " \t":
                    j += 1
                k = j
                while k < n and line[k] not in _SH_DELIMS:
                    k += 1
                tag = line[j:k].strip("'\"")
                if tag:
                    pending_heredoc = (tag, strip)
                i = k
                continue
            if ch in _SH_DELIMS:
                flush()
                i += 1
                continue
            word += ch
            i += 1
        if in_code():
            flush()
        if pending_heredoc is not None:
            heredoc_end, heredoc_strip = pending_heredoc
    if depth != 0 or frames or parens or heredoc_end is not None:
        raise ValueError(
            f"shell_block_depths: script ends unbalanced (depth={depth}, "
            f"open frames={[f[0] for f in frames]}, open parens={len(parens)}, "
            f"heredoc={heredoc_end!r})"
        )
    return out


# ---------------------------------------------------------------------------
# Environment-variable read sites (punch 547 — PD-2 / PD-6).
#
# The ONE env-read scanner. Before punch 547 three pins each carried their own:
# N-465's ``_env_literals`` (``.environ.get`` / ``getenv`` with a literal key),
# ``test_health_build_endpoint._env_reads_in_code`` (a SUBSTRING scan of one
# function's source, blind after any later triple-quoted literal — 538 fold-check
# DA-FC4), and the census script. They converge here; the registry pin
# (``test_env_registry_pin.py``) and both older pins consume it.
#
# What counts as a site: every ``environ`` / ``environb`` mapping touch
# (``.get`` / ``.setdefault`` / ``.pop`` / ``[k]`` read, write or delete /
# ``k in`` / whole-mapping ``.copy()`` ``.items()`` ...), every ``getenv`` /
# ``putenv`` / ``unsetenv`` call, through ANY receiver name (``_os.environ``) and
# through ``from os import environ as E`` / ``getenv as g`` aliases. Anything
# else that references those names — ``e = os.environ``, ``getattr(os,
# "environ")``, a bare ``getenv`` passed as a value — is reported with shape
# ``"unrecognised"`` so a consuming pin can refuse it outright.
#
# Interprocedural (PD-2): a MODULE-LEVEL function whose env key is one of its
# own parameters is a helper (``_envbool.env_bool``). Every call to it anywhere
# in the scanned set becomes a site keyed at the caller's argument (by position
# or keyword), and a caller that passes its OWN parameter through becomes a
# helper in turn — run to a fixpoint, so helper-of-helper is followed.
#
# SCOPE (what a clean scan does NOT prove): methods are not propagated
# (``EnvSecrets.get(key)`` is reached through the SecretsProvider interface; its
# callers are the secret-read class, pinned by ``test_secret_read_funnel_pin``);
# a key smuggled through a dict/list or ``**kwargs`` is reported unresolved,
# never followed; env read INSIDE a third-party library (httpx ``trust_env``,
# pip's ``PIP_*``, OpenSSL ``SSL_CERT_FILE``) and interpreter-level env
# (``PYTHONPATH``, ``LD_PRELOAD``) are outside any AST of ours.
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dataclass

ENV_MAPPING_NAMES: frozenset[str] = frozenset({"environ", "environb"})
ENV_FUNC_NAMES: frozenset[str] = frozenset({"getenv", "getenvb", "putenv", "unsetenv"})
_ENV_KEYED_METHODS: frozenset[str] = frozenset({"get", "setdefault", "pop"})
_ENV_WHOLE_METHODS: frozenset[str] = frozenset(
    {"copy", "items", "keys", "values", "__iter__", "__contains__"}
)


@_dataclass(frozen=True)
class EnvSite:
    """One environment touch. ``key`` is the resolved literal (``None`` when it
    could not be resolved statically); ``param`` names the enclosing function's
    parameter the key flows from (a helper); ``shape`` is how the env is
    touched (``get`` / ``subscript`` / ``in`` / ``setdefault`` / ``pop`` /
    ``write`` / ``delete`` / ``whole`` / ``getenv`` / ``helper:<name>`` /
    ``unrecognised``)."""

    path: str
    qualname: str
    key: str | None
    param: str | None
    shape: str
    lineno: int


def _module_dotted(rel: str) -> str:
    parts = rel[:-3].split("/") if rel.endswith(".py") else rel.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["email_triage", *parts])


def module_str_consts(tree: ast.AST) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` / ``A = B = "literal"`` / ``NAME: str = "literal"``
    bindings, as ``{NAME: literal}``. The ONE reader of module string constants (punch 812: the
    publish reach check resolves a constant path tail through it; the settings-key catalog pin
    imports it, cycle P db P5-1). Every Name target of a chained assignment is read; a tuple
    target is not. A name rebound at runtime or assigned twice is last-wins."""
    consts: dict[str, str] = {}
    for stmt in getattr(tree, "body", []):
        if (isinstance(stmt, ast.Assign)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = stmt.value.value
        elif (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)):
            consts[stmt.target.id] = stmt.value.value
    return consts


def _os_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Local names bound to ``os.environ``-like mappings and ``os.getenv``-like
    functions by ``from os import ... [as ...]`` anywhere in the module."""
    mappings, funcs = set(ENV_MAPPING_NAMES), set(ENV_FUNC_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os" and not node.level:
            for a in node.names:
                if a.name in ENV_MAPPING_NAMES:
                    mappings.add(a.asname or a.name)
                elif a.name in ENV_FUNC_NAMES:
                    funcs.add(a.asname or a.name)
    return mappings, funcs


def enclosing_callable(node: ast.AST):
    """The nearest enclosing ``FunctionDef`` / ``AsyncFunctionDef`` / ``Lambda`` NODE, or None
    at module level: the scope a call runs in, where a lambda (handed to ``asyncio.to_thread``
    or ``tls.tls_connect``) is its own scope. Requires annotated parents (cycle P fold B)."""
    cur = getattr(node, "_ph_parent", None)
    while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        cur = getattr(cur, "_ph_parent", None)
    return cur


def _enclosing_def(node: ast.AST):
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = getattr(cur, "_ph_parent", None)
    return None


def outermost_enclosing_def(node: ast.AST):
    """The OUTERMOST enclosing ``FunctionDef`` / ``AsyncFunctionDef`` NODE of ``node`` (None at
    module level): a closure and the def that holds it share one answer, so a pin that asks "are
    these two calls in the same function" counts a call inside a nested def, or a lambda, as its
    definer's (census-r2 B5; a lambda is not a def). Requires annotated parents."""
    found = None
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found = cur
        cur = getattr(cur, "_ph_parent", None)
    return found


def _def_params(fn: ast.AST) -> list[str]:
    a = fn.args
    return [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]


def _resolve_env_key(expr: ast.AST | None, consts: dict[str, str], fn) -> tuple[str | None, str | None]:
    if expr is None:
        return None, None
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value, None
    if isinstance(expr, ast.Name):
        if fn is not None and expr.id in _def_params(fn):
            return None, expr.id
        if expr.id in consts:
            return consts[expr.id], None
    return None, None


def _is_mapping_ref(node: ast.AST, mappings: set[str]) -> bool:
    return ((isinstance(node, ast.Attribute) and node.attr in ENV_MAPPING_NAMES)
            or (isinstance(node, ast.Name) and node.id in mappings))


def _is_func_ref(node: ast.AST, funcs: set[str]) -> bool:
    return ((isinstance(node, ast.Attribute) and node.attr in ENV_FUNC_NAMES)
            or (isinstance(node, ast.Name) and node.id in funcs))


def _direct_env_sites(tree: ast.AST, rel: str) -> list[EnvSite]:
    consts = module_str_consts(tree)
    mappings, funcs = _os_aliases(tree)
    out: list[EnvSite] = []

    def add(node, key_expr, shape):
        fn = _enclosing_def(node)
        key, param = _resolve_env_key(key_expr, consts, fn)
        out.append(EnvSite(rel, enclosing_qualified_name(node), key, param, shape, node.lineno))

    for node in ast.walk(tree):
        par = getattr(node, "_ph_parent", None)
        if _is_mapping_ref(node, mappings):
            if isinstance(par, ast.Attribute) and par.value is node:
                gp = getattr(par, "_ph_parent", None)
                if isinstance(gp, ast.Call) and gp.func is par and par.attr in _ENV_KEYED_METHODS:
                    add(node, gp.args[0] if gp.args else None, par.attr)
                elif isinstance(gp, ast.Call) and gp.func is par and par.attr in _ENV_WHOLE_METHODS:
                    add(node, None, "whole")
                else:
                    add(node, None, "unrecognised")
            elif isinstance(par, ast.Subscript) and par.value is node:
                shape = {ast.Load: "subscript", ast.Store: "write", ast.Del: "delete"}[type(par.ctx)]
                add(node, par.slice, shape)
            elif (isinstance(par, ast.Compare) and node in par.comparators
                    and len(par.ops) == 1 and isinstance(par.ops[0], (ast.In, ast.NotIn))):
                add(node, par.left, "in")
            else:
                add(node, None, "unrecognised")
        elif _is_func_ref(node, funcs):
            if isinstance(par, ast.Call) and par.func is node:
                add(node, par.args[0] if par.args else None,
                    node.attr if isinstance(node, ast.Attribute) else "getenv")
            else:
                add(node, None, "unrecognised")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("getattr", "hasattr") and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in (ENV_MAPPING_NAMES | ENV_FUNC_NAMES)):
            add(node, None, "unrecognised")
    return out


def _import_bindings(tree: ast.AST, rel: str, target_dotted: str, fn_name: str) -> tuple[set[str], set[str]]:
    """Names in ``tree`` bound to ``target_dotted.fn_name`` (direct) and names
    bound to the ``target_dotted`` module itself (for ``mod.fn_name(...)``)."""
    direct, modules = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            full = import_from_module(node, rel)  # the ONE relative-import resolver (punch 672)
            for a in node.names:
                if full == target_dotted and a.name == fn_name:
                    direct.add(a.asname or a.name)
                elif f"{full}.{a.name}" == target_dotted:
                    modules.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == target_dotted and a.asname:
                    modules.add(a.asname)
    return direct, modules


def scan_env_reads(modules: list[tuple[str, ast.AST]]) -> list[EnvSite]:
    """Every env site in ``modules`` (``(relpath, annotated tree)`` pairs):
    direct touches plus helper-resolved caller sites, to a fixpoint. Pure over
    its input, so a teeth test can feed planted modules."""
    sites: list[EnvSite] = []
    trees = dict(modules)
    for rel, tree in modules:
        sites.extend(_direct_env_sites(tree, rel))
    frontier = [s for s in sites if s.param is not None]
    seen: set[tuple[str, str, str]] = set()
    while frontier:
        nxt: list[EnvSite] = []
        for s in frontier:
            if "." in s.qualname or s.qualname == "<module>":
                continue  # methods / nested defs are not propagated (SCOPE)
            ident = (s.path, s.qualname, s.param)
            if ident in seen:
                continue
            seen.add(ident)
            fdef = next((n for n in getattr(trees[s.path], "body", [])
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and n.name == s.qualname), None)
            if fdef is None:
                continue
            params = _def_params(fdef)
            idx = params.index(s.param)
            target = _module_dotted(s.path)
            for rel, tree in modules:
                consts = module_str_consts(tree)
                direct, mods = _import_bindings(tree, rel, target, s.qualname)
                if rel == s.path:
                    direct.add(s.qualname)
                for call in ast.walk(tree):
                    if not isinstance(call, ast.Call):
                        continue
                    f = call.func
                    hit = ((isinstance(f, ast.Name) and f.id in direct)
                           or (isinstance(f, ast.Attribute) and f.attr == s.qualname
                               and isinstance(f.value, ast.Name) and f.value.id in mods))
                    if not hit:
                        continue
                    arg = call.args[idx] if idx < len(call.args) else next(
                        (k.value for k in call.keywords if k.arg == s.param), None)
                    fn = _enclosing_def(call)
                    key, param = _resolve_env_key(arg, consts, fn)
                    site = EnvSite(rel, enclosing_qualified_name(call), key, param,
                                   f"helper:{s.qualname}", call.lineno)
                    sites.append(site)
                    if param is not None:
                        nxt.append(site)
        frontier = nxt
    return sites


@lru_cache(maxsize=1)
def _env_read_sites_cached() -> tuple[EnvSite, ...]:
    return tuple(scan_env_reads([(rel, tree) for _p, rel, tree in walk_src()]))


def env_read_sites() -> list[EnvSite]:
    """Every environment touch under ``src/email_triage`` (see the section
    comment above for what is and is not covered)."""
    return list(_env_read_sites_cached())


# ---------------------------------------------------------------------------
# Intra-module call reachability (punch 594 / 485, PD-2 / PD-6).
#
# A funnel pin must follow the value through helpers: "every range check
# reaches the net chooser" is false-green if the pin only looks at direct
# calls. Two pins already hand-roll this fixpoint (test_582_audit_loss_trace_pin
# `reachers`, test_n543_deleter_before_witness_pin `_fixpoint`); new pins use
# this one. SCOPE: by NAME, within one module: a Name call, an Attribute call's
# attr, and (census-r2 B1) the
# callee a dispatcher hands off (``db_call(f, ..)``, ``to_thread(partial(f, ..))``,
# ``loop.run_in_executor(None, f)``, ``db_call(lambda: f(..))``: :func:`hop_target`).
# It does not follow cross-module calls, calls through a variable, or a callable
# passed to anything that is not a :data:`HOP_DISPATCHERS` / :data:`EXECUTOR_HOPS`
# name (``Thread(target=f)``, ``executor.submit(f)``, ``add_done_callback(f)``).
# A lambda's body counts only when the lambda is an argument of a dispatcher call
# (``db_call(lambda: f(); g())``): a stored lambda is not a call. Two defs of one name are ONE
# name here (their call sets union); to keep them apart use :func:`reach_closure`,
# which keys every def by module and qualified name.
# ---------------------------------------------------------------------------


def _own_call_names(fn: ast.AST, dispatchers: "frozenset[str] | None" = None) -> set[str]:
    out: set[str] = set()
    disp = HOP_DISPATCHERS if dispatchers is None else dispatchers
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue  # a stored lambda is not a call; a dispatcher's lambda argument is pushed below
        if isinstance(n, ast.Call):
            out |= call_callee_names(n, disp)
            if call_name(n) in disp or call_name(n) in EXECUTOR_HOPS:
                stack.extend(a.body for a in n.args if isinstance(a, ast.Lambda))
        stack.extend(ast.iter_child_nodes(n))
    return out


def reachers_of(tree: ast.AST, target: str, *, dispatchers: "frozenset[str] | None" = None) -> set[str]:
    """Names of the defs in ``tree`` that call ``target``, directly, through a dispatcher hop, or
    through another def of the same module, to a fixpoint. Defs are tracked one by one, so a second
    def of the same name adds its calls instead of replacing the first's; the answer is the set of
    their names."""
    fns = [fn for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
    calls = [_own_call_names(fn, dispatchers) for fn in fns]
    reach = {i for i, c in enumerate(calls) if target in c}
    changed = True
    while changed:
        changed = False
        names = {fns[i].name for i in reach}
        for i, c in enumerate(calls):
            if i not in reach and c & names:
                reach.add(i)
                changed = True
    return {fns[i].name for i in reach}


# ---------------------------------------------------------------------------
# "A name interpolated into a persisted message" -- ONE funnel, two name sets
# (punch 595 / N-475 widen, PD-5 / PD-6).
#
# ``record.getMessage()`` is hashed and persisted into ``log_entries.message``
# with no scrub of any kind (only ``extra`` is redacted), and an exception's
# text reaches ``log_entries.error`` / ``audit_gap_events.exc_msg`` through
# ``redact_exc`` alone. A value already interpolated into that text cannot be
# removed afterwards. The N-475 pin keys this on PHI_NAMES; the punch-595 pin
# keys it on SECRET_TOKEN_KEYS. Both consume this one detector so the four
# interpolation shapes cannot drift apart between them.
#
# Shapes: f-string, ``"..." % x``, ``"..." + x``, ``"...".format(x)``; with
# ``printf_args=True`` also the positional args a logger %-formats into the
# message (``log.info("... %s", x)``) -- TriageLogger's N-338 gate redacts those
# only in HIPAA mode. SCOPE: a value rebound to an unrelated name, or carried in
# a dict, is not followed; a name-keyed net over source is a floor.
# ---------------------------------------------------------------------------

LOG_EMIT_METHODS: frozenset[str] = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
})


def interpolation_bearers(expr: ast.AST) -> set[str]:
    """Names a value expression contributes: an Attribute contributes its
    ATTRIBUTE (``msg.subject`` -> ``subject``), a Name only when it is not an
    attribute receiver (so ``body.role`` does not score ``body``)."""
    receivers = {
        sub.value for sub in ast.walk(expr)
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
    }
    out: set[str] = set()
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Attribute):
            out.add(sub.attr)
        elif isinstance(sub, ast.Name) and sub not in receivers:
            out.add(sub.id)
    return out


def _is_str_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
            and (_is_str_literal(node.left) or _is_str_literal(node.right)))


def interpolated_names(expr: ast.AST | None) -> set[str]:
    """Every name interpolated into the string ``expr`` builds, across the
    four shapes. Empty for a plain literal or a non-string expression."""
    if expr is None:
        return set()
    if isinstance(expr, ast.JoinedStr):
        names: set[str] = set()
        for part in expr.values:
            if isinstance(part, ast.FormattedValue):
                names |= interpolation_bearers(part.value)
        return names
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod) and _is_str_literal(expr.left):
        return interpolated_names(expr.left) | interpolation_bearers(expr.right)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add) and _is_str_literal(expr):
        names = set()
        for side in (expr.left, expr.right):
            names |= (interpolated_names(side) if _is_str_literal(side)
                      else interpolation_bearers(side))
        return names
    if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format" and _is_str_literal(expr.func.value)):
        names = interpolated_names(expr.func.value)
        for a in [*expr.args, *(k.value for k in expr.keywords)]:
            names |= interpolation_bearers(a)
        return names
    return set()


def log_message_arg(call: ast.Call) -> ast.expr | None:
    """The argument that becomes the persisted message (``.log`` takes the
    level first), or None when ``call`` is not a log emit."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr in LOG_EMIT_METHODS):
        return None
    idx = 1 if call.func.attr == "log" else 0
    return call.args[idx] if len(call.args) > idx else None


def message_interpolation_offenders(
    tree: ast.AST, names: frozenset[str], *, printf_args: bool = False,
) -> list[tuple[int, str, str]]:
    """(lineno, kind, hit-names) for every raise / log message in ``tree`` that
    interpolates a name in ``names``."""
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            hit: set[str] = set()
            # Every subnode: interpolated_names is set() for a non-string node,
            # and a filter here hid the `%` BinOp shape (panel B3 DA F1).
            for sub in ast.walk(node.exc):
                hit |= interpolated_names(sub) & names
            if hit:
                found.append((node.lineno, "raise", ",".join(sorted(hit))))
        if isinstance(node, ast.Call):
            msg = log_message_arg(node)
            if msg is None:
                continue
            hit = interpolated_names(msg) & names
            if printf_args:
                idx = 2 if node.func.attr == "log" else 1  # type: ignore[union-attr]
                for a in node.args[idx:]:
                    hit |= interpolation_bearers(a) & names
            if hit:
                found.append((node.lineno, f".{node.func.attr}", ",".join(sorted(hit))))  # type: ignore[union-attr]
    return found


# ---------------------------------------------------------------------------
# Punch 672 (PD-2, PD-6): ONE resolver for the callee a dispatcher hands off.
# N-520's `resolve`, the secret-write scanner and the punch-627 call-site pin each
# read a dispatcher's first argument their own way (ast.Name only, or Name and
# Attribute), and none unwrapped `lambda: f(..)`, `functools.partial(f, ..)` or
# `loop.run_in_executor(None, f, ..)`, so a funnel reached that way was a false green.
# Resolving the NAME is this resolver's job; following an import or deciding whether
# the callee is local is the consumer's.
# ---------------------------------------------------------------------------

#: Off-loop dispatchers whose FIRST positional argument is the callee they run.
HOP_DISPATCHERS: frozenset[str] = frozenset({
    "db_call", "db_call_async", "run_in_threadpool", "to_thread",
})
#: Dispatchers whose callee is a LATER positional argument (the executor comes first).
EXECUTOR_HOPS: dict[str, int] = {"run_in_executor": 1}
#: Wrappers that bind leading arguments onto a callable (`functools.partial(f, a)`).
_PARTIAL_WRAPPERS = frozenset({"partial"})


def call_name(call: ast.Call) -> str | None:
    """The called name: ``f(..)`` -> ``f``, ``a.b.f(..)`` -> ``f``."""
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def callee_ref(expr: ast.AST) -> str | None:
    """The name a callee expression refers to: ``f`` -> ``f``, ``self.f`` / ``mod.f`` -> ``f``."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


@_dataclass(frozen=True)
class HopTarget:
    """What a dispatched call really runs: the callee expression (an ``ast.Name`` or
    ``ast.Attribute``) and the arguments it receives."""

    callee: ast.expr
    args: tuple
    keywords: tuple

    @property
    def name(self) -> str | None:
        return callee_ref(self.callee)


def unwrap_callable(expr: ast.AST, args=(), keywords=()) -> HopTarget | None:
    """``expr`` as the callable it runs, through ``partial(f, ..)`` and ``lambda: f(..)``.

    A partial's bound arguments come before ``args``; a lambda's body call supplies its
    own arguments (the lambda's parameters are not tracked). None when the callable is
    anything else (a subscript, a call result, a lambda whose body is not one call)."""
    for _ in range(8):  # nesting bound; real code is 1-2 deep
        if isinstance(expr, (ast.Name, ast.Attribute)):
            return HopTarget(expr, tuple(args), tuple(keywords))
        if isinstance(expr, ast.Call) and call_name(expr) in _PARTIAL_WRAPPERS and expr.args:
            args = (*expr.args[1:], *args)
            keywords = (*expr.keywords, *keywords)
            expr = expr.args[0]
            continue
        if isinstance(expr, ast.Lambda) and isinstance(expr.body, ast.Call):
            args, keywords, expr = expr.body.args, expr.body.keywords, expr.body.func
            continue
        return None
    return None


def hop_target(call: ast.AST, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> HopTarget | None:
    """The callee a dispatcher call hands off, or None when ``call`` is not a hop.

    ``db_call(f, a)``, ``db_call(self.f, a)``, ``db_call(lambda: f(a))``,
    ``to_thread(partial(f, a))`` and ``loop.run_in_executor(None, f, a)`` all answer
    ``f`` with the arguments it receives. An ``await`` around the call is looked through.

    A ``Starred`` callable argument (``db_call(*args)``) answers None, and consumers read
    None as "not a hop": a callee unpacked from a sequence is invisible to every pin built
    on this resolver (accepted, panel Z db NOTE-Z2-7).
    """
    if isinstance(call, ast.Await):
        call = call.value
    if not isinstance(call, ast.Call):
        return None
    idx = dispatched_slot(call, dispatchers)
    if idx is None:
        return None
    return unwrap_callable(call.args[idx], call.args[idx + 1:], call.keywords)


def dispatched_slot(call: ast.Call, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> int | None:
    """Where in ``call.args`` a dispatcher call keeps the callable it hands off (``0`` for
    ``db_call(f, a)``, ``1`` for ``run_in_executor(None, f, a)``), else None: not a dispatcher call,
    or the callable argument is missing or ``Starred``. The ONE reader of "is this a hop" behind
    :func:`hop_target` and :class:`CallGraph`'s unresolved-hop report, which needs the raw callable
    when :func:`unwrap_callable` cannot name it (``db_call(table[k], v)``)."""
    name = call_name(call)
    if name in EXECUTOR_HOPS:  # first, so a caller's set naming it cannot read the executor
        idx = EXECUTOR_HOPS[name]
    elif name in dispatchers:
        idx = 0
    else:
        return None
    if len(call.args) <= idx or isinstance(call.args[idx], ast.Starred):
        return None
    return idx


def call_callee_names(call: ast.Call, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> set[str]:
    """Every name ``call`` calls: the direct callee (``f(..)``, ``x.f(..)``)
    and, for a dispatcher call, the callee it hands off (:func:`hop_target`). ``db_call(f, a)``
    answers ``{"db_call", "f"}``. The ONE per-call name reader behind ``reachers_of``,
    :func:`call_sites` and the :func:`reach_closure` name targets (census-r2 B1 / B5)."""
    out: set[str] = set()
    name = callee_ref(call.func)
    if name:
        out.add(name)
    hop = hop_target(call, dispatchers)
    if hop is not None and hop.name:
        out.add(hop.name)
    return out


def call_args_of(node: ast.AST, name: str, dispatchers: frozenset[str] = HOP_DISPATCHERS):
    """``(args, keywords)`` that callee ``name`` receives when ``node`` calls it directly or hands it
    to a dispatcher (the dispatcher's own arguments are not the callee's: for ``db_call(f, a, k=1)``
    the answer for ``f`` is ``((a,), (k=1,))``), else None. The shape several pins hand-rolled:
    "is this a call of NAME, and which keywords does it pass" (census-r2 B5)."""
    if not isinstance(node, ast.Call):
        return None
    if callee_ref(node.func) == name:
        return tuple(node.args), tuple(node.keywords)
    hop = hop_target(node, dispatchers)
    if hop is not None and hop.name == name:
        return tuple(hop.args), tuple(hop.keywords)
    return None


def is_call_of(node: ast.AST, name: str, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> bool:
    """True when ``node`` is a Call that calls ``name`` directly or hands it to a dispatcher."""
    return call_args_of(node, name, dispatchers) is not None


def call_sites(tree: ast.AST, name: str, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> list[ast.Call]:
    """Every Call in ``tree`` that calls ``name`` (``f(..)``, ``x.f(..)``) or hands it to a
    dispatcher (``db_call(f, ..)``, ``to_thread(partial(f, ..))``,
    ``db_call(lambda: f(..))``, ``run_in_executor(None, f)``). For a hop the DISPATCHER call is the
    site. SCOPE: by name, so any receiver matches and two defs of one name are one name; it does
    not follow a callable stored in a variable, a dict or an attribute. Use it where a pin used to
    loop ``ast.walk`` for ``Call`` nodes of one name (census-r2 B5)."""
    return [n for n in ast.walk(tree) if is_call_of(n, name, dispatchers)]


# ---------------------------------------------------------------------------
# Punch 672 (PD-2, PD-6): the cross-module half of the hop resolver.
# `hop_target` names the callee a dispatcher hands off; THIS answers which function
# in which OTHER module that name is. The secret-write scanner used to follow only
# helpers defined in the file it was reading, so a form value handed to a helper in
# another module (`db_call(_save_provider_secret, form, ...)`, the helper living in
# `ui/_shared.py`) was invisible: a false green on a clobber class.
#
# Three ways a module reaches a name defined elsewhere in this tree, all resolved:
#   * `from .b import f [as g]`             -> the module-level `def f` in b;
#   * `from . import b` / `import x.y.b as b`, then `b.f(..)`;
#   * `globals().update({n: v for n, v in vars(b).items()})` (the `web/routers/ui`
#     concern files snapshot `_shared` this way, so a bare `f(..)` resolves with NO
#     import statement naming it; an import-only resolver cannot see the live route).
# Census-r2 B3 (one resolver, extended in place): a name `b` merely RE-EXPORTS
# (`from .a import f` in b, then `from .b import f` in c) is chased through up to
# REEXPORT_DEPTH further modules.
# SCOPE: module-level `def`s only; a re-export chain longer than REEXPORT_DEPTH, a star
# import and a name rebound at run time are invisible (the
# resolver answers None for all of them: it cannot tell "not a function" from "too deep").
# Pure over its input, so a teeth test can feed planted modules.
# ---------------------------------------------------------------------------

#: How many modules past the caller's own import a re-exported name is chased through. Measured
#: 2026-11-05 over all of src: depth 1 -> 2 adds 34 call edges (`cli.py` etc. reach
#: `providers/factory.py` through the `web/routers/ui` snapshot of `_shared`, which re-imports
#: it); depth 2 -> 3 and 3 -> 4 add none. A deeper bound with no live site is slack, so it is 2.
REEXPORT_DEPTH = 2


def import_from_module(node: ast.ImportFrom, rel: str) -> str:
    """The dotted module an ``ImportFrom`` in ``rel`` (a ``SRC_ROOT``-relative path) names,
    relative levels resolved against the file's own package."""
    if not node.level:
        return node.module or ""
    here = _module_dotted(rel).split(".")
    pkg = here if rel.endswith("__init__.py") else here[:-1]
    base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
    return ".".join([*base, *(node.module.split(".") if node.module else [])])


def _is_globals_update(node: ast.AST) -> bool:
    """``globals().update(..)``: the namespace-snapshot idiom."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update" and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name) and node.func.value.func.id == "globals")


class CrossModuleResolver:
    """Which module-level function in ``modules`` (``{relpath: tree}``) a callee expression used
    in module ``rel`` names, when that function lives in a DIFFERENT module."""

    def __init__(self, modules: "dict[str, ast.AST]") -> None:
        self._by_dotted = {_module_dotted(rel): rel for rel in modules}
        self._defs = {
            rel: {n.name for n in getattr(tree, "body", [])
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for rel, tree in modules.items()
        }
        # Every import binding, whether or not the module it names defines the name: a name
        # that module merely re-exports is chased by `_member`. ("mod", rel) or ("name", rel, n).
        self._imports: dict[str, dict[str, tuple]] = {}
        #: local names an import binds to a module OUTSIDE ``modules`` (``import bcrypt``,
        #: ``from json import dumps``): what proves a hop runs no def of the set
        self._outside: dict[str, set[str]] = {}
        self._snapshots: dict[str, list[str]] = {}
        self._fallbacks: dict[str, list[str]] = {}
        for rel, tree in modules.items():
            binds: dict[str, tuple] = {}
            outside: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    full = import_from_module(node, rel)
                    for a in node.names:
                        local = a.asname or a.name
                        if f"{full}.{a.name}" in self._by_dotted:
                            binds[local] = ("mod", self._by_dotted[f"{full}.{a.name}"])
                        elif full in self._by_dotted and a.name != "*":
                            binds[local] = ("name", self._by_dotted[full], a.name)
                        elif a.name != "*":
                            outside.add(local)
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        if a.asname and a.name in self._by_dotted:
                            binds[a.asname] = ("mod", self._by_dotted[a.name])
                        elif a.asname:
                            outside.add(a.asname)
                        elif not any(d == a.name.split(".")[0] or d.startswith(a.name.split(".")[0] + ".")
                                     for d in self._by_dotted):
                            outside.add(a.name.split(".")[0])  # `import x.y` binds `x`
            self._imports[rel] = binds
            self._outside[rel] = outside
            self._snapshots[rel] = [
                binds[arg.id][1]
                for call in ast.walk(tree) if _is_globals_update(call)
                for sub in ast.walk(call)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "vars" and len(sub.args) == 1
                for arg in sub.args if isinstance(arg, ast.Name) and binds.get(arg.id, ("",))[0] == "mod"
            ]
        for rel, tree in modules.items():
            self._fallbacks[rel] = self._getattr_fallbacks(rel, tree)

    def _getattr_fallbacks(self, rel: str, tree: ast.AST) -> list[str]:
        """The modules a PEP 562 ``__getattr__`` of module ``rel`` falls back to, in the order it tries
        them. Read from the AST of the ``__getattr__`` def (a module-level def, or the method of the
        module subclass ``web/routers/ui/__init__.py`` installs): a module alias it asks with
        ``hasattr(<alias>, name)`` / ``getattr(<alias>, name)``, and each module a
        ``for m in <CONST>: import_module(m, ..)`` loop names, ``<CONST>`` being a module-level tuple or
        list of strings (a leading ``.`` is relative to the package)."""
        out: list[str] = []
        consts: dict[str, list[str]] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Tuple, ast.List)) \
                    and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.value.elts):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        consts[t.id] = [e.value for e in node.value.elts]
        package = _module_dotted(rel) if rel.endswith("__init__.py") else _module_dotted(rel).rpartition(".")[0]
        for fn in ast.walk(tree):
            if not (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name == "__getattr__"):
                continue
            asked: list[tuple[int, int, list[str]]] = []  # (line, column, modules): the order it tries them
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                        and node.func.id in ("hasattr", "getattr") and node.args \
                        and isinstance(node.args[0], ast.Name):
                    bound = self._imports[rel].get(node.args[0].id)
                    if bound is not None and bound[0] == "mod":
                        asked.append((node.lineno, node.col_offset, [bound[1]]))
                elif isinstance(node, ast.For) and isinstance(node.iter, ast.Name) \
                        and isinstance(node.target, ast.Name) and node.iter.id in consts \
                        and any(isinstance(c, ast.Call) and call_name(c) == "import_module"
                                and c.args and isinstance(c.args[0], ast.Name) and c.args[0].id == node.target.id
                                for c in ast.walk(node)):
                    named = (f"{package}{text}" if text.startswith(".") else text for text in consts[node.iter.id])
                    asked.append((node.lineno, node.col_offset,
                                  [self._by_dotted[d] for d in named if d in self._by_dotted]))
            for _line, _col, mods in sorted(asked, key=lambda a: a[:2]):
                out.extend(m for m in mods if m not in out)
        return out

    def _member(self, rel: str, name: str, hops: int) -> "tuple | None":
        """What ``name`` is as a member of module ``rel``: ``("def", rel, name)`` for its own
        module-level ``def``, ``("mod", rel)`` for a module it imported, or whatever an import or a
        ``vars(mod)`` snapshot or a PEP 562 ``__getattr__`` fallback it holds leads to, chased through
        at most ``hops`` more modules."""
        if name in self._defs[rel]:
            return ("def", rel, name)
        if hops <= 0:
            return None
        bound = self._imports[rel].get(name)
        if bound is not None:
            return bound if bound[0] == "mod" else self._member(bound[1], bound[2], hops - 1)
        for snap in self._snapshots[rel]:
            found = self._member(snap, name, hops - 1)
            if found is not None:
                return found
        for fallback in self._fallbacks[rel]:  # PEP 562 ``__getattr__``, after everything bound
            found = self._member(fallback, name, hops - 1)
            if found is not None:
                return found
        return None

    def resolve(self, rel: str, callee: ast.AST) -> "tuple[str, str] | None":
        """``(defining module, function name)`` for ``callee`` used in ``rel``, else None.
        The caller checks ``rel``'s OWN definitions first: a local ``def`` shadows an import and a
        snapshot, as at run time."""
        found = None
        if isinstance(callee, ast.Name):
            bound = self._imports.get(rel, {}).get(callee.id)
            if bound is not None and bound[0] == "name":
                found = self._member(bound[1], bound[2], REEXPORT_DEPTH)
            if found is None:
                for snap in self._snapshots.get(rel, ()):
                    found = self._member(snap, callee.id, REEXPORT_DEPTH)
                    if found is not None:
                        break
        elif isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            bound = self._imports.get(rel, {}).get(callee.value.id)
            if bound is not None and bound[0] == "name":
                bound = self._member(bound[1], bound[2], REEXPORT_DEPTH)  # a module re-exported
            if bound is not None and bound[0] == "mod":
                found = self._member(bound[1], callee.attr, REEXPORT_DEPTH)
        if found is not None and found[0] == "def":
            return found[1], found[2]
        return None


# ---------------------------------------------------------------------------
# Census round 2, class B (T8): reach and taint over the hop resolver.
#
# ONE reader of "which def does this call reach": `CallGraph`. It joins `hop_target` (the
# callee a dispatcher hands off), `CrossModuleResolver` (a callee in another module) and a
# lexical lookup for a callee in THIS module, and keys every def by (module rel, QUALIFIED
# name), never a bare name: a bare-name closure merged every `_work` nested in every endpoint
# (round 1: a 408-name closure grew to 2530). Two fixpoints consume it and differ in what they
# propagate, not in how a call resolves:
#   * `reach_closure` / `CallGraph.reach`: which defs reach a target (reachability);
#   * `param_taint_fixpoint`: which parameters receive a tainted value (taint).
#
# SCOPE, shared by both (what NO helper here follows; the census seat names the hop it needs
# that is not on this list before it writes a throwaway detector):
#   * an attribute call is followed only on a module alias (`mod.f(..)`),
#     on `self` / `cls` (the lexical class's method, else a same-named method of the module: an
#     inheritance guess), and, with `loose_receivers=True`, on ANY receiver (`obj.f`, or `mod.f` with
#     `mod` not an import the resolver knows) when the name has exactly ONE def, a method or a
#     module-level def, in the whole module set. A call or a dispatcher hop on a receiver of unknown
#     type is otherwise never followed and never fanned out to every same-named def: it is recorded in
#     `CallGraph.ambiguous_edges` (and counted in `ReachSet.ambiguous_edges`) with its candidates, and
#     `param_taint_fixpoint` reports the ones that carry a derived value (`TaintResult.unresolved`);
#   * a dispatcher hop the graph cannot name a def for is recorded in `CallGraph.unresolved_hops`
#     (an `UnresolvedHop`) and reported the same way, never read as "does not reach": a callable that
#     is a subscript or a call result (`db_call(table[k], v)`, `db_call(make(), v)`, a constant
#     `getattr(obj, "f")`), a name an import of the module set binds that resolves to no def (a
#     re-export chain past REEXPORT_DEPTH, or not a def), a bare name no import binds (a callable
#     held in a parameter or a local, or a builtin), `self.f` / `cls.f` with no method `f` in the
#     module (an inherited method), and `mod.f` on a module-set import with no def `f`. NOT recorded:
#     a hop whose callee's root name is an import of a module OUTSIDE the set (`bcrypt.hashpw`,
#     `from json import dumps`), read from the resolver's import table (`_outside`; no name list),
#     and an unknown receiver (`obj.f`), whose defs of the name `_targets` already weighed;
#   * the callable must be a Name or an attribute (through `partial` and `lambda`) handed to
#     HOP_DISPATCHERS / EXECUTOR_HOPS; `Thread(target=f)`,
#     `executor.submit(f)`, `add_done_callback(f)`, `Depends(f)`, a callable kept in a dict,
#     list or attribute, and `db_call(*fns)` are not hops;
#   * only defs are nodes: a class construction (`Cls(..)` -> `__init__`), a property, a dunder
#     operator, a decorator wrapper and a subclass override are not edges;
#   * a parameter or local that shadows a def's name is not tracked (the def wins);
#   * a hop call is an edge to the callee it hands off, not also to the dispatcher's own def (the
#     dispatcher's NAME is still a name target); two defs of one qualified name (a conditional
#     redefinition) are one node.
# ---------------------------------------------------------------------------

from dataclasses import field as _field  # noqa: E402
from typing import NamedTuple as _NamedTuple  # noqa: E402

#: The scope key of statements outside any def (module and class bodies).
MODULE_SCOPE = "<module>"
#: A closure past this many (module, def) nodes stops with an error: a bound, never a silent cap.
#: Measured 2026-11-05 over src at 7aa4d534 (3847 defs): round 1's 30 db_call exception-edge targets
#: reach 74-80 defs, its six `*_txn` emitters 487-490, both together 506-514 (round 1: 408 guarded,
#: 2530 unguarded). The bound is about twice the largest legitimate closure and well under the
#: module set, so an unguarded blow-up trips it.
REACH_NODE_BOUND = 1000
_RECEIVER = ast.Constant(None)  # stands in for the bound receiver in a method call's arguments


@_dataclass
class _Scope:
    qual: str
    nodes: list = _field(default_factory=list)  # the def node(s) of this name
    parent: "str | None" = None  # the enclosing def's qualified name (None at module level)
    cls: "str | None" = None  # the class whose body this def sits directly in
    calls: list = _field(default_factory=list)  # Calls the scope's own body runs (a lambda's body is its definer's)
    bound: dict = _field(default_factory=dict)  # {bare name: qual} defs bound directly in this scope


class _ModuleScopes:
    """The scopes of ONE parsed module: every def keyed by qualified name (the class and def
    names above it joined with ``.``, as :func:`enclosing_qualified_name` writes them), the calls
    each scope's own body makes, and the lexical bindings that resolve a bare name."""

    def __init__(self, tree: ast.AST) -> None:
        self.scopes: dict[str, _Scope] = {MODULE_SCOPE: _Scope(MODULE_SCOPE, nodes=[tree])}
        self.classes: dict[str, dict[str, str]] = {}
        self.methods: dict[str, list[str]] = {}
        stack = [(tree, (), MODULE_SCOPE, None)]
        while stack:
            node, path, owner, cls = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = ".".join((*path, node.name))
                scope = self.scopes.get(qual)
                if scope is None:
                    parent = None if owner == MODULE_SCOPE else owner
                    scope = self.scopes[qual] = _Scope(qual, parent=parent, cls=cls)
                scope.nodes.append(node)
                if cls is not None:
                    self.classes[cls][node.name] = qual
                    if qual not in self.methods.setdefault(node.name, []):
                        self.methods[node.name].append(qual)
                else:
                    self.scopes[owner].bound[node.name] = qual
                a = node.args
                outside = [*node.decorator_list, *a.defaults, *(d for d in a.kw_defaults if d is not None)]
                stack.extend((c, path, owner, cls) for c in outside)  # read in the enclosing scope
                stack.extend((c, (*path, node.name), qual, None) for c in node.body)
            elif isinstance(node, ast.ClassDef):
                cqual = ".".join((*path, node.name))
                self.classes.setdefault(cqual, {})
                outside = [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]
                stack.extend((c, path, owner, cls) for c in outside)
                stack.extend((c, (*path, node.name), owner, cqual) for c in node.body)
            else:
                if isinstance(node, ast.Call):
                    self.scopes[owner].calls.append(node)
                stack.extend((c, path, owner, cls) for c in ast.iter_child_nodes(node))

    def lookup(self, scope: str, name: str) -> "str | None":
        """The def a bare ``name`` called from ``scope`` binds to: LEGB, so a def bound in the scope
        or an enclosing def first, then module level. A class body is skipped, as in Python."""
        q = scope
        while True:
            sc = self.scopes[q]
            if name in sc.bound:
                return sc.bound[name]
            if q == MODULE_SCOPE:
                return None
            q = sc.parent or MODULE_SCOPE

    def class_of(self, scope: str) -> "str | None":
        """The qualified class a ``self`` / ``cls`` in ``scope`` belongs to (a closure inside a
        method reads the method's), else None."""
        q = scope
        while q != MODULE_SCOPE:
            sc = self.scopes[q]
            if sc.cls:
                return sc.cls
            q = sc.parent or MODULE_SCOPE
        return None


def scope_key(node: ast.AST) -> str:
    """The qualified key of the scope that runs ``node``, in the form :class:`CallGraph` uses: a def
    node answers its own key, any other node its nearest enclosing def's, :data:`MODULE_SCOPE` when
    none (a decorator or a default reads as the decorated def). Requires annotated parents
    (:func:`parse_module` / :func:`parse_source` / :func:`annotate_parents`)."""
    chain: list = []
    cur = node
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            chain.append(cur)
        cur = getattr(cur, "_ph_parent", None)
    chain.reverse()
    last = max((i for i, c in enumerate(chain) if not isinstance(c, ast.ClassDef)), default=None)
    return MODULE_SCOPE if last is None else ".".join(c.name for c in chain[: last + 1])


def call_site(call: ast.Call, dispatchers: frozenset[str] = HOP_DISPATCHERS):
    """``(callee expression, arguments it receives, keywords)`` for ``call``: the callee a dispatcher
    hands off for a hop, else the call's own callee. The ONE reader of "what does this call run" behind :class:`CallGraph`,
    :func:`forwarder_edges` and :func:`call_args_of`; the callee expression may be anything (a
    subscript, a call result), so ask :func:`callee_ref` for its name."""
    hop = hop_target(call, dispatchers)
    if hop is not None:
        return hop.callee, tuple(hop.args), tuple(hop.keywords)
    return call.func, tuple(call.args), tuple(call.keywords)


def forwarder_edges(tree: ast.AST, dispatchers: frozenset[str] = HOP_DISPATCHERS) -> set[tuple[str, str]]:
    """``(forwarder's qualified name, callee name)`` for every call that carries NOTHING but its
    enclosing def's own ``*args`` / ``**kwargs``: ``def f(*a, **k): return g(*a, **k)`` yields
    ``("f", "g")``, and so does ``return await db_call(g, *a, **k)``. A pin keyed on the callee name
    ``g`` sees ``f``'s callers only if it also keys on ``f``: this is how it learns ``f`` (census-r2
    B6; :func:`pass_through_calls` exempts only a forwarder NAMED like the funnel). SCOPE: names, one
    module, a direct or hop call; a forwarder that adds an argument is not one, and this gives edges,
    not the transitive set (``reach_closure(.., forwarders_only=True)`` chases forwarders of
    forwarders)."""
    out: set[tuple[str, str]] = set()
    for qual, sc in _ModuleScopes(tree).scopes.items():
        if qual == MODULE_SCOPE:
            continue
        for call in sc.calls:
            expr, args, kws = call_site(call, dispatchers)
            name = callee_ref(expr)
            if name and any(carries_only_own_splats(args, kws, fn) for fn in sc.nodes):
                out.add((qual, name))
    return out


@_dataclass(frozen=True)
class CallEdge:
    """One call that reaches a def in the module set. ``args`` / ``keywords`` are what the callee
    receives (for a bound method a placeholder ``None`` comes first, standing for the receiver, so
    positions line up with the callee's parameters)."""

    caller: tuple  # (module rel, qualified name of the scope that makes the call)
    callee: tuple  # (module rel, qualified name of the def reached)
    call: ast.Call
    args: tuple
    keywords: tuple
    forwarder: bool  # the call carries only its caller's own *args / **kwargs


class ReachBoundExceeded(RuntimeError):
    """A closure reached more nodes than the bound the caller allowed."""


@_dataclass(frozen=True)
class AmbiguousEdge:
    """A call ``x.attr(..)`` (or a dispatcher hop of ``x.attr``) whose receiver is of unknown type and
    that the graph did NOT follow: ``candidates`` are the (module rel, qualified name) defs named
    ``attr`` it might have run, a method or a module-level def."""

    caller: tuple
    attr: str
    candidates: tuple
    call: ast.Call

    @property
    def callee(self) -> str:
        """The callee as a pin prints it (shared with :class:`UnresolvedHop`)."""
        return self.attr

    @property
    def reason(self) -> str:
        return (f"receiver of unknown type, not pinned to one of the {len(self.candidates)} def(s) "
                f"named {self.attr!r}")


@_dataclass(frozen=True)
class UnresolvedHop:
    """A dispatcher hop (``db_call(<callee>, ..)``) whose callee the graph could not name a def for,
    and that is not shown to run outside the module set (see the SCOPE note above
    :data:`MODULE_SCOPE`). ``callee`` is the callable's source text, ``reason`` why it was not
    followed, ``candidates`` the (module rel, qualified name) defs of the set that bear its name
    (empty for a subscript or a call result), ``values`` what the hop hands the callee: the
    expressions :func:`param_taint_fixpoint` judges for a derived value."""

    caller: tuple
    callee: str
    reason: str
    candidates: tuple
    call: ast.Call
    values: tuple


class ReachSet(set):
    """The (module rel, qualified name) keys that reach a target, plus the size of the walk."""

    edge_count: int = 0
    ambiguous_edges: int = 0


class CallGraph:
    """The call edges of ``modules`` (``{relpath: tree}``), built once. ``resolver`` is the ONE
    :class:`CrossModuleResolver` (built over ``modules`` when omitted). See the SCOPE note above
    :data:`MODULE_SCOPE` for what is and is not an edge."""

    def __init__(self, modules: "dict[str, ast.AST]", *, resolver: "CrossModuleResolver | None" = None,
                 dispatchers: frozenset[str] = HOP_DISPATCHERS, loose_receivers: bool = False) -> None:
        self.resolver = resolver if resolver is not None else CrossModuleResolver(modules)
        self.loose_receivers = loose_receivers
        self.scopes = {rel: _ModuleScopes(tree) for rel, tree in modules.items()}
        #: ((rel, qual), every name the call calls, the name a pure forwarder call forwards to) per call
        self.records: list[tuple] = []
        self.edges: list[CallEdge] = []
        #: unknown-receiver method calls not followed (see the SCOPE note): reported, never dropped
        self.ambiguous_edges: list[AmbiguousEdge] = []
        #: dispatcher hops whose callee names no def and may still run one of the set: reported, never dropped
        self.unresolved_hops: list[UnresolvedHop] = []
        #: every def a ``x.attr`` of unknown receiver may run, as (module, qualified name, receiver is
        #: bound): each method named ``attr`` (``x`` an instance) and each module-level def named
        #: ``attr`` (``x`` a module the graph cannot tell is one)
        self._attr_defs: dict[str, list[tuple]] = {}
        for rel, ms in self.scopes.items():
            for attr, quals in ms.methods.items():
                self._attr_defs.setdefault(attr, []).extend((rel, q, True) for q in quals)
            for qual, sc in ms.scopes.items():
                if qual != MODULE_SCOPE and sc.parent is None and sc.cls is None:
                    self._attr_defs.setdefault(qual, []).append((rel, qual, False))
        for rel, ms in self.scopes.items():
            for qual, sc in ms.scopes.items():
                for call in sc.calls:
                    expr, args, kws = call_site(call, dispatchers)
                    fwd = qual != MODULE_SCOPE and any(
                        carries_only_own_splats(args, kws, fn) for fn in sc.nodes)
                    self.records.append(
                        ((rel, qual), call_callee_names(call, dispatchers), callee_ref(expr) if fwd else None))
                    seen = len(self.ambiguous_edges)
                    targets = self._targets(rel, ms, qual, expr, call)
                    for callee, bound in targets:
                        self.edges.append(CallEdge(
                            (rel, qual), callee, call, ((_RECEIVER, *args) if bound else args), kws, fwd))
                    hop = self._unresolved_hop(rel, qual, call, dispatchers,
                                               followed=bool(targets) or len(self.ambiguous_edges) > seen)
                    if hop is not None:
                        self.unresolved_hops.append(hop)

    def _unresolved_hop(self, rel: str, scope: str, call: ast.Call, dispatchers: frozenset[str], *,
                        followed: bool) -> "UnresolvedHop | None":
        """The :class:`UnresolvedHop` ``call`` is, else None (not a hop, followed, recorded as an
        :class:`AmbiguousEdge`, or shown to run outside the module set)."""
        idx = dispatched_slot(call, dispatchers)
        if idx is None:
            return None
        handed = call.args[idx]
        kw_values = tuple(k.value for k in call.keywords if k.arg is not None)
        hop = hop_target(call, dispatchers)
        if hop is None:  # the callable is neither a name nor an attribute: never followed
            what = ("a getattr(..) result" if isinstance(handed, ast.Call) and call_name(handed) == "getattr"
                    else "a subscript" if isinstance(handed, ast.Subscript)
                    else "a call result" if isinstance(handed, ast.Call)
                    else f"an {type(handed).__name__} that names no callee")
            return UnresolvedHop((rel, scope), ast.unparse(handed), f"callee is {what}", (), call,
                                 (handed, *call.args[idx + 1:], *kw_values))
        if followed:
            return None
        expr = hop.callee
        root = expr
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name):
            return None  # an unknown receiver: `_targets` already weighed the defs of the name
        res = self.resolver
        sources = (rel, *res._snapshots.get(rel, ()))  # a snapshot binds what its module imports
        in_set = any(root.id in res._imports.get(s, {}) for s in sources)
        if not in_set and any(root.id in res._outside.get(s, ()) for s in sources):
            return None  # the root is an import of a module outside the set (`bcrypt.hashpw`)
        if isinstance(expr, ast.Name):
            reason = ("a module-set import that resolves to no def (a re-export past REEXPORT_DEPTH, or "
                      "not a def)" if in_set else
                      "a name no import binds (a parameter, a local or a builtin): the callable it holds "
                      "is not followed")
        elif root is expr.value and root.id in ("self", "cls"):
            reason = f"no method {expr.attr!r} in this module (an inherited method is not followed)"
        elif in_set:
            reason = "an attribute of a module-set import that resolves to no def"
        else:
            return None  # an unknown receiver: `_targets` already weighed the defs of the name
        name = callee_ref(expr)
        candidates = tuple((c[0], c[1]) for c in self._attr_defs.get(name, ()))
        return UnresolvedHop((rel, scope), ast.unparse(expr), reason, candidates, call,
                             (*hop.args, *(k.value for k in hop.keywords if k.arg is not None)))

    def _targets(self, rel: str, ms: _ModuleScopes, scope: str, expr: ast.AST, call: ast.Call) -> list:
        """``[((module, qualified def), receiver is bound)]`` the callee expression ``expr``, used in
        ``scope`` of module ``rel``, names. A def of the module's own wins over an import, as at run time."""
        if isinstance(expr, ast.Name):
            local = ms.lookup(scope, expr.id)
            if local is not None:
                return [((rel, local), False)]
            hit = self.resolver.resolve(rel, expr)
            return [(hit, False)] if hit else []
        if not isinstance(expr, ast.Attribute):
            return []
        hit = self.resolver.resolve(rel, expr)
        if hit:
            return [(hit, False)]
        on_self = isinstance(expr.value, ast.Name) and expr.value.id in ("self", "cls")
        if on_self:
            cls = ms.class_of(scope)
            own = ms.classes.get(cls, {}).get(expr.attr) if cls else None
            if own:
                return [((rel, own), True)]
        if on_self:
            return [((rel, q), True) for q in ms.methods.get(expr.attr, ())]
        candidates = self._attr_defs.get(expr.attr, ())
        if len(candidates) == 1 and self.loose_receivers:
            c_rel, c_qual, bound = candidates[0]
            return [((c_rel, c_qual), bound)]
        if candidates:
            self.ambiguous_edges.append(AmbiguousEdge(
                (rel, scope), expr.attr, tuple((c[0], c[1]) for c in candidates), call))
        return []

    def reach(self, targets, *, forwarders_only: bool = False,
              max_nodes: int = REACH_NODE_BOUND) -> ReachSet:
        """Every (module rel, qualified def name) that reaches a target, to a fixpoint. A target is a
        callee NAME (``"mark_backfill_capped"``: any call that calls or dispatches that name, on any
        receiver, defined in the module set or not) or a ``(module rel, qualified name)`` pair (only
        calls the graph resolves to that def). The target's own def is in the answer only if it
        reaches a target itself. ``forwarders_only`` follows just the pure-forwarder calls (the set
        of forwarders of a funnel, and of their forwarders). Past ``max_nodes`` nodes this raises
        :class:`ReachBoundExceeded`, naming the bound, the count and the edge count."""
        names = {t for t in targets if isinstance(t, str)}
        defs = {t for t in targets if isinstance(t, tuple)}
        edges = [e for e in self.edges if e.forwarder or not forwarders_only]
        callers: dict[tuple, list] = {}
        for e in edges:
            callers.setdefault(e.callee, []).append(e.caller)
        reach = ReachSet()
        reach.edge_count = len(edges)
        reach.ambiguous_edges = len(self.ambiguous_edges)
        frontier: list = []

        def add(key: tuple) -> None:
            if key in reach:
                return
            reach.add(key)
            frontier.append(key)
            if len(reach) > max_nodes:
                raise ReachBoundExceeded(
                    f"reach_closure: {len(reach)} nodes reached over {len(edges)} call edges, past the "
                    f"bound of {max_nodes}. A target name this common, or loose_receivers=True, pulls in "
                    f"the module set: name the target as a (module, qualified name) pair, or raise "
                    f"max_nodes on purpose.")

        for caller, called, forwarded in self.records:
            if (forwarded in names) if forwarders_only else (called & names):
                add(caller)
        for d in defs:
            for caller in callers.get(d, ()):
                add(caller)
        while frontier:
            for caller in callers.get(frontier.pop(), ()):
                add(caller)
        return reach


def reach_closure(modules: "dict[str, ast.AST]", targets, *, resolver: "CrossModuleResolver | None" = None,
                  forwarders_only: bool = False, loose_receivers: bool = False,
                  max_nodes: int = REACH_NODE_BOUND,
                  dispatchers: frozenset[str] = HOP_DISPATCHERS) -> ReachSet:
    """``{(module rel, qualified def name)}`` of every def that reaches any of ``targets`` through
    direct, attribute, hop and cross-module calls, to a fixpoint (census-r2 B2). Keys are qualified,
    so two defs of one bare name in different classes, functions or modules stay apart: only the one
    that reaches the target is returned. The result carries ``.edge_count``; past ``max_nodes`` it
    raises :class:`ReachBoundExceeded` with the bound and the counts; ``.ambiguous_edges`` counts the
    unknown-receiver calls it did not follow. See :class:`CallGraph` for the
    scope. To ask several questions of one module set, build the graph once and call its ``reach``."""
    return CallGraph(modules, resolver=resolver, dispatchers=dispatchers,
                     loose_receivers=loose_receivers).reach(
        targets, forwarders_only=forwarders_only, max_nodes=max_nodes)


def iter_defs(modules: "dict[str, ast.AST]"):
    """``(module rel, qualified name, def node)`` for every def of ``modules``, an enclosing def
    before the defs nested in it (a conditional redefinition yields each of its nodes)."""
    for rel, tree in modules.items():
        scopes = [s for q, s in _ModuleScopes(tree).scopes.items() if q != MODULE_SCOPE]
        for sc in sorted(scopes, key=lambda s: (s.qual.count("."), s.nodes[0].lineno)):
            for node in sc.nodes:
                yield rel, sc.qual, node


# --- taint: which parameters receive a value derived from a root --------------------------------


def expr_references(expr: ast.AST, roots) -> bool:
    """True if ``expr`` names a root anywhere inside it."""
    return any(isinstance(sub, ast.Name) and sub.id in roots for sub in ast.walk(expr))


def dotted_name(node: ast.AST) -> str | None:
    """A name / attribute chain as a dotted string (``config.google_oauth.web_client_id``), else None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def derived_places(fn: ast.AST, roots) -> set[str]:
    """Dotted targets (names AND attribute chains) assigned from a root-derived value anywhere in
    ``fn``, nested defs included (an over-approximation that only ever adds genuine flags)."""
    places: set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):
            targets, value = sub.targets, sub.value
        elif isinstance(sub, (ast.AnnAssign, ast.NamedExpr)) and sub.value is not None:
            targets, value = [sub.target], sub.value
        else:
            continue
        if expr_references(value, roots):
            places.update(d for d in map(dotted_name, targets) if d)
    return places


def arg_is_derived(arg: ast.AST, roots, places) -> bool:
    """True when ``arg`` names a root, or is a name / attribute chain assigned from one."""
    if expr_references(arg, roots):
        return True
    d = dotted_name(arg)
    return d is not None and d in places


class TaintResult(_NamedTuple):
    #: {(module rel, qualified def): parameter names that receive a derived value from a caller}
    tainted: dict
    #: {(caller module, callee module, callee qualified name)}: a derived value handed to another module
    crossings: set
    #: the calls that carry a derived value to a def the graph cannot name, and were therefore NOT
    #: followed: each an :class:`AmbiguousEdge` (an unknown receiver whose name several defs share) or
    #: an :class:`UnresolvedHop` (a dispatcher hop to a subscript, a call result, a module-set import
    #: that resolves to no def, a name no import binds, or an inherited ``self.f``). Both print as
    #: ``caller`` / ``call.lineno``
    #: / ``callee`` / ``reason`` / ``candidates``. A pin must fail on any, or pin their count; dropping
    #: them is a silent pass (PD-8)
    unresolved: tuple = ()


def param_taint_fixpoint(modules: "dict[str, ast.AST]", base_roots, is_derived=arg_is_derived, *,
                         resolver: "CrossModuleResolver | None" = None,
                         dispatchers: frozenset[str] = HOP_DISPATCHERS,
                         loose_receivers: bool = False, places_of=derived_places) -> TaintResult:
    """Which parameters of which defs receive a root-derived value, to a fixpoint over the whole
    module set (census-r2 B4: hoisted from the secret-write pin).

    ``base_roots(def_node)`` is the set of names that root a def's own taint (the secret-write pin:
    ``form`` plus its ``Form(..)`` parameters). Inside a def a value is derived when
    ``is_derived(arg, roots, places)`` says so, ``roots`` being its base roots plus the parameters
    already found tainted and ``places`` what ``places_of(def, roots)`` finds assigned from them.
    When a def passes a derived value to a def of the module set (by position OR keyword, through a
    direct call, an attribute call, a dispatcher hop or another module), the callee's parameter
    becomes tainted, and the walk repeats until nothing new appears.

    The calls of a def are those in its body AND its nested defs' (``ast.walk`` of the def), because
    a closure reads the variables its definer derived. SCOPE: the :class:`CallGraph` scope, plus
    ``*``-splat arguments, ``**kwargs`` spreads and values smuggled through a container are not
    tracked. A call or hop of an unknown receiver that the graph cannot pin to one def (several defs
    share the name, or ``loose_receivers`` is off), and a dispatcher hop whose callee names no def but
    may run one of the set (:class:`UnresolvedHop`), that carries a derived value is returned in
    ``TaintResult.unresolved``, never dropped. Returns :class:`TaintResult`."""
    graph = CallGraph(modules, resolver=resolver, dispatchers=dispatchers, loose_receivers=loose_receivers)
    nodes = {(rel, q): sc.nodes for rel, ms in graph.scopes.items() for q, sc in ms.scopes.items()
             if q != MODULE_SCOPE}
    params = {key: _def_params(ns[0]) for key, ns in nodes.items()}
    base = {key: set(base_roots(ns[0])) for key, ns in nodes.items()}
    owned: dict[tuple, list] = {}
    for e in graph.edges:  # an edge belongs to its caller and to every def that encloses the caller
        rel, qual = e.caller
        parts = qual.split(".")
        for i in range(1, len(parts) + 1):
            key = (rel, ".".join(parts[:i]))
            if key in nodes:
                owned.setdefault(key, []).append(e)
    tainted: dict[tuple, set[str]] = {key: set() for key in nodes}
    crossings: set[tuple[str, str, str]] = set()

    def taint(key: tuple, callee: tuple, param: str) -> bool:
        if param in tainted[callee]:
            return False
        tainted[callee].add(param)
        if callee[0] != key[0]:
            crossings.add((key[0], callee[0], callee[1]))
        return True

    changed = True
    while changed:
        changed = False
        for key, node_list in nodes.items():
            roots = base[key] | tainted[key]
            places = places_of(node_list[0], roots)
            for e in owned.get(key, ()):
                cps = params.get(e.callee, [])
                for i, arg in enumerate(e.args):
                    if isinstance(arg, ast.Starred):
                        continue
                    if i < len(cps) and is_derived(arg, roots, places):
                        changed |= taint(key, e.callee, cps[i])
                for kw in e.keywords:
                    if kw.arg is None:  # **kwargs spread: cannot track
                        continue
                    if is_derived(kw.value, roots, places):
                        changed |= taint(key, e.callee, kw.arg)
    def handed(u) -> tuple:
        if isinstance(u, UnresolvedHop):
            return u.values
        _expr, args, kws = call_site(u.call, dispatchers)
        return (*args, *(k.value for k in kws if k.arg is not None))

    unresolved: list = []
    # judged at the fixpoint, under each enclosing def's final roots
    for u in (*graph.ambiguous_edges, *graph.unresolved_hops):
        rel, qual = u.caller
        values = [v for v in handed(u) if not isinstance(v, ast.Starred)]
        parts = qual.split(".")
        for i in range(1, len(parts) + 1):
            key = (rel, ".".join(parts[:i]))
            if key not in nodes:
                continue
            roots = base[key] | tainted[key]
            places = places_of(nodes[key][0], roots)
            if any(is_derived(v, roots, places) for v in values):
                unresolved.append(u)
                break
    return TaintResult(tainted, crossings, unresolved)


# ---------------------------------------------------------------------------
# Punch 709 (cycle P panel, db-sme P2 items 1-2; PD-5 / PD-6): the EMERGENCY-revoke
# sanction, ONE predicate for the two pins that exempt it
# (tests/test_session_epoch_on_revoke_pin.py, tests/test_audit_emit_swallow_pin.py).
# Before this each pin exempted it its own way: the epoch pin every line of every
# ``except`` handler in a function calling the funnel, the swallow pin the whole of
# ``set_user_disabled`` by name. Both were green with the flag guard deleted.
#
# The sanctioned shape is a witness-phase ``except`` handler carrying, as a statement of
# its own body, ``if emergency_reason is None:`` whose body ENDS in ``raise`` (and holds no
# return / break / continue / try that could leave it first) and has no ``else``, in a
# function that calls ``record_emergency_revoke``. Only the statements AFTER that guard,
# in that handler, run with the flag set, so only they are sanctioned. SCOPE: by name
# (``emergency_reason``, ``record_emergency_revoke``) and statement order, not data flow.
# ---------------------------------------------------------------------------

EMERGENCY_FLAG = "emergency_reason"
EMERGENCY_FUNNEL = "record_emergency_revoke"


def _own_nodes(fn: ast.AST):
    """Every node of ``fn``'s own body, not descending into a nested def / class / lambda."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))


def _is_flag_is_none(test: ast.AST) -> bool:
    return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
            and test.left.id == EMERGENCY_FLAG and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Is) and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None)


def _block_ends_in_raise(stmts: list) -> bool:
    if not stmts or not isinstance(stmts[-1], ast.Raise):
        return False
    return not any(isinstance(n, (ast.Return, ast.Break, ast.Continue, ast.Try))
                   for s in stmts for n in ast.walk(s))


def emergency_guard_index(handler: ast.ExceptHandler) -> int | None:
    """Index in ``handler.body`` of its ``if emergency_reason is None: ... raise`` guard."""
    for i, stmt in enumerate(handler.body):
        if (isinstance(stmt, ast.If) and _is_flag_is_none(stmt.test) and not stmt.orelse
                and _block_ends_in_raise(stmt.body)):
            return i
    return None


def emergency_sanctioned_handlers(fn: ast.AST) -> list:
    """``(handler, guard index)`` for every guarded ``except`` handler in ``fn``'s own
    body, when ``fn``'s own body calls the emergency funnel; ``[]`` otherwise."""
    nodes = list(_own_nodes(fn))
    if not any(isinstance(n, ast.Call) and call_name(n) == EMERGENCY_FUNNEL for n in nodes):
        return []
    out = []
    for h in nodes:
        if isinstance(h, ast.ExceptHandler):
            i = emergency_guard_index(h)
            if i is not None:
                out.append((h, i))
    return out


def emergency_sanctioned_lines(fn: ast.AST) -> set[int]:
    """Every line inside the statements AFTER the guard of a sanctioned handler: the
    code that runs only with the flag set."""
    return {n.lineno for h, i in emergency_sanctioned_handlers(fn)
            for stmt in h.body[i + 1:] for n in ast.walk(stmt) if hasattr(n, "lineno")}


def is_emergency_sanctioned_handler(fn: ast.AST, handler: ast.ExceptHandler) -> bool:
    """``handler`` is one of ``fn``'s sanctioned emergency handlers."""
    return any(h is handler for h, _i in emergency_sanctioned_handlers(fn))
# The LIVE ROUTE-TABLE walk
# ---------------------------------------------------------------------------

def iter_app_routes(app):
    """Every unique ``(method, path, endpoint_module, endpoint_name)`` in ``app``.

    Hoisted from ``tests/test_web/test_csrf_route_coverage_pin.py::_guarded_routes``
    when the  route-scope pin needed the same walk (PD#6 — the pins obey the
    SSOT rule; a second hand-rolled router walk is exactly the drift the harness
    exists to stop). The CSRF pin now imports this.

    Handles all three ``app.routes`` shapes so the walk stays correct across
    fastapi versions — the drift class the count-agnostic directive is about:

    * **fastapi 0.139.x** ``_IncludedRouter`` — the real routes live under
      ``route.original_router.routes`` with the prefix on
      ``route.include_context.prefix``.
    * **Mount / sub-router** with its own ``.routes`` (StaticFiles, WSGI mounts,
      and pre-0.139 ``include_router`` expansions) — recurse through ``.routes``.
    * a plain leaf ``APIRoute``.

    **DE-DUPLICATES, and that is load-bearing.** The UI routers share one
    ``APIRouter`` object which ``app.routes`` holds under several
    ``_IncludedRouter`` wrappers, so the raw walk re-emits the same route up to
    24 times (measured 2026-09-29: 2257 raw rows for 310 distinct routes — a 7x
    inflation). Any pin that REPORTS a route count off the raw walk publishes a
    number 7x too large. Count-agnostic pins should still never assert the count;
    this dedup is so the walk is a faithful ROUTE SET.

    One row per ``(method, path)``: a route declaring ``{"GET", "POST"}`` yields
    two rows, because the scope fence keys on method AND path.

    Returns a sorted list of ``(method, path, module, endpoint_name)`` tuples.
    """
    out: set[tuple[str, str, str, str]] = set()

    def _walk(route, prefix: str) -> None:
        original = getattr(route, "original_router", None)
        ctx = getattr(route, "include_context", None)
        if original is not None and hasattr(original, "routes"):
            sub_prefix = prefix + (getattr(ctx, "prefix", "") or "")
            for child in original.routes:
                _walk(child, sub_prefix)
            return
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        children = getattr(route, "routes", None)
        if children is not None and path is not None:
            for child in children:
                _walk(child, prefix + path)
            return
        if not path:
            return
        endpoint = getattr(route, "endpoint", None)
        module = getattr(endpoint, "__module__", "?")
        name = getattr(endpoint, "__name__", "?")
        for method in methods:
            out.add((method, prefix + path, module, name))

    for route in app.routes:
        _walk(route, "")
    return sorted(out)
