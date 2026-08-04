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


def iter_files(root: Path, pattern: str = "*.py", subdir: str | None = None):
    """Yield every file matching ``pattern`` under ``root`` (or ``root/subdir``),
    sorted, skipping ``__pycache__`` — the GENERIC walker. ``iter_src_files`` /
    ``iter_template_files`` are thin wrappers. A pin that audits a non-``.py``
    tree (templates) or a different glob routes through HERE instead of
    re-rolling ``Path(...).rglob(...)`` + the ``__pycache__`` skip (R5c)."""
    base = root if subdir is None else root / subdir
    for path in sorted(base.rglob(pattern)):
        if "__pycache__" in path.parts:
            continue
        yield path


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
    than silently under-catching. **N-182b follow-up:** SQLiteLogHandler.emit
    is a THIRD log_entries chain writer flagged by DA — routes through
    `logging.Handler.handleError` (stderr swallow), same class as the
    cli.py:283 case. Deferred: adding `emit` here would fail-red the swallow
    pin until emit itself routes through `safe_audit_write` (hot-path
    change; needs a separate wave)."""
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

    **Residual (documented per DA hedge da-fix-2, `feedback_just_be_honest`):**
    a runtime dynamic import like ``bg = importlib.import_module(
    "email_triage.classify.baa_gate")`` is invisible to this pure-AST
    resolver — the module reference materializes only at runtime, and the
    bound name (``bg`` here) is not linked to the SSOT module in any AST
    node. Zero known offenders at HEAD; a future dynamic-import shape
    would require a text-scan complement or an additional AST pattern
    (``ast.Call(func=Attribute(attr='import_module'))`` with a string-
    literal first arg)."""
    out: set[str] = set()
    prefix = ssot_module + "."
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                if mod == ssot_module or mod.startswith(prefix):
                    out.add(alias.asname or mod.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            src = node.module or ""
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
    return out


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
