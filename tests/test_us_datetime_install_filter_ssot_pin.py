"""Interprocedural SSOT pin — us_datetime install_filter over FileSystemLoader-Env.

Drive-5 follow-up to  US-datetime fanout (Phases 1+2 landed
`576e54df` → hotfix `93ac676e`). The SSOT for `us_datetime` filter
registration is `src/email_triage/_us_datetime.py::install_filter(env)`.
Every code path that constructs a `jinja2.Environment(loader=
FileSystemLoader(...))` intended to render REPO templates MUST call
`install_filter(env)` in the same enclosing function — otherwise a
template using `{{ x | us_datetime }}` raises `TemplateRuntimeError:
No filter named 'us_datetime' found` at render time. Standalone
`Environment(...)` render smoke tests never reached the inline
registration that used to live in `web/app.py`, and green-locally-
but-red-in-CI'd on the 2026-07-14 fanout — the SSOT + this pin
convert that recurrence class into a build-break instead of a
CI-time render surprise.

Scope: `src/**` + `tests/**`. Any `Environment(...)` call whose
`loader=` kwarg contains a `FileSystemLoader(...)` construction MUST
have an `install_filter(<any-arg>)` call in the SAME enclosing
function (or module, for module-scope Env). Bare `Environment(
autoescape=...)` for `from_string` rendering (e.g.
`actions/digest.py:501`) is OUT of scope — it renders operator-
supplied templates, not repo templates; a separate follow-up covers
that path via a different SSOT anchor.

Per PD#1 (count-agnostic structural pin) + PD#6 (reuse the shared
harness). Detector walks with `ast.walk`, keys offenders by
harness-canonical `relpath(...)`.

Refs:
  - feedback_divergence_audit_and_ssot_pin (SSOT+pin down-payment)
  - STATE_2026-07-14_1326_edt_rot_resumed_ci_watching_579b2436
    (Drive-5 follow-up queued)
  - src/email_triage/_us_datetime.py (the SSOT)
"""
from __future__ import annotations

import ast
from pathlib import Path

# Add repo/tests to sys.path so `from _pin_harness import ...` resolves
# regardless of pytest invocation cwd.
import sys as _sys
_HARNESS_DIR = Path(__file__).resolve().parent
if str(_HARNESS_DIR) not in _sys.path:
    _sys.path.insert(0, str(_HARNESS_DIR))

from _pin_harness import (  # noqa: E402
    SRC_ROOT,
    REPO_ROOT,
    iter_files,
    parse_module,
    relpath,
)


TESTS_ROOT: Path = REPO_ROOT / "tests"


def _is_environment_call(node: ast.Call) -> bool:
    """`Environment(...)` or `jinja2.Environment(...)`."""
    f = node.func
    if isinstance(f, ast.Name) and f.id == "Environment":
        return True
    if isinstance(f, ast.Attribute) and f.attr == "Environment":
        return True
    return False


def _kwarg_holds_fsl(node: ast.Call) -> bool:
    """`loader=FileSystemLoader(...)` or `loader=jinja2.FileSystemLoader(...)`."""
    for kw in node.keywords:
        if kw.arg != "loader":
            continue
        v = kw.value
        if not isinstance(v, ast.Call):
            continue
        vf = v.func
        if isinstance(vf, ast.Name) and vf.id == "FileSystemLoader":
            return True
        if isinstance(vf, ast.Attribute) and vf.attr == "FileSystemLoader":
            return True
    return False


def _find_enclosing_scope(tree: ast.Module, target_lineno: int) -> ast.AST:
    """Return the innermost FunctionDef/AsyncFunctionDef enclosing `target_lineno`,
    or the module itself if the call sits at module scope."""
    best: ast.AST = tree
    best_line = -1
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = getattr(node, "end_lineno", None) or node.lineno
        if node.lineno <= target_lineno <= end_line and node.lineno > best_line:
            best = node
            best_line = node.lineno
    return best


def _scope_calls_install_filter(scope: ast.AST) -> bool:
    """True iff any `install_filter(<any-arg>)` or
    `<any>.install_filter(<any-arg>)` call appears anywhere in `scope`.
    Import aliases (`install_filter as _install_us_datetime`) are covered
    by the attr/id name-check falling through to the aliased binding —
    since callers use the aliased binding name, we accept ANY function-
    call whose invoked name is `install_filter` OR whose LOCAL binding
    resolves through the module import table to it. To keep the pin
    simple + count-agnostic without an import-graph walk, we accept:

      * direct `install_filter(...)` call (bare or via `mod.install_filter`)
      * ANY call whose `func.id` (or `.attr`) ends with `install_us_datetime`
        (the canonical alias used in `web/app.py` + these tests).

    Any renamed alias falls under the second arm; any completely
    idiosyncratic name is deliberately unaccepted — divergence itself.
    """
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            name = f.id
        elif isinstance(f, ast.Attribute):
            name = f.attr
        else:
            continue
        if name == "install_filter":
            return True
        if name.endswith("install_us_datetime"):
            return True
    return False


def _walk_tree(root: Path) -> list[tuple[Path, ast.Module]]:
    out: list[tuple[Path, ast.Module]] = []
    for p in iter_files(root, "*.py"):
        tree = parse_module(p)
        if tree is None:
            continue
        out.append((p, tree))
    return out


def _scope_uses_from_string(scope: ast.AST) -> bool:
    """True iff scope contains a `<any>.from_string(...)` call — the
    marker that a bare-Env is being used to render operator-supplied
    templates (as opposed to being constructed for an unrelated
    reason and never actually rendering anything)."""
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "from_string":
            return True
    return False


def _collect_bare_env_offenders(root: Path, root_label: str) -> list[str]:
    """Return `path:line` for every bare `Environment(...)` construction
    (no `loader=` kwarg) whose enclosing scope contains a
    `.from_string(...)` call but lacks an `install_filter(...)` call.

    Post-panel (2026-07-15 hipaa-sme + devils-advocate GO-WITH-FIXES):
    the FileSystemLoader detector was closing only the repo-template
    render class. `actions/digest.py:501` was a bare-Env twin that
    renders operator-supplied HTML via `.from_string(...)` — same
    filter-miss class, invisible to the FSL detector. Widening per
    PD #1 (count-agnostic structural pin) + PD #6 (shared harness).
    Scope-limited to bare-Env sites that ACTUALLY render (contain a
    `.from_string(...)` in the same enclosing scope) so we don't
    over-flag a bare-Env constructed for a different purpose.
    """
    offenders: list[str] = []
    for path, tree in _walk_tree(root):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_environment_call(node):
                continue
            # Bare-Env only: skip anything with a `loader=` kwarg — those
            # are covered by the FileSystemLoader detector.
            if any(kw.arg == "loader" for kw in node.keywords):
                continue
            scope = _find_enclosing_scope(tree, node.lineno)
            # Only flag when scope uses `.from_string(...)` — the marker
            # for operator-template render (as opposed to a bare-Env
            # constructed for some other unrelated purpose).
            if not _scope_uses_from_string(scope):
                continue
            if _scope_calls_install_filter(scope):
                continue
            if scope is tree and _scope_calls_install_filter(tree):
                continue
            rel = relpath(path, REPO_ROOT)
            offenders.append(f"[{root_label}] {rel}:{node.lineno}")
    return offenders


def _collect_offenders(root: Path, root_label: str) -> list[str]:
    """Return `path:line` for every FileSystemLoader-Env construction
    whose enclosing scope lacks an `install_filter(...)` call."""
    offenders: list[str] = []
    for path, tree in _walk_tree(root):
        # First pass: locate every FileSystemLoader-Env construction.
        candidates: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_environment_call(node):
                continue
            if not _kwarg_holds_fsl(node):
                continue
            candidates.append(node)
        if not candidates:
            continue
        for call in candidates:
            scope = _find_enclosing_scope(tree, call.lineno)
            if _scope_calls_install_filter(scope):
                continue
            # Skip the module itself if the call is module-scope AND
            # some other scope in the module calls install_filter (an
            # env instantiated at module scope but registered from a
            # setup helper). Module-scope Env is discouraged but not
            # a certainty of miss.
            if scope is tree:
                # Give the module one last chance: any install_filter
                # call anywhere in the module.
                if _scope_calls_install_filter(tree):
                    continue
            # Route through the harness relpath so path-normalization
            # lives in ONE place (harness contract #5). REPO_ROOT base
            # covers both src/ and tests/ scans in one canonical form.
            rel = relpath(path, REPO_ROOT)
            offenders.append(f"[{root_label}] {rel}:{call.lineno}")
    return offenders


def test_us_datetime_install_filter_ssot_src():
    """No `src/**` FileSystemLoader-Env may skip `install_filter`."""
    offenders = _collect_offenders(SRC_ROOT, "src")
    assert not offenders, (
        "us_datetime install_filter SSOT pin: src/-side FileSystemLoader Env "
        "construction without an `install_filter(...)` call in enclosing scope. "
        "Every code path that renders REPO templates MUST call "
        "`email_triage._us_datetime.install_filter(env)` — see the SSOT "
        "at src/email_triage/_us_datetime.py::install_filter and web/app.py:1266 "
        "for the canonical form. Offenders:\n  " + "\n  ".join(offenders)
    )


def test_us_datetime_install_filter_ssot_src_bare_env_from_string():
    """No `src/**` bare `Environment(...)` (no loader= kwarg) that
    calls `.from_string(...)` in the same scope may skip
    `install_filter`. Panel-folded 2026-07-15 (hipaa-sme+DA GO-WITH-
    FIXES): closes the `actions/digest.py:501` twin class that the
    FileSystemLoader detector's docstring pre-deferred. Recurrence-
    class shape of `feedback_dont_over_defer` #8."""
    offenders = _collect_bare_env_offenders(SRC_ROOT, "src")
    assert not offenders, (
        "us_datetime install_filter SSOT pin (bare-Env twin): src/-side "
        "`Environment(...)` construction (no loader= kwarg) that renders "
        "operator-supplied templates via `.from_string(...)` without an "
        "`install_filter(...)` call in enclosing scope. See "
        "`src/email_triage/actions/digest.py::build_digest_html` for the "
        "canonical form. Offenders:\n  " + "\n  ".join(offenders)
    )


def test_us_datetime_install_filter_ssot_tests_bare_env_from_string():
    """No `tests/**` bare `Environment(...)` (no loader= kwarg) that
    calls `.from_string(...)` in the same scope may skip
    `install_filter` — same widening as the src-side sibling."""
    offenders = _collect_bare_env_offenders(TESTS_ROOT, "tests")
    assert not offenders, (
        "us_datetime install_filter SSOT pin (bare-Env twin): tests/-side "
        "`Environment(...)` construction that renders operator-supplied "
        "templates via `.from_string(...)` without an `install_filter(...)` "
        "call in enclosing scope. Offenders:\n  " + "\n  ".join(offenders)
    )


def test_us_datetime_install_filter_ssot_tests():
    """No `tests/**` FileSystemLoader-Env may skip `install_filter`.

    Test smoke-render fixtures MUST mirror the prod Env registration
    surface (per `feedback_test_the_view_not_just_machinery`) — a
    fixture that omits `install_filter` will pass locally against a
    template that DOES NOT use `us_datetime`, and 500 the day a
    template starts using it. Convert the failure class from
    render-time surprise to build-break."""
    offenders = _collect_offenders(TESTS_ROOT, "tests")
    assert not offenders, (
        "us_datetime install_filter SSOT pin: tests/-side FileSystemLoader Env "
        "construction without an `install_filter(...)` call in enclosing scope. "
        "Add `from email_triage._us_datetime import install_filter as "
        "_install_us_datetime; _install_us_datetime(env)` after Env "
        "construction (see tests/test_web/test_template_phi_render.py fixture "
        "for the canonical form). Offenders:\n  " + "\n  ".join(offenders)
    )
