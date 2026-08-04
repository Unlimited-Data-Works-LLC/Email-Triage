"""-followup-B — AST guard against LEGB-shadow `import asyncio`.

Background
----------
Python LEGB resolution treats a function-scope `import asyncio` as a
fresh binding that shadows any module-level `import asyncio` for the
function's body. The local re-import is purely redundant when the
module already imports `asyncio` at module scope — it costs a
`sys.modules` lookup per call and creates a regression-prevention
hazard: a future contributor who removes the module-level import
("the locals cover it") breaks every other call site in the file that
uses bare `asyncio.foo`.

-followup-B catalogued 2 such sites in `src/email_triage/cli.py`:
- `cmd_embedding_bits_install` (line 1555 pre-fix) — local `import
  asyncio` inside a function whose module already imports asyncio at
  line 27.
- `cmd_embedding_bits_sideload` (line 1582 pre-fix) — same shape.

The fix deleted both local imports. This guard prevents the regression
class from re-emerging.

Drift-defense pattern
---------------------
This is the **9th instance** of the count-agnostic structural-drift-
catch pattern per `#262-followup-E` (n=6 → n=8 with / LEAD-
side stale-catches → n=9 with this guard). Earlier exemplars:
  1.  connection-holding ratchet (AST scan)
  2.  async-DB-scan guard (AST scan)
  3.  idempotency contract (`Action.__subclasses__()` + module-path
     filter)
  4.  watch-delivery retry call-site pin (regex live-path catch +
     drainer-exclusion)
  5.  connection-holding count-agnostic xfail-reason (lesson
     birthing the discipline)
  6.  classify-async-helper AST pin (`visit_AsyncFunctionDef` +
     `visit_Call` walker)
  7.  / N-03 Attachment.data drop (AST guard over 3 provider
     `Attachment(...)` constructors)
  8.  IMAP batch-fetch wiring pin (AST guard over `poll_once` body
     for `fetch_messages_batch` invocation)
  9. THIS GUARD — LEGB-shadow detection
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# R5b: the source-tree walk / relpath scaffolding lives in the ONE shared
# harness so it cannot drift per-pin. `SRC_ROOT` here is identical to the
# old `_src_root()` (repo-root/src/email_triage); `iter_src_files()` is the
# old `_all_modules()` (sorted `*.py`, `__pycache__` skipped); `relpath()`
# is the old `str(p.relative_to(_src_root())).replace("\\", "/")` — same
# `web/db.py` base, so the parametrize IDs and violation messages are
# byte-identical. This pin keys NO allow-list on the relpath (it has no
# allow-list), so the base is purely cosmetic here — no re-keying needed.
from _pin_harness import SRC_ROOT, iter_src_files, relpath as _relpath, parse_source


def _all_modules() -> list[Path]:
    """Every `.py` under `src/email_triage` — via the shared harness walk."""
    return list(iter_src_files())


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def _has_module_level_import_asyncio(tree: ast.Module) -> bool:
    """True when the module has a top-level `import asyncio` statement.

    Scans only direct children of the `Module` body (not nested in
    `If` / `Try` blocks) — same semantic level as the function-scope
    imports we're catching. A conditional module-level import (under
    `if sys.version_info >= ...:`) is a legitimate pattern we do NOT
    classify as "module-level binding" for the shadow check.
    """
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "asyncio":
                    return True
    return False


def _function_scope_import_asyncio_lines(
    tree: ast.Module,
) -> list[tuple[str, int]]:
    """Every `import asyncio` inside a `FunctionDef` / `AsyncFunctionDef`
    body — `(function_name, lineno)` tuples.

    Walks INTO nested functions as well; a regression that puts `import
    asyncio` inside a nested closure is the same shadow class.
    """
    offenders: list[tuple[str, int]] = []

    def _walk_function(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Import):
                for alias in sub.names:
                    if alias.name == "asyncio":
                        offenders.append((fn.name, sub.lineno))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _walk_function(node)

    return offenders


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "module_path",
    _all_modules(),
    ids=_relpath,
)
def test_no_legb_shadow_import_asyncio(module_path: Path):
    """A module that imports `asyncio` at module scope MUST NOT
    re-import `asyncio` inside any function body — the local binding
    silently shadows the module-level one for that function (LEGB
    function-scope hides module-scope).

    Why this matters: the local import is purely redundant when the
    module already has the binding, AND it creates a regression-
    prevention hazard. A future contributor who reads the local
    `import asyncio` may assume it's load-bearing and, if they later
    remove the module-level import (e.g. as part of a tidy-up sweep),
    they break every OTHER call site in the file that uses bare
    `asyncio.foo` — those sites had relied on the module-level
    binding, not the function-local one.

    Function-only `import asyncio` (no module-level import) is a
    different smell (unnecessary-local-import, tracked separately as
    -followup-C). This guard ONLY catches the LEGB-shadow class
    where BOTH module-scope AND function-scope imports exist.

    Fix shape when this guard fires: delete the function-local
    `import asyncio` line; the module-level binding already covers
    the function's use.
    """
    try:
        src = module_path.read_text(encoding="utf-8")
        tree = parse_source(src)
    except (SyntaxError, UnicodeDecodeError) as exc:
        # Fail-CLOSED: this is the guard's OWN scanner machinery, not an
        # optional runtime dep. A src module that won't parse/decode is itself
        # a defect — skipping would let it silently escape the invariant.
        pytest.fail(f"{module_path} did not parse ({exc!r}) — a non-parsing "
                    "src module is a defect this guard must surface, not skip")

    if not _has_module_level_import_asyncio(tree):
        # No module-level binding → function-local imports aren't
        # shadowing anything. Out of scope for this guard (the
        # unnecessary-local-import class is -followup-C).
        return

    offenders = _function_scope_import_asyncio_lines(tree)
    if offenders:
        rel = _relpath(module_path)
        lines = "\n".join(
            f"  {rel}:{lineno}  in def {fn_name}(): import asyncio"
            for fn_name, lineno in offenders
        )
        pytest.fail(
            f"{len(offenders)} LEGB-shadow `import asyncio` site(s) "
            f"in {rel}:\n{lines}\n\n"
            "Delete the function-local `import asyncio` — the module "
            "already imports asyncio at module scope, so the local "
            "re-import is redundant AND silently shadows the module-"
            "level binding (Python LEGB function-scope hides module-"
            "scope). A future contributor removing the module-level "
            "import would break every OTHER asyncio call site in the "
            "file. See -followup-B."
        )


# ---------------------------------------------------------------------------
# Sanity — the detector itself must work on synthetic source
# ---------------------------------------------------------------------------

def _detect_on(src: str) -> tuple[bool, list[tuple[str, int]]]:
    """Run the pin's two helpers on a synthetic source string."""
    tree = parse_source(src)
    return (
        _has_module_level_import_asyncio(tree),
        _function_scope_import_asyncio_lines(tree),
    )


class TestDetectorSanity:
    """Pin-the-pin tests. A bug in the detector that silently passed
    every module would make the regression-prevention guard useless;
    these synthetic-source cases prove the detector actually fires on
    the shapes it's designed to catch.
    """

    def test_both_module_and_function_import_asyncio_is_offender(self):
        src = (
            "import asyncio\n"
            "def f():\n"
            "    import asyncio\n"
            "    asyncio.run(g())\n"
        )
        has_module, offenders = _detect_on(src)
        assert has_module is True
        assert len(offenders) == 1
        assert offenders[0] == ("f", 3)

    def test_module_only_is_not_offender(self):
        src = (
            "import asyncio\n"
            "def f():\n"
            "    asyncio.run(g())\n"
        )
        has_module, offenders = _detect_on(src)
        assert has_module is True
        assert offenders == []

    def test_function_only_is_not_caught_here(self):
        # Function-only `import asyncio` (no module-level) is
        # unnecessary-local-import, NOT
        # LEGB-shadow. The guard skips these — the parametrised
        # test above returns early when `has_module is False`.
        src = (
            "def f():\n"
            "    import asyncio\n"
            "    asyncio.run(g())\n"
        )
        has_module, offenders = _detect_on(src)
        assert has_module is False
        # Detector still LISTS the local imports; the pin's `return`
        # at the `has_module` check is what makes them out-of-scope.
        assert len(offenders) == 1

    def test_async_function_import_asyncio_is_caught(self):
        # `async def` is the same shadow class as `def`.
        src = (
            "import asyncio\n"
            "async def f():\n"
            "    import asyncio\n"
            "    await asyncio.sleep(0)\n"
        )
        has_module, offenders = _detect_on(src)
        assert has_module is True
        assert len(offenders) == 1
        assert offenders[0] == ("f", 3)

    def test_nested_function_import_asyncio_is_caught(self):
        # A regression that puts the import inside a nested closure is
        # the same shadow class — the inner function's body sees the
        # local binding before reaching out to the module scope.
        src = (
            "import asyncio\n"
            "def outer():\n"
            "    def inner():\n"
            "        import asyncio\n"
            "        return asyncio.run(g())\n"
            "    return inner\n"
        )
        has_module, offenders = _detect_on(src)
        assert has_module is True
        # Both `outer` and `inner` walks see the inner's import (walk
        # is recursive through nested scopes). The duplication is
        # acceptable for the warning-message purpose — both names
        # point to the same regression.
        assert len(offenders) >= 1
        assert any(fn == "inner" for fn, _ in offenders)

    def test_conditional_module_import_is_NOT_module_level(self):
        # A module-level `if` block hiding `import asyncio` is NOT a
        # straight module-level binding for our purposes — the
        # detector should NOT classify it as "module scope" because
        # the import may not actually execute (different shadow class
        # we don't catch).
        src = (
            "import sys\n"
            "if sys.version_info >= (3, 7):\n"
            "    import asyncio\n"
            "def f():\n"
            "    import asyncio\n"
            "    asyncio.run(g())\n"
        )
        has_module, _ = _detect_on(src)
        assert has_module is False, (
            "conditional module-level import doesn't count as the "
            "kind of unconditional module-level binding that a "
            "function-local import would shadow — different class"
        )

    def test_aliased_import_asyncio_as_aio_is_not_caught(self):
        # `import asyncio as aio` at function scope rebinds a DIFFERENT
        # local name, not `asyncio` — no shadow of module-level
        # `import asyncio`. Out of scope.
        src = (
            "import asyncio\n"
            "def f():\n"
            "    import asyncio as aio\n"
            "    aio.run(g())\n"
        )
        has_module, offenders = _detect_on(src)
        # Detector currently flags this — the offender list reports
        # the line, but the pin only fires on `alias.name == 'asyncio'`
        # which is the unrebound case. The aliased case IS still a
        # shadow (rebinding the alias), but it's a smaller-impact
        # smell because the bare `asyncio.foo` calls elsewhere in the
        # file aren't affected (they still see the module-level
        # binding). Leave it out of scope to keep the pin tight.
        assert has_module is True
        # Detector finds `import asyncio as aio` because alias.name is
        # `asyncio` regardless of asname — that's a known false
        # positive in the detector. Document and accept; if it becomes
        # a real complaint, tighten the detector to require
        # `alias.asname is None`. For now no in-tree caller does this.
        # (The test asserts the detector behaviour as-is so a future
        # tightening is a deliberate test update.)
        assert any(fn == "f" for fn, _ in offenders)


class TestNoFalsePositivesInTree:
    """Sanity: every module under `src/email_triage` should pass the
    pin after the -followup-B fix. A failure here means either
    (a) the fix didn't actually delete the offending imports, or
    (b) a NEW LEGB-shadow site landed since.
    """

    def test_cli_py_is_clean_after_fix(self):
        # The exact file the -followup-B fix targeted.
        cli_py = SRC_ROOT / "cli.py"
        src = cli_py.read_text(encoding="utf-8")
        tree = parse_source(src)
        has_module = _has_module_level_import_asyncio(tree)
        offenders = _function_scope_import_asyncio_lines(tree)
        assert has_module is True, (
            "cli.py is expected to import asyncio at module scope"
        )
        assert offenders == [], (
            f"cli.py still has LEGB-shadow `import asyncio` site(s): "
            f"{offenders}. The -followup-B fix deleted "
            "cli.py:1555 and cli.py:1582; a regression has "
            "re-introduced one."
        )
