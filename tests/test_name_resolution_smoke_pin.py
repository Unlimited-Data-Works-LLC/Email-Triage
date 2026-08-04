"""N-295 R30 (narrowed 2026-07-04 per N-335) — SYNTAX-only smoke pin.

DA post-hoc panel on 2026-07-03 flagged "same-change name-resolution
coupling" as a recurring defect class this session (6+ instances:
N-283 `_metrics`, N-283b `_backend_for_classifier` + `parse_iso`,
N-287 test seam, N-294b pin window). Each incident is the SAME class:
the new-symbol's satellite artifact (import block, registration
table, pin window, migration version file) wasn't touched in the
same commit.

**N-335 R31 correction (2026-07-04):** the original N-295 R30 docstring
claimed py_compile catches "Import-time NameError from missing
top-level import (N-283 `_metrics`, N-283b `_backend_for_classifier`)."
**That claim is EMPIRICALLY FALSE.** ``py_compile.compile(..., doraise=True)``
produces bytecode without executing the module body — undefined
names, missing top-level imports, and cross-module refs are NEVER
resolved at compile time. Python defers name resolution to import
time; the smoke never imports. The N-283 / N-283b examples the
original docstring cited would NOT have been caught by this pin.

**What this pin actually catches** (narrow, correct scope):

- Syntax errors — broken indent (the N-269b batch-script defect),
  malformed f-strings, unbalanced brackets, `def` without `:`.
- Grammar-level issues — walrus scope, PEP-8-strict placement of
  `from __future__ import`, module-level `await` outside async.
- Parse errors on encoding declaration mismatches.

**What this pin does NOT catch** (deferred to the runtime-import
name-resolution walker — see follow-up N-335b):

- Missing top-level imports (`_metrics` used without `import`).
- Cross-module semantic drift (function renamed in module A, still
  called in module B).
- `NameError` from a rename that didn't touch every caller.
- Import-time side-effect failures.

`feedback_by_path_commit_completeness` remains the CHECKLIST tier
for these; the runtime-import walker is the STRUCTURAL tier the
original docstring meant to describe but did not deliver. One rule
per defect class — this pin is the cheap SYNTAX tier only.
"""
from __future__ import annotations

import py_compile
import pytest

from _pin_harness import SRC_ROOT, iter_files, relpath


@pytest.mark.parametrize("path", list(iter_files(SRC_ROOT)))
def test_src_file_py_compile_clean(path):
    """Every `.py` file under `src/email_triage/` must py_compile
    clean. Catches SYNTAX errors ONLY:
      - Broken indent (the N-269b batch-script defect).
      - Malformed f-strings / walrus scope / bracket mismatch.
      - `def`/`class` without `:`, `from __future__` misplacement.

    Does NOT catch: missing top-level imports (Python defers name
    resolution to import time; py_compile only parses to bytecode).
    That surface is the runtime-import name-resolution walker
    (follow-up N-335b).
    """
    rel = relpath(path)
    try:
        py_compile.compile(str(path), doraise=True)
    except py_compile.PyCompileError as e:
        pytest.fail(
            f"N-295 R30 py_compile SYNTAX check failed on {rel} — "
            f"the source does not parse.\n\n{e}"
        )
