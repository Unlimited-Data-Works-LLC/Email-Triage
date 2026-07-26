"""N-421 Drive-3 close-out task  — Meta-pin detection HARDENING.

Extends the N-411 src-declaration meta-pin
(`tests/test_ssot_src_declaration_registered_pin.py`) with two independent
tightening axes so the pin's blind spots do not silently exempt future drift:

  1. **AST-docstring-scoped detection** (via `ast.get_docstring` at
     Module / ClassDef / FunctionDef / AsyncFunctionDef scope) — the
     original detector walks raw source text line-by-line, so a stray
     `#` comment mentioning *"single source of truth"* in a reader-side
     file (e.g. *"# Note: this is the single source of truth for X, see
     other_module"*) falsely counts as a declaration. Docstring-anchored
     detection only fires on ACTUAL declarations that live at a named
     lexical scope, matching Prime Directive 1's intent (*"Every SSOT
     ships its count-agnostic structural pin in the same change"*).

  2. **§3 column-specific coverage** — the original registry-check is a
     whole-doc substring match (`rel in playbook_text`). A src path
     mentioned in ANOTHER row's prose (my Drive-3 task  §3 row first-
     draft tripped this — mentioning `retry_backoff.py` in the N-228 row's
     prose marked that file as "registered") false-positives. Column-
     specific coverage parses the §3 markdown table and checks the
     path against the SSOT (column 2) + Structural pin (column 3) cells
     only — the two cells that MUST reference the src file when it is
     genuinely registered.

Both checks are ADDITIVE — the original pin still runs; this pin adds
tighter probes that are expected to converge on the same registration
decisions. Any divergence between the two checks IS the drift signal.

Reuses `_pin_harness` per PD#6. Rot-guard PD#7 on both new detectors'
allow-lists (inherit from the original pin's `_UNREGISTERED_ALLOW` where
applicable). Teeth via planted-fake docstring + planted-fake row.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    REPO_ROOT,
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_PLAYBOOK = REPO_ROOT / "docs" / "ssot-and-divergence-playbook.md"


_SSOT_DECLARATION_RE = re.compile(
    r"single\s+source\s+of\s+truth",
    re.IGNORECASE,
)


# Inherit the same allow-list from the original pin so exemptions stay
# consistent. Import to avoid drift.
from test_ssot_src_declaration_registered_pin import _UNREGISTERED_ALLOW  # noqa: E402


# Hardened-detector-only allow-list. Entries caught by the AST-docstring
# scope + missed by the raw-text scan (typically due to multi-line
# docstring phrase splits the raw-text scan can't reassemble). Each entry
# MUST carry a stated reason. Rot-guarded via `test_hardened_allow_no_stale`.
_HARDENED_ALLOW: dict[str, str] = {
    # N-411 (2026-07-14) resolved actions/base.py: the §3 registry row for
    # the action-log `extra=` shape now cites the src file explicitly
    # (`src/email_triage/actions/base.py::build_action_log_extras`) so the
    # column-specific check finds it directly — no allow-list entry needed.
    "actions/sent_mail_index.py": (
        "N-421 hardened caught 2026-07-13 READER: `_strip_quoted` at line "
        "190 REFERENCES the SSOT in `actions/style_profile.py` (multi-line "
        "docstring `\"keep a single\\nsource of truth for X\"`) — the raw-"
        "text scan missed the phrase split across lines. Not a declaration; "
        "consumer of `actions/style_profile._strip_quoted`."
    ),
}


# ---------------------------------------------------------------------------
# Detector 1 — AST-docstring-scoped SSOT declaration detection
# ---------------------------------------------------------------------------


def _ast_docstring_declarations(path):
    """Yield ``(lineno, docstring_snippet)`` for every AST-docstring on a
    Module / ClassDef / FunctionDef / AsyncFunctionDef that contains the
    canonical SSOT-declaration phrase (case-insensitive).

    This is STRICTLY narrower than the raw-text detector — it only fires
    on phrase-in-actual-docstring, not phrase-in-`#`-comment. That's the
    intent: an SSOT declaration lives in a lexical-scope docstring where
    the reader will see it, not in a stray comment.
    """
    tree = parse_module(path)
    if tree is None:
        return
    scoped_nodes = (
        ast.Module,
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
    )
    for node in ast.walk(tree):
        if not isinstance(node, scoped_nodes):
            continue
        ds = ast.get_docstring(node)
        if ds and _SSOT_DECLARATION_RE.search(ds):
            snippet = ds.replace("\n", " ").strip()[:100]
            lineno = getattr(node, "lineno", 1)
            yield lineno, snippet


def _src_files_with_ast_declarations() -> dict[str, list[int]]:
    """Return ``{relpath: [linenos]}`` for every src file whose AST-docstrings
    contain an SSOT declaration."""
    out: dict[str, list[int]] = {}
    for path in iter_src_files():
        rel = relpath(path)
        hits = [lineno for lineno, _ in _ast_docstring_declarations(path)]
        if hits:
            out[rel] = hits
    return out


# ---------------------------------------------------------------------------
# Detector 2 — §3 column-specific coverage
# ---------------------------------------------------------------------------


def _playbook_text() -> str:
    return _PLAYBOOK.read_text(encoding="utf-8")


def _playbook_ssot_and_pin_cells(playbook_text: str) -> list[tuple[str, str]]:
    """Parse the §3 markdown table and return ``[(ssot_cell, pin_cell), ...]``
    for every row. Skips the header row and the separator ``|---|`` row.

    The §3 table has 4 columns: ``| Operation class | SSOT | Structural pin
    | State |``. We index cells 2 (SSOT) + 3 (Structural pin) — these are
    the two cells that MUST reference the src file when a row is genuinely
    registering that file. The Operation-class cell (1) may mention a src
    path in its prose but that reference alone does NOT count as
    registration under this tightened check.

    Returns cells with markdown escapes preserved so a caller doing a
    substring match still gets the same behavior as the whole-doc check.
    """
    lines = playbook_text.split("\n")
    cells: list[tuple[str, str]] = []
    in_table = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("| Operation class"):
            in_table = True
            continue
        if not in_table:
            continue
        if not stripped.startswith("|"):
            # table ended
            break
        if stripped.startswith("|---") or stripped.startswith("| ---"):
            continue
        parts = [p.strip() for p in stripped.split("|")]
        # parts = ["", op-class, ssot, pin, state, ""]
        if len(parts) >= 5:
            cells.append((parts[2], parts[3]))
    return cells


def _src_file_in_ssot_or_pin_column(rel: str, playbook_text: str) -> bool:
    """Column-specific coverage check — the src path must appear in the SSOT
    cell OR the Structural-pin cell of some §3 row. A mention in the
    Operation-class column's prose is intentionally NOT sufficient (that
    was the whole-doc-substring false-positive class)."""
    for ssot_cell, pin_cell in _playbook_ssot_and_pin_cells(playbook_text):
        if rel in ssot_cell or rel in pin_cell:
            return True
    return False


# ---------------------------------------------------------------------------
# Pin 1 — AST-docstring declarations are registered or allow-listed
# ---------------------------------------------------------------------------


def test_ast_docstring_declarations_are_registered_or_allowed():
    """Every AST-docstring-scoped SSOT declaration MUST correspond to a §3
    SSOT-or-Pin-cell match OR an entry in `_UNREGISTERED_ALLOW`. This is a
    STRICTER version of the original pin's forward-coverage check.
    """
    playbook = _playbook_text()
    declarations = _src_files_with_ast_declarations()
    unregistered: list[str] = []
    for rel, linenos in declarations.items():
        if _src_file_in_ssot_or_pin_column(rel, playbook):
            continue
        if rel in _UNREGISTERED_ALLOW:
            continue
        if rel in _HARDENED_ALLOW:
            continue
        unregistered.append(f"  {rel}  (docstring linenos: {linenos})")
    assert not unregistered, (
        "N-421 AST-docstring-scoped SSOT-declaration coverage gap — src "
        "file(s) declare `Single source of truth` in an actual docstring "
        "(not a `#` comment) but are neither §3-registered in the SSOT or "
        "Structural-pin column NOR on `_UNREGISTERED_ALLOW`.\n\n"
        + "\n".join(unregistered)
    )


# ---------------------------------------------------------------------------
# Pin 2 — column-specific coverage matches whole-doc coverage where expected
# ---------------------------------------------------------------------------


def test_column_specific_coverage_agrees_with_whole_doc_for_known_registered():
    """For every src file that the original whole-doc-substring check
    considers "registered", the column-specific check MUST also consider
    it registered. A divergence means the whole-doc check false-positive'd
    on a prose mention in the Operation-class column — which is the exact
    drift class this hardening exists to catch (my Drive-3 task  first-
    draft `retry_backoff.py`-in-prose incident).
    """
    playbook = _playbook_text()
    # Import the original pin's declarations helper for parity
    from test_ssot_src_declaration_registered_pin import _src_files_with_declarations
    declarations = _src_files_with_declarations()
    divergences: list[str] = []
    for rel in sorted(declarations):
        whole_doc = rel in playbook
        column_match = _src_file_in_ssot_or_pin_column(rel, playbook)
        if whole_doc and not column_match:
            divergences.append(
                f"  {rel}  — whole-doc-substring TRUE (prose mention?) "
                "but column-specific FALSE (not in SSOT/Pin cells). This "
                "is the false-positive class the original pin has; move "
                "the file to `_UNREGISTERED_ALLOW` OR add a proper §3 "
                "row placing the src path in the SSOT or Pin cell."
            )
    assert not divergences, (
        "N-421 whole-doc-vs-column-specific registry divergence — some src "
        "file(s) appear in playbook prose but NOT in the SSOT or Pin cells "
        "of any §3 row. The whole-doc-substring check is over-attributing "
        "coverage.\n\n" + "\n".join(divergences)
    )


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------


def test_hardened_allow_no_stale():
    """PD#7 rot-guard: every `_HARDENED_ALLOW` entry MUST correspond to a
    live src file whose AST-docstring STILL contains an SSOT declaration
    phrase (else the exemption is dead weight).
    """
    declarations = _src_files_with_ast_declarations()
    stale: list[str] = []
    for rel in sorted(_HARDENED_ALLOW):
        if rel not in declarations:
            stale.append(f"  {rel}  — no AST-docstring declaration on HEAD")
    assert not stale, (
        "N-421 hardened rot-guard: `_HARDENED_ALLOW` has stale entries.\n\n"
        + "\n".join(stale)
    )


def test_pin_has_teeth():
    """Three planted-fake probes: (a) the docstring detector fires on a
    canonical planted docstring; (b) does NOT fire on a `#` comment with
    the same phrase; (c) the column parser recovers the right cell count
    for the current playbook + rejects a planted fake path.
    """
    # (a) planted docstring — must be detected
    module_src = '"""This is the single source of truth for X."""\n'
    tree = ast.parse(module_src)
    scoped = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    hit = False
    for node in ast.walk(tree):
        if not isinstance(node, scoped):
            continue
        ds = ast.get_docstring(node)
        if ds and _SSOT_DECLARATION_RE.search(ds):
            hit = True
            break
    assert hit, (
        "teeth: canonical docstring declaration not detected — pin is "
        "vacuously silent"
    )

    # (b) `#` comment — must NOT fire (ast.get_docstring only reads
    #     actual docstrings, not comments)
    comment_only = "# This is the single source of truth for Y.\n"
    tree_c = ast.parse(comment_only)
    hit_c = False
    for node in ast.walk(tree_c):
        if not isinstance(node, scoped):
            continue
        ds = ast.get_docstring(node)
        if ds and _SSOT_DECLARATION_RE.search(ds):
            hit_c = True
            break
    assert not hit_c, (
        "teeth: docstring detector incorrectly fired on a `#` comment — "
        "the whole point of the AST-docstring scope is to reject those"
    )

    # (c) column parser produces at least a few rows for the current
    #     playbook (there are 20+ registered SSOTs); and a planted fake
    #     path is NOT in any SSOT/Pin cell.
    playbook = _playbook_text()
    cells = _playbook_ssot_and_pin_cells(playbook)
    assert len(cells) >= 10, (
        f"teeth: column parser recovered too few cells ({len(cells)}) — "
        "either parser is broken or playbook §3 lost most of its rows"
    )
    fake = "web/definitely_not_in_playbook_xyz.py"
    assert not _src_file_in_ssot_or_pin_column(fake, playbook), (
        "teeth: planted fake path unexpectedly matched a §3 SSOT/Pin cell"
    )
