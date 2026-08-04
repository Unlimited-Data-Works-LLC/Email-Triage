"""the backlog  — golden-hash → `.gitattributes text eol=lf` meta-pin.

Prime Directive #7 (census the censusers) applied to the golden-hash class.

**Class:** any test that computes ``hashlib.sha256(<X>.read_bytes()).hexdigest()``
under ``tests/``. Two subcategories:

* **CHECKED-IN** — X resolves to a checked-in repo file (``.github/op-approve/
  allowed_signers``, ``scripts/embedding-bits-manifest.json``, …). The hash
  drifts if a Windows checkout CRLF-normalises the file, so a matching
  ``.gitattributes text eol=lf`` entry is REQUIRED. This is the exact drift
  that red-CI'd N-326-C5 on ``1e720601`` (fix-forward ``fed0187e``).
* **RUNTIME-GEN** — X is a tempfile / fixture / snapshot output the test
  itself created. No ``.gitattributes`` coverage possible / needed;
  documented via explicit allow-list entry.

**MEMBERSHIP PREDICATE (strict, count-agnostic):** an ``ast.Call`` matching
``hashlib.sha256(<X>.read_bytes()).hexdigest()`` under ``tests/**/*.py``.
No hand-count — the AST walk is the net. A new site anywhere in ``tests/``
NOT in ``_KNOWN_SITES`` fails LOUD with a categorisation prompt (add either
a CHECKED-IN entry + a ``.gitattributes`` line in the SAME commit, or a
RUNTIME-GEN entry with a one-line justification).

The class-hint's counting_convention (per census methodology rule #2) is
``super-set`` — every ``ast.Call`` under ``tests/`` matching the predicate
is counted; the fail-loud shape means the pin's net is authoritative, not
the ``_KNOWN_SITES`` dict.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from _pin_harness import REPO_ROOT, enclosing_fn, iter_files, parse_module, parse_source, relpath

TESTS_ROOT: Path = REPO_ROOT / "tests"
GITATTRIBUTES: Path = REPO_ROOT / ".gitattributes"


# Every golden-hash site under ``tests/**`` MUST be listed here. The value is
# the repo-relative path of the CHECKED-IN file hashed (requires a matching
# ``text eol=lf`` line in ``.gitattributes``), or ``None`` for a runtime-
# generated file (temp / fixture / snapshot output — no eol=lf needed).
#
# Key: ``(test_relpath, enclosing_fn_qname)`` — repo-relative posix form.
_KNOWN_SITES: dict[tuple[str, str], str | None] = {
    # CHECKED-IN: `.github/op-approve/allowed_signers` — the SSH signing-key
    # trust root. Golden hash lives at `tests/goldens/allowed_signers.sha256`.
    # `.gitattributes text eol=lf` on BOTH added by the DA-panel fix-forward
    # `fed0187e` (N-326-C5) after the same-day CRLF drift red-CI.
    (
        "tests/test_n326_c5_allowed_signers_ssot.py",
        "test_repo_trust_root_matches_golden_hash",
    ): ".github/op-approve/allowed_signers",
    # RUNTIME-GEN: `out = tmp_path / "snap.db"` — a runtime-created SQLite
    # snapshot file. The hash verifies backup_mod.snapshot_db_to_path's own
    # sha256 return matches the on-disk bytes it produced. No checked-in
    # file involved.
    (
        "tests/test_db_snapshot.py",
        "test_snapshot_sha256_matches_written_bytes",
    ): None,
}


def _relpath(p: Path) -> str:
    # Route through the harness relpath so a copy-paste to another meta-pin
    # cannot silently drift the base (R38 lesson).
    return relpath(p, REPO_ROOT)


def _iter_test_files():
    # META-pin — AUDITS the tests/ tree itself, not src/email_triage.
    # Routes through the harness generic walker (`iter_files`) rather
    # than a hand-rolled `TESTS_ROOT.rglob("*.py")` + __pycache__ skip;
    # the harness owns the walk/pycache/sort idiom (PD #6 / R5c), same
    # convergence pattern as `test_ssot_registry_bijection_pin.py`.
    yield from iter_files(TESTS_ROOT, "*.py")


def _is_hash_call(node: ast.AST) -> bool:
    """True iff ``node`` matches ``hashlib.sha256(<X>.read_bytes()).hexdigest()``.

    Handles both attribute-chain (``hashlib.sha256``) and bare-name
    (``from hashlib import sha256; sha256(...)``) callsites.
    """
    if not isinstance(node, ast.Call):
        return False
    # The outer call must be `.hexdigest()`.
    if not (
        isinstance(node.func, ast.Attribute) and node.func.attr == "hexdigest"
    ):
        return False
    inner = node.func.value
    if not isinstance(inner, ast.Call):
        return False
    # Inner call must be `sha256(...)` or `hashlib.sha256(...)`.
    ifunc = inner.func
    is_sha256 = (
        (isinstance(ifunc, ast.Attribute) and ifunc.attr == "sha256")
        or (isinstance(ifunc, ast.Name) and ifunc.id == "sha256")
    )
    if not is_sha256:
        return False
    if len(inner.args) != 1:
        return False
    arg = inner.args[0]
    # The single arg must be `<X>.read_bytes()` — an attribute call on some X.
    if not (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "read_bytes"
    ):
        return False
    return True


def _find_matches_in_tree(tree: ast.AST, relpath: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if _is_hash_call(node):
            fn = enclosing_fn(node) or "<module>"
            matches.append((relpath, fn))
    return matches


def _find_matches_from_source(source: str, relpath: str) -> list[tuple[str, str]]:
    try:
        tree = parse_source(source)
    except SyntaxError:
        return []
    return _find_matches_in_tree(tree, relpath)


def _load_all_sites() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for p in _iter_test_files():
        rel = _relpath(p)
        tree = parse_module(p)
        if tree is None:
            continue
        for site in _find_matches_in_tree(tree, rel):
            found.add(site)
    return found


def _gitattributes_covers(path: str) -> bool:
    """True iff ``.gitattributes`` has a ``text eol=lf`` line covering ``path``.

    Literal-line match only (no glob expansion). CHECKED-IN paths in
    ``_KNOWN_SITES`` MUST be listed literally so the operator can see the
    correspondence at a glance.
    """
    if not GITATTRIBUTES.exists():
        return False
    for line in GITATTRIBUTES.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if not parts:
            continue
        pattern = parts[0]
        attrs = " ".join(parts[1:])
        if pattern == path and "eol=lf" in attrs:
            return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_every_found_site_is_categorised():
    """Every ``hashlib.sha256(<X>.read_bytes()).hexdigest()`` site in
    ``tests/`` must appear in ``_KNOWN_SITES`` (CHECKED-IN with a path OR
    RUNTIME-GEN with ``None``). A new site NOT in the dict fails LOUD."""
    found = _load_all_sites()
    unregistered = found - set(_KNOWN_SITES.keys())
    assert not unregistered, (
        "Unregistered golden-hash site(s) under `tests/`:\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(unregistered))
        + "\n\nAdd to `_KNOWN_SITES` in this file. If the hashed path is a "
        "checked-in file, set the value to its repo-relative posix path AND "
        "add a `<path> text eol=lf` line to `.gitattributes` in the SAME "
        "commit. If it's a runtime-generated file (tempfile / fixture / "
        "snapshot), set the value to `None` and add a one-line justification "
        "comment."
    )
    stale = set(_KNOWN_SITES.keys()) - found
    assert not stale, (
        "Stale entry in `_KNOWN_SITES` (source no longer matches predicate):\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(stale))
    )


def test_checked_in_sites_have_gitattributes_eol_lf():
    """Every CHECKED-IN entry (``path != None``) in ``_KNOWN_SITES`` must
    have a matching ``<path> text eol=lf`` line in ``.gitattributes``."""
    missing: list[tuple[tuple[str, str], str]] = []
    for site, path in _KNOWN_SITES.items():
        if path is None:
            continue
        if not _gitattributes_covers(path):
            missing.append((site, path))
    assert not missing, (
        "CHECKED-IN golden-hash path(s) missing `text eol=lf` in "
        "`.gitattributes`:\n"
        + "\n".join(
            f"  {rel}::{fn} → {path}" for (rel, fn), path in missing
        )
        + "\n\nAdd `<path> text eol=lf` to `.gitattributes` in the same "
        "commit as the golden-hash landing. Without it, a Windows checkout "
        "CRLF-normalises the file and the hash drifts from the Linux value."
    )


def test_pin_has_teeth():
    """Planted-bad-source proof: ``_find_matches`` DOES fire on the predicate.
    The N-135 net-completeness lesson: a pin with no teeth silently degrades
    to green as the codebase drifts. Prime Directive #7."""
    bad_source = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h():\n"
        "    p = Path('nope')\n"
        "    return hashlib.sha256(p.read_bytes()).hexdigest()\n"
    )
    matches = _find_matches_from_source(bad_source, "tests/synthetic_teeth.py")
    assert matches == [("tests/synthetic_teeth.py", "h")], (
        "The AST walker MUST detect the bare `hashlib.sha256(X.read_bytes())"
        ".hexdigest()` pattern. If this fails, the walker itself has drifted "
        "and the CHECKED-IN category is going undetected → silent CRLF-drift "
        "regression waiting to red-CI."
    )
    # Anti-vacuity: a bare `.read_text()` (not `.read_bytes()`) MUST NOT
    # match — the pin scopes to the byte-hash class only.
    good_source = (
        "import hashlib\n"
        "from pathlib import Path\n"
        "def h():\n"
        "    return hashlib.sha256(Path('x').read_text().encode()).hexdigest()\n"
    )
    assert _find_matches_from_source(good_source, "tests/synthetic_ok.py") == []
