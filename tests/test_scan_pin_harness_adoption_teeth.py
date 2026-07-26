"""Teeth test for scripts/leira_discover.scan_pin_harness_adoption.

DA panel N-382 R32 HIGH #2 close (2026-07-10): the scanner IS the census
for the pin-harness-adoption class; per Prime Directive #7 (census the
censusers), the scanner MUST itself carry a teeth test that proves it
detects a live drift shape. Without a teeth test, a future refactor that
silently breaks the scanner (`.glob` → `.iterdir`, or an argument-shape
change to `iter_files`) would degrade the scanner to always-empty output
and quietly re-enable the class of drift the scanner exists to prevent.

Three arms:
- PLANTED-DRIFT: seed a fake pin file with each of the 3 recognised
  drift shapes (`.rglob("*.py")`, `.relative_to(...)`, `.replace("\\", "/")`)
  in a tmp tests-dir and confirm the scanner finds ALL 3.
- CLEAN-FILE: seed a fake pin file that routes ONLY through the harness
  helpers and confirm the scanner returns EMPTY.
- SUBTREE-VISIBILITY: seed a fake pin file under a NESTED subdir
  (`tmp/nested/*_pin.py`) — proves the scanner uses a RECURSIVE walk
  (`rglob`), not a shallow `glob`. This is the exact bug DA panel found:
  the shallow-glob shape was blind to `tests/test_web/*_pin.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Under-test target: scripts/ is not a package; import via sys.path.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "scripts"))
from leira_discover import scan_pin_harness_adoption  # noqa: E402


_DRIFT_SHAPES_PLANT = '''\
"""Planted drift shape — DA teeth test."""
from pathlib import Path

def _walk():
    return list(Path("/x").rglob("*.py"))

def _rel(p, base):
    return str(p.relative_to(base))

def _norm(rel):
    return rel.replace("\\\\", "/")
'''

_CLEAN_PLANT = '''\
"""Clean shape — routes through the harness."""
from _pin_harness import iter_files, relpath

def _walk(root):
    return list(iter_files(root, "*.py"))

def _rel(p, base):
    return relpath(p, base)
'''


def test_scanner_detects_all_three_drift_shapes(tmp_path: Path) -> None:
    """PLANTED-DRIFT arm: the 3 recognised shapes each fire."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    probe = tests_dir / "test_probe_pin.py"
    probe.write_text(_DRIFT_SHAPES_PLANT, encoding="utf-8")

    hits = scan_pin_harness_adoption(_REPO_ROOT / "src" / "email_triage",
                                     tests_dir=tests_dir)
    kinds = {h[2].split()[1] for h in hits}  # extract the .attr name from snippet
    assert hits, "scanner returned NO hits on a file with all 3 planted shapes"
    assert ".rglob()" in " ".join(h[2] for h in hits), (
        f"scanner missed the .rglob() shape (hits: {hits})"
    )
    assert ".relative_to()" in " ".join(h[2] for h in hits), (
        f"scanner missed the .relative_to() shape (hits: {hits})"
    )
    assert ".replace" in " ".join(h[2] for h in hits), (
        f"scanner missed the .replace() shape (hits: {hits})"
    )


def test_scanner_returns_empty_on_clean_pin(tmp_path: Path) -> None:
    """CLEAN-FILE arm: a pin routing only through the harness fires 0 hits."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_clean_pin.py").write_text(_CLEAN_PLANT, encoding="utf-8")

    hits = scan_pin_harness_adoption(_REPO_ROOT / "src" / "email_triage",
                                     tests_dir=tests_dir)
    assert hits == [], (
        f"scanner false-positive on a harness-routed pin: {hits}"
    )


def test_scanner_walks_subdirs_recursively(tmp_path: Path) -> None:
    """SUBTREE-VISIBILITY arm: the DA-caught bug — a NESTED pin file
    must be found. The prior `tests_dir.glob("*_pin.py")` shape was
    BLIND to tests/test_web/*_pin.py; the fix uses `rglob`."""
    tests_dir = tmp_path / "tests"
    (tests_dir / "test_nested").mkdir(parents=True)
    (tests_dir / "test_nested" / "test_probe_pin.py").write_text(
        _DRIFT_SHAPES_PLANT, encoding="utf-8"
    )

    hits = scan_pin_harness_adoption(_REPO_ROOT / "src" / "email_triage",
                                     tests_dir=tests_dir)
    assert hits, (
        "scanner is BLIND to tests/test_web/**/*_pin.py — the DA-caught "
        "non-recursive-glob regression is back"
    )
    hit_files = {h[0] for h in hits}
    assert any("test_nested" in f for f in hit_files), (
        f"scanner surfaced hits but not from the nested subdir: {hit_files}"
    )
