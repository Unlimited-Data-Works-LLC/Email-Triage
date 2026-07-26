"""N-259 R26 structural pin — backup routes through artifact registry (2026-07-03).

Census R26 discovered MED (ondisk-artifact-disposal registry, verifier
LATENT gap): `backup.py::_collect_data_dir_files` hardcoded the literal
`data_dir.glob("msal_cache*.json")` — a NEW per-account artifact
family (registered in `_ondisk_artifacts._BUILDERS` per N-245/N-252)
would be SILENTLY OMITTED from backups, re-forking the run18 #1 CIDI
shape one level up.

N-259 fix: `backup.py` now iterates
`PER_ACCOUNT_ARTIFACT_GLOBS + PER_USER_ARTIFACT_GLOBS` from the
registry, so a new artifact family lands in backups automatically.

WHAT IT PINS (anti-vacuity):

The `backup.py` source textually references either
`PER_ACCOUNT_ARTIFACT_GLOBS` or `PER_USER_ARTIFACT_GLOBS`, ensuring
the collector routes through the registry symbol rather than a
literal glob.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_backup_references_artifact_registry_globs():
    """`backup.py` MUST reference `PER_ACCOUNT_ARTIFACT_GLOBS` (or the
    per-user sibling) — the registry symbol. A refactor that drops the
    symbol reference AND hardcodes a glob literal instead fires this
    pin."""
    path = SRC_ROOT / "backup.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "PER_ACCOUNT_ARTIFACT_GLOBS" in source or "PER_USER_ARTIFACT_GLOBS" in source, (
        "N-259 R26 REGRESSION: `backup.py` no longer references the "
        "artifact-registry glob symbols. Route through "
        "`providers._ondisk_artifacts.PER_ACCOUNT_ARTIFACT_GLOBS +"
        " PER_USER_ARTIFACT_GLOBS` so a new artifact family lands in "
        "backups automatically without editing this collector."
    )
