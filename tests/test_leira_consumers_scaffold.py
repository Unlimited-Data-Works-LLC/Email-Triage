"""test_leira_consumers_scaffold.py — teeth test for the llm-host offload stack
Consumers #5-#9 added 2026-07-02.

Purpose: ensure each new consumer script (a) imports cleanly, (b) exposes a
`main` entrypoint, (c) has an argparse-based `--help` that exits 0. This is
a scaffold-level test — actual llm-host LLM calls are gated behind the runtime
`leira_prepass` module and NOT exercised here (requires network + a live
llm-host endpoint on the deploy host).

Structural pin: any NEW `scripts/leira_*.py` script MUST appear in the
`_CONSUMERS` list below — the walk catches drift.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

_CONSUMERS_2026_07_02 = [
    "leira_docs_summarizer.py",   # #5
    "leira_pr_prereview.py",      # #6
    "leira_flag_advisor.py",      # #7
    "leira_newsletter_extract.py",  # #8
    "leira_style_precompute.py",  # #9
    "leira_verify_fix.py",        #  (Improvement #3)
    "leira_discover.py",          #  (Improvement #6)
    "leira_hardcode_scanner.py",  #  (N-231 R22 — scope-aware hardcode scanner)
]

# Non-consumer helpers added 2026-07-02 (Improvements #1, #2, #4). These
# are libraries the consumers import — NOT their own runnable Consumer, so
# they're excluded from the drift guard's `_ALL_CONSUMERS` list via the
# name-prefix guard in `test_no_new_leira_consumer_without_test_update`.
_LEIRA_HELPERS_2026_07_02 = [
    "leira_class_hints.py",       # Improvement #1
    "leira_cache.py",             # Improvement #4
]

# Pre-existing consumers (baseline; drift-guard below asserts these + the new
# five are ALL that exist on-disk — a NEW consumer requires a test update).
_CONSUMERS_PREEXISTING = [
    "leira_census_prepass.py",
    "leira_verify_prepass.py",
    "leira_draft.py",
    "leira_log_triage.py",
]

# Consumers landed 2026-07-15 — defer-language sweep over session JSONL /
# memory drawers / audit reports / commit log / the backlog. Writes verdicts
# + tables to defer_sweep/ at repo root.
_CONSUMERS_2026_07_15 = [
    "leira_defer_sweep.py",       #  (all-history defer-language census)
]

_ALL_CONSUMERS = _CONSUMERS_PREEXISTING + _CONSUMERS_2026_07_02 + _CONSUMERS_2026_07_15


_CONSUMERS_WITH_SCAFFOLD = _CONSUMERS_2026_07_02 + _CONSUMERS_2026_07_15


@pytest.mark.parametrize("script", _CONSUMERS_WITH_SCAFFOLD)
def test_consumer_imports(script):
    """Every Consumer added 2026-07-02 or later imports without error and
    exposes a `main` entrypoint."""
    path = _SCRIPTS_DIR / script
    assert path.is_file(), f"{script} missing on-disk"
    module_stem = path.stem
    r = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, r'{_SCRIPTS_DIR}'); "
         f"import {module_stem}; assert hasattr({module_stem}, 'main')"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, f"{script} import failed: {r.stderr[:500]}"


@pytest.mark.parametrize("script", _CONSUMERS_WITH_SCAFFOLD)
def test_consumer_help_exits_zero(script):
    """--help exits 0 (argparse hookup is present)."""
    path = _SCRIPTS_DIR / script
    r = subprocess.run(
        [sys.executable, str(path), "--help"],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, f"{script} --help exit={r.returncode}: {r.stderr[:300]}"
    assert "usage:" in r.stdout.lower(), f"{script} --help output has no `usage:`"


def test_no_new_leira_consumer_without_test_update():
    """DRIFT GUARD: enumerate all `scripts/leira_*.py` on-disk and require the
    file list to match `_ALL_CONSUMERS`. Adding a new Consumer  (or a helper
    script matching the `leira_*.py` prefix) MUST update this test — otherwise
    the new consumer ships without a scaffold-level regression covering it.

    Waivable via `_ALL_CONSUMERS` list update OR renaming the helper to
    something outside the `leira_*.py` prefix if it isn't a real Consumer."""
    on_disk = sorted(
        p.name for p in _SCRIPTS_DIR.glob("leira_*.py")
        if p.is_file() and p.name not in {
            "leira_prepass.py", "leira_config.py",
            # 2026-07-02 helpers (Improvements #1, #4) — not runnable Consumers.
            "leira_class_hints.py", "leira_cache.py",
        }
    )
    expected = sorted(_ALL_CONSUMERS)
    assert on_disk == expected, (
        f"llm-host consumer drift: on-disk={on_disk}; expected={expected}. "
        "Add the new consumer to `_ALL_CONSUMERS` or rename the helper."
    )
