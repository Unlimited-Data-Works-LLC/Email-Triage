"""install_auto + install_sideload are idempotent.

A second call against a target_dir where every file is already
present + hash-valid should be a fast-path no-op: no download,
no error; updates the installed_at timestamp.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from email_triage.embedding_bits import (
    install_auto, install_sideload, get_install_status,
)


@pytest.mark.asyncio
async def test_install_auto_idempotent_second_call_is_no_op(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    monkeypatch,
):
    """First install succeeds; second call doesn't redownload."""
    target = tmp_path / "runtime-deps"

    # First call: full install
    result1 = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result1.status == "installed"
    state1 = get_install_status(test_db)
    first_installed_at = state1["installed_at"]
    assert first_installed_at is not None

    # Replace _http_download with one that explodes — second call
    # must not invoke it.
    def _explode(url, dest):
        raise AssertionError(
            f"second call should be fast-path but _http_download({url}) fired",
        )
    monkeypatch.setattr(
        "email_triage.embedding_bits._http_download", _explode,
    )

    # Second call: fast-path
    result2 = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result2.status == "installed"
    state2 = get_install_status(test_db)
    assert state2["status"] == "installed"
    # installed_at was refreshed
    assert state2["installed_at"] >= first_installed_at


@pytest.mark.asyncio
async def test_install_sideload_idempotent(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    staged_source_dir: Path,
):
    """Sideload twice into the same target_dir is a clean no-op the
    second time."""
    target = tmp_path / "runtime-deps"

    result1 = await install_sideload(
        conn=test_db, manifest_path=fake_manifest_path,
        source_dir=staged_source_dir, target_dir=target,
    )
    assert result1.status == "installed"

    result2 = await install_sideload(
        conn=test_db, manifest_path=fake_manifest_path,
        source_dir=staged_source_dir, target_dir=target,
    )
    assert result2.status == "installed"


@pytest.mark.asyncio
async def test_fast_path_actually_runs_pip(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    monkeypatch,
):
    """2026-05-18 regression — operator hit this on deploy-host: first install
    failed at pip (disk OOM), wheels survived on disk. Second install
    click triggered the fast-path which previously jumped straight to
    ``status="installed"`` WITHOUT re-running pip — leaving
    ``/app/data/runtime-deps/lib/`` empty and
    ``sentence_transformers`` still un-importable. The state row lied.
    Post-fix the fast-path re-invokes pip + the verify gate.
    """
    target = tmp_path / "runtime-deps"

    # First call: full install (autouse stubs make this fast).
    result1 = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result1.status == "installed"

    # Wipe the marker the pip stub wrote so we can detect the rerun.
    marker = target / ".pip-installed-marker"
    assert marker.exists(), "first call should have written marker"
    marker.unlink()

    # Second call: must re-run pip (i.e. rewrite the marker), not skip
    # to "installed" while leaving the runtime path unpopulated.
    result2 = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result2.status == "installed"
    assert marker.exists(), (
        "fast-path MUST re-invoke pip — pre-fix this assertion failed "
        "because the fast-path silently skipped pip and the marker "
        "was never re-written, while the state row claimed installed"
    )


@pytest.mark.asyncio
async def test_verify_gate_fails_when_runtime_doesnt_import(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    monkeypatch,
):
    """Belt-and-braces: even if pip exits 0, the post-install verify
    gate runs ``runtime_imports_cleanly`` (a real subprocess import of
    sentence_transformers) and catches failures pip alone won't catch
    — most commonly a missing transitive dep (e.g. the 2026-05-18
    ``packaging``-missing regression).

    Force the strong probe to return failure; result MUST be
    ``status="failed"`` with ``PostInstallVerifyFailed``, not the
    previous mis-reported ``installed``.
    """
    target = tmp_path / "runtime-deps"

    # Force the strong probe to fail with a representative error.
    monkeypatch.setattr(
        "email_triage.embedding_bits.runtime_imports_cleanly",
        lambda runtime_deps_path=None: (
            False, "ModuleNotFoundError: No module named 'packaging'",
        ),
    )

    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result.status == "failed", (
        "verify gate must reject when actual import fails; pre-fix "
        "this returned ``installed`` and the operator hit "
        "'imports successfully' in the UI while the live process "
        "couldn't actually use the backend"
    )
    assert result.error_class == "PostInstallVerifyFailed"
    state = get_install_status(test_db)
    assert state["status"] == "failed"
    assert state["last_error_class"] == "PostInstallVerifyFailed"
    # The actual ImportError class + module name must surface in the
    # operator-facing message — otherwise the diagnosis lives only in
    # container logs and the operator has to dig.
    assert "packaging" in (state["last_error_msg"] or ""), (
        "verify-gate error message must carry the underlying import "
        "failure detail (module name, error class) — pre-fix the gate "
        "swallowed the cause behind a generic 'does not import' message"
    )
