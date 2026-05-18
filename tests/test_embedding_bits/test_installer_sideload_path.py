"""install_sideload: copy + hash-verify from a staged source dir."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from email_triage.embedding_bits import (
    install_sideload, get_install_status,
)


@pytest.mark.asyncio
async def test_install_sideload_happy_path(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    staged_source_dir: Path,
):
    """Sideload from a clean source dir → status=installed."""
    target = tmp_path / "runtime-deps"
    result = await install_sideload(
        conn=test_db, manifest_path=fake_manifest_path,
        source_dir=staged_source_dir, target_dir=target,
    )
    assert result.status == "installed"
    state = get_install_status(test_db)
    assert state["install_method"] == "sideload"
    assert (target / "wheels" / "fake_a-1.0.whl").exists()
    assert (target / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"
            / "config.json").exists()


@pytest.mark.asyncio
async def test_install_sideload_does_not_hit_network(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    staged_source_dir: Path,
    monkeypatch,
):
    """Sideload must NOT call _http_download — any call is a bug.

    The privacy-invariant test is the static-source-scan; this is the
    runtime confirmation that the sideload path is truly offline.
    """
    def _explode(url, dest):
        raise AssertionError(
            f"sideload path called _http_download({url}) — "
            "should NOT hit the network",
        )
    monkeypatch.setattr(
        "email_triage.embedding_bits._http_download", _explode,
    )

    target = tmp_path / "runtime-deps"
    result = await install_sideload(
        conn=test_db, manifest_path=fake_manifest_path,
        source_dir=staged_source_dir, target_dir=target,
    )
    assert result.status == "installed"
