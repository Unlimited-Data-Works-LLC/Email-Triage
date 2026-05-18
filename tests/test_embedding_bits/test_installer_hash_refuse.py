"""Hard hash-refusal: install_auto + install_sideload trip on mismatched bytes.

This is the key security invariant — the installer MUST refuse any
file whose SHA-256 does not match the manifest, in both auto + sideload
paths. No skip-hash override, no --force.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from email_triage.embedding_bits import (
    install_auto, install_sideload, get_install_status,
)


@pytest.mark.asyncio
async def test_install_auto_refuses_persistent_hash_mismatch(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    monkeypatch,
):
    """All 3 attempts return garbage → status=failed; HashMismatch surfaced."""
    def _fake_download(url: str, dest: Path) -> int:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"persistent-garbage-bytes")
        return 24

    def _fast_sleep(secs):
        pass

    monkeypatch.setattr(
        "email_triage.embedding_bits._http_download", _fake_download,
    )
    monkeypatch.setattr(
        "email_triage.embedding_bits.time.sleep", _fast_sleep,
    )

    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )

    assert result.status == "failed"
    assert result.error_class == "HashMismatch"
    # Offending filename is surfaced in error_msg (first wheel since
    # that's where the loop trips)
    assert "fake_a-1.0.whl" in (result.error_msg or "")

    state = get_install_status(test_db)
    assert state["status"] == "failed"
    assert state["last_error_class"] == "HashMismatch"
    assert state["attempt_count"] >= 1


@pytest.mark.asyncio
async def test_install_sideload_refuses_mismatched_file(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    staged_source_dir: Path,
):
    """Tamper with one staged file → status=failed; sideload doesn't
    trust operator-staged bytes."""
    # Corrupt the wheel A file in the staged source
    bad = staged_source_dir / "wheels" / "fake_a-1.0.whl"
    bad.write_bytes(b"tampered-sideload-bytes")

    target = tmp_path / "runtime-deps"
    result = await install_sideload(
        conn=test_db, manifest_path=fake_manifest_path,
        source_dir=staged_source_dir, target_dir=target,
    )

    assert result.status == "failed"
    assert result.error_class == "HashMismatch"
    assert "fake_a-1.0.whl" in (result.error_msg or "")

    state = get_install_status(test_db)
    assert state["status"] == "failed"
    assert state["last_error_class"] == "HashMismatch"


@pytest.mark.asyncio
async def test_install_refuses_placeholder_manifest(
    test_db: sqlite3.Connection,
    tmp_path: Path,
):
    """The skeleton manifest with PLACEHOLDER_*_SHA256 strings hard-fails
    the entry-point check.

    Mirrors the shipped scripts/embedding-bits-manifest.json which is
    a PLACEHOLDER skeleton until release-cut runs
    scripts/build-embedding-bits-manifest.py.
    """
    import json
    placeholder_path = tmp_path / "placeholder-manifest.json"
    placeholder_path.write_text(json.dumps({
        "manifest_version": 1,
        "wheels": [{
            "name": "torch", "version": "2.5.1+cpu",
            "filename": "torch.whl", "url": "https://example.test/torch.whl",
            "sha256": "PLACEHOLDER_TORCH_SHA256_64HEX",
            "size_bytes": 0,
        }],
        "models": [],
    }))

    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=placeholder_path, target_dir=target,
    )
    assert result.status == "failed"
    # Specific error class — RuntimeError, message names the placeholder
    assert "PLACEHOLDER" in (result.error_msg or "") or \
           "placeholder" in (result.error_msg or "")
