"""install_auto: end-to-end through state transitions + retry logic."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from email_triage.embedding_bits import install_auto, get_install_status


@pytest.mark.asyncio
async def test_install_auto_happy_path(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
):
    """Clean install: state -> installed; files on disk + hashes match."""
    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )

    assert result.status == "installed"
    assert result.error_class is None
    assert result.files_installed == 3  # 2 wheels + 1 model file

    # Files on disk
    assert (target / "wheels" / "fake_a-1.0.whl").exists()
    assert (target / "wheels" / "fake_b-2.0.whl").exists()
    assert (target / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"
            / "config.json").exists()
    # pip-install marker (from the conftest stub)
    assert (target / ".pip-installed-marker").exists()

    # State row
    state = get_install_status(test_db)
    assert state["status"] == "installed"
    assert state["install_method"] == "auto"
    assert state["installed_at"] is not None
    assert state["last_error_class"] is None
    assert state["progress_files_done"] == 3


@pytest.mark.asyncio
async def test_install_auto_transitions_through_states(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    monkeypatch,
):
    """The progress_callback sees downloading -> verifying -> installing
    -> installed in order."""
    seen_statuses: list[str] = []

    def _cb(payload: dict) -> None:
        s = payload.get("status")
        if s and (not seen_statuses or seen_statuses[-1] != s):
            seen_statuses.append(s)

    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path,
        target_dir=target, progress_callback=_cb,
    )

    assert result.status == "installed"
    # All four phases must appear in order.
    for phase in ("downloading", "verifying", "installing", "installed"):
        assert phase in seen_statuses, (
            f"Phase {phase!r} missing from {seen_statuses!r}"
        )
    assert seen_statuses.index("downloading") < seen_statuses.index("verifying")
    assert seen_statuses.index("verifying") < seen_statuses.index("installing")
    assert seen_statuses.index("installing") < seen_statuses.index("installed")


@pytest.mark.asyncio
async def test_install_auto_retry_on_transient_then_succeeds(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
    url_to_bytes: dict[str, bytes],
    monkeypatch,
):
    """Two transient hash-mismatches, third attempt clean.

    Replaces _http_download with one that returns garbage on the
    first 2 calls then good bytes on the 3rd. The installer's retry
    loop (3 attempts) should succeed.
    """
    call_counts: dict[str, int] = {}
    sleeps: list[float] = []

    def _fake_download(url: str, dest: Path) -> int:
        call_counts[url] = call_counts.get(url, 0) + 1
        dest.parent.mkdir(parents=True, exist_ok=True)
        if url in url_to_bytes:
            if call_counts[url] <= 2:
                # Garbage bytes to trip HashMismatch
                dest.write_bytes(b"garbage-attempt-" + str(
                    call_counts[url],
                ).encode())
                return 16
            dest.write_bytes(url_to_bytes[url])
            return len(url_to_bytes[url])
        raise FileNotFoundError(url)

    def _fake_sleep(secs: float) -> None:
        sleeps.append(secs)

    monkeypatch.setattr(
        "email_triage.embedding_bits._http_download", _fake_download,
    )
    monkeypatch.setattr(
        "email_triage.embedding_bits.time.sleep", _fake_sleep,
    )

    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result.status == "installed"
    # Each URL needed 3 attempts (2 failures + 1 success)
    for url in url_to_bytes:
        assert call_counts[url] == 3, (
            f"Expected 3 attempts on {url}, got {call_counts[url]}"
        )
    # Backoff sleeps fired (1s and 4s between the 3 attempts; 16s
    # would only fire on a 4th attempt which doesn't happen here)
    assert any(s == 1 for s in sleeps)
    assert any(s == 4 for s in sleeps)


@pytest.mark.asyncio
async def test_install_auto_writes_manifest_sha(
    test_db: sqlite3.Connection,
    tmp_path: Path,
    fake_manifest_path: Path,
):
    """install_state.manifest_sha256 is populated with a 64-char hex
    string after a successful install."""
    target = tmp_path / "runtime-deps"
    result = await install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result.status == "installed"
    state = get_install_status(test_db)
    sha = state["manifest_sha256"]
    assert sha is not None
    assert len(sha) == 64
    int(sha, 16)  # hex-parseable
