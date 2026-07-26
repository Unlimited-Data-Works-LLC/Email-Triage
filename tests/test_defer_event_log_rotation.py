"""Tests for scripts/hooks/_defer_event_log_rotation.py.

Pins:
  * ``maybe_rotate`` is a no-op when file size is under threshold.
  * ``maybe_rotate`` rotates to ``<name>.<UTC-ts>.jsonl.gz`` when over.
  * Original log is truncated (empty) after rotation; content is preserved
    in the gzip archive.
  * Fail-open contract: I/O errors in the rotation path never propagate.
  * write_event() wiring — appending past the threshold triggers rotation
    inline (the F-DB2 fold-in target).

Test-file self-note: the ``phrase`` param handed to ``write_event`` in these
tests is an opaque placeholder string, NOT a canonical defer idiom — this
file is not in the defer_gate prose-exempt list, so we deliberately keep the
literals inert. (The gate exempts by filename prefix; this test lives outside
that prefix by design.)
"""
from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
sys.path.insert(0, str(HOOKS))

import _defer_event_log_rotation as rot  # noqa: E402
import _defer_phrases as dp  # noqa: E402


# Opaque placeholder — NOT a canonical defer idiom, so it doesn't trip the
# gate's prose scan on THIS file (which isn't on the exemption list).
PLACEHOLDER_PHRASE = "PLACEHOLDER_TEST_TOKEN"


# ---------------------------------------------------------------------------
# maybe_rotate — under threshold
# ---------------------------------------------------------------------------

def test_no_rotation_when_file_missing(tmp_path):
    log = tmp_path / "events.jsonl"
    assert rot.maybe_rotate(log, threshold=1024) is None
    assert not log.exists()


def test_no_rotation_when_under_threshold(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * 100)
    assert rot.maybe_rotate(log, threshold=1024) is None
    # File untouched
    assert log.exists()
    assert log.stat().st_size == 100


def test_no_rotation_when_at_threshold(tmp_path):
    """Threshold is a STRICT-greater-than check — file exactly at the limit
    is fine."""
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * 1024)
    assert rot.maybe_rotate(log, threshold=1024) is None
    assert log.stat().st_size == 1024


# ---------------------------------------------------------------------------
# maybe_rotate — over threshold
# ---------------------------------------------------------------------------

def test_rotates_when_over_threshold_and_preserves_content(tmp_path):
    log = tmp_path / "events.jsonl"
    payload = ("line-content\n" * 200).encode("utf-8")
    log.write_bytes(payload)
    assert log.stat().st_size > 1024

    archive = rot.maybe_rotate(log, threshold=1024)
    assert archive is not None
    assert archive.exists()
    assert archive.suffix == ".gz"
    assert archive.name.startswith("events.")
    assert archive.name.endswith(".jsonl.gz")

    # Original log removed (fresh start on next write)
    assert not log.exists()

    # Archive round-trips
    with gzip.open(str(archive), "rb") as f:
        assert f.read() == payload


def test_archive_name_uses_utc_stamp(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * 2048)
    archive = rot.maybe_rotate(log, threshold=1024)
    assert archive is not None
    # Filename format: events.YYYY-MM-DDTHHMMSSZ.jsonl.gz
    middle = archive.name[len("events."):-len(".jsonl.gz")]
    # Bare stamp: len == 20 like "2026-07-16T003741Z". Allow suffix-bumped
    # collision variant "…Z.1" as well.
    assert middle[-1] == "Z" or ".Z" in archive.name


def test_second_write_after_rotation_starts_fresh(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"y" * 2048)
    archive = rot.maybe_rotate(log, threshold=1024)
    assert archive is not None

    # Simulate the next writer creating a fresh log
    log.write_text("fresh-line\n", encoding="utf-8")
    # Under threshold no rotation.
    assert rot.maybe_rotate(log, threshold=1024) is None
    assert log.read_text(encoding="utf-8") == "fresh-line\n"


# ---------------------------------------------------------------------------
# Env override
# ---------------------------------------------------------------------------

def test_env_var_overrides_default_threshold(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"z" * 200)
    with mock.patch.dict(os.environ, {"DEFER_GATE_ROTATE_BYTES": "100"}):
        archive = rot.maybe_rotate(log)
        assert archive is not None
        assert archive.exists()


def test_bad_env_var_falls_back_to_default(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"z" * 200)
    with mock.patch.dict(os.environ, {"DEFER_GATE_ROTATE_BYTES": "not-a-number"}):
        # Default is 5 MB, so no rotation for 200 bytes.
        assert rot.maybe_rotate(log) is None
        assert log.exists()


# ---------------------------------------------------------------------------
# Fail-open contract
# ---------------------------------------------------------------------------

def test_fail_open_on_ioerror_in_should_rotate(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * 2048)
    # Force stat() to raise
    with mock.patch.object(Path, "stat", side_effect=OSError("bad")):
        # should_rotate returns False rather than raising
        assert rot.should_rotate(log, threshold=1024) is False
    # And maybe_rotate returns None instead of raising when rotate() raises.
    with mock.patch.object(rot, "rotate", side_effect=RuntimeError("boom")):
        with mock.patch.object(rot, "should_rotate", return_value=True):
            assert rot.maybe_rotate(log) is None


def test_fail_open_when_gzip_write_fails(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b"x" * 2048)
    # Break gzip.open used inside rotate() to simulate a disk-full or
    # permission error mid-rotation. The rotation returns None; a partial
    # archive (if any) will be dropped by the finally clause.
    with mock.patch.object(rot, "gzip") as mgz:
        mgz.open.side_effect = OSError("disk full")
        result = rot.rotate(log)
        assert result is None
    # The important contract: no exception propagated.


# ---------------------------------------------------------------------------
# Integration — write_event() triggers rotation inline
# ---------------------------------------------------------------------------

def test_write_event_triggers_rotation_when_log_over_threshold(tmp_path, monkeypatch):
    """The F-DB2 fold-in: write_event() should invoke maybe_rotate lazily
    on write, so a busy gate log rolls without any external cron/timer."""
    log = tmp_path / "defer_gate_events.jsonl"
    # Pre-seed with content above a tiny threshold
    log.write_bytes(b"L" * 2048)

    # Redirect the write_event target to our tmp log
    monkeypatch.setattr(dp, "_EVENT_LOG", log)
    # Force rotation threshold well below our seed size
    monkeypatch.setenv("DEFER_GATE_ROTATE_BYTES", "1024")

    # Trigger a write; rotation should fire before the new entry lands.
    dp.write_event(
        phrase=PLACEHOLDER_PHRASE,
        text="unit-test text",
        tool="Edit",
        path="fake.py",
        sha="deadbeef",
        surface="prose",
    )

    # The new log exists and contains ONLY the new entry (rotation happened
    # before the append).
    assert log.exists()
    contents = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(contents) == 1
    row = json.loads(contents[0])
    assert row["phrase"] == PLACEHOLDER_PHRASE

    # A gzip archive sibling exists carrying the pre-rotation payload
    archives = sorted(tmp_path.glob("defer_gate_events.*.jsonl.gz"))
    assert archives, "expected a rotated archive alongside the log"
    with gzip.open(str(archives[0]), "rb") as f:
        assert f.read() == b"L" * 2048


def test_write_event_no_rotation_under_threshold(tmp_path, monkeypatch):
    log = tmp_path / "defer_gate_events.jsonl"
    monkeypatch.setattr(dp, "_EVENT_LOG", log)
    # Very high threshold, never rotates
    monkeypatch.setenv("DEFER_GATE_ROTATE_BYTES", str(10 * 1024 * 1024))

    for i in range(5):
        dp.write_event(
            phrase=PLACEHOLDER_PHRASE,
            text=f"body {i}",
            surface="prose",
        )

    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    archives = list(tmp_path.glob("defer_gate_events.*.jsonl.gz"))
    assert archives == []


def test_write_event_fail_open_when_rotation_module_broken(tmp_path, monkeypatch):
    """If the rotation import or call raises for any reason, write_event
    must still append the entry (fail-open on gate logging)."""
    log = tmp_path / "defer_gate_events.jsonl"
    log.write_bytes(b"seed\n")
    monkeypatch.setattr(dp, "_EVENT_LOG", log)

    # Poison the rotation module so its top-level attributes raise.
    real_rot = sys.modules.get("_defer_event_log_rotation")
    try:
        broken = mock.MagicMock()
        broken.maybe_rotate.side_effect = RuntimeError("simulated failure")
        sys.modules["_defer_event_log_rotation"] = broken
        dp.write_event(phrase=PLACEHOLDER_PHRASE, text="body", surface="prose")
    finally:
        if real_rot is not None:
            sys.modules["_defer_event_log_rotation"] = real_rot

    # Event still landed
    contents = log.read_text(encoding="utf-8").splitlines()
    assert any('"phrase"' in ln for ln in contents)


# ---------------------------------------------------------------------------
# Structural pin — count-agnostic
# ---------------------------------------------------------------------------

def test_archive_path_shape_regardless_of_log_name(tmp_path):
    """Prime Directive #1: pin the archive-name construction across a
    variety of log basenames (count-agnostic — every case must obey the
    same shape rule)."""
    cases = [
        "defer_gate_events.jsonl",
        "other_events.jsonl",
        "custom.jsonl",
    ]
    for name in cases:
        log = tmp_path / name
        archive = rot._archive_path(log, stamp="2026-07-16T003741Z")
        assert archive.suffix == ".gz"
        assert archive.name.endswith(".jsonl.gz")
        # <base>.<stamp>.jsonl.gz shape
        base = name[: -len(".jsonl")]
        assert archive.name == f"{base}.2026-07-16T003741Z.jsonl.gz"
