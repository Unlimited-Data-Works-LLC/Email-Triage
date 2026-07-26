"""Regression tests for verified-test.py auto-include ratchet+SSOT pin sweep.

Anchors: feedback_pre_push_ratchet_pin_sweep — build_queue_2026-07-13 punch .
The helper `_augment_args_with_ratchet_sweep` MUST auto-add cross-cutting
`tests/test_n*_*_ratchet_pin.py` + `tests/test_n*_*_ssot_pin.py` when the
staged diff touches `src/`; MUST bypass on `VERIFIED_TEST_NO_AUTO=1`; MUST
de-duplicate against paths the caller already passed.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verified-test.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("verified_test", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def vt():
    return _load_module()


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Bare git repo with a src/ dir and two ratchet+ssot pin files under tests/."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "src").mkdir()
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_n001_foo_ratchet_pin.py").write_text("# stub\n")
    (tests / "test_n002_bar_ssot_pin.py").write_text("# stub\n")
    (tests / "test_unrelated.py").write_text("# stub\n")
    return tmp_path


def test_staged_touches_src_true_when_src_staged(vt, fake_repo):
    (fake_repo / "src" / "foo.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "src/foo.py"], cwd=fake_repo, check=True)
    assert vt._staged_touches_src(str(fake_repo)) is True


def test_staged_touches_src_false_when_only_tests_staged(vt, fake_repo):
    (fake_repo / "tests" / "test_new.py").write_text("# stub\n")
    subprocess.run(["git", "add", "tests/test_new.py"], cwd=fake_repo, check=True)
    assert vt._staged_touches_src(str(fake_repo)) is False


def test_cross_cutting_pin_files_globs_both_patterns(vt, fake_repo):
    found = vt._cross_cutting_pin_files(str(fake_repo))
    names = {Path(p).name for p in found}
    assert names == {"test_n001_foo_ratchet_pin.py", "test_n002_bar_ssot_pin.py"}


def test_augment_adds_pins_when_src_staged(vt, fake_repo, monkeypatch):
    monkeypatch.delenv("VERIFIED_TEST_NO_AUTO", raising=False)
    (fake_repo / "src" / "foo.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "src/foo.py"], cwd=fake_repo, check=True)
    args, added = vt._augment_args_with_ratchet_sweep(["-q"], str(fake_repo))
    assert args[0] == "-q"
    assert len(added) == 2
    assert all(p.endswith(".py") for p in added)


def test_augment_noop_when_no_src_change(vt, fake_repo, monkeypatch):
    monkeypatch.delenv("VERIFIED_TEST_NO_AUTO", raising=False)
    (fake_repo / "tests" / "test_new.py").write_text("# stub\n")
    subprocess.run(["git", "add", "tests/test_new.py"], cwd=fake_repo, check=True)
    args, added = vt._augment_args_with_ratchet_sweep(["-q"], str(fake_repo))
    assert args == ["-q"]
    assert added == []


def test_augment_bypassed_by_env(vt, fake_repo, monkeypatch):
    monkeypatch.setenv("VERIFIED_TEST_NO_AUTO", "1")
    (fake_repo / "src" / "foo.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "src/foo.py"], cwd=fake_repo, check=True)
    args, added = vt._augment_args_with_ratchet_sweep(["-q"], str(fake_repo))
    assert args == ["-q"]
    assert added == []


def test_augment_dedupes_user_provided_pin_path(vt, fake_repo, monkeypatch):
    monkeypatch.delenv("VERIFIED_TEST_NO_AUTO", raising=False)
    (fake_repo / "src" / "foo.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "src/foo.py"], cwd=fake_repo, check=True)
    already_path = (fake_repo / "tests" / "test_n001_foo_ratchet_pin.py").as_posix()
    args, added = vt._augment_args_with_ratchet_sweep(["-q", already_path], str(fake_repo))
    added_names = {Path(p).name for p in added}
    assert already_path in args
    # The user-supplied path must NOT appear twice; only the SSOT pin file added.
    assert added_names == {"test_n002_bar_ssot_pin.py"}
    assert args.count(already_path) == 1
