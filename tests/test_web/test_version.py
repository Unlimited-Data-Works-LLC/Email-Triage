"""Tests for ``_resolve_version()`` — the source resolver for the
``version`` field on the ``/health`` endpoint.

Resolution order (see ``src/email_triage/web/app.py`` docstring):
    1. ``EMAIL_TRIAGE_VERSION`` env var
    2. ``GIT_SHA`` env var
    3. ``/app/VERSION`` file baked in at container build time
    4. ``.git/HEAD`` walk (dev checkout fallback)
    5. ``"unknown"``
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from email_triage.web.app import _resolve_version


@pytest.fixture
def clear_version_env(monkeypatch):
    """Strip any process-level version env vars so tests start clean."""
    monkeypatch.delenv("EMAIL_TRIAGE_VERSION", raising=False)
    monkeypatch.delenv("GIT_SHA", raising=False)


def _patch_git_walk_returns(value: str):
    """Patch Path.exists so the ``.git`` walk never finds anything,
    forcing the resolver to fall through to ``unknown`` (or to the
    preceding /app/VERSION branch)."""
    # Make every Path(...).exists() call return False so the for-loop
    # over parents finds no ``.git`` and falls through to "unknown".
    return patch("email_triage.web.app.Path.exists", return_value=False)


def test_resolve_version_prefers_app_version_file(clear_version_env):
    """With no env var and a populated /app/VERSION file, the baked
    value wins over any .git/HEAD walk."""
    baked = "a1b2c3d4e5f6"
    with patch("builtins.open", mock_open(read_data=baked + "\n")) as m:
        with _patch_git_walk_returns(""):
            assert _resolve_version() == baked
    m.assert_called_with("/app/VERSION", encoding="utf-8")


def test_resolve_version_env_overrides_app_version_file(monkeypatch):
    """``EMAIL_TRIAGE_VERSION`` env var takes precedence over a baked
    /app/VERSION file — required for ad-hoc testing + CI injection."""
    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "override-sha")
    monkeypatch.delenv("GIT_SHA", raising=False)
    # Even if /app/VERSION contains a different value, env wins — so we
    # pass a would-be-baked blob and assert the env value is returned
    # instead. ``open`` should not even be called because the env check
    # returns first.
    with patch("builtins.open", mock_open(read_data="baked-sha\n")) as m:
        assert _resolve_version() == "override-sha"
    m.assert_not_called()


def test_resolve_version_falls_back_to_git_head_without_version_file(
    clear_version_env, tmp_path, monkeypatch
):
    """When /app/VERSION is missing (OSError on open), walk .git/HEAD.

    We don't stub the whole walk — we exercise the real walk against a
    synthetic ``.git`` directory so the fallback path is covered
    end-to-end.
    """
    # Build a fake git dir with a detached HEAD containing a sha.
    sha = "deadbeefcafebabe" * 2 + "00000000"  # 40 chars
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text(sha + "\n", encoding="utf-8")
    app_file = tmp_path / "src" / "email_triage" / "web" / "app.py"
    app_file.parent.mkdir(parents=True)
    app_file.write_text("# fake", encoding="utf-8")

    # Force ``open("/app/VERSION")`` to raise so branch 3 is skipped.
    real_open = open

    def _open(path, *a, **kw):
        if str(path) == "/app/VERSION":
            raise OSError("no such file")
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", _open)
    # Redirect the module-level ``__file__`` so the walk starts in tmp_path.
    monkeypatch.setattr("email_triage.web.app.__file__", str(app_file))

    assert _resolve_version() == sha[:7]


def test_resolve_version_unknown_when_no_sources(
    clear_version_env, tmp_path, monkeypatch
):
    """No env, no baked file, no .git — terminal ``unknown`` sentinel."""
    # Force /app/VERSION open to fail.
    real_open = open

    def _open(path, *a, **kw):
        if str(path) == "/app/VERSION":
            raise OSError("no such file")
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", _open)
    # Point ``__file__`` at a directory tree with no ``.git`` anywhere
    # from it up to the filesystem root.
    isolated = tmp_path / "no_git" / "src" / "email_triage" / "web" / "app.py"
    isolated.parent.mkdir(parents=True)
    isolated.write_text("# fake", encoding="utf-8")
    monkeypatch.setattr("email_triage.web.app.__file__", str(isolated))
    # Short-circuit the walk: make every Path(...).exists() return False.
    with _patch_git_walk_returns(""):
        assert _resolve_version() == "unknown"
