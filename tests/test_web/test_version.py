"""Tests for ``_resolve_version()`` — the source resolver for the
``version`` field on the ``/health`` endpoint.

Resolution order (see ``src/email_triage/web/app.py`` docstring):
    1. ``/app/VERSION`` file baked in at container build time
    2. ``.git/HEAD`` walk (dev checkout fallback)
    3. ``"unknown"``

``EMAIL_TRIAGE_VERSION`` and ``GIT_SHA`` used to occupy the first two places.
The operator directed that override GUTTED on 2026-09-29, so the environment is
no longer a source at all — and the test that used to assert env PRECEDENCE now
asserts env IRRELEVANCE. The structural counterpart, which catches an env read
re-introduced anywhere in a build-identity resolver rather than only on this
one call, lives in ``tests/test_web/test_health_build_endpoint.py``.
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


def test_resolve_version_ignores_the_environment_entirely(monkeypatch):
    """INVERTED 2026-09-29 by operator directive. This test used to assert
    that ``EMAIL_TRIAGE_VERSION`` took PRECEDENCE over the baked
    /app/VERSION file. The override was gutted, so it now asserts the
    opposite: with BOTH variables set to plausible 40-hex shas, the baked
    file still wins and the environment contributes nothing.

    Both are set, to DIFFERENT values, and both are 40-hex — the shape that
    would sail through any downstream sha check. A test that set only one, or
    set an obviously-bogus value, would pass against a resolver that still read
    the other variable or still read the environment for well-formed input.
    """
    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "a" * 40)
    monkeypatch.setenv("GIT_SHA", "b" * 40)
    baked = "c1d2e3f4a5b6" + "0" * 28
    # ``open`` MUST now be called — previously the env check returned before it.
    with patch("builtins.open", mock_open(read_data=baked + "\n")) as m:
        with _patch_git_walk_returns(""):
            assert _resolve_version() == baked, (
                "an environment variable moved the build identifier. Both "
                "/health's `version` and /health/build's `build_sha` must be "
                "bounded by what was true at BUILD time."
            )
    m.assert_called_with("/app/VERSION", encoding="utf-8")


def test_the_health_version_field_is_fed_by_that_same_resolver(monkeypatch):
    """Close the chain: the assertion above is about `_resolve_version()`, and
    this proves that function is what `/health`'s `version` field reports, so
    the unit arm is not measuring a resolver nobody reads.

    Structural rather than behavioural on purpose. `app.state.version` is
    resolved ONCE at startup, so monkeypatching an env var after the app
    fixture has been built proves nothing — the same trap register row N-523
    names. What can be proven is the wiring: there is exactly one writer of
    `app.state.version`, and its right-hand side is `_resolve_version()`.
    """
    import ast
    import inspect

    from email_triage.web import app as app_mod

    writers = []
    for node in ast.walk(ast.parse(inspect.getsource(app_mod))):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if (
                isinstance(tgt, ast.Attribute)
                and tgt.attr == "version"
                and isinstance(tgt.value, ast.Attribute)
                and tgt.value.attr == "state"
            ):
                writers.append(ast.unparse(node.value))
    assert writers == ["_resolve_version()"], (
        f"app.state.version is written from {writers!r}. Exactly one writer, "
        f"and it must be _resolve_version() — a second assignment is a second "
        f"source for the field, and only one of them would be pinned."
    )


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
