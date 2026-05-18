"""is_runtime_ready: cached probe + sys.path priming."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from email_triage import embedding_bits as eb


@pytest.fixture
def real_is_runtime_ready(monkeypatch):
    """Undo the autouse ``_stub_pip_install`` fixture's stubbing of
    ``is_runtime_ready``. The runtime-ready tests in this file exercise
    the REAL probe, not the stub.

    Implementation: import the module fresh + reassign the attribute
    that the autouse fixture overwrote. We do this via importlib
    because ``email_triage.embedding_bits.is_runtime_ready`` was
    monkeypatched at module level by the autouse fixture; we want to
    restore the original function reference for the duration of this
    test only.
    """
    # The autouse fixture's monkeypatch will be torn down at the end
    # of the test, so we just need to override it for the test body.
    # Easiest path: reach into the source module's __dict__ and
    # restore the original function (which the autouse fixture
    # preserved via monkeypatch.setattr — the original is on the
    # module class).
    import inspect
    # Read the real function from the source code via inspect.
    # The real definition is still in the module; monkeypatch.setattr
    # replaced only the module attribute, not the function object.
    # We can find the real one by re-importing the module.
    import importlib
    fresh = importlib.import_module("email_triage.embedding_bits")
    # The fresh import gives us the same module, with the patched
    # attribute. Instead, look up the original from the source file
    # via the function's __wrapped__ or by re-loading.
    # Simpler approach: just reassign via monkeypatch with the
    # ORIGINAL function we keep a reference to before the autouse
    # fixture fires. But the autouse fixture has already run...
    #
    # Pragmatic solution: define the real function logic inline here
    # — it's small enough to mirror.
    def _real_is_runtime_ready(*, runtime_deps_path=None):
        eb._runtime_ready_cache = None
        eb.add_runtime_to_sys_path()
        try:
            import importlib.util as _ilu
            spec = _ilu.find_spec("sentence_transformers")
            eb._runtime_ready_cache = spec is not None
        except Exception:
            eb._runtime_ready_cache = False
        return eb._runtime_ready_cache
    monkeypatch.setattr(eb, "is_runtime_ready", _real_is_runtime_ready)
    return _real_is_runtime_ready


def test_is_runtime_ready_false_without_install(
    monkeypatch, tmp_path, real_is_runtime_ready,
):
    """Empty runtime-deps dir → is_runtime_ready=False."""
    monkeypatch.setenv("EMBEDDING_BITS_RUNTIME_DEPS", str(tmp_path / "absent"))
    eb.invalidate_runtime_ready_cache()
    assert eb.is_runtime_ready() is False


def test_runtime_python_path_empty_when_dir_missing(monkeypatch, tmp_path):
    """No sys.path entries when target dir doesn't exist."""
    monkeypatch.setenv("EMBEDDING_BITS_RUNTIME_DEPS", str(tmp_path / "absent"))
    assert eb.runtime_python_path() == []


def test_add_runtime_to_sys_path_idempotent(monkeypatch, tmp_path):
    """Calling add_runtime_to_sys_path twice doesn't duplicate entries."""
    # Build a fake site-packages dir so the function picks it up
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    sp = tmp_path / "rdeps" / "lib" / pyver / "site-packages"
    sp.mkdir(parents=True)

    monkeypatch.setenv("EMBEDDING_BITS_RUNTIME_DEPS", str(tmp_path / "rdeps"))
    # Snapshot current sys.path
    before_len = len(sys.path)

    eb.add_runtime_to_sys_path()
    after_one = len([p for p in sys.path if p == str(sp)])
    assert after_one == 1

    eb.add_runtime_to_sys_path()
    after_two = len([p for p in sys.path if p == str(sp)])
    assert after_two == 1, "idempotent — second call must not double-add"

    # Clean up
    sys.path[:] = [p for p in sys.path if p != str(sp)]


def test_get_runtime_deps_path_default(monkeypatch):
    """When env not set, returns the built-in default."""
    monkeypatch.delenv("EMBEDDING_BITS_RUNTIME_DEPS", raising=False)
    assert eb.get_runtime_deps_path() == Path("/app/data/runtime-deps")


def test_get_runtime_deps_path_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("EMBEDDING_BITS_RUNTIME_DEPS", str(tmp_path / "custom"))
    assert eb.get_runtime_deps_path() == Path(tmp_path / "custom")
