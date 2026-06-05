"""is_runtime_ready: cached probe + sys.path priming."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from email_triage import embedding_bits as eb


def test_is_runtime_ready_false_without_install(tmp_path):
    """Empty runtime-deps dir → is_runtime_ready() is False.

    Runs the probe in a subprocess with site-packages disabled (``-S``)
    so the result reflects ONLY the (empty) runtime-deps dir, not
    whatever the ambient dev venv happens to have installed.

    ``is_runtime_ready()`` calls ``find_spec("sentence_transformers")``
    across the whole ``sys.path`` — without ``-S``, a dev venv that has
    sentence-transformers installed (e.g. a developer working on the
    embedding feature, or right after running the embedding-bits
    install locally) makes this assertion spuriously fail. The
    subprocess + ``-S`` reconstructs the genuine slim-image "not
    installed" state regardless of the host venv. .
    """
    repo_src = str(Path(__file__).resolve().parents[2] / "src")
    snippet = (
        "from email_triage import embedding_bits as eb; "
        "eb.invalidate_runtime_ready_cache(); "
        "print(eb.is_runtime_ready())"
    )
    env = {
        **os.environ,
        "EMBEDDING_BITS_RUNTIME_DEPS": str(tmp_path / "absent"),
        "PYTHONPATH": repo_src,
    }
    result = subprocess.run(
        [sys.executable, "-S", "-c", snippet],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert result.returncode == 0, (
        f"subprocess failed: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert result.stdout.strip() == "False", (
        f"expected False; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


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
