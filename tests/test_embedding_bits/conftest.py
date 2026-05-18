"""Fixtures for the embedding-bits installer test bundle (#180)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from email_triage.web.db import init_db


# --- A tiny manifest pinned at known bytes ---
# We synthesise three fake files (two wheels + one model file) with
# real bytes + real sha256 so the installer can run end-to-end
# against a fixture HTTP server (auto path) or a fixture source dir
# (sideload path). Real bytes mean the fast-path / mismatch tests
# exercise the same code-path the production installer takes.

def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# Fake wheel bytes — small but real-bytes-with-real-hashes so the
# installer's verify step exercises the same path as production.
_WHEEL_A_BYTES = b"#!/wheel-A-fake-bytes\nname=fake-a\nversion=1.0\n" * 32
_WHEEL_B_BYTES = b"#!/wheel-B-fake-bytes\nname=fake-b\nversion=2.0\n" * 16
_MODEL_CONFIG_BYTES = json.dumps({"model": "fake-mini"}, indent=2).encode("utf-8")


@pytest.fixture
def fake_manifest_dict() -> dict[str, Any]:
    """Build a manifest pointing at the test bytes above.

    URLs are placeholder strings — tests using the auto-download
    path patch _http_download to serve our fixture bytes instead.
    """
    return {
        "manifest_version": 1,
        "pinned_for": "test fixture",
        "generated_at": "2026-05-17T00:00:00+00:00",
        "install_target": "/tmp/runtime-deps/site-packages",
        "model_cache_target": "/tmp/runtime-deps/hf-cache",
        "wheels": [
            {
                "name": "fake-a",
                "version": "1.0",
                "filename": "fake_a-1.0.whl",
                "url": "https://example.test/fake_a-1.0.whl",
                "sha256": _sha256(_WHEEL_A_BYTES),
                "size_bytes": len(_WHEEL_A_BYTES),
                "rationale": "test fixture",
            },
            {
                "name": "fake-b",
                "version": "2.0",
                "filename": "fake_b-2.0.whl",
                "url": "https://example.test/fake_b-2.0.whl",
                "sha256": _sha256(_WHEEL_B_BYTES),
                "size_bytes": len(_WHEEL_B_BYTES),
                "rationale": "test fixture",
            },
        ],
        "models": [
            {
                "name": "all-MiniLM-L6-v2",
                "files": [
                    {
                        "name": "config.json",
                        "url": "https://example.test/all-MiniLM-L6-v2/config.json",
                        "sha256": _sha256(_MODEL_CONFIG_BYTES),
                        "size_bytes": len(_MODEL_CONFIG_BYTES),
                    },
                ],
                "rationale": "test fixture",
            },
        ],
    }


@pytest.fixture
def fake_manifest_path(tmp_path: Path, fake_manifest_dict: dict) -> Path:
    """Write the fixture manifest to tmp_path and return its path."""
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(fake_manifest_dict, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def fake_wheel_a_bytes() -> bytes:
    return _WHEEL_A_BYTES


@pytest.fixture
def fake_wheel_b_bytes() -> bytes:
    return _WHEEL_B_BYTES


@pytest.fixture
def fake_model_config_bytes() -> bytes:
    return _MODEL_CONFIG_BYTES


@pytest.fixture
def url_to_bytes(
    fake_wheel_a_bytes: bytes,
    fake_wheel_b_bytes: bytes,
    fake_model_config_bytes: bytes,
) -> dict[str, bytes]:
    return {
        "https://example.test/fake_a-1.0.whl": fake_wheel_a_bytes,
        "https://example.test/fake_b-2.0.whl": fake_wheel_b_bytes,
        "https://example.test/all-MiniLM-L6-v2/config.json":
            fake_model_config_bytes,
    }


@pytest.fixture
def test_db(tmp_path: Path) -> sqlite3.Connection:
    """Migrated DB for install_state row writes.

    init_db creates the canonical settings/email_accounts/etc tables
    (via _apply_migrations pre-framework block) THEN runs the v1+
    migration framework. Direct run_migrations() against a bare
    sqlite3.connect skips the pre-framework bootstrap and trips on
    v5 expecting a settings table.

    Also seeds a user row (id=1) so create_email_account fixtures
    don't trip on the FK to users.
    """
    db_path = tmp_path / "test.db"
    conn = init_db(str(db_path))
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR IGNORE INTO users (id, email, name, role, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (1, "test@example.com", "Test User", "admin", now),
    )
    conn.commit()
    return conn


@pytest.fixture(autouse=True)
def _stub_pip_install(monkeypatch):
    """Replace _run_pip_install with a no-op so tests don't actually
    invoke pip against the fake wheels.

    The fake wheels aren't real PEP-427 zips — pip would reject them.
    Tests that need to exercise the pip path can override via their
    own monkeypatch.

    2026-05-18: the installer now has a post-install verify gate that
    calls ``is_runtime_ready`` after pip exits. With the real pip
    stubbed out, ``sentence_transformers`` won't be on sys.path so the
    real ``is_runtime_ready`` would return False, tripping the verify
    gate and flipping status to ``failed``. Stub the readiness probe
    in concert with pip so the success-path tests stay green. Tests
    that want to exercise the verify-gate failure path override this
    via their own monkeypatch (``_force_runtime_not_ready`` shape).
    """
    def _fake_pip(*, wheels_dir, target_dir, wheel_names):
        # Create an empty marker so pip-install-step tests can assert
        # it ran without actually invoking pip.
        marker = Path(target_dir) / ".pip-installed-marker"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            ",".join(wheel_names), encoding="utf-8",
        )

    monkeypatch.setattr(
        "email_triage.embedding_bits._run_pip_install", _fake_pip,
    )
    # In concert with the pip stub: pretend the runtime is ready
    # post-install so the verify gate passes. Tests that want to
    # exercise the verify-failure path override these stubs.
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready",
        lambda runtime_deps_path=None: True,
    )
    # The install verify gate (post-2026-05-18) uses the stronger
    # runtime_imports_cleanly probe; stub it too.
    monkeypatch.setattr(
        "email_triage.embedding_bits.runtime_imports_cleanly",
        lambda runtime_deps_path=None: (True, None),
    )


@pytest.fixture(autouse=True)
def _stub_http_download(monkeypatch, url_to_bytes):
    """Replace _http_download so auto-install tests don't hit the
    network. Writes the fixture bytes to the destination path the
    installer asked for.

    Tests that need to simulate a hash mismatch / network error
    override this fixture in their own monkeypatch.
    """
    def _fake_download(url: str, dest: Path) -> int:
        if url not in url_to_bytes:
            raise FileNotFoundError(f"fixture URL not mocked: {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(url_to_bytes[url])
        return len(url_to_bytes[url])

    monkeypatch.setattr(
        "email_triage.embedding_bits._http_download", _fake_download,
    )


@pytest.fixture
def staged_source_dir(
    tmp_path: Path,
    fake_wheel_a_bytes: bytes,
    fake_wheel_b_bytes: bytes,
    fake_model_config_bytes: bytes,
) -> Path:
    """A pre-populated sideload source dir mimicking what
    scripts/download-embedding-bits.sh produces on a connected
    machine."""
    src = tmp_path / "sideload-src"
    (src / "wheels").mkdir(parents=True)
    (src / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2").mkdir(
        parents=True,
    )
    (src / "wheels" / "fake_a-1.0.whl").write_bytes(fake_wheel_a_bytes)
    (src / "wheels" / "fake_b-2.0.whl").write_bytes(fake_wheel_b_bytes)
    (src / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"
        / "config.json").write_bytes(fake_model_config_bytes)
    return src
