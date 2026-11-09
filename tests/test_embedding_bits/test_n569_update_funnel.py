"""Punch 569 D3/D4 — the atomic runtime update funnel and its crash recovery.

``update_runtime`` stages the image's set beside the live prefix, verifies it,
swaps by rename and re-verifies, putting the previous set back on any failure.
The install step itself (download, hash, pip, import probe) is
``_install_common``'s, covered by the installer tests; here it is replaced by a
stand-in that builds the staged tree and records it with the REAL
``write_installed_marker``, so what is under test is exactly the new code: the
staging, the swap, the rollback, the recovery and the restart decision.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from email_triage import embedding_bits as eb
from tests import _embedding_runtime_fixture as fx

NEW_SET = (("fake-a", "1.1"), ("fake-b", "2.0"))


@pytest.fixture(autouse=True)
def _clean_process_flags(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setenv("HF_HOME", "unchanged")
    yield
    eb.invalidate_runtime_ready_cache()


def _fake_install(packages=NEW_SET, *, fail: str = ""):
    def fake(*, conn, manifest_path, target_dir, source_dir, method, progress_callback):
        if fail:
            return eb.InstallResult(status="failed", error_class=fail, error_msg="planted")
        fx._write_tree(target_dir, packages)
        raw = eb._load_raw_manifest(manifest_path)
        eb.write_installed_marker(
            target_dir=target_dir, manifest=raw,
            manifest_sha256=eb._manifest_sha256(manifest_path), raw_manifest=raw,
        )
        return eb.InstallResult(status="installed")
    return fake


def _stale(tmp_path, monkeypatch):
    prefix, site, mpath = fx.make_versioned_prefix(
        tmp_path, monkeypatch, declared=NEW_SET, steps=(False,),
    )
    (prefix / eb.WHEELS_DIRNAME).mkdir(exist_ok=True)
    (prefix / eb.WHEELS_DIRNAME / "fake_b-2.0.whl").write_bytes(b"wheel-b")
    assert eb.runtime_status().state == eb.STATE_STALE_OK
    return prefix, site, mpath


def _installed_versions(prefix: Path) -> dict:
    return {n: vs[0] for n, vs in eb.scan_installed_distributions(prefix).items()}


def test_a_successful_update_swaps_in_the_new_set(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    result = eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert result.status == "updated", result
    assert result.from_state == eb.STATE_STALE_OK
    assert _installed_versions(prefix) == {"fake-a": "1.1", "fake-b": "2.0"}
    assert eb.runtime_status().state == eb.STATE_OK
    assert not eb.staging_prefix(prefix).exists()
    assert not eb.previous_prefix(prefix).exists(), "a verified swap retires .prev"
    assert eb.removal_tombstones(prefix), "the old set is a tombstone for the purge"
    row = eb.get_install_status(test_db)
    assert row["status"] == "installed"
    assert row["runtime_deps_path"] == str(prefix), "the row names the LIVE prefix"
    assert result.to_set_version == 2
    assert result.restart_required is False and not eb.restart_pending()
    import os
    assert os.environ["HF_HOME"] == str(prefix / eb.HF_CACHE_DIRNAME)


def test_the_staging_prefix_is_seeded_by_link_not_download(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    seen: list[bool] = []

    def spy(**kw):
        seen.append((kw["target_dir"] / eb.WHEELS_DIRNAME / "fake_b-2.0.whl").is_file())
        return _fake_install()(**kw)

    monkeypatch.setattr(eb, "_install_common", spy)
    eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert seen == [True]


def test_a_failed_install_leaves_the_old_set_live(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    before = _installed_versions(prefix)
    monkeypatch.setattr(eb, "_install_common", _fake_install(fail="HashMismatch"))
    result = eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert result.status == "failed" and result.error_class == "HashMismatch"
    assert _installed_versions(prefix) == before
    assert eb.runtime_status().state == eb.STATE_STALE_OK, "still serving"
    assert not eb.staging_prefix(prefix).exists()
    row = eb.get_install_status(test_db)
    assert row["status"] == "failed"
    assert row["runtime_deps_path"] == str(prefix)


def test_a_staged_set_that_does_not_verify_is_never_swapped_in(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    before = _installed_versions(prefix)
    # Installs the OLD versions: the staged set is not the image's.
    monkeypatch.setattr(eb, "_install_common", _fake_install(fx.DEFAULT_PACKAGES))
    monkeypatch.setattr(eb, "write_installed_marker", _lying_marker_writer())
    result = eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert result.status == "failed"
    assert result.error_class == "StagedSetNotVerified"
    assert _installed_versions(prefix) == before


def _lying_marker_writer():
    real = eb.write_installed_marker

    def lying(**kw):
        # A marker that records the OLD set, so it never matches the image.
        record = real(**{**kw, "manifest": {"wheels": [
            {"name": n, "version": v} for n, v in fx.DEFAULT_PACKAGES
        ]}})
        return record
    return lying


def test_a_swapped_set_that_fails_reverification_is_rolled_back(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    before = _installed_versions(prefix)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    real_status = eb.runtime_status
    calls = {"n": 0}

    def flaky(**kw):
        st = real_status(**kw)
        if kw.get("target_dir") is None:
            calls["n"] += 1
            if calls["n"] >= 2:  # the pre-update read, then the post-swap check
                return eb.RuntimeStatus(state=eb.STATE_REFUSED, reason="planted: refused")
        return st

    monkeypatch.setattr(eb, "runtime_status", flaky)
    result = eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert result.status == "failed" and result.error_class == "PostSwapVerifyFailed"
    monkeypatch.setattr(eb, "runtime_status", real_status)
    assert _installed_versions(prefix) == before, "the previous set was put back"
    assert not eb.previous_prefix(prefix).exists()


def test_an_update_under_loaded_packages_requires_a_restart(test_db, tmp_path, monkeypatch):
    prefix, site, mpath = _stale(tmp_path, monkeypatch)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    monkeypatch.setattr(eb, "_modules_loaded_from", lambda p: ["torch"])
    result = eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert result.status == "updated"
    assert result.restart_required is True
    assert eb.restart_pending() is True
    # is_runtime_ready is stubbed by this directory's conftest; the unstubbed
    # arm is in tests/test_n569_runtime_update_pin.py.
    assert eb.runtime_importable_probe() is False
    eb.add_runtime_to_sys_path()
    assert str(site) not in sys.path


def test_an_update_the_automatic_caller_defers_is_not_swapped_under_loaded_packages(
    test_db, tmp_path, monkeypatch,
):
    """Operator ruling R1 (2026-10-25): ``defer_if_loaded`` is the automatic
    caller's guard. A NON-security update that finds this process already running
    on the runtime swaps nothing (the restart-pending path is not reached) and says
    so with the typed class; the same call swaps normally once nothing is loaded."""
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    monkeypatch.setattr(eb, "_modules_loaded_from", lambda p: ["torch"])
    before = _installed_versions(prefix)
    result = eb.update_runtime(conn=test_db, manifest_path=mpath, defer_if_loaded=True)
    assert result.status == "failed" and result.error_class == eb.DEFERRED_ERROR_CLASS
    assert eb.restart_pending() is False, "the restart-pending path was reached"
    assert _installed_versions(prefix) == before
    assert eb.runtime_status().state == eb.STATE_STALE_OK
    monkeypatch.setattr(eb, "_modules_loaded_from", lambda p: [])
    ok = eb.update_runtime(conn=test_db, manifest_path=mpath, defer_if_loaded=True)
    assert ok.status == "updated" and ok.restart_required is False


def test_a_second_concurrent_update_is_refused(test_db, tmp_path, monkeypatch):
    _prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    assert eb._update_lock.acquire(blocking=False)
    try:
        assert eb.update_in_progress()
        result = eb.update_runtime(conn=test_db, manifest_path=mpath)
        assert result.error_class == "UpdateInFlight"
        with pytest.raises(eb.RemoveInFlight):
            eb.remove_install(conn=test_db)
    finally:
        eb._update_lock.release()


# ---------------------------------------------------------------------------
# Crash recovery (boot and the start of every update)
# ---------------------------------------------------------------------------

def test_a_crash_between_the_renames_restores_the_previous_set(tmp_path, monkeypatch):
    """live -> .prev done, .next -> live not: live is absent. Boot puts the
    previous set back and retires the half-finished staging prefix."""
    prefix, _site, _m = _stale(tmp_path, monkeypatch)
    before = _installed_versions(prefix)
    prev, staging = eb.previous_prefix(prefix), eb.staging_prefix(prefix)
    prefix.rename(prev)
    fx._write_tree(staging, NEW_SET)
    actions = eb.recover_interrupted_update()
    assert prefix.is_dir() and not prev.exists() and not staging.exists()
    assert _installed_versions(prefix) == before
    assert any("restored" in a for a in actions)
    assert eb.runtime_status().state == eb.STATE_STALE_OK


def test_a_crash_after_a_good_swap_retires_the_previous_set(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    # Simulate the crash: the swap happened, the retire of .prev did not.
    real_retire = eb._retire
    monkeypatch.setattr(eb, "_retire", lambda path, base: (
        "kept" if path.name.endswith(eb.PREVIOUS_SUFFIX) else real_retire(path, base)
    ))
    eb.update_runtime(conn=test_db, manifest_path=mpath)
    assert eb.previous_prefix(prefix).exists()
    monkeypatch.setattr(eb, "_retire", real_retire)
    eb.recover_interrupted_update()
    assert not eb.previous_prefix(prefix).exists()
    assert eb.runtime_status().state == eb.STATE_OK


def test_a_crash_after_a_bad_swap_restores_the_previous_set(tmp_path, monkeypatch):
    prefix, _site, _m = _stale(tmp_path, monkeypatch)
    before = _installed_versions(prefix)
    prev = eb.previous_prefix(prefix)
    prefix.rename(prev)
    fx._write_tree(prefix, NEW_SET)  # a live tree with no marker: refused
    eb.recover_interrupted_update()
    assert _installed_versions(prefix) == before
    assert not prev.exists()


def test_a_leftover_symlink_is_never_followed(tmp_path, monkeypatch):
    prefix, _site, _m = _stale(tmp_path, monkeypatch)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_text("x", encoding="utf-8")
    link = eb.staging_prefix(prefix)
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted here")
    eb.recover_interrupted_update()
    assert link.is_symlink() and (target / "keep.txt").exists()


def test_the_purge_deletes_what_the_update_retired(test_db, tmp_path, monkeypatch):
    prefix, _site, mpath = _stale(tmp_path, monkeypatch)
    monkeypatch.setattr(eb, "_install_common", _fake_install())
    eb.update_runtime(conn=test_db, manifest_path=mpath)
    purged = eb.purge_removal_tombstones(prefix)
    assert purged and not eb.removal_tombstones(prefix)


def test_boot_runs_the_recovery(tmp_path):
    """The lifespan calls ``recover_interrupted_update`` (structural: a crash
    leftover is resolved before anything imports from the prefix)."""
    src = Path(eb.__file__).resolve().parents[1] / "web" / "app.py"
    text = src.read_text(encoding="utf-8")
    assert "recover_interrupted_update()" in text
    assert text.index("recover_interrupted_update()") < text.index(
        "build_embedding_backend(config)"
    )


def test_reverify_upgrades_a_pre_569_marker(test_db, tmp_path, monkeypatch):
    """The spec's "unless the operator re-verifies": a schema-1 marker on an
    exact-match install is rewritten as schema 2 by an OK reverify, so the next
    non-security change can be stale_ok instead of refused."""
    import hashlib

    prefix, _site, mpath = fx.make_verified_prefix(tmp_path, monkeypatch)
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    wheels = prefix / eb.WHEELS_DIRNAME
    wheels.mkdir()
    for w in manifest["wheels"]:
        data = w["name"].encode()
        (wheels / w["filename"]).write_bytes(data)
        w["sha256"] = hashlib.sha256(data).hexdigest()
    manifest["set_changes"] = [fx.history_entry(manifest, 1, security=False)]
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    assert eb.runtime_status().state == eb.STATE_OK

    result = eb.reverify(conn=test_db, manifest_path=mpath, target_dir=prefix)
    assert result.status == "installed", result
    upgraded = json.loads(marker_path.read_text(encoding="utf-8"))
    assert upgraded["schema"] == eb.INSTALLED_MARKER_SCHEMA
    assert upgraded["set_version"] == 1
    assert upgraded["set_digest"] == eb.manifest_set_digest(manifest)
