"""Punch 732: a base-image interpreter bump must not serve the old ABI's runtime.

The image moved from python:3.12-slim to python:3.14-slim. The persistent volume
(``/app/data/runtime-deps/``) still holds the install the OLD image made: a
``lib/python3.12/site-packages`` tree of cp312 wheels and an ``INSTALLED.json``
recording set v4. The v5 manifest pins the SAME package versions as cp314 wheels,
so the version comparison in ``runtime_status`` cannot see the change: with the
tree visible, the v4 marker reads ``ok`` against v5 (the control arm below proves
it). The only thing that keeps the cp312 ``.so`` files off ``sys.path`` is that
the site-packages candidates are interpreter-versioned
(``runtime_site_packages_candidates``: ``lib/python<maj>.<min>/site-packages``).

This test builds that prefix for an interpreter that is NOT the running one
(derived, never a literal version) and asserts it does not serve and nothing under
it reaches ``sys.path``. That arm asserts "not serving" in general; the arms below
pin the specific answer, the ``interpreter_mismatch`` refusal the boot updater heals (punch 732, DA 1029b D2).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from email_triage import embedding_bits as eb
from tests import _embedding_runtime_fixture as fx


def _other_interpreter() -> str:
    """A ``python<maj>.<min>`` dir name that is not the running interpreter's."""
    major, minor = sys.version_info.major, sys.version_info.minor
    return f"python{major}.{minor - 2 if minor >= 2 else minor + 2}"


def _abi_moved_prefix(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    """An install recorded as set v1 under an image whose manifest is set v2:
    the same names and versions, every filename re-tagged (the cp312 -> cp314
    move), and a non-security history step. Returns ``(prefix, site_packages)``
    with the tree still under the RUNNING interpreter's dir."""
    prefix = tmp_path / "rdeps"
    site = fx._write_tree(prefix, fx.DEFAULT_PACKAGES)
    old_path = tmp_path / "manifest-v1.json"
    old = fx._write_manifest(old_path, fx.DEFAULT_PACKAGES)
    v1 = fx.history_entry(old, 1, security=False)
    old["set_changes"] = [v1]
    old_path.write_text(json.dumps(old), encoding="utf-8")
    eb.write_installed_marker(
        target_dir=prefix, manifest=old,
        manifest_sha256=eb._manifest_sha256(old_path),
    )
    new_path = tmp_path / "manifest.json"
    new = fx._write_manifest(new_path, fx.DEFAULT_PACKAGES)
    for wheel in new["wheels"]:
        wheel["filename"] = wheel["filename"].replace(".whl", "-newabi.whl")
    assert eb.manifest_set_digest(new) != v1["set_digest"]
    new["set_changes"] = [v1, fx.history_entry(new, 2, security=False)]
    new_path.write_text(json.dumps(new), encoding="utf-8")
    fx.point_defaults_at(monkeypatch, prefix, new_path)
    eb.invalidate_runtime_ready_cache()
    return prefix, site


def test_same_versions_new_abi_reads_ok_while_the_tree_is_visible(tmp_path, monkeypatch):
    """Control arm: the rig can PASS, and the version check alone cannot see an
    ABI move. If this ever stops reading ``ok``, the arm below no longer proves
    that the versioned path is what keeps the old tree out."""
    _abi_moved_prefix(tmp_path, monkeypatch)
    status = eb.runtime_status()
    assert status.state == eb.STATE_OK, status.reason
    assert eb.runtime_marker_status()[0] is True


def test_old_interpreter_tree_does_not_serve_or_reach_sys_path(tmp_path, monkeypatch):
    prefix, site = _abi_moved_prefix(tmp_path, monkeypatch)
    old_lib = prefix / "lib" / _other_interpreter()
    site.parent.rename(old_lib)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["python"] = _other_interpreter().removeprefix("python")
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()

    status = eb.runtime_status()
    assert not status.serving, status.reason
    assert status.state not in (eb.STATE_OK, eb.STATE_STALE_OK), status.reason
    serving, reason = eb.runtime_marker_status()
    assert serving is False, reason

    old_tree = old_lib.resolve()
    assert not [p for p in eb.runtime_python_path() if Path(p).resolve().is_relative_to(old_tree)]
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.add_runtime_to_sys_path()
    leaked = [p for p in sys.path if p and Path(p).resolve().is_relative_to(old_tree)]
    assert leaked == [], f"the old interpreter's tree reached sys.path: {leaked}"


def _set_marker_python(prefix: Path, version: str) -> None:
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["python"] = version
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()


def test_old_interpreter_tree_is_refused_as_interpreter_mismatch_and_auto_updatable(
    tmp_path, monkeypatch,
):
    """The refusal is manifest-driven, not integrity: the boot updater replaces it
    (decision 2026-10-25: runtime updates apply automatically). The set version
    comes from the marker, because the refusal precedes the drift classification."""
    prefix, site = _abi_moved_prefix(tmp_path, monkeypatch)
    site.parent.rename(prefix / "lib" / _other_interpreter())
    eb.invalidate_runtime_ready_cache()

    status = eb.runtime_status()
    assert status.state == eb.STATE_REFUSED, status.reason
    assert status.reason_token == "interpreter_mismatch", status.reason
    assert status.reason_token not in eb.INTEGRITY_TOKENS
    assert status.update_required and status.auto_updatable
    assert status.installed_set_version == 1
    assert status.old_tree_verified is True  # orphan matched its record_digests


def test_a_prefix_with_no_marker_stays_no_prefix(tmp_path, monkeypatch):
    """Without INSTALLED.json the old tree is not an install this app recorded:
    the first install stays the admin's click (embedding_update_runner)."""
    prefix, site = _abi_moved_prefix(tmp_path, monkeypatch)
    site.parent.rename(prefix / "lib" / _other_interpreter())
    eb.installed_marker_path(prefix).unlink()
    eb.invalidate_runtime_ready_cache()

    status = eb.runtime_status()
    assert status.state == eb.STATE_NO_PREFIX, status.reason
    assert not status.update_required


def test_marker_python_is_the_signal_on_an_unversioned_layout(tmp_path, monkeypatch):
    """``Lib/site-packages`` carries no version, so the tree stays visible to every
    interpreter; the marker's ``python`` is the only signal there."""
    prefix, site = _abi_moved_prefix(tmp_path, monkeypatch)
    unversioned = prefix / "Lib" / "site-packages"
    if site.resolve() != unversioned.resolve():
        staging = prefix / "_move"
        site.rename(staging)
        for leftover in sorted(prefix.glob("lib/python*"), reverse=True):
            leftover.rmdir()
        unversioned.parent.mkdir(parents=True, exist_ok=True)
        staging.rename(unversioned)
    eb.invalidate_runtime_ready_cache()
    assert eb.runtime_status().state == eb.STATE_OK  # control: same interpreter

    _set_marker_python(prefix, _other_interpreter().removeprefix("python"))
    status = eb.runtime_status()
    assert status.state == eb.STATE_REFUSED, status.reason
    assert status.reason_token == "interpreter_mismatch", status.reason
    assert status.auto_updatable


def _orphan_prefix(tmp_path, monkeypatch) -> tuple[Path, Path]:
    """The base-image-bump shape: the marker's tree under ANOTHER interpreter."""
    prefix, site = _abi_moved_prefix(tmp_path, monkeypatch)
    old_lib = prefix / "lib" / _other_interpreter()
    site.parent.rename(old_lib)
    eb.invalidate_runtime_ready_cache()
    return prefix, old_lib / "site-packages"


def test_a_tampered_orphan_tree_is_an_integrity_refusal_not_an_automatic_replace(
    tmp_path, monkeypatch,
):
    """Panel py314 (hipaa SHOULD-3 / db SHOULD-2): the replace wipes the orphan
    tree, so a tree that no longer matches its marker must wait for an admin
    (integrity token, never healed automatically) rather than be destroyed."""
    prefix, orphan = _orphan_prefix(tmp_path, monkeypatch)
    metadata = next(orphan.glob("*.dist-info")) / "METADATA"
    metadata.write_text(metadata.read_text(encoding="utf-8") + "X-Tampered: 1\n",
                        encoding="utf-8")
    eb.invalidate_runtime_ready_cache()

    status = eb.runtime_status()
    assert status.state == eb.STATE_REFUSED, status.reason
    assert status.reason_token in eb.INTEGRITY_TOKENS, status.reason
    assert status.integrity_refusal and not status.auto_updatable
    assert orphan.is_dir()


def test_a_legacy_marker_without_record_digests_replaces_unverified(tmp_path, monkeypatch):
    """A schema-1 marker carries no ``record_digests``: the orphan's names and
    versions are still checked, the replace stays automatic, and the audit row
    says the old tree was NOT verified."""
    prefix, _orphan = _orphan_prefix(tmp_path, monkeypatch)
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    marker.pop("record_digests", None)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()

    status = eb.runtime_status()
    assert status.reason_token == "interpreter_mismatch", status.reason
    assert status.auto_updatable
    assert status.old_tree_verified is False
