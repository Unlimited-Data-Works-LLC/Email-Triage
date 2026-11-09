"""is_runtime_ready: cached probe + sys.path priming."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from _pin_harness import tree_src_env
from _embedding_runtime_fixture import (
    make_stale_prefix,
    make_verified_prefix,
    point_defaults_at,
)

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
    # Punch 547: no env var moves the prefix. Steer the module default, the way
    # point_defaults_at does in-process, and print the resolved prefix so a
    # steer that stops reaching the resolver fails here instead of passing on
    # whatever /app/data/runtime-deps happens to be on this host.
    absent = str(tmp_path / "absent")
    snippet = (
        "from email_triage import embedding_bits as eb; "
        f"eb.DEFAULT_RUNTIME_DEPS = {absent!r}; "
        "eb.invalidate_runtime_ready_cache(); "
        "print(eb.get_runtime_deps_path()); "
        "print(eb.is_runtime_ready())"
    )
    env = tree_src_env()
    result = subprocess.run(
        [sys.executable, "-S", "-c", snippet],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert result.returncode == 0, (
        f"subprocess failed: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    resolved, ready = result.stdout.strip().splitlines()
    assert resolved == absent, (
        f"the steer did not reach get_runtime_deps_path: resolved {resolved!r}"
    )
    assert ready == "False", (
        f"expected False; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_runtime_python_path_empty_when_dir_missing(monkeypatch, tmp_path):
    """No sys.path entries when target dir doesn't exist."""
    point_defaults_at(monkeypatch, tmp_path / "absent")
    assert eb.runtime_python_path() == []


def test_add_runtime_to_sys_path_idempotent(monkeypatch, tmp_path):
    """Calling add_runtime_to_sys_path twice doesn't duplicate entries.

    N-524: the prefix must now be VERIFIED for the add to happen at all, so the
    fixture writes a matching INSTALLED.json. Pre-N-524 this test built a bare
    directory and the path went on regardless — which was the defect.
    """
    _prefix, sp, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    try:
        eb.add_runtime_to_sys_path()
        after_one = len([p for p in sys.path if p == str(sp)])
        assert after_one == 1

        eb.add_runtime_to_sys_path()
        after_two = len([p for p in sys.path if p == str(sp)])
        assert after_two == 1, "idempotent — second call must not double-add"
    finally:
        sys.path[:] = [p for p in sys.path if p != str(sp)]


def test_add_runtime_to_sys_path_appends_never_shadows_the_image(
    monkeypatch, tmp_path,
):
    """N-525 / punch 540 — APPEND, not ``insert(0, …)``.

    The pre-fix insert put the data volume ahead of the image AND the stdlib for
    the life of the process, and nothing ever removed the entry, so any name the
    volume also carried was served from the volume. Appending means the image's
    own lock-pinned, CVE-scanned copy still wins.
    """
    _prefix, sp, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    head_before = sys.path[0]
    try:
        eb.add_runtime_to_sys_path()
        assert sys.path[-1] == str(sp), (
            "the runtime prefix must be APPENDED; anything else can shadow the "
            "image's own packages"
        )
        assert sys.path[0] == head_before, "sys.path[0] must not move"
    finally:
        sys.path[:] = [p for p in sys.path if p != str(sp)]


def test_a_prefix_with_no_marker_is_refused(
    monkeypatch, tmp_path, real_runtime_probes,
):
    """N-524 behavioural pin — the retroactive half.

    Every install made before this change wrote no ``INSTALLED.json``, so
    "missing marker" is the state of the 2026-05-18 tree sitting on the deploy host right
    now. Refusing on missing (rather than grandfathering it) is what makes the
    gate catch installs that pre-date it. Fail CLOSED (PD-8).
    """
    _prefix, site, _manifest = make_stale_prefix(
        tmp_path, monkeypatch, write_marker=False,
    )
    before = list(sys.path)
    ok, reason = eb.runtime_marker_status()
    assert ok is False
    assert "marker_invalid" in reason

    eb.add_runtime_to_sys_path()
    assert sys.path == before, (
        "an unrecorded install must not be put on the import path"
    )
    assert str(site) not in sys.path
    assert eb.is_runtime_ready() is False, (
        "is_runtime_ready must not report ready over an unverified prefix — "
        "every downstream gate (reindex job, style-learning UI, install card) "
        "reads it"
    )


def test_a_marker_from_an_older_manifest_is_refused(
    monkeypatch, tmp_path, real_runtime_probes,
):
    """N-524 behavioural pin — the drift half, and THE finding.

    Packages on disk, an honest marker recording them, every file hash-valid —
    and the image's manifest now names different versions. Nothing is corrupt;
    the install is simply not the one this image expects. That is the case that
    used to pass unnoticed, so it is the case with the sharpest test.
    """
    _prefix, site, _manifest = make_stale_prefix(tmp_path, monkeypatch)
    before = list(sys.path)
    ok, reason = eb.runtime_marker_status()
    assert ok is False
    assert "set_mismatch" in reason
    assert "fake-a" in reason, "the reason must name what drifted"

    eb.add_runtime_to_sys_path()
    assert sys.path == before
    assert str(site) not in sys.path
    assert eb.is_runtime_ready() is False


def test_two_versions_of_one_name_is_refused(monkeypatch, tmp_path):
    """Ambiguity is refused, not resolved by path order.

    This is what a pre-fix "refresh" produced: pip's ``--prefix`` run does not
    uninstall, so the old ``dist-info`` survived beside the new one. Which code
    imported then depended on directory order — a silent, machine-specific
    answer.
    """
    prefix, site, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    stale = site / "fake_a-0.1.dist-info"
    stale.mkdir()
    (stale / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fake-a\nVersion: 0.1\n", encoding="utf-8",
    )
    eb.invalidate_runtime_ready_cache()

    scan = eb.scan_installed_distributions(prefix)
    assert scan["fake-a"] == ["0.1", "1.0"], (
        "the scan must report EVERY version found, never first-wins"
    )
    ok, reason = eb.runtime_marker_status()
    assert ok is False
    assert "duplicate_versions" in reason


def test_environment_provided_names_are_accounted_for(monkeypatch, tmp_path):
    """The measured reason the gate is not a flat equals-the-manifest compare.

    The installer passes BARE requirement names to pip, so a name the image
    already provides is skipped ("Requirement already satisfied") and never lands
    in the prefix. Three manifest names are in ``requirements.lock`` today
    (``jinja2``, ``packaging``, ``regex``), so a strict compare would refuse
    every install forever and the feature could never be installed at all.
    Here ``pytest`` stands in for such a name: it is installed in the
    environment, absent from the prefix, and must still verify.
    """
    prefix = tmp_path / "rdeps"
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = prefix / "lib" / pyver / "site-packages"
    site.mkdir(parents=True)
    dist_info = site / "fake_a-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fake-a\nVersion: 1.0\n", encoding="utf-8",
    )
    import pytest as _pytest

    manifest = {
        "manifest_version": 1,
        "wheels": [
            {"name": "fake-a", "version": "1.0",
             "filename": "fake-a-1.0.whl", "sha256": "0" * 64},
            {"name": "pytest", "version": _pytest.__version__,
             "filename": "pytest.whl", "sha256": "0" * 64},
        ],
        "models": [],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    point_defaults_at(monkeypatch, prefix, manifest_path)

    provided = eb.environment_provided_versions(
        ["fake-a", "pytest"], target_dir=prefix,
    )
    assert "pytest" in provided, "an installed name must be detected"
    assert "fake-a" not in provided, (
        "a name that lives IN the prefix must never be counted as "
        "image-provided — otherwise a prefix on sys.path could excuse itself"
    )

    record = eb.write_installed_marker(
        target_dir=prefix, manifest=manifest,
        manifest_sha256=eb._manifest_sha256(manifest_path),
    )
    assert record["distributions"] == {"fake-a": "1.0"}
    assert "pytest" in record["provided_by_image"]
    eb.invalidate_runtime_ready_cache()
    ok, reason = eb.runtime_marker_status()
    assert ok is True, reason


def test_a_missing_manifest_package_is_still_refused(monkeypatch, tmp_path):
    """The accounting must not become a loophole.

    ``provided_by_image`` excuses a name the ENVIRONMENT has. A name that is in
    neither the prefix nor the environment is simply not installed, and the
    marker write must refuse rather than record a partial tree as verified.
    """
    prefix = tmp_path / "rdeps"
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    (prefix / "lib" / pyver / "site-packages").mkdir(parents=True)
    manifest = {
        "manifest_version": 1,
        "wheels": [{
            "name": "definitely-not-installed-anywhere",
            "version": "1.0",
            "filename": "x.whl",
            "sha256": "0" * 64,
        }],
        "models": [],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    point_defaults_at(monkeypatch, prefix, manifest_path)
    with pytest.raises(eb.RuntimeRecordError) as exc:
        eb.write_installed_marker(
            target_dir=prefix, manifest=manifest,
            manifest_sha256=eb._manifest_sha256(manifest_path),
        )
    assert "definitely-not-installed-anywhere" in str(exc.value)


def test_remove_install_deletes_the_tree_and_resets_the_row(
    monkeypatch, tmp_path, test_db,
):
    """N-526 / punch 541 — both halves, one call.

    The row-reset half is the one that had no other route: pre-fix,
    ``_update_state`` could not write NULL (None meant "leave alone"), so
    correcting a stale row meant hand-written SQL against the SQLCipher DB.
    """
    prefix, site, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    eb._update_state(
        test_db,
        status="installed",
        install_method="auto",
        manifest_sha256="deadbeef" * 8,
        runtime_deps_path=str(prefix),
        set_installed_now=True,
        progress_files_done=18,
        progress_files_total=18,
    )
    eb.add_runtime_to_sys_path()
    assert str(site) in sys.path, "precondition: the verified path went on"

    try:
        summary = eb.remove_install(conn=test_db, target_dir=prefix)
        # ASSERT BEFORE THE CLEANUP. The first version of this test stripped the
        # entry in a `finally` and asserted afterwards, so the assertion was
        # satisfied by the test's own cleanup and would have passed over a
        # removal that never touched sys.path at all — which is exactly the bug
        # it was hiding: `remove_runtime_from_sys_path` filtered on `.exists()`
        # and ran AFTER the rmtree, so it found nothing to remove.
        assert str(site) not in sys.path, (
            "removal must also drop the entry from the live sys.path — it "
            "cannot un-import, but it must stop a later import resolving there"
        )
        assert summary["sys_path_entries"], (
            "the summary must report what it dropped"
        )
    finally:
        sys.path[:] = [p for p in sys.path if p != str(site)]

    assert summary["removed"] is True
    assert summary["residual_tree"] is False
    assert not prefix.exists(), "the whole prefix must be gone"

    row = eb.get_install_status(test_db)
    assert row["status"] == "not_installed"
    for column in ("manifest_sha256", "runtime_deps_path", "installed_at"):
        assert row[column] is None, (
            f"{column} must be NULL after removal — a row naming a manifest "
            f"sha over a deleted tree reads as 'installed, mid-glitch'"
        )
    assert row["progress_files_done"] == 0
    assert row["progress_files_total"] == 0
    assert row["attempt_count"] == 0


def test_an_explicit_target_dir_is_honoured_over_the_env(monkeypatch, tmp_path):
    """Every gate that accepts ``target_dir`` must use it for the EXISTENCE check
    too, not only for the dist-info scan.

    `embedding-bits status --target-dir X` and `reverify(target_dir=...)` hand a
    prefix in explicitly. Pre-fix, `runtime_marker_status` scanned the given
    prefix but tested existence against the ENV-resolved one, so those callers
    could read ``no_prefix`` for a prefix that is plainly there — or proceed for
    one that is not. Production never noticed because env and target are the same
    path there, which is why a fixture that sets both could not see it either.
    """
    prefix, _site, manifest_path = make_verified_prefix(tmp_path, monkeypatch)
    # Point the ENV somewhere empty; the explicit target still holds the install.
    point_defaults_at(monkeypatch, tmp_path / "somewhere-else")
    eb.invalidate_runtime_ready_cache()

    assert eb.runtime_python_path() == [], "precondition: the env prefix is empty"
    assert eb.runtime_python_path(prefix), "the explicit prefix must be seen"

    ok, reason = eb.runtime_marker_status(
        target_dir=prefix, manifest_path=manifest_path,
    )
    assert ok is True, f"the explicit prefix verifies; got {reason}"

    record = eb.runtime_install_record(
        target_dir=prefix, manifest_path=manifest_path,
    )
    assert record["present"] is True
    assert record["verified"] is True
    assert record["distributions"]["fake-a"] == ["1.0"]

    # ...and the env-resolved prefix, which has nothing, still reads no_prefix.
    env_ok, env_reason = eb.runtime_marker_status()
    assert env_ok is False
    assert env_reason == "no_prefix"


def test_remove_install_refuses_mid_install(monkeypatch, tmp_path, test_db):
    """Removing under a live installer would race a running pip against rmtree."""
    prefix, _site, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    eb._update_state(test_db, status="installing", install_method="auto")
    with pytest.raises(eb.RemoveInFlight):
        eb.remove_install(conn=test_db, target_dir=prefix)
    assert prefix.exists(), "nothing may be deleted on the refusal path"


def test_reverify_refuses_when_the_installed_set_drifted(
    monkeypatch, tmp_path, test_db,
):
    """DR-1's other half: ``reverify`` never read ``manifest_sha256``.

    Re-hashing the staged wheels proves the BYTES are the manifest's. It says
    nothing about what is INSTALLED — and this function used to flip the row to
    ``installed`` on the strength of the first claim alone.
    """
    prefix, _site, manifest_path = make_stale_prefix(tmp_path, monkeypatch)
    # Stage the wheels the CURRENT manifest names, hash-valid, so every check
    # reverify used to make passes.
    wheels = prefix / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    import hashlib
    for wheel in manifest["wheels"]:
        payload = f"bytes-for-{wheel['name']}".encode()
        (wheels / wheel["filename"]).write_bytes(payload)
        wheel["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = eb.reverify(
        conn=test_db, manifest_path=manifest_path, target_dir=prefix,
    )
    assert result.status == "failed", (
        "staged bytes matching the manifest is not the same claim as the "
        "installed set matching it"
    )
    assert result.error_class == "RuntimeRecordError"
    assert eb.get_install_status(test_db)["status"] == "failed"


def test_get_runtime_deps_path_default(monkeypatch):
    """When env not set, returns the built-in default."""
    monkeypatch.delenv("EMBEDDING_BITS_RUNTIME_DEPS", raising=False)
    assert eb.get_runtime_deps_path() == Path("/app/data/runtime-deps")


def test_get_runtime_deps_path_ignores_the_environment(monkeypatch, tmp_path):
    """Punch 547: the prefix that is verified and ADDED TO sys.path (and is
    the default target of ``remove_install``) is never chosen by an
    environment variable."""
    monkeypatch.setenv("EMBEDDING_BITS_RUNTIME_DEPS", str(tmp_path / "custom"))
    assert eb.get_runtime_deps_path() == Path(eb.DEFAULT_RUNTIME_DEPS)


def test_the_manifest_resolver_reads_no_environment(monkeypatch, tmp_path):
    """hipaa H539FC-8 / R7 (punch 539 fold-check). An environment override of the
    manifest path used to WIN here, and this resolver is the default reference
    for the N-524 drift gate and for ``image_manifest_sha256``. Set one: the
    resolver must not move."""
    monkeypatch.setenv("EMBEDDING_BITS_" + "MANIFEST", str(tmp_path / "m.json"))
    assert eb.resolve_manifest_path() == Path(eb.DEFAULT_MANIFEST_PATH)
    assert eb.resolve_manifest_path() == Path(
        "/app/scripts/embedding-bits-manifest.json"
    )


def _marked(prefix: Path) -> Path:
    """A directory the guard can POSITIVELY identify: it holds the installer's
    marker. Content is irrelevant to the identification check."""
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / eb.INSTALLED_MARKER_NAME).write_text(
        json.dumps({"schema": eb.INSTALLED_MARKER_SCHEMA, "distributions": {}}),
        encoding="utf-8",
    )
    return prefix


def test_remove_install_refuses_a_target_that_holds_the_database(tmp_path, test_db):
    """N-549 guard, arm 1 (hipaa H539FC-9 / db 539fc §4b). ``test_db`` lives at
    ``tmp_path/test.db``. Its directory is MARKED, so positive identification
    alone would pass: the database-ancestor arm must refuse by itself, BEFORE
    the rmtree and before the row reset. The DB file, a sentinel and the row all
    survive."""
    db_file = tmp_path / "test.db"
    assert db_file.exists(), "precondition: the fixture DB is file-backed here"
    _marked(tmp_path)
    sentinel = tmp_path / "keep-me.txt"
    sentinel.write_text("x", encoding="utf-8")
    eb._update_state(test_db, status="installed", install_method="auto")
    test_db.commit()

    for target in (tmp_path, db_file, tmp_path / "rdeps" / ".."):
        with pytest.raises(eb.RemoveTargetRefused, match="database"):
            eb.remove_install(conn=test_db, target_dir=target)
    assert db_file.exists() and sentinel.exists(), "nothing may be deleted"
    assert eb.get_install_status(test_db)["status"] == "installed", (
        "the row must not be reset on the refusal path"
    )


def test_remove_install_refuses_a_symlink_to_the_database_directory(tmp_path, test_db):
    """Arm 1 compares RESOLVED paths, so a symlink cannot walk around it."""
    link_home = tmp_path / "elsewhere"
    link_home.mkdir()
    alias = link_home / "alias"
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create a directory symlink")
    with pytest.raises(eb.RemoveTargetRefused, match="database"):
        eb.remove_install(conn=test_db, target_dir=alias)
    assert (tmp_path / "test.db").exists()


def test_remove_install_refuses_the_data_volume_and_its_parents(test_db):
    """Arm 2: ``/``, ``/app`` and ``/app/data`` — the parents of
    ``DEFAULT_RUNTIME_DEPS`` — are refused whatever they hold. Nothing exists at
    those paths on a test host, so a refusal here is the guard, not a miss."""
    for target in Path(eb.DEFAULT_RUNTIME_DEPS).parents:
        with pytest.raises(eb.RemoveTargetRefused, match="data volume|database"):
            eb.remove_install(conn=test_db, target_dir=target)


def test_remove_install_refuses_an_unidentified_directory(tmp_path, test_db):
    """Arm 3, positive identification: a directory that is neither the default
    prefix nor holds the installer's marker is refused, and its contents
    survive. A deny-list alone would have deleted it."""
    stray = tmp_path / "vol" / "backups"
    stray.mkdir(parents=True)
    (stray / "nightly.bin").write_text("x", encoding="utf-8")
    with pytest.raises(eb.RemoveTargetRefused, match="INSTALLED.json"):
        eb.remove_install(conn=test_db, target_dir=stray)
    assert (stray / "nightly.bin").exists()


def test_remove_install_removes_a_marked_prefix(tmp_path, test_db):
    """The guard's accept arm: a prefix holding the installer's marker, away from
    the database, is removed and the row is reset."""
    prefix = _marked(tmp_path / "vol" / "runtime-deps")
    (prefix / "lib").mkdir()
    eb._update_state(test_db, status="installed", install_method="auto")
    test_db.commit()
    summary = eb.remove_install(conn=test_db, target_dir=prefix)
    assert summary["removed"] is True
    assert not prefix.exists()
    assert eb.get_install_status(test_db)["status"] == "not_installed"


def test_remove_install_refuses_a_marker_plus_one_foreign_entry(tmp_path, test_db):
    """hipaa 539 fold-2 re-check F1. The marker proves the installer wrote there,
    not that the directory holds only runtime files. A marked prefix with one
    entry outside :func:`runtime_prefix_layout` is refused, and everything
    survives."""
    prefix = _marked(tmp_path / "vol" / "rdeps")
    (prefix / "lib").mkdir()
    (prefix / "bundle.etbak").write_bytes(b"ciphertext")
    with pytest.raises(eb.RemoveTargetRefused, match="bundle.etbak"):
        eb.remove_install(conn=test_db, target_dir=prefix)
    assert (prefix / "bundle.etbak").exists() and (prefix / "lib").exists()


def test_remove_install_refuses_the_backup_directory_shape(tmp_path, test_db):
    """The walk-through hipaa gave: ``EMBEDDING_BITS_RUNTIME_DEPS=/app/data/backups``
    makes an install write ``INSTALLED.json`` and a pip tree INTO the backup
    directory. Backup bundles are not attached to the connection, so the
    database arm cannot see them; only the layout check stands between the
    [Remove] button and the encrypted §164.308(a)(7) copies."""
    backups = tmp_path / "data" / "backups"
    _marked(backups)
    (backups / "lib").mkdir()
    (backups / eb.WHEELS_DIRNAME).mkdir()
    for name in ("email-triage-2026-09-29.etbak", "email-triage-2026-09-30.etbak"):
        (backups / name).write_bytes(b"ciphertext")
    with pytest.raises(eb.RemoveTargetRefused, match="installer never writes"):
        eb.remove_install(conn=test_db, target_dir=backups)
    assert len(list(backups.glob("*.etbak"))) == 2, "the backups must survive"


def test_runtime_prefix_layout_is_derived_from_the_installer_and_pip():
    """The layout set holds the installer's own names (the constants every
    installer write uses) and the directories pip ``--prefix`` creates on this
    interpreter, and nothing a backup or certificate directory holds."""
    layout = eb.runtime_prefix_layout()
    for name in (eb.WHEELS_DIRNAME, eb.HF_CACHE_DIRNAME, eb.INSTALLED_MARKER_NAME):
        assert name in layout, name
    site = eb.runtime_site_packages_candidates(Path("/p"))
    for candidate in site:
        assert candidate.relative_to(Path("/p")).parts[0] in layout, candidate
    for foreign in ("backups", "certs", "triage.db", "bundle.etbak", "server.key"):
        assert foreign not in layout, foreign


def test_remove_install_refuses_a_garbage_marker(tmp_path, test_db):
    """db DB-539F2-1: the marker must PARSE with a known schema. db measured the
    eccc3125 guard ADMITTING a backups directory holding an unparseable marker,
    a ``.db.enc`` and ``master_key.bin``. Here the layout is clean, so only the
    parse check can refuse."""
    prefix = tmp_path / "vol" / "rdeps"
    (prefix / "lib").mkdir(parents=True)
    (prefix / eb.INSTALLED_MARKER_NAME).write_text("not json {", encoding="utf-8")
    with pytest.raises(eb.RemoveTargetRefused, match="readable"):
        eb.remove_install(conn=test_db, target_dir=prefix)
    assert (prefix / "lib").exists()


def test_remove_install_refuses_the_measured_backups_shape(tmp_path, test_db):
    """db's exact probe: garbage marker + ``triage-2026-09-29.db.enc`` +
    ``master_key.bin``. Refused, and both files survive."""
    backups = tmp_path / "data" / "backups"
    backups.mkdir(parents=True)
    (backups / eb.INSTALLED_MARKER_NAME).write_text("\x00garbage", encoding="utf-8")
    (backups / "triage-2026-09-29.db.enc").write_bytes(b"ciphertext")
    (backups / "master_key.bin").write_bytes(b"k" * 32)
    with pytest.raises(eb.RemoveTargetRefused):
        eb.remove_install(conn=test_db, target_dir=backups)
    assert (backups / "triage-2026-09-29.db.enc").exists()
    assert (backups / "master_key.bin").exists()


@pytest.mark.parametrize("marked", [True, False], ids=["marked", "unmarked"])
def test_remove_install_refuses_a_planted_database_file(tmp_path, test_db, marked):
    """devils-advocate teeth: an ``x.db`` in a would-be target is refused, with or
    without a valid marker, and the file still exists afterwards."""
    target = tmp_path / "vol" / "rdeps"
    (target / "lib").mkdir(parents=True)
    if marked:
        _marked(target)
    (target / "x.db").write_bytes(b"SQLite format 3\x00")
    with pytest.raises(eb.RemoveTargetRefused):
        eb.remove_install(conn=test_db, target_dir=target)
    assert (target / "x.db").exists()


def test_the_installer_refuses_a_foreign_target(tmp_path):
    """devils-advocate defence in depth: the installer never writes (or marks) a
    directory that already holds something outside its layout."""
    target = tmp_path / "data" / "backups"
    target.mkdir(parents=True)
    (target / "x.db").write_bytes(b"SQLite format 3\x00")
    reason = eb.install_target_refusal(target)
    assert "x.db" in reason
    # empty, missing, layout-only (a retry after a failed download) are all fine
    assert eb.install_target_refusal(tmp_path / "fresh") == ""
    partial = tmp_path / "partial"
    (partial / eb.WHEELS_DIRNAME).mkdir(parents=True)
    (partial / eb.HF_CACHE_DIRNAME).mkdir()
    assert eb.install_target_refusal(partial) == ""


@pytest.mark.asyncio
async def test_an_install_into_a_foreign_target_writes_nothing(
    tmp_path, test_db, fake_manifest_path,
):
    target = tmp_path / "data" / "backups"
    target.mkdir(parents=True)
    (target / "x.db").write_bytes(b"SQLite format 3\x00")
    result = await eb.install_auto(
        conn=test_db, manifest_path=fake_manifest_path, target_dir=target,
    )
    assert result.status == "failed"
    assert result.error_class == "InstallTargetRefused"
    assert sorted(p.name for p in target.iterdir()) == ["x.db"], (
        "the installer must not create wheels/, hf-cache/ or a marker there"
    )
    assert eb.get_install_status(test_db)["last_error_class"] == "InstallTargetRefused"


def test_remove_install_renames_and_the_purge_deletes_the_tombstone(tmp_path, test_db):
    """N-543 residual closed: remove_install only RENAMES the prefix (O(1)) and
    the delete happens in purge_removal_tombstones, which callers run OFF the
    DB writer. The tombstone is a SIBLING, so it is never inside a prefix the
    guard reads."""
    prefix = _marked(tmp_path / "vol" / "runtime-deps")
    (prefix / "lib" / "big").mkdir(parents=True)
    (prefix / "lib" / "big" / "f.bin").write_bytes(b"x" * 1024)
    summary = eb.remove_install(conn=test_db, target_dir=prefix)
    assert summary["removed"] is True and not prefix.exists()
    tombs = eb.removal_tombstones(prefix)
    assert [t.name for t in tombs] == [summary["tombstone"]]
    assert tombs[0].parent == prefix.parent
    assert (tombs[0] / "lib" / "big" / "f.bin").exists(), "the bytes are not deleted yet"
    assert eb.purge_removal_tombstones(prefix) == [summary["tombstone"]]
    assert eb.removal_tombstones(prefix) == []


def test_a_leftover_tombstone_is_purged_by_the_next_install_check(tmp_path, test_db):
    """A crash between the rename and the purge leaves a tombstone. The next
    remove's purge (and the installer's pre-write purge) deletes it; it never
    blocks the guard, because it is not inside the prefix."""
    prefix = _marked(tmp_path / "vol" / "runtime-deps")
    (prefix / "lib").mkdir()
    leftover = prefix.with_name(prefix.name + eb.REMOVAL_TOMBSTONE_INFIX + "1")
    (leftover / "lib").mkdir(parents=True)
    eb._refuse_unsafe_target(prefix, test_db)  # the guard is not confused
    assert eb.purge_removal_tombstones(prefix) == [leftover.name]
    assert prefix.exists(), "the purge touches tombstones only"


def test_the_purge_leaves_a_look_alike_that_is_not_a_tombstone(tmp_path):
    """devils-advocate round 4: a name match is not an identity. A sibling named
    ``<prefix>.removing-*`` that holds a foreign entry is left on disk."""
    prefix = tmp_path / "vol" / "runtime-deps"
    prefix.mkdir(parents=True)
    impostor = prefix.with_name(prefix.name + eb.REMOVAL_TOMBSTONE_INFIX + "x")
    impostor.mkdir()
    (impostor / "triage.db").write_bytes(b"SQLite format 3\x00")
    assert eb.purge_removal_tombstones(prefix) == []
    assert (impostor / "triage.db").exists()


def test_remove_install_refuses_a_symlinked_target(tmp_path, test_db):
    """devils-advocate round 4: renaming a symlink moves the link, not the tree,
    and the outcome row would then claim ``removed=True`` over bytes still on
    disk. A symlinked target is refused."""
    real = _marked(tmp_path / "vol" / "real-rdeps")
    (real / "lib").mkdir()
    link = tmp_path / "vol" / "rdeps-link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create a directory symlink")
    with pytest.raises(eb.RemoveTargetRefused, match="symbolic link"):
        eb.remove_install(conn=test_db, target_dir=link)
    assert (real / "lib").exists() and link.is_symlink()


def test_remove_install_refuses_a_symlink_to_the_default_prefix(tmp_path, test_db, monkeypatch):
    """devils-advocate (539 CI fold): the symlink refusal runs AFTER arms 1-2 but
    must stay BEFORE the unconditional admission of the default prefix, or a link
    to the default would be renamed (moving the link, not the tree)."""
    default = tmp_path / "rdeps"
    (default / "lib").mkdir(parents=True)
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(default))
    link = tmp_path / "vol" / "rdeps-link"
    link.parent.mkdir()
    try:
        link.symlink_to(default, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create a directory symlink")
    with pytest.raises(eb.RemoveTargetRefused, match="symbolic link"):
        eb.remove_install(conn=test_db, target_dir=link)
    assert (default / "lib").exists() and link.is_symlink()


def test_remove_install_refuses_a_symlink_loop(tmp_path, test_db):
    """A target whose resolution loops is refused cleanly (``resolve()`` raises
    on a loop; before the 539 CI fold the symlink check caught it first)."""
    a, b = tmp_path / "loop-a", tmp_path / "loop-b"
    try:
        a.symlink_to(b, target_is_directory=True)
        b.symlink_to(a, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create a directory symlink")
    with pytest.raises(eb.RemoveTargetRefused, match="symbolic link|cannot be resolved"):
        eb.remove_install(conn=test_db, target_dir=a)
