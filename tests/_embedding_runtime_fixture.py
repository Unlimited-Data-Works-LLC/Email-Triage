"""Build an embedding runtime-deps prefix in a state the N-524 gate accepts.

ONE builder, shared by the unit tests in ``tests/test_embedding_bits/`` and the
route/render pins in ``tests/test_web/``. It exists because a HALF-built fixture
silently disarms every behavioural arm that uses it: post-N-524
``add_runtime_to_sys_path`` refuses a prefix with no valid ``INSTALLED.json``, so
a test that builds only the directory tree observes "sys.path unchanged" whether
or not the code under test was ever fixed. A pin like that reads green forever
(``pattern_a_silently_partial_verification_rig_manufactures_findings``).

So the builder writes all four pieces — site-packages, one ``*.dist-info`` per
package, a manifest naming exactly those packages, and the marker produced by the
REAL ``write_installed_marker`` — and ``make_stale_prefix`` produces the
NEGATIVE state by the same route, so the two differ in one fact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from email_triage import embedding_bits as eb

DEFAULT_PACKAGES: tuple[tuple[str, str], ...] = (
    ("fake-a", "1.0"),
    ("fake-b", "2.0"),
)


def _write_tree(prefix: Path, packages) -> Path:
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = prefix / "lib" / pyver / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for name, version in packages:
        dist_info = site / f"{name.replace('-', '_')}-{version}.dist-info"
        dist_info.mkdir(exist_ok=True)
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            encoding="utf-8",
        )
    return site


def _write_manifest(path: Path, packages) -> dict:
    manifest = {
        "manifest_version": 1,
        "wheels": [
            {
                "name": name,
                "version": version,
                "filename": f"{name}-{version}.whl",
                "sha256": "0" * 64,
            }
            for name, version in packages
        ],
        "models": [],
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def history_entry(
    manifest: dict, version: int, *, security, advisories=(), release=None,
) -> dict:
    """One ``set_changes`` entry describing ``manifest`` (punch 569)."""
    return {
        "set_version": version,
        "set_digest": eb.manifest_set_digest(manifest),
        "security_change": security,
        "advisories": list(advisories),
        "release": release,
    }


def make_versioned_prefix(
    tmp_path: Path,
    monkeypatch,
    *,
    installed=DEFAULT_PACKAGES,
    declared=(("fake-a", "1.1"), ("fake-b", "2.0")),
    steps=(False,),
    advisories=(),
) -> tuple[Path, Path, Path]:
    """A prefix installed from set v1, under an image whose manifest is set
    v1+len(steps). ``steps`` is each later change's ``security_change`` (a value
    that is not a bool is written as-is, to test the strict parse). The install
    is recorded by the REAL ``write_installed_marker`` against the v1 manifest,
    so it differs from :func:`make_verified_prefix` in exactly the set history.
    Returns ``(prefix, site_packages, image_manifest_path)``."""
    prefix = tmp_path / "rdeps"
    site = _write_tree(prefix, installed)
    old_path = tmp_path / "manifest-v1.json"
    old = _write_manifest(old_path, installed)
    v1 = history_entry(old, 1, security=False)
    old["set_changes"] = [v1]
    old_path.write_text(json.dumps(old), encoding="utf-8")
    eb.write_installed_marker(
        target_dir=prefix, manifest=old,
        manifest_sha256=eb._manifest_sha256(old_path),
    )
    new_path = tmp_path / "manifest.json"
    new = _write_manifest(new_path, declared)
    history = [v1]
    for i, security in enumerate(steps, start=2):
        history.append({
            "set_version": i,
            "set_digest": "0" * 64,
            "security_change": security,
            "advisories": list(advisories) if security is True else [],
            "release": None,
        })
    history[-1]["set_digest"] = eb.manifest_set_digest(new)
    new["set_changes"] = history
    new_path.write_text(json.dumps(new), encoding="utf-8")
    point_defaults_at(monkeypatch, prefix, new_path)
    eb.invalidate_runtime_ready_cache()
    return prefix, site, new_path


def point_defaults_at(monkeypatch, prefix: Path, manifest_path: Path | None = None) -> None:
    """Point the runtime prefix (and the manifest) at test paths, the ONE way.

    The prefix default is patched on the module: punch 547 removed the
    ``EMBEDDING_BITS_RUNTIME_DEPS`` env read, and ``get_runtime_deps_path``
    reads ``DEFAULT_RUNTIME_DEPS`` at call time. The manifest resolver reads NO
    environment since the punch 539 fold-check (hipaa H539FC-8), so the manifest
    default is patched on the module; ``resolve_manifest_path`` reads that global
    at call time, so every in-process reader sees it."""
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(prefix))
    if manifest_path is not None:
        monkeypatch.setattr(eb, "DEFAULT_MANIFEST_PATH", str(manifest_path))


def make_verified_prefix(
    tmp_path: Path, monkeypatch, *, packages=DEFAULT_PACKAGES,
) -> tuple[Path, Path, Path]:
    """A prefix that PASSES the drift gate. ``(prefix, site_packages, manifest)``.

    The runtime prefix and the manifest are pointed at it through
    :func:`point_defaults_at`, and the ready-cache is invalidated, so a caller
    can assert on gate behaviour immediately.
    """
    prefix = tmp_path / "rdeps"
    site = _write_tree(prefix, packages)
    manifest_path = tmp_path / "manifest.json"
    manifest = _write_manifest(manifest_path, packages)
    point_defaults_at(monkeypatch, prefix, manifest_path)
    eb.write_installed_marker(
        target_dir=prefix,
        manifest=manifest,
        manifest_sha256=eb._manifest_sha256(manifest_path),
    )
    eb.invalidate_runtime_ready_cache()
    return prefix, site, manifest_path


def make_stale_prefix(
    tmp_path: Path,
    monkeypatch,
    *,
    installed=DEFAULT_PACKAGES,
    declared=(("fake-a", "9.9"), ("fake-b", "9.9")),
    write_marker: bool = True,
) -> tuple[Path, Path, Path]:
    """A prefix the gate must REFUSE — the 2026-05-18 shape in miniature.

    Packages from an OLD manifest are on disk with a marker recording them
    honestly; the image's manifest now declares different versions. Nothing is
    corrupt and every file hashes fine: the install is simply not the one this
    image expects, which is exactly the case that used to pass unnoticed.

    ``write_marker=False`` gives the other refusal shape — packages on disk with
    no record at all, which is every install made before this change shipped.
    """
    prefix = tmp_path / "rdeps"
    site = _write_tree(prefix, installed)
    old_manifest_path = tmp_path / "manifest-old.json"
    old_manifest = _write_manifest(old_manifest_path, installed)
    if write_marker:
        eb.write_installed_marker(
            target_dir=prefix,
            manifest=old_manifest,
            manifest_sha256=eb._manifest_sha256(old_manifest_path),
        )
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, declared)
    point_defaults_at(monkeypatch, prefix, manifest_path)
    eb.invalidate_runtime_ready_cache()
    return prefix, site, manifest_path
