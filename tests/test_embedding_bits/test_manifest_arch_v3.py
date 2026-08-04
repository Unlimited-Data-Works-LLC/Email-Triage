""" multi-arch — embedding-bits manifest v3 + installer arch-resolution pins.

Count-agnostic structural pins (no ``len(...) == 8``): every binary wheel
present for one arch MUST have a same-named sibling for the other, the
shipped manifest must be fully hash-populated on BOTH arches, and the
installer's single arch-resolution point (``_load_manifest``) must merge the
running arch's binary wheels into the flat ``wheels`` list every downstream
consumer reads.

Grounding: the shipped ``scripts/embedding-bits-manifest.json`` is what the
image bakes; an arch added to one side but not the other (or shipped with a
placeholder hash) would leave an arm64 install unable to fetch a wheel — these
pins fail the build before that reaches a customer. The torch-+cpu pin guards
the  gate-A3 trap (a plain default-PyPI aarch64 torch is CUDA-bundled since
PyTorch 2.11; the CPU-only target must use the /whl/cpu +cpu wheel).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from email_triage.embedding_bits import _load_manifest, normalize_arch

_REPO = Path(__file__).resolve().parents[2]
_MANIFEST = _REPO / "scripts" / "embedding-bits-manifest.json"


def _raw() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# normalize_arch — the arch-selection SSOT
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("m", ["x86_64", "amd64", "AMD64", "x64", "X86_64"])
def test_normalize_arch_x86(m):
    assert normalize_arch(m) == "x86_64"


@pytest.mark.parametrize("m", ["aarch64", "arm64", "ARM64", "AArch64"])
def test_normalize_arch_arm(m):
    assert normalize_arch(m) == "aarch64"


@pytest.mark.parametrize("m", ["ppc64le", "s390x", "riscv64"])
def test_normalize_arch_unsupported_raises(m):
    """An unknown arch must fail LOUD — a silent skip would leave the binary
    wheels (torch/tokenizers/…) uninstalled and sentence_transformers broken.
    (An empty/None arg is NOT "unsupported" — it means "detect from the running
    system" via platform.machine(), covered by the x86/arm cases above.)"""
    with pytest.raises(RuntimeError, match="unsupported CPU arch"):
        normalize_arch(m)


# ---------------------------------------------------------------------------
# Shipped manifest v3 structure + arch completeness
# ---------------------------------------------------------------------------


def test_manifest_is_v3_with_wheels_by_arch():
    m = _raw()
    assert m["manifest_version"] >= 3
    assert "wheels_by_arch" in m, "v3 manifest must carry wheels_by_arch"
    assert set(m["wheels_by_arch"]) >= {"x86_64", "aarch64"}


def test_every_binary_wheel_has_a_sibling_on_both_arches():
    """Count-agnostic: the SET of binary-wheel names must match across arches.
    A wheel added to one arch but not the other is the drift this catches —
    asserted as set-equality, never ``== 8``."""
    by_arch = _raw()["wheels_by_arch"]
    names = {arch: {w["name"] for w in entries} for arch, entries in by_arch.items()}
    x86, arm = names["x86_64"], names["aarch64"]
    assert x86 == arm, (
        f"binary-wheel set differs across arches; "
        f"x86_64-only={x86 - arm}, aarch64-only={arm - x86}"
    )
    # version parity per wheel (same pinned version, just a different platform
    # tag) — except torch, which legitimately differs only by the +cpu local
    # version present on both (handled in the torch-specific pin below).
    ver = {
        arch: {w["name"]: w["version"] for w in entries}
        for arch, entries in by_arch.items()
    }
    for name in x86:
        assert ver["x86_64"][name] == ver["aarch64"][name], (
            f"{name} version differs across arches: "
            f"{ver['x86_64'][name]} vs {ver['aarch64'][name]}"
        )


def test_shipped_manifest_has_no_placeholder_hashes_either_arch():
    """The image bakes this manifest; a placeholder hash on EITHER arch would
    make that arch's install hard-fail. Every wheel (neutral + both arches)
    and every model file must carry a real sha256."""
    m = _raw()
    buckets = [m.get("wheels", [])]
    buckets += list(m.get("wheels_by_arch", {}).values())
    for bucket in buckets:
        for w in bucket:
            assert "PLACEHOLDER" not in str(w.get("sha256", "")), w["name"]
            assert len(w["sha256"]) == 64, w["name"]
    for model in m.get("models", []):
        for f in model.get("files", []):
            assert "PLACEHOLDER" not in str(f.get("sha256", "")), f["name"]


def test_neutral_wheels_are_arch_independent_and_binaries_are_tagged():
    """``wheels`` holds only py3-none-any (arch-neutral) wheels; the
    arch-specific buckets hold only wheels whose filename carries that arch's
    platform tag. A binary wheel leaking into ``wheels`` would be installed on
    the wrong arch."""
    m = _raw()
    for w in m.get("wheels", []):
        assert w["filename"].endswith("-none-any.whl"), (
            f"{w['name']} in neutral `wheels` is not py3-none-any "
            f"({w['filename']}) — it belongs in wheels_by_arch"
        )
    for arch, entries in m["wheels_by_arch"].items():
        tag = "x86_64" if arch == "x86_64" else "aarch64"
        for w in entries:
            assert tag in w["filename"], (
                f"{w['name']} in {arch} bucket lacks the {tag} platform tag "
                f"({w['filename']})"
            )


def test_torch_aarch64_is_cpu_only_not_cuda():
    """ gate-A3 trap: since PyTorch 2.11 a plain default-PyPI aarch64
    ``torch`` is CUDA-bundled (~426 MB + multi-GB CUDA). The CPU-only
    target MUST pin the /whl/cpu ``+cpu`` wheel. Pin both the +cpu local
    version AND the /whl/cpu index URL."""
    arm_torch = next(
        w for w in _raw()["wheels_by_arch"]["aarch64"] if w["name"] == "torch"
    )
    assert arm_torch["version"].endswith("+cpu"), arm_torch["version"]
    assert "+cpu" in arm_torch["filename"] or "%2Bcpu" in arm_torch["url"]
    assert "/whl/cpu" in arm_torch["url"], (
        "aarch64 torch must come from the CPU index, not default PyPI "
        "(default PyPI aarch64 torch is CUDA-bundled since 2.11)"
    )


# ---------------------------------------------------------------------------
# Installer arch-resolution — the single merge point
# ---------------------------------------------------------------------------


def test_load_manifest_merges_running_arch_binaries():
    """``_load_manifest(arch=…)`` returns a flat ``wheels`` = neutral + that
    arch's binary set, so every downstream consumer stays arch-unaware."""
    neutral = {w["name"] for w in _raw().get("wheels", [])}
    x86 = _load_manifest(_MANIFEST, arch="x86_64")
    arm = _load_manifest(_MANIFEST, arch="aarch64")
    x86_names = {w["name"] for w in x86["wheels"]}
    arm_names = {w["name"] for w in arm["wheels"]}
    # Same overall wheel-NAME set on both arches (neutral + binaries).
    assert x86_names == arm_names
    assert neutral <= x86_names
    # ...but the resolved binary FILENAMES differ by arch.
    x86_files = {w["filename"] for w in x86["wheels"]}
    arm_files = {w["filename"] for w in arm["wheels"]}
    assert x86_files != arm_files
    # The arch-specific wheels actually carry the right platform tag.
    assert any("x86_64" in f for f in x86_files)
    assert any("aarch64" in f for f in arm_files)
    assert not any("aarch64" in f for f in x86_files)


def test_load_manifest_unknown_arch_raises():
    with pytest.raises(RuntimeError):
        _load_manifest(_MANIFEST, arch="ppc64le")


def test_load_manifest_v2_flat_still_loads(tmp_path):
    """Back-compat: a v2 manifest (flat ``wheels``, no wheels_by_arch) loads
    unchanged — no arch resolution applied."""
    v2 = {"manifest_version": 2, "wheels": [{"name": "x", "filename": "x-none-any.whl", "sha256": "0" * 64}], "models": []}
    p = tmp_path / "v2.json"
    p.write_text(json.dumps(v2), encoding="utf-8")
    loaded = _load_manifest(p, arch="aarch64")
    assert [w["name"] for w in loaded["wheels"]] == ["x"]
