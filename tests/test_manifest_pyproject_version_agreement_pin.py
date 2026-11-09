"""No package may be stated in contradictory versions by pyproject.toml and the runtime manifest.

``scripts/embedding-bits-manifest.json`` installs sha256-pinned wheels into the running container
(the embedding lazy-install). ``pyproject.toml`` declares versions for the image build and the
dev extra. When the same package appears in both, the two statements must not contradict each
other: the manifest's version must satisfy every pyproject specifier for that package. Dependabot
reads pyproject but not the manifest JSON, so the automated bump path can move only one side;
this pin makes the divergence loud instead of silent (punch 518, 2026-09-24).

Count-agnostic: the property is asserted over the INTERSECTION of the two files, computed at run
time. A package that enters both files is covered with no edit here.

SCOPE, stated honestly (DA 2026-09-24): this is NON-CONTRADICTION. For an exact pyproject pin
(``==``, today only markdown-it-py) it means the two versions are EQUAL. For a floor (``>=``,
today jinja2, packaging, regex, sentence-transformers, torch) a manifest bump upward always
satisfies it, so this pin does not keep those in step and is not meant to. An entry with an empty
specifier is not checked.
"""

from __future__ import annotations

import json
import re
import tomllib

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from _pin_harness import REPO_ROOT

PYPROJECT = REPO_ROOT / "pyproject.toml"
MANIFEST = REPO_ROOT / "scripts" / "embedding-bits-manifest.json"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _pyproject_specs(project: dict) -> dict[str, list[tuple[str, str]]]:
    """name -> [(where, specifier)] over dependencies and every optional extra."""
    out: dict[str, list[tuple[str, str]]] = {}
    lists = [("dependencies", project.get("dependencies", []))]
    lists += [(f"extra:{k}", v) for k, v in project.get("optional-dependencies", {}).items()]
    for where, reqs in lists:
        for raw in reqs:
            req = Requirement(raw)
            out.setdefault(_norm(req.name), []).append((where, str(req.specifier)))
    return out


def _manifest_versions(manifest: dict) -> dict[str, set[str]]:
    """name -> versions, over the arch-neutral wheels and every per-arch wheel set."""
    wheels = list(manifest.get("wheels", []))
    for arch_wheels in (manifest.get("wheels_by_arch") or {}).values():
        wheels += arch_wheels
    out: dict[str, set[str]] = {}
    for w in wheels:
        out.setdefault(_norm(w["name"]), set()).add(w["version"])
    return out


def _disagreements(project: dict, manifest: dict) -> list[str]:
    specs, versions = _pyproject_specs(project), _manifest_versions(manifest)
    bad = []
    for name in sorted(set(specs) & set(versions)):
        for where, spec in specs[name]:
            for v in sorted(versions[name]):
                # The manifest carries local labels such as "+cpu"; compare the public version.
                if spec and Version(v.split("+")[0]) not in SpecifierSet(spec):
                    bad.append(f"{name}: manifest {v} does not satisfy pyproject {where} '{spec}'")
    return bad


def _load() -> tuple[dict, dict]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return project, manifest


def test_shared_packages_agree() -> None:
    project, manifest = _load()
    assert _disagreements(project, manifest) == []


def test_the_intersection_is_not_empty() -> None:
    """Guards against a vacuous pass: if parsing broke, the intersection would be empty."""
    project, manifest = _load()
    shared = set(_pyproject_specs(project)) & set(_manifest_versions(manifest))
    assert "markdown-it-py" in shared


def test_teeth_manifest_side_drift_is_caught() -> None:
    project, manifest = _load()
    for w in manifest["wheels"]:
        if _norm(w["name"]) == "markdown-it-py":
            w["version"] = "4.3.0"
    assert any(d.startswith("markdown-it-py:") for d in _disagreements(project, manifest))


def test_teeth_per_arch_wheels_are_in_scope() -> None:
    """The per-arch merge must be live: eight shared-or-candidate packages exist ONLY there."""
    project, manifest = _load()
    arch_names = {
        _norm(w["name"]) for ws in manifest["wheels_by_arch"].values() for w in ws
    }
    neutral = {_norm(w["name"]) for w in manifest["wheels"]}
    arch_only_shared = (arch_names - neutral) & set(_pyproject_specs(project))
    assert arch_only_shared, "no arch-only package is shared with pyproject; teeth need one"
    target = sorted(arch_only_shared)[0]
    for ws in manifest["wheels_by_arch"].values():
        for w in ws:
            if _norm(w["name"]) == target:
                w["version"] = "0.0.1"
    assert any(d.startswith(f"{target}:") for d in _disagreements(project, manifest))


def test_teeth_pyproject_side_drift_is_caught() -> None:
    project, manifest = _load()
    dev = project["optional-dependencies"]["dev"]
    project["optional-dependencies"]["dev"] = [
        "markdown-it-py==4.3.0" if _norm(Requirement(r).name) == "markdown-it-py" else r for r in dev
    ]
    assert any(d.startswith("markdown-it-py:") for d in _disagreements(project, manifest))
