"""Privacy invariants over the embedding lazy-install: WHERE it calls, and WHAT it installs.

Two halves, both about ``scripts/embedding-bits-manifest.json``:

* **hosts** (original) — a static source scan proving the installer contacts
  no host outside the allowlist.
* **identities** (punch 513/514/515, hipaa-sme N4/N5/N6, 2026-09-24) — the
  packages the manifest puts INSIDE the PHI-bearing container are walked
  through the same admission predicate the ``pyproject.toml`` dependency
  review uses, each must record WHICH package requires it, and each
  regeneration must record the package set it installs so a bump cannot
  widen that set silently. Register §3 row "Runtime embedding package set
  — identity review".


The lazy-install path downloads wheels + model files over
HTTPS. The only URLs the installer is permitted to contact are the
ones listed in scripts/embedding-bits-manifest.json (resolved via
PyPI JSON API for placeholder PyPI URLs at build time, baked into
the manifest at release-cut time).

This is a STATIC SOURCE SCAN — not a runtime test. We grep the
embedding_bits package source for any literal URL that isn't an
allowlisted host. Adding a new HTTP call to the installer requires
adding the host to the allowlist here (which is a security review
gate, not a refactor).

Why static-source:
* A runtime test would require running the installer to confirm.
  Some telemetry endpoints fire only on rare paths (model auto-
  download retry, upgrade ping). Static scan catches them all.
* Tests grep the SOURCE, not the BUILT module — Python bytecode
  could in principle hide a literal URL behind base64 / format
  ops; the source check is the truth.

Allowlisted hosts (download endpoints in the production manifest):
  download.pytorch.org    PyTorch CPU index (torch wheel)
  files.pythonhosted.org  PyPI hosted-file CDN (all other wheels)
  pypi.org                PyPI JSON metadata API (URL resolution
                          step in the builder script)
  huggingface.co          HuggingFace model file CDN

Banned hosts (HF / pip / Python telemetry):
  hf.co                                 abbreviated HF (telemetry sometimes)
  huggingface.co/api/telemetry         explicit HF telemetry endpoint
  pypi.org/simple                       not used; we only hit JSON
  api.github.com                        not used in installer path
  api.pypistats.org                     not used
  warehouse.python.org                  not used
"""

from __future__ import annotations

import importlib.util
import json
import re
import zipfile
from pathlib import Path

import pytest

# --- which files this invariant covers ---
from _pin_harness import SRC_ROOT as PKG_ROOT  # census run15 #3 — harness SRC root, not a hand-rolled off-by-one

# The ONE admission predicate, shared with the pyproject.toml dependency
# walk (punch 513 / PD#5 — a copied denylist in this file would drift away
# from the one that gate uses).
from _privacy_dep_funnel import (
    MANIFEST_BUILDER,
    MANIFEST_FILE,
    REPO_ROOT,
    ROOT_REQUIRER,
    RUNTIME_KNOWN_SAFE,
    admission_failure,
    normalise,
    parse_allowlist_overrides,
)

EMBEDDING_BITS_SOURCES = [
    PKG_ROOT / "embedding_bits" / "__init__.py",
    # The manifest builder is in scripts/; same allowlist applies.
    MANIFEST_BUILDER,
]


# --- allowlist: literal substrings permitted in URLs ---
ALLOWLISTED_HOSTS = (
    "download.pytorch.org",
    "files.pythonhosted.org",
    "pypi.org",          # used only for JSON metadata in the builder
    "huggingface.co",    # model file CDN
)

# Hosts that should NEVER appear in the installer module.
BANNED_HOSTS = (
    "hf.co",
    "api.github.com",
    "api.pypistats.org",
    "warehouse.python.org",
    "googleapis.com",     # GCS / Drive — out of scope
    "amazonaws.com",      # S3 — out of scope
)


URL_REGEX = re.compile(r'https?://([a-zA-Z0-9_.\-]+)/?[^\s\'"]*')


@pytest.mark.parametrize("path", EMBEDDING_BITS_SOURCES, ids=lambda p: p.name)
def test_no_banned_urls(path: Path):
    """No banned host appears in the embedding-bits installer source."""
    if not path.exists():
        pytest.skip(f"{path} not present in this checkout")
    text = path.read_text(encoding="utf-8")
    for host in BANNED_HOSTS:
        assert host not in text, (
            f"Banned host {host!r} found in {path}; this is a privacy "
            f"regression — embedding-bits installer must NOT call "
            f"telemetry / out-of-scope endpoints. Either remove the "
            f"call or update the privacy review."
        )


@pytest.mark.parametrize("path", EMBEDDING_BITS_SOURCES, ids=lambda p: p.name)
def test_every_url_is_allowlisted(path: Path):
    """Every literal URL in the installer module points at an allowlisted host."""
    if not path.exists():
        pytest.skip(f"{path} not present in this checkout")
    text = path.read_text(encoding="utf-8")
    for match in URL_REGEX.finditer(text):
        host = match.group(1)
        if any(host == h or host.endswith("." + h) for h in ALLOWLISTED_HOSTS):
            continue
        pytest.fail(
            f"URL host {host!r} found in {path} is NOT in the privacy "
            f"allowlist. Either add the host to ALLOWLISTED_HOSTS in "
            f"tests/test_privacy_invariants_no_embedding_telemetry.py "
            f"(after security review) or remove the URL from the "
            f"installer."
        )


def test_pip_telemetry_disabled_in_env():
    """The installer module unconditionally sets PIP_DISABLE_PIP_VERSION_CHECK
    and HF_HUB_DISABLE_TELEMETRY at module import time."""
    src_text = (PKG_ROOT / "embedding_bits" / "__init__.py").read_text(
        encoding="utf-8",
    )
    # Punch 547 (N-554): these are FORCED assignments at import time, not
    # setdefault(). An inherited env value of "0" used to win and re-enable
    # the egress; a forced "1" cannot be overridden from the environment.
    for key in ("PIP_DISABLE_PIP_VERSION_CHECK", "HF_HUB_DISABLE_TELEMETRY",
                "DO_NOT_TRACK", "HF_HUB_DISABLE_IMPLICIT_TOKEN",
                "HF_HUB_DISABLE_PROGRESS_BARS"):
        assert f'os.environ["{key}"] = "1"' in src_text, key
        assert f'os.environ.setdefault("{key}"' not in src_text, key


# ===========================================================================
# Identity review of the RUNTIME package set
# (punch 513 / 514 / 515 — hipaa-sme N4 / N5 / N6, register §3)
#
# The host scan above answers "where does the installer CALL". It says
# nothing about "WHAT does the installer install", and the pyproject
# dependency-review gate walks pyproject.toml only — so the wheels landing
# in /app/data/runtime-deps/site-packages inside the PHI-bearing container
# had no identity-level privacy record at all. These three sections are
# that record's enforcement:
#
#   513 — every wheel NAME goes through the SAME admission predicate the
#         pyproject walk uses (imported from _privacy_dep_funnel, not a
#         copied denylist), over EVERY entry in both `wheels` and
#         `wheels_by_arch` (count-agnostic: the walk is the generator's own
#         iterator, so the gate cannot disagree with the writer about which
#         entries exist).
#   514 — every wheel records WHICH package requires it (`required_by`),
#         machine-derived from the wheels' METADATA by the generator.
#   515 — every regeneration records the package set it installs plus the
#         added/removed delta, and an ADDED package may not carry
#         network-capable imports without an explicit operator acceptance.
# ===========================================================================


def _load_builder():
    """The manifest generator module, loaded by path.

    Its filename has dashes, so it cannot be imported normally (the
    known-safe admission-log pin loads the dep-review gate the same way).
    Loading it gives this pin the generator's OWN manifest walk
    (`iter_wheel_entries`) and name normaliser, so the gate that checks the
    record and the writer that produces it cannot drift apart in WHICH
    entries they consider. Module level is defs + constants only.
    """
    spec = importlib.util.spec_from_file_location(
        "_embedding_manifest_builder_for_pin", MANIFEST_BUILDER,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BUILDER = _load_builder()

# Adversarial names for the normaliser cross-check: the generator and the
# funnel each own a PEP-503 normaliser (the generator cannot import from
# tests/), so the two are pinned EQUAL rather than merged.
_NORMALISE_PROBES = (
    "markdown-it-py", "markdown_it_py", "MARKDOWN.IT.PY", "Markdown_It.Py",
    "hf_xet", "HF-XET", "scikit-learn", "SciKit_Learn", "Pillow",
    "sentence_transformers", " typer ", "mdurl",
)


def _read_manifest() -> dict:
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


def _entries(manifest: dict) -> list[tuple[str | None, dict]]:
    """Every wheel entry, via the generator's own walk."""
    return list(_BUILDER.iter_wheel_entries(manifest))


def _manifest_names(manifest: dict) -> set[str]:
    return {normalise(e["name"]) for _arch, e in _entries(manifest)}


def _reviewed_sets() -> tuple[frozenset[str], set[str]]:
    """The runtime surface's reviewed sets: in-gate + operator overrides.

    The override set is EMPTY on the public mirror (internal documentation
    does not ship), which closes the override door there rather than
    opening it — see the PUBLISH NOTE in _privacy_dep_funnel.
    """
    return RUNTIME_KNOWN_SAFE, parse_allowlist_overrides()


def identity_offenders(manifest: dict) -> list[str]:
    """Every wheel name the shared admission predicate REFUSES (513)."""
    reviewed = _reviewed_sets()
    offenders: list[str] = []
    for arch, entry in _entries(manifest):
        surface = "wheels" if arch is None else f"wheels_by_arch.{arch}"
        reason = admission_failure(
            entry["name"], reviewed=reviewed, surface=surface,
        )
        if reason is not None:
            offenders.append(f"{surface}::{entry['name']} — {reason}")
    return offenders


def dead_reviewed_entries(
    manifest: dict, reviewed=RUNTIME_KNOWN_SAFE,
) -> list[str]:
    """Reviewed names this manifest does NOT install — pre-approvals (513).

    The identity walk proves manifest ⊆ reviewed. Without this reverse arm,
    a package trimmed from the manifest (pillow's own rationale invites a
    future trim) but left in the reviewed set becomes a standing
    pre-approval: a later bump re-adds it and the 513 walk passes with no
    human looking, and 515 cannot catch it either when the package has no
    Python-level network import. Same stale-guard shape the pin-harness
    meta-pin uses for dead _ALLOW entries and the admission log uses for
    its may-only-shrink grandfather set.
    """
    return sorted({normalise(n) for n in reviewed} - _manifest_names(manifest))


def required_by_offenders(manifest: dict) -> list[str]:
    """Every wheel entry whose ``required_by`` record is missing or bogus (514)."""
    names = _manifest_names(manifest)
    offenders: list[str] = []
    for arch, entry in _entries(manifest):
        surface = "wheels" if arch is None else f"wheels_by_arch.{arch}"
        where = f"{surface}::{entry.get('name')!r}"
        value = entry.get("required_by")
        if not isinstance(value, list) or not value:
            offenders.append(
                f"{where} has no required_by — regenerate with "
                f"scripts/build-embedding-bits-manifest.py so the field is "
                f"derived from the wheel's METADATA, never hand-written."
            )
            continue
        own = normalise(entry["name"])
        for requirer in value:
            if not isinstance(requirer, str) or not requirer.strip():
                offenders.append(f"{where} has an empty required_by element")
                continue
            norm = normalise(requirer)
            if norm == own:
                offenders.append(f"{where} lists ITSELF as its requirer")
            elif norm == normalise(ROOT_REQUIRER):
                if len(value) != 1:
                    offenders.append(
                        f"{where} mixes {ROOT_REQUIRER!r} with package "
                        f"requirers {value} — a wheel is either a direct "
                        f"install target or pulled in by other packages."
                    )
            elif norm not in names:
                offenders.append(
                    f"{where} says {requirer!r} requires it, but no such "
                    f"package is in this manifest (and it is not "
                    f"{ROOT_REQUIRER!r}) — the record names a package that "
                    f"is not installed."
                )
    return offenders


def audit_offenders(manifest: dict) -> list[str]:
    """Everything wrong with the regeneration record (515).

    Checks the record is PRESENT, describes THIS manifest, and that every
    package this regeneration ADDED was admitted by the 513 funnel and
    carries no network-capable import the operator has not accepted.
    """
    audit = manifest.get("regeneration_audit")
    if not isinstance(audit, dict):
        return [
            "no regeneration_audit block — the manifest does not record "
            "which packages it installs, so a bump that widens the set "
            "leaves no trace. Regenerate with "
            "scripts/build-embedding-bits-manifest.py."
        ]
    offenders: list[str] = []
    live = _manifest_names(manifest)
    recorded = {normalise(n) for n in (audit.get("package_set") or [])}
    if recorded != live:
        offenders.append(
            f"regeneration_audit.package_set does not describe this "
            f"manifest: only-recorded={sorted(recorded - live)}, "
            f"only-live={sorted(live - recorded)}. Every wheel change "
            f"must go through a regeneration so the record moves with it."
        )
    previous = audit.get("previous_package_set")
    if previous is not None and not isinstance(previous, list):
        offenders.append(
            f"regeneration_audit.previous_package_set must be a list or "
            f"null, got {type(previous).__name__}"
        )
    added = [normalise(n) for n in (audit.get("added") or [])]
    removed = [normalise(n) for n in (audit.get("removed") or [])]
    stray_added = sorted(set(added) - live)
    if stray_added:
        offenders.append(
            f"regeneration_audit.added names package(s) this manifest does "
            f"not install: {stray_added}"
        )
    stray_removed = sorted(set(removed) & live)
    if stray_removed:
        offenders.append(
            f"regeneration_audit.removed names package(s) this manifest "
            f"still installs: {stray_removed}"
        )
    hits = {
        normalise(k): sorted(v)
        for k, v in (audit.get("network_import_hits") or {}).items()
    }
    accepted = {
        normalise(k): sorted(v)
        for k, v in (audit.get("accepted_network_imports") or {}).items()
    }
    reviewed = _reviewed_sets()
    for name in added:
        reason = admission_failure(
            name, reviewed=reviewed, surface="regeneration_audit.added",
        )
        if reason is not None:
            offenders.append(f"added package {name!r} — {reason}")
        found = hits.get(name)
        if found and accepted.get(name) != found:
            offenders.append(
                f"added package {name!r} imports {found} and inherits the "
                f"'no network-capable package' review of whatever pulled "
                f"it in. Review it, then re-run the generator with "
                f"--accept-network-import {name} so the acceptance is "
                f"recorded (accepted={accepted.get(name)})."
            )
    return offenders


def _seed_manifest(*, extra_neutral=None, extra_arch=None) -> dict:
    """A minimal manifest shaped like the real one, for the teeth tests.

    Deliberately NOT the live file with a mutation applied: a seeded
    fixture keeps a teeth test from going quiet if the live manifest
    changes shape.
    """
    manifest = {
        "manifest_version": 3,
        "wheels": [
            {
                "name": "sentence-transformers", "version": "5.5.0",
                "filename": "sentence_transformers-5.5.0-py3-none-any.whl",
                "required_by": ["email-triage"],
            },
            {
                "name": "typer", "version": "0.25.1",
                "filename": "typer-0.25.1-py3-none-any.whl",
                "required_by": ["transformers"],
            },
            {
                "name": "transformers", "version": "5.8.1",
                "filename": "transformers-5.8.1-py3-none-any.whl",
                "required_by": ["sentence-transformers"],
            },
        ],
        "wheels_by_arch": {
            "x86_64": [
                {
                    "name": "torch", "version": "2.12.0+cpu",
                    "filename": "torch-2.12.0+cpu-x86_64.whl",
                    "required_by": ["sentence-transformers"],
                },
            ],
            "aarch64": [
                {
                    "name": "torch", "version": "2.12.0+cpu",
                    "filename": "torch-2.12.0+cpu-aarch64.whl",
                    "required_by": ["sentence-transformers"],
                },
            ],
        },
        "models": [],
    }
    for entry in extra_neutral or []:
        manifest["wheels"].append(entry)
    for entry in extra_arch or []:
        manifest["wheels_by_arch"]["x86_64"].append(entry)
    names = sorted({
        normalise(e["name"]) for _a, e in _BUILDER.iter_wheel_entries(manifest)
    })
    manifest["regeneration_audit"] = {
        "previous_package_set": names,
        "package_set": names,
        "added": [],
        "removed": [],
        "network_import_hits": {},
        "accepted_network_imports": {},
    }
    return manifest


def _synthetic_wheel(path: Path, name: str, version: str, *, body: str) -> Path:
    """A minimal real .whl: a dist-info/METADATA member + one .py member.

    Lets the generator's fail-closed arm be exercised for real — the
    refusal reads a wheel's Python members, so a fixture that is not a
    zip with a `.py` inside would test nothing.
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n",
        )
        zf.writestr(f"{name}/__init__.py", body)
    return path


class TestRuntimePackageIdentity:
    """513 — every runtime wheel goes through the pyproject walk's predicate.

    MUST: no wheel in the shipped manifest is refused by the shared
    predicate (asserted over every entry the generator's own walk yields);
    the walk is non-vacuous on both surfaces and both arches; the predicate
    is the imported funnel, not a local re-implementation; a denylisted
    wheel and an unreviewed wheel are both caught while a reviewed one
    passes.

    Also MUST: no name sits in the reviewed set that this manifest does not
    install (the reverse arm — a reviewed name with no entry is a standing
    pre-approval for a future re-add).

    Does NOT prove: that a reviewed package is harmless. Admission means a
    human put the name in RUNTIME_KNOWN_SAFE (or an operator exception),
    the same trust model _KNOWN_SAFE gives pyproject.toml. It also cannot
    see a package pip resolves at install time that is NOT in the manifest
    — the installer runs --no-deps, and test_manifest_pyproject_version_
    agreement_pin covers the version side.
    """

    def test_every_manifest_wheel_passes_the_shared_admission_predicate(self):
        assert identity_offenders(_read_manifest()) == []

    def test_the_walk_is_not_vacuous(self):
        """A gate that inspects nothing reads exactly like a gate that passes."""
        manifest = _read_manifest()
        entries = _entries(manifest)
        assert entries, "the walk yielded no wheel entries at all"
        arches = {arch for arch, _e in entries if arch is not None}
        assert arches >= {"x86_64", "aarch64"}, arches
        assert any(arch is None for arch, _e in entries), "no neutral wheels walked"

    def test_the_predicate_is_the_shared_funnel_not_a_local_copy(self):
        """PD#5: the pyproject walk imports this same object."""
        assert admission_failure.__module__ == "_privacy_dep_funnel"
        assert admission_failure(
            "anthropic", reviewed=({"anthropic"},),
        ) is not None, "the denylist must beat any reviewed set"

    def test_teeth_an_injected_package_in_a_manifest_FILE_reds_the_walk(self, tmp_path, monkeypatch):
        """DA-513-1. The decisive probe, end to end: take the SHIPPED manifest,
        append one unreviewed package, write it to a real file, and re-run the
        walk through its own read path. A green suite is consistent with a dead
        detector; this arm distinguishes them at the seam where a lazily-
        installed package actually arrives, not at the predicate alone."""
        manifest = _read_manifest()
        manifest["wheels"].append({
            "name": "telemetry-sdk", "version": "1.0.0",
            "filename": "telemetry_sdk-1.0.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/x/telemetry_sdk-1.0.0-py3-none-any.whl",
            "sha256": "0" * 64, "size_bytes": 1,
            "rationale": "injected by a teeth test", "required_by": ["transformers"],
        })
        path = tmp_path / "embedding-bits-manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setitem(globals(), "MANIFEST_FILE", path)
        offenders = identity_offenders(_read_manifest())
        assert any("telemetry-sdk" in o for o in offenders), offenders

    def test_an_operator_exception_in_the_allowlist_doc_admits_a_runtime_package(
        self, tmp_path, monkeypatch,
    ):
        """The runbook tells an operator that a `## Approved exceptions` bullet
        is the second door for this surface. Enforce that the door actually
        opens — an instruction no test covers is a claim the gate does not
        keep — and that it is shut before the bullet exists."""
        import _privacy_dep_funnel as funnel
        seeded = _seed_manifest(extra_neutral=[{
            "name": "some-new-transitive", "version": "0.1.0",
            "filename": "some_new_transitive-0.1.0-py3-none-any.whl",
            "required_by": ["typer"],
        }])
        assert any("some-new-transitive" in o for o in identity_offenders(seeded))
        doc = tmp_path / "privacy-dep-allowlist.md"
        doc.write_text(
            "# x\n\n## Approved exceptions\n\n"
            "- **Package**: `some-new-transitive>=0.1`\n"
            "  - **Reviewer**: teeth test\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(funnel, "ALLOWLIST_FILE", doc)
        assert identity_offenders(seeded) == []

    def test_no_reviewed_name_is_a_standing_pre_approval(self):
        """Every name in RUNTIME_KNOWN_SAFE is installed by this manifest, so
        the set cannot carry an approval for a package nothing installs."""
        assert dead_reviewed_entries(_read_manifest()) == []

    def test_teeth_a_reviewed_name_the_manifest_dropped_is_caught(self):
        seeded = _seed_manifest()
        assert dead_reviewed_entries(seeded, {"typer", "pillow"}) == ["pillow"]
        assert dead_reviewed_entries(seeded, {"typer"}) == []

    def test_the_override_door_degrades_closed_when_its_doc_is_absent(self):
        """Mirror safety: this walk SHIPS, internal documentation does
        not. The override parser must return an empty set there — an empty
        override set can only REFUSE more, never admit more — instead of
        raising at runtime where --collect-only cannot see it (the N-504
        failure class)."""
        import _privacy_dep_funnel as funnel
        original = funnel.ALLOWLIST_FILE
        try:
            funnel.ALLOWLIST_FILE = REPO_ROOT / "docs" / "does-not-exist-here.md"  # publish: absent-tolerant: a probe path that exists nowhere by design, inside the very pin that proves the degrade; pinned by test_the_override_door_degrades_closed_when_its_doc_is_absent
            assert funnel.parse_allowlist_overrides() == set()
            assert funnel.admission_failure(
                "sentence-transformers", reviewed=(RUNTIME_KNOWN_SAFE,),
            ) is None
            # The property that is actually load-bearing, asserted over EVERY wheel
            # instead of one hardcoded name (punch 537 panel 3, DA-A1): with the
            # override doc absent the whole manifest must still be admitted. The
            # single-name assert above passed while 12 of the 13 override entries
            # went unexercised, which is PD#1 — assert the property over every site.
            assert identity_offenders(_read_manifest()) == [], (
                "with the override doc absent the walk must still admit every wheel "
                "the manifest installs — otherwise the mirror suite goes RED, not "
                "merely non-erroring"
            )
        finally:
            funnel.ALLOWLIST_FILE = original

    def test_teeth_a_denylisted_wheel_is_caught(self):
        seeded = _seed_manifest(extra_neutral=[{
            "name": "anthropic", "version": "1.0.0",
            "filename": "anthropic-1.0.0-py3-none-any.whl",
            "required_by": ["transformers"],
        }])
        offenders = identity_offenders(seeded)
        assert any("anthropic" in o for o in offenders), offenders

    def test_teeth_an_unreviewed_wheel_is_caught(self):
        """The arm that matters for N6: a bump adds an innocuous-looking name."""
        seeded = _seed_manifest(extra_arch=[{
            "name": "some-new-transitive", "version": "0.1.0",
            "filename": "some_new_transitive-0.1.0-x86_64.whl",
            "required_by": ["torch"],
        }])
        offenders = identity_offenders(seeded)
        assert any("some-new-transitive" in o for o in offenders), offenders

    def test_teeth_a_reviewed_wheel_passes(self):
        """The other arm: a gate that refuses everything is not a gate."""
        assert identity_offenders(_seed_manifest()) == []


class TestRequiredBy:
    """514 — every wheel records which package requires it.

    MUST: every entry in both surfaces carries a non-empty ``required_by``
    whose elements are packages this manifest installs or the app root
    literal; the root literal is never mixed with package requirers; no
    entry names itself; the generator's root literal and normaliser agree
    with the funnel's.

    Does NOT prove: that the recorded requirer is the TRUE one — the pin
    checks the shape and the referent, not the derivation. The derivation's
    integrity comes from the generator computing the field from each
    wheel's own METADATA (``required_by_source`` in the audit block records
    the method), so a hand-edited value is a deliberate act that the next
    regeneration overwrites.
    """

    def test_every_wheel_records_who_requires_it(self):
        assert required_by_offenders(_read_manifest()) == []

    def test_the_seven_v011_bump_entries_name_a_real_requirer(self):
        """The N-5 finding by name: the seven "Added in the v0.1.1 HF stack
        bump" entries said only that. Each must now name a requirer, and
        that requirer must itself be in the manifest."""
        manifest = _read_manifest()
        names = _manifest_names(manifest)
        bump_only = {
            "markdown-it-py", "mdurl", "pygments", "rich", "setuptools",
            "shellingham", "typer",
        }
        seen = {}
        for _arch, entry in _entries(manifest):
            norm = normalise(entry["name"])
            if norm in bump_only:
                seen[norm] = entry.get("required_by")
        assert set(seen) == bump_only, f"missing from the manifest: {bump_only - set(seen)}"
        for name, value in seen.items():
            assert value, f"{name} still has no required_by"
            assert all(normalise(v) in names for v in value), (
                f"{name} required_by={value} names a package not in the manifest"
            )

    def test_root_requirer_literal_agrees_with_the_generator(self):
        assert _BUILDER.ROOT_REQUIRER == ROOT_REQUIRER

    @pytest.mark.parametrize("name", _NORMALISE_PROBES)
    def test_generator_and_funnel_normalise_agree(self, name):
        """Two PEP-503 normalisers exist because the generator cannot import
        from tests/; pin them equal so neither can drift alone."""
        assert _BUILDER._norm_pkg(name) == normalise(name)

    def test_teeth_a_missing_required_by_is_caught(self):
        seeded = _seed_manifest()
        seeded["wheels"][1].pop("required_by")
        offenders = required_by_offenders(seeded)
        assert any("has no required_by" in o for o in offenders), offenders

    def test_teeth_a_required_by_naming_a_non_manifest_package_is_caught(self):
        seeded = _seed_manifest()
        seeded["wheels_by_arch"]["aarch64"][0]["required_by"] = ["not-installed-anywhere"]
        offenders = required_by_offenders(seeded)
        assert any("not-installed-anywhere" in o for o in offenders), offenders

    def test_teeth_a_self_referential_required_by_is_caught(self):
        seeded = _seed_manifest()
        seeded["wheels"][1]["required_by"] = ["typer"]
        offenders = required_by_offenders(seeded)
        assert any("ITSELF" in o for o in offenders), offenders

    def test_teeth_mixing_the_root_literal_with_a_package_requirer_is_caught(self):
        seeded = _seed_manifest()
        seeded["wheels"][0]["required_by"] = [ROOT_REQUIRER, "typer"]
        offenders = required_by_offenders(seeded)
        assert any("mixes" in o for o in offenders), offenders

    def test_teeth_a_well_formed_manifest_passes(self):
        assert required_by_offenders(_seed_manifest()) == []


class TestRegenerationAudit:
    """515 — each regeneration records the package set, and a widened set fails.

    MUST: the shipped manifest carries a ``regeneration_audit`` whose
    ``package_set`` is exactly the set of packages it installs (so adding a
    wheel entry without regenerating fails here); ``added``/``removed``
    refer to this manifest; every ADDED package passes the 513 predicate;
    an ADDED package with recorded network-capable imports fails unless the
    operator's acceptance for exactly those modules is recorded.

    Does NOT prove: that ``network_import_hits`` is a true scan result —
    the wheels are not in the repo, so this pin cannot re-run the scan. It
    asserts the record's internal consistency; the scan itself is the
    generator's job (``_network_import_hits``, Python members only, blind
    to compiled extensions), and every regeneration rewrites the whole
    block so a hand-edited empty map is a visible diff, not a quiet one.
    Nor is ``accepted_network_imports`` a durable review record: it covers
    the ONE regeneration that added the package, and the next regeneration
    (which sees the package in ``previous_package_set``, so not added)
    empties it. The durable record is the RUNTIME_KNOWN_SAFE entry plus the
    git history of the accepting commit.
    """

    def test_the_recorded_package_set_is_the_live_one(self):
        manifest = _read_manifest()
        audit = manifest.get("regeneration_audit")
        assert isinstance(audit, dict), "shipped manifest has no regeneration_audit"
        assert {normalise(n) for n in audit["package_set"]} == _manifest_names(manifest)

    def test_the_shipped_audit_has_no_offenders(self):
        assert audit_offenders(_read_manifest()) == []

    def test_teeth_a_missing_audit_block_is_caught(self):
        seeded = _seed_manifest()
        seeded.pop("regeneration_audit")
        offenders = audit_offenders(seeded)
        assert any("no regeneration_audit" in o for o in offenders), offenders

    def test_teeth_a_stale_package_set_is_caught(self):
        """The live arm with teeth: a wheel added to the manifest without a
        regeneration leaves package_set behind, and that is the shape of a
        silently-widened runtime set."""
        seeded = _seed_manifest(extra_neutral=[{
            "name": "rich", "version": "15.0.0",
            "filename": "rich-15.0.0-py3-none-any.whl",
            "required_by": ["typer"],
        }])
        seeded["regeneration_audit"]["package_set"] = [
            n for n in seeded["regeneration_audit"]["package_set"] if n != "rich"
        ]
        offenders = audit_offenders(seeded)
        assert any("does not describe this manifest" in o for o in offenders), offenders

    def test_teeth_an_added_package_the_manifest_does_not_install_is_caught(self):
        seeded = _seed_manifest()
        seeded["regeneration_audit"]["added"] = ["never-installed-here"]
        offenders = audit_offenders(seeded)
        assert any("does not install" in o for o in offenders), offenders

    def test_teeth_a_removed_package_the_manifest_still_installs_is_caught(self):
        seeded = _seed_manifest()
        seeded["regeneration_audit"]["removed"] = ["typer"]
        offenders = audit_offenders(seeded)
        assert any("still installs" in o for o in offenders), offenders

    def test_teeth_an_added_network_capable_package_without_acceptance_is_caught(self):
        seeded = _seed_manifest(extra_neutral=[{
            "name": "fsspec", "version": "2026.4.0",
            "filename": "fsspec-2026.4.0-py3-none-any.whl",
            "required_by": ["huggingface-hub"],
        }])
        audit = seeded["regeneration_audit"]
        audit["added"] = ["fsspec"]
        audit["previous_package_set"] = [
            n for n in audit["package_set"] if n != "fsspec"
        ]
        audit["network_import_hits"] = {"fsspec": ["aiohttp", "requests"]}
        offenders = audit_offenders(seeded)
        assert any("inherits the" in o for o in offenders), offenders

    def test_teeth_an_accepted_added_package_passes(self):
        """The other arm: the operator's recorded acceptance clears it —
        otherwise the gate blocks every bump and gets switched off."""
        seeded = _seed_manifest(extra_neutral=[{
            "name": "fsspec", "version": "2026.4.0",
            "filename": "fsspec-2026.4.0-py3-none-any.whl",
            "required_by": ["huggingface-hub"],
        }])
        audit = seeded["regeneration_audit"]
        audit["added"] = ["fsspec"]
        audit["previous_package_set"] = [
            n for n in audit["package_set"] if n != "fsspec"
        ]
        audit["network_import_hits"] = {"fsspec": ["aiohttp", "requests"]}
        audit["accepted_network_imports"] = {"fsspec": ["aiohttp", "requests"]}
        assert audit_offenders(seeded) == []

    def test_teeth_an_acceptance_that_misses_a_new_module_is_caught(self):
        """An acceptance covers the modules MEASURED when it was given; a
        later bump that adds one is not covered by the old yes."""
        seeded = _seed_manifest(extra_neutral=[{
            "name": "fsspec", "version": "2026.4.0",
            "filename": "fsspec-2026.4.0-py3-none-any.whl",
            "required_by": ["huggingface-hub"],
        }])
        audit = seeded["regeneration_audit"]
        audit["added"] = ["fsspec"]
        audit["previous_package_set"] = [
            n for n in audit["package_set"] if n != "fsspec"
        ]
        audit["network_import_hits"] = {"fsspec": ["aiohttp", "requests", "socket"]}
        audit["accepted_network_imports"] = {"fsspec": ["aiohttp", "requests"]}
        offenders = audit_offenders(seeded)
        assert any("inherits the" in o for o in offenders), offenders

    def test_teeth_the_generator_refuses_an_added_network_capable_package(self, tmp_path):
        """The runbook says the generator REFUSES to write when an ADDED package
        imports a network module. Pin the refusal itself, not only the record it
        leaves: a synthetic wheel whose one .py member imports `socket` must
        raise, and the operator's acceptance must then clear it and record the
        modules that were measured."""
        whl = _synthetic_wheel(
            tmp_path / "netpkg-1.0.0-py3-none-any.whl", "netpkg", "1.0.0",
            body="import socket\n",
        )
        manifest = {
            "wheels": [{
                "name": "netpkg", "version": "1.0.0",
                "filename": "netpkg-1.0.0-py3-none-any.whl",
            }],
            "regeneration_audit": {"package_set": []},
        }
        paths = {(None, "netpkg-1.0.0-py3-none-any.whl"): whl}
        with pytest.raises(RuntimeError, match="REFUSING to write"):
            _BUILDER.record_regeneration_audit(manifest, paths)
        audit = _BUILDER.record_regeneration_audit(
            manifest, paths, accepted_network_imports=["netpkg"],
        )
        assert audit["added"] == ["netpkg"]
        assert audit["accepted_network_imports"] == {"netpkg": ["netpkg/__init__.py:socket"]}

    def test_teeth_the_generator_passes_an_added_local_only_package(self, tmp_path):
        """The other arm: a gate that refuses every addition is not a gate."""
        whl = _synthetic_wheel(
            tmp_path / "localpkg-1.0.0-py3-none-any.whl", "localpkg", "1.0.0",
            body="import json\nfrom urllib.parse import quote\n",
        )
        manifest = {
            "wheels": [{
                "name": "localpkg", "version": "1.0.0",
                "filename": "localpkg-1.0.0-py3-none-any.whl",
            }],
            "regeneration_audit": {"package_set": []},
        }
        audit = _BUILDER.record_regeneration_audit(
            manifest, {(None, "localpkg-1.0.0-py3-none-any.whl"): whl},
        )
        assert audit["added"] == ["localpkg"]
        assert audit["network_import_hits"] == {}

    def test_teeth_an_added_unreviewed_package_is_caught(self):
        seeded = _seed_manifest(extra_neutral=[{
            "name": "brand-new-thing", "version": "1.0.0",
            "filename": "brand_new_thing-1.0.0-py3-none-any.whl",
            "required_by": ["typer"],
        }])
        audit = seeded["regeneration_audit"]
        audit["added"] = ["brand-new-thing"]
        audit["previous_package_set"] = [
            n for n in audit["package_set"] if n != "brand-new-thing"
        ]
        offenders = audit_offenders(seeded)
        assert any("brand-new-thing" in o for o in offenders), offenders
