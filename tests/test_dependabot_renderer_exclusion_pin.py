"""Punch 520 — the N-495 renderer never rides a grouped or auto-merged Dependabot PR.

``markdown-it-py`` is the CommonMark renderer the N-495 register render pin's ratchet
ceilings are calibrated against. The ceilings are MAXIMA, so a renderer bump can make that
pin over-permit while CI stays green. efc34bb3 therefore excluded the package from every
pip group in ``.github/dependabot.yml`` (``exclude-patterns``), so each bump arrives as its
own PR for a human to review as a renderer change. Nothing enforced that: deleting the
three ``exclude-patterns`` lines failed no check (DA verify of efc34bb3, 2026-09-24).

This pin enforces three properties, each over EVERY site it finds at run time (never a
count):

1. **Group isolation.** For every ``pip`` entry under ``updates``, no group admits the
   renderer. A group admits a dependency unless an ``exclude-patterns`` entry matches it,
   or the group declares ``patterns`` and none of them match it. A group with no
   ``patterns`` key (``update-types`` / ``dependency-type`` only) matches every
   dependency, so it must exclude the renderer explicitly. The renderer must also not sit
   under ``ignore``: that would stop its version updates, not route them to review.
2. **No auto-merge label.** No ``updates`` entry carries an auto-merge-shaped label.
3. **Auto-merge rules exclude by NAME.** Every workflow (and every known merge-bot config)
   that can merge a PR names the renderer, so the rule can skip its PR.

DECISION (the row's "a label, or a name check"): a future auto-merge rule must exclude the
renderer by NAME — ``dependabot/fetch-metadata``'s ``dependency-names`` output, or the PR
branch/title — never by label. Dependabot's ``labels`` apply per ``updates`` entry (per
ecosystem/directory/branch), not per group or per dependency, so the renderer's ungrouped
PR carries exactly the same ``dependencies`` + ``python`` labels as the grouped ones. A
label-keyed rule cannot tell them apart. Property 2 stops the label route; property 3
requires the name route.

SCOPE (honest): property 3 is a text-shape check. It sees workflow files under
``.github/workflows`` and the merge-bot configs in ``_MERGE_BOT_CONFIGS``. It cannot see
the repository's "Allow auto-merge" setting, auto-merge enabled by hand in the UI, a
GitHub App with no config file in the repo, or a workflow that names the renderer without
actually skipping it. Matching follows Dependabot's ``*`` wildcard on a PEP 503-normalised
name; the exact server-side matcher is not reproduced.
"""

from __future__ import annotations

import ast
import copy
import fnmatch
import re
import tomllib

import pytest
import yaml
from packaging.requirements import Requirement

from _pin_harness import REPO_ROOT, iter_files, parse_module, relpath

_DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
_WORKFLOWS = REPO_ROOT / ".github" / "workflows"
_PYPROJECT = REPO_ROOT / "pyproject.toml"

# The renderer, as Dependabot names it (distribution) and as the walker imports it.
_RENDERER_DIST = "markdown-it-py"
_RENDERER_IMPORT = "markdown_it"
# The module that imports the renderer for the N-495 pin. Not shipped to the public mirror
# (default-deny ship set), so the linkage arm runs only in the full dev tree.
_RENDERER_CONSUMER = REPO_ROOT / "scripts" / "md_table_fidelity.py"  # publish: absent-tolerant: the walker does not ship; absent, the linkage arm returns only on a curated tree (no strip list) and FAILS in the dev tree, and every other assertion in this file still runs; pinned by test_pinned_renderer_is_the_n495_renderer
from _pin_harness import _FULL_DEV_TREE  # noqa: E402  (the one dev-tree detector, PD-5)

# Merge-bot configs that can merge a PR with no workflow file. Present = treated as
# auto-merging (fail closed), so each must name the renderer.
_MERGE_BOT_CONFIGS = (
    ".mergify.yml",
    ".mergify/config.yml",
    ".github/mergify.yml",
    ".kodiak.toml",
    ".github/.kodiak.toml",
)

# A workflow that can merge a PR: the gh CLI, the GraphQL/REST merge calls, or any
# auto-merge action. Matched against comment-stripped text, case-insensitive.
_MERGE_SHAPE = re.compile(
    r"gh\s+pr\s+merge|enablePullRequestAutoMerge|pulls\.merge|auto[-_ ]?merge|merge-dependabot",
    re.IGNORECASE,
)
_AUTOMERGE_LABEL = re.compile(r"auto[-_ ]?merge", re.IGNORECASE)


def _norm(name: str) -> str:
    """PEP 503 name normalisation, also applied to wildcard patterns."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _matches(name: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(_norm(name), _norm(p)) for p in (patterns or ()))


def _pip_entries(config: dict) -> list[dict]:
    return [u for u in (config.get("updates") or []) if u.get("package-ecosystem") == "pip"]


def _entry_key(entry: dict) -> str:
    return f"pip:{entry.get('directory', '?')}@{entry.get('target-branch', 'default')}"


def _group_admits(group: dict, dep: str) -> bool:
    """True when Dependabot would put ``dep`` in this group."""
    group = group or {}
    if _matches(dep, group.get("exclude-patterns")):
        return False
    if "patterns" in group:
        return _matches(dep, group.get("patterns"))
    return True  # update-types / dependency-type only: every dependency is a candidate


def _group_violations(config: dict, dep: str = _RENDERER_DIST) -> list[str]:
    """Every ``<entry>/<group>`` that would sweep ``dep`` into a grouped PR."""
    out = []
    for entry in _pip_entries(config):
        for name, group in (entry.get("groups") or {}).items():
            if _group_admits(group, dep):
                out.append(f"{_entry_key(entry)}/{name}")
    return out


def _ignore_violations(config: dict, dep: str = _RENDERER_DIST) -> list[str]:
    """Every pip entry whose ``ignore`` list stops ``dep``'s version updates."""
    out = []
    for entry in _pip_entries(config):
        for rule in entry.get("ignore") or []:
            if _matches(dep, [rule.get("dependency-name", "")]):
                out.append(f"{_entry_key(entry)} ignore {rule.get('dependency-name')!r}")
    return out


def _automerge_label_violations(config: dict) -> list[str]:
    out = []
    for entry in config.get("updates") or []:
        for label in entry.get("labels") or []:
            if _AUTOMERGE_LABEL.search(str(label)):
                out.append(f"{entry.get('package-ecosystem')}: label {label!r}")
    return out


def _strip_comments(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _merges_without_name_check(text: str, dep: str = _RENDERER_DIST) -> bool:
    """True when a workflow/config can merge a PR but never names ``dep``."""
    body = _strip_comments(text)
    return bool(_MERGE_SHAPE.search(body)) and dep not in body


def _merge_capable_files() -> list:
    files = [*iter_files(_WORKFLOWS, "*.yml"), *iter_files(_WORKFLOWS, "*.yaml")]
    return files + [REPO_ROOT / rel for rel in _MERGE_BOT_CONFIGS if (REPO_ROOT / rel).exists()]


def _load() -> dict:
    return yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))


def _declared_requirements() -> list[Requirement]:
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]
    specs = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        specs.extend(extra)
    return [Requirement(s) for s in specs]


# --------------------------------------------------------------------------- the pins


def test_every_pip_group_excludes_the_renderer():
    config = _load()
    groups = [g for e in _pip_entries(config) for g in (e.get("groups") or {})]
    assert groups, "non-vacuity: no pip group found in .github/dependabot.yml"
    bad = _group_violations(config)
    assert not bad, (
        f"{_RENDERER_DIST} would ride a grouped Dependabot PR via {bad}. It is the N-495 "
        "render pin's renderer; each bump must arrive as its own PR. Add "
        f'exclude-patterns: ["{_RENDERER_DIST}"] to every listed group.'
    )


def test_renderer_still_gets_version_updates():
    config = _load()
    assert _pip_entries(config), "non-vacuity: no pip entry in .github/dependabot.yml"
    declared = {_norm(r.name) for r in _declared_requirements()}
    assert _norm(_RENDERER_DIST) in declared, (
        f"non-vacuity: {_RENDERER_DIST} is not declared in pyproject.toml, so Dependabot "
        "would never propose it and this pin guards nothing"
    )
    bad = _ignore_violations(config)
    assert not bad, (
        f"{_RENDERER_DIST} is under ignore ({bad}): that stops its updates instead of "
        "routing them to human review. Use exclude-patterns on the groups."
    )


def test_no_ecosystem_entry_carries_an_automerge_label():
    bad = _automerge_label_violations(_load())
    assert not bad, (
        f"auto-merge label(s) {bad}: Dependabot labels apply per updates entry, so the "
        f"ungrouped {_RENDERER_DIST} PR carries them too. Exclude it by name, not label."
    )


def test_every_merge_capable_workflow_names_the_renderer():
    files = _merge_capable_files()
    assert any(p.parent == _WORKFLOWS for p in files), "non-vacuity: no workflow files found"
    bad = [
        relpath(p, base=REPO_ROOT)
        for p in files
        if _merges_without_name_check(p.read_text(encoding="utf-8"))
    ]
    assert not bad, (
        f"{bad} can merge a PR but never name {_RENDERER_DIST}. Skip its PR by name "
        "(dependabot/fetch-metadata dependency-names, or the PR branch); a label cannot "
        "tell it apart from the grouped PRs."
    )


def test_pinned_renderer_is_the_n495_renderer():
    """The constant above must be the renderer the N-495 pin actually uses."""
    exact = [
        r for r in _declared_requirements()
        if _norm(r.name) == _norm(_RENDERER_DIST) and any(s.operator == "==" for s in r.specifier)
    ]
    assert exact, f"{_RENDERER_DIST} is no longer exact-pinned (==) in pyproject.toml"
    if not _RENDERER_CONSUMER.exists():
        assert not _FULL_DEV_TREE, f"{_RENDERER_CONSUMER.name} is missing from the dev tree"
        pytest.skip("curated public tree: scripts/md_table_fidelity.py is not shipped, so "
                    "the renderer linkage is checked in the dev tree only")
    tree = parse_module(_RENDERER_CONSUMER)
    assert tree is not None
    imported = {
        alias.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names
    } | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert _RENDERER_IMPORT in imported, (
        f"{_RENDERER_CONSUMER.name} no longer imports {_RENDERER_IMPORT}; the N-495 renderer "
        "changed, so update _RENDERER_DIST/_RENDERER_IMPORT and the dependabot exclusions"
    )


# --------------------------------------------------------------------------- teeth


def test_teeth_dropping_one_exclusion_is_caught():
    config = _load()
    entry = _pip_entries(config)[0]
    name = next(iter(entry["groups"]))
    del entry["groups"][name]["exclude-patterns"]
    assert _group_violations(config) == [f"{_entry_key(entry)}/{name}"]


def test_teeth_dropping_every_exclusion_flags_every_group():
    config = _load()
    for entry in _pip_entries(config):
        for group in (entry.get("groups") or {}).values():
            group.pop("exclude-patterns", None)
    flagged = _group_violations(config)
    total = sum(len(e.get("groups") or {}) for e in _pip_entries(config))
    assert len(flagged) == total and total > 0


def test_teeth_group_shapes():
    base = {"updates": [{"package-ecosystem": "pip", "directory": "/", "groups": {}}]}

    def with_group(group):
        cfg = copy.deepcopy(base)
        cfg["updates"][0]["groups"]["g"] = group
        return _group_violations(cfg)

    assert with_group({"patterns": ["*"]}), "catch-all patterns group missed"
    assert with_group({"dependency-type": "development"}), "dependency-type-only group missed"
    assert with_group({"patterns": ["markdown*"]}), "wildcard that matches the renderer missed"
    assert with_group({"update-types": ["patch"], "exclude-patterns": ["other"]})
    assert not with_group({"patterns": ["cryptography*"]}), "non-matching patterns group flagged"
    assert not with_group({"update-types": ["patch"], "exclude-patterns": ["markdown-it*"]})
    assert not with_group({"update-types": ["patch"], "exclude-patterns": ["Markdown_It_Py"]})
    # A non-pip ecosystem is out of scope even with a catch-all group.
    other = {"updates": [{"package-ecosystem": "npm", "groups": {"g": {"patterns": ["*"]}}}]}
    assert not _group_violations(other)


def test_teeth_ignore_and_label():
    config = _load()
    entry = _pip_entries(config)[0]
    entry.setdefault("ignore", []).append({"dependency-name": _RENDERER_DIST})
    assert _ignore_violations(config)
    entry["labels"] = [*entry.get("labels", []), "automerge"]
    assert _automerge_label_violations(config)
    assert not _automerge_label_violations({"updates": [{"labels": ["dependencies", "python"]}]})


def test_teeth_workflow_name_check():
    merges = (
        "jobs:\n  m:\n    steps:\n"
        "      - uses: dependabot/fetch-metadata@v2\n        id: meta\n"
        "      - run: gh pr merge --auto --squash \"$PR_URL\"\n"
    )
    assert _merges_without_name_check(merges)
    guarded = merges.replace(
        "      - run:",
        f"      - if: \"!contains(steps.meta.outputs.dependency-names, '{_RENDERER_DIST}')\"\n"
        "        run:",
    )
    assert not _merges_without_name_check(guarded)
    assert _merges_without_name_check("steps:\n  - uses: pascalgn/automerge-action@v0.16\n")
    assert _merges_without_name_check("steps:\n  - run: github.rest.pulls.merge({})\n")
    assert not _merges_without_name_check("# a future auto-merge rule\njobs: {}\n")
    assert not _merges_without_name_check("jobs:\n  t:\n    steps:\n      - run: pytest\n")
