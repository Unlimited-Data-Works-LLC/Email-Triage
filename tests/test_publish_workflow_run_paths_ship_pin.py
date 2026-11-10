"""Every script a SHIPPED workflow runs must itself ship to the public mirror.

2026-11-09: the v0.2.0 public Release run (42672573256) failed because the shipped
.github/workflows/tests.yml runs `python scripts/workflows/feature-add-e2e-gate.py`,
and the default-deny ship-set stripped that script. The --prepare build-green gate is
collect-only, so it could not see a workflow step. This pin reads every `run:` step of
every shipped workflow, takes each repo-relative file it executes (python/bash/sh/pwsh
argument, or a bare ./path), and asserts the ship-set keeps it.

Scope: tokens that name a tracked file with a script suffix. A path built at run time
(a variable, a glob) is not seen.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

_SCRIPT = re.compile(r"(?<![\w/.-])\.?/?((?:[\w.-]+/)+[\w.-]+\.(?:py|sh|ps1|js))\b")


def _tracked() -> set[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True)
    return set(out.stdout.splitlines())


def _run_blocks(doc) -> list[str]:
    runs: list[str] = []
    for job in (doc.get("jobs") or {}).values():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                runs.append(step["run"])
    return runs


def _executed_paths(run: str, tracked: set[str]) -> set[str]:
    hits = set()
    for line in run.splitlines():
        code = line.split("#", 1)[0]
        for m in _SCRIPT.finditer(code):
            if m.group(1) in tracked:
                hits.add(m.group(1))
    return hits


def _check(ships, tracked: set[str], workflows: dict[str, str]) -> list[str]:
    bad = []
    for wf, text in sorted(workflows.items()):
        if not ships(wf):
            continue
        for run in _run_blocks(yaml.safe_load(text) or {}):
            for p in sorted(_executed_paths(run, tracked)):
                if not ships(p):
                    bad.append(f"{wf} runs {p}, which the public ship-set strips")
    return bad


def test_every_script_a_shipped_workflow_runs_ships():
    try:
        from publish_shipset import make_ships
    except ImportError:
        # The mirror itself ships neither the ship-set funnel nor its config. In the dev
        # tree (config present) a missing funnel is a real failure, so re-raise there.
        if (REPO / "scripts" / "publish-allow.txt").is_file():
            raise
        return
    tracked = _tracked()
    ships = make_ships(str(REPO))
    wfs = {p: (REPO / p).read_text(encoding="utf-8")
           for p in tracked if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))}
    bad = _check(ships, tracked, wfs)
    assert not bad, "\n".join(bad)


def test_the_run_path_check_has_teeth():
    tracked = {"scripts/a.py", "scripts/b.sh", ".github/workflows/w.yml"}
    wf = {".github/workflows/w.yml": (
        "jobs:\n  j:\n    steps:\n"
        "      - run: python scripts/a.py --x\n"
        "      - run: |\n          bash ./scripts/b.sh  # scripts/c.py only in a comment\n")}
    assert _check(lambda p: p != "scripts/a.py", tracked, wf) == [
        ".github/workflows/w.yml runs scripts/a.py, which the public ship-set strips"]
    assert _check(lambda p: p not in {"scripts/b.sh"}, tracked, wf) == [
        ".github/workflows/w.yml runs scripts/b.sh, which the public ship-set strips"]
    assert _check(lambda p: True, tracked, wf) == []
