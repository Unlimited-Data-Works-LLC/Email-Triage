#!/usr/bin/env python3
"""test_flake_classifier.py — Component A of the autonomous test-resolution daemon.

Runs the full test suite N times on a clean checkout, classifies each failing test as:
  - REGRESSION       — fails all N runs (deterministic; a real bug or fixture defect)
  - FLAKE            — fails some / passes some (timing, order, network, resource)
  - INFRA-FLAKE      — matches the known-infra EXCLUSION list; do NOT auto-repair
                       (test-isolation infra like request_id bleed / SQLite file-lock;
                       see testinfra_full_tree_xdist_flakes + the backlog line 68)
  - OK               — passes all N runs

For each REGRESSION and FLAKE, llm-host (qwen3.6:35b) reads a truncated pytest failure
excerpt and proposes a flake subtype + one-line root-cause hypothesis. llm-host output is
a HINT — Component B (the AI assistant, worktree, PR-gated) does the real repair.

SAFETY:
  - This component ONLY READS + REPORTS. It never modifies source or tests.
  - Known-infra flakes are classified + reported; they are NEVER auto-repaired
    (would be actively wrong; see the drawer).

Usage:
  python scripts/test_flake_classifier.py \
    --repo-root . --runs 3 [--pytest-args "-x -k foo"] \
    --exclusion-list scripts/test_flake_exclusions.json \
    --output flake_report.json

The EXCLUSION list JSON: {"known_infra_flakes": [
  {"test_id_glob": "tests/test_cli_audit*", "reason": "request_id global bleed; the backlog line 68"},
  ...
]}. Match is fnmatch on the pytest test id.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import call_leira, OllamaCallError, get_consumer_config

_cfg = get_consumer_config("flake_classifier")
PYTEST_TIMEOUT_S = int(_cfg.get("pytest_timeout_s", 1800))

# Match "PASSED"/"FAILED"/"ERROR" in pytest -v output.
_RESULT_RE = re.compile(r"^(?P<test_id>\S+)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b")

FLAKE_SUBTYPE_SCHEMA = {
    "type": "object",
    "required": ["subtype", "root_cause_hypothesis", "confidence"],
    "properties": {
        "subtype": {
            "type": "string",
            "enum": ["timing", "order-dependence", "fixture-lag", "resource-contention",
                     "network", "flake-general", "deterministic-regression"],
        },
        "root_cause_hypothesis": {"type": "string", "description": "one line"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "safe_to_auto_repair": {
            "type": "boolean",
            "description": "true = a small test-file edit could plausibly fix; false = needs human/SME",
        },
    },
}


def _run_pytest_once(repo_root: Path, pytest_args: list[str], run_idx: int) -> dict[str, str]:
    """Run pytest -v once. Return {test_id: status}. Also stashes the FAILED excerpts to a
    per-run tmp file for later llm-host classification."""
    cmd = ["python", "-m", "pytest", "-v", "--tb=short", "--no-header", "-p", "no:cacheprovider"] + pytest_args
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=PYTEST_TIMEOUT_S)
    dur = time.monotonic() - started
    out = proc.stdout + "\n" + proc.stderr

    results: dict[str, str] = {}
    for line in out.splitlines():
        m = _RESULT_RE.match(line)
        if m:
            results[m.group("test_id")] = m.group("status")

    excerpts_dir = repo_root / "scratchpad" / "flake_runs"
    excerpts_dir.mkdir(parents=True, exist_ok=True)
    (excerpts_dir / f"run{run_idx}.out").write_text(out, encoding="utf-8")
    print(f"  run {run_idx}: {sum(1 for s in results.values() if s == 'PASSED')} passed, "
          f"{sum(1 for s in results.values() if s == 'FAILED')} failed, "
          f"{sum(1 for s in results.values() if s == 'ERROR')} error in {dur:.0f}s",
          file=sys.stderr)
    return results


def _extract_failure_excerpt(all_runs_dir: Path, test_id: str) -> str:
    """Best-effort: grab the FAILED block for this test from any run's output."""
    for run_out in sorted(all_runs_dir.glob("run*.out")):
        text = run_out.read_text(encoding="utf-8", errors="replace")
        # Find "___ <test-name-tail> ___" and grab a few lines after
        tail = test_id.split("::")[-1]
        rx = re.compile(rf"_{{3,}}\s*{re.escape(tail)}\s*_{{3,}}(.*?)(?=\n_{{3,}}|\n=+ )", re.S)
        m = rx.search(text)
        if m:
            return m.group(1)[:2000]
    return ""


def _classify_via_leira(test_id: str, excerpt: str, fail_count: int, run_count: int) -> dict:
    if not excerpt.strip():
        return {"subtype": "flake-general", "root_cause_hypothesis": "no excerpt available",
                "confidence": "low", "safe_to_auto_repair": False}
    prompt = (
        f"Test {test_id} failed {fail_count}/{run_count} runs on the same checkout. "
        f"Classify the failure subtype from this pytest excerpt. Distinguish TIMING (sleeps, "
        f"deadlines), ORDER-DEPENDENCE (shared global state), FIXTURE-LAG (setup timing), "
        f"RESOURCE-CONTENTION (locks, connections), NETWORK, or generic FLAKE. If it fails "
        f"ALL runs, subtype='deterministic-regression'. "
        f"safe_to_auto_repair=true ONLY if a small test-file-only edit could plausibly fix; "
        f"false for anything touching source, fixtures, or infrastructure. Be conservative.\n\n"
        f"EXCERPT:\n----\n{excerpt}\n----"
    )
    try:
        return call_leira(prompt, schema=FLAKE_SUBTYPE_SCHEMA)
    except OllamaCallError as e:
        return {"subtype": "flake-general",
                "root_cause_hypothesis": f"llm-host classify failed: {e}",
                "confidence": "low", "safe_to_auto_repair": False, "_error": str(e)}


def classify_test(test_id: str, pass_count: int, fail_count: int, error_count: int,
                  run_count: int, exclusions: list[dict], excerpts_dir: Path) -> dict:
    total_bad = fail_count + error_count
    infra_reason = None
    for e in exclusions:
        if fnmatch.fnmatch(test_id, e.get("test_id_glob", "")):
            infra_reason = e.get("reason", "known-infra-flake")
            break

    if infra_reason:
        return {"test_id": test_id, "classification": "INFRA-FLAKE",
                "pass": pass_count, "fail": fail_count, "error": error_count,
                "reason": infra_reason, "safe_to_auto_repair": False,
                "leira_hint": None}
    if total_bad == 0:
        return {"test_id": test_id, "classification": "OK",
                "pass": pass_count, "fail": fail_count, "error": error_count}

    excerpt = _extract_failure_excerpt(excerpts_dir, test_id)
    leira_hint = _classify_via_leira(test_id, excerpt, total_bad, run_count)

    cls = "REGRESSION" if total_bad == run_count else "FLAKE"
    return {"test_id": test_id, "classification": cls,
            "pass": pass_count, "fail": fail_count, "error": error_count,
            "leira_hint": leira_hint,
            "safe_to_auto_repair": leira_hint.get("safe_to_auto_repair", False)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", type=Path, default=".", help="path to the checkout to test")
    ap.add_argument("--runs", type=int, default=3, help="number of pytest runs")
    ap.add_argument("--pytest-args", default="", help="extra args passed to pytest")
    ap.add_argument("--exclusion-list", type=Path, default=None,
                    help="JSON with known_infra_flakes[]")
    ap.add_argument("--output", type=Path, default=Path("scratchpad/flake_report.json"))
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    exclusions = []
    if args.exclusion_list and args.exclusion_list.is_file():
        exclusions = json.loads(args.exclusion_list.read_text(encoding="utf-8")).get(
            "known_infra_flakes", [])

    # Run the suite N times
    all_results: list[dict[str, str]] = []
    for i in range(1, args.runs + 1):
        r = _run_pytest_once(repo_root, args.pytest_args.split(), i)
        all_results.append(r)
        if not r:
            print(f"WARN: run {i} produced no parsable results; suite may have errored before collection",
                  file=sys.stderr)

    # Tally
    all_tests = set().union(*(set(r) for r in all_results))
    tally = {}
    for t in all_tests:
        p = sum(1 for r in all_results if r.get(t) == "PASSED")
        f = sum(1 for r in all_results if r.get(t) == "FAILED")
        e = sum(1 for r in all_results if r.get(t) == "ERROR")
        tally[t] = (p, f, e)

    excerpts_dir = repo_root / "scratchpad" / "flake_runs"
    classified = [classify_test(t, *tally[t], args.runs, exclusions, excerpts_dir)
                  for t in sorted(all_tests)]

    counts = {"OK": 0, "REGRESSION": 0, "FLAKE": 0, "INFRA-FLAKE": 0}
    for c in classified:
        counts[c["classification"]] = counts.get(c["classification"], 0) + 1

    report = {
        "repo_root": str(repo_root),
        "runs": args.runs,
        "totals": counts,
        "tests": [c for c in classified if c["classification"] != "OK"],  # only non-OK detailed
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(counts, indent=2))
    print(f"full report -> {args.output}")


if __name__ == "__main__":
    main()
