#!/usr/bin/env python3
"""leira_pr_prereview.py — Consumer #6 of the llm-host offload stack (2026-07-02).

PR pre-review: given a git diff (or a PR ref), llm-host emits a fast smoke-quality
review — typos, missing tests, obvious bug shapes, doc drift. Cheap first pass
BEFORE the AI assistant is invoked for a deep review. Not a substitute for `cavecrew-
reviewer` or code-review skills — a pre-filter.

Modes:
  diff     — read a unified diff from stdin or --input FILE.
  branch   — `git diff <base>...<head>` (default base = origin/main).

Usage:
  git diff origin/main...HEAD | python scripts/leira_pr_prereview.py diff -
  python scripts/leira_pr_prereview.py branch --base origin/main --head HEAD

Prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("pr_prereview")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.50)))

PREREVIEW_SCHEMA = {
    "type": "object",
    "required": ["overall_confidence", "findings"],
    "properties": {
        "overall_confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "high = looks ready; medium = has issues worth flagging; low = clear blockers.",
        },
        "findings": {
            "type": "array",
            "description": "Up to 6 findings. Each MUST be a real, actionable observation.",
            "items": {
                "type": "object",
                "required": ["kind", "file", "note"],
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["bug", "typo", "missing_test", "doc_drift", "style", "safety"],
                    },
                    "file": {"type": "string"},
                    "note": {"type": "string"},
                    "line": {"type": "integer"},
                },
            },
        },
        "summary": {"type": "string", "description": "One line overview."},
    },
}


def _git_diff(base: str, head: str) -> str:
    r = subprocess.run(
        ["git", "diff", f"{base}...{head}"], capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        raise SystemExit(f"git diff failed: {r.stderr[:200]}")
    return r.stdout


def _read_input(path_or_dash: str) -> str:
    if path_or_dash == "-":
        return sys.stdin.read()
    return Path(path_or_dash).read_text(encoding="utf-8", errors="replace")


def prereview(diff_text: str) -> dict:
    trimmed = False
    if len(diff_text) > MAX_INPUT_BYTES:
        # Prefer HEAD of diff (which has the newer hunks). This is a heuristic.
        diff_text = diff_text[:MAX_INPUT_BYTES]
        trimmed = True
    result = call_leira(
        prompt=(
            "You are a fast pre-reviewer of a git diff. Return findings ONLY for real, "
            "actionable issues:\n"
            "- bug: a defect in the added/modified code (wrong condition, missing await, "
            "leaked resource, obvious off-by-one).\n"
            "- typo: a real typo in code identifiers or user-facing strings (NOT docstring nits).\n"
            "- missing_test: a code change with no test coverage in the diff (new function, "
            "new branch).\n"
            "- doc_drift: a comment/docstring that describes the OLD behavior (contradicts the "
            "code change).\n"
            "- style: only if it changes meaning (naming that hides intent, an inconsistent "
            "invariant). Skip pure formatting.\n"
            "- safety: security-adjacent (missing input validation, unescaped user data, "
            "hardcoded secret shape, leaked exception).\n\n"
            "Do NOT invent findings. If the diff is clean, return findings=[] + confidence=high. "
            "Cap at 6 findings.\n\n"
            f"Diff{' (trimmed)' if trimmed else ''}:\n{diff_text}"
        ),
        schema=PREREVIEW_SCHEMA,
    )
    result["trimmed"] = trimmed
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    df = sub.add_parser("diff")
    df.add_argument("input", nargs="?", default="-", help="- for stdin, else a file")
    br = sub.add_parser("branch")
    br.add_argument("--base", default="origin/main")
    br.add_argument("--head", default="HEAD")
    args = ap.parse_args(argv)
    if args.mode == "diff":
        diff = _read_input(args.input)
    else:
        diff = _git_diff(args.base, args.head)
    if not diff.strip():
        json.dump({"overall_confidence": "high", "findings": [], "summary": "empty diff"},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    try:
        out = prereview(diff)
    except OllamaCallError as e:
        json.dump({"overall_confidence": "low", "findings": [], "summary": f"llm-host error: {e}"},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
