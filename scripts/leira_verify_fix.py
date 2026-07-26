#!/usr/bin/env python3
"""leira_verify_fix.py — Consumer  of the llm-host offload stack (2026-07-02).

Improvement #3 of the sharpening: given a git diff (or a range spec) + a
declared SSOT function name, llm-host reports whether each hunk that touched
the class's surface routes through the SSOT. Cuts a whole the AI assistant re-read
round per remediation cycle.

Modes:
  diff     — read a unified diff from stdin or --input FILE.
  range    — `git diff <base>..<head>` for a given range.

Usage:
  git diff HEAD~1 | python scripts/leira_verify_fix.py diff - \
      --ssot request_meta
  python scripts/leira_verify_fix.py range --base HEAD~5 --head HEAD \
      --ssot dump_json_col

Prints JSON to stdout with per-hunk verdicts (`routes_through_ssot`, `notes`,
`overall_confidence`).
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

_cfg = get_consumer_config("verify_fix")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.50)))


VERDICT_SCHEMA = {
    "type": "object",
    "required": ["overall_confidence", "hunks"],
    "properties": {
        "overall_confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "high = every hunk routes through SSOT; medium = some do, "
                           "some ambiguous; low = SSOT is bypassed / diff has no SSOT context.",
        },
        "hunks": {
            "type": "array",
            "description": "One entry per changed hunk that touched the class surface.",
            "items": {
                "type": "object",
                "required": ["file", "routes_through_ssot"],
                "properties": {
                    "file": {"type": "string"},
                    "routes_through_ssot": {
                        "type": "string",
                        "enum": ["yes", "no", "ambiguous"],
                    },
                    "notes": {"type": "string",
                              "description": "One-line: WHICH SSOT symbol appears (or doesn't)."},
                    "line_range": {"type": "string",
                                   "description": "Optional hunk line-range e.g. '145-150'"},
                },
            },
        },
        "summary": {"type": "string",
                    "description": "One-line: routes_through_ssot='no' → what SSOT should be."},
    },
}


def _git_range(base: str, head: str) -> str:
    r = subprocess.run(
        ["git", "diff", f"{base}..{head}"], capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        raise SystemExit(f"git diff failed: {r.stderr[:200]}")
    return r.stdout


def _read_input(p: str) -> str:
    if p == "-":
        return sys.stdin.read()
    return Path(p).read_text(encoding="utf-8", errors="replace")


def verify(diff_text: str, ssot_name: str) -> dict:
    trimmed = False
    if len(diff_text) > MAX_INPUT_BYTES:
        diff_text = diff_text[:MAX_INPUT_BYTES]
        trimmed = True
    result = call_leira(
        prompt=(
            f"You are verifying that a remediation diff routes every touched call site through "
            f"the SSOT symbol `{ssot_name}`. For each changed hunk that touched a call site of "
            f"the class {ssot_name} governs:\n"
            f"- routes_through_ssot=yes: the added/modified line calls {ssot_name}(...) directly "
            f"OR uses a variable bound from {ssot_name}(...) (1-hop taint).\n"
            f"- routes_through_ssot=no: the hunk added/modified a call at the seam without going "
            f"through {ssot_name} — a raw substitute (e.g. `request.client.host` instead of "
            f"`request_meta(request).host`, or `json.dumps(x)` instead of `dump_json_col(x)`).\n"
            f"- routes_through_ssot=ambiguous: the hunk doesn't clearly touch the seam OR the "
            f"routing depends on a variable defined outside the diff window.\n\n"
            f"Do NOT invent hunks. Do NOT rate severity. Cap at 12 hunks. If no hunk touches the "
            f"SSOT surface, return hunks=[] + overall_confidence=low.\n\n"
            f"Diff{' (trimmed)' if trimmed else ''}:\n{diff_text}"
        ),
        schema=VERDICT_SCHEMA,
    )
    result["ssot"] = ssot_name
    result["trimmed"] = trimmed
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ssot", required=True,
                    help="canonical SSOT symbol name the diff should route through")
    sub = ap.add_subparsers(dest="mode", required=True)
    df = sub.add_parser("diff")
    df.add_argument("input", nargs="?", default="-", help="- for stdin, else a file")
    rg = sub.add_parser("range")
    rg.add_argument("--base", default="HEAD~1")
    rg.add_argument("--head", default="HEAD")
    args = ap.parse_args(argv)
    if args.mode == "diff":
        diff = _read_input(args.input)
    else:
        diff = _git_range(args.base, args.head)
    if not diff.strip():
        json.dump({"overall_confidence": "low", "hunks": [],
                   "summary": "empty diff"},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    try:
        out = verify(diff, args.ssot)
    except OllamaCallError as e:
        json.dump({"overall_confidence": "low", "hunks": [],
                   "leira_error": str(e)},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
