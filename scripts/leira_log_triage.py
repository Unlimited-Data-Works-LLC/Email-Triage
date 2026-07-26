#!/usr/bin/env python3
"""leira_log_triage.py — Consumer #4 of the llm-host offload stack.

Log/output triage: given a CI log, pytest output, the monitoring system notification, mail-queue
dump, or generic error stream, llm-host extracts the DECISIVE lines + a one-line summary
+ severity. the AI assistant reads 3 lines instead of 3000.

Modes:
  pytest   — pytest -v output; find failing tests, extract first Traceback per test.
  ci       — GitHub Actions / CI log; find the first hard failure + its stack.
  the monitoring system   — the monitoring system notification / plugin output; find the CRITICAL/UNKNOWN chunk.
  generic  — freeform log; find lines matching ERROR/CRITICAL/FAIL/Traceback + immediate context.

Usage:
  python scripts/leira_log_triage.py <mode> [--input FILE|-] [--max-lines N]

  stdin by default; --input FILE for a file. Prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import call_leira, OllamaCallError, get_consumer_config, context_bytes

_cfg = get_consumer_config("log_triage")
# Context-derived (learned from llm-host at import time, not hardcoded 98K):
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.40)))
DEFAULT_MAX_LINES = int(_cfg.get("default_max_lines", 12))

TRIAGE_SCHEMA = {
    "type": "object",
    "required": ["summary", "severity", "decisive_lines"],
    "properties": {
        "summary": {"type": "string", "description": "One line: what went wrong and where"},
        "severity": {
            "type": "string",
            "enum": ["critical", "error", "warning", "info", "none"],
            "description": "critical = process died / cannot recover; error = a test/step failed; warning = something noticed; info = normal; none = no issue found",
        },
        "decisive_lines": {
            "type": "array",
            "description": "The lines that carry the actionable signal. NEVER the whole log — up to the max requested. Preserve verbatim.",
            "items": {"type": "string"},
        },
        "affected_symbols": {
            "type": "array",
            "description": "Optional: test names, module paths, service names, or file:line refs the failure points at.",
            "items": {"type": "string"},
        },
        "suggested_next_step": {
            "type": "string",
            "description": "Optional one-liner: what a maintainer should check first",
        },
    },
}


_MODE_PROMPTS = {
    "pytest": (
        "This is pytest -v output. Find failing tests (FAILED lines or Tracebacks) and extract "
        "the FIRST Traceback per failing test verbatim. ALSO include any lines from the "
        "'Captured stderr' / 'Captured stdout' / 'Captured log call' blocks that carry a root-cause "
        "signal (a WARNING/ERROR/[audit]/[hipaa]-tag line, a 'no chain row'/'connection refused'/"
        "'gap event' message). Those captured-output lines are often the WHY behind the AssertionError. "
        "Skip only pure setup/teardown noise (import chatter, fixture-instantiate log lines with no "
        "error content). Fill affected_symbols with test names (test_x.py::TestClass::test_case)."
    ),
    "ci": (
        "This is a CI log (GitHub Actions or similar). Find the FIRST hard failure line + its immediate "
        "stack (max 20 lines around it). Skip retry-noise, git-checkout output, dependency-install noise "
        "unless they contain the failure itself. Fill affected_symbols with the job/step name if present."
    ),
    "the monitoring system": (
        "This is a the monitoring system notification / plugin output. Find the CRITICAL / UNKNOWN / WARNING chunk + "
        "the plugin's actual output line. Fill affected_symbols with the host + service name."
    ),
    "generic": (
        "This is a freeform log. Find lines matching ERROR / CRITICAL / FAIL / Traceback / Exception + "
        "up to 3 lines of context above and below. Merge overlapping ranges."
    ),
}


def triage(mode: str, log: str, max_lines: int) -> dict:
    if mode not in _MODE_PROMPTS:
        raise SystemExit(f"unknown mode: {mode}; choices: {list(_MODE_PROMPTS)}")
    trimmed = False
    if len(log) > MAX_INPUT_BYTES:
        # Prefer the END of the log — decisive lines are usually near the failure (near EOF)
        log = "... [truncated head]\n" + log[-MAX_INPUT_BYTES:]
        trimmed = True

    mode_hint = _MODE_PROMPTS[mode]
    prompt = (
        f"You are a log-triage pre-filter. Extract the ACTIONABLE signal from this log so a maintainer "
        f"reads a few decisive lines instead of the whole log.\n\n"
        f"Mode: {mode}\n"
        f"{mode_hint}\n\n"
        f"Cap decisive_lines at {max_lines} lines total (preserve VERBATIM). If nothing meaningful is "
        f"in the log, set severity='none' and summary='no failure found'. Do NOT invent lines.\n\n"
        f"LOG:\n----\n{log}\n----"
    )
    try:
        result = call_leira(prompt, schema=TRIAGE_SCHEMA)
    except OllamaCallError as e:
        return {
            "summary": f"triage failed: {e}",
            "severity": "error",
            "decisive_lines": [],
            "_prepass_error": str(e),
        }
    if trimmed:
        result.setdefault("_caveats", []).append("input log was trimmed to last {} bytes".format(MAX_INPUT_BYTES))
    # Cap enforcement (llm-host may overshoot)
    if len(result.get("decisive_lines", [])) > max_lines:
        result["decisive_lines"] = result["decisive_lines"][:max_lines]
        result.setdefault("_caveats", []).append(f"trimmed decisive_lines to {max_lines}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=list(_MODE_PROMPTS))
    ap.add_argument("--input", type=Path, help="input file (- for stdin, default)")
    ap.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    args = ap.parse_args()
    log = args.input.read_text(encoding="utf-8", errors="replace") if (
        args.input and str(args.input) != "-") else sys.stdin.read()
    out = triage(args.mode, log, args.max_lines)
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
