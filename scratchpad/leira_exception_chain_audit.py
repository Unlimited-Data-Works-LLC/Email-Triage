#!/usr/bin/env python3
"""Exception-chaining-loss audit — per-class llm-host offload.

`except X as e: raise Y(...)` (without `from e`) LOSES the original
exception's `__cause__`, breaking traceback visibility. Classify
each hit as ACTUAL_DEFECT, HELPER_CALL_PRESERVING (raise foo(e, ...)
where foo internally raises with cause), or FALSE_POSITIVE.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

REPO = Path("C:/Users/ExampleUser/Documents/the AI assistant/Projects/email-triage")
sys.path.insert(0, str(REPO / "scripts"))

from leira_prepass import call_leira


def gather_context() -> str:
    """Gather ±3 lines of context around each raise-without-from hit."""
    hits: list[str] = []
    for p in (REPO / "src" / "email_triage").rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.name:
                for child in ast.walk(node):
                    if (isinstance(child, ast.Raise)
                            and child.exc is not None
                            and child.cause is None
                            and isinstance(child.exc, ast.Call)):
                        # snapshot 8 lines around raise
                        try:
                            lines = p.read_text(encoding="utf-8").splitlines()
                        except Exception:
                            break
                        lo = max(0, child.lineno - 5)
                        hi = min(len(lines), child.lineno + 3)
                        rel = p.relative_to(REPO / "src" / "email_triage").as_posix()
                        snippet = "\n".join(
                            f"{i + 1:5d}: {lines[i]}"
                            for i in range(lo, hi)
                        )
                        hits.append(f"=== {rel}:{child.lineno} (except {node.name}) ===\n{snippet}\n")
                        break
    body = "\n".join(hits)
    return body[:30000]


SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line_hint": {"type": "string"},
                    "classification": {
                        "type": "string",
                        "enum": [
                            "ACTUAL_DEFECT_MISSING_FROM_E",
                            "HELPER_CALL_PRESERVING_CAUSE",
                            "STRING_INTERPOLATION_PRESERVES_MSG_ONLY",
                            "LEGIT_UNWRAPPING_HELPER",
                            "FALSE_POSITIVE",
                            "NONE",
                        ],
                    },
                    "why": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["HIGH", "MED", "LOW", "INFO"],
                    },
                },
                "required": ["classification", "why", "severity"],
            },
        },
        "verdict": {
            "type": "string",
            "enum": ["CONVERGED", "RESIDUAL_DEFECTS_FOUND",
                     "UNCERTAIN_NEEDS_HUMAN_REVIEW"],
        },
    },
    "required": ["findings", "verdict"],
}


def main() -> int:
    body = gather_context()
    prompt = (
        "Audit `except X as e: raise Y(...)` sites in email-triage src for "
        "exception-chaining loss. Classic Python defect: `raise Y(...)` "
        "inside `except X as e:` without `from e` sets `__cause__=None` and "
        "breaks the debugging traceback.\n\n"
        "Categories:\n"
        "- ACTUAL_DEFECT_MISSING_FROM_E: `raise SomeExc(f'... {e} ...')` — "
        "  interpolates the exception's `str()` but loses the chain.\n"
        "- HELPER_CALL_PRESERVING_CAUSE: `raise raise_api_error(e, ...)` or "
        "  similar — helper receives `e` as an arg and may internally raise "
        "  `from e`; needs code-verification.\n"
        "- STRING_INTERPOLATION_PRESERVES_MSG_ONLY: preserves the message "
        "  text but not the chain; still a defect for full traceback.\n"
        "- LEGIT_UNWRAPPING_HELPER: helper explicitly re-raises with cause "
        "  or intentionally strips the chain for security.\n"
        "- FALSE_POSITIVE: my walker's false trigger.\n\n"
        "Return strict JSON.\n\n"
        "== hits ==\n" + body
    )
    result = call_leira(prompt, SCHEMA)
    if not result.get("findings"):
        result["verdict"] = "CONVERGED"
    out = REPO / "scratchpad_leira_exception_chain_audit.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"verdict = {result.get('verdict')}")
    print(f"findings = {len(result.get('findings', []))}")
    for f in result.get("findings", []):
        print(f"  - [{f.get('severity')}] {f.get('classification')} — "
              f"{f.get('file', '?')} — {f.get('why', '')[:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
