#!/usr/bin/env python3
"""leira_flag_advisor.py — Consumer #7 of the llm-host offload stack (2026-07-02).

Feature-flag advisor: scan src/ for `env_bool("EMAIL_TRIAGE_*")` and `getenv`
patterns, group by flag name, emit deprecation candidates (flags with only 1
call site, or flags whose default has been the same for > N days).

Usage:
  python scripts/leira_flag_advisor.py --src src/email_triage --min-sites 1

Prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("flag_advisor")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.40)))
FLAG_NAME_RE = re.compile(r'EMAIL_TRIAGE_[A-Z0-9_]+')


ADVISOR_SCHEMA = {
    "type": "object",
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["flag", "reason", "recommendation"],
                "properties": {
                    "flag": {"type": "string"},
                    "reason": {"type": "string"},
                    "recommendation": {
                        "type": "string",
                        "enum": ["retire", "promote", "no_change"],
                    },
                    "sites": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}


def _find_flag_sites(src: Path) -> dict[str, list[str]]:
    """Grep AST for every EMAIL_TRIAGE_* env-var reference. Returns
    {flag_name: [file:line, ...]}."""
    sites = defaultdict(list)
    for p in src.rglob("*.py"):
        if "__pycache__" in str(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            for m in FLAG_NAME_RE.finditer(node.value):
                sites[m.group(0)].append(f"{p.relative_to(src.parent)}:{node.lineno}")
    return sites


def advise(sites: dict[str, list[str]], min_sites: int) -> dict:
    """Emit candidates. Small-count flags → retire candidates; give llm-host the
    site list to sanity-check + recommend."""
    candidates_input = {
        flag: locs for flag, locs in sites.items() if len(locs) >= min_sites
    }
    # Compact serialisation for llm-host prompt (flag: N sites: [top-5]).
    compact = "\n".join(
        f"{flag}: {len(locs)} sites: {', '.join(sorted(locs)[:5])}"
        for flag, locs in sorted(candidates_input.items())
    )
    if len(compact) > MAX_INPUT_BYTES:
        compact = compact[:MAX_INPUT_BYTES]
    try:
        result = call_leira(
            prompt=(
                "You are advising on feature-flag hygiene. For each flag in the list, decide:\n"
                "- retire: 1-2 sites AND flag looks single-purpose / temporary (env-vars for one-off "
                "migrations, dev-only guards, 'quick-fix' bypasses).\n"
                "- promote: MANY sites AND behavior is now core — flag should become the default.\n"
                "- no_change: shared config, deployment knob, or actively-tuned production flag.\n\n"
                "Do NOT invent flags. Only recommend on flags in the list. Explain each in one line.\n\n"
                f"Flag inventory:\n{compact}"
            ),
            schema=ADVISOR_SCHEMA,
        )
    except OllamaCallError as e:
        return {"candidates": [], "leira_error": str(e)}
    # Enrich with the full site list per llm-host-flagged candidate.
    for c in result.get("candidates", []):
        c["sites"] = sites.get(c["flag"], [])
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", type=Path, default=Path("src/email_triage"))
    ap.add_argument("--min-sites", type=int, default=1)
    args = ap.parse_args(argv)
    sites = _find_flag_sites(args.src)
    out = advise(sites, args.min_sites)
    out["total_flags"] = len(sites)
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
