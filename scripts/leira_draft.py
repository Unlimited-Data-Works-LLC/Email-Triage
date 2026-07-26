#!/usr/bin/env python3
"""leira_draft.py — Consumer #3 of the llm-host offload stack.

Drafting helper: llm-host produces a FIRST DRAFT of a commit message, PR body, STATE
drawer, session retro, or a README/changelog section. the AI assistant polishes only if the draft
touches risk surface (HIPAA / audit / auth / egress / schema). Zero-AI provider on the
mechanical drafts (STATE drawers, log summaries, changelog rows).

Contract: llm-host draft is a STARTING TEXT, never the final. the AI assistant reads + edits before
any commit/publish. On risk-surface content SME review still applies. Never let llm-host's
draft become the record without human sign-off.

Modes:
  commit    — a git commit message (subject + body) from a diff.
  pr        — a PR body from the branch diff-summary + the goal.
  state     — a STATE_<date>_<slug>.md drawer body given a summary of what happened.
  retro     — a session-retro paragraph given a transcript excerpt.
  readme    — a README section from a feature description.
  changelog — a one-line changelog entry from a commit message.

Usage:
  python scripts/leira_draft.py <mode> [--input FILE|-] [options]

  input on stdin by default. Options depend on mode; see main().
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import call_leira, OllamaCallError, get_consumer_config, context_bytes

_cfg = get_consumer_config("draft")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.30)))

_PROMPTS = {
    "commit": (
        "Draft a git commit message from this diff. Use conventional-commit style: "
        "'<type>(<scope>): <subject>' on line 1 (max 72 chars, no trailing period), blank "
        "line, then a body wrapped at 78 chars. Body = the WHY (constraint, root cause) + "
        "one paragraph on what changed + one honest limitation if any. Do NOT invent test "
        "numbers you didn't see. Do NOT add Co-Authored-By or emoji. Output plain text only, "
        "no fences.\n\nDIFF:\n----\n{payload}\n----"
    ),
    "pr": (
        "Draft a GitHub PR body. Format: '## Summary' section (3-5 bullets), '## Test plan' "
        "section (checklist), '## Risks / limitations' section (honest). Wrap at 78 chars. No "
        "emoji. Do NOT invent CI or test counts. Output plain text.\n\nCONTEXT:\n----\n{payload}\n----"
    ),
    "state": (
        "Draft a STATE_<date>_<slug>.md drawer body. Start with a RESUME: line (one paragraph: "
        "goal, done, exact next step, open IDs, HEAD sha if given). Then a ## Done section, "
        "## Numbers/verified section, ## Known limitations section (honest), ## Queue section. "
        "Cite related drawers with [[double-brackets]]. Output plain text.\n\nSUMMARY:\n----\n{payload}\n----"
    ),
    "retro": (
        "Draft a session retro paragraph: what tools/scripts were built + one lesson + one "
        "decision. Under 200 words. Honest — never claim green without evidence.\n\n"
        "TRANSCRIPT EXCERPT:\n----\n{payload}\n----"
    ),
    "readme": (
        "Draft a README section for this feature. Sections: one-line what, quick-start command, "
        "'How it works' (3-6 bullets), 'Limitations' (honest). Plain markdown, no emoji.\n\n"
        "FEATURE:\n----\n{payload}\n----"
    ),
    "changelog": (
        "Draft ONE changelog line for this commit message: '<type>: <what changed> (<scope>)'. "
        "Max 100 chars, one line, no period.\n\nCOMMIT:\n----\n{payload}\n----"
    ),
}


def draft(mode: str, payload: str, *, extra_context: str = "") -> str:
    if mode not in _PROMPTS:
        raise SystemExit(f"unknown mode: {mode}; choices: {list(_PROMPTS)}")
    if len(payload) > MAX_INPUT_BYTES:
        payload = payload[:MAX_INPUT_BYTES] + "\n... [truncated]"
    prompt = _PROMPTS[mode].format(payload=payload)
    if extra_context:
        prompt = f"CONTEXT: {extra_context}\n\n" + prompt
    return call_leira(prompt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=list(_PROMPTS))
    ap.add_argument("--input", type=Path, help="input file (- for stdin, default)")
    ap.add_argument("--context", default="", help="short extra context prepended to prompt")
    args = ap.parse_args()
    if args.input and str(args.input) != "-":
        payload = args.input.read_text(encoding="utf-8", errors="replace")
    else:
        payload = sys.stdin.read()
    try:
        out = draft(args.mode, payload, extra_context=args.context)
    except OllamaCallError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(out.strip() if isinstance(out, str) else out)


if __name__ == "__main__":
    main()
