#!/usr/bin/env python3
"""leira_verify_prepass.py — Consumer #2 of the llm-host offload stack.

Verify-don't-accept pre-filter: given a set of findings (each a claim + file:line
evidence pointers), llm-host reads the source at HEAD and classifies each as CONFIRMED /
STALE / REFUTED / PARTIAL / UNCERTAIN with a one-line reason. the AI assistant confirms only the
non-obviously-STALE/REFUTED ones + always owns the final verdict on HIPAA/security calls.

Bulk usage: run against the run19 backlog's finding list to auto-mark obvious STALEs
(code moved / SSOT already exists / pin already widened) BEFORE the AI assistant spends any tokens.
The typical audit reshapes ~half of findings — this consumer catches the cheap half.

Contract: llm-host output is a PROBE. Always confirm CONFIRMED/REFUTED results with a the AI assistant
read-of-source before acting on them; llm-host may have misread. The savings are on the
EASY reshapes, not on the load-bearing calls.

Usage:
    python scripts/leira_verify_prepass.py --findings-json findings.json > verdicts.json

findings.json = list[{
    "id": "F1",
    "claim": "The _GATE_NAMES set is incomplete — 5 gate names are missing",
    "evidence_paths": ["tests/test_authz_by_id_fetch_pin.py"],   # files to READ
    "evidence_snippets": [],                                     # optional pre-quoted lines
}]
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

_cfg = get_consumer_config("verify_prepass")
# Context-derived (learned from llm-host at import time, not hardcoded 98K):
MAX_FILE_BYTES = int(_cfg.get("max_file_bytes_override") or context_bytes(
    _cfg.get("per_file_context_ratio", 0.10)))
MAX_EVIDENCE_FILES = int(_cfg.get("max_evidence_files", 5))

VERDICT_SCHEMA = {
    "type": "object",
    "required": ["id", "verdict", "reason", "confidence"],
    "properties": {
        "id": {"type": "string"},
        "verdict": {
            "type": "string",
            "enum": ["CONFIRMED", "STALE", "REFUTED", "PARTIAL", "UNCERTAIN"],
        },
        "reason": {"type": "string", "description": "One line: what the source shows"},
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "high=obvious from evidence; low=the AI assistant should re-read",
        },
        "evidence_line_ref": {
            "type": "string",
            "description": "Optional: 'path:line' most-supporting your verdict (empty if none)",
        },
    },
}


def _load_evidence(paths: list[str], repo_root: Path) -> tuple[str, list[str]]:
    """Read up to MAX_EVIDENCE_FILES; each capped at MAX_FILE_BYTES. Return blob + honest
    caveat list (files trimmed, files skipped)."""
    caveats: list[str] = []
    blob_parts: list[str] = []
    for p in paths[:MAX_EVIDENCE_FILES]:
        # Normalize path
        pn = p.replace("\\", "/").lstrip("./")
        # Try repo_root/<as-is> then repo_root/src/email_triage/<as-is>
        for candidate in (repo_root / pn, repo_root / "src" / "email_triage" / pn):
            if candidate.is_file():
                try:
                    content = candidate.read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    caveats.append(f"unreadable: {p} ({e})")
                    break
                if len(content) > MAX_FILE_BYTES:
                    content = content[:MAX_FILE_BYTES] + "\n... [truncated]"
                    caveats.append(f"trimmed to {MAX_FILE_BYTES}B: {p}")
                blob_parts.append(f"=== FILE: {pn} ===\n{content}\n")
                break
        else:
            caveats.append(f"NOT FOUND at HEAD: {p}")
    if len(paths) > MAX_EVIDENCE_FILES:
        caveats.append(f"only read first {MAX_EVIDENCE_FILES} of {len(paths)} evidence files")
    return "\n".join(blob_parts), caveats


def verify_one(finding: dict, repo_root: Path) -> dict:
    fid = finding.get("id") or "?"
    claim = finding.get("claim") or ""
    ev_paths = finding.get("evidence_paths") or []
    ev_snippets = finding.get("evidence_snippets") or []

    evidence_blob, caveats = _load_evidence(ev_paths, repo_root)
    snippet_block = ""
    if ev_snippets:
        snippet_block = "\nPRE-QUOTED SNIPPETS FROM THE FINDING:\n" + "\n".join(ev_snippets) + "\n"

    prompt = (
        f"You are a verify-don't-accept PRE-FILTER for an email-triage HIPAA-class code audit. "
        f"A claim has been made; you read the source at HEAD and classify. the AI assistant will confirm "
        f"non-obvious verdicts after you.\n\n"
        f"FINDING id: {fid}\n"
        f"CLAIM: {claim}\n"
        f"{snippet_block}"
        f"SOURCE AT HEAD (may be truncated):\n----\n{evidence_blob}\n----\n\n"
        f"Choose ONE verdict:\n"
        f"- CONFIRMED — the source clearly supports the claim (name the file:line).\n"
        f"- STALE — the code has changed; the claim's premise no longer applies (e.g. the SSOT "
        f"the claim says is missing ALREADY exists at HEAD, or the pin the claim says is incomplete "
        f"has been widened).\n"
        f"- REFUTED — the source clearly contradicts the claim.\n"
        f"- PARTIAL — the claim is right about some part, wrong about another.\n"
        f"- UNCERTAIN — you can't tell from what you can see. Confidence must be 'low'.\n\n"
        f"For confidence: 'high' means a maintainer would agree from what you read; 'medium' means "
        f"a reread is prudent; 'low' means the AI assistant MUST re-verify.\n"
        f"Do not over-declare CONFIRMED — audits often reshape (~half of findings). Default to "
        f"UNCERTAIN if the evidence is thin. Cite one file:line in evidence_line_ref if you can."
    )

    try:
        result = call_leira(prompt, schema=VERDICT_SCHEMA)
    except OllamaCallError as e:
        # Fail-open: return UNCERTAIN so the AI assistant picks it up
        return {
            "id": fid,
            "verdict": "UNCERTAIN",
            "reason": f"llm-host call failed; the AI assistant must verify. ({e})",
            "confidence": "low",
            "evidence_line_ref": "",
            "_prepass_error": str(e),
        }

    if caveats:
        result["_evidence_caveats"] = caveats
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings-json", type=Path, required=True,
                    help="JSON file: list of {id,claim,evidence_paths[,evidence_snippets]}")
    ap.add_argument("--repo-root", default=".", type=Path)
    args = ap.parse_args()

    findings = json.loads(args.findings_json.read_text(encoding="utf-8"))
    repo_root = args.repo_root.resolve()

    verdicts = []
    for f in findings:
        v = verify_one(f, repo_root)
        verdicts.append(v)
        # progress to stderr, JSON on stdout
        print(f"  {v['id']}: {v['verdict']} ({v['confidence']}) — {v['reason'][:80]}",
              file=sys.stderr)

    print(json.dumps(verdicts, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
