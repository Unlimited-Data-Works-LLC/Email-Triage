#!/usr/bin/env python3
"""C1 companion — SME-panel launcher + verdict writer.

Writes `audit-reports/sme-verdicts/<staged-diff-sha256>.json` with:
  * verdict (GO / GO-WITH-FIXES / REJECT)
  * agents (3-SME panel agent IDs)
  * transcripts[] (paths to the subagent transcript files)
  * diff_sha (the staged-diff sha256 the trailer will claim)
  * timestamp (ISO8601 UTC)
  * notes (operator-visible)

The `sme_evidence_gate.py` hook reads this artifact on commit and
DENIES `GO` / `GO-WITH-FIXES` trailers without one.

Usage
-----
This script does NOT actually spawn subagents (that's the agent's job
in the AI development tooling— it uses the Agent tool with subagent_type
hipaa-sme / db-sme / devils-advocate). Instead, the AGENT runs this
script AFTER the panel closes, passing the collected verdict + agent
IDs + transcript paths.

    python scripts/run-sme-panel.py write \\
        --verdict GO-WITH-FIXES \\
        --agent hipaa-sme=abc123 \\
        --agent db-sme=def456 \\
        --agent devils-advocate=ghi789 \\
        --transcript C:/…/tasks/abc123.output \\
        --transcript C:/…/tasks/def456.output \\
        --transcript C:/…/tasks/ghi789.output \\
        --notes "Tranche  close"

The `write` sub-command hashes the STAGED diff and writes the artifact.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def _staged_diff_sha(cwd: str) -> str:
    # N-328 R30 — MUST match the hook's `_staged_diff_sha` byte-shape
    # exactly. Both scripts use `text=True` + `.encode("utf-8")` so
    # \r\n → \n normalization applies consistently on Windows.
    r = subprocess.run(
        ["git", "diff", "--cached"],
        cwd=cwd, capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        sys.exit(f"git diff --cached failed: {r.stderr}")
    return hashlib.sha256(r.stdout.encode("utf-8")).hexdigest()


def cmd_write(args: argparse.Namespace) -> int:
    cwd = os.getcwd()
    diff_sha = _staged_diff_sha(cwd)
    if not diff_sha or diff_sha == hashlib.sha256(b"").hexdigest():
        sys.exit("staged diff is EMPTY — nothing to review. `git add` first.")

    agents: dict[str, str] = {}
    for entry in (args.agent or []):
        if "=" not in entry:
            sys.exit(f"--agent must be role=id, got: {entry}")
        role, aid = entry.split("=", 1)
        agents[role.strip()] = aid.strip()

    transcripts: list[str] = []
    for tref in (args.transcript or []):
        p = Path(tref)
        if not p.exists():
            sys.exit(f"--transcript file not found: {tref}")
        transcripts.append(tref)

    out = {
        "verdict": args.verdict,
        "diff_sha": diff_sha,
        "agents": agents,
        "transcripts": transcripts,
        "notes": args.notes or "",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    dst_dir = Path(cwd) / "audit-reports" / "sme-verdicts"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / f"{diff_sha}.json"
    dst.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote verdict artifact: {dst}")
    print(f"  verdict = {args.verdict}")
    print(f"  agents  = {list(agents.keys())}")
    print(f"  transcripts × {len(transcripts)}")
    print(f"  diff_sha = {diff_sha[:16]}…")
    print()
    print(
        "Now write the commit with the trailer:\n"
        f"  SME-Reviewed: {args.verdict} "
        f"({' + '.join(agents.keys())}, "
        f"{datetime.date.today().isoformat()})"
    )
    return 0


def cmd_hash(_args: argparse.Namespace) -> int:
    """Print the current staged-diff sha256 — useful for debugging."""
    print(_staged_diff_sha(os.getcwd()))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("write", help="Write the verdict artifact")
    w.add_argument("--verdict", required=True,
                   choices=["GO", "GO-WITH-FIXES", "REJECT"])
    w.add_argument("--agent", action="append", metavar="ROLE=ID",
                   help="Panel agent role=id (repeat for each agent)")
    w.add_argument("--transcript", action="append", metavar="PATH",
                   help="Transcript file path (repeat for each agent)")
    w.add_argument("--notes", default="")

    sub.add_parser("hash", help="Print staged-diff sha256")

    args = p.parse_args()
    if args.cmd == "write":
        return cmd_write(args)
    if args.cmd == "hash":
        return cmd_hash(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
