#!/usr/bin/env python3
"""leira_style_precompute.py — Consumer #9 of the llm-host offload stack (2026-07-02).

Batch style-distill precompute: for each account with recent sent-mail activity,
sample up to N messages and pre-warm the style profile via llm-host. Runs on-demand
or via cron; results are just cached by the existing distill pipeline (no new
storage).

The actual distill / writer-profile pipeline lives in
`style_learning/distill_hipaa.py` + `style_learning/per_contact_hipaa.py`;
this consumer is a THIN dispatcher that walks accounts + calls the pipeline
via CLI. HIPAA gating stays enforced at the pipeline (this dispatcher doesn't
bypass it — an HIPAA-flagged account still hits the BAA gate; a non-BAA'd llm-host
config = SKIP with reason).

Usage:
  python scripts/leira_style_precompute.py --dry-run   # list accounts + counts
  python scripts/leira_style_precompute.py --run       # actually invoke

Prints JSON progress + summary to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import get_consumer_config

_cfg = get_consumer_config("style_precompute")
MAX_SAMPLES = int(_cfg.get("max_samples_per_account", 25))
PIPELINE_TIMEOUT_S = int(_cfg.get("pipeline_timeout_s", 1800))  # NO-HARDCODE pillar #1


def _list_accounts() -> list[dict]:
    """List accounts with recent sent activity. Delegates to email-triage CLI
    which knows the DB schema + HIPAA gate."""
    r = subprocess.run(
        ["python", "-m", "email_triage", "accounts", "--list", "--json"],
        capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        return []
    try:
        return json.loads(r.stdout).get("accounts", [])
    except (ValueError, TypeError):
        return []


def _precompute_one(account_id: int, max_samples: int, dry_run: bool) -> dict:
    """Invoke the pipeline for one account. On dry_run just report the plan."""
    if dry_run:
        return {"account_id": account_id, "planned_samples": max_samples, "dispatched": False}
    r = subprocess.run(
        [
            "python", "-m", "email_triage", "style", "distill",
            "--account-id", str(account_id),
            "--max-samples", str(max_samples),
            "--json",
        ],
        capture_output=True, text=True, check=False, timeout=PIPELINE_TIMEOUT_S,
    )
    result = {
        "account_id": account_id,
        "returncode": r.returncode,
        "dispatched": True,
    }
    if r.returncode != 0:
        result["error"] = r.stderr[-500:] if r.stderr else "unknown"
        return result
    try:
        result["distill_output"] = json.loads(r.stdout) if r.stdout.strip() else {}
    except (ValueError, TypeError):
        result["distill_output_raw"] = r.stdout[:500]
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true",
                    help="List accounts + planned max-samples; do not dispatch.")
    ap.add_argument("--run", action="store_true",
                    help="Actually invoke the distill pipeline per account.")
    ap.add_argument("--max-samples", type=int, default=MAX_SAMPLES)
    ap.add_argument("--account-id", type=int, help="Limit to a specific account.")
    args = ap.parse_args(argv)
    if not args.dry_run and not args.run:
        raise SystemExit("must pass --dry-run or --run")

    accounts = _list_accounts()
    if args.account_id is not None:
        accounts = [a for a in accounts if a.get("id") == args.account_id]

    results = []
    for a in accounts:
        aid = a.get("id")
        if aid is None:
            continue
        results.append(_precompute_one(aid, args.max_samples, dry_run=args.dry_run))
    summary = {
        "mode": "dry_run" if args.dry_run else "run",
        "account_count": len(results),
        "dispatched_count": sum(1 for r in results if r.get("dispatched")),
        "failed_count": sum(1 for r in results if r.get("returncode") not in (None, 0)),
        "results": results,
    }
    json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
