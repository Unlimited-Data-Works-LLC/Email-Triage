#!/usr/bin/env python3
"""leira_docs_summarizer.py — Consumer #5 of the llm-host offload stack (2026-07-02).

Docs digest: scan a directory of markdown docs, emit a per-doc one-line summary
+ stale-flag (last-modified > N days). the AI assistant reads 20 summary lines instead
of 200 raw docs.

Modes:
  scan     — walk a dir; per-file summary + stale flag.
  weekly   — mtime-since-last-run; only summarise touched files.

Usage:
  python scripts/leira_docs_summarizer.py scan --dir docs/ --stale-days 90
  python scripts/leira_docs_summarizer.py weekly --dir docs/ --since 2026-06-25

Prints JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))
from leira_prepass import OllamaCallError, call_leira, context_bytes, get_consumer_config

_cfg = get_consumer_config("docs_summarizer")
MAX_INPUT_BYTES = int(_cfg.get("max_input_bytes_override") or context_bytes(
    _cfg.get("context_usage_ratio", 0.30)))
DEFAULT_STALE_DAYS = int(_cfg.get("default_stale_days", 90))

SUMMARY_SCHEMA = {
    "type": "object",
    "required": ["title", "one_line", "primary_topics"],
    "properties": {
        "title": {"type": "string", "description": "Extract from first H1 or use filename."},
        "one_line": {"type": "string", "description": "Single sentence: what this doc is FOR."},
        "primary_topics": {
            "type": "array",
            "items": {"type": "string"},
            "description": "3-5 short topic labels for cross-referencing.",
        },
        "stale_signal": {
            "type": "string",
            "description": "Optional: markers of staleness (e.g. 'references v0.1.x', 'TODO from Q4', 'unresolved P0').",
        },
    },
}


def _list_md(root: Path, since_mtime: float | None = None):
    """Yield md files under `root`; if since_mtime, only those newer."""
    for p in sorted(root.rglob("*.md")):
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if since_mtime is not None and m < since_mtime:
            continue
        yield p


def _summarise_one(path: Path, content: str) -> dict:
    if len(content) > MAX_INPUT_BYTES:
        content = content[:MAX_INPUT_BYTES]
    result = call_leira(
        prompt=(
            "You are summarising a project documentation markdown file. Return a "
            "one-sentence description of its purpose + 3-5 primary topic labels. "
            "If the doc references outdated versions, unresolved TODOs, or 'DRAFT'/"
            "'TBD' markers, note the stale_signal. Do NOT invent content. If the "
            "file is empty or unreadable, return title=filename + one_line='(empty)'.\n"
            f"Filename: {path.name}\n\n{content}"
        ),
        schema=SUMMARY_SCHEMA,
    )
    return result


def scan(dir_path: Path, stale_days: int) -> dict:
    cutoff = time.time() - stale_days * 86400
    entries = []
    stale_count = 0
    for p in _list_md(dir_path):
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            mtime = p.stat().st_mtime
        except OSError:
            continue
        try:
            summary = _summarise_one(p, content)
        except OllamaCallError as e:
            summary = {"title": p.name, "one_line": f"(llm-host error: {e})", "primary_topics": []}
        summary["path"] = str(p)
        summary["mtime_iso"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        summary["stale"] = mtime < cutoff
        if summary["stale"]:
            stale_count += 1
        entries.append(summary)
    return {
        "mode": "scan",
        "dir": str(dir_path),
        "count": len(entries),
        "stale_count": stale_count,
        "stale_days_threshold": stale_days,
        "entries": entries,
    }


def weekly(dir_path: Path, since: str) -> dict:
    try:
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit(f"bad --since (want ISO8601): {since}")
    since_mtime = since_dt.timestamp()
    entries = []
    for p in _list_md(dir_path, since_mtime=since_mtime):
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            summary = _summarise_one(p, content)
        except OllamaCallError as e:
            summary = {"title": p.name, "one_line": f"(llm-host error: {e})", "primary_topics": []}
        summary["path"] = str(p)
        entries.append(summary)
    return {"mode": "weekly", "dir": str(dir_path), "since": since, "count": len(entries), "entries": entries}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("--dir", type=Path, required=True)
    sc.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    wk = sub.add_parser("weekly")
    wk.add_argument("--dir", type=Path, required=True)
    wk.add_argument("--since", required=True, help="ISO8601 timestamp; files with mtime>=this are included.")
    args = ap.parse_args(argv)
    if args.mode == "scan":
        out = scan(args.dir, args.stale_days)
    else:
        out = weekly(args.dir, args.since)
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
