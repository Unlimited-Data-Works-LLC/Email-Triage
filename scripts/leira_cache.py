#!/usr/bin/env python3
"""leira_cache.py — response cache for llm-host offload consumers (2026-07-02).

Improvement #4 of the llm-host offload stack sharpening: cache Consumer #1
(census pre-pass) responses per (consumer_name, class_name, HEAD_sha) so
consecutive census runs on the SAME code state reuse the previous run's
llm-host output — zero llm-host tokens for unchanged classes.

Cache layout:
  ~/.llm-host-cache/<consumer_name>/<HEAD_sha>-<class_slug>.json

Callers use `cache_get(consumer, cls, head_sha)` + `cache_put(consumer,
cls, head_sha, payload)`. Both fail-open — a cache miss / read error /
write error never blocks the call chain (the consumer falls back to a
fresh llm-host invocation).

Invalidation: a new HEAD sha automatically invalidates all prior entries
(the key changes). Explicit invalidation via `cache_clear(consumer=None)`
— pass a specific consumer to clear one, None to clear all.

Storage bounded by design: each entry is small (<20KB typically); the
cache directory grows with (unique HEADs × classes), self-pruned by
`cache_prune(max_age_days=30)` on demand.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any


_CACHE_DIR = Path.home() / ".llm-host-cache"
_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def _cache_path(consumer: str, head_sha: str, class_name: str) -> Path:
    slug = _SLUG_RE.sub("_", class_name.lower())
    return _CACHE_DIR / consumer / f"{head_sha[:12]}-{slug}.json"


def cache_get(consumer: str, class_name: str, head_sha: str) -> Any | None:
    """Return the cached payload for (consumer, class_name, head_sha), or None
    on any miss / read error / decode error. Never raises."""
    try:
        p = _cache_path(consumer, head_sha, class_name)
        if not p.is_file():
            return None
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def cache_put(consumer: str, class_name: str, head_sha: str,
              payload: Any) -> bool:
    """Write the payload to the cache. Returns True on success, False on any
    error. Never raises — a failing put must not block the calling consumer."""
    try:
        p = _cache_path(consumer, head_sha, class_name)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: write to `<name>.tmp` then rename.
        tmp = p.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
        return True
    except (OSError, TypeError, ValueError):
        return False


def cache_clear(consumer: str | None = None) -> int:
    """Delete cache entries. When `consumer` is None → clear all consumers.
    Returns the count of files deleted. Never raises."""
    n = 0
    try:
        root = _CACHE_DIR if consumer is None else _CACHE_DIR / consumer
        if not root.is_dir():
            return 0
        for p in root.rglob("*.json"):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    except OSError:
        pass
    return n


def cache_prune(max_age_days: int = 30) -> int:
    """Remove cache entries older than `max_age_days`. Returns count deleted."""
    n = 0
    cutoff = time.time() - max_age_days * 86400
    try:
        if not _CACHE_DIR.is_dir():
            return 0
        for p in _CACHE_DIR.rglob("*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    n += 1
            except OSError:
                pass
    except OSError:
        pass
    return n


def cache_stats() -> dict[str, int]:
    """Return `{consumer: count_of_entries}` for each consumer with a cache
    dir. Useful for debugging / operator status."""
    out: dict[str, int] = {}
    try:
        if not _CACHE_DIR.is_dir():
            return out
        for d in _CACHE_DIR.iterdir():
            if d.is_dir():
                out[d.name] = len(list(d.glob("*.json")))
    except OSError:
        pass
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--clear", metavar="CONSUMER",
                    help="clear one consumer's cache (or ALL for everyone)")
    ap.add_argument("--prune-days", type=int, default=0,
                    help="delete entries older than N days")
    args = ap.parse_args()
    if args.stats:
        import sys
        stats = cache_stats()
        for k, v in sorted(stats.items()):
            print(f"{k}: {v}")
        if not stats:
            print("(no cache entries)")
    if args.clear:
        cleared = cache_clear(None if args.clear == "ALL" else args.clear)
        print(f"cleared {cleared} entries")
    if args.prune_days > 0:
        pruned = cache_prune(args.prune_days)
        print(f"pruned {pruned} entries older than {args.prune_days} days")
