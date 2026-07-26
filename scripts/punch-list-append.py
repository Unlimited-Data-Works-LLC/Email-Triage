#!/usr/bin/env python3
"""the backlog-append.py — schema-compliant the backlog row emitter.

Any future audit / scanner that wants to file items into the backlog
MUST route through this helper — the 2026-07-03 hardcode-audit-v2
incident emitted 25 rows with `hardcode-audit-v2 sev=X cat=Y: <path>
= <val> |||||| |` shape, packing every field into cell 2 with 6
empty trailing columns and BYPASSING the 8-column schema the file's
header describes. Result: `slim-the backlog.py` couldn't archive the
`closed` rows because a malformed row upstream broke its inner
walker, AND an HTML comment inserted next to them broke the same
walker at a different line.

CONTRACT (matches the backlog header):
    | # | Sev | Status | Release | Feature | Item | Action | Impact |

Usage from Python:
    from scripts.punch_list_append import append_row
    append_row(
        sev="HIGH",              # CRIT | HIGH | MED | LOW
        status="open",           # open | in-flight | deferred | parked | closed
        release="v0.2.0",        # v0.1.1 | v0.1.2 | v0.1.x | v0.2.0 | Roadmap
        feature="Config drift",  # short label
        item="**Hardcoded url** — `foo.py:36` = `'http://localhost'`",
        action="None yet — move to config or SSOT-derived value",
        impact="Config drift risk when the hardcoded value diverges",
    )

Usage from CLI (any language, one row per invocation):
    python scripts/the backlog-append.py \\
        --sev HIGH --status open --release v0.2.0 \\
        --feature 'Config drift' \\
        --item '**Hardcoded url** — ...' \\
        --action 'None yet — ...' \\
        --impact 'Config drift risk ...'

The helper AUTO-ASSIGNS the next `#` slot by scanning the existing
table for the max row number + 1 (no pre-assignment races if two
scanners run — file lock via O_APPEND + read-modify-write is a
follow-up if that becomes a real problem).

SCHEMA VALIDATION:
- Refuses to append if cells contain unescaped `|` (breaks the table).
- Refuses `sev` outside the enum.
- Refuses `status` outside the enum.
- Refuses a blank item.

Never emits an HTML comment or blank line adjacent to a data row
(both break `slim-the backlog.py`'s inner walker — same failure the
hardcode-audit incident triggered).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PUNCH_LIST = Path(__file__).resolve().parent.parent / "the backlog"

_SEV_ENUM = frozenset({"CRIT", "HIGH", "MED", "LOW"})
_STATUS_ENUM = frozenset({
    "open", "in-flight", "deferred", "parked", "closed",
    "done", "shipped",
})
_RELEASE_HINTS = ("v0.1.1", "v0.1.2", "v0.1.x", "v0.2.0", "Roadmap")


def _next_row_number() -> int:
    """Scan the backlog for the max `| N |` prefix + return N+1."""
    if not PUNCH_LIST.exists():
        return 1
    max_n = 0
    for line in PUNCH_LIST.read_text(encoding="utf-8").split("\n"):
        m = re.match(r"^\|\s*(\d+)\s*\|", line)
        if m:
            n = int(m.group(1))
            if n > max_n:
                max_n = n
    return max_n + 1


def _escape_pipe(cell: str) -> str:
    """A `|` character inside a cell BREAKS the markdown table. Replace
    with escaped `\\|` — GitHub-flavored markdown renders that as a
    literal pipe."""
    return cell.replace("|", "\\|")


def append_row(
    *,
    sev: str,
    status: str,
    release: str,
    feature: str,
    item: str,
    action: str = "",
    impact: str = "",
    number: int | None = None,
) -> int:
    """Append a compliant row to the backlog. Returns the assigned #."""
    if sev not in _SEV_ENUM:
        raise ValueError(
            f"sev must be one of {sorted(_SEV_ENUM)}; got {sev!r}"
        )
    if status not in _STATUS_ENUM:
        raise ValueError(
            f"status must be one of {sorted(_STATUS_ENUM)}; got {status!r}"
        )
    if not item.strip():
        raise ValueError("item cannot be blank")
    # Refuse HTML-comment-like item (breaks slim's inner walker).
    if item.strip().startswith("<!--"):
        raise ValueError("item cannot start with an HTML comment")

    n = number if number is not None else _next_row_number()

    # Escape pipes inside cells so the table row parses.
    cells = [
        str(n),
        sev,
        status,
        _escape_pipe(release.strip()),
        _escape_pipe(feature.strip()),
        _escape_pipe(item.strip()),
        _escape_pipe(action.strip()) or "None yet",
        _escape_pipe(impact.strip()) or "See item description",
    ]
    row = "| " + " | ".join(cells) + " |"

    # Append. Ensure a newline before if the file doesn't end in one,
    # and never emit a blank line between rows.
    text = PUNCH_LIST.read_text(encoding="utf-8") if PUNCH_LIST.exists() else ""
    if text and not text.endswith("\n"):
        text += "\n"
    text += row + "\n"
    PUNCH_LIST.write_text(text, encoding="utf-8")
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Append a compliant row to the backlog.")
    p.add_argument("--sev", required=True, choices=sorted(_SEV_ENUM))
    p.add_argument("--status", required=True, choices=sorted(_STATUS_ENUM))
    p.add_argument("--release", required=True, help=f"e.g. {', '.join(_RELEASE_HINTS)}")
    p.add_argument("--feature", required=True, help="short label (e.g. 'Config drift')")
    p.add_argument("--item", required=True, help="what it is; use **bold** for the headline")
    p.add_argument("--action", default="", help="what the operator does; default: 'None yet'")
    p.add_argument("--impact", default="", help="why it matters + honest scope")
    p.add_argument("--number", type=int, help="explicit row #; default: auto")
    args = p.parse_args(argv)

    try:
        n = append_row(
            sev=args.sev, status=args.status, release=args.release,
            feature=args.feature, item=args.item, action=args.action,
            impact=args.impact, number=args.number,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"appended row #{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
