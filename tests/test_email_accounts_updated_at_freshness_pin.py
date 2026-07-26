"""UPDATE email_accounts freshness pin (llm-host census MED #3, 2026-07-24).

Structural guarantee: every raw-SQL `UPDATE email_accounts SET …`
statement in `src/email_triage/` MUST bump `updated_at` in the same
SET clause. The row is the writer/reader coherence key — a mutation
without `updated_at` is a silent staleness leak (cached readers,
label-invalidation misses, replication-lag drift).

Anchors: llm-host census wf_372dbfb0-8f2 row 3 (MED, effort S,
discovered). Sibling `web/db.py:5041` is compliant — this pin
brings the rest of the tree to that shape.

The grandfather list shrinks monotonically — every fold of a listed
site drops its grandfather row, and the anti-stale companion test
prunes rows whose SET-shape no longer matches the tree.
"""
from __future__ import annotations

import re

from _pin_harness import SRC_ROOT, iter_src_files, relpath

# Locate every "UPDATE email_accounts SET" hit; a FIXED 400-char
# follow-through window is scanned for `updated_at`. This handles
# multi-line SET clauses assembled via Python adjacent-string-literal
# concatenation ("UPDATE ... SET " "col = ?, " "updated_at = ? ").
# The window is a plain slice — generous vs the ~80-char real
# statements; if a future statement outgrows it the pin fails LOUD
# (offender listed), never silently passes.
_UPDATE_ANCHOR_RE = re.compile(
    r"UPDATE\s+email_accounts\s+SET\b",
    re.IGNORECASE,
)

# Grandfathered sites — known drift documented by llm-host census
# wf_372dbfb0-8f2. Each key = repo-relative path; value = LOWER-CASED
# distinguishing snippet of the SET clause (matched substring) + a
# free-text reason. Any new offending UPDATE fails the pin unless
# added here explicitly with an operator sign-off.
_GRANDFATHERED: dict[str, list[tuple[str, str]]] = {
    "db/accounts.py": [
        ("style_alias_mode_enabled",
         "llm-host census row 3 — pre-SSOT set_alias_mode_enabled; "
         "TODO: route through _update_email_account_row funnel"),
    ],
    "cli.py": [
        ("aliases_json",
         "llm-host census row 3 — sibling of accounts.py:1309 which IS "
         "compliant; TODO: dedup to _update_email_account_row funnel"),
    ],
    "web/db.py": [
        # Two occurrences (lines 678 + 796) — SAME SET-clause shape
        # `UPDATE ... SET config_json = ? WHERE id = ?` (single-line).
        ("config_json = ? where",
         "llm-host census row 3 — settings-tab persist path; TODO: "
         "route through _update_email_account_row funnel"),
    ],
}

# Files whose UPDATE-email_accounts statements are exempt entirely.
# Migration bodies are IMMUTABLE post-apply per
# `test_migrations_applied_body_immutable.py` — the shape they wrote
# was correct for the migration's rev; adding updated_at now would
# break the checksum invariant. This pin covers LIVE writers only.
_FILE_EXEMPT: frozenset[str] = frozenset({
    "web/migrations.py",
    "db/migrations.py",
})


def _iter_updates_in_file(path):
    """Yield (match_obj, window_lower, text) for every UPDATE anchor.
    Window = the next 400 chars after the anchor (covers multi-line
    string-literal concat + the WHERE clause). Lower-cased for
    keyword matching."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _UPDATE_ANCHOR_RE.finditer(text):
        window = text[m.end() : m.end() + 400].lower()
        yield m, window, text


def _is_grandfathered(rel_path: str, window: str) -> bool:
    entries = _GRANDFATHERED.get(rel_path, [])
    return any(snippet in window for snippet, _reason in entries)


def test_update_email_accounts_bumps_updated_at_or_grandfathered():
    """Every live `UPDATE email_accounts SET …` must include
    `updated_at` in the SET clause, unless the site is on the
    grandfather list with a documented llm-host-census reason."""
    offenders: list[tuple[str, int, str]] = []

    for py in iter_src_files():
        rel = relpath(py, SRC_ROOT)
        if rel in _FILE_EXEMPT:
            continue
        for m, window, text in _iter_updates_in_file(py):
            if "updated_at" in window:
                continue
            if _is_grandfathered(rel, window):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            offenders.append((rel, lineno, window[:80].strip()))

    assert not offenders, (
        "UPDATE email_accounts freshness violation (llm-host census "
        "wf_372dbfb0-8f2 row 3). Every raw-SQL `UPDATE email_accounts "
        "SET …` must bump `updated_at` in the same SET clause OR be "
        "on the grandfather list in this pin (with a documented "
        "reason to migrate). New offenders:\n"
        + "\n".join(f"  - {p}:{ln}  SET {snip!r}" for p, ln, snip in offenders)
    )


def test_grandfather_entries_still_exist_in_tree():
    """Anti-drift: a grandfather row whose SET-shape no longer
    matches anything in the src tree must be pruned (it means the
    fold happened elsewhere — keeping the row masks a new drift)."""
    stale: list[tuple[str, str]] = []
    for rel, entries in _GRANDFATHERED.items():
        py = SRC_ROOT / rel
        if not py.exists():
            for snip, _reason in entries:
                stale.append((rel, snip))
            continue
        text = py.read_text(encoding="utf-8", errors="replace").lower()
        for snip, _reason in entries:
            if snip not in text:
                stale.append((rel, snip))
    assert not stale, (
        "Grandfather entry no longer matches any UPDATE site — prune the "
        "row from _GRANDFATHERED (the referenced fold may have happened "
        "elsewhere):\n"
        + "\n".join(f"  - {p}: {s!r}" for p, s in stale)
    )
