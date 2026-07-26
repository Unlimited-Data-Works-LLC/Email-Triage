"""N-357 R31 — `parse_iso_aware` SSOT + assume-UTC-on-naive shim ban.

Trust-repair fix-forward per PHASE2 tranche  db-sme +  hipaa-sme +
the backlog  (TASK ). Three inline sites did the same 3-line
assume-UTC-on-naive shim:

    dt = parse_iso(raw)
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

An inline change to the assume-UTC posture (e.g. "assume US/Central
instead") would have had to touch every site. N-357 collapses them onto
`_isotime.parse_iso_aware`; this pin bans new inline shims + verifies
the SSOT exists.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_MODULE = SRC_ROOT / "_isotime.py"


def test_parse_iso_aware_ssot_exists():
    """The SSOT MUST live in `_isotime.py`. Deleting it re-opens every
    migrated caller (auth.py + poll_ingestion.py) to a fresh inline
    shim — the very drift class this pin prevents."""
    tree = parse_module(_SSOT_MODULE)
    assert tree is not None
    fn_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "parse_iso_aware" in fn_names, (
        "N-357: `parse_iso_aware` missing from `_isotime.py`. Restore it "
        "or migrate the 3 callers back to inline shims (and file a new "
        "the backlog row explaining why the SSOT-of-3 was abandoned)."
    )


# Baseline allow-list of SITES (relpath:qname / relpath) whose inline
# shim shape is known-existing at N-357 landing (2026-07-05). Every entry
# here is a MIGRATION IOU — tracked as the backlog N-357b (mass migration
# to `parse_iso_aware`). Do NOT add new entries; the pin exists to
# prevent NEW inline shims. The migration cycle SHRINKS this set
# monotonically. This mirrors the shape-based-baseline pattern used by
# other ratchet pins (e.g. N-338c walker's `_ALLOWLIST_UNRESOLVED`).
#
# Key format: `<relpath>:<qname>` where qname is
# `enclosing_qualified_name(node)`. Falls back to `<relpath>` when the
# node has no enclosing function (module-scope shim — rare).
_ALLOWED_INLINE_BASELINE: frozenset[str] = frozenset({
    # Migration IOUs (baseline snapshot at N-357 landing 2026-07-05).
    # Every entry below MUST get a follow-up migration commit + one
    # deletion from this set. The pin fails if any migration reintroduces
    # a shape here.
    # actions/digest_filter.py — migrated 2026-07-06 (N-357b tranche 4)
    # actions/hipaa_style_distill.py — migrated 2026-07-05 (N-357b tranche 1)
    # classify/safety_detect.py — migrated 2026-07-06 (N-357b tranche 4)
    # engine/models.py — migrated 2026-07-06 (N-357b tranche 4)
    # providers/gmail_api.py — migrated 2026-07-06 (N-357b tranche 3)
    # providers/gmail_calendar.py — migrated 2026-07-06 (N-357b tranche 2)
    "providers/office365_calendar.py",  # semantic-carrying shim (is_all_day) — see db-sme REJECT on tranche 4; kept out of migration
    # style_learning/distill_hipaa.py — migrated 2026-07-06 (N-357b tranche 2)
    # style_learning/per_contact_hipaa.py — migrated 2026-07-06 (N-357b tranche 4)
    # style_learning/trigger_watcher.py — migrated 2026-07-06 (N-357b tranche 3)
    # web/acme_renewer.py — migrated 2026-07-06 (N-357b tranche 3)
    # web/routers/agent_api.py — migrated 2026-07-06 (N-357b tranche 3)
    # web/routers/health.py — migrated 2026-07-06 (N-357b tranche 3, both sites)
    # web/routers/integrations.py — migrated 2026-07-06 (N-357b tranche 3)
    # web/routers/ui/_shared.py — migrated 2026-07-06 (N-357b tranche 4)
    # web/routers/ui/oauth.py — migrated 2026-07-06 (N-357b tranche 2)
    # web/routers/ui/profile.py — migrated 2026-07-06 (N-357b tranche 2)
})


def _is_assume_utc_shim_pattern(node: ast.If) -> bool:
    """Recognise the shim shape:

        if <X>.tzinfo is None:
            <X> = <X>.replace(tzinfo=<something-utc>)

    The <utc> RHS can be `timezone.utc`, `dt.timezone.utc`, `datetime.
    timezone.utc`, `pytz.UTC`, etc. — this walker matches on the shape
    of the guard + the `.replace(tzinfo=...)` call, not the specific tz.
    """
    # Guard: `X.tzinfo is None`
    if not isinstance(node.test, ast.Compare):
        return False
    if len(node.test.ops) != 1 or not isinstance(node.test.ops[0], ast.Is):
        return False
    if not isinstance(node.test.left, ast.Attribute) or node.test.left.attr != "tzinfo":
        return False
    if not (
        len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value is None
    ):
        return False
    # Body: `X = X.replace(tzinfo=<...>)` — accept as either single Assign
    # or the same shim wrapped in a sibling if statement's body first stmt.
    body = list(node.body)
    if not body:
        return False
    first = body[0]
    if not isinstance(first, ast.Assign):
        return False
    if not isinstance(first.value, ast.Call):
        return False
    call = first.value
    if not (
        isinstance(call.func, ast.Attribute) and call.func.attr == "replace"
    ):
        return False
    if not any(
        isinstance(k, ast.keyword) and k.arg == "tzinfo" for k in call.keywords
    ):
        return False
    return True


def test_no_new_inline_assume_utc_shim_outside_ssot():
    """Ban the 3-line shim shape outside `_isotime.py`. Every legit
    caller uses `parse_iso_aware`; anyone reaching for the inline shape
    is either (a) rebuilding the SSOT locally (drift), (b) using a
    different tz assumption (which needs its own SSOT + register row).

    Baseline (`_ALLOWED_INLINE_BASELINE`) carries the 17-file snapshot
    of shim sites at N-357 landing (2026-07-05) — these are the
    N-357b migration IOU. Every file in the baseline is a MIGRATION
    TARGET; the file is removed from the baseline when its shims are
    migrated. NEW files (not in the baseline) MUST use the SSOT.
    """
    baseline_hits: dict[str, int] = {}
    new_violations: list[str] = []
    for path in iter_files(SRC_ROOT):
        # Skip the SSOT module — its body IS the shim, but the shape
        # inside `parse_iso_aware` uses an unconditional replace after
        # a None-guard, not the `if tzinfo is None: replace(...)`
        # walker-matched pattern.
        if path.name == "_isotime.py":
            continue
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _is_assume_utc_shim_pattern(node):
                if rel in _ALLOWED_INLINE_BASELINE:
                    baseline_hits[rel] = baseline_hits.get(rel, 0) + 1
                else:
                    new_violations.append(f"{rel}:{node.lineno}")
    if new_violations:
        pytest.fail(
            "N-357: NEW inline `if <X>.tzinfo is None: <X> = <X>."
            "replace(tzinfo=<utc>)` shim(s) outside `_isotime.py` — "
            "file not in the N-357 baseline. Migrate to "
            "`parse_iso_aware` (SSOT), or if the tz assumption differs "
            "land a new SSOT (with a register row) instead of hand-"
            "rolling.\n\nNEW violations:\n  "
            + "\n  ".join(new_violations)
        )
    # Monotone shrink guard: every baseline entry MUST still contain at
    # least one shim. If a baseline file no longer has any shim, remove
    # its entry from `_ALLOWED_INLINE_BASELINE` to keep the ratchet
    # shrinking.
    stale = _ALLOWED_INLINE_BASELINE - baseline_hits.keys()
    if stale:
        pytest.fail(
            "N-357 ratchet-shrink: baseline entries with ZERO remaining "
            "shims — remove them from `_ALLOWED_INLINE_BASELINE` so the "
            "ratchet keeps shrinking monotonically.\n\nStale baseline "
            "entries:\n  " + "\n  ".join(sorted(stale))
        )
