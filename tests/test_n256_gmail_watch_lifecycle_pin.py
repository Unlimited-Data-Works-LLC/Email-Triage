"""N-256 R25 structural pin — gmail_watches.status lifecycle funnel (2026-07-03).

Census R25 discovered MED #7 (gmail_watches lifecycle triple, sibling
to N-69 O365): `gmail_watches` had NO `status`/`error_count`/`error_last`
columns; a Gmail watch renewal failure (non-auth) was invisible on
/health. The account-level auth_stale chip was the only signal.

N-256 fix (this commit):
  - Migration v50 adds `status TEXT DEFAULT 'active'` +
    `error_count INTEGER DEFAULT 0` + `error_last TEXT` to
    `gmail_watches` (mirrors office365_subscriptions shape exactly).
  - `web/db.py::record_gmail_watch_outcome` — SSOT funnel mirroring
    `record_o365_subscription_outcome` (N-69). Success → clear to
    active + reset; failure → bump + set errored.
  - CREATE TABLE schema in `web/db.py` updated for fresh installs.

FOLLOW-UP (deferred to a wiring commit): the renewal + IDLE + send
call sites in the gmail push consumer + watch renewer must call this
funnel. That wiring needs SME judgment on non-decisional paths (some
render-preview paths correctly do NOT touch the lifecycle) — same
class as N-255 record_provider_outcome adoption sweep. Wiring commits
will decrement the accompanying growth-cap ratchet as sites migrate.

WHAT IT PINS THIS COMMIT:

1. Anti-vacuity: `record_gmail_watch_outcome` imports + is callable.
2. STRICT-0 count-agnostic: raw
   `UPDATE gmail_watches SET status = ...` outside `web/db.py`
   (the funnel's home module) fires. Prevents future writers from
   forking the lifecycle.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILE = "web/db.py"
_TABLE = "gmail_watches"
_UPDATE_STATUS_RE = re.compile(
    rf"UPDATE\s+{_TABLE}\s+SET\s+.*\bstatus\s*=",
    re.IGNORECASE | re.DOTALL,
)


def test_record_gmail_watch_outcome_ssot_reachable():
    """Anti-vacuity: SSOT imports + accepts the documented kwargs."""
    from email_triage.web.db import record_gmail_watch_outcome
    assert callable(record_gmail_watch_outcome)


def test_record_gmail_watch_outcome_has_non_test_callers():
    """N-256b R27 anti-vacuity: `record_gmail_watch_outcome` MUST have
    at least one non-test caller in `src/email_triage/`. R27 census
    caught R26's N-256 landing the SSOT + schema + pin VACUOUSLY —
    zero callers, so /health silently lied for every Gmail push
    channel. This test fires if a refactor drops all wire-ups again."""
    caller_count = 0
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            # Direct call: `record_gmail_watch_outcome(...)`.
            if isinstance(node, ast.Call):
                f = node.func
                if (isinstance(f, ast.Name) and f.id == "record_gmail_watch_outcome"):
                    caller_count += 1
                if (isinstance(f, ast.Attribute) and f.attr == "record_gmail_watch_outcome"):
                    caller_count += 1
                # N-256b R27: also count `db_call(record_gmail_watch_outcome,
                # ...)` — the async-DB seam that WRAPS the SSOT to run it
                # under the process-wide DB write lock. Passing the fn as
                # an arg IS a caller (the wrapper invokes it).
                if isinstance(f, ast.Name) and f.id == "db_call" and node.args:
                    first_arg = node.args[0]
                    if (isinstance(first_arg, ast.Name)
                            and first_arg.id == "record_gmail_watch_outcome"):
                        caller_count += 1
    assert caller_count >= 3, (
        "N-256b R27 anti-vacuity: `record_gmail_watch_outcome` has "
        f"only {caller_count} non-test callers under src/. R26 census "
        "caught this SSOT landing vacuously (schema + pin + funnel but "
        "zero call-site wiring), so /health reported 'active' forever "
        "regardless of live watch health. Wire the funnel at every "
        "renew/notify/errored site (see N-256b commit for the 3+ "
        "seams: watch renewal success/failure + push consumer empty-"
        "delta + main-success paths)."
    )


def test_no_raw_update_gmail_watches_status_outside_ssot():
    """STRICT-0 count-agnostic: raw
    `UPDATE gmail_watches SET status = ...` outside `web/db.py` fires."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if _UPDATE_STATUS_RE.search(node.value):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-256 R25 gmail_watches.status lifecycle SSOT bypass: raw "
        f"`UPDATE gmail_watches SET status = ...` outside `{_SSOT_FILE}`. "
        "Route through `record_gmail_watch_outcome(db, account_id=..., "
        "error_text=...)` so the SET/CLEAR edges of the lifecycle stay "
        "symmetric — PD#18.\n\n"
        + "\n".join(offenders)
    )
