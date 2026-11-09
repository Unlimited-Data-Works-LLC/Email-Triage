""" / -A — the fire-and-forget ``create_task`` tracking pin.

PD#1/#3:  (commit 7ed4f72) made the fire-and-forget task SSOT (track tasks in
``app.state._fire_and_forget_pending`` / a supervisor set, cancel them in the
autouse drain) but shipped WITHOUT its count-agnostic interprocedural pin — so a
NEW bare ``asyncio.create_task(...)`` whose result is never stored can land
again, GC'd mid-run (the exact  bug). The warnings gate does NOT cover this
class: the bug is a SCHEDULED-then-garbage-collected task, which never emits
"coroutine was never awaited" — so it is invisible to ``error::RuntimeWarning``.

This pin is the prevention. Following the established  allow-list shape
(``TestInverseAuditEmitterPin._RAW_WRITE_ALLOWLIST``): every ``create_task`` site
in src/ must be an EXPLICIT entry keyed on ``(relpath, enclosing_fn)`` with a
one-line justification of HOW the task is tracked (stored in a persistent set/
dict, or immediately gathered) so it cannot be GC'd. A new site that is not
allow-listed fails the pin, forcing a conscious "how is this tracked?" decision +
reviewer check. Built on the shared ``_pin_harness`` (PD#6 — no hand-rolled walk);
the allow-list is census'd for stale entries (PD#7).

Why an allow-list and not an AST "is it tracked?" check: proving a task is stored
into a PERSISTENT container needs cross-statement dataflow (fragile), and the
 bug was a task assigned to a LOCAL that was never persisted — a "result is
discarded" (bare-Expr) check alone would miss it. A justified allow-list is the
interprocedural, low-false-positive shape the project already uses for raw audit
writes.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    walk_src,
)

# (relpath, enclosing_fn) -> how the task is tracked so it cannot be GC'd
# mid-run. VERIFIED at HEAD against each site's tracking mechanism.
_CREATE_TASK_ALLOWLIST = {
    ("web/access_audit.py", "_launch_access_write"):
        "AccessAuditMiddleware fire-and-forget audit write — the task is added "
        "to app.state._audit_pending with a discard-on-done callback (#284); "
        "punch 636 moved the launch out of dispatch into this one launch path "
        "for a completed and a cancelled request.",
    ("web/routers/ui/embedding_install.py", "embedding_install"):
        "tracked via app.state._fire_and_forget_pending (the #284 SSOT pattern).",
    ("web/routers/ui/embedding_install.py", "embedding_sideload"):
        "tracked via app.state._fire_and_forget_pending (the #284 SSOT pattern).",
    ("web/embedding_update_runner.py", "start_runtime_update"):
        "punch 569, moved here by the 2026-10-25 single-funnel change: tracked "
        "via app.state._fire_and_forget_pending (_track) with a discard-on-done "
        "callback (the #284 SSOT pattern); its coroutine (_finish) catches and "
        "audits every exception.",
    ("web/app.py", "lifespan"):
        "punch 569 boot recovery: the tombstone purge task is tracked via "
        "app.state._fire_and_forget_pending with a discard-on-done callback "
        "(the #284 SSOT pattern); purge_removal_tombstones logs its own "
        "failures and never raises for a held file.",
    ("web/embedding_update_runner.py", "schedule_tombstone_purge"):
        "tracked via app.state._fire_and_forget_pending with a discard-on-done "
        "callback (the #284 SSOT pattern); its coroutine catches and logs every "
        "exception, so a failed purge is never an unretrieved task exception.",
    ("web/task_supervisor.py", "supervise"):
        "the supervised-task SSOT itself — stored in self._tasks, the canonical "
        "tracking set the autouse drain cancels.",
    ("web/triage_runner_bulk.py", "run_triage_all"):
        "collected into the `tasks` list and immediately `await "
        "asyncio.gather(*tasks)` — held for the gather, not fire-and-forget.",
    ("web/watcher.py", "_start_imap_push"):
        "stored in self._tasks[key] (the WatcherManager per-account tracking "
        "dict).",
    ("web/routers/backup.py", "ops_db_backup_trigger"):
        "tracked via the module-level _BACKUP_BG_TASKS set + discard-on-done "
        "callback (#284 SSOT pattern — devils-advocate-flagged 2nd silent-drop).",
}


def _create_task_sites(tree: ast.AST):
    """Yield ``(enclosing_fn, lineno)`` for every ``<x>.create_task(...)`` call —
    asyncio.create_task, loop.create_task, get_event_loop().create_task, all of
    which schedule a task whose strong ref the caller must keep."""
    out = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create_task"
        ):
            out.append((enclosing_fn(node), node.lineno))
    return out


class TestCreateTaskTrackingPin:
    def test_every_create_task_site_is_allowlisted(self):
        violations = []
        for _path, rel, tree in walk_src():
            for fn, lineno in _create_task_sites(tree):
                if (rel, fn) not in _CREATE_TASK_ALLOWLIST:
                    violations.append(f"{rel}:{lineno}  create_task in {fn!r}")
        assert not violations, (
            "Un-allow-listed fire-and-forget create_task (#284 GC-leak class — a "
            "task whose strong ref is dropped can be garbage-collected mid-run, "
            "silently and with NO 'never awaited' warning):\n  "
            + "\n  ".join(violations)
            + "\n\nFIX: store the task in a persistent set/dict (e.g. "
            "app.state._fire_and_forget_pending) or await/gather it; THEN add "
            "(relpath, enclosing_fn) to _CREATE_TASK_ALLOWLIST with a one-line "
            "justification of how it is tracked (reviewer confirms)."
        )

    def test_no_stale_allowlist_entries(self):
        """PD#7 — census the censuser. Every allow-list entry must still be a
        live create_task site on HEAD; a stale entry (the site was removed/
        renamed/refactored) is flagged so it can't silently exempt a future
        same-named function."""
        live = set()
        for _path, rel, tree in walk_src():
            for fn, _lineno in _create_task_sites(tree):
                live.add((rel, fn))
        stale = set(_CREATE_TASK_ALLOWLIST) - live
        assert not stale, (
            "Stale _CREATE_TASK_ALLOWLIST entries (no longer a create_task site "
            f"on HEAD): {sorted(stale)}. Remove them."
        )

    def test_pin_has_teeth(self):
        """The detector flags a create_task call, and does NOT flag a function
        with none."""
        bad = (
            "import asyncio\n"
            "def leaker():\n"
            "    asyncio.create_task(_run())  # bare, no strong ref kept\n"
        )
        good = (
            "import asyncio\n"
            "async def fine():\n"
            "    await _run()\n"
        )
        assert_pin_has_teeth(
            lambda tree: _create_task_sites(tree), bad, good
        )
