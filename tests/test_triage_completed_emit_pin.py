"""Structural pin — every terminal triage-run completion emits triage.completed.

run18 census #7. The live defect: ``poll_ingestion._poll_once_imap`` wrote a
``record_triage_run`` history row for an IMAP poll but never fired the
``triage.completed`` outbound webhook, while its same-file O365-poll sibling
(``_poll_once_office365``) did. Poll-ingested triage runs silently never
notified downstream consumers (digest / notify / the  outbound webhook).

The seam is "a terminal triage-run completion emits triage.completed." This pin
keys on the seam, count-agnostically (a property over every site, not
``len(X) == N``), via two complementary rules:

R1 — DIRECT record⇒emit (Pattern A: poll / push / IDLE).
    Every function that *calls* ``record_triage_run`` for a terminal run must,
    in the SAME function, also reference an emit (``fire_triage_completed`` or
    the ``complete_triage_run`` SSOT) — unless function-allow-listed.

R2 — INTERPROCEDURAL caller⇒emit (Pattern B: the core ``run_triage`` records;
    its callers emit on the returned ``TriageRunResult``).
    ``run_triage`` itself records but defers the emit to its caller (so it is
    R1-allow-listed). To keep that hop honest, every function that *calls*
    ``run_triage`` must reference an emit — the value (the run) hops through a
    helper, so a pin keyed only on the record site would be blind by
    construction (PD#2).

The allow-list is FUNCTION-keyed ``(relpath, funcname)`` — never file-level
(run18 #2 lesson: a file-level entry masks a sibling in the same file), and the
key uses the harness ``enclosing_fn`` (innermost), so the bulk per-message
``_record_outcome`` (nested in ``_process_one_message``) is distinguishable from
its enclosing function.

Allow-listed record sites (record-without-direct-emit BY DESIGN, each with the
terminal emit proven to live elsewhere):

  * ``web/triage_runner.py::run_triage`` — Pattern B. Records the inline run and
    RETURNS a ``TriageRunResult``; the caller (manual UI / agent API) fires
    ``fire_triage_completed`` on it. R2 proves those callers emit.
  * ``web/triage_runner_bulk.py::_record_outcome`` — Pattern C. Writes ONE
    ``triage_runs`` row PER MESSAGE inside a bulk sweep; emitting per message
    would be an event storm. The bulk TERMINAL emit lives in ``run_triage_all``
    (the ``_finalise_bulk_job`` clean-done path), which routes through
    ``complete_triage_run(record=False, ...)``.

Reuses ``tests/_pin_harness`` (walk / parse / enclosing-fn) per PD#6 — no
hand-rolled scanner.
"""

from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, parse_source, relpath, walk_src

# The emit references that satisfy the invariant — the existing per-emit SSOT
# and the run18 #7 record+emit bundling SSOT.
EMIT_NAMES = frozenset({"fire_triage_completed", "complete_triage_run"})

# Record-site allow-list (R1). FUNCTION-keyed (relpath, funcname). Each entry is
# a record-without-direct-emit site that is correct BY DESIGN; the value is the
# documented reason the terminal emit lives elsewhere.
ALLOWLIST_RECORD: dict[tuple[str, str], str] = {
    ("web/triage_runner.py", "run_triage"):
        "Pattern B — records the inline run, returns TriageRunResult; the "
        "caller emits (proven by R2).",
    ("web/triage_runner_bulk.py", "_record_outcome"):
        "Pattern C — per-message triage_runs row in a bulk sweep; the bulk "
        "terminal emit is in run_triage_all's _finalise_bulk_job done path.",
}

# Caller-site allow-list (R2). Empty on HEAD: both src callers of run_triage
# (triage_classify / agent_api) emit. (The scripts/one-shot-retriage.py CLI
# caller is outside src/email_triage, so the harness src-walk never sees it.)
ALLOWLIST_CALLER: dict[tuple[str, str], str] = {}


def _refs_emit(node: ast.AST) -> bool:
    """True if AST ``node`` references an emit name — a call/load of
    ``fire_triage_completed`` / ``complete_triage_run`` (``ast.Name`` /
    ``ast.Attribute``) OR a ``from ... import`` of one (the inline sites
    late-import the emit inside the function body)."""
    if isinstance(node, ast.Name) and node.id in EMIT_NAMES:
        return True
    if isinstance(node, ast.Attribute) and node.attr in EMIT_NAMES:
        return True
    if isinstance(node, ast.ImportFrom):
        return any(a.name in EMIT_NAMES for a in node.names)
    return False


def _fn_facts(tree: ast.AST) -> dict[str, dict]:
    """For each innermost-enclosing function name in ``tree``, collect whether
    it REFERENCES ``record_triage_run``, REFERENCES ``run_triage``, and
    references an emit name. Keyed by the harness ``enclosing_fn`` (innermost),
    so a nested function is its own key (function-grain, not file-grain).

    Detection is by NAME REFERENCE (``ast.Name``), not by direct ``ast.Call`` —
    because every Pattern A record site dispatches through the threadpool as
    ``db_call(record_triage_run, ...)``, where ``record_triage_run`` is a NAME
    ARGUMENT, never the call target (PD#2: the value hops through the ``db_call``
    dispatcher, so a call-target-only pin is blind by construction). A bare
    ``from ... import record_triage_run`` is an ``ast.alias`` (not an
    ``ast.Name``), so an import alone never counts as a record site."""
    facts: dict[str, dict] = {}

    def _slot(fn: str) -> dict:
        return facts.setdefault(
            fn, {"records": False, "calls_run_triage": False, "emits": False},
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id == "record_triage_run":
                _slot(enclosing_fn(node))["records"] = True
            elif node.id == "run_triage":
                _slot(enclosing_fn(node))["calls_run_triage"] = True
        if _refs_emit(node):
            _slot(enclosing_fn(node))["emits"] = True
    return facts


def _violations_in_tree(tree: ast.AST, rel: str) -> list[str]:
    """Return human-readable violation strings for one parsed module at
    repo-relative path ``rel``. Pure (no filesystem) so the teeth tests can
    drive it with a planted source string under a synthetic relpath."""
    out: list[str] = []
    for fn, f in _fn_facts(tree).items():
        key = (rel, fn)
        if f["records"] and not f["emits"] and key not in ALLOWLIST_RECORD:
            out.append(
                f"{rel}::{fn} calls record_triage_run but never references "
                f"an emit ({' / '.join(sorted(EMIT_NAMES))}). A terminal "
                f"triage-run completion must emit triage.completed."
            )
        if (
            f["calls_run_triage"]
            and not f["emits"]
            and key not in ALLOWLIST_CALLER
        ):
            out.append(
                f"{rel}::{fn} calls run_triage but never references an emit "
                f"({' / '.join(sorted(EMIT_NAMES))}). run_triage records the "
                f"run; its caller must fire triage.completed (PD#2 seam)."
            )
    return out


def test_every_terminal_completion_emits_triage_completed():
    """No record-without-emit / run_triage-caller-without-emit across src."""
    violations: list[str] = []
    for _path, rel, tree in walk_src():
        violations.extend(_violations_in_tree(tree, rel))
    assert not violations, (
        "triage.completed emission divergence (run18 #7):\n  "
        + "\n  ".join(violations)
        + "\n\nRoute the terminal completion through "
        "events.complete_triage_run, or — for a by-design intermediate "
        "record (per-message bulk) / deferred emit (run_triage) — add a "
        "FUNCTION-keyed allow-list entry with a documented reason."
    )


# --- teeth -----------------------------------------------------------------

# A planted module mirroring the EXACT pre-fix IMAP-poll shape: records a poll
# run, never emits. Under a non-allow-listed relpath it MUST be flagged.
_BAD_RECORD = (
    "async def _poll_once_somewhere(app, acct):\n"
    "    await db_call(\n"
    "        record_triage_run, db, account_id=1, query='poll',\n"
    "        total_messages=3, results=[], errors=[], elapsed_secs=0.0,\n"
    "    )\n"
)

# The fixed shape: routes the record+emit through the SSOT.
_GOOD_RECORD = (
    "async def _poll_once_somewhere(app, acct):\n"
    "    from email_triage.web.events import complete_triage_run\n"
    "    await complete_triage_run(\n"
    "        dispatcher, db, config, acct, run_id='x', query='poll',\n"
    "        trigger='poll', total_messages=3, results=[], errors=[],\n"
    "        elapsed_secs=0.0,\n"
    "    )\n"
)

# A planted caller of run_triage that forgets to emit (Pattern B hop broken).
_BAD_CALLER = (
    "async def handle(request, db, config, acct):\n"
    "    run = await run_triage(db, config, secrets, acct, trigger='manual')\n"
    "    return run\n"
)

_GOOD_CALLER = (
    "async def handle(request, db, config, acct):\n"
    "    from email_triage.web.events import fire_triage_completed\n"
    "    run = await run_triage(db, config, secrets, acct, trigger='manual')\n"
    "    await fire_triage_completed(dispatcher, db, config, acct, run)\n"
    "    return run\n"
)


def test_pin_has_teeth_record_site():
    rel = "web/_planted_not_allowlisted.py"
    assert _violations_in_tree(parse_source(_BAD_RECORD), rel), (
        "R1 missed a record-without-emit site (no teeth)"
    )
    assert not _violations_in_tree(parse_source(_GOOD_RECORD), rel), (
        "R1 flagged a correctly-routed complete_triage_run site"
    )


def test_pin_has_teeth_caller_site():
    rel = "web/_planted_not_allowlisted.py"
    assert _violations_in_tree(parse_source(_BAD_CALLER), rel), (
        "R2 missed a run_triage caller that never emits (no teeth)"
    )
    assert not _violations_in_tree(parse_source(_GOOD_CALLER), rel), (
        "R2 flagged a run_triage caller that does emit"
    )


def test_allowlisted_record_sites_still_record():
    """Guard the allow-list against bit-rot: every allow-listed (relpath,fn)
    must still EXIST and still call record_triage_run — otherwise the entry is
    masking nothing (or has moved) and should be removed/retargeted."""
    seen: set[tuple[str, str]] = set()
    for _path, rel, tree in walk_src():
        for fn, f in _fn_facts(tree).items():
            if f["records"]:
                seen.add((rel, fn))
    stale = [k for k in ALLOWLIST_RECORD if k not in seen]
    assert not stale, (
        "ALLOWLIST_RECORD entries no longer call record_triage_run "
        f"(stale — remove or retarget): {stale}"
    )
