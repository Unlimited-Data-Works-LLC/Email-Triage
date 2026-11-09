"""Pin for N-474 (D1) — shipped prose may not promise a queue worker that does not exist.

WHAT THIS PINS, and why it is not a word-list pin
-------------------------------------------------
N-474: prose across the tree asserted that a style-distill queue row is re-tried
"on the next tick" by "the existing queue worker". No such worker exists at HEAD
and none ever did (``git log -S`` over the claim helper returns only its own
definition and extraction commits).

A pin that merely greps for banned phrases would be (a) vacuous the moment
someone rephrases, and (b) WRONG once a worker is actually built — the sentences
become TRUE then, and a phrase-ban would force authors to delete accurate
documentation.

So the pin asserts a CONDITIONAL invariant instead:

    IF no production caller of claim_next_style_distill_* exists,
    THEN no shipped prose may assert that a worker/tick drains the queue.

It therefore RETIRES ITSELF correctly: the day someone wires a drainer, the
antecedent goes false and the prose is free to say so. That is the property a
phrase-ban cannot have.

Count-agnostic per PD#1, and routed through ``_pin_harness`` per PD#6 (the pins
obey the SSOT rule too — the meta-pin caught the first draft hand-rolling
``ast.parse``, its own src-root spelling, and ``relative_to(...).as_posix()``).
The caller check walks every module under src rather than consulting a
hand-maintained list of "the files that matter"; the hand-built site list was
wrong three times (4 -> 6 -> 9+), and two docstrings inherit the claim by
reference while carrying none of its vocabulary.

KNOWN LIMIT — this pin is NOT a complete enumeration
----------------------------------------------------
It catches prose asserting DRAINAGE. It does NOT catch prose asserting
ENABLEMENT. Live example: ``db/style.py`` told the operator the pipeline was
unwired "until the operator both (a) flips this flag and (b) signs off" —
flipping the flag wires NOTHING, in either state. That sentence contains no
drain vocabulary at all. It is corrected by hand in the D1 edit and recorded in
the N-474 register row. A green run here means "no DRAINAGE promise remains
while no drainer exists" — never "no false promises remain".
"""
from __future__ import annotations

import ast
import re

import pytest

from _pin_harness import iter_src_files, relpath, walk_src

#: The helpers a real drain worker must call to take work off either queue.
CLAIM_HELPERS = {
    "claim_next_style_distill_queue_entry",
    "claim_next_style_distill_contact_queue_entry",
}

#: Modules that only RE-EXPORT the helpers (an import is not a call site).
RE_EXPORT_ONLY = {"web/db.py"}

#: Prose asserting automatic drainage. Deliberately broad — it only ever fires
#: while the antecedent (no worker) holds.
DRAIN_CLAIM = re.compile(
    r"(on (?:the )?next tick|next retry-?tick|retry-?tick re-?pauses|"
    r"queue worker|retry worker|existing worker|worker to drain|"
    r"worker polls|re-?fires? with the new|re-?tries with the new|"
    r"re-?checks .{0,30} on the next|eligible to resume)",
    re.I,
)

#: The claim vocabulary alone is NOT sufficient, and the first draft proved it:
#: run unanchored it flagged 28 sites, most of them ACCURATE prose about other
#: subsystems that really do have workers — ``db/_writer.py`` ("Signal the
#: worker to drain"), ``background_sweepers.py`` and ``migrations.py`` (the
#:  LLM-down retry worker), ``routers/ui/retry_queue.py``
#: (``watcher_retry_queue``, a different table with a real drainer). Banning
#: true sentences is itself a defect, so a claim only counts when it sits near
#: something naming THIS queue.
ANCHOR = re.compile(
    r"(style_distill|next_retry_at|unpause_|baa_required|scrubber_fail|"
    r"claim_next_style_distill|distill_hipaa)",
    re.I,
)
ANCHOR_WINDOW = 8

#: POLARITY. The claim vocabulary matches "no queue worker exists" exactly as
#: readily as "the existing queue worker drains it". A polarity-blind detector
#: fires on the HONEST correction and would force authors to avoid mentioning
#: the absent worker at all — the opposite of what N-474's D1 fix is for.
#: (Measured: the first run of this pin after D1 landed flagged 11 sites, every
#: one of them a correction.) So a match is skipped when its window DENIES the
#: worker's existence rather than asserting it.
DENIAL = re.compile(
    r"(no queue worker|no such worker|does not exist|do(es)? not exist|none exists|"
    r"never (has|existed|been)|nothing (drains|claims|re-?schedules)|not wired|"
    r"no production caller|no worker polls|N-474|would (re-?select|otherwise)|"
    r"could not re-?select|guard for a future|ENQUEUES only|"
    r"original intent, not the behaviour|historical wording)",
    re.I,
)
DENIAL_WINDOW = 4

#: The §164.316 register is deliberately NOT scanned. It is an append-only
#: history whose older rows legitimately describe PAST states, and its
#: convention for a claim gone false is a dated REOPEN amendment — which is what
#: PUNCH-#100 received. A pin cannot tell a historical record from a
#: present-tense promise, so it must not police one.


def _production_claim_callers() -> list[str]:
    """Every src site that CALLS a claim helper. Imports do not count."""
    hits: list[str] = []
    for _path, rel, tree in walk_src():
        if rel in RE_EXPORT_ONLY:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in CLAIM_HELPERS:
                hits.append(f"{rel}:{node.lineno}")
            # interprocedural: db_call(claim_next_..., conn) style dispatch
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in CLAIM_HELPERS:
                    hits.append(f"{rel}:{node.lineno} (via {name})")
    return sorted(set(hits))


def _prose_claim_sites() -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for path in iter_src_files():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            if not DRAIN_CLAIM.search(line):
                continue
            lo = max(0, i - 1 - ANCHOR_WINDOW)
            hi = min(len(lines), i + ANCHOR_WINDOW)
            if not any(ANCHOR.search(x) for x in lines[lo:hi]):
                continue  # a real worker elsewhere in the tree; not our class
            dlo = max(0, i - 1 - DENIAL_WINDOW)
            dhi = min(len(lines), i + DENIAL_WINDOW)
            if any(DENIAL.search(x) for x in lines[dlo:dhi]):
                continue  # prose DENYING the worker is the fix, not the defect
            out.append((relpath(path), i, line.strip()[:160]))
    return out


def test_no_prose_promises_a_drain_worker_while_none_exists() -> None:
    """A shipped sentence may not promise drainage the tree cannot perform."""
    callers = _production_claim_callers()
    if callers:
        pytest.skip(
            "A production claim-helper caller exists (%s) — a drain worker is "
            "wired, so prose describing a tick is now accurate and this pin "
            "correctly stands down. Re-verify the prose says what the worker "
            "ACTUALLY does before deleting this pin." % ", ".join(callers)
        )
    offenders = _prose_claim_sites()
    assert not offenders, (
        "N-474: %d shipped sentence(s) assert that a worker or tick drains the "
        "style-distill queue, while NO production code calls %s. Either wire a "
        "drainer (then this pin stands down by itself), or correct the prose to "
        "say what the code does: the flag is cleared and nothing re-schedules "
        "the row.\n%s"
        % (
            len(offenders),
            " / ".join(sorted(CLAIM_HELPERS)),
            "\n".join(f"  {f}:{n}  {t}" for f, n, t in offenders),
        )
    )


def test_pin_has_teeth() -> None:
    """Anti-vacuity: the detector must fire on the shape it bans.

    Without this, a regex typo silently turns the pin into a no-op that reports
    PASS forever — the failure mode this project files under
    ``pattern_an_uninvoked_control_is_indistinguishable_from_no_control``.
    """
    assert DRAIN_CLAIM.search(
        "# the retry queue re-fires with the new backend on next tick"
    ), "detector no longer matches the N-474 shape"
    assert not DRAIN_CLAIM.search("# clears the paused flag; the row is left as-is")
    # Polarity: the DENIAL filter must spare an honest correction and must NOT
    # spare the original false promise. Both directions, or the filter could be
    # widened until it swallows the defect it exists to catch.
    assert DENIAL.search("# no queue worker exists at HEAD (N-474)")
    assert not DENIAL.search(
        "# the retry queue re-fires with the new backend on the next tick"
    )


def test_claim_helper_names_still_exist() -> None:
    """The antecedent must reference real symbols.

    If a rename made CLAIM_HELPERS stale, :func:`_production_claim_callers`
    would return [] forever and the pin would look permanently armed while
    checking nothing — a vacuous-antecedent failure.
    """
    defined: set[str] = set()
    for _path, rel, tree in walk_src():
        if rel != "db/style.py":
            continue
        defined = {
            n.name
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
    missing = CLAIM_HELPERS - defined
    assert not missing, (
        "CLAIM_HELPERS names no longer defined in db/style.py: %s. This pin's "
        "antecedent is stale and it has been checking nothing." % sorted(missing)
    )
