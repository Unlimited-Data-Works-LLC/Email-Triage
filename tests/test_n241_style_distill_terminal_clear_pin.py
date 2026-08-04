"""N-241 R24 structural pin — style_distill terminal-clear (2026-07-03).

Census R24 discovered HIGH class (style_distill_queue terminal-clear):
`distill_hipaa_account` had 7 return-paths — 4 short-circuit gates
(NOT_HIPAA/DISABLED/NOT_OPTED_IN/NO_MESSAGES) returned WITHOUT clearing
a pre-existing `style_distill_queue` row. Result: the retry worker
re-selected the row forever, the terminal path re-fired every poll,
and `already_queued` blocked triggered re-entry.

N-241 fix: `_audit_and_return` in `distill_hipaa.py` now calls
`clear_style_distill_queue_entry` when `result.status ∈ _TERMINAL_
OUTCOMES` (SUCCESS + NOT_HIPAA + DISABLED + NOT_OPTED_IN + NO_MESSAGES).
Transient outcomes (CADENCE_SKIP / BACKEND_FAIL / BAA_REQUIRED) each
handle their own retry/pause and intentionally do NOT clear.

WHAT IT PINS (anti-vacuity):

`_TERMINAL_OUTCOMES` must import + contain at least the 4 gate-
outcomes census flagged. `_audit_and_return` in `distill_hipaa.py`
must textually call `clear_style_distill_queue_entry` (the funnel is
in that one function; wider structural coverage is deferred).
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT, parse_module


def test_terminal_outcomes_set_covers_the_4_gate_outcomes():
    """`_TERMINAL_OUTCOMES` must include the 4 census-flagged gate
    outcomes + SUCCESS."""
    from email_triage.style_learning.distill_hipaa import (
        _TERMINAL_OUTCOMES,
        OUTCOME_DISABLED,
        OUTCOME_NO_MESSAGES,
        OUTCOME_NOT_HIPAA,
        OUTCOME_NOT_OPTED_IN,
        OUTCOME_SUCCESS,
    )
    required = {
        OUTCOME_SUCCESS,
        OUTCOME_NOT_HIPAA,
        OUTCOME_DISABLED,
        OUTCOME_NOT_OPTED_IN,
        OUTCOME_NO_MESSAGES,
    }
    missing = required - _TERMINAL_OUTCOMES
    assert not missing, (
        "N-241 R24: `_TERMINAL_OUTCOMES` is missing "
        f"{missing}. A gate outcome returning without clearing "
        "the queue re-fires the same terminal path forever."
    )


def test_audit_and_return_calls_clear_on_terminal():
    """Anti-vacuity: `_audit_and_return` textually calls
    `clear_style_distill_queue_entry`. If a refactor removes it, the
    queue-clear invariant regresses silently."""
    path = SRC_ROOT / "style_learning" / "distill_hipaa.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    # Very simple: the string must appear inside the file. A more
    # rigorous structural check would walk `_audit_and_return`'s body
    # for the call; deferred for now.
    assert "clear_style_distill_queue_entry(conn, account_id=account_id)" in source, (
        "N-241 R24: `distill_hipaa._audit_and_return` no longer clears "
        "the queue on terminal outcomes. Restore the clear or re-verify "
        "the census's terminal-clear invariant."
    )


# ---------------------------------------------------------------------------
# N-241b R31 (2026-07-07 census r24 close-out) — per-contact sibling
# ---------------------------------------------------------------------------
#
# The per-contact orchestrator has an isomorphic terminal-clear
# invariant on a distinct queue table (``style_distill_contact_queue``,
# keyed on ``(account_id, recipient_hash)``). Same shape as the account-
# scope sibling; anti-vacuity teeth mirror the sibling's.


def test_per_contact_terminal_outcomes_set_covers_the_4_gate_outcomes():
    """`_TERMINAL_OUTCOMES_PER_CONTACT` must include the same 5 census-
    flagged outcomes as the sibling. Kept as a separate frozenset (per
    the sibling comment) so a future per-contact-only extension can
    diverge without widening the sibling."""
    from email_triage.style_learning.per_contact_hipaa import (
        _TERMINAL_OUTCOMES_PER_CONTACT,
        OUTCOME_DISABLED,
        OUTCOME_NO_MESSAGES,
        OUTCOME_NOT_HIPAA,
        OUTCOME_NOT_OPTED_IN,
        OUTCOME_SUCCESS,
    )
    required = {
        OUTCOME_SUCCESS,
        OUTCOME_NOT_HIPAA,
        OUTCOME_DISABLED,
        OUTCOME_NOT_OPTED_IN,
        OUTCOME_NO_MESSAGES,
    }
    missing = required - _TERMINAL_OUTCOMES_PER_CONTACT
    assert not missing, (
        "N-241b R31: `_TERMINAL_OUTCOMES_PER_CONTACT` is missing "
        f"{missing}. A gate outcome returning without clearing "
        "the per-contact queue re-fires the same terminal path forever."
    )


def test_audit_per_contact_calls_clear_on_terminal():
    """Anti-vacuity: `_audit_per_contact` textually calls
    `clear_style_distill_contact_queue_entry` with `recipient_hash`
    keyed off `result.recipient_hash`."""
    path = SRC_ROOT / "style_learning" / "per_contact_hipaa.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    assert "clear_style_distill_contact_queue_entry(" in source, (
        "N-241b R31: `per_contact_hipaa._audit_per_contact` no longer "
        "clears the per-contact queue on terminal outcomes. Restore the "
        "clear or re-verify the census's per-contact terminal-clear "
        "invariant."
    )
    # The clear must key on result.recipient_hash so a stale queue row
    # under a re-hashed recipient can't survive the terminal outcome.
    assert "recipient_hash=result.recipient_hash" in source, (
        "N-241b R31: `per_contact_hipaa._audit_per_contact` clear must "
        "key on `result.recipient_hash` — a fixed / literal / None hash "
        "would clear the wrong row (or none) and re-fire the terminal "
        "path forever."
    )


def test_per_contact_terminal_set_matches_sibling_at_least_at_the_5_gates():
    """Scope-parity anti-drift: the per-contact terminal set must contain
    every element the sibling's set contains. Future extensions may add
    to the per-contact set (per the sibling comment); shrinking below
    sibling parity is the drift class this test prevents."""
    from email_triage.style_learning.distill_hipaa import (
        _TERMINAL_OUTCOMES,
    )
    from email_triage.style_learning.per_contact_hipaa import (
        _TERMINAL_OUTCOMES_PER_CONTACT,
    )
    missing = _TERMINAL_OUTCOMES - _TERMINAL_OUTCOMES_PER_CONTACT
    assert not missing, (
        "N-241b R31: `_TERMINAL_OUTCOMES_PER_CONTACT` is missing outcomes "
        f"present in the sibling `_TERMINAL_OUTCOMES`: {missing}. Sibling "
        "shape parity is required — a per-contact-only widening of the "
        "sibling's terminal set is fine, but a shrink is a drift defect."
    )


def test_per_contact_result_empty_hash_never_paired_with_terminal_status():
    """N-241b R31 F2 (DA fix): the ``recipient_hash=""`` sentinel is only
    valid on defensive early-fail paths that set a NON-terminal status
    (BACKEND_FAIL — its retry queue owns re-fire, so the empty-hash guard
    in ``_audit_per_contact`` is a defensive no-op, not the correctness
    barrier). This pin prevents a future refactor from constructing a
    ``PerContactDistillResult(recipient_hash="", status=<terminal>)`` —
    which would slip past the empty-hash guard and leak a queue row.

    Walks the file's AST for every ``PerContactDistillResult(...)`` call
    that passes an empty string literal for ``recipient_hash``; asserts
    each such call's ``status`` keyword resolves to a NON-terminal
    OUTCOME_* name (``OUTCOME_BACKEND_FAIL`` at HEAD)."""
    import ast

    from email_triage.style_learning.per_contact_hipaa import (
        _TERMINAL_OUTCOMES_PER_CONTACT,
    )
    # Terminal outcome NAMES (identifier strings), for AST comparison.
    terminal_names = {
        "OUTCOME_SUCCESS",
        "OUTCOME_NOT_HIPAA",
        "OUTCOME_DISABLED",
        "OUTCOME_NOT_OPTED_IN",
        "OUTCOME_NO_MESSAGES",
    }
    # Sanity: the runtime set and the name-set stay in sync.
    from email_triage.style_learning import per_contact_hipaa as _pc
    assert {
        getattr(_pc, n) for n in terminal_names
    } == _TERMINAL_OUTCOMES_PER_CONTACT, (
        "N-241b R31 pin drift: `terminal_names` in this pin no longer "
        "matches the runtime `_TERMINAL_OUTCOMES_PER_CONTACT` set. Sync "
        "the pin's identifier list."
    )

    path = SRC_ROOT / "style_learning" / "per_contact_hipaa.py"
    # N-224 R22 / N-251 R25 harness contract #3 — route through the
    # shared harness's `parse_module` so a syntax-error / io-error in
    # the target file doesn't abort the walk with a bare `ast.parse`.
    tree = parse_module(path)
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # PerContactDistillResult(...) construction.
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "PerContactDistillResult"
        ):
            continue
        # Collect kwargs by name.
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        rh = kwargs.get("recipient_hash")
        st = kwargs.get("status")
        # Only care about calls that pass an empty-string literal for
        # recipient_hash — that's the sentinel path.
        if not (
            isinstance(rh, ast.Constant)
            and isinstance(rh.value, str)
            and rh.value == ""
        ):
            continue
        # The status must resolve to a NON-terminal OUTCOME_* name.
        if isinstance(st, ast.Name) and st.id in terminal_names:
            offenders.append((node.lineno, st.id))
    assert not offenders, (
        "N-241b R31 F2: `PerContactDistillResult(recipient_hash=\"\", "
        "status=<terminal>)` constructed at these sites — the empty-hash "
        "sentinel is reserved for BACKEND_FAIL (retry queue owns re-fire) "
        "and NEVER a terminal outcome. A terminal + empty-hash pairing "
        "leaks a queued row past the terminal-clear guard, defeating "
        "N-241b.\n\n"
        + "\n".join(f"  per_contact_hipaa.py:{ln} status={s}" for ln, s in offenders)
    )
