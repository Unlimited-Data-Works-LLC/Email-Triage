"""dry_run side-effect suppression — count-agnostic structural pin (N-61).

Loop-5 divergence census: ``triage_single_message`` (web/triage_one.py) checked
``ctx.dry_run`` at only 2 of its side-effecting stages (the per-route action
loop + the  topic-match). The other side effects ran FOR REAL during a
preview: rule-driven internal labels, provider-native labels (live-mailbox
mutation), watch-fire (REAL SMTP/SMS escalation + webhook POST), the
``mark_triaged`` dedup stamp, and the IMAP ``$EmailTriaged`` keyword. So a HIPAA
"preview" paged on-call, POSTed PHI-metadata to third-party webhooks, and
mutated the mailbox.

The fix gates every side-effecting stage on ``not ctx.dry_run``. This pin is
the count-agnostic guard (``pattern_count_agnostic_structural_drift_catch``): it
walks ``triage_single_message`` and asserts EVERY call to a known side-effecting
function is dominated by a ``dry_run``-referencing ``if`` branch — so a NEW
side-effecting stage added without the gate is caught structurally.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, annotate_parents, parse_module  # N-350 R31

SRC = SRC_ROOT
_TRIAGE = SRC / "web" / "triage_one.py"

# The ACTIONS inside triage_single_message that egress / mutate the live
# mailbox and therefore must never run under a dry_run/preview ("poll-but-
# don't-ACT"). Matched whether called directly OR via ``db_call(<fn>, …)`` (the
# #239a off-loop dispatch indirection).
#
# DELIBERATELY EXCLUDED: ``mark_triaged`` — the install-INTERNAL rfc_id
# processing record. dry_run still records that it PROCESSED the message
# (coherent with the caller advancing the durable cursor on status="p" in
# dry_run too); gating it would desync the dedup from the cursor (DA MF-1).
#
# NEEDLE-LIST DRIFT (db-sme C1): this set is a hand-maintained list of the
# known action helpers. The pin enforces *gating* count-agnostically, but a
# FUTURE stage calling a NEW egress/mutation helper not named here is invisible
# until added. Re-census on any new side-effecting stage.
_SIDE_EFFECT_CALLS = frozenset({
    "fire_watches_for_message",     # REAL SMTP/SMS escalation + webhook POST
    "_apply_rule_internal_labels",  # DB label write (apply_labels_to_message)
    "_apply_rule_provider_labels",  # live-mailbox provider label apply
    "set_keywords",                 # IMAP $EmailTriaged keyword (mailbox write)
})


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _side_effect_target(node: ast.Call) -> str | None:
    """The side-effect fn this Call invokes — directly OR via ``db_call(fn,…)``."""
    name = _call_name(node)
    if name in _SIDE_EFFECT_CALLS:
        return name
    if name == "db_call" and node.args and isinstance(node.args[0], ast.Name):
        if node.args[0].id in _SIDE_EFFECT_CALLS:
            return node.args[0].id
    return None


def _test_negates_dry_run(test: ast.AST) -> bool:
    """True iff the ``if`` test contains a ``not <…>.dry_run`` — the body runs
    when dry_run is FALSE. Polarity matters (DA SF-4): a side-effect nested
    under the WRONG-polarity ``if ctx.dry_run:`` branch must NOT count as
    guarded, so we require an explicit negation, not just any dry_run mention."""
    for n in ast.walk(test):
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            for m in ast.walk(n.operand):
                if isinstance(m, ast.Attribute) and m.attr == "dry_run":
                    return True
                if isinstance(m, ast.Name) and m.id == "dry_run":
                    return True
    return False


def _funcdef(tree: ast.AST, name: str):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _unguarded_side_effects(fn: ast.AST) -> list[str]:
    annotate_parents(fn)
    offenders: list[str] = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        target = _side_effect_target(n)
        if target is None:
            continue
        cur = getattr(n, "_ph_parent", None)
        guarded = False
        while cur is not None:
            if isinstance(cur, ast.If) and _test_negates_dry_run(cur.test):
                guarded = True
                break
            if cur is fn:
                break
            cur = getattr(cur, "_ph_parent", None)
        if not guarded:
            offenders.append(f"{target}:{n.lineno}")
    return offenders


def test_every_side_effect_in_triage_single_message_is_dry_run_gated():
    tree = parse_module(_TRIAGE); assert tree is not None  # N-350 R31
    fn = _funcdef(tree, "triage_single_message")
    assert fn is not None, "triage_single_message not found"
    offenders = _unguarded_side_effects(fn)
    assert offenders == [], (
        "side-effecting call(s) in triage_single_message NOT under a dry_run "
        f"branch: {offenders}. A preview must apply NO side effects (no labels, "
        "no watch escalations/webhooks, no mailbox keyword, no dedup stamp) — "
        "wrap the stage in `if not ctx.dry_run:` (N-61, Loop-5 census)."
    )


def test_pin_actually_inspects_the_side_effects():
    """Vacuous-pass guard: the side-effect calls must actually be PRESENT in
    triage_single_message (else the pin above passes by finding nothing)."""
    tree = parse_module(_TRIAGE); assert tree is not None  # N-350 R31
    fn = _funcdef(tree, "triage_single_message")
    found = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            t = _side_effect_target(n)
            if t:
                found.add(t)
    # All five must be present + accounted for (so the pin isn't vacuous).
    assert found == set(_SIDE_EFFECT_CALLS), (
        f"expected all side-effect calls present; found {found} "
        f"(missing {set(_SIDE_EFFECT_CALLS) - found})"
    )


def test_pin_has_teeth():
    bad = (
        "async def triage_single_message(ctx, message, msg_id):\n"
        "    if not ctx.dry_run:\n"
        "        await db_call(_apply_rule_internal_labels, ctx, m)\n"  # guarded
        "    await fire_watches_for_message(db=db)\n"                    # UNGUARDED
        "    if ctx.dry_run:\n"
        "        await ctx.provider.set_keywords(m, ['x'])\n"  # WRONG-polarity → must FLAG
    )
    fn = _funcdef(ast.parse(bad), "triage_single_message")
    offenders = _unguarded_side_effects(fn)
    # the unguarded watch-fire is flagged ...
    assert any(o.startswith("fire_watches_for_message") for o in offenders)
    # ... the genuinely not-dry_run-guarded internal-label call is NOT ...
    assert not any(o.startswith("_apply_rule_internal_labels") for o in offenders)
    # ... and the WRONG-polarity (under `if ctx.dry_run:`) set_keywords IS
    # flagged — a positive dry_run branch must not count as a guard (DA SF-4).
    assert any(o.startswith("set_keywords") for o in offenders)
