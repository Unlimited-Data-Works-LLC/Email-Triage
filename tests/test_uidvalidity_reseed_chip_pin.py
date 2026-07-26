"""UIDVALIDITY-reseed operator-chip pin (divergence census run18 ).

When an IMAP mailbox's UIDVALIDITY changes, the stored high-water-mark cursor is
invalidated: ``app._resolve_hwm_with_uidvalidity`` resolves ``since_uid == 0``
even though a cursor WAS stored. The unified poll path then RESEEDS the HWM to
the current latest UID (``set_mailbox_hwm(make_hwm_value(get_latest_uid(), …))``)
so it does not re-triage the whole renumbered mailbox. But that reseed advances
the cursor PAST every message that arrived in the gap WITHOUT enumerating them —
the same un-triage hazard the cursor-expiry recovery path (Gmail ``historyId``
aged out / O365 ``deltaLink`` 410-resync) already surfaces via
``mark_backfill_capped``. Before run18  the UIDVALIDITY reseed stayed SILENT,
so a renumbered mailbox lost its operator backfill notice while the sibling
cursor-expiry path raised one — a real divergence.

Count-agnostic property (a property over every reseed branch, not ``len(...)==N``):
an ``if`` branch whose GUARD is an ``and``-conjunction that contains a ``<x> == 0``
comparison — the structural signature of "the resolved cursor is zero AND [a
prior-cursor precondition held]", i.e. a mail-LOSS reseed — and whose body
reseeds via ``set_mailbox_hwm`` MUST also emit ``mark_backfill_capped`` in that
same branch.

Why the ``and``-conjunction is the discriminator (the "genuinely different
semantics" the reseed shapes carry — the verify-don't-accept call here): a BARE
``if since_uid == 0:`` is the FRESH-mailbox first-seed — there was NO prior
cursor, nothing was lost, and a chip would be operator noise. Only the conjoined
guard (``_had_stored_uid and since_uid == 0``) proves a cursor EXISTED and is now
gone → real mail-loss → chip required. Normal forward HWM advance
(``if hwm_safe_uid > since_uid:``) is a ``>`` compare, never ``== 0``, so it is
never matched. The three poll ``set_mailbox_hwm`` sites all live in the SAME
function (``_poll_once_imap``), so a function-keyed allow-list could not separate
them — the guard SHAPE is what carries the semantic difference.

WATCHER ARM (run18 's parallel sibling — N-171, the N-170 root-cause sibling
on the IDLE path): the IMAP IDLE watcher (``web/watcher.py:_watch_account``)
reseeds to latest in the ``else`` of ``if hwm_uid:`` — a branch that CONFLATES
first-watch (no prior cursor, no loss) with a UIDVALIDITY change (prior cursor,
loss), so it cannot be proven a mail-loss reseed from its GUARD alone (no
``== 0`` conjunction). N-171 plumbs the loss-signal the poll path already
carries: ``_had_stored_uid = bool(int((_hwm_data or {}).get("uid", 0)))`` read
from the STORED row before ``_resolve_hwm_with_uidvalidity`` collapses it to 0.
The watcher then chips ``mark_backfill_capped`` in the reseed branch ONLY under
``if _had_stored_uid:`` — a renumber chips, a first-watch does not.

Because the watcher's discriminator is a NAME (``_had_stored_uid``) not a guard
SHAPE, the poll arm's ``and``-``== 0`` signature cannot see it. So the watcher is
pinned by a SECOND, function-keyed arm (:func:`_loss_signal_reseed_missing_chip`):
any function that BOTH reseeds (``set_mailbox_hwm``) AND derives the
``_had_stored_uid`` loss-signal MUST contain an ``if`` whose test references
``_had_stored_uid`` and whose body emits ``mark_backfill_capped`` — i.e. the chip
is GATED on the loss-signal. That arm has teeth in BOTH directions: a loss-aware
reseed with no chip (or with an UNGUARDED chip that would false-chip first-watch)
→ RED; the gated chip → GREEN; a pure first-watch seeder that never derives
``_had_stored_uid`` → not required to chip (no false positive). Both arms walk all
of ``src`` (count-agnostic) and resolve ``db_call(fn, …)`` interprocedurally via
:func:`_name_referenced`. The real poll function ``_poll_once_imap`` satisfies the
watcher arm too (its ``if _had_stored_uid and since_uid == 0:`` is a gated chip),
so the two arms don't double-jeopardy a correct site.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    enclosing_fn, iter_src_files, parse_module, parse_source, relpath,
)

_RESEED = "set_mailbox_hwm"
_CHIP = "mark_backfill_capped"
# The watcher's mail-loss discriminator — a stored cursor that resolved to 0
# (a renumber) vs no stored cursor (a first watch). Keyed by NAME because the
# watcher's reseed lives in the ``else`` of ``if hwm_uid:`` and so carries no
# ``and``-``== 0`` guard shape for the poll arm to match.
_LOSS_SIGNAL = "_had_stored_uid"

# Function-keyed escape hatch for a FUTURE and-guarded ``== 0`` reseed that
# legitimately loses no mail (start EMPTY — there is none today). Mirrors the
# keep-raw allow-list idiom of test_inflight_claim_no_await_gap_pin.py.
_RESEED_CHIP_ALLOW: set[tuple[str, str]] = set()


def _name_referenced(node: ast.AST, target: str) -> bool:
    """True if ``target`` appears as a bare ``ast.Name`` reference anywhere in
    ``node`` — covers BOTH a direct ``target(...)`` call and the
    ``db_call(target, …)`` off-loop dispatch the real code uses. An ``import``
    alias is an ``ast.alias`` (not an ``ast.Name``), so a ``from … import
    mark_backfill_capped`` inside the branch does NOT falsely satisfy the chip
    requirement — only a genuine reference does."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id == target:
            return True
    return False


def _is_loss_reseed_guard(test: ast.AST) -> bool:
    """True when ``test`` is an ``and``-conjunction (``ast.BoolOp`` / ``ast.And``)
    that includes a ``<x> == 0`` comparison — the mail-LOSS reseed signature
    (resolved cursor is zero AND a prior-cursor precondition). A bare ``== 0``
    Compare (fresh-mailbox seed) is deliberately NOT matched."""
    if not (isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And)):
        return False
    for v in test.values:
        if (isinstance(v, ast.Compare)
                and len(v.ops) == 1 and isinstance(v.ops[0], ast.Eq)
                and len(v.comparators) == 1
                and isinstance(v.comparators[0], ast.Constant)
                and v.comparators[0].value == 0):
            return True
    return False


def _reseed_branches_missing_chip(tree: ast.AST, rel: str) -> list[str]:
    """``relpath:enclosing_fn:lineno`` for every mail-loss reseed branch (per
    :func:`_is_loss_reseed_guard`) whose THEN body reseeds via ``set_mailbox_hwm``
    but does NOT pair it with ``mark_backfill_capped`` (and is not allow-listed)."""
    out: list[str] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.If) and _is_loss_reseed_guard(n.test)):
            continue
        # The guard qualifies the THEN block — that is where the reseed lives.
        if not any(_name_referenced(s, _RESEED) for s in n.body):
            continue
        if any(_name_referenced(s, _CHIP) for s in n.body):
            continue
        fn = enclosing_fn(n)
        if (rel, fn) in _RESEED_CHIP_ALLOW:
            continue
        out.append(f"{rel}:{fn}:{n.lineno}")
    return out


def _has_loss_gated_chip(fn: ast.AST) -> bool:
    """True if ``fn`` contains an ``if`` whose TEST references the
    ``_had_stored_uid`` loss-signal and whose BODY references
    ``mark_backfill_capped`` — i.e. the chip is GATED on the loss-signal. This
    is precisely the watcher's correct shape (``if _had_stored_uid: … chip``):
    it rejects BOTH a missing chip AND an UNGUARDED chip (one that would
    false-chip a first-watch seed)."""
    for n in ast.walk(fn):
        if (isinstance(n, ast.If)
                and _name_referenced(n.test, _LOSS_SIGNAL)
                and any(_name_referenced(s, _CHIP) for s in n.body)):
            return True
    return False


def _loss_signal_reseed_missing_chip(tree: ast.AST, rel: str) -> list[str]:
    """``relpath:funcname`` for every function that BOTH reseeds via
    ``set_mailbox_hwm`` AND derives the ``_had_stored_uid`` loss-signal, yet does
    NOT gate a ``mark_backfill_capped`` chip on that signal (per
    :func:`_has_loss_gated_chip`). The WATCHER arm: it keys on the loss-signal
    NAME because the watcher reseed has no ``and``-``== 0`` guard shape. A pure
    first-watch seeder (reseeds but never derives ``_had_stored_uid``) is NOT a
    loss site and is deliberately not required to chip — no false positive."""
    out: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not (_name_referenced(fn, _RESEED) and _name_referenced(fn, _LOSS_SIGNAL)):
            continue
        if (rel, fn.name) in _RESEED_CHIP_ALLOW:
            continue
        if _has_loss_gated_chip(fn):
            continue
        out.append(f"{rel}:{fn.name}")
    return out


def test_every_uidvalidity_reseed_emits_backfill_chip():
    offenders: list[str] = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders.extend(_reseed_branches_missing_chip(tree, relpath(p)))
    assert not offenders, (
        "A UIDVALIDITY-change reseed advances the HWM past un-enumerated mail "
        f"with NO operator backfill chip (run18 ): {offenders}. Emit "
        "mark_backfill_capped(..., kind='imap_uidvalidity', recovered=0) in the "
        "same branch as the set_mailbox_hwm reseed, matching the cursor-expiry "
        "recovery path — else a renumbered mailbox loses real mail with no signal."
    )


def test_pin_has_teeth():
    # and-guarded ==0 reseed with NO chip → flagged.
    bad = (
        "async def _poll_once_imap(db, a, mb, v):\n"
        "    if _had_stored_uid and since_uid == 0:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
        "        return\n"
    )
    assert _reseed_branches_missing_chip(parse_source(bad), "web/x.py"), (
        "missed an and-guarded ==0 reseed with no backfill chip"
    )
    # The real shape: reseed AND chip in the same branch → not flagged.
    good = (
        "async def _poll_once_imap(db, a, mb, v):\n"
        "    if _had_stored_uid and since_uid == 0:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
        "        from email_triage.web._backfill_chip import mark_backfill_capped\n"
        "        await db_call(mark_backfill_capped, db, a, kind='imap_uidvalidity')\n"
        "        return\n"
    )
    assert not _reseed_branches_missing_chip(parse_source(good), "web/x.py"), (
        "false-positived a reseed branch that DOES emit the chip"
    )
    # Bare ==0 fresh-mailbox seed (no prior cursor → no loss) → not flagged.
    fresh = (
        "async def _poll_once_imap(db, a, mb, v):\n"
        "    if since_uid == 0:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
    )
    assert not _reseed_branches_missing_chip(parse_source(fresh), "web/x.py"), (
        "false-positived a bare ==0 fresh-mailbox seed (no prior cursor, no loss)"
    )
    # Normal forward HWM advance (`>` compare, not ==0) → not flagged.
    advance = (
        "async def _poll_once_imap(db, a, mb, v):\n"
        "    if hwm_safe_uid > since_uid:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
    )
    assert not _reseed_branches_missing_chip(parse_source(advance), "web/x.py"), (
        "false-positived a normal forward HWM advance"
    )


def test_watcher_loss_reseed_emits_backfill_chip():
    """WATCHER arm (N-171): the IDLE watcher's renumber reseed must chip too."""
    offenders: list[str] = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders.extend(_loss_signal_reseed_missing_chip(tree, relpath(p)))
    assert not offenders, (
        "A function reseeds the HWM (set_mailbox_hwm) and derives the "
        "_had_stored_uid loss-signal but does NOT gate a mark_backfill_capped "
        f"chip on it (N-171): {offenders}. A renumber (prior cursor → resolved 0) "
        "advances the cursor past un-enumerated mail with no operator signal "
        "where the poll path chips. Emit mark_backfill_capped(..., "
        "kind='imap_uidvalidity', recovered=0) under `if _had_stored_uid:` in the "
        "reseed branch — gated so a first-watch seed (no prior cursor) doesn't "
        "false-chip."
    )


def test_watcher_pin_has_teeth():
    # Loss-aware reseed (derives _had_stored_uid) with NO chip → flagged.
    bad = (
        "async def _watch_account(db, a, mb, hwm):\n"
        "    _had_stored_uid = bool(int((hwm or {}).get('uid', 0)))\n"
        "    if not hwm_uid:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
    )
    assert _loss_signal_reseed_missing_chip(parse_source(bad), "web/watcher.py"), (
        "missed a loss-aware watcher reseed with no backfill chip"
    )
    # The real watcher shape: reseed + chip GATED on _had_stored_uid → not flagged.
    good = (
        "async def _watch_account(db, a, mb, hwm):\n"
        "    _had_stored_uid = bool(int((hwm or {}).get('uid', 0)))\n"
        "    if not hwm_uid:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
        "        if _had_stored_uid:\n"
        "            from email_triage.web._backfill_chip import mark_backfill_capped\n"
        "            await db_call(mark_backfill_capped, db, a, kind='imap_uidvalidity')\n"
    )
    assert not _loss_signal_reseed_missing_chip(parse_source(good), "web/watcher.py"), (
        "false-positived a watcher reseed that DOES gate the chip on the loss-signal"
    )
    # UNGUARDED chip — present but NOT under `if _had_stored_uid:` → flagged
    # (an unconditional chip would false-chip every first-watch seed).
    unguarded = (
        "async def _watch_account(db, a, mb, hwm):\n"
        "    _had_stored_uid = bool(int((hwm or {}).get('uid', 0)))\n"
        "    if not hwm_uid:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
        "        from email_triage.web._backfill_chip import mark_backfill_capped\n"
        "        await db_call(mark_backfill_capped, db, a, kind='imap_uidvalidity')\n"
    )
    assert _loss_signal_reseed_missing_chip(parse_source(unguarded), "web/watcher.py"), (
        "missed an UNGUARDED chip (would false-chip a first-watch seed)"
    )
    # Pure first-watch seeder — reseeds but never derives _had_stored_uid → not a
    # loss site, not required to chip (no false positive).
    fresh = (
        "async def _watch_account(db, a, mb):\n"
        "    if not hwm_uid:\n"
        "        await db_call(set_mailbox_hwm, db, a, mb, v)\n"
    )
    assert not _loss_signal_reseed_missing_chip(parse_source(fresh), "web/watcher.py"), (
        "false-positived a pure first-watch seeder (no _had_stored_uid, no loss)"
    )
