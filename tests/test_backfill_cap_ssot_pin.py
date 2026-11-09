"""N-414 Drive-2 close-out #3 — `web/_backfill_chip.py` bounded-backfill ceiling SSOT pin.

`web/_backfill_chip.py` declares itself the *"single source of truth for the
bounded-backfill ceiling"* at line 33-36 with the module-scope constant
`BACKFILL_CAP = 200`. The three cursor-expiry recovery sites
(`web/poll_ingestion.py`, `web/ingestion_push.py` — two sites for IMAP + Gmail)
all import THIS rather than hardcoding 200, so raising / lowering the cap
(or pinning it) happens in one place. §164.308(a)(1)(ii)(D) — bounded
retrospective ingestion is the recovery-scope safety limit.

Divergence vectors this pin locks:

  1. **A saturation record sees the cap** — a src module that records a
     SATURATED walk (a `mark_backfill_capped` call, direct or via a
     dispatcher, whose `recovered=` is anything but the literal 0) MUST
     import `BACKFILL_CAP` from the SSOT: it is asserting the walk hit a cap
     it must not hardcode. Punch 854 (2026-11-04) narrowed this from "any
     importer of mark/clear", which needed a two-entry allow-list for the
     dismiss endpoint (clear only) and the IDLE watcher (`recovered=0`).
     Neither asserts the cap, so the rule no longer reaches them and the
     allow-list is gone.

  2. **No local re-definition of the constant** — a module-scope
     `BACKFILL_CAP = <n>` outside the SSOT module would shadow the shared
     ceiling for its readers. Refuse.

Both checks are count-agnostic (walks every src file), reuse `_pin_harness`
per PD#6, rot-guarded PD#7. §3 registered in `docs/ssot-and-divergence-
playbook.md`; §4.30 register row filed.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    call_args_of,
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "web/_backfill_chip.py"
_SSOT_IMPORT_PATH = "email_triage.web._backfill_chip"
_MARK_FN = "mark_backfill_capped"


def _records_saturation(tree: ast.AST) -> bool:
    """True if the module calls ``mark_backfill_capped`` (direct or via a
    dispatcher hop) with a ``recovered=`` other than the literal 0, i.e. it
    records a walk that hit the cap."""
    for node in ast.walk(tree):
        got = call_args_of(node, _MARK_FN)
        if got is None:
            continue
        keywords = got[1]
        recovered = next((k.value for k in keywords if k.arg == "recovered"), None)
        if isinstance(recovered, ast.Constant) and recovered.value == 0:
            continue
        return True
    return False


def _module_ssot_imports(tree: ast.AST) -> set[str]:
    """Return the set of names imported from the SSOT module at ANY scope
    (module + function-local — the repo's paired helpers ARE typically
    lazy-imported inside the recovery try-block)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _SSOT_IMPORT_PATH:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _module_has_local_assign(tree: ast.AST, name: str) -> bool:
    """True if the module has a top-level assignment to ``name`` at module
    scope."""
    if not hasattr(tree, "body"):
        return False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
    return False


# ---------------------------------------------------------------------------
# Pin — paired-symbol import discipline
# ---------------------------------------------------------------------------


def test_saturation_records_import_the_cap():
    """Every src module that records a saturated walk (see
    :func:`_records_saturation`) MUST import `BACKFILL_CAP` from the SSOT.
    A saturation record without the cap constant is either hardcoding the
    cap (fork candidate) or asserting a walk limit it cannot see."""
    offenders: list[str] = []
    seen = 0
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        tree = parse_module(path)
        if tree is None or not _records_saturation(tree):
            continue
        seen += 1
        if "BACKFILL_CAP" not in _module_ssot_imports(tree):
            offenders.append(
                f"  {rel}  records a saturated walk via `{_MARK_FN}` but "
                f"does not import `BACKFILL_CAP` from `{_SSOT_IMPORT_PATH}`."
            )
    # Non-vacuous: the three cursor-expiry recovery sites record saturation.
    assert seen, "no saturation record found in src; the detector is blind"
    assert not offenders, (
        "N-414 BACKFILL_CAP drift — src file(s) record a saturated backfill "
        "walk without importing the SSOT cap constant. Import `BACKFILL_CAP` "
        f"from `{_SSOT_IMPORT_PATH}`. There is no allow-list.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Pin — no local re-definition of the constant
# ---------------------------------------------------------------------------


def test_backfill_cap_not_redefined_locally_in_src():
    """A module-scope `BACKFILL_CAP = <n>` outside the SSOT module would
    shadow the shared ceiling for that module's readers. Refuse."""
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        if _module_has_local_assign(tree, "BACKFILL_CAP"):
            offenders.append(
                f"  {rel}  module-scope assignment `BACKFILL_CAP = …` "
                "shadows the SSOT for this module's readers."
            )
    assert not offenders, (
        "N-414 BACKFILL_CAP local re-definition drift — src module(s) "
        "locally re-assign the shared ceiling constant. Import it from "
        f"`{_SSOT_IMPORT_PATH}` instead.\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Rot-guard PD#7 + teeth
# ---------------------------------------------------------------------------


def test_pin_has_teeth():
    """Planted-fake probes: (a) BACKFILL_CAP is a real module-scope int
    constant at the SSOT; (b) a saturated mark through the dispatcher seam is
    detected, a `recovered=0` reseed mark is not; (c) synthetic AST with a
    module-scope `BACKFILL_CAP = 500` is flagged by the local-assign
    detector.
    """
    # (a) SSOT still declares the constant. Otherwise every consumer's
    #     paired-import discipline is vacuously satisfied (no BACKFILL_CAP
    #     to be imported).
    tree = parse_module(SRC_ROOT / _SSOT_MODULE_REL)
    assert tree is not None
    declared = False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "BACKFILL_CAP":
                    declared = True
        if declared:
            break
    assert declared, (
        "teeth: `BACKFILL_CAP` is no longer declared at module scope in "
        "the SSOT module. Either restore it or update this pin's target."
    )

    # (b) Saturation-record detector, both ways.
    saturated = ast.parse(
        f"from {_SSOT_IMPORT_PATH} import mark_backfill_capped\n"
        "async def f(db, a):\n"
        "    await db_call(mark_backfill_capped, db, a, kind='k', window='w',\n"
        "                  recovered=200, source_mailbox='INBOX')\n"
    )
    assert _records_saturation(saturated), (
        "teeth: saturation detector missed a planted saturated mark"
    )
    assert "BACKFILL_CAP" not in _module_ssot_imports(saturated), (
        "teeth: planted probe unexpectedly imported the cap"
    )
    reseed = ast.parse(
        "async def f(db, a):\n"
        "    await db_call(mark_backfill_capped, db, a, kind='imap_uidvalidity',\n"
        "                  window='w', recovered=0, source_mailbox='INBOX')\n"
    )
    assert not _records_saturation(reseed), (
        "teeth: a recovered=0 reseed mark was read as a saturation record"
    )

    # (c) Synthetic local re-assignment — must be detected.
    fake_reassign = ast.parse("BACKFILL_CAP = 500\n")
    assert _module_has_local_assign(fake_reassign, "BACKFILL_CAP"), (
        "teeth: local-assign detector missed a planted re-assignment"
    )
