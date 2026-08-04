"""N-414 Drive-2 close-out #3 — `web/_backfill_chip.py` bounded-backfill ceiling SSOT pin.

`web/_backfill_chip.py` declares itself the *"single source of truth for the
bounded-backfill ceiling"* at line 33-36 with the module-scope constant
`BACKFILL_CAP = 200`. The three cursor-expiry recovery sites
(`web/poll_ingestion.py`, `web/ingestion_push.py` — two sites for IMAP + Gmail)
all import THIS rather than hardcoding 200, so raising / lowering the cap
(or pinning it) happens in one place. §164.308(a)(1)(ii)(D) — bounded
retrospective ingestion is the recovery-scope safety limit.

Divergence vectors this pin locks:

  1. **Paired-symbol import discipline** — the SSOT module exposes THREE
     paired public symbols: `BACKFILL_CAP`, `mark_backfill_capped`,
     `clear_backfill_capped`. Any src consumer that references EITHER
     of the mark/clear pair without ALSO importing `BACKFILL_CAP` from the
     SSOT is a fork candidate — the recovery-loop is setting/clearing a
     capped-chip without knowing (or referencing) the cap value it's
     asserting the walk saturated at. Enforce: import routing MUST bring
     the trio together.

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
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "web/_backfill_chip.py"
_SSOT_IMPORT_PATH = "email_triage.web._backfill_chip"

# The pair of chip-lifecycle helpers whose callers MUST also see the cap.
_PAIRED_LIFECYCLE = frozenset({"mark_backfill_capped", "clear_backfill_capped"})


# Src modules ALLOWED to reference a paired-lifecycle helper WITHOUT
# importing BACKFILL_CAP. Empty on HEAD (all three real consumer files
# already import the trio together). Rot-guarded PD#7.
_PAIRED_IMPORT_ALLOW: dict[str, str] = {
    "web/routers/ui/accounts.py": (
        "operator-initiated dismiss endpoint — invokes `clear_backfill_capped` "
        "as a pure lifecycle-clear on operator action; does not walk the "
        "backfill (that lives in poll_ingestion.py + ingestion_push.py which "
        "both import BACKFILL_CAP). No cap value referenced or asserted here."
    ),
    "web/watcher.py": (
        "IDLE watcher tick-boundary orchestrator — invokes the mark/clear "
        "helpers at the IDLE lifecycle seam; the actual bounded walk that "
        "asserts against BACKFILL_CAP happens in poll_ingestion.py / "
        "ingestion_push.py which DO import the cap. No hardcoded `200` in "
        "this file (verified 2026-07-13)."
    ),
}


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


def test_paired_lifecycle_callers_also_import_the_cap():
    """Every src module that imports `mark_backfill_capped` or
    `clear_backfill_capped` from the SSOT MUST also import `BACKFILL_CAP`
    from it. A capped-chip lifecycle call without visibility to the cap
    constant means the caller is either hardcoding the cap (fork candidate)
    or asserting a saturated walk without knowing the walk's own limit —
    both are the class of drift this pin exists to catch.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        if rel in _PAIRED_IMPORT_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        imported = _module_ssot_imports(tree)
        touches_pair = bool(_PAIRED_LIFECYCLE & imported)
        if touches_pair and "BACKFILL_CAP" not in imported:
            missing = sorted(_PAIRED_LIFECYCLE & imported)
            offenders.append(
                f"  {rel}  imports {missing} from `{_SSOT_IMPORT_PATH}` "
                "but not `BACKFILL_CAP` — the recovery loop is manipulating "
                "the capped-chip lifecycle without importing the shared "
                "ceiling constant it's asserting saturation against."
            )
    assert not offenders, (
        "N-414 BACKFILL_CAP paired-import drift — src file(s) touch the "
        "backfill-cap chip lifecycle without also importing the SSOT cap "
        "constant. Import `BACKFILL_CAP` alongside `mark_backfill_capped` / "
        "`clear_backfill_capped` from the SSOT module, or add an entry to "
        "`_PAIRED_IMPORT_ALLOW` if the omission is legitimate.\n\n"
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


def test_paired_import_allow_list_has_no_stale_entries():
    """`_PAIRED_IMPORT_ALLOW` entries MUST correspond to live src modules
    that STILL import a paired lifecycle helper without the cap. A stale
    entry silently exempts a future violation under the same relpath."""
    stale: list[str] = []
    for rel in sorted(_PAIRED_IMPORT_ALLOW):
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"  {rel}  — file missing")
            continue
        tree = parse_module(path)
        if tree is None:
            stale.append(f"  {rel}  — did not parse")
            continue
        imported = _module_ssot_imports(tree)
        touches_pair = bool(_PAIRED_LIFECYCLE & imported)
        if not touches_pair or "BACKFILL_CAP" in imported:
            stale.append(
                f"  {rel}  — no longer in the paired-without-cap shape "
                "(the exemption is dead weight)."
            )
    assert not stale, (
        "N-414 rot-guard: `_PAIRED_IMPORT_ALLOW` has stale entries. Keep "
        "the allow-list honest (PD#7).\n\n" + "\n".join(stale)
    )


def test_pin_has_teeth():
    """Three planted-fake probes: (a) BACKFILL_CAP is a real module-scope
    int constant at the SSOT; (b) synthetic AST with a paired import and no
    cap import is flagged by the detector; (c) synthetic AST with a
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

    # (b) Synthetic paired-without-cap import — must be detected.
    fake_paired_only = ast.parse(
        f"from {_SSOT_IMPORT_PATH} import mark_backfill_capped\n"
    )
    fake_imports = _module_ssot_imports(fake_paired_only)
    assert bool(_PAIRED_LIFECYCLE & fake_imports), (
        "teeth: paired-lifecycle import detector missed a planted probe"
    )
    assert "BACKFILL_CAP" not in fake_imports, (
        "teeth: planted probe unexpectedly imported the cap"
    )

    # (c) Synthetic local re-assignment — must be detected.
    fake_reassign = ast.parse("BACKFILL_CAP = 500\n")
    assert _module_has_local_assign(fake_reassign, "BACKFILL_CAP"), (
        "teeth: local-assign detector missed a planted re-assignment"
    )
