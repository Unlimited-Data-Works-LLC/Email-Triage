"""N-418 Drive-2 close-out #7 (FINAL) — `web/calendars.py` calendar-provider gate SSOT pin.

`web/calendars.py:358-370` declares `is_calendar_effectively_enabled(acct)`
the *"single source of truth for 'should this account get a calendar
provider?' across the dispatch surface (IDLE watcher, Gmail / O365 push
consumers, poll loop, manual triage_runner)."* Pre-2026-05-13 each site
called its own ad-hoc predicate — a second predicate at any dispatch
site would silently divergent per-account provisioning across the four
consumers (an account gets a Google calendar provider from the IDLE watcher
but not from the push consumer, etc.).

Divergence class this pin locks:

  **No local twin of the gate predicate** — a `def
  is_calendar_effectively_enabled(...)` outside `web/calendars.py`
  shadows the SSOT for that module's readers and silently forks the
  provisioning decision.

Reuses `_pin_harness` per PD#6. Rot-guard PD#7 on `_LOCAL_DECL_ALLOW`.
Teeth via planted-fake function.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "web/calendars.py"
_SSOT_NAME = "is_calendar_effectively_enabled"


_LOCAL_DECL_ALLOW: dict[str, str] = {}


def _module_declares_function(tree: ast.AST, name: str) -> bool:
    """N-409 Drive-4 refinement (db-sme note #3): gate on module scope only
    — a nested inner-fn same-name is NOT a competing SSOT twin."""
    from _pin_harness import module_declares_function
    return module_declares_function(tree, name, module_scope_only=True)


def test_calendar_gate_declared_only_in_ssot():
    """`is_calendar_effectively_enabled` is declared once at
    `web/calendars.py:358`. A local twin outside the SSOT silently forks
    the "should this account get a calendar provider?" decision across
    the four dispatch consumers (IDLE watcher, Gmail push, O365 push,
    poll loop) — per-account provisioning drift.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        if rel in _LOCAL_DECL_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        if _module_declares_function(tree, _SSOT_NAME):
            offenders.append(
                f"  {rel}  declares `def {_SSOT_NAME}(...)` — SSOT lives at "
                "`web/calendars.py`; local twin forks the calendar-provider "
                "provisioning decision across dispatch sites."
            )
    assert not offenders, (
        "N-418 calendar-gate local re-declaration drift — src file(s) "
        "declare a twin of the SSOT predicate. Import from "
        "`email_triage.web.calendars` instead.\n\n" + "\n".join(offenders)
    )


def test_local_decl_allow_list_has_no_stale_entries():
    stale: list[str] = []
    for rel in sorted(_LOCAL_DECL_ALLOW):
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"  {rel}  — file missing")
            continue
        tree = parse_module(path)
        if tree is None:
            stale.append(f"  {rel}  — did not parse")
            continue
        if not _module_declares_function(tree, _SSOT_NAME):
            stale.append(f"  {rel}  — no twin declaration on HEAD")
    assert not stale, (
        "N-418 rot-guard: `_LOCAL_DECL_ALLOW` has stale entries (PD#7)."
        "\n\n" + "\n".join(stale)
    )


def test_pin_has_teeth():
    tree = parse_module(SRC_ROOT / _SSOT_MODULE_REL)
    assert tree is not None
    assert _module_declares_function(tree, _SSOT_NAME), (
        f"teeth: SSOT no longer declares `{_SSOT_NAME}` — pin is "
        "vacuously silent"
    )
    fake = ast.parse(f"def {_SSOT_NAME}(acct):\n    return True\n")
    assert _module_declares_function(fake, _SSOT_NAME), (
        "teeth: function-declaration detector missed a planted twin"
    )
