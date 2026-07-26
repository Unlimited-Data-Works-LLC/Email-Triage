"""N-109 count-agnostic pin — deactivated accounts stay hidden from operational
pickers as the codebase grows.

A single perfectly-clean structural pin is HARD here (the plan said so): pickers
are heterogeneous — <select> dropdowns, checkbox lists, radio groups, a
Python-f-string dropdown (the calendar-surrogate picker), and a JSON roster
(OpenClaw GET /accounts). So this is LAYERED, and honest about its gaps (project
model: drift is MANAGED, not eliminated — never read "a pin exists" as proof of
total safety).

  Part A — NEW-PICKER TRIPWIRE (count-agnostic, the primary guard): a property
  over ALL templates — every account-selector ``<select>`` (name in
  {account_id, account_ids, selected_account_ids}) MUST live in a registered
  template whose feeder applies the active_only filter. A new account ``<select>``
  in an unregistered template turns this RED, forcing the author to filter its
  feeder + register it.

  Part B — FEEDER REGRESSION GUARD: each known picker-feeder function must still
  reference ``active_only`` or ``is_active`` (the two filter styles used). A
  regression that strips the filter from a known feeder turns this RED.

  KNOWN GAPS (documented, not hidden): the tripwire covers ``<select>`` pickers
  only. Checkbox account pickers (profile/watches.html), radio copy-from
  (account_wizard/step4.html), the Python-rendered calendar-surrogate dropdown
  (_shared.py::_render_calendar_surrogate_picker), and the OpenClaw JSON roster
  are guarded by Part B's feeder registry + the behavioural tests in
  tests/test_web/test_n109_picker_hide.py, NOT by Part A. Also (db-sme): the
  ``<select ...>`` regex stops at the first ``>``, so a future tag with a Jinja
  ``>`` (e.g. ``{% if n > 0 %}``) BEFORE its ``name=`` would slip Part A — no
  such tag exists today; this is layered defense, not a proof. And ``db.py``'s
  ``get_dashboard_getting_started`` picks a ``first_account_id`` deep-link
  default — CONSIDERED and intentionally left UNFILTERED (it also drives the
  onboarding "accounts added" count, which a deactivated account legitimately
  satisfies; a deactivated first-account merely deep-links to its own disabled
  page — not a footgun), so it is deliberately neither registered nor filtered.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    TEMPLATES_ROOT,
    iter_template_files,
    parse_module,  # N-350 R31
    relpath,
)

_SRC = SRC_ROOT
_TEMPLATES = TEMPLATES_ROOT

# Account-selector input names that denote a "pick an account to act on" control.
_PICKER_SELECT_NAMES = {"account_id", "account_ids", "selected_account_ids"}

# Templates KNOWN to carry an account-selector <select>, each fed by a filtered
# feeder (see Part B). A new account <select> NOT in this set fails Part A.
_REGISTERED_PICKER_SELECT_TEMPLATES = {
    "profile/_topic_digest_editor.html",   # _topic_editor_snapshot (carve-out)
    "profile/regulatory_clocks.html",      # _page_db_work admin_accts (is_active)
    "routes_top.html",                     # _routes_top_resolve (active_only)
    "triage/discover.html",                # _discover_page_snapshot (active_only)
    "triage/run.html",                     # _triage_page_snapshot (active_only)
}

# (relative module path, function name) — picker feeders that MUST keep the
# active_only / is_active filter. A regression that drops it fails Part B.
_PICKER_FEEDERS = [
    ("web/routers/ui/categories.py", "edit_rule_form"),
    ("web/routers/ui/routes.py", "_routes_top_resolve"),
    ("web/routers/ui/wizard.py", "_wizard_step4_snapshot"),
    ("web/routers/agent_api.py", "_accounts_snapshot"),
    ("web/routers/ui/_shared.py", "_should_skip_step4"),
    ("web/routers/ui/_shared.py", "_render_calendar_surrogate_picker"),
    ("web/routers/ui/_shared.py", "_triage_page_snapshot"),
    ("web/routers/ui/_shared.py", "_discover_page_snapshot"),
    ("web/routers/ui/profile.py", "_profile_watches_user_accounts"),
    ("web/routers/ui/profile.py", "_topic_editor_snapshot"),
    ("web/routers/ui/profile.py", "_page_db_work"),  # regulatory-clocks (is_active)
]

_SELECT_TAG_RE = re.compile(r"<select\b[^>]*?>", re.IGNORECASE | re.DOTALL)
_NAME_RE = re.compile(r'name="([^"]+)"')


def _templates_with_account_select() -> set[str]:
    found: set[str] = set()
    for p in iter_template_files():
        txt = p.read_text(encoding="utf-8")
        for tag in _SELECT_TAG_RE.findall(txt):
            m = _NAME_RE.search(tag)
            if m and m.group(1) in _PICKER_SELECT_NAMES:
                found.add(relpath(p, base=TEMPLATES_ROOT))
    return found


def test_new_account_select_picker_is_registered_and_filtered():
    """Part A — every account-selector <select> lives in a registered template
    (whose feeder filters deactivated accounts). A new unregistered one fails,
    forcing the author to wire active_only + register the template."""
    found = _templates_with_account_select()
    unregistered = found - _REGISTERED_PICKER_SELECT_TEMPLATES
    assert not unregistered, (
        "NEW account-selector <select> picker(s) found in unregistered "
        f"template(s): {sorted(unregistered)}. Filter their feeder with "
        "active_only=True (or an is_active guard) and add the template to "
        "_REGISTERED_PICKER_SELECT_TEMPLATES."
    )
    # Keep the registry honest — a template that lost its <select> shouldn't
    # linger as a registered picker.
    stale = _REGISTERED_PICKER_SELECT_TEMPLATES - found
    assert not stale, (
        f"registered picker template(s) no longer contain an account <select>: "
        f"{sorted(stale)} — drop them from the registry."
    )


def test_picker_feeders_keep_the_active_only_filter():
    """Part B — each known picker-feeder function still references active_only or
    is_active. A regression that strips the filter turns this RED."""
    missing: list[str] = []
    for rel, fname in _PICKER_FEEDERS:
        path = _SRC / rel
        tree = parse_module(path); assert tree is not None  # N-350 R31
        src_lines = path.read_text(encoding="utf-8").splitlines()
        ok = False
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == fname
            ):
                seg = "\n".join(
                    src_lines[node.lineno - 1 : (node.end_lineno or node.lineno)]
                )
                if "active_only=True" in seg or "is_active" in seg:
                    ok = True
                    break
        if not ok:
            missing.append(f"src/email_triage/{rel}::{fname}")
    assert not missing, (
        "picker feeder(s) no longer apply the N-109 active_only/is_active "
        f"filter (deactivated accounts would reappear in the picker): {missing}"
    )
