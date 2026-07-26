"""the backlog  (Census v3 finding #2) minimal pin.

Structural: ``providers/gmail_calendar.py::respond_to_event`` MUST
reference ``canonical_email`` at least once. Under the old shape
(``(self._account or "").lower()`` + ``(a.get("email") or "").lower()``),
IDNA divergence (U-label vs A-label) or display-name-wrap divergence
caused the RSVP attendee-match equality to fail → the operator's
existing attendee row stayed ``needsAction`` while a DUPLICATE row
was PATCHed onto the event.

Peer ``providers/office365.py:172/356`` already routes account/attendee
comparisons through ``canonical_email`` per N-346 partial 3; this pin
holds the gmail sibling to the same convention.

Scope: intentionally narrow to gmail_calendar's RSVP path. The
wider providers/-tree pin (Census v3 finding #2 broader scope +
per_contact_hipaa.py:1326 cache-key sub-finding #5) is filed as a
follow-up task per feedback_dont_over_defer with a same-drive
minimal down-payment here (PD#1 SSOT ships its pin same-change).

Prime Directive #6: routes through shared ``_pin_harness``.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


_TARGET_REL = "providers/gmail_calendar.py"
_TARGET_FN = "respond_to_invite"


def _fn_body_names(tree: ast.Module) -> dict[str, set[str]]:
    """Return {funcname: set(identifier_names)} for module-scope AsyncDef/Def
    functions. Nested defs / methods on classes are picked up too via walk."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                names.add(sub.attr)
        out[node.name] = names
    return out


def test_gmail_rsvp_routes_through_canonical_email():
    path = SRC_ROOT / "providers" / "gmail_calendar.py"
    tree = parse_module(path)
    assert isinstance(tree, ast.Module), (
        f"parse_module returned no tree for {_TARGET_REL}"
    )
    fn_names = _fn_body_names(tree)
    assert _TARGET_FN in fn_names, (
        f"{_TARGET_REL}::{_TARGET_FN} not found; refactor renamed the "
        "RSVP path — update this pin's _TARGET_FN AND verify the new "
        "site references canonical_email."
    )
    assert "canonical_email" in fn_names[_TARGET_FN], (
        f"{_TARGET_REL}::{_TARGET_FN} does NOT reference "
        "``canonical_email``. Attendee-match equality on ``.lower()`` "
        "alone diverges under IDNA (U-label vs A-label) or display-"
        "name-wrap shapes → duplicate attendee row PATCHed onto the "
        "event. Route both sides through email_triage.mail_headers."
        "canonical_email per the backlog  / N-253 R25 / peer "
        "office365.py convention (N-346 partial 3)."
    )
