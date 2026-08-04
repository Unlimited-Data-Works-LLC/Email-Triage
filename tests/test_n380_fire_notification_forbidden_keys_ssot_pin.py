"""N-380 R32 structural pin — `fire_notification` `_FORBIDDEN_KEYS` SSOT
completeness (2026-07-09).

the backlog  (Phase-4 digest_notification MED, workflow wf_1dcde854):
`web/events.py::fire_notification._FORBIDDEN_KEYS` previously covered
the mail-header shape (`sender/subject/body/snippet/from/to/cc/bcc/
message_id/thread_id`) but omitted 5 generic content-carrying keys
(`text/html/content/message/preview`). A future caller shape naming one
of the 5 generic keys with a PHI value would slip past the
unconditional refusal path — §164.312(b) audit-of-record NOT fired
on that class.  No live offender at HEAD, but the SSOT completeness
gap is defense-in-depth per PD #1.

WHAT IT PINS (count-agnostic + structural):

The `_FORBIDDEN_KEYS` set literal inside
``web/events.py::fire_notification`` MUST contain the following
required-superset (both mail-header AND generic-content classes):

  - Mail-header: `sender`, `subject`, `body`, `snippet`, `from`, `to`,
    `cc`, `bcc`, `message_id`, `thread_id`.
  - Generic content-carrying: `text`, `html`, `content`, `message`,
    `preview`.

A future set-shrink (removing any key) OR a NEW key on the ambient
notification-payload contract without a redaction-map review is the
CIDI-drift class the pin catches.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath


_REQUIRED_FORBIDDEN_KEYS = frozenset({
    # Mail-header shape.
    "sender", "subject", "body", "snippet", "from", "to",
    "cc", "bcc", "message_id", "thread_id",
    # Generic content-carrying shape (N-380 R32 initial widen).
    "text", "html", "content", "message", "preview",
    # DA fold N-380 Attack A (2026-07-09) — attachment-family + raw
    # (highest-severity medical-scope omissions).
    "attachment", "attachments", "raw",
})


def _find_events_py():
    """Locate ``src/email_triage/web/events.py`` via a direct
    SRC_ROOT-relative lookup — the canonical route per PD #6.

    N-382 R32: the prior implementation had a doubled-package-root bug
    (``SRC_ROOT / "email_triage" / "web" / "events.py"``, but SRC_ROOT
    IS ``src/email_triage`` — the check silently missed and fell
    through to a fragile rglob-first-hit fallback that could resolve
    to a fixture events.py under any web/ dir). Fix: correct path +
    remove the fallback so a real absence fails LOUD.
    """
    canonical = SRC_ROOT / "web" / "events.py"
    return canonical if canonical.exists() else None


def _extract_forbidden_keys_literal(tree: ast.AST) -> set[str] | None:
    """Walk into ``fire_notification`` + return the ``_FORBIDDEN_KEYS``
    set literal as a python set of strings.  Returns None if the
    function is missing OR the variable is not a set-of-string-literals
    assignment (anti-vacuity: a future refactor that binds it to a
    computed value would fail the pin loudly here)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if node.name != "fire_notification":
            continue
        # Function found.  Walk its body for `_FORBIDDEN_KEYS = {...}`.
        for stmt in ast.walk(node):
            if not isinstance(stmt, ast.Assign):
                continue
            if len(stmt.targets) != 1:
                continue
            tgt = stmt.targets[0]
            if not (isinstance(tgt, ast.Name) and tgt.id == "_FORBIDDEN_KEYS"):
                continue
            if not isinstance(stmt.value, ast.Set):
                return None
            keys: set[str] = set()
            for elt in stmt.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    keys.add(elt.value)
                else:
                    return None
            return keys
    return None


def test_forbidden_keys_covers_required_superset():
    """`_FORBIDDEN_KEYS` MUST cover the required mail-header + generic
    content-carrying superset — a future set-shrink fails the pin.
    """
    target = _find_events_py()
    assert target is not None, (
        "N-380 pin harness: could not locate src/email_triage/web/events.py"
    )
    tree = parse_module(target)
    assert tree is not None, (
        f"N-380 pin: web/events.py failed to parse ({target})"
    )
    keys = _extract_forbidden_keys_literal(tree)
    assert keys is not None, (
        "N-380 pin: `_FORBIDDEN_KEYS` inside `fire_notification` MUST be "
        "a set-of-string-literals assignment — a computed value would "
        "let a runtime-drift shrink the set silently."
    )
    missing = _REQUIRED_FORBIDDEN_KEYS - keys
    assert not missing, (
        f"N-380 R32 SSOT completeness: `_FORBIDDEN_KEYS` inside "
        f"`web/events.py::fire_notification` is MISSING required keys "
        f"{sorted(missing)}. Both the mail-header shape "
        f"(sender/subject/body/snippet/from/to/cc/bcc/message_id/"
        f"thread_id) AND the generic content-carrying shape "
        f"(text/html/content/message/preview) MUST be refused per PD #1 "
        f"defense-in-depth. \n\n"
        f"Currently present: {sorted(keys)}\n"
        f"Required superset: {sorted(_REQUIRED_FORBIDDEN_KEYS)}"
    )


def test_fire_notification_exists_at_expected_seam():
    """Anti-vacuity: `fire_notification` MUST exist in
    ``web/events.py`` — a missing symbol means the SSOT was renamed
    and the pin above is vacuous.
    """
    target = _find_events_py()
    assert target is not None, (
        "N-380 anti-vacuity: could not locate web/events.py"
    )
    tree = parse_module(target)
    fn_names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    }
    assert "fire_notification" in fn_names, (
        "N-380 anti-vacuity: `fire_notification` MUST exist in "
        "web/events.py — a missing symbol means the SSOT was renamed "
        "and the required-superset pin above is vacuous."
    )
