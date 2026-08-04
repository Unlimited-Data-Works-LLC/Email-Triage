"""N-263d R28 structural pin — Gmail watch liveness SSOT.

Census r27 discovered row 13 (Gmail watch liveness triplicated):
`topic_name + expires_at > now` liveness idiom spread across 5 hand-
roll sites. N-263d lands `web.gmail_watch_status.is_gmail_watch_live`
SSOT + adopts at 2 clean hand-roll sites in `_shared.py`.

WHAT IT PINS (count-agnostic, growth-cap ratchet)

Any function containing BOTH a `topic_name` read AND an
`expires_at`-derived datetime comparison against `datetime.now(...)`
must be either:

* Routed through `is_gmail_watch_live`, or
* Allow-listed with an in-source rationale.

Baseline captures the 4 legitimately-exempt sites at N-263d landing.
Any new site fires the ratchet — either adopt the SSOT or explicit
allow-list.

The pin uses the shared `_pin_harness.parse_module` +
`enclosing_qualified_name` for the walk (meta-pin adoption per
Prime Directive #6).
"""
from __future__ import annotations

import ast

from _pin_harness import (
    enclosing_qualified_name,
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
)


# Legitimately-exempt sites at N-263d landing.
#
#   (relpath, enclosing qualified fn)
#
# Each entry has a documented rationale in
# `web/gmail_watch_status.py`'s module docstring under "Sites explicitly
# OUT-OF-SSOT (allow-listed) and why". Do not add here without also
# adding the rationale there.
_ALLOWLIST: frozenset[tuple[str, str]] = frozenset({
    # topic-only by design (operator intent, not liveness)
    ("providers/dispatcher.py", "_gmail_infer_push_enabled"),
    # trichotomy (healthy / transient-grace / expired) — bool doesn't fit
    ("web/watcher.py", "_gmail_status"),
    # mirrors watcher trichotomy with poll-fallback awareness
    ("web/routers/health.py", "_gmail_watch_counts"),
    # UI hours-until-expiry math + 5-bucket status label; different shape
    ("web/routers/integrations.py", "_hours_until"),
    ("web/routers/integrations.py", "_watch_status"),
})


def _reads_topic_name(fn_node: ast.AST) -> bool:
    """Detect a `topic_name` read within the function body. Covers:

    * ``<expr>.get("topic_name", ...)`` (dict-shaped)
    * ``<expr>["topic_name"]`` (subscript)
    * ``row_get(<row>, "topic_name", ...)`` — the ``db._helpers.row_get``
      SSOT idiom used on ``sqlite3.Row`` / ``sqlcipher3.Row`` shapes
      (db-sme + devils-advocate N-263d panel: the earlier version's
      dict-only detection was blind to this — a new liveness site
      written with ``row_get`` evades the ratchet by construction).
    """
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call):
            f = node.func
            # <expr>.get("topic_name", ...)
            if isinstance(f, ast.Attribute) and f.attr == "get" and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and a0.value == "topic_name":
                    return True
            # row_get(<row>, "topic_name", ...)
            if isinstance(f, ast.Name) and f.id == "row_get" and len(node.args) >= 2:
                a1 = node.args[1]
                if isinstance(a1, ast.Constant) and a1.value == "topic_name":
                    return True
        if isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant) and sl.value == "topic_name":
                return True
    return False


def _has_expires_at_comparison_against_now(fn_node: ast.AST) -> bool:
    """Detect a comparison whose subtree references BOTH ``expires_at``
    (via `.get("expires_at")` or `["expires_at"]`) AND a `datetime.now`
    call — the canonical liveness idiom."""
    # Collect all names/constants seen inside the fn (a broader net
    # than trying to structurally match a specific expression tree —
    # the goal is coverage of the idiom class, not a specific form).
    saw_expires_at_read = False
    saw_now_call = False
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Constant) and node.value == "expires_at":
            # Only count as a read if parent is (a) `.get("expires_at",..)`,
            # (b) `[..]["expires_at"]` subscript slice, or (c) the 2nd
            # positional arg of a `row_get(row, "expires_at", ...)` call
            # — the db._helpers.row_get SSOT idiom (db-sme + DA panel
            # N-263d must-fix — plain dict-only detection was blind).
            # Otherwise it's likely a SQL literal.
            parent = getattr(node, "_ph_parent", None)
            if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute):
                if parent.func.attr == "get":
                    saw_expires_at_read = True
            elif isinstance(parent, ast.Subscript):
                saw_expires_at_read = True
            elif isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name):
                if (parent.func.id == "row_get" and len(parent.args) >= 2
                        and parent.args[1] is node):
                    saw_expires_at_read = True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "now":
                # datetime.now(...) shape.
                saw_now_call = True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "now":
                saw_now_call = True
    return saw_expires_at_read and saw_now_call


def _calls_ssot(fn_node: ast.AST) -> bool:
    for node in ast.walk(fn_node):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = None
        if isinstance(f, ast.Name):
            name = f.id
        elif isinstance(f, ast.Attribute):
            name = f.attr
        if name == "is_gmail_watch_live":
            return True
    return False


def test_gmail_watch_liveness_ssot_adoption():
    """Every function that reads `topic_name` AND does an
    `expires_at`-vs-now comparison must call `is_gmail_watch_live` OR
    be allow-listed with an in-source rationale."""
    offenders: list[tuple[str, str, int]] = []
    for path in iter_src_files():
        rel = relpath(path)
        # Skip the SSOT + tests
        if rel == "web/gmail_watch_status.py":
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _reads_topic_name(node):
                continue
            if not _has_expires_at_comparison_against_now(node):
                continue
            qname = _own_qualified_name(node)
            if (rel, qname) in _ALLOWLIST:
                continue
            if _calls_ssot(node):
                continue
            offenders.append((rel, qname, node.lineno))
    assert not offenders, (
        "N-263d R28: functions that combine a `topic_name` read AND an "
        "`expires_at`-vs-`datetime.now(...)` comparison MUST call "
        "`web.gmail_watch_status.is_gmail_watch_live` — the SSOT owns "
        "the topic-non-empty + assume-UTC-on-naive + future-check "
        "predicate. Add to _ALLOWLIST only with an in-source rationale "
        "in gmail_watch_status.py's 'Sites explicitly OUT-OF-SSOT' block.\n\n"
        + "\n".join(f"{p}:{ln}  ({fn})" for p, fn, ln in offenders)
    )


def _own_qualified_name(fn_node: ast.AST) -> str:
    """Qualified name of a FunctionDef itself (walks parents INCLUDING
    the fn's own class/name; enclosing_qualified_name walks starting
    from the fn's parent, so we prepend the fn's own name here)."""
    from _pin_harness import enclosing_qualified_name as _enc

    parent_chain = _enc(fn_node)
    own = fn_node.name  # type: ignore[attr-defined]
    if parent_chain == "<module>":
        return own
    return f"{parent_chain}.{own}"


def test_pin_teeth_row_get_shape():
    """Anti-vacuity: a hand-roll using the ``row_get(row, "topic_name",
    0)`` idiom must trip the pin's detectors. Guards the widening the
    db-sme + devils-advocate N-263d panel required."""
    from _pin_harness import parse_source

    bad_source = """
def _bad_new_liveness_site(row):
    from datetime import datetime, timezone
    topic = (row_get(row, "topic_name", 0) or "").strip()
    exp = row_get(row, "expires_at", 1)
    if topic and exp and exp > datetime.now(timezone.utc):
        return True
    return False
"""
    tree = parse_source(bad_source)
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_bad_new_liveness_site":
            fn = node
            break
    assert fn is not None
    # Both prongs must fire on this shape — else the widening was
    # vacuous.
    assert _reads_topic_name(fn), (
        "widened `_reads_topic_name` missed row_get(row, 'topic_name', 0)"
    )
    assert _has_expires_at_comparison_against_now(fn), (
        "widened `_has_expires_at_comparison_against_now` missed row_get(row, 'expires_at', 1)"
    )


def test_is_gmail_watch_live_ssot_shape():
    """Anti-vacuity: the SSOT rejects synthetic-poll rows + past expiry
    + empty topic; accepts a well-formed future watch."""
    from datetime import datetime, timedelta, timezone

    from email_triage.web.gmail_watch_status import is_gmail_watch_live

    now = datetime.now(timezone.utc)
    # None / empty
    assert not is_gmail_watch_live(None)
    assert not is_gmail_watch_live({})
    # Empty topic (synthetic poll-mode row)
    assert not is_gmail_watch_live({
        "topic_name": "",
        "expires_at": (now + timedelta(days=7)).isoformat(),
    })
    # Past expiry
    assert not is_gmail_watch_live({
        "topic_name": "projects/x/topics/gmail-pubsub",
        "expires_at": (now - timedelta(hours=1)).isoformat(),
    })
    # Unparseable expiry
    assert not is_gmail_watch_live({
        "topic_name": "projects/x/topics/gmail-pubsub",
        "expires_at": "not-a-date",
    })
    # Well-formed future watch
    assert is_gmail_watch_live({
        "topic_name": "projects/x/topics/gmail-pubsub",
        "expires_at": (now + timedelta(days=7)).isoformat(),
    })
    # Naive datetime (assume-UTC posture; parse_iso_aware normalizes)
    naive = (now + timedelta(days=7)).replace(tzinfo=None).isoformat()
    assert is_gmail_watch_live({
        "topic_name": "projects/x/topics/gmail-pubsub",
        "expires_at": naive,
    })


def test_gmail_watch_expiry_sibling_shape():
    """Anti-vacuity: the ``gmail_watch_expiry`` sibling returns a
    UTC-aware datetime for a well-formed row, ``None`` for missing/
    unparseable, and normalises a naive expiry to UTC.

    This sibling is the "one home for the parse" complement to
    ``is_gmail_watch_live``; the double-parse smell devils-advocate
    flagged is closed by routing both bool + parsed-dt through the SSOT.
    """
    from datetime import datetime, timedelta, timezone

    from email_triage.web.gmail_watch_status import gmail_watch_expiry

    now = datetime.now(timezone.utc)
    assert gmail_watch_expiry(None) is None
    assert gmail_watch_expiry({}) is None
    assert gmail_watch_expiry({"expires_at": ""}) is None
    assert gmail_watch_expiry({"expires_at": "not-a-date"}) is None
    future = now + timedelta(days=7)
    got = gmail_watch_expiry({"expires_at": future.isoformat()})
    assert got is not None and got.tzinfo is not None
    # Naive input → assume-UTC posture.
    naive = future.replace(tzinfo=None).isoformat()
    got2 = gmail_watch_expiry({"expires_at": naive})
    assert got2 is not None and got2.tzinfo is timezone.utc
