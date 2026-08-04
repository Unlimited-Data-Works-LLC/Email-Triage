"""Lifecycle-status SSOT pin (census run23 #1, MEDIUM sev).

The SET-narrow / CLEAR-broad divergence class the sibling N-256 / N-69
funnels expose: every function that calls ``record_provider_outcome(db,
acct, exc)`` in a failure ``except`` branch (the auth_stale chip) —
alongside a sibling arm calling ``register_watch`` /
``upsert_gmail_watch`` /  ``create_subscription`` /
``upsert_o365_subscription`` (i.e. it touches the push/O365 lifecycle) —
must ALSO call the matching lifecycle SSOT SET half
``record_gmail_watch_outcome(error_text=...)`` /
``record_o365_subscription_outcome(error_text=...)``.

Pre-fix (census run23 discovered class #1): 7 sites flipped only the
auth_stale chip on failure, leaving ``gmail_watches.status`` /
``office365_subscriptions.status`` as ``'active'`` on ``/health`` for
hours until the next renewer sweep caught up. The mirror-image N-49 /
N-213 / N-215 / PD#18 pattern.

Existing pin ``test_n256_gmail_watch_lifecycle_pin.py`` guarded raw
``UPDATE gmail_watches SET status = ...`` at the schema level + an
anti-vacuity caller-count floor. Neither shape catches the
INTERPROCEDURAL "recorded auth_stale but skipped the lifecycle SSOT"
divergence — this pin closes that gap.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    parse_module,
    relpath as _relpath,
    walk_src,
)


_AUTH_STALE_MARKER = "record_provider_outcome"

_GMAIL_LIFECYCLE_KEYS = frozenset({
    "register_watch",
    "upsert_gmail_watch",
    "update_gmail_watch_history",
})
_GMAIL_LIFECYCLE_SET = "record_gmail_watch_outcome"

_O365_LIFECYCLE_KEYS = frozenset({
    "create_subscription",
    "upsert_o365_subscription",
})
_O365_LIFECYCLE_SET = "record_o365_subscription_outcome"

# The SSOT home for the lifecycle funnels + wrappers/renewers that
# LEGITIMATELY re-clear or re-set on a schedule (their whole function
# body IS the lifecycle machinery, not a divergent site).
_ALLOW_LIST: frozenset[str] = frozenset({
    "web/db.py",
    "web/app.py",
    "web/o365_renewer.py",
    "web/gmail_watch_renewer.py",
    # ingestion_push.py holds the wired renewer failure branch template
    # (line ~1494) as well as the freshly-wired push-consumer branches;
    # its bodies are the RIGHT shape.
})


def _calls_by_name(func: ast.AST) -> set[str]:
    """Every callee name reachable inside ``func`` (bare-Name calls only —
    ``x(...)`` / ``x.y(...)`` yields ``x`` / ``y`` respectively; a fully-
    qualified module call ``a.b.c(...)`` yields ``c``)."""
    names: set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                names.add(f.id)
                # `db_call(SSOT_FUNC, ...)` — the async-DB wrapper seam.
                # Its first arg IS the callee, so a wrapped SSOT call
                # must count as a direct call to that SSOT.
                if f.id == "db_call" and n.args:
                    first = n.args[0]
                    if isinstance(first, ast.Name):
                        names.add(first.id)
            elif isinstance(f, ast.Attribute):
                names.add(f.attr)
    return names


def _except_bodies(func: ast.AST):
    """Yield the AST nodes that appear inside any ``except`` handler body
    reachable from ``func`` — a shallow structural filter for the SET
    edge of the lifecycle."""
    for n in ast.walk(func):
        if isinstance(n, ast.ExceptHandler):
            for stmt in n.body:
                yield stmt


def _except_calls(func: ast.AST) -> set[str]:
    """Every callee name reachable inside any ``except`` handler in
    ``func`` — the same walker as :func:`_calls_by_name`, scoped to the
    except-branch subtree (so a lifecycle SET half inside a success
    branch is NOT credited on the failure edge)."""
    names: set[str] = set()
    for stmt in _except_bodies(func):
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Name):
                    names.add(f.id)
                    if f.id == "db_call" and n.args:
                        first = n.args[0]
                        if isinstance(first, ast.Name):
                            names.add(first.id)
                elif isinstance(f, ast.Attribute):
                    names.add(f.attr)
    return names


def _walk_functions(tree: ast.AST):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def test_no_orphan_auth_stale_gmail_lifecycle_touch():
    """Every function that TOUCHES the Gmail push lifecycle (
    ``register_watch`` / ``upsert_gmail_watch`` / ``update_gmail_watch_history``
    somewhere in the function body) AND records the auth_stale SET in an
    ``except`` branch MUST also call ``record_gmail_watch_outcome`` in an
    ``except`` branch of the SAME function."""
    offenders: list[str] = []
    for path, rel, tree in walk_src():
        if rel in _ALLOW_LIST:
            continue
        for fn in _walk_functions(tree):
            body_calls = _calls_by_name(fn)
            if not (body_calls & _GMAIL_LIFECYCLE_KEYS):
                continue  # function doesn't touch the Gmail lifecycle
            except_calls = _except_calls(fn)
            if _AUTH_STALE_MARKER not in except_calls:
                continue  # no auth_stale SET on a failure branch here
            if _GMAIL_LIFECYCLE_SET in except_calls:
                continue  # lifecycle SET already wired on failure branch
            offenders.append(
                f"{rel}::{fn.name} (line {fn.lineno})"
            )
    assert not offenders, (
        "Census run23 #1 — Gmail push lifecycle SET-narrow / CLEAR-broad "
        f"divergence: {offenders}. Each listed function flips the "
        "auth_stale chip on a failure branch (via record_provider_outcome) "
        "and touches the Gmail push lifecycle (register_watch / "
        "upsert_gmail_watch / update_gmail_watch_history) but does NOT "
        "wire record_gmail_watch_outcome(error_text=...) on the same "
        "except branch — so gmail_watches.status stays 'active' on "
        "/health while auth_stale flips. Route the SET half through "
        "record_gmail_watch_outcome — see the wired renewer template "
        "in web/ingestion_push.py:~1494."
    )


def test_no_orphan_auth_stale_o365_lifecycle_touch():
    """O365 sibling of the Gmail pin — every function that touches
    ``create_subscription`` / ``upsert_o365_subscription`` AND records
    the auth_stale SET in an ``except`` branch MUST also call
    ``record_o365_subscription_outcome`` in the same except branch."""
    offenders: list[str] = []
    for path, rel, tree in walk_src():
        if rel in _ALLOW_LIST:
            continue
        for fn in _walk_functions(tree):
            body_calls = _calls_by_name(fn)
            if not (body_calls & _O365_LIFECYCLE_KEYS):
                continue
            except_calls = _except_calls(fn)
            if _AUTH_STALE_MARKER not in except_calls:
                continue
            if _O365_LIFECYCLE_SET in except_calls:
                continue
            offenders.append(
                f"{rel}::{fn.name} (line {fn.lineno})"
            )
    assert not offenders, (
        "Census run23 #1 — O365 subscription lifecycle SET-narrow / "
        f"CLEAR-broad divergence: {offenders}. Wire "
        "record_o365_subscription_outcome(error_text=...) on the failure "
        "except branch alongside record_provider_outcome."
    )


# --------------------------------------------------------------------------
# Teeth.
# --------------------------------------------------------------------------
def test_pin_has_teeth_gmail(tmp_path):
    """Planted bad shape: function touches register_watch + records
    auth_stale in an except but misses the lifecycle SSOT SET."""
    bad = tmp_path / "b.py"
    bad.write_text(
        "async def start(db, acct):\n"
        "    try:\n"
        "        await provider.register_watch(topic)\n"
        "    except Exception as e:\n"
        "        await db_call(record_provider_outcome, db, acct, e)\n"
        "        raise\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fns = list(_walk_functions(tree))
    assert fns
    fn = fns[0]
    assert _GMAIL_LIFECYCLE_KEYS & _calls_by_name(fn)
    assert _AUTH_STALE_MARKER in _except_calls(fn)
    assert _GMAIL_LIFECYCLE_SET not in _except_calls(fn)


def test_pin_passes_wired_shape(tmp_path):
    """Planted good shape: same failure branch fires the lifecycle SET."""
    ok = tmp_path / "g.py"
    ok.write_text(
        "async def start(db, acct, account_id):\n"
        "    try:\n"
        "        await provider.register_watch(topic)\n"
        "    except Exception as e:\n"
        "        await db_call(record_provider_outcome, db, acct, e)\n"
        "        await db_call(\n"
        "            record_gmail_watch_outcome, db,\n"
        "            account_id=account_id, error_text=str(e),\n"
        "        )\n"
        "        raise\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = next(_walk_functions(tree))
    assert _GMAIL_LIFECYCLE_SET in _except_calls(fn)
