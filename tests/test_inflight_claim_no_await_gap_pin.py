"""In-flight dedup slot-leak pin (divergence census run13 #3).

``web/triage_inflight.py`` hands out a per-(account, UID) dedup slot:
``mark_inflight`` claims it, ``release_inflight`` frees it, and ``claim()`` is the
exception-safe context-manager that always releases. The 5 ingestion entry
points hand-roll ``if not mark_inflight(...): continue`` then a ``try:`` whose
``finally`` releases — which is safe ONLY if nothing between the claim and that
``try`` can RAISE. The watcher had a raise-capable ``await db_call(_account_is_
active, …)`` in that gap: a DB error there left the UID marked in-flight FOREVER
(skipped as "in_flight" until a process restart), silently un-triaged.

Count-agnostic property: for every ``if not mark_inflight(...): …`` claim guard,
the statements between it and the next sibling ``try:`` (the releasing block)
contain NO ``await`` — an await is the raise-capable hop that leaks the slot.
A claim with no following ``try:`` at all is also flagged. ``triage_inflight.py``
(the SSOT, where ``claim()`` wraps mark/release in its own try/finally) is exempt.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    enclosing_fn, iter_src_files, parse_module, parse_source, relpath,
)


# ── run18  — every mark_inflight routes through claim() ──────────────
# ``claim()`` (web/triage_inflight.py) is the exception-safe SSOT: it marks at
# entry and ALWAYS releases at with-exit. All 5 ingestion entry points USED to
# hand-roll ``if not mark_inflight(...): continue`` + a ``try/finally`` release —
# correct today, but a future caller that forgets the finally leaks a slot
# (skips the UID as "in_flight" until a process restart). run18  routed the
# four clean sites through ``claim()``; the prevention is THIS pin: a
# ``mark_inflight`` CALL anywhere outside ``claim()``'s own module and outside
# the allow-list is a defect (every mark ⇒ claim).
#
# Function-keyed allow-list (NOT file-keyed — a file key would mask a sibling
# function in the same module; cf. run17 #2 / N-134). The SSOT module
# ``web/triage_inflight.py`` (where ``claim()`` legitimately calls
# ``mark_inflight``) is exempt wholesale.
_INFLIGHT_SSOT = "web/triage_inflight.py"
_CLAIM_ROUTING_ALLOW = {
    # The IMAP unified-poll per-message loop keeps the raw mark/release: its
    # ``finally`` does meaningful work BEYOND the release (the 
    # ``hwm_run_open`` / ``hwm_safe_uid`` contiguous-safe-run advancement) that
    # ``claim()``'s release-only context manager would drop. Documented keep-raw.
    ("web/poll_ingestion.py", "_poll_once_imap"),
}


def _mark_inflight_call_sites(tree: ast.AST, rel: str) -> list[tuple[str, str, int]]:
    """``(relpath, enclosing_fn, lineno)`` for every ``mark_inflight`` /
    ``_mark_inflight`` CALL in ``tree`` (the alias the entry points use)."""
    out: list[tuple[str, str, int]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if name in ("mark_inflight", "_mark_inflight"):
                out.append((rel, enclosing_fn(n), n.lineno))
    return out


def _claim_routing_offenders(tree: ast.AST, rel: str) -> list[str]:
    """``mark_inflight`` CALL sites in ``tree`` that are NOT routed through
    ``claim()``: every such call must live in the SSOT module
    (:data:`_INFLIGHT_SSOT`, where ``claim()`` legitimately wraps mark/release)
    or be ``(relpath, enclosing_fn)``-allow-listed (:data:`_CLAIM_ROUTING_ALLOW`,
    the documented keep-raw sites). Anything else is an un-routed claim that can
    forget its release (run18 : every mark ⇒ claim)."""
    if rel == _INFLIGHT_SSOT:
        return []
    out: list[str] = []
    for r, fn, lineno in _mark_inflight_call_sites(tree, rel):
        if (r, fn) in _CLAIM_ROUTING_ALLOW:
            continue
        out.append(f"{r}:{fn}:{lineno}")
    return out


def _calls_mark_inflight(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if name in ("mark_inflight", "_mark_inflight"):
                return True
    return False


def _has_await(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Await) for n in ast.walk(node))


def _scan_block(body: list, rel: str, out: list) -> None:
    """Scan one statement list for a mark_inflight claim-guard whose path to the
    releasing ``try:`` is not await-free."""
    for i, stmt in enumerate(body):
        if not (isinstance(stmt, ast.If) and _calls_mark_inflight(stmt.test)):
            continue
        gap: list = []
        found_try = False
        for nxt in body[i + 1:]:
            if isinstance(nxt, ast.Try):
                found_try = True
                break
            gap.append(nxt)
        if not found_try:
            out.append(f"{rel}:{stmt.lineno} (mark_inflight claim with no releasing try after it)")
        elif any(_has_await(g) for g in gap):
            out.append(f"{rel}:{stmt.lineno} (await between the mark_inflight claim and the releasing try — a raise there leaks the slot)")


def _offenders(tree: ast.AST, rel: str) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(node, attr, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                _scan_block(block, rel, out)
    return out


def test_no_await_between_inflight_claim_and_release_try():
    offenders = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        bad = _offenders(tree, relpath(p))
        if bad:
            offenders.extend(bad)
    assert not offenders, (
        "An in-flight dedup slot can LEAK (census run13 #3): a raise-capable "
        f"await sits between the mark_inflight claim and the releasing try: "
        f"{offenders}. Move the await BEFORE the claim, or route the whole "
        "block through web.triage_inflight.claim() (the exception-safe CM). A "
        "leaked slot skips the UID as 'in_flight' until a process restart."
    )


def test_pin_has_teeth():
    bad = (
        "async def w():\n"
        "    if not mark_inflight(s, a, u):\n"
        "        continue\n"
        "    ok = await db_call(check, a)\n"   # ← raise-capable gap
        "    try:\n"
        "        await work()\n"
        "    finally:\n"
        "        release_inflight(s, a, u)\n"
    )
    assert _offenders(ast.parse(bad), "x.py"), "missed an await in the claim→try gap"
    good = (
        "async def w():\n"
        "    ok = await db_call(check, a)\n"   # await BEFORE the claim — safe
        "    if not mark_inflight(s, a, u):\n"
        "        continue\n"
        "    t0 = now()\n"                      # benign, no await
        "    try:\n"
        "        await work()\n"
        "    finally:\n"
        "        release_inflight(s, a, u)\n"
    )
    assert not _offenders(ast.parse(good), "x.py"), "false-positived an await-free gap"
    no_try = (
        "async def w():\n"
        "    if not mark_inflight(s, a, u):\n"
        "        continue\n"
        "    await work()\n"                    # claimed but no releasing try
    )
    assert _offenders(ast.parse(no_try), "x.py"), "missed a claim with no releasing try"


# ── run18  — the routing pin (every mark_inflight ⇒ claim) ──────────────

def test_every_mark_inflight_routes_through_claim():
    """A ``mark_inflight`` CALL outside the SSOT module + outside the documented
    keep-raw allow-list is a defect: it hand-rolls the claim/release the
    ``claim()`` context manager makes exception-safe, and a future edit that
    forgets the ``finally`` release leaks the slot (the UID is skipped as
    'in_flight' until a process restart). run18  routed the four clean entry
    points through ``claim()``; this pin keeps them there."""
    offenders: list[str] = []
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders.extend(_claim_routing_offenders(tree, relpath(p)))
    assert not offenders, (
        "An in-flight claim hand-rolls raw mark_inflight outside claim() "
        f"(run18 #14): {offenders}. Route the block through "
        "web.triage_inflight.claim() (the exception-safe mark+release SSOT), or "
        "— if the site's finally does meaningful work beyond release — add its "
        "(relpath, enclosing_fn) to _CLAIM_ROUTING_ALLOW with a reason."
    )


def test_claim_routing_pin_has_teeth():
    # A raw mark_inflight in a non-SSOT, non-allow-listed function → flagged.
    bad = (
        "def handle(s, a, u):\n"
        "    if not mark_inflight(s, a, u):\n"
        "        return\n"
        "    work()\n"
    )
    assert _claim_routing_offenders(parse_source(bad), "web/some_entry.py"), (
        "missed a raw mark_inflight outside claim() / the allow-list"
    )
    # The documented keep-raw site (poll IMAP loop,  finally) → exempt.
    allowed = (
        "def _poll_once_imap(s, a, u):\n"
        "    if not _mark_inflight(s, a, u):\n"
        "        continue\n"
    )
    assert not _claim_routing_offenders(parse_source(allowed), "web/poll_ingestion.py"), (
        "false-positived the allow-listed _poll_once_imap keep-raw site"
    )
    # The SSOT module (claim() calls mark_inflight internally) → exempt wholesale.
    ssot = "def claim(s, a, u):\n    won = mark_inflight(s, a, u)\n"
    assert not _claim_routing_offenders(parse_source(ssot), _INFLIGHT_SSOT), (
        "false-positived the claim() SSOT module"
    )
    # A claim()-routed site (no raw mark_inflight call) → nothing to flag.
    routed = (
        "def handle(s, a, u):\n"
        "    with claim(s, a, u) as won:\n"
        "        if not won:\n"
        "            return\n"
        "        work()\n"
    )
    assert not _claim_routing_offenders(parse_source(routed), "web/some_entry.py"), (
        "false-positived a claim()-routed site that never calls mark_inflight"
    )
