""" (divergence census 2026-06-10) — IMAP literal-fetch transport SSOT pin.

WHY: aioimaplib 2.0.1's ``_handle_responses`` parser RECURSES once per CRLF line
(``bug_aioimaplib_recursion``), so a large-body FETCH — ``BODY[]`` / ``RFC822`` /
``BODY.PEEK[...]`` on a multi-MB message — overflows the Python stack and crashes
the async IMAP path. The 2026-05-04 mitigation: every large literal-body fetch
goes through the SYNCHRONOUS stdlib-``imaplib`` backend
``providers/imap_blocking.py`` (whose parser does NOT recurse), reached ONLY via
``providers/imap.py``. The async aioimaplib path (``imap.py``) fetches METADATA
ONLY — ``(UID)`` / ``(UID INTERNALDATE)`` / ``FLAGS`` — never a body literal. A
ONE-TOKEN widening of an aioimaplib fetch to carry ``BODY.PEEK[...]`` silently
re-enters the crash on the next big message.

NO LIVE DRIFT today (census , enumeration verified complete); this pin keeps
it that way. Count-agnostic (``pattern_count_agnostic_structural_drift_catch``):
asserts a PROPERTY over every fetch / every module — never ``len(X) == N``.

Four invariants:
  1. No aioimaplib fetch carries a ``BODY[]`` / ``BODY.PEEK[]`` / ``RFC822``
     literal (the recursion-bug trigger) — covering BOTH async fetch shapes
     ``client.fetch(seq, criteria)`` AND ``client.uid("fetch", seq, criteria)``.
     Scoped to the async-transport module ``imap.py``; ``imap_blocking.py`` is
     the stdlib path where ``BODY.PEEK[]`` is SAFE and legitimately lives —
     exempt. Uses the AST of the CALL ARGS, so the same literals in docstrings /
     log examples don't trip it.
  2. Only the allow-set provider modules name ``imaplib`` / ``aioimaplib`` — no
     other module hand-rolls an IMAP transport (which would bypass the blocking
     SSOT and could re-introduce the async-recursion crash).
  3. The ``imap_blocking`` ``*_blocking`` entry points are imported ONLY from
     ``imap.py`` — the single funnel into the synchronous literal-body transport.
  4. (run18 #9) No module outside the confined transport set reaches a provider's
     PRIVATE ``_connect`` opener by name (``getattr(provider, "_connect")``) or
     issues a raw aioimaplib ``client.list('""', "*")`` — invariant 2 is blind to
     this shape because the offender borrows the provider's LIVE client and so
     names neither IMAP library. See the invariant-4 block for the PIN-ONLY
     rationale + the one allow-listed legacy bypass + its follow-on.

SCOPE CAVEAT (R38, db-sme  review):
  * Invariant 1 sees only LITERAL-Constant fetch criteria. A criteria built
    dynamically — ``section = "(BODY.PEEK[])"; client.fetch(uid, section)`` or an
    f-string ``f"(BODY.PEEK[{part}])"`` — is AST-invisible and would slip the
    guard. HEAD enumeration confirms all 5 ``imap.py`` fetch sites pass STRING
    LITERALS, so there is no live evasion; the convention to keep is: async
    transport criteria stay literal so this guard stays effective.
  * Invariant 1 is scoped to ``imap.py`` on the premise that it is the only
    module that speaks AIOIMAPLIB (the recursion-prone async lib). True at HEAD
    (``dispatcher.py`` hand-rolls only a stdlib ``imaplib`` health-probe with NO
    FETCH — recursion-immune). If a future change makes another allow-set module
    issue aioimaplib fetches, widen invariant 1's scope to it.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
    walk_src,
)

# The async aioimaplib transport — the recursion-prone module. Invariant 1 is
# scoped here (imap_blocking is the stdlib path, exempt).
_ASYNC_TRANSPORT = "providers/imap.py"
# Modules that may legitimately name imaplib / aioimaplib (invariant 2).
_IMAP_ALLOW = {
    "providers/imap.py",
    "providers/_aioimaplib_patch.py",
    # The IMAP fetch-transport SSOT (census run12 #3): the ONE chokepoint that
    # constructs imaplib/aioimaplib clients (imap_connect / aioimaplib_connect).
    # The 5 fetch/probe sites above now route construction through it; it
    # legitimately names both libs as the sanctioned transport seam.
    "providers/imap_fetch_transport.py",
}
# The synchronous literal-body backend + its sole sanctioned importer (inv 3).
_BLOCKING_HOME = "providers/imap_blocking.py"
_BLOCKING_SOLE_CALLER = "providers/imap.py"

# Substrings (compared upper-cased) that mark a literal-body fetch — the
# recursion trigger (a multi-MB literal response that _handle_responses recurses
# over per CRLF line). "BODY[" also covers "BODY[HEADER]"; "BODY.PEEK[" is the
# distinct PEEK form ("BODY[" is NOT a substring of "BODY.PEEK["); "BINARY[" is
# RFC 3516, which returns the full decoded body literal (db-sme  catch).
_BODY_SUBSTRINGS = ("BODY[", "BODY.PEEK[", "BINARY[")
# RFC822 forms that return a BODY literal — bare RFC822 (full message),
# RFC822.TEXT (body), RFC822.HEADER (header literal). RFC822.SIZE returns a
# NUMBER (metadata-safe) and must NOT be flagged.
_RFC822_BODY_RE = re.compile(r"RFC822(?!\.SIZE)")


# --- Invariant 1 ------------------------------------------------------------

def _is_uid_fetch_call(n: ast.Call) -> bool:
    """``client.uid("fetch", message_set, criteria)`` — the aioimaplib UID-FETCH
    shape (the body literal rides in a later arg). The first positional is the
    IMAP command name; we match it case-insensitively."""
    return bool(
        isinstance(n.func, ast.Attribute) and n.func.attr == "uid" and n.args
        and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
        and n.args[0].value.lower() == "fetch"
    )


def _fetch_body_literal_lines(tree: ast.AST) -> list[int]:
    """Lines of a fetch CALL whose string args carry a body literal. Covers BOTH
    aioimaplib fetch shapes: ``<x>.fetch(seq, criteria)`` and
    ``<x>.uid("fetch", seq, criteria)`` — a one-token widening via either
    re-enters the recursion crash, so both must be guarded."""
    out: list[int] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        if not (n.func.attr == "fetch" or _is_uid_fetch_call(n)):
            continue
        for a in list(n.args) + [kw.value for kw in n.keywords]:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                up = a.value.upper()
                if any(s in up for s in _BODY_SUBSTRINGS) or _RFC822_BODY_RE.search(up):
                    out.append(n.lineno)
                    break
    return out


def test_no_aioimaplib_fetch_carries_a_body_literal():
    """The async aioimaplib transport (imap.py) must FETCH metadata only — never
    a BODY[]/BODY.PEEK[]/RFC822 literal, which re-enters the parser-recursion
    stack overflow on a large message. Body fetches go through imap_blocking."""
    tree = parse_module(SRC_ROOT / "providers" / "imap.py"); assert tree is not None  # N-350 R31
    offenders = _fetch_body_literal_lines(tree)
    assert offenders == [], (
        f"aioimaplib .fetch() in {_ASYNC_TRANSPORT} carries a body literal at "
        f"lines {offenders} — this re-enters the aioimaplib _handle_responses "
        "recursion crash on a large message. Route literal-body fetches through "
        "providers/imap_blocking.py (the synchronous stdlib backend) instead."
    )


# --- Invariant 2 ------------------------------------------------------------

def _names_imap_lib(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            if any(a.name.split(".")[0] in ("imaplib", "aioimaplib") for a in n.names):
                return True
        elif isinstance(n, ast.ImportFrom):
            if (n.module or "").split(".")[0] in ("imaplib", "aioimaplib"):
                return True
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            if n.value.id in ("imaplib", "aioimaplib"):
                return True
    return False


def test_only_allow_set_modules_name_imap_libraries():
    """imaplib / aioimaplib may only be named by the sanctioned provider
    transport modules — no other module may hand-roll an IMAP client (which
    would bypass the imap_blocking SSOT for large-body fetches)."""
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel in _IMAP_ALLOW:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        if _names_imap_lib(tree):
            offenders.append(rel)
    assert offenders == [], (
        f"module(s) outside the IMAP-transport allow-set name imaplib/"
        f"aioimaplib: {offenders}. IMAP transport is confined to {sorted(_IMAP_ALLOW)} "
        "so large-body fetches can't bypass the imap_blocking SSOT."
    )


# --- Invariant 3 ------------------------------------------------------------

def _imports_blocking_backend(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("imap_blocking"):
            return True
        if isinstance(n, ast.Import):
            if any(a.name.endswith("imap_blocking") for a in n.names):
                return True
    return False


def test_blocking_backend_imported_only_from_imap_py():
    """The synchronous literal-body backend (imap_blocking) is the funnel for
    every large-body fetch; it must be reached ONLY through the async provider
    imap.py, so no other module can call it on the event loop (it blocks) or
    fan out an un-funnelled literal fetch."""
    offenders = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel in (_BLOCKING_HOME, _BLOCKING_SOLE_CALLER):
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        if _imports_blocking_backend(tree):
            offenders.append(rel)
    assert offenders == [], (
        f"module(s) other than {_BLOCKING_SOLE_CALLER} import the imap_blocking "
        f"backend: {offenders}. Route through ImapProvider (imap.py) so the "
        "synchronous literal-body transport stays single-funnelled + off the loop."
    )


# --- Invariant 4 (run18 #9) -------------------------------------------------
# Direct IMAP-transport bypass: a module OUTSIDE the confined transport set that
# reaches a provider's PRIVATE ``_connect`` opener by name and/or issues a raw
# aioimaplib ``client.list('""', "*")`` LIST. imap.py confines ALL aioimaplib
# transport — including the RFC 6154 SPECIAL-USE LIST probe and the four-layer
# resilience funnel (``session_2026-05-04_imap_resilience``: the patched parser,
# the ``_reset`` re-auth, the IDLE-recursion Layer-1). ``sent_folder.py``'s
# Sent-folder SPECIAL-USE probe does ``getattr(provider, "_connect", None)`` then
# ``client.list('""', "*")`` directly — borrowing the provider's live client, so
# it imports/names NEITHER imaplib NOR aioimaplib and invariant 2 is BLIND to it.
#
# VERIFIED future-risk only (census run18 #9, is_live_defect=FALSE): a LIST
# response never carries the multi-MB body literal that triggers the aioimaplib
# parser-recursion crash, so there is no present-day fault — the bypass risk is
# the brittle private-attr coupling + the missed resilience layers, not a crash.
#
# PIN-ONLY (run18 #9): a behavior-PRESERVING route is impossible without an
# imap.py change — the public ``list_folders()`` discards the ``\Sent``
# SPECIAL-USE flags, so a faithful route needs a NEW SPECIAL-USE-aware method on
# ImapProvider (a behavior-touching transport-surface change to the
# resilience-confined module). ``providers/sent_folder.py``'s own module
# docstring (lines ~20-26) already DEFERRED lifting this duplicated probe out of
# ``send_draft``. FOLLOW-ON: add e.g.
# ``ImapProvider.discover_special_use_folder(flag, fallbacks)`` (lifting the
# Drafts SPECIAL-USE probe at imap.py:~1536 — the SAME pattern), route
# ``_discover_imap_sent`` through it, then REMOVE the allow-list entry below.
# Needs resilience-layer SME review (does a discovery LIST need the Layer-1
# patch / ``_reset`` re-auth?).
#
# Function-keyed allow-list (R38): the ONE known legacy bypass, frozen so a
# SECOND such site fails loudly rather than being silently absorbed.
_TRANSPORT_BYPASS_ALLOW: set[tuple[str, str]] = set()
# N-273 R28: the previously-frozen bypass at
# ("providers/sent_folder.py", "_discover_imap_sent") — migrated to
# the public `ImapProvider.discover_special_use_folder(flag, fallbacks)`
# method (row 78 in the punch list). Empty allow-list = STRICT-0: any
# NEW `getattr(<x>, "_connect")` reach fires.


def _is_foreign_connect_getattr(n: ast.AST) -> bool:
    """``getattr(<x>, "_connect"[, default])`` — reaching a FOREIGN object's
    private transport opener by name. ``self._connect()`` (a class calling its
    OWN method, e.g. engine/store.py's DB opener) is a plain attribute call, NOT
    this dynamic-getattr shape, so it is correctly not flagged."""
    return bool(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == "getattr"
        and len(n.args) >= 2
        and isinstance(n.args[1], ast.Constant)
        and n.args[1].value == "_connect"
    )


def _is_raw_imap_list_call(n: ast.AST) -> bool:
    """``<x>.list(<str-literal>, ...)`` — the raw aioimaplib LIST wire shape (the
    first positional is the IMAP reference name, ``'""'`` / ``""``). A builtin
    ``list(...)`` has an ``ast.Name`` func (not a ``.list`` attribute) — not
    matched; a Gmail/Graph ``.list(userId=...)`` passes no positional string
    literal — not matched."""
    return bool(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == "list"
        and n.args
        and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
    )


def _is_transport_bypass(n: ast.AST) -> bool:
    return _is_foreign_connect_getattr(n) or _is_raw_imap_list_call(n)


def test_no_module_hand_rolls_imap_transport_outside_the_allow_set():
    """No module outside the confined IMAP-transport set reaches a provider's
    private ``_connect`` opener or issues a raw aioimaplib LIST — either bypasses
    the imap.py resilience funnel. Invariant 2 is blind to this shape (the
    offender borrows the provider's live client, naming no IMAP library)."""
    offenders = []
    for _p, rel, tree in walk_src():
        if rel in _IMAP_ALLOW:
            continue
        for n in ast.walk(tree):
            if not _is_transport_bypass(n):
                continue
            fn = enclosing_fn(n)
            if (rel, fn) in _TRANSPORT_BYPASS_ALLOW:
                continue
            offenders.append((rel, fn, n.lineno))
    assert offenders == [], (
        f"module(s) outside {sorted(_IMAP_ALLOW)} hand-roll IMAP transport "
        f"(foreign `_connect` getattr or raw `client.list(\"\")`): {offenders}. "
        "Route through ImapProvider (imap.py) so the LIST inherits the aioimaplib "
        "resilience funnel; do not borrow the provider's private client."
    )


# --- Teeth ------------------------------------------------------------------

def test_inv1_has_teeth():
    # Both aioimaplib fetch shapes carrying a body literal must be flagged.
    bad_fetch = (
        "async def f(client, seq):\n"
        "    return await client.fetch(seq, '(UID BODY.PEEK[])')\n"
    )
    assert _fetch_body_literal_lines(ast.parse(bad_fetch)) == [2]
    bad_uid_fetch = (
        "async def f(client, seq):\n"
        "    return await client.uid('fetch', seq, '(UID BODY[])')\n"  # uid-fetch shape
    )
    assert _fetch_body_literal_lines(ast.parse(bad_uid_fetch)) == [2]
    for crit in ("(RFC822)", "(RFC822.TEXT)", "(BINARY[])", "(BODY[HEADER])"):
        src = f"async def f(c, s):\n    return await c.fetch(s, '{crit}')\n"
        assert _fetch_body_literal_lines(ast.parse(src)) == [2], crit
    # Metadata-safe items + a non-fetch uid command must NOT be flagged —
    # including RFC822.SIZE (a number, not a body literal — db-sme precision fix).
    good = (
        "async def f(client, seq, mid):\n"
        "    a = await client.fetch(seq, '(UID INTERNALDATE)')\n"      # metadata
        "    s = await client.fetch(seq, '(RFC822.SIZE)')\n"          # number, safe
        "    b = await client.uid('store', mid, '+FLAGS', '(\\\\Seen)')\n"  # not a fetch
        "    return a, s, b\n"
    )
    assert _fetch_body_literal_lines(ast.parse(good)) == []


def test_inv2_has_teeth():
    assert _names_imap_lib(ast.parse("import aioimaplib\n"))
    assert _names_imap_lib(ast.parse("import imaplib\n"))
    assert _names_imap_lib(ast.parse("from aioimaplib import IMAP4_SSL\n"))
    assert not _names_imap_lib(ast.parse("import email\nx = re.compile('a')\n"))


def test_inv3_has_teeth():
    assert _imports_blocking_backend(
        ast.parse("from email_triage.providers.imap_blocking import fetch_message_blocking\n")
    )
    assert not _imports_blocking_backend(ast.parse("from email_triage.providers.imap import ImapProvider\n"))


def test_inv4_has_teeth():
    def _hits(src: str) -> int:
        return sum(1 for n in ast.walk(ast.parse(src)) if _is_transport_bypass(n))

    # BAD — the exact sent_folder.py bypass shape (both signals).
    bad = (
        "async def probe(provider):\n"
        "    connect = getattr(provider, '_connect', None)\n"
        "    client = await connect()\n"
        "    result, data = await client.list('\"\"', '*')\n"
    )
    assert _hits(bad) == 2  # the getattr + the raw .list

    # BAD — raw LIST alone.
    assert _hits("async def f(c):\n    return await c.list('', '*')\n") == 1
    # BAD — foreign _connect getattr alone (with a default arg).
    assert _hits("def f(p):\n    return getattr(p, '_connect', None)\n") == 1

    # GOOD — a class calling its OWN private opener (engine/store.py shape).
    assert _hits("class S:\n    def go(self):\n        return self._connect()\n") == 0
    # GOOD — builtin list(...) is a Name func, not a `.list` attribute.
    assert _hits("def f(xs):\n    return list(xs)\n") == 0
    # GOOD — a Gmail/Graph `.list(userId=...)` passes no positional str literal.
    assert _hits("def f(svc):\n    return svc.users().labels().list(userId='me')\n") == 0
    # GOOD — getattr for an unrelated attr name.
    assert _hits("def f(p):\n    return getattr(p, 'name', '')\n") == 0


def test_inv4_allow_list_is_function_keyed():
    """The transport-bypass allow-list is ``(relpath, funcname)`` — never a bare
    lineno (R38), so it survives an unrelated line shift fail-closed."""
    for entry in _TRANSPORT_BYPASS_ALLOW:
        assert isinstance(entry, tuple) and len(entry) == 2, entry
        assert all(isinstance(part, str) for part in entry), entry
