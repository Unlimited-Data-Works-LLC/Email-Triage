"""Pin (punch 694): a function that opens a provider/IMAP session to probe it releases the session
on EVERY exit, a failed probe included.

Before punch 694, five request handlers ran ``probe`` then ``await provider.close()`` in the
SAME try body, so a probe that failed after login skipped the close and the authenticated IMAP
session leaked until the server timed it out. The census found two more of the same shape
outside the row (``providers/dispatcher.py`` ``_gmail_test_connection`` and the raw ``imaplib``
``_imap_test_connection``); the funnel is ``providers/render_probe.probe_session`` /
``close_provider``.

Property (PD-1, count-agnostic, PD-2 on the seam): for EVERY src call site that probes a
provider (``render_probe(p, ...)`` or ``p.list_folders()`` / ``p.list_labels()`` on a plain name)
one of these holds:

* ``p`` is a parameter of the enclosing function (the caller owns the session and is itself
  checked at its own creation site);
* the call sits inside ``async with probe_session(p):``;
* the call sits inside a ``try`` whose ``finally`` closes ``p`` (``p.close()``,
  ``close_provider(p)``, ``p.logout()``, ``_imap_release(p)``).

And for every ``imap_connect(...)`` (a raw ``imaplib`` session) the enclosing function has a
``try`` whose ``finally`` closes the name it was assigned to.

SCOPE CAVEAT: a provider reached through ``self.x``, an attribute, a callable passed as a value or
``getattr`` is not followed (the same residual the ``render_probe`` bound pin documents); a
parameter-owned provider is trusted, not chased up the call graph.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth, iter_src_files, parse_module, parse_source, relpath,
)

PROBE_ATTRS = frozenset({"list_folders", "list_labels"})
FUNNEL = "probe_session"
CLOSE_NAMES = frozenset({"close_provider", "_imap_release"})
CLOSE_ATTRS = frozenset({"close", "logout", "shutdown"})
RAW_SESSION = "imap_connect"
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else None


def _probe_receiver(call: ast.Call) -> str | None:
    """The provider NAME a probe call acts on, or ``None`` when the call is not a probe."""
    f = call.func
    if isinstance(f, ast.Name) and f.id == "render_probe":
        first = call.args[0] if call.args else None
        return first.id if isinstance(first, ast.Name) else "<unnamed>"
    if (isinstance(f, ast.Attribute) and f.attr in PROBE_ATTRS
            and isinstance(f.value, ast.Name) and f.value.id != "self"):
        return f.value.id
    return None


def _enclosing_function(node: ast.AST):
    while node is not None:
        node = getattr(node, "_ph_parent", None)
        if isinstance(node, _FUNCS):
            return node
    return None


def _params(fn: ast.AST) -> set[str]:
    a = fn.args
    return {x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs,
                            *([a.vararg] if a.vararg else []),
                            *([a.kwarg] if a.kwarg else [])]}


def _closes(stmts: list[ast.stmt], name: str) -> bool:
    """A statement list that closes ``name``: ``name.close()`` / ``.logout()`` /
    ``.shutdown()``, or ``close_provider(name)`` / ``_imap_release(name)``."""
    for stmt in stmts:
        for call in ast.walk(stmt):
            if not isinstance(call, ast.Call):
                continue
            f = call.func
            if (isinstance(f, ast.Attribute) and f.attr in CLOSE_ATTRS
                    and isinstance(f.value, ast.Name) and f.value.id == name):
                return True
            if (isinstance(f, ast.Name) and f.id in CLOSE_NAMES and call.args
                    and isinstance(call.args[0], ast.Name) and call.args[0].id == name):
                return True
    return False


def _released_on_every_exit(call: ast.Call, name: str) -> bool:
    fn = _enclosing_function(call)
    if fn is not None and name in _params(fn):
        return True
    child, anc = call, getattr(call, "_ph_parent", None)
    while anc is not None and anc is not fn:
        if isinstance(anc, (ast.With, ast.AsyncWith)):
            for item in anc.items:
                ctx = item.context_expr
                if (isinstance(ctx, ast.Call) and _call_name(ctx) == FUNNEL and ctx.args
                        and isinstance(ctx.args[0], ast.Name) and ctx.args[0].id == name):
                    return True
        if isinstance(anc, ast.Try) and child not in anc.finalbody and _closes(anc.finalbody, name):
            return True
        child, anc = anc, getattr(anc, "_ph_parent", None)
    return False


def unreleased_probes(tree: ast.AST) -> list[int]:
    """Lines of probe calls whose session is not released on every exit, plus raw ``imaplib``
    sessions with no ``finally`` close."""
    hits: list[int] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = _probe_receiver(call)
        if name is not None and not _released_on_every_exit(call, name):
            hits.append(call.lineno)
        if _call_name(call) == RAW_SESSION:
            parent = getattr(call, "_ph_parent", None)
            target = (parent.targets[0] if isinstance(parent, ast.Assign)
                      and len(parent.targets) == 1 else None)
            fn = _enclosing_function(call)
            ok = (isinstance(target, ast.Name) and fn is not None and any(
                isinstance(t, ast.Try) and _closes(t.finalbody, target.id)
                for t in ast.walk(fn)))
            if not ok:
                hits.append(call.lineno)
    return hits


def _probe_sites(tree: ast.AST) -> int:
    return sum(1 for c in ast.walk(tree) if isinstance(c, ast.Call)
               and (_probe_receiver(c) is not None or _call_name(c) == RAW_SESSION))


def test_every_probe_session_is_released_on_every_exit():
    offenders, sites = [], 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        sites += _probe_sites(tree)
        offenders += [f"{relpath(path)}:{line}" for line in unreleased_probes(tree)]
    assert sites, "the probe-site net found nothing: the detector is blind, not the tree clean"
    assert not offenders, (
        "A provider/IMAP session opened to probe is not released on a failed probe (punch 694). "
        "Wrap the probe in `async with probe_session(p):` "
        "(providers/render_probe.py), or close `p` in a `finally`:\n  " + "\n  ".join(offenders))


_BAD = "async def h(a, s):\n    p = make(a, s)\n    f = await render_probe(p)\n    await p.close()\n"


def test_detector_has_teeth():
    assert_pin_has_teeth(
        unreleased_probes,
        bad_source=_BAD,
        good_source=("async def h(a, s):\n    p = make(a, s)\n    async with probe_session(p):\n"
                     "        f = await render_probe(p)\n"),
    )


def test_teeth_close_in_except_or_in_the_try_body_is_not_a_finally():
    for src in (
        "async def h(a):\n    p = make(a)\n    try:\n        x = await p.list_labels()\n"
        "    except Exception:\n        await p.close()\n",
        "async def h(a):\n    p = make(a)\n    try:\n        x = await p.list_labels()\n"
        "        await p.close()\n    except Exception:\n        pass\n",
        "async def h(a):\n    p = make(a)\n    try:\n        pass\n    finally:\n"
        "        x = await render_probe(p)\n        await p.close()\n",
    ):
        assert unreleased_probes(parse_source(src)), src


def test_teeth_the_accepted_shapes_pass():
    for src in (
        "async def h(p):\n    return await render_probe(p)\n",          # caller owns it
        "async def h(a):\n    p = make(a)\n    try:\n        x = await p.list_folders()\n"
        "    finally:\n        await close_provider(p)\n",
        "async def h(a):\n    p = make(a)\n    try:\n        x = await render_probe(p)\n"
        "    finally:\n        await p.close()\n",
        "def h(a):\n    i = imap_connect(a)\n    try:\n        i.login(a)\n    finally:\n"
        "        _imap_release(i)\n",
    ):
        assert not unreleased_probes(parse_source(src)), src


def test_teeth_a_raw_imap_session_without_a_finally_is_flagged():
    assert unreleased_probes(parse_source(
        "def h(a):\n    i = imap_connect(a)\n    i.login(a)\n    i.logout()\n"))
    # closing a DIFFERENT name does not release this one
    assert unreleased_probes(parse_source(
        "async def h(a, b):\n    p = make(a)\n    try:\n        x = await render_probe(p)\n"
        "    finally:\n        await b.close()\n"))
