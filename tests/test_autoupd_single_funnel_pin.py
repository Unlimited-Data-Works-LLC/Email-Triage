"""Operator decision 2026-10-25 -- the embedding runtime updates ITSELF, through the
ONE funnel the admin's click uses. This is the count-agnostic, interprocedural
pin that keeps it one (PD-1, PD-2, PD-5, PD-6).

Three properties over EVERY site in ``src/`` (never ``len(X) == N``):

1. ``update_runtime`` (the domain funnel) is referenced nowhere outside
   ``embedding_bits/__init__.py`` except ``web/embedding_update_runner.py::_finish``.
   The reference shapes caught: a call, a call's FIRST positional argument
   (``asyncio.to_thread(update_runtime, ...)``, ``db_call``, ``run_in_executor``,
   ``functools.partial``), any other ``Name``/``Attribute`` load, and an
   ``import`` of the name. A hop through a helper does not hide it: the hop is
   the reference.
2. The runner's private parts (``_claim``, ``_finish``, ``_note_failure``) are
   referenced only inside the runner, so no caller can take the work without the
   INTENT row, the in-flight guard and the OUTCOME row.
3. Attribution (PD-3, §164.312(b)): an ``apply_runtime_update`` call is always
   made as ``UpdateActor.system()``, a ``start_runtime_update`` call as
   ``UpdateActor.from_user(...)``, and ``UpdateActor(...)`` is never constructed
   outside the runner, so an unattended run cannot be written under a blank or
   borrowed actor. No ``embedding_runtime_update`` row in ``src/`` is written with a
   missing or string-literal ``email=`` (the boot-recovery row included: it carries
   ``BOOT_RECOVERY_ACTOR_EMAIL``).

Plus the reach arms: the route reaches ``start_runtime_update``; the sweeper's
``auto_update_once`` reaches ``apply_runtime_update``; both reach ``_claim`` and
``_finish``; and the app wires the sweeper and the switch.

SCOPE CAVEAT (what a green run does NOT prove): a reference built from a string
(``getattr(eb, "update_runtime")``, ``importlib``) is not seen; a value carried in
a dict or an attribute is not followed; the walk covers ``src/email_triage`` only
(``scripts/`` and ``tests/`` may call the domain funnel directly -- the CLI is not
a runtime caller). The behavioural arms (``tests/test_web/test_autoupd_runner.py``)
prove the funnel does the right thing; this pin proves nothing else does the work.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    parse_source,
    reachers_of,
    walk_src,
)

_DOMAIN = "embedding_bits/__init__.py"
_RUNNER = "web/embedding_update_runner.py"
_ROUTE = "web/routers/ui/embedding_install.py"

#: (relpath, enclosing_fn) -> why this site may reference ``update_runtime``.
#: Repo-relative, line-stable (R38).
_UPDATE_RUNTIME_ALLOW = {
    (_RUNNER, "<module>"):
        "the module-level import the funnel's one call uses",
    (_RUNNER, "_finish"):
        "THE call: asyncio.to_thread(update_runtime, ...) after _claim's INTENT row "
        "and in-flight guard, followed by the OUTCOME row",
}

_PRIVATE_PARTS = frozenset({"_claim", "_finish", "_note_failure"})


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def update_runtime_refs(tree: ast.AST):
    """``(enclosing_fn, lineno)`` of every reference to ``update_runtime``."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "update_runtime":
            out.append((enclosing_fn(node), node.lineno))
        elif isinstance(node, ast.Attribute) and node.attr == "update_runtime":
            out.append((enclosing_fn(node), node.lineno))
        elif isinstance(node, ast.ImportFrom) and any(
            a.name == "update_runtime" for a in node.names
        ):
            out.append((enclosing_fn(node), node.lineno))
    return out


def private_part_refs(tree: ast.AST):
    out = []
    for node in ast.walk(tree):
        name = _name_of(node)
        if name in _PRIVATE_PARTS and isinstance(node, (ast.Name, ast.Attribute)):
            out.append((enclosing_fn(node), node.lineno))
        elif isinstance(node, ast.ImportFrom) and any(a.name in _PRIVATE_PARTS for a in node.names):
            out.append((enclosing_fn(node), node.lineno))
    return out


def _actor_arg(call: ast.Call) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == "actor":
            return kw.value
    return None


def bad_actor_calls(tree: ast.AST):
    """Funnel entry calls made under the wrong actor shape."""
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name_of(node.func)
        if name not in ("apply_runtime_update", "start_runtime_update"):
            continue
        actor = _actor_arg(node)
        want = "system" if name == "apply_runtime_update" else "from_user"
        ok = (
            isinstance(actor, ast.Call)
            and isinstance(actor.func, ast.Attribute)
            and actor.func.attr == want
            and _name_of(actor.func.value) == "UpdateActor"
        )
        if not ok:
            bad.append((enclosing_fn(node), node.lineno))
    return bad


def raw_actor_constructions(tree: ast.AST):
    return [
        (enclosing_fn(n), n.lineno)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _name_of(n.func) == "UpdateActor"
    ]


# ---------------------------------------------------------------------------
# 1. update_runtime has one caller
# ---------------------------------------------------------------------------

def test_update_runtime_is_referenced_only_by_the_funnel():
    violations = []
    for _path, rel, tree in walk_src():
        if rel == _DOMAIN:
            continue
        for fn, lineno in update_runtime_refs(tree):
            if (rel, fn) not in _UPDATE_RUNTIME_ALLOW:
                violations.append(f"{rel}:{lineno}  update_runtime referenced in {fn!r}")
    assert not violations, (
        "update_runtime is the DOMAIN funnel; its only caller is "
        "web/embedding_update_runner.py::_finish (operator decision 2026-10-25: "
        "the click and the automatic updater share one funnel):\n  "
        + "\n  ".join(violations)
        + "\n\nFIX: call start_runtime_update / apply_runtime_update instead."
    )


def test_update_runtime_allowlist_is_not_stale():
    live = set()
    for _path, rel, tree in walk_src():
        if rel == _DOMAIN:
            continue
        for fn, _lineno in update_runtime_refs(tree):
            live.add((rel, fn))
    stale = set(_UPDATE_RUNTIME_ALLOW) - live
    assert not stale, f"stale allow-list entries (site gone or renamed): {sorted(stale)}"


def test_update_runtime_pin_has_teeth():
    bad_call = "async def apply():\n    await asyncio.to_thread(update_runtime, conn=c)\n"
    bad_attr = "def apply():\n    loop.run_in_executor(None, eb.update_runtime)\n"
    bad_import = "from email_triage.embedding_bits import update_runtime\n"
    bad_partial = "def apply():\n    f = functools.partial(update_runtime, conn=c)\n"
    good = "async def apply():\n    await start_runtime_update(app, actor=a)\n"
    for bad in (bad_call, bad_attr, bad_import, bad_partial):
        assert_pin_has_teeth(update_runtime_refs, bad, good)


# ---------------------------------------------------------------------------
# 2. the runner's private parts stay private
# ---------------------------------------------------------------------------

def test_the_funnels_private_parts_are_used_only_inside_the_runner():
    violations = []
    for _path, rel, tree in walk_src():
        if rel == _RUNNER:
            continue
        for fn, lineno in private_part_refs(tree):
            violations.append(f"{rel}:{lineno}  runner internal referenced in {fn!r}")
    assert not violations, (
        "embedding_update_runner._claim/_finish/_note_failure are the funnel's "
        "internals; a caller that takes them skips the INTENT row or the OUTCOME "
        "row:\n  " + "\n  ".join(violations)
    )


def test_private_parts_pin_has_teeth():
    bad = "from email_triage.web.embedding_update_runner import _finish\n"
    bad_attr = "def f():\n    return runner._claim(app, a, None, None)\n"
    good = "def f():\n    return runner.start_runtime_update(app, actor=a)\n"
    assert_pin_has_teeth(private_part_refs, bad, good)
    assert_pin_has_teeth(private_part_refs, bad_attr, good)


# ---------------------------------------------------------------------------
# 3. attribution
# ---------------------------------------------------------------------------

def test_every_funnel_call_names_its_actor_by_the_typed_constructor():
    violations = []
    for _path, rel, tree in walk_src():
        for fn, lineno in bad_actor_calls(tree):
            violations.append(f"{rel}:{lineno}  funnel entry in {fn!r} with a wrong actor shape")
    assert not violations, (
        "apply_runtime_update must be called as actor=UpdateActor.system() (the "
        "unattended run) and start_runtime_update as actor=UpdateActor.from_user(...) "
        "(the admin's click):\n  " + "\n  ".join(violations)
    )


def test_an_actor_is_never_built_outside_the_runner():
    violations = []
    for _path, rel, tree in walk_src():
        if rel == _RUNNER:
            continue
        for fn, lineno in raw_actor_constructions(tree):
            violations.append(f"{rel}:{lineno}  UpdateActor(...) in {fn!r}")
    assert not violations, (
        "UpdateActor is built by UpdateActor.system() / .from_user(...) only, so "
        "an update is never written under a blank or invented actor:\n  "
        + "\n  ".join(violations)
    )


def test_attribution_pin_has_teeth():
    bad_blank = "async def f():\n    await apply_runtime_update(app, actor=UpdateActor('', None))\n"
    bad_user = "async def f():\n    await apply_runtime_update(app, actor=UpdateActor.from_user(u))\n"
    bad_missing = "async def f():\n    await start_runtime_update(app)\n"
    good_auto = "async def f():\n    await apply_runtime_update(app, actor=UpdateActor.system())\n"
    good_click = "async def f():\n    await start_runtime_update(app, actor=UpdateActor.from_user(u))\n"
    for bad in (bad_blank, bad_user, bad_missing):
        assert_pin_has_teeth(bad_actor_calls, bad, good_auto)
    assert not bad_actor_calls(parse_source(good_click))
    assert_pin_has_teeth(raw_actor_constructions, "x = UpdateActor('', None)\n", "x = UpdateActor.system()\n")


def update_rows_with_a_literal_email(tree: ast.AST):
    """Every emitter call that writes an ``embedding_runtime_update`` row with no
    ``email=`` or a string-literal one. The actor must come from a typed constant
    or an ``UpdateActor`` (operator ruling R5: the boot-recovery row used to carry
    ``email=""``)."""
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _name_of(node.func) in ("record_auth_event", "_rae")):
            continue
        kws = {k.arg: k.value for k in node.keywords}
        et = kws.get("event_type")
        is_update = (
            isinstance(et, ast.Constant) and et.value == "embedding_runtime_update"
        ) or (isinstance(et, ast.Name) and et.id == "EVENT_TYPE")
        email = kws.get("email")
        if is_update and (email is None or isinstance(email, ast.Constant)):
            out.append((enclosing_fn(node), node.lineno))
    return out


def test_no_embedding_runtime_update_row_is_written_with_a_literal_or_blank_actor():
    violations = [
        f"{rel}:{lineno}  embedding_runtime_update row in {fn!r} with no typed actor"
        for _path, rel, tree in walk_src()
        for fn, lineno in update_rows_with_a_literal_email(tree)
    ]
    assert not violations, "\n  " + "\n  ".join(violations)


def test_the_literal_actor_pin_has_teeth():
    blank = "def f():\n    record_auth_event(db, event_type='embedding_runtime_update', email='')\n"
    literal = "def f():\n    _rae(c, event_type='embedding_runtime_update', email='x@y')\n"
    missing = "def f():\n    record_auth_event(db, event_type=EVENT_TYPE)\n"
    good = "def f():\n    _rae(c, event_type='embedding_runtime_update', email=BOOT_RECOVERY_ACTOR_EMAIL)\n"
    other = "def f():\n    record_auth_event(db, event_type='something_else', email='')\n"
    for bad in (blank, literal, missing):
        assert_pin_has_teeth(update_rows_with_a_literal_email, bad, good)
    assert not update_rows_with_a_literal_email(parse_source(other))


def test_the_named_system_actors_are_typed_and_distinct():
    from email_triage.web import embedding_update_runner as ru

    assert ru.SYSTEM_ACTOR_EMAIL == "system:embedding-auto-update"
    assert ru.BOOT_RECOVERY_ACTOR_EMAIL == "system:embedding-boot-recovery"
    assert ru.SYSTEM_ACTOR_EMAIL != ru.BOOT_RECOVERY_ACTOR_EMAIL
    for email in (ru.SYSTEM_ACTOR_EMAIL, ru.BOOT_RECOVERY_ACTOR_EMAIL):
        assert email.startswith("system:") and email.strip() and email != "unknown"


# ---------------------------------------------------------------------------
# 4. no update check (hipaa-sme panel S NOTE): the trigger asks nobody what is newer
# ---------------------------------------------------------------------------

#: Modules that open a connection. The trigger decides staleness from the installed
#: set and the manifest the image ships; a network client in the runner is the door
#: through which a "what is newer?" question to PyPI / PyTorch / Hugging Face would
#: enter. The downloads themselves live in ``embedding_bits`` (``update_runtime``).
_NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "urllib3", "httpx", "requests", "aiohttp",
    "pip", "smtplib", "imaplib", "poplib", "ftplib", "telnetlib", "xmlrpc",
})


def network_imports(tree: ast.AST):
    """``(enclosing_fn, lineno)`` of every import of a network client."""
    out = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names = [node.module]
        if any(n.split(".")[0] in _NETWORK_MODULES for n in names):
            out.append((enclosing_fn(node), node.lineno))
    return out


def test_the_runner_imports_no_network_client():
    violations = [
        f"{rel}:{lineno}  network client imported in {fn!r}"
        for _path, rel, tree in walk_src()
        if rel == _RUNNER
        for fn, lineno in network_imports(tree)
    ]
    assert not violations, (
        "web/embedding_update_runner.py decides staleness from local data only "
        "(installed set vs the manifest shipped in the image); it must not import "
        "a network client:\n  " + "\n  ".join(violations)
    )


def test_network_import_pin_has_teeth():
    for bad in ("import httpx\n", "from urllib.request import urlopen\n",
                "def f():\n    import socket\n", "import urllib3.util\n"):
        assert_pin_has_teeth(network_imports, bad, "import asyncio\nfrom pathlib import Path\n")


# ---------------------------------------------------------------------------
# Reach arms: both callers reach the funnel; the app wires them
# ---------------------------------------------------------------------------

def _tree_of(rel: str) -> ast.AST:
    for _path, r, tree in walk_src():
        if r == rel:
            return tree
    raise AssertionError(f"{rel} not found under src/")


def test_the_click_route_reaches_the_funnel():
    assert "embedding_update" in reachers_of(_tree_of(_ROUTE), "start_runtime_update")


def test_the_automatic_updater_reaches_the_funnel():
    tree = _tree_of(_RUNNER)
    assert "auto_update_once" in reachers_of(tree, "apply_runtime_update")
    for entry in ("start_runtime_update", "apply_runtime_update"):
        assert entry in reachers_of(tree, "_claim"), entry
        assert entry in reachers_of(tree, "_finish"), entry


def test_the_app_wires_the_sweeper_and_the_switch():
    tree = _tree_of("web/app.py")
    supervised = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _name_of(n.func) == "supervise"
        and n.args and isinstance(n.args[0], ast.Constant)
        and n.args[0].value == "embedding-auto-update-sweeper"
    ]
    assert supervised, "the embedding auto-update sweeper is not supervised in web/app.py"
    configured = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _name_of(n.func) == "configure_auto_update"
    ]
    assert configured, "the lifespan must wire embedding.auto_update into embedding_bits"
    # The sweeper's tick (a nested def, passed to the supervised loop) is the
    # one call of the runner's trigger.
    sweeper = _tree_of("web/background_sweepers.py")
    assert any(
        isinstance(n, ast.Call) and _name_of(n.func) == "auto_update_once"
        for n in ast.walk(sweeper)
    ), "background_sweepers.py never calls auto_update_once"
