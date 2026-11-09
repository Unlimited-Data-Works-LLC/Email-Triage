"""Pin: every CLI function that opens the DB read-write wires the audit keys.

Each ``email-triage`` invocation is its own process with an empty HMAC key
registry. A handler that opens the DB and then writes a chained audit row
fails closed (H-02a) unless it wired the keys first. On 2026-11-03 ``user
create`` and ``apikey create`` never did, and the operator-approved mint of
cve-arc's credential failed on the deploy host.

The property is keyed on the OPENER, not on the writer: a function in
``cli.py`` that calls one of ``OPENERS`` must itself call one of ``WIRERS``.
That makes a new opener site fail this pin by default. The wirer set is fixed,
never derived: a helper that reaches the funnel only behind a gate (the
HIPAA-gated, fail-soft ``_emit_cli_audit_event``) does not count (panel 647
SHOULD-1). A read-only site that must not depend on the secrets store goes in
``_READ_ONLY_OPENERS`` with its reason.

Scope (panel 647): ``open_dedicated_conn_readish`` and ``FlowStore`` opens
(``cmd_run`` / ``cmd_watch`` / ``cmd_status``) are not openers here; none of
them reaches a chained writer today, and one that does fails CLOSED (H-02a).
Call order inside a function is not checked; every current site wires right
after the open.

Inverse (PD-5): ``wire_audit_chain_hmac_keys`` is called in ``cli.py`` only
inside the funnel, by any spelling (a bare name, an attribute, an import
alias), so the wiring cannot fork into per-handler copies again.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, assert_pin_has_teeth, enclosing_fn, parse_module

CLI = SRC_ROOT / "cli.py"
OPENERS = frozenset({"_cli_open_config_db", "open_dedicated_conn"})
FUNNEL = "_cli_wire_audit_keys"
WIRERS = frozenset({FUNNEL, "_cli_wire_audit_keys_or_refuse"})
WIRE = "wire_audit_chain_hmac_keys"

_READ_ONLY_OPENERS: dict[str, str] = {
    "_write_restore_witness": (
        "reads the live chain head only, and must still write the witness "
        "marker when the secrets store is unreadable (punch 711)"
    ),
    "_embedding_bits_open_db": (
        "install_state rows only; embedding-bits writes no chained audit row, "
        "and its status/verify verbs must work without the secrets store"
    ),
}


def _aliases(tree: ast.AST) -> dict[str, str]:
    """``import x as y`` / ``from m import x as y`` -> ``{y: x}``."""
    return {
        a.asname: a.name.rsplit(".", 1)[-1] for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names if a.asname
    }


def _callee(call: ast.Call, aliases: dict[str, str]) -> str | None:
    f = call.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
    return aliases.get(name, name) if name else None


def _called_names(fn: ast.AST, aliases: dict[str, str]) -> set[str]:
    return {
        c for n in ast.walk(fn) if isinstance(n, ast.Call)
        if (c := _callee(n, aliases)) is not None
    }


def _functions(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        n.name: n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _calls_by_function(tree: ast.AST) -> dict[str, set[str]]:
    aliases = _aliases(tree)
    return {name: _called_names(fn, aliases) for name, fn in _functions(tree).items()}


def _unwired_openers(tree: ast.AST, allow: dict[str, str] | None = None) -> list[str]:
    allow = _READ_ONLY_OPENERS if allow is None else allow
    return sorted(
        name for name, c in _calls_by_function(tree).items()
        if c & OPENERS and name not in OPENERS | WIRERS
        and not c & WIRERS and name not in allow
    )


def _forked_wiring(tree: ast.AST) -> list[str]:
    aliases = _aliases(tree)
    return sorted(
        f"{enclosing_fn(n)}:{n.lineno}" for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _callee(n, aliases) == WIRE
        and enclosing_fn(n) != FUNNEL
    )


def _tree():
    tree = parse_module(CLI)
    assert tree is not None, f"could not parse {CLI}"
    return tree


def test_every_cli_db_opener_wires_the_audit_keys():
    bad = _unwired_openers(_tree())
    assert not bad, (
        f"these cli.py functions open the DB read-write ({sorted(OPENERS)}) but never "
        f"call {sorted(WIRERS)}: {bad}. Call one right after the open; add to "
        f"_READ_ONLY_OPENERS only for a site that writes no chained audit row, with the reason."
    )


def test_wire_audit_chain_hmac_keys_is_called_only_in_the_funnel():
    bad = _forked_wiring(_tree())
    assert not bad, f"{WIRE}() called outside {FUNNEL}(): {bad}; route it through the funnel"


def test_read_only_entries_are_live():
    calls = _calls_by_function(_tree())
    dead = sorted(n for n in _READ_ONLY_OPENERS if not calls.get(n, set()) & OPENERS)
    assert not dead, f"_READ_ONLY_OPENERS entries no longer open the DB: {dead}; drop them"


def test_pin_has_teeth():
    good = f"""
import email_triage.secrets as s
def {FUNNEL}(conn, config):
    {WIRE}(None, config)
def cmd_a(config):
    db = _cli_open_config_db(config)
    {FUNNEL}(db, config)
def cmd_d(path):
    conn = open_dedicated_conn(path)
    _cli_wire_audit_keys_or_refuse(conn, None)
"""
    # A dedicated read-write open with no wiring (panel 647 MUST: audit reconcile).
    unwired = good + """
def cmd_b(path):
    conn = open_dedicated_conn(path)
"""
    # Reaching the funnel only through a gated helper does not count (SHOULD-1).
    gated = good + f"""
def _emit(config):
    if config.hipaa:
        {FUNNEL}(None, config)
def cmd_e(config):
    db = _cli_open_config_db(config)
    _emit(config)
"""
    forked_attr = good + f"""
def cmd_c(config):
    s.{WIRE}(None, config)
"""
    forked_alias = f"""
from email_triage.secrets import {WIRE} as _w
""" + good + """
def cmd_f(config):
    _w(None, config)
"""
    assert_pin_has_teeth(lambda t: _unwired_openers(t, {}), unwired, good)
    assert_pin_has_teeth(lambda t: _unwired_openers(t, {}), gated, good)
    assert_pin_has_teeth(_forked_wiring, forked_attr, good)
    assert_pin_has_teeth(_forked_wiring, forked_alias, good)
