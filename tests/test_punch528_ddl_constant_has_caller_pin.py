"""Punch : every ``_*_DDL`` schema constant in ``src/email_triage`` is used.

``db/audit.py`` carried ``_AUDIT_GAP_EVENT_DDL``, a copy of the
``audit_gap_events`` schema that nothing ran. The table is created only by
migration v38 (``web/migrations.py``). Three panel seats cited the copy as the
live schema during punch , and a schema fix made in it would not have taken
effect. The constant is deleted; migration v38 is the single source.

INVARIANT (count-agnostic, a property over every site): every module-level
assignment to a name shaped ``_<UPPER>_DDL`` anywhere under ``src/email_triage``
is READ somewhere under ``src/email_triage``: a ``Name`` in load context or an
attribute access with that name. An ``import`` of the name alone does not count,
so a constant imported and never used is still flagged. A name in a string or a
comment does not count either.

Scope, stated: this proves a constant is referenced, not that the reference
reaches a code path that executes DDL. A constant read by dead code passes.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import parse_source, walk_src

_DDL_NAME = re.compile(r"^_[A-Z0-9_]+_DDL$")


def _ddl_definitions(modules):
    """``{name: [(relpath, lineno), ...]}`` for every module-level ``_*_DDL``."""
    defs: dict[str, list[tuple[str, int]]] = {}
    for rel, tree in modules:
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            for tgt in targets:
                if isinstance(tgt, ast.Name) and _DDL_NAME.match(tgt.id):
                    defs.setdefault(tgt.id, []).append((rel, node.lineno))
    return defs


def _ddl_reads(modules):
    """Every ``_*_DDL`` name that is READ (load-context Name or attribute)."""
    reads: set[str] = set()
    for _rel, tree in modules:
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            else:
                continue
            if _DDL_NAME.match(name):
                reads.add(name)
    return reads


def _orphans(modules):
    """``[(relpath, lineno, name)]`` for every ``_*_DDL`` constant nobody reads."""
    modules = list(modules)
    defs = _ddl_definitions(modules)
    reads = _ddl_reads(modules)
    return sorted(
        (rel, line, name)
        for name, sites in defs.items()
        if name not in reads
        for rel, line in sites
    )


def _src_modules():
    return [(rel, tree) for _path, rel, tree in walk_src()]


def test_scan_covers_the_audit_ddl_constants():
    """Positive control: the scan finds DDL constants, including in db/audit.py.

    Without this, a broken regex or an empty walk would find no constants and
    the pin below would pass on nothing.
    """
    defs = _ddl_definitions(_src_modules())
    assert defs, "found no _*_DDL constants under src/email_triage; the scan is broken"
    homes = {rel for sites in defs.values() for rel, _line in sites}
    assert "db/audit.py" in homes, (
        "found no _*_DDL constant in db/audit.py; the module this pin was written "
        f"for is outside the scan. Homes found: {sorted(homes)}"
    )


def test_every_ddl_constant_is_read_somewhere():
    orphans = _orphans(_src_modules())
    assert not orphans, (
        "These _*_DDL schema constants are defined but never read. An unread "
        "schema copy does not run, so a fix made in it does not take effect "
        "(punch #528). Delete it and keep the migration as the single source, "
        "or wire it into the list that runs it:\n"
        + "\n".join(f"  {rel}:{line} {name}" for rel, line, name in orphans)
    )


def test_teeth_flags_an_unread_constant():
    planted = parse_source('_PLANTED_DDL = "CREATE TABLE t (id INTEGER)"\n')
    assert _orphans([("db/planted.py", planted)]) == [
        ("db/planted.py", 1, "_PLANTED_DDL")
    ]


def test_teeth_import_alone_is_not_a_read():
    home = parse_source('_PLANTED_DDL = "CREATE TABLE t (id INTEGER)"\n')
    importer = parse_source("from email_triage.db.planted import _PLANTED_DDL\n")
    assert _orphans([("db/planted.py", home), ("web/x.py", importer)]) == [
        ("db/planted.py", 1, "_PLANTED_DDL")
    ]


def test_teeth_a_read_in_another_module_satisfies_the_pin():
    home = parse_source('_PLANTED_DDL = "CREATE TABLE t (id INTEGER)"\n')
    user = parse_source(
        "from email_triage.db.planted import _PLANTED_DDL\n"
        "def init_db(conn):\n"
        "    conn.executescript(_PLANTED_DDL)\n"
    )
    assert _orphans([("db/planted.py", home), ("web/x.py", user)]) == []
