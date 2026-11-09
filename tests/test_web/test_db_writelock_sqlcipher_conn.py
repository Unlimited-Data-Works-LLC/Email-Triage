"""Punch 921 / panel r17 db-sme SHOULD-B4.

``@db_write`` rolls back a dangling transaction only when ``_find_connection``
recognises the connection. ``sqlcipher3`` (the encrypted-at-rest driver) has
its own ``Connection`` class, not a stdlib ``sqlite3.Connection`` subclass, so
a stdlib-only isinstance check skipped the rollback on every encrypted install.
"""

from __future__ import annotations

import ast
import sqlite3

import pytest

from _pin_harness import iter_src_files, parse_module, relpath
from email_triage.web.db_writelock import _CONN_TYPES, _find_connection, db_write


def test_stdlib_connection_found():
    c = sqlite3.connect(":memory:")
    assert _find_connection((c,), {}) is c
    assert _find_connection((), {"conn": c}) is c


def test_sqlcipher_connection_found_and_rolled_back(tmp_path):
    sqlcipher_dbapi2 = pytest.importorskip("sqlcipher3.dbapi2")
    assert sqlcipher_dbapi2.Connection in _CONN_TYPES
    c = sqlcipher_dbapi2.connect(str(tmp_path / "e.db"))
    c.execute("PRAGMA key = 'k'")
    c.execute("CREATE TABLE t (x INTEGER)")
    c.commit()
    assert _find_connection((c,), {}) is c

    @db_write
    def boom(conn):
        conn.execute("INSERT INTO t VALUES (1)")
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        boom(c)
    assert not c.in_transaction, "rollback skipped on a sqlcipher3 connection"
    assert c.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0


def _stdlib_conn_isinstance_lines(tree: ast.AST) -> list[int]:
    """Lines of ``isinstance(x, <stdlib Connection>)`` where the type operand
    names only the stdlib class: ``sqlite3.Connection``, a name bound by
    ``from sqlite3 import Connection [as C]``, or a tuple holding either with
    no sqlcipher member (r17 db-sme SHOULD-B7)."""
    aliases = {
        a.asname or a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module == "sqlite3"
        for a in n.names if a.name == "Connection"
    }

    def is_stdlib(e: ast.AST) -> bool:
        if (isinstance(e, ast.Attribute) and e.attr == "Connection"
                and isinstance(e.value, ast.Name) and e.value.id == "sqlite3"):
            return True
        return isinstance(e, ast.Name) and e.id in aliases

    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "isinstance" and len(node.args) == 2):
            continue
        t = node.args[1]
        elts = t.elts if isinstance(t, ast.Tuple) else [t]
        if any(is_stdlib(e) for e in elts) and not any(
                "sqlcipher" in ast.unparse(e) for e in elts):
            out.append(node.lineno)
    return out


def test_no_stdlib_only_connection_isinstance_in_src():
    """Count-agnostic: no src isinstance check names ``sqlite3.Connection``
    alone (it silently misses sqlcipher3 connections). Use ``_CONN_TYPES``."""
    bad = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        bad += [f"{relpath(path)}:{ln}" for ln in _stdlib_conn_isinstance_lines(tree)]
    assert not bad, f"stdlib-only Connection isinstance (misses sqlcipher3): {bad}"


def test_stdlib_conn_isinstance_pin_has_teeth():
    assert _stdlib_conn_isinstance_lines(
        ast.parse("import sqlite3\nisinstance(c, sqlite3.Connection)\n")) == [2]
    assert _stdlib_conn_isinstance_lines(
        ast.parse("from sqlite3 import Connection as C\nisinstance(c, C)\n")) == [2]
    assert _stdlib_conn_isinstance_lines(
        ast.parse("import sqlite3\nisinstance(c, (sqlite3.Connection, int))\n")) == [2]
    assert _stdlib_conn_isinstance_lines(
        ast.parse("isinstance(c, (sqlite3.Connection, sqlcipher3.dbapi2.Connection))\n")) == []
    assert _stdlib_conn_isinstance_lines(
        ast.parse("isinstance(c, _CONN_TYPES)\n")) == []
