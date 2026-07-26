"""Schema-version READ — count-agnostic structural pin (census run15 ).

The applied-schema-version read off a connection (``MAX(version)`` from
``schema_migrations``) must live in ONE place: ``version.read_schema_version``
(the pure, side-effect-free SSOT; ``version.read_db_schema_version`` is its
path-based entry point and delegates to it). Before this fix the raw
``SELECT MAX(version) FROM schema_migrations`` was ALSO inlined in
``web/daily_health.py`` (the banner render) — an intra-file divergence in the
same family as the schema=1 manifest bug.

Note the migration FRAMEWORK reader (``web.migrations.schema_version`` →
``applied_versions``) is a DIFFERENT concern: it ``_ensure_bookkeeping``
(CREATEs the table) and computes ``max()`` in Python from a
``SELECT version, name, … FROM schema_migrations`` — it does NOT use the raw
``MAX(version)`` SQL, so it is not a fork of this idiom and is not flagged.

INVARIANT: the raw ``MAX(version)`` … ``schema_migrations`` SELECT appears only
in ``version.py``. A banner/health/CLI path that needs the version must call
``version.read_schema_version(conn)`` (or ``read_db_schema_version(path)``).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import iter_src_files, parse_module, relpath

_SSOT_RELPATH = "version.py"
# A raw max-applied-version read: a string literal naming MAX(version) and the
# schema_migrations table together.
_RAW_MAXVER = re.compile(r"MAX\s*\(\s*version\s*\)", re.IGNORECASE)


def _raw_maxver_literals(tree: ast.AST) -> list[int]:
    out: list[int] = []
    for node in ast.walk(tree):
        text = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
        if text and _RAW_MAXVER.search(text) and "schema_migrations" in text:
            out.append(node.lineno)
    return out


def test_raw_max_version_read_only_in_version_module():
    offenders = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_RELPATH:
            continue
        locs = _raw_maxver_literals(parse_module(path))
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "a raw `MAX(version) FROM schema_migrations` read is inlined outside the "
        f"SSOT version.py: {offenders}. Call version.read_schema_version(conn) "
        "(or read_db_schema_version(path)) — a re-inlined banner read drifts from "
        "the SSOT's None/missing-table handling (census run15 ). The migration "
        "framework's own read (migrations.schema_version) is a different concern "
        "and does not use this MAX(version) idiom."
    )


def test_ssot_actually_holds_the_read():
    """Anti-vacuity: version.py must still carry the raw read, else the
    invariant is vacuously true."""
    from _pin_harness import SRC_ROOT
    locs = _raw_maxver_literals(parse_module(SRC_ROOT / "version.py"))
    assert locs, "the MAX(version) read vanished from version.py — pin is vacuous"


def test_pin_has_teeth():
    bad = ast.parse('row = c.execute("SELECT MAX(version) FROM schema_migrations")\n')
    assert _raw_maxver_literals(bad)
    badf = ast.parse('row = c.execute(f"SELECT MAX(version) FROM {tbl}schema_migrations")\n')
    assert _raw_maxver_literals(badf)
    # A different MAX() or a different table is NOT this idiom.
    ok = ast.parse('row = c.execute("SELECT MAX(id) FROM other_table")\n')
    assert not _raw_maxver_literals(ok)
    ok2 = ast.parse('row = c.execute("SELECT version, name FROM schema_migrations")\n')
    assert not _raw_maxver_literals(ok2)
