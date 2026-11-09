"""N-522's exploitability bound, pinned: no FTS index and no json1 / MATCH query in src (punch 551).

N-522 (the SQLCipher C library and the SQLite amalgamation it embeds are matched
to no vulnerability feed) is graded MEDIUM, not HIGH, on a measured bound: the
application builds no FTS virtual table and issues no ``MATCH`` and no json1
function in its SQL, so the SQLite CVE families that live in those extensions
have nothing in this codebase to reach. The row's own re-score trigger is "the
moment any FTS or json1 query over message content is added". Until this pin,
that trigger was a sentence: the bound was a one-time grep, and the next commit
could invalidate it silently (538 fold-check hipaa ``H538FC-4``, 2026-09-29).

WHAT IS ASSERTED, over every module the shared harness walks (count-agnostic,
PD-1; docstrings exempt, because prose must be able to name what code may not
do). Widened at the punch 539 fold-check (hipaa H539FC-6, db DB-539FC-6, da
DA-FC551-1) from an enumerated deny-list to SHAPES, each arm with teeth:

* no code string names an FTS module (``fts3`` / ``fts4`` / ``fts5``,
  ``USING fts…``) or a ``VIRTUAL TABLE``, in any case;
* no code string that reads as SQL uses ``MATCH``, a json1/JSONB function or a
  JSON arrow. A string reads as SQL when it carries an UPPER-case keyword
  (``SELECT``, ``FROM``, ``WHERE``, ``JOIN``, ``INSERT INTO``, ``UPDATE``,
  ``DELETE FROM``, ``ORDER BY``, ``GROUP BY``, ``CREATE [VIRTUAL|UNIQUE]
  TABLE|INDEX|TRIGGER|VIEW``, ``ALTER TABLE``, ``GENERATED ALWAYS``) OR a
  lower-case statement shape (``select … from``, ``insert into``,
  ``delete from``, ``update <t> set``, ``create [unique] table|index|trigger|
  view``, ``alter table``). The needles are: upper-case ``MATCH``, or any-case
  ``<column> match`` followed by a bind parameter or a quote; ANY
  ``json…(`` / ``jsonb…(`` call by shape (``json(``, ``jsonb(``, ``json_pretty(``,
  ``json_error_position(``, ``jsonb_extract(`` and every name not yet invented);
  and ``->`` / ``->>`` followed by a literal, a number or a bind parameter. An
  expression index or a generated column over a json function is caught by the
  ``CREATE INDEX`` / ``ALTER TABLE`` / ``GENERATED ALWAYS`` gate plus the json arm;
* no ORM expression calls a json function: an attribute named ``json…`` /
  ``jsonb…`` on a receiver named ``func`` (``sqlalchemy.func.json_extract``,
  ``sa.func.jsonb_extract``).

WHAT IS NOT: SQL assembled at run time from pieces none of which carries a gate
keyword AND a needle; a needle-bearing fragment with no keyword, interpolated
into a SELECT held elsewhere; an arrow whose right operand is a column
(``a -> b``, excluded on purpose: it is also Python-type-hint prose); an ORM
json call not spelled through ``func``; SQL issued outside ``src/email_triage/``
(``alembic/`` and ``scripts/`` held none at 2026-09-30); an FTS table already
present in a live database's schema; eponymous virtual tables that need no
CREATE (``json_each`` is caught as a json call; ``dbstat`` / ``pragma_*`` are
not); and a native SQLite extension loaded with no SQL at all (``web/app.py``
loads ``sqlite_vec`` when importable; it is in no lock or manifest, so dormant).

A FAILURE HERE IS NOT A BUG REPORT. It means N-522's MEDIUM grade no longer
rests on a true premise: re-score N-522 (``internal documentation``)
with hipaa-sme before the change lands, and only then allow-list the site here
with the re-score cited.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    assert_pin_has_teeth,
    docstring_constant_ids,
    iter_string_literals,
    parse_source,
    walk_src,
)

FTS_NEEDLE = re.compile(r"\bfts[345]\b|\busing\s+fts|\bvirtual\s+table\b", re.IGNORECASE)

#: A string "reads as SQL" when it carries an UPPER-case keyword (SQL in this
#: codebase is written upper-case) or a lower-case STATEMENT shape. A bare
#: lower-case ``from`` / ``where`` / ``match`` is prose ("match the sender from
#: the list") and is deliberately not a gate on its own.
SQL_KEYWORD = re.compile(
    r"\b(SELECT|INSERT INTO|UPDATE|DELETE FROM"
    r"|CREATE (?:VIRTUAL |UNIQUE )?(?:TABLE|INDEX|TRIGGER|VIEW)"
    r"|ALTER TABLE|GENERATED ALWAYS|FROM|WHERE|JOIN|ORDER BY|GROUP BY)\b"
    r"|(?i:\bselect\b[\s\S]*?\bfrom\b|\binsert\s+into\b|\bdelete\s+from\b"
    r"|\bupdate\s+\w+\s+set\b|\bcreate\s+(?:virtual\s+|unique\s+)?(?:table|index|trigger|view)\b"
    r"|\balter\s+table\b)"
)

#: The needles, by SHAPE. ``MATCH`` upper-case anywhere in SQL, or any-case
#: ``<col> match`` before a bind parameter / quote; any json/jsonb call; an arrow
#: before a literal, a number or a bind parameter.
JSON1_OR_MATCH = re.compile(
    r"\bMATCH\b"
    r"|(?i:\b[\w.\"]+\s+match\s+(?:\?|'|:\w|\$))"
    r"|(?i:\bjsonb?(?:_\w+)?\s*\()"
    r"|->>?\s*(?:'|\?|\d)"
)

#: An ORM json call: ``func.json_extract`` / ``sa.func.jsonb_extract``.
ORM_JSON_ATTR = re.compile(r"(?i)^jsonb?(?:_\w+)?$")

#: Sites that have been re-scored against N-522 by hipaa-sme. Key: repo-relative
#: path; value: the re-score citation. Empty by construction at 2026-09-30.
RESCORED: dict[str, str] = {}


def code_strings(tree: ast.AST) -> list[str]:
    """Every string the CODE in ``tree`` carries (f-strings and ``+`` joins
    reconstructed by the harness), minus the docstrings."""
    ids = docstring_constant_ids(tree)
    doc_texts = {n.value for n in ast.walk(tree) if id(n) in ids}
    return [s for s in iter_string_literals(tree) if s not in doc_texts]


def orm_json_calls(tree: ast.AST) -> list[str]:
    """``func.json…`` attribute references, whatever the ``func`` receiver's path."""
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not ORM_JSON_ATTR.match(node.attr):
            continue
        recv = node.value
        recv_name = recv.id if isinstance(recv, ast.Name) else (
            recv.attr if isinstance(recv, ast.Attribute) else ""
        )
        if recv_name == "func":
            out.append(f"func.{node.attr}")
    return out


def offending_strings(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for s in code_strings(tree):
        m = FTS_NEEDLE.search(s)
        if not m and SQL_KEYWORD.search(s):
            m = JSON1_OR_MATCH.search(s)
        if m:
            out.append(f"{m.group(0)!r} in {s.strip()[:80]!r}")
    out.extend(orm_json_calls(tree))
    return out


def test_no_fts_index_or_json1_query_in_src():
    scanned = 0
    offenders: dict[str, list[str]] = {}
    for _path, rel, tree in walk_src():
        scanned += 1
        hits = offending_strings(tree)
        if hits and rel not in RESCORED:
            offenders[rel] = hits
    assert scanned > 100, f"the harness walked only {scanned} modules; the scan is mis-wired"
    assert not offenders, (
        f"{offenders}: an FTS index or a json1/MATCH query is now in src. N-522 is "
        f"graded MEDIUM on the premise that neither exists, so its grade is stale. "
        f"Re-score N-522 with hipaa-sme BEFORE this lands, then add the site to "
        f"RESCORED with that citation (punch 551, 538 fold-check H538FC-4)."
    )


def test_the_detector_has_teeth():
    """Each arm FLAGS a planted shape and passes the prose and Python look-alikes
    that exist in this codebase today. The punch-539 fold-check rows are the
    escapes hipaa (H539FC-6), db (DB-539FC-6) and da (DA-FC551-1) measured
    against the first version of this pin."""
    clean = (
        'import json\n'
        'def f(conn):\n'
        '    """Never builds an fts5 VIRTUAL TABLE and never uses json_extract()."""\n'
        '    prompt = "Match each article FROM the newsletter"\n'
        '    hint = "select a folder from the list to match senders"\n'
        '    fmt = {"type": "json_object"}\n'
        '    data = json.loads("{}")\n'
        '    arrow = "SELECT a -> b FROM t"\n'
        '    return conn.execute("SELECT id FROM messages WHERE account_id = ?")\n'
    )
    for bad in (
        # the original arms
        'conn.execute("CREATE VIRTUAL TABLE m USING fts5(body)")\n',
        'conn.execute("SELECT rowid FROM m WHERE m MATCH ?")\n',
        'conn.execute("SELECT json_extract(body, \'$.x\') FROM messages")\n',
        'conn.execute(f"SELECT id FROM t WHERE {col} ->> \'$.subject\' = ?")\n',
        # JSONB and the unlisted json1 names (H539FC-6)
        'conn.execute("SELECT jsonb_extract(b, \'$.x\') FROM m")\n',
        'conn.execute("UPDATE t SET j = jsonb(?) WHERE id = ?")\n',
        'conn.execute("SELECT json_pretty(meta) FROM t")\n',
        'conn.execute("SELECT json_error_position(?) FROM t")\n',
        # label, index and bind-parameter arrow operands
        'conn.execute("SELECT id FROM m WHERE h ->> \'subject\' = ?")\n',
        'conn.execute("SELECT meta -> 0 FROM t")\n',
        'conn.execute("SELECT id FROM m WHERE h ->> ? = ?")\n',
        # lower-case SQL
        'conn.execute("select json_extract(b, \'$.a\') from messages")\n',
        'conn.execute("select id from m where m match ?")\n',
        # expression index, generated column, trigger body (DB-539FC-6)
        'conn.execute("CREATE INDEX ix ON messages(json_extract(body, \'$.s\'))")\n',
        'conn.execute("create index ix on messages(json_extract(body, \'$.s\'))")\n',
        'conn.execute("ALTER TABLE m ADD COLUMN s GENERATED ALWAYS AS (json_extract(b, \'$.s\'))")\n',
        'conn.execute("CREATE TRIGGER t AFTER INSERT ON m BEGIN SELECT json_valid(NEW.b); END")\n',
        # ORM json calls (DA-FC551-1)
        'from sqlalchemy import func\nq = func.json_extract(col, "$.a")\n',
        'import sqlalchemy as sa\nq = sa.func.jsonb_extract(col, "$.a")\n',
    ):
        assert_pin_has_teeth(offending_strings, bad, clean)
    # the docstring exemption is real, not accidental
    assert offending_strings(parse_source(clean)) == []
