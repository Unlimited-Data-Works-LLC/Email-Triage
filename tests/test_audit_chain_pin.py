""" / N-15 seam 7 — the INVERSE pin for the audit-event HMAC chain.

PD#1/#3: every SSOT ships its count-agnostic, interprocedural structural pin in
the same change. The chained-audit SSOT is ``db.audit._chain_insert``; this pin
guards it from being BYPASSED (a raw literal ``INSERT INTO <chained_table>`` that
forks the §164.312(b)/(c)(1) HMAC chain), and guards the Option-A canonical-field
contract from silent drift.

Built on the shared ``_pin_harness`` (PD#6 — no hand-rolled walker). Keyed on
"the INSERT targets a chained audit table", NOT on a decorator — per the SME/DA
ruling, ``@audit_emitter`` means gap-event-on-FAILURE, not chained-insert, so a
decorator-keyed net is blind by construction to exactly the writes we must catch.
"""
from __future__ import annotations
from _db_tracking import track

import ast
import re

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    parse_source,
    walk_src,
)
from email_triage.db.audit import _AUDIT_CHAIN_CANONICAL_FIELDS

# The chained audit-EVENT tables = the registry keys (the  SSOT). Distinct
# from the chain-PRIMITIVE tables (log_entries, audit_gap_events) which are
# written by their own inline primitives.
_CHAINED_TABLES = frozenset(_AUDIT_CHAIN_CANONICAL_FIELDS)
_SSOT_FN = "_chain_insert"
_CHAIN_COLS = {"prev_hash", "row_hash", "hash_alg", "master_key_version"}
_PRIMITIVE_TABLES = {"log_entries", "audit_gap_events"}

_INSERT_RE = re.compile(
    r"\bINSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)
_UPDATE_RE = re.compile(
    r"\bUPDATE\s+([A-Za-z_][A-Za-z0-9_]*)\s+SET\b", re.IGNORECASE
)
_SET_COL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _first_str_literal_arg(call: ast.Call) -> str | None:
    """The first string-literal positional arg of an ``.execute()`` call.

    Adjacent string literals are collapsed to one ``ast.Constant`` by the
    parser, so implicit-concatenated SQL ("INSERT INTO x " "(cols)") is matched.
    An f-string is an ``ast.JoinedStr`` (not a Constant) and is intentionally
    NOT matched — that is how ``_chain_insert``'s own ``f"INSERT INTO {table}"``
    stays invisible to this scanner (it is the SSOT, not a bypass).
    """
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def _bypass_inserts(tree: ast.AST):
    """Yield ``(enclosing_fn, table, lineno)`` for every raw literal INSERT into
    a chained audit table whose enclosing function is NOT the SSOT."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in ("execute", "executemany"):
            continue
        sql = _first_str_literal_arg(node)
        if sql is None:
            continue
        m = _INSERT_RE.search(sql)
        if not m:
            continue
        table = m.group(1)
        if table not in _CHAINED_TABLES:
            continue
        fn = enclosing_fn(node)
        if fn == _SSOT_FN:
            continue  # the SSOT itself is the legitimate writer
        out.append((fn, table, node.lineno))
    return out


def _hashed_column_updates(tree: ast.AST):
    """Yield ``(enclosing_fn, table, hashed_cols, lineno)`` for every UPDATE to a
    chained audit table whose SET clause touches a column that IS in that table's
    canonical (hashed) tuple — i.e. an in-place mutation that would silently
    break the chain. Generalises the hipaa_access_events Option-A exclusion to
    EVERY chained table (today only hipaa_access_events has an UPDATE — its
    finalise SETs outcome/detail, both EXCLUDED, so it is chain-transparent; a
    future UPDATE on a hashed column anywhere must be caught)."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in ("execute", "executemany"):
            continue
        sql = _first_str_literal_arg(node)
        if sql is None:
            continue
        m = _UPDATE_RE.search(sql)
        if not m:
            continue
        table = m.group(1)
        if table not in _CHAINED_TABLES:
            continue
        # SET columns = identifiers before '=' in the SET..WHERE span.
        set_span = re.split(r"\bWHERE\b", sql, maxsplit=1, flags=re.IGNORECASE)[0]
        set_span = re.split(r"\bSET\b", set_span, maxsplit=1, flags=re.IGNORECASE)
        set_clause = set_span[1] if len(set_span) > 1 else ""
        set_cols = set(_SET_COL_RE.findall(set_clause))
        hashed = set_cols & set(_AUDIT_CHAIN_CANONICAL_FIELDS[table])
        if hashed:
            out.append((enclosing_fn(node), table, sorted(hashed), node.lineno))
    return out


class TestAuditChainBypassPin:
    def test_no_raw_insert_bypasses_the_chain_ssot(self):
        """No raw literal INSERT to a chained audit table outside _chain_insert.

        A bypass would write a row WITHOUT prev_hash/row_hash — forking the
        HMAC chain (the verifier would see a prechain '' row mid-chain, or a
        following row whose prev_hash links to nothing). Every chained-audit
        write MUST route through _chain_insert.
        """
        violations = []
        for _path, rel, tree in walk_src():
            for fn, table, lineno in _bypass_inserts(tree):
                violations.append(f"{rel}:{lineno}  INSERT {table}  in {fn!r}")
        assert not violations, (
            "PD#3 chain-bypass: raw literal INSERT into a chained audit table "
            "OUTSIDE db.audit._chain_insert (forks the §164.312(c)(1) HMAC "
            "chain):\n  " + "\n  ".join(violations)
            + "\n\nFIX: route the write through _chain_insert(conn, table, "
            "{col: val, ...}) so the row carries its chain columns."
        )

    def test_pin_has_teeth(self):
        """Detector flags a planted raw INSERT to a chained table, and does NOT
        flag a write to a non-chained table."""
        bad = (
            "def some_writer(conn):\n"
            "    conn.execute('INSERT INTO hipaa_access_events (ts) "
            "VALUES (?)', (now,))\n"
        )
        good = (
            "def some_writer(conn):\n"
            "    conn.execute('INSERT INTO triage_runs (ts) VALUES (?)', "
            "(now,))\n"
        )
        assert_pin_has_teeth(
            lambda tree: _bypass_inserts(tree), bad, good
        )

    def test_ssot_itself_is_exempt(self):
        """A raw INSERT to a chained table INSIDE _chain_insert is NOT a
        violation (it is the SSOT). Guards the exemption from a false positive
        if _chain_insert ever used a literal table name for one path."""
        ssot = (
            "def _chain_insert(conn, table, data):\n"
            "    conn.execute('INSERT INTO hipaa_access_events (ts) "
            "VALUES (?)', (now,))\n"
        )
        assert not _bypass_inserts(parse_source(ssot))


class TestNoUpdateMutatesAHashedColumn:
    """The GENERAL Option-A guard (DA impl-review should-fix, done now per
    feedback_dont_over_defer): no UPDATE to ANY chained audit table may SET a
    column that is in that table's canonical (hashed) tuple. The
    hipaa_access_events-specific exclusion test only guards ONE table; this
    catches a FUTURE in-place UPDATE on a hashed column of any of the 8.

    NOTE (DA residual #2 — documented, not closed): both this pin and the
    bypass pin match string-LITERAL SQL only (ast.Constant). An f-string with a
    dynamic table name is invisible BY DESIGN (it is how _chain_insert's own
    f"INSERT INTO {table}" is exempt). A future dynamic-table writer to a chained
    table is therefore a structural blind spot of the literal scanner; the
    registry-vs-live-schema test + the  gap-coverage pin are the partial
    backstop. Grep confirms no such dynamic writer exists today.
    """

    def test_no_chained_table_update_touches_a_hashed_column(self):
        violations = []
        for _path, rel, tree in walk_src():
            for fn, table, hashed, lineno in _hashed_column_updates(tree):
                violations.append(
                    f"{rel}:{lineno}  UPDATE {table} SET {hashed}  in {fn!r}"
                )
        assert not violations, (
            "An UPDATE mutates a HASHED column of a chained audit table — this "
            "silently breaks the §164.312(c)(1) chain (the row_hash no longer "
            "matches its content):\n  " + "\n  ".join(violations)
            + "\n\nFIX: either move the column OUT of the table's canonical "
            "tuple in _AUDIT_CHAIN_CANONICAL_FIELDS (if it is legitimately a "
            "mutable lifecycle field, like hipaa_access_events.outcome/detail "
            "under Option A), or stop mutating it in place (append a new chained "
            "row instead)."
        )

    def test_pin_has_teeth(self):
        """Flags an UPDATE on a hashed column (ts); does NOT flag an UPDATE on
        an excluded column (outcome, the real finalise shape)."""
        bad = (
            "def f(conn):\n"
            "    conn.execute('UPDATE hipaa_access_events SET ts = ? "
            "WHERE id = ?', (t, i))\n"
        )
        good = (
            "def f(conn):\n"
            "    conn.execute('UPDATE hipaa_access_events SET outcome = ?, "
            "detail = ? WHERE id = ?', (o, d, i))\n"
        )
        assert_pin_has_teeth(
            lambda tree: _hashed_column_updates(tree), bad, good
        )


class TestAuditChainRegistryContract:
    def test_registry_matches_the_live_chained_schema(self):
        """Count-agnostic completeness: the registry keys == exactly the tables
        that carry all 4 chain columns in the live schema (minus the two
        chain-primitive tables). Catches a new chained table with no registry
        entry, OR a registry entry whose table lost its chain columns."""
        from email_triage.web.db import init_db
        conn = track(init_db(":memory:"))
        try:
            live = set()
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall():
                cols = {
                    r[1] for r in conn.execute(
                        f"PRAGMA table_info({name})"
                    ).fetchall()
                }
                if _CHAIN_COLS <= cols and name not in _PRIMITIVE_TABLES:
                    live.add(name)
        finally:
            conn.close()
        assert live == _CHAINED_TABLES, (
            f"registry/schema drift — in schema not registry: "
            f"{sorted(live - _CHAINED_TABLES)}; in registry not schema: "
            f"{sorted(_CHAINED_TABLES - live)}"
        )

    def test_hipaa_access_events_excludes_mutable_fields(self):
        """Option A contract: the canonical tuple for hipaa_access_events must
        EXCLUDE outcome + detail, the fields update_hipaa_access_event mutates
        in place. Including a mutable field would make the finalise UPDATE break
        the chain (the whole reason Option A exists)."""
        fields = set(_AUDIT_CHAIN_CANONICAL_FIELDS["hipaa_access_events"])
        assert "outcome" not in fields
        assert "detail" not in fields

    def test_every_canonical_field_is_a_real_column(self):
        """No phantom field: every registry field must be an actual column of
        its table, or _chain_insert's ``data[name]`` KeyErrors at runtime."""
        from email_triage.web.db import init_db
        conn = track(init_db(":memory:"))
        try:
            problems = []
            for table, fields in _AUDIT_CHAIN_CANONICAL_FIELDS.items():
                cols = {
                    r[1] for r in conn.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()
                }
                missing = set(fields) - cols
                if missing:
                    problems.append(f"{table}: {sorted(missing)}")
        finally:
            conn.close()
        assert not problems, f"registry names non-existent columns: {problems}"


def test_anti_drift_chained_set_matches_288_emitter_routed_tables():
    """The  gap-coverage pin keys on _EMITTER_ROUTED_TABLES; the  chain
    pin keys on the registry. They describe the same audit-event tables from two
    angles — assert they agree so the two table-sets cannot silently diverge."""
    try:
        from test_web.test_288_phase3_d3_audit_gap import (
            TestInverseAuditEmitterPin,
        )
    except Exception as exc:  # pragma: no cover - must fail loud, never silently skip
        pytest.fail(
            "could not import the  emitter-routed table set from "
            f"test_web.test_288_phase3_d3_audit_gap: {exc!r}. This HIPAA anti-drift "
            "guard FAILS LOUD by design — a silent skip here would let the  and "
            " audit-table sets diverge undetected if the source were renamed/moved."
        )
    emitter_routed = set(TestInverseAuditEmitterPin._EMITTER_ROUTED_TABLES)
    assert emitter_routed == set(_CHAINED_TABLES), (
        "the  emitter-routed table set and the  chained-table registry "
        f"diverged —  only: {sorted(emitter_routed - set(_CHAINED_TABLES))}; "
        f" only: {sorted(set(_CHAINED_TABLES) - emitter_routed)}"
    )
