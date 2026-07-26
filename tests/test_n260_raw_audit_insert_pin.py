"""N-260 R26 structural pin — raw INSERT into audit tables outside SSOT (2026-07-03).

Census R26 discovered MED (audit-emit N-182b residual): the SQLite
audit-chain has 3 known-legit raw `INSERT INTO log_entries` sites —
`triage_logging.SQLiteLogHandler.emit` (two shapes for the with/without
extra chain-write) and `db/audit.insert_log_entry` (the SSOT-shaped
programmatic writer). New raw INSERTs into any of the chained audit
tables outside those sites would fork the HMAC chain OR bypass
`@audit_emitter`'s redaction map.

N-342 R31 (2026-07-08 Phase-4 journal triage HIGH #1 close): `_AUDIT_TABLES`
derives from `db/audit.py::_AUDIT_CHAIN_CANONICAL_FIELDS.keys()` (SSOT
import at collect time) + `log_entries` — closes the pre-N-342 blind
class where the hardcoded list missed `api_key_events`, `access_log`,
`discover_runs`, `regulatory_clock_event` (all landed later than N-260's
2026-07-03 baseline). New chained tables auto-enroll (PD #1 + PD #5).

N-260 lands the STRICT-0 pin at baseline 3. Any NEW raw INSERT into
`log_entries` OR any table in the `_AUDIT_CHAIN_CANONICAL_FIELDS` SSOT
outside the allow-list fires.

WHAT IT PINS (count-agnostic):

Any `conn.execute("INSERT INTO <audit_table> ...")` outside the
allow-list is a defect. Route through the `@audit_emitter`-decorated
helper for that table.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    enclosing_qualified_name,
    iter_files,
    parse_module,
    relpath,
)


# N-342-n260 (2026-07-08, Phase-4 journal triage HIGH #1 close-out):
# widen `_AUDIT_TABLES` to derive from the `_AUDIT_CHAIN_CANONICAL_FIELDS`
# SSOT (`src/email_triage/db/audit.py`) so every chained audit table is
# covered — including `api_key_events`, `access_log`, `discover_runs`,
# `regulatory_clock_event` which the pre-N-342 hardcoded list was blind
# to. A NEW chained table added to the SSOT auto-enrolls in the pin
# without a manual edit (PD #1 + PD #5).
#
# `log_entries` stays hardcoded because it does NOT live in
# `_AUDIT_CHAIN_CANONICAL_FIELDS` — it has its own chain-write path via
# `SQLiteLogHandler.emit` and `insert_log_entry` (both allow-listed
# below); the SSOT is scoped to the `_chain_insert`-tabled surface.
def _load_audit_tables() -> tuple[str, ...]:
    """Return the union of `log_entries` + every table in
    `_AUDIT_CHAIN_CANONICAL_FIELDS.keys()`. Import at collect time so a
    future chained-table addition to the SSOT trips the STRICT-0 pin
    without a hand-edit here (N-342 R31 SSOT-derived widening)."""
    from email_triage.db.audit import _AUDIT_CHAIN_CANONICAL_FIELDS
    ssot_tables = tuple(sorted(_AUDIT_CHAIN_CANONICAL_FIELDS.keys()))
    return ("log_entries",) + ssot_tables


_AUDIT_TABLES = _load_audit_tables()
_INSERT_RE = re.compile(
    r"\bINSERT\s+INTO\s+(" + "|".join(_AUDIT_TABLES) + r")\b",
    re.IGNORECASE,
)

# Known-legit chain-writer sites — the ONE class-qualified function per
# module that owns the raw INSERT (regardless of how many INSERT strings
# it contains). Keyed on ``(relpath, enclosing_qualified_name)`` so an
# unrelated edit above / below the site cannot shift the allow-list
# match, AND same-name methods on different classes stay disambiguated
# (``SQLiteLogHandler.emit`` vs a hypothetical ``OtherHandler.emit``).
#
# Drift lineage (N-260 line-shift history captured for the pattern log):
# * pre-N-300: (triage_logging.py, 736) + (triage_logging.py, 818)
# * N-311 R30 (post-N-300): 736 → 769, 818 → 851
# * N-341 R31 (post-N-338): 769 → 846, 851 → 928
# * N-341b (this migration, 2026-07-04): drop line numbers entirely.
#   The two triage_logging sites collapse to ONE entry because both live
#   inside ``SQLiteLogHandler.emit`` — fewer entries, same coverage,
#   drift-immune. If a NEW class in the same file grows a raw
#   ``INSERT INTO log_entries`` inside its own ``emit`` method, the pin
#   FIRES (that offender's qualified name is not on the list) —
#   exactly the STRICT-0 contract N-260 was written to enforce.
_ALLOW: frozenset[tuple[str, str]] = frozenset({
    ("triage_logging.py", "SQLiteLogHandler.emit"),  # covers 2 raw INSERT INTO log_entries branches (with/without extra chain-write)
    ("db/audit.py", "insert_log_entry"),             # @audit_emitter-decorated SSOT programmatic writer
})


def test_no_raw_audit_table_insert_outside_ssot():
    """STRICT-0 count-agnostic: any `INSERT INTO <audit-table>` string
    constant outside the allow-list fires."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            m = _INSERT_RE.search(node.value)
            if m is None:
                continue
            qname = enclosing_qualified_name(node)
            if (rel, qname) in _ALLOW:
                continue
            offenders.append(
                f"{rel}:{node.lineno} ({qname}) INSERT INTO {m.group(1)} — "
                "route through the @audit_emitter-decorated helper"
            )
    assert not offenders, (
        "N-260 R26 audit-table SSOT bypass: raw `INSERT INTO <audit-"
        "table>` outside the allow-list forks the HMAC chain or "
        "bypasses the @audit_emitter redaction map. Route through the "
        "helper for that table (see `db/audit.py` for the "
        "@audit_emitter-decorated family). If a legit new chain-writer "
        "must land, add its "
        "``(relpath, enclosing_qualified_name)`` to `_ALLOW` with a "
        "reason (fn-scope keying survives line shifts; PD #1 count-"
        "agnostic).\n\n"
        + "\n".join(offenders)
    )
