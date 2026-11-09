"""N-417 Drive-2 close-out #6 — `web/migrations.py` no-projection-double-write SSOT pin.

`web/migrations.py:3919-3924` (migration -era regulatory-clock table
docstring) declares `regulatory_clock_event` the *"single source of truth
(no projection double-write)"* for the §164.316(b)(2)(i)-retention audit
chain — the durable §164.312(b) audit-integrity chain for regulatory-clock
row lifecycle. A second table that projects rows from this chain would
fork the audit chain: a §164.316(b)(2)(i) 6-year retention window mismatch
between the SSOT table (never pruned) and its projection (subject to the
`log_entries` retention sweep) would silently invalidate the projection
row before the SSOT row's window elapses.

Divergence class this pin locks:

  **Unauthorized ownership of the `regulatory_clock_event` name.** Only
  three src modules may reference the table by name in a string literal:

    - `web/migrations.py` — the schema SSOT (CREATE TABLE + column
      contract + initial seed).
    - `db/audit.py` — the sole runtime writer via `_chain_insert(conn,
      "regulatory_clock_event", ...)` and the `HmacChainedTable` column
      declaration.
    - `db/regulatory_clock.py` — the reader logic (SELECT / view helpers).

  Any OTHER src module holding a string literal containing
  `"regulatory_clock_event"` is a projection-candidate: either a hand-
  rolled INSERT (silent second writer with different HMAC-hop logic) or
  a shadow CREATE TABLE (projection destination). Refuse.

Reuses `_pin_harness` per PD#6. Rot-guard PD#7 on `_EMITTER_ALLOW`.
Teeth via planted-fake string literal outside the allow-list.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_TABLE_NAME_NEEDLE = "regulatory_clock_event"


# Three src modules ALLOWED to reference the table by name. Each is a
# load-bearing SSOT owner (schema / writer / reader). Rot-guarded PD#7.
_EMITTER_ALLOW: dict[str, str] = {
    "web/migrations.py": (
        "schema SSOT — CREATE TABLE + column contract + initial seed for "
        "the HMAC-chained table."
    ),
    "db/audit.py": (
        "runtime writer SSOT — `_chain_insert(conn, 'regulatory_clock_event', "
        "...)` is the sole INSERT emitter; also declares the "
        "`HmacChainedTable` column set for chain-verify."
    ),
    "db/regulatory_clock.py": (
        "reader SSOT — SELECT / view helpers over the chained table; "
        "no writes."
    ),
}


def _module_string_literals(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue):
                    parts.append("{}")
            yield node.lineno, "".join(parts)


def test_regulatory_clock_event_name_only_in_ssot_owners():
    """Only `web/migrations.py` + `db/audit.py` + `db/regulatory_clock.py`
    may hold a string literal containing `regulatory_clock_event`. A twin
    reference in any other src module is a projection candidate — either
    a hand-rolled INSERT (silent second writer with different HMAC-hop
    logic) or a shadow CREATE TABLE.
    """
    import os as _os
    sql_shape_only = _os.environ.get("PIN_N417_SQL_SHAPE_ONLY") == "1"
    # N-409 Drive-4 refinement (db-sme note #4): recognize the SQL-shape
    # contexts a real projection would emit (`INSERT INTO … regulatory_clock_event`,
    # `CREATE TABLE … regulatory_clock_event`, `SELECT … FROM regulatory_clock_event`,
    # `UPDATE regulatory_clock_event`, `DELETE FROM regulatory_clock_event`). By
    # default the check REMAINS broad (any string containing the needle
    # flags) — no HEAD offenders exist, and a narrower net would risk
    # missing a hand-rolled writer that assembles SQL from fragments. Set
    # ``PIN_N417_SQL_SHAPE_ONLY=1`` to gate the check on SQL-shape context;
    # the broad-mode message now labels each offender ``[SQL]`` /
    # ``[non-SQL]`` so an operator triaging a future false-positive can
    # decide whether the narrower net is warranted.
    def _sql_shape(text: str) -> bool:
        lowered = text.lower()
        needle_low = _TABLE_NAME_NEEDLE.lower()
        return any(
            marker + needle_low in lowered or marker + " " + needle_low in lowered
            for marker in (
                "insert into ",
                "create table ",
                "create table if not exists ",
                "from ",
                "update ",
                "delete from ",
                "drop table ",
                "alter table ",
            )
        )

    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel in _EMITTER_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, text in _module_string_literals(tree):
            if _TABLE_NAME_NEEDLE in text:
                is_sql = _sql_shape(text)
                if sql_shape_only and not is_sql:
                    continue
                tag = "[SQL]" if is_sql else "[non-SQL]"
                offenders.append(f"  {rel}:{lineno} {tag}")
                break
    assert not offenders, (
        "N-417 no-projection-double-write drift — src file(s) reference "
        f"`{_TABLE_NAME_NEEDLE}` outside the three SSOT-owning modules "
        f"({sorted(_EMITTER_ALLOW)}). A second writer with different HMAC-"
        "hop logic desyncs the chain; a projection subject to `log_entries` "
        "retention pruning silently invalidates before the §164.316(b)(2)(i) "
        "6-year retention window elapses.\n\n" + "\n".join(offenders)
    )


def test_emitter_allow_list_has_no_stale_entries():
    """PD#7 rot-guard — every allow-listed module must still exist and
    still reference the table name."""
    stale: list[str] = []
    for rel in sorted(_EMITTER_ALLOW):
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"  {rel}  — file missing")
            continue
        tree = parse_module(path)
        if tree is None:
            stale.append(f"  {rel}  — did not parse")
            continue
        if not any(_TABLE_NAME_NEEDLE in text for _, text in _module_string_literals(tree)):
            stale.append(
                f"  {rel}  — no longer references `{_TABLE_NAME_NEEDLE}`"
            )
    assert not stale, (
        "N-417 rot-guard: `_EMITTER_ALLOW` has stale entries (PD#7).\n\n"
        + "\n".join(stale)
    )


def test_pin_has_teeth():
    """Three planted-fake probes: (a) the three SSOT-owning files each
    still hold the needle (else the pin is vacuously silent — all three
    could reference nothing and the offenders list stays empty); (b)
    synthetic AST with the needle in a non-allow-listed shape is flagged;
    (c) needle is a non-empty string that would appear naturally only in
    intentional references.
    """
    for rel in _EMITTER_ALLOW:
        tree = parse_module(SRC_ROOT / rel)
        assert tree is not None
        found = any(_TABLE_NAME_NEEDLE in text for _, text in _module_string_literals(tree))
        assert found, (
            f"teeth: SSOT owner `{rel}` no longer holds the table-name "
            "needle — pin is vacuously silent for that owner"
        )

    fake = ast.parse(f'SQL = "INSERT INTO {_TABLE_NAME_NEEDLE} VALUES (?)"\n')
    hits: list[str] = []
    for lineno, text in _module_string_literals(fake):
        if _TABLE_NAME_NEEDLE in text:
            hits.append(f"fake:{lineno}")
    assert hits, "teeth: planted literal missed by detector"

    assert _TABLE_NAME_NEEDLE, "teeth: needle is empty"
