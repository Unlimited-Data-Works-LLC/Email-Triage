"""N-387 R33 lifecycle-triple-clear preventative pin (2026-07-10 post-
deploy census wf_69674c7e-c67 seeded #6).

The ``gmail_watches`` (N-256 v50 + N-347 SSOT-tighten) and
``office365_subscriptions`` (N-69) tables share a **lifecycle triple**:
``status TEXT`` / ``error_count INTEGER`` / ``error_last TEXT``.
An UPSERT that renews a row MUST also CLEAR the triple to
(``'active'``, ``0``, ``NULL``) in the ``ON CONFLICT ... DO UPDATE SET``
payload; otherwise a re-registered watch inherits the stale ``errored``
chip — the exact defect N-347 closed at ``upsert_gmail_watch`` (4 of 5
callers had omitted the follow-up ``record_gmail_watch_outcome(None)``
clear, including the OAuth-recovery path).

This pin is **preventative**: at HEAD the two live upserts (both in
``web/db.py``) already clear all three columns, so N-347 has zero live
regression. But a future sibling table (``topic_watches``,
``ical_watches``, ``email_watches`` if it grows the triple, or a new
provider watch/subscription table) can regrow the bug without anything
catching it. **Cross-file DDL discovery** (per PD #5 — string-constant
scan is module-const seam-safe) auto-covers any new table that gains
the triple: no allow-list, no per-table opt-in.

STRICT-0 count-agnostic: every ``INSERT INTO <t> ... ON CONFLICT(...)
DO UPDATE SET <payload>`` where ``<t>`` carries the triple MUST have
``status =``, ``error_count =``, ``error_last =`` all present in
``<payload>``. Omitting any one is a defect (§164.312(b) operational-
surface reliability + operator UX — a user-visible "errored" chip that
never clears is a support-load and trust hit).

Grounding: ``audit-reports/divergence-census-2026-07-10-wf_69674c7e-c67.md``
§2 rank 6.

Known limitations (queued; NOT gating this drive per SME panel):
* ``INSERT OR REPLACE`` on a triple-table is UNSCANNED. Semantically it
  deletes-then-inserts, so a fresh row picks up the v50 DEFAULTs
  (``'active'`` / ``0`` / ``NULL``) provided the INSERT column list
  omits the triple — the pin's protection isn't needed in that case.
  A future OR-REPLACE that EXPLICITLY sets the triple to non-clear
  values is a separate class (queued).
* Dynamic-table names via f-string (``f"INSERT INTO {tbl} ..."``) lose
  the identifier slot to the regex; those sites evade the scan. No such
  caller exists in-tree at HEAD. Interprocedural / dynamic-table
  detection is a follow-up class in the backlog.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, relpath


_TRIPLE_COLS: frozenset[str] = frozenset({"status", "error_count", "error_last"})
_SQL_CONSTRAINT_KEYWORDS: frozenset[str] = frozenset({
    "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT",
})

_RE_CREATE_TABLE_HEAD = re.compile(
    r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_RE_ALTER_ADD_COLUMN = re.compile(
    r"ALTER\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)",
    re.IGNORECASE,
)
_RE_UPSERT_HEAD = re.compile(
    r"INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\b",
    re.IGNORECASE,
)
# N-387-DA fold: `INSERT OR IGNORE INTO <triple>` bypasses `ON CONFLICT DO
# UPDATE SET` entirely — the stale `errored` chip is preserved on conflict,
# which is N-347's defect via a different route. Flag every OR-IGNORE on a
# triple-table as an automatic offender (nothing to clear = the defect).
# OR REPLACE is NOT auto-flagged: it deletes-then-inserts, and the v50 column
# DEFAULTs (`'active'`, `0`, `NULL`) clear the triple on a fresh row when the
# INSERT column list omits the triple. A future OR REPLACE that EXPLICITLY
# sets the triple to non-clear values is a separate class (queued in the backlog
# as an interprocedural / dynamic-table follow-up).
_RE_INSERT_OR_IGNORE_HEAD = re.compile(
    r"INSERT\s+OR\s+IGNORE\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\b",
    re.IGNORECASE,
)
# Non-greedy body up to the next INSERT INTO / RETURNING / WHERE / ; /
# end-of-string — lets a single SQL literal carry multiple ON CONFLICT
# blocks (rare but real) without the FIRST match's body eating the SECOND
# upsert's INSERT header. N-387-db-sme fold: `\bWHERE\b` is a terminator
# too — SQLite permits a trailing WHERE on the SET (`DO UPDATE SET x=?
# WHERE status='active'`), and without cutting at WHERE the `\bcol\s*=`
# presence check would falsely see the WHERE-clause `status =` and mask
# an omitted SET assignment. Not exploitable at HEAD but a real
# future-shape risk. Sub-query WHERE inside a SET expression is not
# exercised in-tree — safe cutoff.
_RE_UPSERT_SET = re.compile(
    r"ON\s+CONFLICT\s*(?:\([^)]*\))?\s*DO\s+UPDATE\s+SET\s+(.*?)(?=\bINSERT\s+INTO\b|\bRETURNING\b|\bWHERE\b|;|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def _walk_string_constants(source: str):
    """Yield every ``str`` literal in ``source``.

    Python auto-concatenates adjacent string tokens into ONE
    ``ast.Constant`` — so an SQL literal built by implicit-concat
    (``"INSERT INTO ... " "VALUES ... " "ON CONFLICT ... DO UPDATE
    SET ..."``, the shape used throughout ``web/db.py``) arrives as
    one merged value here, not three fragments.

    f-strings arrive as ``ast.JoinedStr``; interpolated ``{expr}`` slots
    are replaced with a single space so token boundaries survive (we
    only match on the literal SQL text around interpolations)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value
        elif isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append(" ")
            yield "".join(parts)


def _extract_paren_body(text: str, open_idx: int) -> str:
    """``text[open_idx]`` MUST be ``"("`` — returns the balanced-paren
    body excluding the outer parens. If unbalanced, returns the tail."""
    assert text[open_idx] == "("
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return text[open_idx + 1 :]


def _maybe_add_col(seg_chars: list[str], cols: set[str]) -> None:
    seg = "".join(seg_chars).strip()
    if not seg:
        return
    tokens = seg.split(None, 1)
    if not tokens:
        return
    first = tokens[0].upper()
    if first in _SQL_CONSTRAINT_KEYWORDS:
        return
    cols.add(tokens[0].strip('"\'`[]').lower())


def _cols_from_create_body(body: str) -> set[str]:
    """Extract top-level column NAMES from a ``CREATE TABLE`` body —
    comma-separated segments at paren-depth 0. Skips ``PRIMARY KEY`` /
    ``FOREIGN KEY`` / ``UNIQUE`` / ``CHECK`` / ``CONSTRAINT`` trailing
    clauses."""
    cols: set[str] = set()
    depth = 0
    seg_chars: list[str] = []
    for ch in body:
        if ch in "([":
            depth += 1
            seg_chars.append(ch)
        elif ch in ")]":
            depth -= 1
            seg_chars.append(ch)
        elif ch == "," and depth == 0:
            _maybe_add_col(seg_chars, cols)
            seg_chars = []
        else:
            seg_chars.append(ch)
    _maybe_add_col(seg_chars, cols)
    return cols


def _discover_lifecycle_triple_tables() -> tuple[set[str], dict[str, set[str]]]:
    """Cross-file DDL scan of ``src/email_triage/**/*.py``.

    Returns ``(triple_tables, all_tables_columns)``:

    * ``triple_tables`` — tables whose ``CREATE TABLE`` + every
      ``ALTER TABLE ADD COLUMN`` union to a column set that is a
      superset of :data:`_TRIPLE_COLS`.
    * ``all_tables_columns`` — the full ``table -> col-set`` map (used
      for anti-vacuity diagnostics + teeth)."""
    all_cols: dict[str, set[str]] = {}
    for path in iter_files(SRC_ROOT):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for s in _walk_string_constants(text):
            for m in _RE_CREATE_TABLE_HEAD.finditer(s):
                table = m.group(1).lower()
                body = _extract_paren_body(s, m.end() - 1)
                cols = _cols_from_create_body(body)
                all_cols.setdefault(table, set()).update(cols)
            for m in _RE_ALTER_ADD_COLUMN.finditer(s):
                table = m.group(1).lower()
                col = m.group(2).lower()
                all_cols.setdefault(table, set()).add(col)
    triple = {t for t, cols in all_cols.items() if _TRIPLE_COLS.issubset(cols)}
    return triple, all_cols


def _iter_upserts_in_source(source: str):
    """Yield ``(table_lower, set_payload)`` for every
    ``INSERT INTO T ... ON CONFLICT(...) DO UPDATE SET <payload>`` in
    ``source``. The INSERT + ON CONFLICT arrive in the SAME string
    literal (Python implicit-concat fuses them into one
    ``ast.Constant``)."""
    for s in _walk_string_constants(source):
        for head in _RE_UPSERT_HEAD.finditer(s):
            rest = s[head.end():]
            set_m = _RE_UPSERT_SET.search(rest)
            if not set_m:
                continue
            yield head.group(1).lower(), set_m.group(1)


def _iter_or_ignore_inserts_in_source(source: str):
    """Yield ``table_lower`` for every ``INSERT OR IGNORE INTO T`` in
    ``source`` — the shape that BYPASSES ``ON CONFLICT DO UPDATE SET``
    entirely (SQLite drops the INSERT on conflict without touching the
    existing row). On a lifecycle-triple table this preserves the stale
    ``errored`` chip — the exact operator-visible defect N-347 closed at
    ``upsert_gmail_watch``, via a different SQL route."""
    for s in _walk_string_constants(source):
        for m in _RE_INSERT_OR_IGNORE_HEAD.finditer(s):
            yield m.group(1).lower()


def _payload_missing_triple_cols(payload: str) -> set[str]:
    """Return which of :data:`_TRIPLE_COLS` are NOT assigned in
    ``payload`` (case-insensitive; matches ``col =`` / ``col=`` at a
    word boundary)."""
    lower = payload.lower()
    missing: set[str] = set()
    for col in _TRIPLE_COLS:
        if not re.search(rf"\b{col}\s*=", lower):
            missing.add(col)
    return missing


def test_lifecycle_triple_tables_discovery_is_nonempty():
    """Anti-vacuity: at HEAD ``gmail_watches`` + ``office365_subscriptions``
    both carry the lifecycle triple. If discovery comes up empty, the
    ``CREATE TABLE`` / ``ALTER TABLE`` regex or the string-walker
    regressed — every upsert-clear assertion below would then pass
    vacuously and the pin would be blind by construction."""
    triple, all_cols = _discover_lifecycle_triple_tables()
    assert triple, (
        "N-387 R33: cross-file DDL scan found ZERO tables carrying the "
        f"lifecycle triple {sorted(_TRIPLE_COLS)}. Known-at-HEAD: "
        "`gmail_watches` (N-256 migration v50) + `office365_subscriptions` "
        "(N-69). An empty result means the DDL scanner regressed — check "
        "`_walk_string_constants` / `_RE_CREATE_TABLE_HEAD` / "
        f"`_RE_ALTER_ADD_COLUMN`. Discovered (first 5): "
        f"{sorted((t, sorted(c)) for t, c in all_cols.items())[:5]}"
    )
    for known in ("gmail_watches", "office365_subscriptions"):
        assert known in triple, (
            f"N-387 R33: expected `{known}` in the lifecycle-triple set; "
            f"got {sorted(triple)}. Column detection missed a migration's "
            "ALTER TABLE ADD COLUMN line or the CREATE TABLE body parser "
            "dropped a segment."
        )


def test_every_upsert_on_lifecycle_triple_table_clears_all_three_columns():
    """The pin: every UPSERT (``INSERT INTO T ... ON CONFLICT(...) DO
    UPDATE SET body``) where ``T`` carries the lifecycle triple MUST
    assign ``status``, ``error_count``, and ``error_last`` in ``body``.
    No allow-list — omitting any one of the three is a defect
    (§164.312(b) operational-surface reliability + operator UX; the
    exact failure N-347 closed at ``upsert_gmail_watch``)."""
    triple_tables, _ = _discover_lifecycle_triple_tables()
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = relpath(path)
        for table, payload in _iter_upserts_in_source(text):
            if table not in triple_tables:
                continue
            missing = _payload_missing_triple_cols(payload)
            if missing:
                offenders.append(
                    f"{rel}: UPSERT on `{table}` DO UPDATE SET "
                    f"omits {sorted(missing)} — clear required by N-347's "
                    "SSOT-tightening (§164.312(b))."
                )
        # N-387-DA fold: OR-IGNORE bypass — the stale-chip defect via a
        # different SQL route. Auto-flag every `INSERT OR IGNORE INTO
        # <triple>` (nothing to clear = the defect).
        for table in _iter_or_ignore_inserts_in_source(text):
            if table in triple_tables:
                offenders.append(
                    f"{rel}: `INSERT OR IGNORE INTO {table}` bypasses "
                    "`ON CONFLICT DO UPDATE SET` entirely — the stale "
                    "`errored` chip is preserved on conflict (N-347's "
                    "defect via a different route). Use `INSERT INTO "
                    f"{table} (...) VALUES (...) ON CONFLICT(...) DO "
                    "UPDATE SET status = 'active', error_count = 0, "
                    "error_last = NULL, ...` — mirror the "
                    "`gmail_watches` / `office365_subscriptions` upserts."
                )
    assert not offenders, (
        "N-387 R33: every UPSERT on a lifecycle-triple table MUST clear "
        f"all three columns {sorted(_TRIPLE_COLS)} in its `ON CONFLICT "
        "DO UPDATE SET` payload — AND `INSERT OR IGNORE INTO <triple>` "
        "is auto-forbidden (bypasses the SET payload entirely). Missing "
        "clears leave a re-registered watch with the stale `errored` "
        "chip (N-347's exact defect shape).\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# TEETH — planted-drift + clean arms for the discovery + omit-detection
# ---------------------------------------------------------------------------

_TEETH_SRC_OMIT_STATUS = '''\
def upsert_bad(conn, account_id):
    conn.execute(
        "INSERT INTO gmail_watches (account_id) VALUES (?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  error_count = 0, "
        "  error_last  = NULL",
        (account_id,),
    )
'''


_TEETH_SRC_OMIT_ERROR_COUNT = '''\
def upsert_bad(conn, account_id):
    conn.execute(
        "INSERT INTO office365_subscriptions (account_id) VALUES (?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  status     = 'active', "
        "  error_last = NULL",
        (account_id,),
    )
'''


_TEETH_SRC_OMIT_ERROR_LAST = '''\
def upsert_bad(conn, account_id):
    conn.execute(
        "INSERT INTO gmail_watches (account_id) VALUES (?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  status      = 'active', "
        "  error_count = 0",
        (account_id,),
    )
'''


_TEETH_SRC_ALL_THREE_PRESENT = '''\
def upsert_ok(conn, account_id):
    conn.execute(
        "INSERT INTO gmail_watches (account_id) VALUES (?) "
        "ON CONFLICT(account_id) DO UPDATE SET "
        "  status      = 'active', "
        "  error_count = 0, "
        "  error_last  = NULL",
        (account_id,),
    )
'''


_TEETH_SRC_NON_TRIPLE_TABLE = '''\
def upsert_ok(conn, key, value):
    conn.execute(
        "INSERT INTO kv_store (key, value_json) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
        (key, value),
    )
'''


_TEETH_SRC_OR_IGNORE_ON_TRIPLE = '''\
def upsert_bad(conn, account_id):
    conn.execute(
        "INSERT OR IGNORE INTO gmail_watches (account_id, email_address) "
        "VALUES (?, ?)",
        (account_id, "x@y"),
    )
'''


_TEETH_SRC_OR_IGNORE_ON_NON_TRIPLE = '''\
def upsert_ok(conn, key, value):
    conn.execute(
        "INSERT OR IGNORE INTO kv_store (key, value_json) VALUES (?, ?)",
        (key, value),
    )
'''


def _upsert_offenders_in_synthetic(source: str, triple_tables: set[str]) -> list[str]:
    offenders: list[str] = []
    for table, payload in _iter_upserts_in_source(source):
        if table not in triple_tables:
            continue
        missing = _payload_missing_triple_cols(payload)
        if missing:
            offenders.append(f"{table}: missing {sorted(missing)}")
    for table in _iter_or_ignore_inserts_in_source(source):
        if table in triple_tables:
            offenders.append(f"{table}: OR-IGNORE bypass")
    return offenders


def test_teeth_omit_status_flags_offender():
    """PLANTED-DRIFT: a synthetic UPSERT on ``gmail_watches`` that OMITS
    ``status =`` from its SET payload MUST fire the pin."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_OMIT_STATUS, triple)
    assert offenders, (
        "N-387 R33 teeth (omit-status): a synthetic UPSERT on "
        "gmail_watches that OMITS `status =` MUST fire the pin; got 0 "
        "offenders — the missing-cols detector or the UPSERT extractor "
        "regressed."
    )


def test_teeth_omit_error_count_flags_offender():
    """PLANTED-DRIFT: a synthetic UPSERT on ``office365_subscriptions``
    that OMITS ``error_count =`` MUST fire the pin."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_OMIT_ERROR_COUNT, triple)
    assert offenders, (
        "N-387 R33 teeth (omit-error_count): a synthetic UPSERT on "
        "office365_subscriptions that OMITS `error_count =` MUST fire "
        "the pin; got 0 offenders."
    )


def test_teeth_omit_error_last_flags_offender():
    """PLANTED-DRIFT: a synthetic UPSERT on ``gmail_watches`` that OMITS
    ``error_last =`` MUST fire the pin."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_OMIT_ERROR_LAST, triple)
    assert offenders, (
        "N-387 R33 teeth (omit-error_last): a synthetic UPSERT on "
        "gmail_watches that OMITS `error_last =` MUST fire the pin; "
        "got 0 offenders."
    )


def test_teeth_all_three_present_does_not_flag():
    """CLEAN: a synthetic UPSERT that clears all three MUST NOT be
    flagged — false-positive guard."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_ALL_THREE_PRESENT, triple)
    assert not offenders, (
        "N-387 R33 teeth (clean false-positive): a synthetic UPSERT that "
        "clears all three columns MUST NOT be flagged; got: "
        f"{offenders}. The missing-cols detector is over-firing."
    )


def test_teeth_non_triple_table_upsert_ignored():
    """SCOPE: an UPSERT on a table NOT in ``LIFECYCLE_TRIPLE_TABLES``
    (no ``status`` / ``error_count`` / ``error_last`` columns) MUST NOT
    be flagged, even with a minimal SET payload."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_NON_TRIPLE_TABLE, triple)
    assert not offenders, (
        "N-387 R33 teeth (scope false-positive): an UPSERT on a table "
        "NOT carrying the lifecycle triple MUST NOT be flagged. "
        f"LIFECYCLE_TRIPLE_TABLES scope is broken. Hits: {offenders}"
    )


def test_teeth_or_ignore_on_triple_table_flags_offender():
    """N-387-DA fold: PLANTED-DRIFT — ``INSERT OR IGNORE INTO
    gmail_watches`` bypasses ``ON CONFLICT DO UPDATE SET`` and
    preserves the stale ``errored`` chip on conflict (N-347's defect
    via a different SQL route). Pin MUST auto-flag."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_OR_IGNORE_ON_TRIPLE, triple)
    assert offenders, (
        "N-387 R33 teeth (OR-IGNORE bypass planted): a synthetic "
        "`INSERT OR IGNORE INTO gmail_watches` MUST fire the pin — it "
        "silently drops the write on conflict, leaving the row's stale "
        "`errored` chip intact. Got 0 offenders — the OR-IGNORE "
        "detector regressed or is not wired into the offender loop."
    )


def test_teeth_or_ignore_on_non_triple_table_ignored():
    """SCOPE: ``INSERT OR IGNORE`` on a NON-triple table is legit
    behaviour (e.g. dedupe on a ``kv_store``); pin MUST NOT flag."""
    triple, _ = _discover_lifecycle_triple_tables()
    offenders = _upsert_offenders_in_synthetic(_TEETH_SRC_OR_IGNORE_ON_NON_TRIPLE, triple)
    assert not offenders, (
        "N-387 R33 teeth (OR-IGNORE scope false-positive): "
        "`INSERT OR IGNORE INTO kv_store` (not carrying the triple) is "
        "a legitimate dedupe shape; pin MUST NOT flag it. Hits: "
        f"{offenders}. The OR-IGNORE detector is not scope-gated."
    )


def test_teeth_extractor_liveness_on_web_db():
    """N-387-db-sme fold: POSITIVE-LIVENESS on the UPSERT extractor.

    Parallel to :func:`test_lifecycle_triple_tables_discovery_is_nonempty`
    (discovery liveness) — assert that the extractor
    :func:`_iter_upserts_in_source` **actually** yields BOTH known-live
    UPSERTs from ``src/email_triage/web/db.py`` with all three columns
    cleared in the SET payload. Guards against a silent regression that
    would zero-yield the extractor and cause the main pin to pass
    vacuously (no offenders found because no upserts scanned)."""
    web_db_path = SRC_ROOT / "web" / "db.py"
    assert web_db_path.exists(), (
        f"N-387 R33 teeth (positive-liveness): expected "
        f"`{web_db_path}` at HEAD — reachable via SRC_ROOT. Path drift?"
    )
    text = web_db_path.read_text(encoding="utf-8", errors="replace")
    by_table: dict[str, list[str]] = {}
    for table, payload in _iter_upserts_in_source(text):
        by_table.setdefault(table, []).append(payload)
    for expected in ("gmail_watches", "office365_subscriptions"):
        payloads = by_table.get(expected)
        assert payloads, (
            f"N-387 R33 teeth (positive-liveness): extractor yielded "
            f"ZERO UPSERTs for `{expected}` from `web/db.py`. Known-live "
            "sites at HEAD: `web/db.py:2764` (gmail_watches) + "
            "`web/db.py:2907` (office365_subscriptions). Extractor "
            "regression — the main pin would pass vacuously. Extracted "
            f"tables: {sorted(by_table)}."
        )
        # And each payload MUST already clear the triple (this IS the
        # HEAD contract N-256 + N-347 + N-69 established; verifies the
        # missing-cols detector correctly reports zero missing here).
        for payload in payloads:
            missing = _payload_missing_triple_cols(payload)
            assert not missing, (
                f"N-387 R33 teeth (positive-liveness): the `{expected}` "
                f"UPSERT payload in `web/db.py` is now MISSING "
                f"{sorted(missing)} — either a live regression on the "
                "clear (main pin should catch it) or the missing-cols "
                "detector is over-firing. Payload head: "
                f"{payload[:200]}..."
            )
