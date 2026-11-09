""" Deliverable 3 — audit-emitter gap-event sentinel tests.

What this file pins
-------------------
1. The ``@audit_emitter`` decorator marks helpers so
   ``@db_write``'s wrapper recognises them on the exception path.
2. The migration v38 ``audit_gap_events`` table exists with the
   expected HMAC-chained schema.
3. When an ``@audit_emitter``-marked helper raises mid-write, the
   wrapper writes a chained ``audit_gap_events`` row recording the
   failed emit with:
     - per-emitter redacted IN-class fields verbatim
     - per-emitter OUT-class fields excluded (PHI safety per
       §164.502(a) + §164.514(b)(2)(i))
     - SHA-256 hash of ALL canonicalised args (for forensic match
       against payloads stored elsewhere)
     - HMAC-SHA256 row_hash chained against the prior gap row
       (§164.312(c)(1) integrity — reuses the same key derivation
       as the log_entries chain per EQM-05)
4. The gap-write itself catching failures: a broken gap-write must
   NEVER bury the original exception.
5. A NON-audit-emitter ``@db_write`` failure does NOT trigger a gap
   write (no false positives).
6. A successful ``@db_write @audit_emitter`` helper does NOT
   trigger a gap write (no false positives).
"""

from __future__ import annotations
from _db_tracking import track

import json
import sqlite3
from pathlib import Path

import pytest

from _pin_harness import (
    AUDIT_EMITTER_MODULES,
    SRC_ROOT,
    annotate_parents,
    audit_emitter_defs,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
)

from email_triage.db.audit import (
    _AUDIT_EMITTER_REDACTION_MAP,
    _get_current_hmac_version,
    audit_emitter,
    compute_gap_row_hash,
    get_last_gap_row_hash,
    record_user_status_event,
    record_auth_event,
    record_hipaa_boundary,
    record_hipaa_access_event,
    record_discover_run,
    record_api_key_event,
    record_access_event,
    set_user_disabled,
)
from email_triage.db.style import record_style_distill_event
from email_triage.web.db import init_db
from email_triage.web.db_writelock import db_write


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    """Per-test file-backed DB with full schema + migrations applied
    (migration v38 creates audit_gap_events).

    The autouse conftest fixture ``_seed_hmac_key_for_audit_chain``
    has already seeded HMAC key version 0 — the gap-event chain
    inherits that key automatically. No per-test seeding needed
    here.
    """
    db_path = tmp_path / "audit_gap.db"
    c = track(init_db(str(db_path)))
    yield c
    c.close()


# Current HMAC version used by all chain ops in this test file —
# inherited from the conftest autouse fixture (version=0).
_TEST_HMAC_VERSION = 0


# ---------------------------------------------------------------------------
# Decorator + marker mechanics
# ---------------------------------------------------------------------------

class TestAuditEmitterDecorator:
    def test_marks_function_with_is_audit_emitter_attr(self):
        @audit_emitter
        def _f(conn):
            pass

        assert getattr(_f, "_is_audit_emitter", False) is True

    def test_known_emitters_are_marked(self):
        """The emitter helpers identified in the hipaa-sme spec carry the
        ``_is_audit_emitter`` marker after `@db_write` wraps them (the
        decorator preserves attributes set on the inner fn via the closure).

        2026-06-09 (census A2): + ``set_user_disabled`` (user_status_events,
        PIN-2) and ``record_style_distill_event`` (style_distill_events,
        §164.502(e) cloud-egress accounting) → 9 emitters. The authoritative
        count-agnostic check is ``TestAuditEmitterRedactionPin`` below; this
        is the named-callability sanity list."""
        # ``@db_write`` is applied OUTER and uses functools.wraps —
        # the marker on the inner fn is reachable via the wrapper's
        # closure but NOT via getattr on the wrapped result. The
        # wrapper checks ``getattr(fn, "_is_audit_emitter", False)``
        # where ``fn`` is the inner — that's what
        # ``db_write.wrapper`` actually closes over. So we test the
        # mechanism via behaviour (below), not introspection.
        # Sanity here is just that the decorator IS importable + the
        # functions ARE the wrapped versions.
        assert callable(record_user_status_event)
        assert callable(record_auth_event)
        assert callable(record_hipaa_boundary)
        assert callable(record_hipaa_access_event)
        assert callable(record_discover_run)
        assert callable(record_api_key_event)
        assert callable(record_access_event)
        assert callable(set_user_disabled)
        assert callable(record_style_distill_event)


# ---------------------------------------------------------------------------
# Migration v38 schema
# ---------------------------------------------------------------------------

class TestMigrationV38:
    def test_audit_gap_events_table_exists(self, conn):
        """After init_db (which runs all migrations), the
        audit_gap_events table is present with the expected
        columns."""
        rows = conn.execute(
            "PRAGMA table_info(audit_gap_events)"
        ).fetchall()
        cols = {r["name"] for r in rows}
        expected = {
            "id", "ts", "helper_name",
            "original_args_redacted", "original_args_hash",
            "exc_type", "exc_msg",
            "prev_hash", "row_hash",
            "hash_alg", "master_key_version",
        }
        assert expected.issubset(cols), (
            f"audit_gap_events missing columns: {expected - cols}"
        )

    def test_indexes_on_ts_and_helper_name(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND tbl_name='audit_gap_events'"
        ).fetchall()
        names = {r["name"] for r in rows}
        assert "idx_audit_gap_events_ts" in names
        assert "idx_audit_gap_events_helper" in names


# ---------------------------------------------------------------------------
# Per-emitter redaction map matches hipaa-sme spec verdict
# ---------------------------------------------------------------------------

class TestRedactionMap:
    """The IN/OUT split per emitter must EXACTLY match the
    hipaa-sme verdict 2026-05-25. A change here is a HIPAA-side
    decision — the table is the documented control. Each test names
    the §-anchor that drove the split."""

    def test_record_user_status_event_split(self):
        # §164.502(a) Min-Necessary: reason is operator free-text,
        # may contain PHI (e.g. "user requested account closure
        # because diagnosis X") — hash-only.
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_user_status_event"]
        assert spec["in"] == {"target_user_id", "actor_user_id", "event"}
        assert spec["out"] == {"reason"}

    def test_record_auth_event_split(self):
        # §164.514(b)(2)(i) Safe-Harbor: email + ip + user_agent are
        # the canonical de-identification targets (email = direct
        # identifier; IP = geographic identifier).
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_auth_event"]
        assert spec["in"] == {
            "event_type", "user_id", "key_id", "outcome",
        }
        assert spec["out"] == {"email", "ip", "user_agent", "detail"}

    def test_record_hipaa_boundary_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_hipaa_boundary"]
        assert spec["in"] == {"scope", "direction", "actor_id"}
        assert spec["out"] == {"reason"}

    def test_record_hipaa_access_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_hipaa_access_event"]
        assert spec["in"] == {
            "actor_user_id", "account_id", "operation", "outcome",
        }
        assert spec["out"] == {"detail"}

    def test_update_hipaa_access_event_split(self):
        # §164.312(b) finalise-gap: update_hipaa_access_event finalises a
        # record_hipaa_access_event-emitted row. ``detail`` is the SAME
        # free-text-may-contain-PHI field as on the creation event →
        # OUT/hash-only (mirrors record_hipaa_access_event). ``event_id`` +
        # ``outcome`` are Safe-Harbor-class (typed id + bounded-enum) → IN.
        spec = _AUDIT_EMITTER_REDACTION_MAP["update_hipaa_access_event"]
        assert spec["in"] == {"event_id", "outcome"}
        assert spec["out"] == {"detail"}

    def test_record_discover_run_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_discover_run"]
        # account_name + folders are operator-mailbox-label strings
        # — may include PHI-adjacent identifiers.
        assert "account_name" in spec["out"]
        assert "folders" in spec["out"]
        assert spec["in"] >= {
            "account_id", "actor_user_id",
            "scanned_count", "errors_count",
        }

    def test_record_api_key_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_api_key_event"]
        # api-key name is operator-chosen text; hash-only.
        assert "name" in spec["out"]
        assert spec["in"] >= {
            "event", "key_id", "actor_user_id",
            "target_user_id", "source",
        }

    def test_record_access_event_split(self):
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_access_event"]
        # message_id is a PHI-adjacent identifier; detail + request_id
        # are payload-shaped.
        assert spec["out"] >= {"message_id", "detail", "request_id"}
        assert spec["in"] >= {
            "actor_user_id", "method", "route",
            "account_id", "status_code", "outcome",
        }

    def test_set_user_disabled_split(self):
        # A2 (census 2026-06-09): writes user_status_events (same table as
        # record_user_status_event) → matching split. ``reason`` is operator
        # free-text → hash-only; ``disabled`` is the bindable bool (NOT the
        # derived ``event`` local).
        spec = _AUDIT_EMITTER_REDACTION_MAP["set_user_disabled"]
        assert spec["in"] == {"target_user_id", "actor_user_id", "disabled"}
        assert spec["out"] == {"reason"}

    def test_record_style_distill_event_split(self):
        # A2: §164.502(e) cloud-egress accounting. ``was_cloud`` (the egress
        # signal) MUST be IN/readable; ``recipient_hash`` is a correlatable
        # per-contact identifier → hash-only (Minimum Necessary).
        spec = _AUDIT_EMITTER_REDACTION_MAP["record_style_distill_event"]
        assert "was_cloud" in spec["in"]
        assert spec["out"] == {"recipient_hash"}
        assert spec["in"] >= {
            "account_id", "actor_user_id", "backend_id", "outcome", "kind",
        }


# ---------------------------------------------------------------------------
# Structural pin (A2 / db-sme B-1) — every @audit_emitter has a map entry
# ---------------------------------------------------------------------------

class TestAuditEmitterRedactionPin:
    """Count-agnostic pin (pattern_count_agnostic_structural_drift_catch):
    every ``@audit_emitter``-decorated helper MUST have a
    ``_AUDIT_EMITTER_REDACTION_MAP`` entry — else its gap-event rows carry an
    empty (info-free) redacted payload. This is the forcing function the A2
    review found missing: the decorator + the map are two halves of one
    contract, and nothing asserted they stay in sync (the 2026-06-09 census
    added two emitters with the decorator but no map until this pin)."""

    # Canonical SRC_ROOT-relative keys (harness ``relpath`` form: ``db/audit.py``,
    # NOT the old repo-root ``src/email_triage/db/audit.py``). The module list is
    # the SHARED harness constant (run18 #2, PD#5/#6 — one list, not a fork); the
    # module-keyed ``_mod_for_rel`` map below tracks this same SRC_ROOT-relative
    # form.
    _EMITTER_MODULES = AUDIT_EMITTER_MODULES

    @classmethod
    def _emitter_defs(cls):
        """(module, funcname) for every @audit_emitter-decorated def — delegates
        to the shared harness walker ``_pin_harness.audit_emitter_defs`` (PD#6:
        the run18 #2 audit-emit-swallow pin reuses the SAME walker, so the
        emitter net cannot fork into two divergent scanners).

        ``module`` is the harness ``relpath`` form (SRC_ROOT-relative,
        forward-slash: ``db/audit.py``)."""
        return audit_emitter_defs(cls._EMITTER_MODULES)

    def test_every_emitter_has_redaction_map_entry(self):
        missing = [
            (m, fn) for m, fn in self._emitter_defs()
            if fn not in _AUDIT_EMITTER_REDACTION_MAP
        ]
        assert not missing, (
            "@audit_emitter helper(s) with NO _AUDIT_EMITTER_REDACTION_MAP "
            "entry — gap rows would carry an empty redacted payload (the A2 "
            "drift class):\n"
            + "\n".join(f"  {m}::{fn}" for m, fn in missing)
            + "\n\nAdd an IN/OUT split (hipaa-sme owns the §164.502(a) field "
            "classification) + a positional bind branch in "
            "_bind_args_to_emitter_signature if the helper's extras are "
            "positional after conn."
        )

    def test_no_stale_redaction_map_entries(self):
        emitters = {fn for _, fn in self._emitter_defs()}
        stale = set(_AUDIT_EMITTER_REDACTION_MAP) - emitters
        assert not stale, (
            "Stale _AUDIT_EMITTER_REDACTION_MAP entries (no @audit_emitter "
            f"helper): {sorted(stale)}"
        )

    def test_positional_bind_preserves_param_identity(self):
        """DA hedge-check on N-58 (the finalise-gap fix): the per-helper
        positional key lists in ``_bind_args_to_emitter_signature`` are
        hand-maintained with NO enforcement that they match the function's real
        parameter order. A list that drifts out of order maps a value (e.g. the
        PHI ``detail`` field) into the WRONG redaction slot — so a shown IN-field
        could carry an OUT/PHI value, leaking PHI into the gap-event payload.

        Count-agnostic over EVERY ``@audit_emitter`` (PD#1): a sentinel
        round-trip — binding each parameter's NAME as its value must yield
        ``{param: its-own-name}``. A reordered/short key list breaks it. This is
        the enforcing pin the SSOT owed (the bind list was the one hand-mapped
        artifact with no structural guard)."""
        import importlib
        import inspect
        from email_triage.db.audit import _bind_args_to_emitter_signature

        # Keyed on the harness ``relpath`` form (SRC_ROOT-relative) that
        # ``_emitter_defs`` now yields after the R5b harness migration.
        _mod_for_rel = {
            "db/audit.py": "email_triage.db.audit",
            "db/style.py": "email_triage.db.style",
        }
        checked = 0
        for rel, fname in self._emitter_defs():
            mod = importlib.import_module(_mod_for_rel[rel])
            fn = getattr(mod, fname)
            params = [
                p for p in inspect.signature(fn).parameters.values()
                if p.name not in ("conn", "self")
            ]
            names = [p.name for p in params]
            if not names:
                continue
            all_kwonly = all(p.kind == p.KEYWORD_ONLY for p in params)
            if all_kwonly:
                # kwargs-only emitter: callers pass by keyword → bind passes kw through.
                bound = _bind_args_to_emitter_signature(
                    fname, (None,), {n: n for n in names})
            else:
                # positional emitter: bind maps args[1:] by position to its key list.
                bound = _bind_args_to_emitter_signature(
                    fname, (None, *names), {})
            for n in names:
                assert bound.get(n) == n, (
                    f"{fname}: _bind_args_to_emitter_signature binds {n!r} -> "
                    f"{bound.get(n)!r}, not its own value. The positional key "
                    f"list drifted out of the function's signature order; a PHI "
                    f"OUT-field could land in a shown IN-slot. Fix the {fname} "
                    f"branch in _bind_args_to_emitter_signature to the signature "
                    f"order {names}."
                )
            checked += 1
        assert checked >= 9, (
            f"only {checked} @audit_emitter helpers checked — expected >=9; the "
            "pin may have stopped discovering them (vacuous-pass guard)."
        )


# ---------------------------------------------------------------------------
# INVERSE pin (PD#3) — every raw write to an @audit_emitter-routed audit
# table is inside an @audit_emitter helper OR a justified allow-list entry
# ---------------------------------------------------------------------------

class TestInverseAuditEmitterPin:
    """Prime-Directive-3 INVERSE structural pin (Loop-4 census #3-B,
    DRIFT-PREVENTION).

    N-36 shipped the FORWARD pin (``TestAuditEmitterRedactionPin``: every
    ``@audit_emitter`` helper has a redaction-map entry). The INVERSE was
    missing: nothing structurally stopped a NEW raw
    ``conn.execute("INSERT INTO <audit_table> ...")`` (or ``UPDATE ... SET``)
    from being added OUTSIDE the ``@audit_emitter`` family — which forks the
    §164.312(b)/(c)(1) HMAC-chained audit trail (PD#3's exact failure).

    This pin walks every ``.execute(...)`` / ``.executemany(...)`` across the
    audit-write surface (``src/email_triage/db/**`` + ``triage_logging.py``).
    For each call whose FIRST string-literal SQL arg is an ``INSERT INTO <t>``
    or ``UPDATE <t> SET`` against an IN-SCOPE audit table, it asserts the
    ENCLOSING def is ``@audit_emitter``-decorated OR on the comment-justified
    allow-list below. It keys on the WRITE SITE (interprocedural — PD#2).

    Table classification (the IN-SCOPE set = tables a raw write forks the
    audit chain on; proven by enumeration per PD#4 / R4):

      EMITTER-ROUTED (in-scope; raw write MUST be @audit_emitter):
        hipaa_access_events, hipaa_boundary_events, auth_events,
        user_status_events, style_distill_events, discover_runs,
        api_key_events, access_log

      SELF-MANAGED HMAC chain (in-scope for the chain, but written by the
      chain PRIMITIVE itself, not via @audit_emitter → allow-listed writers):
        log_entries        (insert_log_entry, SQLiteLogHandler.emit)
        audit_gap_events   (_write_audit_gap_event — the gap-chain writer)

      OPERATIONAL, NOT the §164.312(b) chain (out of scope):
        acme_renewal_log   (insert_acme_renewal_log — operational telemetry)

    Cover INSERT *and* UPDATE (the UPDATE arm catches
    ``update_hipaa_access_event``, which the INSERT-only signature would miss).
    """

    import ast as _ast
    import re as _re

    # The audit-event tables are LEGITIMATELY written only from db/** (the SSOT
    # home) + triage_logging.py (the SQLiteLogHandler log_entries chain) — but
    # the SCAN deliberately covers the ENTIRE src tree (see ``_source_files``):
    # a raw INSERT/UPDATE on one of these tables is a forked-chain defect
    # WHEREVER it appears, and a db/-only walk let the pin drift in its OWN
    # scoping (PD#6/#7 — "census the censusers", census run12 ). The
    # allow-list below (by enclosing-function name) is what exempts the
    # legitimate db/ writers.

    # The @audit_emitter-routed audit tables (forward map keys, by table). A
    # raw INSERT/UPDATE on one of these MUST be inside an @audit_emitter helper.
    _EMITTER_ROUTED_TABLES = frozenset({
        "hipaa_access_events",
        "hipaa_boundary_events",
        "auth_events",
        "user_status_events",
        "style_distill_events",
        "discover_runs",
        "api_key_events",
        "access_log",
        #  — dedicated chained clock-transition table (v47); written only by
        # record_clock_event via _chain_insert.
        "regulatory_clock_event",
    })

    # Self-managed HMAC-chain tables: a raw write forks NOTHING because these
    # tables ARE the chain primitive's own ledger — the writer computes the
    # chain hash inline. Their writers can never be @audit_emitter (that would
    # be recursive: the gap-chain protecting the gap-chain). Allow-listed by
    # WRITER below, not exempted by table.
    _SELF_MANAGED_CHAIN_TABLES = frozenset({
        "log_entries",
        "audit_gap_events",
    })

    # Full in-scope table set the pin inspects writes against.
    _IN_SCOPE_TABLES = _EMITTER_ROUTED_TABLES | _SELF_MANAGED_CHAIN_TABLES

    # Allow-list: enclosing-function names whose raw audit-table write is
    # legitimate WITHOUT @audit_emitter. Each entry carries a one-line
    # justification. Key = function name (repo has no two same-named audit
    # writers; the stale-guard below proves each entry still raw-writes an
    # in-scope table on HEAD).
    _RAW_WRITE_ALLOWLIST = {
        # NOTE: set_account_hipaa was REMOVED from this allow-list in  when
        # its inline boundary-event INSERT was routed through the chained-audit
        # SSOT (db.audit._chain_insert). It is still an in-txn atomic write (the
        # HIPAA-flag flip + the boundary row share ONE tx — _chain_insert is
        # txn-aware and does NOT commit), but the write is no longer a raw
        # literal INSERT, so it is no longer a "raw writer" this pin must exempt.
        # The log_entries chain primitive — writes the row AND computes its
        # HMAC chain hash inline. Not an emitter (it IS the chain).
        "insert_log_entry": "log_entries HMAC-chain primitive (computes row_hash inline)",
        # SQLiteLogHandler hot-path emit + its #239e drop-sentinel: the same
        # log_entries chain primitive on the stdlib-logging path.
        "emit": "SQLiteLogHandler.emit — log_entries chain primitive (hot path + #239e sentinel)",
        # The gap-event chain writer itself. @audit_emitter wrapping this would
        # be a gap-chain protecting the gap-chain (recursive); it computes its
        # OWN HMAC chain hash inline.
        "_write_audit_gap_event": "audit_gap_events gap-chain writer (computes row_hash inline)",
        # NOTE: update_hipaa_access_event was REMOVED from this allow-list when
        # it became an @audit_emitter (§164.312(b) finalise-gap fix). A failed
        # finalise-UPDATE now emits a gap row instead of silently leaving the
        # row frozen at "in_progress". It belongs in the emitter set, not here.
    }

    _INSERT_RE = _re.compile(r"\bINSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)",
                             _re.IGNORECASE)
    _UPDATE_RE = _re.compile(r"\bUPDATE\s+([A-Za-z_][A-Za-z0-9_]*)\s+SET\b",
                             _re.IGNORECASE)

    @classmethod
    def _audit_emitter_funcnames(cls):
        """Names of every @audit_emitter-decorated def — reuses the existing
        N-36 ``_emitter_defs`` AST harness (PD#6 — don't hand-roll a second
        emitter scanner)."""
        return {fn for _, fn in TestAuditEmitterRedactionPin._emitter_defs()}

    @classmethod
    def _source_files(cls):
        # Walk the ENTIRE src tree (PD#6/#7, census run12 ) — not just db/.
        # A raw write to one of the 10 in-scope audit tables is a forked-chain
        # defect under web/, actions/, jobs/, engine/ too; the 10-table match
        # keeps it specific (verified ZERO raw audit writes exist outside db/ +
        # triage_logging.py at HEAD, so widening is pure future-regression
        # cover). Skips __pycache__, sorted — via the shared harness.
        return list(iter_src_files())

    @classmethod
    def _first_sql_literal(cls, call_node):
        """Return the first arg of an .execute/.executemany call if it is a
        (possibly implicitly-concatenated) string constant, else None. AST
        folds adjacent string literals into a single Constant, so a multi-line
        SQL string split across literals arrives here fully concatenated."""
        if not call_node.args:
            return None
        first = call_node.args[0]
        if isinstance(first, cls._ast.Constant) and isinstance(first.value, str):
            return first.value
        return None

    @classmethod
    def _enclosing_func(cls, node):
        """Walk up the parent chain to the nearest FunctionDef/AsyncFunctionDef
        name (interprocedural keying — PD#2: the write site, not the source)."""
        fn = enclosing_fn(node)
        return None if fn == "<module>" else fn

    @classmethod
    def _scan_raw_audit_writes(cls):
        """Yield (relpath, lineno, table, enclosing_func) for every raw
        INSERT/UPDATE on an in-scope audit table across the write surface.

        ``relpath`` is now the harness SRC_ROOT-relative form (``db/audit.py``)
        rather than the old repo-root ``src/email_triage/db/audit.py``; it is
        used only in the violation message (the allow-list keys on the
        enclosing FUNCTION name, not the path), so the base change is harmless.
        """
        for path in cls._source_files():
            tree = parse_module(path)
            if tree is None:
                continue
            annotate_parents(tree)
            for node in cls._ast.walk(tree):
                if not isinstance(node, cls._ast.Call):
                    continue
                func = node.func
                if not isinstance(func, cls._ast.Attribute):
                    continue
                if func.attr not in ("execute", "executemany"):
                    continue
                sql = cls._first_sql_literal(node)
                if sql is None:
                    continue
                table = None
                m = cls._INSERT_RE.search(sql) or cls._UPDATE_RE.search(sql)
                if m:
                    candidate = m.group(1)
                    if candidate in cls._IN_SCOPE_TABLES:
                        table = candidate
                if table is None:
                    continue
                enclosing = cls._enclosing_func(node)
                rel = relpath(path)
                yield rel, node.lineno, table, enclosing

    def test_every_raw_audit_table_write_is_emitter_or_allowlisted(self):
        emitters = self._audit_emitter_funcnames()
        violations = []
        for rel, lineno, table, enclosing in self._scan_raw_audit_writes():
            if enclosing in emitters:
                continue
            if enclosing in self._RAW_WRITE_ALLOWLIST:
                continue
            violations.append((rel, lineno, table, enclosing))
        assert not violations, (
            "PD#3 INVERSE-pin violation — raw write to an @audit_emitter-routed "
            "audit table OUTSIDE the @audit_emitter family (forks the "
            "§164.312(b)/(c)(1) HMAC audit chain):\n"
            + "\n".join(
                f"  {rel}:{ln}  INSERT/UPDATE {tbl}  in {fn!r}"
                for rel, ln, tbl, fn in violations
            )
            + "\n\nFIX: route the write through the @audit_emitter helper for "
            "that table (record_*); OR, if it is a legitimate chain-primitive "
            "/ atomic-tx writer, add it to _RAW_WRITE_ALLOWLIST with a "
            "one-line justification (hipaa-sme + db-sme review)."
        )

    def test_no_stale_raw_write_allowlist_entries(self):
        """PD#7 — census the censusers. Every allow-list entry must still
        be the enclosing fn of an in-scope raw audit-table write on HEAD;
        a stale entry (the writer was removed/renamed/routed) is flagged so
        the allow-list can't silently grant a future namesake a pass."""
        live_writers = {
            fn for _, _, _, fn in self._scan_raw_audit_writes()
            if fn is not None
        }
        stale = set(self._RAW_WRITE_ALLOWLIST) - live_writers
        assert not stale, (
            "Stale _RAW_WRITE_ALLOWLIST entries (no longer a raw in-scope "
            f"audit-table writer on HEAD): {sorted(stale)}. Remove them — a "
            "stale entry would silently exempt a future same-named function."
        )

    def test_in_scope_table_set_covers_the_forward_emitter_tables(self):
        """Anti-drift cross-check: the FORWARD redaction map exists per
        emitter-FUNCTION; this inverse pin keys on emitter TABLES. Prove the
        emitter-routed table set is non-empty and disjoint from the
        self-managed-chain set (a table can't be both routed-via-emitter AND a
        self-managed chain primitive — that ambiguity would let a writer dodge
        both arms)."""
        assert self._EMITTER_ROUTED_TABLES, "emitter-routed table set is empty"
        overlap = self._EMITTER_ROUTED_TABLES & self._SELF_MANAGED_CHAIN_TABLES
        assert not overlap, (
            f"table classified BOTH emitter-routed AND self-managed-chain: "
            f"{sorted(overlap)} — resolve the classification"
        )


class TestInverseAuditEmitterPinTeeth:
    """Teeth for the inverse pin: drive the scanner+classifier over synthetic
    source so a regression in the matcher itself is caught (PD#7 — the pin's
    own logic is testable, not trusted)."""

    import ast as _ast
    import textwrap as _textwrap

    def _classify(self, src: str):
        """Run the pin's exact matcher logic over a source string; return the
        list of (lineno, table, enclosing_func) raw-audit-write hits."""
        pin = TestInverseAuditEmitterPin
        tree = self._ast.parse(self._textwrap.dedent(src))
        annotate_parents(tree)
        hits = []
        for node in self._ast.walk(tree):
            if not isinstance(node, self._ast.Call):
                continue
            func = node.func
            if not isinstance(func, self._ast.Attribute):
                continue
            if func.attr not in ("execute", "executemany"):
                continue
            sql = pin._first_sql_literal(node)
            if sql is None:
                continue
            m = pin._INSERT_RE.search(sql) or pin._UPDATE_RE.search(sql)
            if not m or m.group(1) not in pin._IN_SCOPE_TABLES:
                continue
            enclosing = pin._enclosing_func(node)
            hits.append((node.lineno, m.group(1), enclosing))
        return hits

    def test_planted_raw_insert_in_non_emitter_is_flagged(self):
        hits = self._classify(
            '''
            def some_handler(conn):
                conn.execute(
                    "INSERT INTO hipaa_access_events "
                    "(ts, actor_user_id, account_id, operation, outcome) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (1, 2, 3, "x", "ok"),
                )
            '''
        )
        assert len(hits) == 1
        _, table, fn = hits[0]
        assert table == "hipaa_access_events"
        assert fn == "some_handler"
        # And the classifier would flag it: not an emitter, not allow-listed.
        emitters = TestInverseAuditEmitterPin._audit_emitter_funcnames()
        assert fn not in emitters
        assert fn not in TestInverseAuditEmitterPin._RAW_WRITE_ALLOWLIST

    def test_update_set_on_audit_table_is_flagged(self):
        """The UPDATE arm — what the INSERT-only signature would miss."""
        hits = self._classify(
            '''
            def rogue_update(conn, event_id):
                conn.execute(
                    "UPDATE hipaa_access_events SET outcome = ? WHERE id = ?",
                    ("ok", event_id),
                )
            '''
        )
        assert len(hits) == 1
        assert hits[0][1] == "hipaa_access_events"
        assert hits[0][2] == "rogue_update"

    def test_emitter_decorated_raw_insert_passes(self):
        """A raw INSERT inside an @audit_emitter def is matched by the scanner
        but PASSES the classifier (enclosing fn is in the emitter set)."""
        hits = self._classify(
            '''
            @db_write
            @audit_emitter
            def record_user_status_event(conn):
                conn.execute(
                    "INSERT INTO user_status_events "
                    "(ts, target_user_id, actor_user_id, event, reason) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (),
                )
            '''
        )
        assert len(hits) == 1
        _, table, fn = hits[0]
        assert table == "user_status_events"
        # record_user_status_event IS a real @audit_emitter on HEAD → passes.
        emitters = TestInverseAuditEmitterPin._audit_emitter_funcnames()
        assert fn in emitters

    def test_allowlisted_writer_passes(self):
        """A raw write inside an allow-listed writer is matched but PASSES."""
        hits = self._classify(
            '''
            def insert_log_entry(conn):
                conn.execute(
                    "INSERT INTO log_entries "
                    "(ts, level, logger, message, extra_json, created_at, "
                    " prev_hash, row_hash, hash_alg, master_key_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (),
                )
            '''
        )
        assert len(hits) == 1
        assert hits[0][2] == "insert_log_entry"
        assert hits[0][2] in TestInverseAuditEmitterPin._RAW_WRITE_ALLOWLIST

    def test_non_audit_table_insert_is_not_flagged(self):
        """A raw INSERT into a NON-audit table (e.g. users) is invisible to
        the pin — no false positive on ordinary data writes."""
        hits = self._classify(
            '''
            def create_user(conn):
                conn.execute(
                    "INSERT INTO users (email, name, role) VALUES (?, ?, ?)",
                    ("a@b.c", "n", "user"),
                )
                conn.execute(
                    "UPDATE email_accounts SET hipaa = ? WHERE id = ?",
                    (1, 5),
                )
            '''
        )
        assert hits == []


# ---------------------------------------------------------------------------
# Gap-event firing — end-to-end
# ---------------------------------------------------------------------------

class TestGapEventFiring:
    """The decisive Deliverable 3 tests: when a marked emitter
    fails, a gap row IS written with the correct payload and chain.
    """

    def test_failed_audit_emitter_writes_gap_row(self, conn):
        """A `@db_write @audit_emitter` helper that raises mid-write
        produces a gap_events row before the original exception
        propagates."""
        # Use record_user_status_event with a bad target_user_id (no
        # such user, FK ON DELETE CASCADE will not catch this because
        # the table has no FK on target_user_id — but the INSERT
        # itself succeeds. To force a failure, simulate a connection-
        # state issue by closing+reopening with a broken cursor.
        #
        # Simplest reliable failure: stuff the call with an
        # incompatible kwarg type via a wrapper that re-raises.
        #
        # Use a custom test emitter to control the failure:

        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing_test_emitter(
            conn, *, target_user_id, actor_user_id, event, reason="",
        ):
            # Simulate an audit INSERT failing mid-helper.
            raise sqlite3.OperationalError("simulated audit failure")

        # Pre-state: zero gap rows.
        pre = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert pre == 0

        # Trigger failure.
        with pytest.raises(sqlite3.OperationalError, match="simulated"):
            _failing_test_emitter(
                conn,
                target_user_id=99, actor_user_id=42,
                event="disabled", reason="op-internal-reason",
            )

        # Post-state: exactly one gap row.
        rows = conn.execute(
            "SELECT helper_name, original_args_redacted, "
            "original_args_hash, exc_type, exc_msg, prev_hash, "
            "row_hash, hash_alg, master_key_version "
            "FROM audit_gap_events"
        ).fetchall()
        assert len(rows) == 1
        r = rows[0]
        assert r["helper_name"] == "_failing_test_emitter"
        assert r["exc_type"] == "OperationalError"
        assert "simulated" in r["exc_msg"]
        # First gap row → prev_hash is the genesis empty string.
        assert r["prev_hash"] == ""
        # row_hash is computed from HMAC chain — not empty.
        assert r["row_hash"] != ""
        assert r["hash_alg"] == "hmac-sha256-v2"
        assert r["master_key_version"] == _TEST_HMAC_VERSION
        # original_args_hash is a hex SHA-256 (64 chars).
        assert len(r["original_args_hash"]) == 64

    def test_successful_audit_emitter_writes_no_gap_row(self, conn):
        """The happy path — a successful emit — must NOT trigger a
        gap-row write (no false positives)."""
        # Seed a user the FK can reference. The audit table itself
        # has no FK to users, but the call will execute cleanly.
        conn.execute(
            "INSERT INTO users (email, name, role, created_at, disabled) "
            "VALUES (?, ?, ?, ?, ?)",
            ("u@example.com", "U", "user", "2026-01-01T00:00:00Z", 0),
        )
        conn.commit()

        record_user_status_event(
            conn, target_user_id=1, actor_user_id=None,
            event="disabled", reason="test",
        )

        rows = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert rows == 0

    def test_set_user_disabled_failure_gap_row_redacts_reason(self, conn):
        """A2: a real `set_user_disabled` failure (unknown user → ValueError
        before the tx) writes a gap row whose redacted payload carries the IN
        fields (target_user_id, actor_user_id, disabled) via the new positional
        bind branch, and DROPS the free-text ``reason`` (hash-only)."""
        with pytest.raises(ValueError, match="not found"):
            # Positional after conn: (target_user_id, disabled, actor_user_id,
            # reason). 99999 = no such user → ValueError inside @db_write.
            set_user_disabled(conn, 99999, True, 42, "phi-laden reason text")
        r = conn.execute(
            "SELECT helper_name, original_args_redacted "
            "FROM audit_gap_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert r["helper_name"] == "set_user_disabled"
        payload = json.loads(r["original_args_redacted"])
        assert payload.get("target_user_id") == 99999
        assert payload.get("actor_user_id") == 42
        assert "disabled" in payload          # the bool IN field bound
        assert "reason" not in payload        # free-text OUT → hash-only

    def test_record_style_distill_event_failure_gap_row_keeps_was_cloud(
        self, conn,
    ):
        """A2: a real `record_style_distill_event` failure (bad recipient_hash
        → ValueError) writes a gap row that KEEPS ``was_cloud`` (the egress
        signal) and DROPS ``recipient_hash`` (correlatable identifier)."""
        with pytest.raises(ValueError, match="recipient_hash"):
            record_style_distill_event(
                conn, account_id=5, actor_user_id=7, backend_id=1,
                backend_type="openai", was_cloud=True, outcome="ok",
                kind="per_contact",
                recipient_hash="not-a-hash@has-an-at-sign",  # → ValueError
            )
        r = conn.execute(
            "SELECT helper_name, original_args_redacted "
            "FROM audit_gap_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert r["helper_name"] == "record_style_distill_event"
        payload = json.loads(r["original_args_redacted"])
        assert payload.get("account_id") == 5
        assert payload.get("was_cloud") is True   # egress signal preserved
        assert "recipient_hash" not in payload    # correlatable id OUT

    def test_non_audit_emitter_failure_writes_no_gap_row(self, conn):
        """A regular `@db_write` helper (no @audit_emitter marker)
        that fails must NOT trigger a gap-row write."""
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        def _failing_non_emitter(conn):
            raise RuntimeError("regular @db_write failure")

        with pytest.raises(RuntimeError, match="regular"):
            _failing_non_emitter(conn)

        rows = conn.execute(
            "SELECT COUNT(*) FROM audit_gap_events"
        ).fetchone()[0]
        assert rows == 0

    def test_redacted_payload_excludes_out_fields(self, conn):
        """The redacted payload contains IN-class fields ONLY. OUT-
        class fields (PHI-adjacent) must be absent."""
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def record_user_status_event(  # shadow real name to hit map
            conn, *, target_user_id, actor_user_id, event, reason="",
        ):
            raise sqlite3.OperationalError("force gap")

        with pytest.raises(sqlite3.OperationalError):
            record_user_status_event(
                conn, target_user_id=7, actor_user_id=3,
                event="enabled",
                reason="PHI-content-must-not-leak-into-gap-table",
            )

        row = conn.execute(
            "SELECT original_args_redacted FROM audit_gap_events"
        ).fetchone()
        payload = json.loads(row["original_args_redacted"])
        # IN-class fields PRESENT.
        assert payload.get("target_user_id") == 7
        assert payload.get("actor_user_id") == 3
        assert payload.get("event") == "enabled"
        # OUT-class (reason) ABSENT from payload — even though its
        # value contributes to original_args_hash.
        assert "reason" not in payload

    def test_gap_chain_links_across_two_rows(self, conn):
        """A SECOND gap row's prev_hash equals the first row's
        row_hash — the chain advances correctly."""
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing(conn):
            raise sqlite3.OperationalError("force chain link")

        with pytest.raises(sqlite3.OperationalError):
            _failing(conn)
        with pytest.raises(sqlite3.OperationalError):
            _failing(conn)

        rows = conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_gap_events "
            "ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        # Row 1: prev_hash = genesis "".
        assert rows[0]["prev_hash"] == ""
        # Row 2: prev_hash = row 1's row_hash. Chain link.
        assert rows[1]["prev_hash"] == rows[0]["row_hash"]
        # Two distinct row_hash values (different ts → different
        # canonical input → different HMAC).
        assert rows[0]["row_hash"] != rows[1]["row_hash"]


# ---------------------------------------------------------------------------
# Chain-hash helpers
# ---------------------------------------------------------------------------

class TestChainHelpers:
    def test_get_last_gap_row_hash_empty_for_fresh_table(self, conn):
        assert get_last_gap_row_hash(conn) == ""

    def test_get_last_gap_row_hash_returns_latest(self, conn):
        # Insert a manual row.
        h = compute_gap_row_hash(
            "", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        conn.execute(
            "INSERT INTO audit_gap_events "
            "(ts, helper_name, original_args_redacted, "
            " original_args_hash, exc_type, exc_msg, prev_hash, "
            " row_hash, hash_alg, master_key_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-05-25T15:00:00+00:00", "test_helper", "{}",
             "deadbeef", "RuntimeError", "test",
             "", h, "hmac-sha256-v1", _TEST_HMAC_VERSION),
        )
        conn.commit()
        assert get_last_gap_row_hash(conn) == h

    def test_compute_gap_row_hash_deterministic(self):
        """Same inputs → same hash. Stamps that the canonicalisation
        is stable across calls."""
        a = compute_gap_row_hash(
            "prev", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        b = compute_gap_row_hash(
            "prev", "2026-05-25T15:00:00+00:00", "test_helper",
            "{}", "deadbeef", "RuntimeError", "test",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        assert a == b
        # Hex of HMAC-SHA256 → 64 chars.
        assert len(a) == 64

    def test_compute_gap_row_hash_changes_with_input(self):
        """Different ts → different hash. The chain is sensitive to
        every field of the row."""
        a = compute_gap_row_hash(
            "", "2026-05-25T15:00:00+00:00", "h", "{}", "", "T", "m",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        b = compute_gap_row_hash(
            "", "2026-05-25T15:00:01+00:00", "h", "{}", "", "T", "m",
            hash_alg="hmac-sha256-v1", master_key_version=_TEST_HMAC_VERSION,
        )
        assert a != b


# ---------------------------------------------------------------------------
#  HOTFIX-4 — gap-on-gap log format (operator-actionable under
# ``logging.lastResort``)
# ---------------------------------------------------------------------------

class TestGapOnGapLogFormat:
    """When ``_write_audit_gap_event`` itself fails (the gap-write
    INSERT times out under file-lock storm — observed live on
    the test container 2026-05-25), the secondary log line at
    ``db_writelock.py:234`` is the operator's last-line §164.312(b)
    signal. hipaa-sme 2026-05-25 verdict: the line MUST embed
    ``helper`` + original emitter's exc_type + gap-write's exc_type
    IN THE MESSAGE STRING so the signal survives
    ``logging.lastResort`` (which strips ``extra`` structured
    fields).

    These tests are the count-agnostic structural pin: a future
    contributor who refactors the log call must keep all three
    substrings present, or the §164.312(b) coverage degrades
    silently under handler-stripped conditions.
    """

    def test_gap_on_gap_log_message_contains_required_substrings(
        self, conn, caplog,
    ):
        """The formatted log message MUST contain
        ``helper=<emitter>``, ``original_exc=<emitter-exc>``,
        ``gap_exc=<gap-write-exc>`` as bare substrings (not
        relying on ``extra`` structured fields)."""
        import logging
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        # Build a synthetic emitter whose @db_write body raises a
        # known class, AND patch _write_audit_gap_event to itself
        # raise so the gap-on-gap branch is taken.
        @_dw
        @_ae
        def _failing_emitter(conn):
            raise sqlite3.ProgrammingError(
                "simulated emitter-side bind error"
            )

        from email_triage.db import audit as audit_mod
        original_write = audit_mod._write_audit_gap_event

        def _write_that_raises(*args, **kwargs):
            raise sqlite3.OperationalError(
                "simulated gap-write file-lock contention"
            )

        audit_mod._write_audit_gap_event = _write_that_raises
        try:
            with caplog.at_level(
                logging.ERROR,
                logger="email_triage.web.db_writelock",
            ):
                with pytest.raises(sqlite3.ProgrammingError):
                    _failing_emitter(conn)
        finally:
            audit_mod._write_audit_gap_event = original_write

        # Find the gap-on-gap record. Multiple ERROR records may
        # exist in caplog (Step 1 / Step 2 rollback logs); the
        # gap-on-gap record is identified by the ``gap-on-gap``
        # marker substring.
        gap_records = [
            r for r in caplog.records
            if "gap-on-gap" in r.getMessage()
        ]
        assert len(gap_records) == 1, (
            f"Expected exactly 1 gap-on-gap log record, got "
            f"{len(gap_records)}: {[r.getMessage() for r in caplog.records]}"
        )
        msg = gap_records[0].getMessage()

        # Required substrings — operator-actionable under
        # ``logging.lastResort`` (the structured ``extra`` fields
        # would be stripped).
        assert "helper=_failing_emitter" in msg, msg
        assert "original_exc=ProgrammingError" in msg, msg
        assert "gap_exc=OperationalError" in msg, msg
        # And the marker stays in place
        assert "gap-on-gap" in msg, msg

    def test_gap_on_gap_log_extra_contains_structured_fields(
        self, conn, caplog,
    ):
        """Defense-in-depth: ``extra._extra`` ALSO carries the
        same fields as discrete keys (structured-JSON consumers
        get them as queryable fields, not just embedded in the
        message string)."""
        import logging
        from email_triage.db.audit import audit_emitter as _ae
        from email_triage.web.db_writelock import db_write as _dw

        @_dw
        @_ae
        def _failing_emitter(conn):
            raise sqlite3.ProgrammingError("simulated")

        from email_triage.db import audit as audit_mod
        original_write = audit_mod._write_audit_gap_event

        def _write_that_raises(*args, **kwargs):
            raise sqlite3.OperationalError("simulated gap")

        audit_mod._write_audit_gap_event = _write_that_raises
        try:
            with caplog.at_level(
                logging.ERROR,
                logger="email_triage.web.db_writelock",
            ):
                with pytest.raises(sqlite3.ProgrammingError):
                    _failing_emitter(conn)
        finally:
            audit_mod._write_audit_gap_event = original_write

        gap_records = [
            r for r in caplog.records
            if "gap-on-gap" in r.getMessage()
        ]
        assert len(gap_records) == 1
        rec = gap_records[0]
        extra = getattr(rec, "_extra", None)
        assert extra is not None, (
            "gap-on-gap record missing ``_extra`` attribute — "
            "structured-JSON consumers won't see the per-field "
            "shape"
        )
        # The four documented fields hipaa-sme called out for the
        # structured-JSON path.
        assert extra.get("original_exception_in_progress") is True
        assert extra.get("helper") == "_failing_emitter"
        assert extra.get("audit_emitter_error_type") == (
            "ProgrammingError"
        )
        assert extra.get("gap_write_error_type") == (
            "OperationalError"
        )
