"""PHI-table / audit-chain reconciliation tooling (H-11, Cycle 7).

Closes the EQM-04 tooling-gap disclosed in the §164.312(c)(2) PHI-tables
equivalent-measure inline rationale block at ``engine/store.py:79+``. Per
hipaa-sme-2 regulatory calibration (H-11 row in
``internal documentation`` §4.1):

  - NOT REQUIRED per literal §164.312(c)(2) Addressable doctrine — the
    regulatory test is mechanism-EXISTS (forensic-reconciliation evidence
    via the HMAC-chained ``log_entries`` audit trail), not mechanism-runs-
    continuously.
  - OCR-posture-aligned per NIST SP 800-66 R2 §4.4 (continuous-monitoring
    patterns leaning).
  - Operator-policy ASAP per ``project_hipaa_asap_policy.md`` (HIPAA items
    must-fix; severity calibrates sequencing, not disposition).

The helper compares the live PHI-table state against the
HMAC-chained ``log_entries`` audit trail (EQM-05) — the authoritative
record of every flow-mutating operation. An insider with direct DB-write
privilege who tampers with a PHI row WITHOUT also forging a chained
``log_entries`` row (which requires the master-key HMAC) leaves the
divergence detectable here.

Design Q resolution (per dispatch §"Design Q for you"): option (a) —
parse ``log_entries.extra_json`` for the row PK. Justification:

  - ``flow_id`` is consistently emitted in every flow-lifecycle log
    (engine/flow.py:79-240: Created, Fetched, Classifying, Classified,
    Routing, Acting, Waiting, Failed, Finished — 7+ emit sites). The
    SQLiteLogHandler at triage_logging.py:360 hoists caller kwargs to
    top-level ``extra_json`` keys.
  - Option (b) ``phi_table_audit`` view would duplicate writes — adds
    hot-path cost and a second key-management surface (rejected for the
    same reasons EQM-04 rationale (b) rejects per-row PHI-table HMAC).
  - Option (c) ``hipaa_access_events`` is HIPAA-mode-only AND HTTP-
    mediated — misses the direct-DB-write threat model and non-HIPAA
    installs that still benefit from integrity checking.

Read-only by design: the public ``verify_phi_table_against_audit_log``
helper opens nothing, mutates nothing, and is safe to run against a
production DB or a backup snapshot. The only write the surrounding CLI
performs is the optional ``hipaa_access_events`` divergence-detected
audit-trail row (HIPAA-mode-only) — that write is the
§164.308(a)(1)(ii)(D) Information System Activity Review surface, not
PHI mutation.

H-11 disposition shape (per Cycle 7 experiment F pre-classify):
**standard EQM-05-supporting-tool** — does NOT introduce a new EQM-NN
substitution row. EQM-04's audit-chain control 1 is the §164.312(c)(2)
mechanism; this module is operational tooling that makes that
mechanism's investigator-workflow latency floor disappear.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Registry — PHI-bearing tables + their per-row "operation log" PK hint
# ---------------------------------------------------------------------------
#
# For each PHI-bearing table we record:
#   - the SQL primary-key column the live table is keyed on
#   - the ``extra_json`` key in log_entries that names the row in
#     emitted log lines (see engine/flow.py for the consistent caller
#     pattern; FlowEngine emits ``flow_id=flow.flow_id``).
#
# Tables NOT in this registry are out of reconciliation scope by design:
#   - ``log_entries`` itself (covered by ``verify_log_chain``; reconciling
#     it against itself would be circular).
#   - ``triaged_messages`` (hashed-only message_id; not PHI-bearing in
#     raw form; integrity is index-side, not PHI-side).
#   - Audit-event sibling tables (``access_log``, ``hipaa_access_events``,
#     ``auth_events``, etc.) — they ARE the audit trail; reconciling
#     audit against audit is circular.
#   - Settings / secrets store (not PHI; integrity is key-rotation-side).
#
# The registry is import-time-static. Adding a new PHI-bearing table
# is a deliberate change — co-locate the audit-trail emit pattern in the
# caller (must emit the PK in extra_json) AND extend this map in the
# same PR.

@dataclass(frozen=True)
class _PhiTableSpec:
    """Static metadata for one PHI-bearing reconciliation target."""
    table: str
    pk_column: str
    extra_key: str


_PHI_TABLES: tuple[_PhiTableSpec, ...] = (
    _PhiTableSpec(table="flows", pk_column="flow_id", extra_key="flow_id"),
)
"""Reconciliation v1 scope.

Currently covers ``flows`` only — the canonical PHI-state table on the
triage hot path. ``triage_runs`` is intentionally deferred: its
``results_json`` is post-classification metadata (no raw PHI) and the
``log_entries`` correlator field for run-level operations is account
+ timestamp, not a stable row PK, so the reconciliation shape would
be different. Add it when there is operator evidence of need; the
register currently has zero divergence reports against this surface.
"""


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------

@dataclass
class _TableReport:
    """Per-table divergence counters + sample rows for the operator.

    All counts are post-prune-aware: an audit row that points at a
    table row that was legitimately deleted (PHI cleanup, account
    deletion ON DELETE CASCADE) shows up as an
    ``audit_rows_without_table_row`` entry but the operator can
    correlate against the cascade record. The reconciliation is
    DIAGNOSTIC not GATING — the operator reads counts + samples and
    decides whether a divergence is real tampering or expected churn.
    """
    table: str
    table_row_count: int = 0
    audit_pk_count: int = 0
    rows_with_audit_match: int = 0
    rows_without_audit_match: int = 0
    audit_rows_without_table_row: int = 0
    sample_diverged_pks: list[str] = field(default_factory=list)


@dataclass
class ReconciliationReport:
    """Operator-readable report from a single reconciliation pass.

    Structured so the CLI can render either a human-friendly summary
    (default) or a JSON blob (``--json``) for scripted callers (the monitoring system,
    operator monitoring scripts).

    The chain-verify roll-up is included in the same report because a
    PHI-table divergence is only meaningfully attributable when the
    audit chain itself is intact — if the chain has a break, the
    diverged rows could be legitimate operations that the broken chain
    cannot vouch for, not tampering. Operator should resolve the chain
    break first, then re-run reconciliation.
    """
    generated_at: str
    chain_verify_passed: bool
    chain_break_reason: str | None
    chain_length: int
    tables: list[_TableReport]
    divergence_count: int

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_phi_table_against_audit_log(
    conn: sqlite3.Connection,
    *,
    table: str | None = None,
    since: datetime | None = None,
    sample_limit: int = 5,
) -> ReconciliationReport:
    """Walk PHI-bearing tables + cross-reference against the audit chain.

    Args:
        conn: open SQLite connection (read-only mode supported and
            recommended — the helper performs zero writes).
        table: optional single-table filter. ``None`` reconciles every
            entry in ``_PHI_TABLES``. Unknown table name → ``ValueError``.
        since: optional cutoff. Audit rows older than this timestamp
            (compared against ``log_entries.ts``) are not consulted.
            PHI-table rows are still listed; an absent audit match for
            a row that pre-dates the cutoff WILL show up in
            ``rows_without_audit_match`` — the operator chooses a
            cutoff with full awareness of this. Passing ``None`` walks
            the full chain.
        sample_limit: how many diverged PKs to include in the report
            samples per table (default 5). Sample PKs are NEVER PHI —
            they are surrogate identifiers (UUIDs, autoincrement ints)
            by design.

    Returns:
        ``ReconciliationReport`` with per-table counters + chain-verify
        roll-up + UTC ISO timestamp.

    Raises:
        ValueError: ``table`` argument names an unknown table.

    The reconciliation is DIAGNOSTIC: zero ``rows_without_audit_match``
    + zero ``audit_rows_without_table_row`` is the clean state; any
    nonzero count is operator-investigatable, not automatically a
    tampering claim. Cascade deletes, log-prune cycles, and legitimate
    pre-chain rows all show as divergence on first run; the operator
    correlates against the chain-anchor / cascade record / prune
    history.
    """
    # Late-bind the chain verifier (avoids module-load cycle through
    # the audit module's re-export shims via web/db).
    from email_triage.db.audit import verify_log_chain

    if table is not None and not any(t.table == table for t in _PHI_TABLES):
        raise ValueError(
            f"verify_phi_table_against_audit_log: unknown table "
            f"{table!r}. Known tables: "
            f"{[t.table for t in _PHI_TABLES]}"
        )

    specs = (
        tuple(t for t in _PHI_TABLES if t.table == table)
        if table is not None
        else _PHI_TABLES
    )

    # Chain-verify is the gate: a broken chain invalidates every
    # divergence claim. We still WALK the tables (report is more useful
    # filled in than not) but flag the chain-break loudly at the top.
    chain_result = verify_log_chain(
        conn,
        since=since.isoformat() if since is not None else None,
    )
    chain_passed = chain_result["first_break_id"] is None
    chain_break_reason = (
        chain_result["first_break_reason"] if not chain_passed else None
    )

    since_iso = since.isoformat() if since is not None else None

    table_reports: list[_TableReport] = []
    divergence_count = 0

    for spec in specs:
        report = _reconcile_one_table(
            conn,
            spec=spec,
            since_iso=since_iso,
            sample_limit=sample_limit,
        )
        table_reports.append(report)
        divergence_count += (
            report.rows_without_audit_match
            + report.audit_rows_without_table_row
        )

    return ReconciliationReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        chain_verify_passed=chain_passed,
        chain_break_reason=chain_break_reason,
        chain_length=int(chain_result["chain_length"] or 0),
        tables=table_reports,
        divergence_count=divergence_count,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _reconcile_one_table(
    conn: sqlite3.Connection,
    *,
    spec: _PhiTableSpec,
    since_iso: str | None,
    sample_limit: int,
) -> _TableReport:
    """Reconcile a single PHI-bearing table against the audit chain.

    Single-pass per direction (table → audit, audit → table). Both use
    a Python set built once from the streamed query result — fine for
    the ``flows`` scale (operator-installed mailbox; thousands of rows,
    not millions). If reconciliation expands to log-scale audit-trail
    sources, swap for a SQL ``LEFT JOIN`` against a transient
    ``CREATE TEMP TABLE`` populated from extra_json — defer until
    operator evidence of need (premature optimization on a tool that
    runs at operator cadence, not on hot path).
    """
    table_pks = _fetch_table_pks(conn, spec)
    audit_pks = _fetch_audit_pks_from_log(conn, spec, since_iso)

    pks_only_in_table = sorted(table_pks - audit_pks)
    pks_only_in_audit = sorted(audit_pks - table_pks)

    report = _TableReport(
        table=spec.table,
        table_row_count=len(table_pks),
        audit_pk_count=len(audit_pks),
        rows_with_audit_match=len(table_pks & audit_pks),
        rows_without_audit_match=len(pks_only_in_table),
        audit_rows_without_table_row=len(pks_only_in_audit),
    )
    # Sample for the operator. PKs are surrogate identifiers (UUIDs /
    # auto-increment ints) by design — they are NOT PHI. The sample
    # field exists so the operator can ``SELECT * FROM <table> WHERE
    # <pk_column> = ?`` to investigate each divergence individually
    # against the row's full audit-chain history.
    sample: list[str] = []
    sample.extend(pks_only_in_table[: sample_limit])
    if len(sample) < sample_limit:
        sample.extend(pks_only_in_audit[: sample_limit - len(sample)])
    report.sample_diverged_pks = sample
    return report


def _fetch_table_pks(
    conn: sqlite3.Connection,
    spec: _PhiTableSpec,
) -> set[str]:
    """Stream every live PK from the PHI table into a Python set."""
    sql = f"SELECT {spec.pk_column} AS pk FROM {spec.table}"
    rows = conn.execute(sql).fetchall()
    return {str(r["pk"]) for r in rows if r["pk"] is not None}


def _fetch_audit_pks_from_log(
    conn: sqlite3.Connection,
    spec: _PhiTableSpec,
    since_iso: str | None,
) -> set[str]:
    """Stream every PK that appears in any log_entries row's extra_json.

    Filters on ``logger LIKE 'email_triage.engine.%'`` to scope to the
    pipeline-emitted rows (FlowEngine + downstream actions). Other loggers
    that happen to mention a flow_id in their extras (e.g., ``web.routers``
    rendering a flow page) are intentionally INCLUDED via the broader
    fallback: any row whose extra_json contains the key. Belt-and-
    suspenders — a row is in the audit set if any logger said its name.
    """
    pks: set[str] = set()
    params: list[Any] = []
    clauses: list[str] = ["row_hash != ''"]
    # Hint the planner with a LIKE on extra_json so non-flow rows don't
    # pay the json.loads cost. ``%"flow_id"%`` is a literal-substring
    # LIKE on the canonical JSON encoding — flow_id is always quoted as
    # a JSON key. False positives (a row whose extra_json mentions the
    # literal string ``flow_id`` without a value) will fall out at the
    # json.loads + .get() step below.
    clauses.append("extra_json LIKE ?")
    params.append(f'%"{spec.extra_key}"%')
    if since_iso is not None:
        clauses.append("ts >= ?")
        params.append(since_iso)
    sql = (
        "SELECT extra_json FROM log_entries "
        f"WHERE {' AND '.join(clauses)}"
    )
    rows = conn.execute(sql, params).fetchall()
    for r in rows:
        raw = r["extra_json"]
        if not raw:
            continue
        try:
            extras = json.loads(raw)
        except (ValueError, TypeError):
            # Malformed extras don't poison the walk — the chain
            # verifier is the authoritative integrity check; reconcile
            # is a downstream consumer.
            continue
        if not isinstance(extras, dict):
            continue
        pk = extras.get(spec.extra_key)
        if pk is None:
            continue
        pks.add(str(pk))
    return pks


def emit_divergence_event(
    conn: sqlite3.Connection,
    *,
    report: ReconciliationReport,
) -> int | None:
    """Emit a ``hipaa_access_events`` row when a HIPAA-mode reconcile
    finds divergence — §164.308(a)(1)(ii)(D) audit-trail surface.

    Caller (the CLI) decides whether to invoke based on
    ``is_hipaa_mode() AND report.divergence_count > 0``. This helper does
    NOT re-check HIPAA mode; it is mechanism only.

    Returns the inserted row id, or ``None`` if the write was suppressed
    (caller passed a divergence_count of 0 — the helper double-checks
    so a no-divergence report never silently writes).

    Per H-06 precedent (digest_archive_failed shape), the
    ``hipaa_access_events`` row uses ``actor_user_id=None`` (system-
    initiated) and a non-PHI detail string carrying the divergence
    count. No table names beyond the registry are emitted; no sample
    PKs are emitted (operator can re-run the CLI to inspect samples).
    """
    if report.divergence_count <= 0:
        return None
    from email_triage.db.audit import record_hipaa_access_event
    # Account anchoring: H-11 reconciliation is system-wide; the
    # ``hipaa_access_events.account_id`` FK requires a specific
    # account anchor (NOT NULL by schema). Anchor on the
    # lowest-id HIPAA-flagged account (``email_accounts.hipaa = 1``).
    # If no HIPAA account exists yet, the event isn't emittable in
    # this schema — return None and let the caller surface a
    # WARNING-tier non-PHI log line instead. (The chain itself
    # already records the reconciliation INVOCATION via the CLI's
    # audit-emit-on-start; H-11 just adds the per-account
    # outcome row when scope permits.)
    anchor = conn.execute(
        "SELECT id FROM email_accounts "
        "WHERE hipaa = 1 ORDER BY id ASC LIMIT 1"
    ).fetchone()
    if anchor is None:
        return None
    detail = (
        f"H-11 reconcile: {report.divergence_count} divergence(s) "
        f"across {sum(1 for t in report.tables if t.table_row_count)} "
        f"PHI table(s); chain_verify_passed="
        f"{report.chain_verify_passed}"
    )
    return record_hipaa_access_event(
        conn,
        actor_user_id=None,
        account_id=int(anchor["id"]),
        operation="reconcile_divergence_detected",
        outcome="error",
        detail=detail,
    )
