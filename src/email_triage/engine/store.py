"""SQLite-backed persistence for flow state with revision-checked mutations.

Canonical connection pattern
─────────────────────────────────────
``FlowStore`` ALWAYS accepts an injected ``sqlite3.Connection`` —
the one owned by ``email_triage.web.db.init_db`` (held on
``app.state.db``). That single shared connection guarantees one
writer per process: WAL still serialises at the OS layer, but
sharing the in-process connection eliminates the stale-read /
expected_revision-regress window that two independent writers would
otherwise create against the same file.

Canonical caller pattern (web handler / orchestrator)::

    from email_triage.engine.store import FlowStore
    store = FlowStore(connection=request.app.state.db)

Legacy fallback (DEPRECATED)
─────────────────────────────
``FlowStore(db_path="/path/to/triage.db")`` — only the standalone
CLI / one-shot triage path still uses this form, because the CLI
runs without a web-app lifespan and therefore has no canonical
connection to inject. The legacy path opens its own connection
(with WAL + FK pragmas), emits a WARNING log naming this entry
point, and otherwise behaves identically. Do NOT introduce new
callers on the legacy path — pass in a connection from
``init_db`` instead.
"""

from __future__ import annotations

from email_triage.db._helpers import dump_json_col, load_json_col

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from email_triage.db._helpers import apply_compatible_row_factory
from email_triage.engine.models import (
    Classification,
    FlowState,
    FlowStatus,
)
from email_triage.triage_logging import get_logger
from email_triage.web.db_writelock import get_write_lock

log = get_logger("engine.store")


class RevisionConflict(Exception):
    """Raised when an update targets a stale revision."""

    def __init__(self, flow_id: str, expected: int, actual: int | None = None):
        self.flow_id = flow_id
        self.expected = expected
        self.actual = actual
        detail = f"expected {expected}"
        if actual is not None:
            detail += f", found {actual}"
        super().__init__(f"Revision conflict on flow {flow_id}: {detail}")


class FlowNotFound(Exception):
    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        super().__init__(f"Flow not found: {flow_id}")


class DuplicateFlow(Exception):
    def __init__(self, provider: str, message_id: str):
        self.provider = provider
        self.message_id = message_id
        super().__init__(f"Flow already exists for {provider}:{message_id}")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
#
# CANONICAL DDL SITE for the ``flows`` table. ``web/db.py`` carries a
# DUPLICATE of this DDL block (lines 35-55, with explicit comment "Flows
# table is owned by engine/store.py but we declare it here too so that
# ``init_db`` can bootstrap a complete schema from scratch") so the web
# app's bootstrap can create the table without importing the engine
# layer. If THIS DDL changes, the duplicate in ``web/db.py`` MUST change
# in the same commit; the two are kept verbatim-identical by convention.
#
# §164.312(c)(2) Addressable integrity mechanism for PHI tables
# (H-02b + N-02 consolidated finding, EQM-04 — Cycle 6, 2026-05-23,
#  revised per db-sme-2 + DA-3 overclaim review 2026-05-23)
# ──────────────────────────────────────────────────────────────────
#
# The ``flows`` table (and its sibling PHI-bearing tables ``email_messages``,
# ``email_account_state``, etc.) holds ePHI at rest. §164.312(c)(2) is an
# Addressable implementation specification: "Implement electronic
# mechanisms to corroborate that electronic protected health information
# has not been altered or destroyed in an unauthorized manner."
#
# Per the §164.306(d)(3)(ii)(B) Addressable framework, the project may
# EITHER strict-implement per-row keyed-MAC integrity OR document an
# equivalent alternative measure. The project chooses the equivalent
# measure (EQM-04) for the PHI tables themselves; the chosen mechanism
# is the COMPOSITION of three primary controls + one supporting control
# that together corroborate-or-detect unauthorized alteration of PHI
# at rest. The control list + scope is calibrated against db-sme-2 +
# DA-3 verify-don't-accept review 2026-05-23 — the original four-control
# framing had four overclaims (WAL category-error, doctrinal
# reconciliation tooling, access_log HTTP-scope overstatement, backup
# cadence REFUTED at cited docs). The revised composition below is
# honest about what each control actually covers.
#
# PRIMARY CONTROLS:
#
#   1. **HMAC-SHA256-chained `log_entries` audit trail** (post-H-02a,
#      EQM-05, Cycle 6 2026-05-23). Every PHI-mutating operation
#      emits an event-stamped row through ``SQLiteLogHandler`` carrying
#      who-when-what-where (flow_id, account_id, operation, actor,
#      ts). The HKDF-keyed HMAC chain at ``db/audit.py`` is
#      tamper-EVIDENT against the insider-with-DB-write threat model.
#      §164.312(c) is the Integrity Standard (Required per §164.306
#      framework); its sole implementation specification (c)(2) is
#      Addressable. H-02a's HMAC contributes to the Standard's
#      integrity objective via the (c)(2)-class mechanism (the
#      EQM-05 audit-chain integrity primitive on `log_entries`).
#
#      **Honest scope note**: this control provides FORENSIC-
#      RECONCILIATION EVIDENCE under §164.312(c)(2)'s "electronic
#      mechanisms to corroborate" framing — the audit-chain is the
#      authoritative record of what SHOULD have been written. An
#      auditor or investigator comparing the chain against the live
#      PHI-table state can detect divergence (i.e., a tampered row
#      that has no matching audit entry, or a row whose content
#      doesn't match the chained operation's stamp). This IS the
#      regulatorily-acceptable §164.312(c)(2) shape — the regulation
#      does not require a continuously-running reconciliation
#      verifier; it requires the mechanism to EXIST.
#
#      **Automated reconciliation tooling (H-11 closed, Cycle 7)**:
#      ``src/email_triage/db/reconciliation.py::
#      verify_phi_table_against_audit_log`` + the
#      ``email-triage audit reconcile`` CLI subcommand close the
#      tooling-gap forward-stub originally disclosed here. The helper
#      walks the registered PHI-bearing tables (currently scoped to
#      ``flows``) and cross-references each row's PK against
#      ``log_entries.extra_json`` for the same PK, surfacing per-table
#      ``rows_without_audit_match`` (candidate-tampering) and
#      ``audit_rows_without_table_row`` (candidate-tampering-or-
#      legitimate-cascade-delete) counters + the chain-verify
#      roll-up. Read-only by design — no PHI is mutated, no chain
#      row is written by the reconciliation itself. When HIPAA mode
#      is on AND divergence is detected, one
#      ``hipaa_access_events`` row lands as a §164.308(a)(1)(ii)(D)
#      Information System Activity Review surface (anchored on the
#      lowest-id HIPAA-flagged account). The CLI exits 0 (clean) /
#      1 (divergence) / 2 (DB-open error) for scripted callers
#      (the monitoring system, operator monitoring). Per hipaa-sme-2 regulatory
#      calibration, the helper is NOT regulatorily-required per the
#      literal §164.312(c)(2) Addressable text (mechanism-EXISTS
#      bar is satisfied by the investigator-workflow shape above)
#      but IS OCR-posture-aligned per NIST SP 800-66 R2 §4.4
#      continuous-monitoring leanings + operator-policy ASAP per
#      ``project_hipaa_asap_policy.md``. Disposition shape:
#      standard EQM-05-supporting-tool (NOT a new EQM-NN
#      substitution); EQM-04 remains the §164.306(d)(3)(ii)(B)
#      equivalent measure for §164.312(c)(2).
#
#   2. **`access_log` middleware audit**
#      — every authenticated **HTTP-mediated** PHI-surface request
#      records its route, method, status, account_id, and actor at
#      the boundary, independent of (and complementary to) the
#      application-emitted `log_entries` chain.
#
#      **Honest scope note**: access_log records HTTP REQUESTS, not
#      direct database writes. An insider with direct-DB-write
#      privileges who bypasses the HTTP surface leaves NO row in
#      access_log — by design. For HTTP-mediated PHI access, the
#      two-layer attribution (access_log says "who requested it via
#      what HTTP surface" + log_entries says "what changed under that
#      request") provides the §164.312(c)(2) corroboration signal.
#      For direct-DB-write integrity coverage, the project relies on
#      controls 1 (audit chain reconciliation) and 3 (backup
#      diff) ONLY — access_log is structurally silent on that surface.
#      The CLI-direct-mutation gap is acknowledged via H-03
#      (CLI procedural-mechanism closure) and H-03-auto (CLI
#      auto-emit residual).
#
#   3. **Off-host backup snapshots** (per `the backup & restore notes`).
#      Operator-driven manual export (operator-controlled cadence;
#      the backup & restore notes §"When to run an export" recommends
#      a **monthly floor** with extras before major operational
#      changes) PLUS the **weekly host VM image** (host-level
#      filesystem snapshot that captures the SQLite DB as a side
#      effect, runs continuously regardless of operator action). A
#      tampered live row that diverges from the most-recent off-host
#      snapshot without a matching audit-log explanation is
#      detectable by snapshot diff; restoration is operationally
#      available if alteration is confirmed.
#
#      **Honest scope note**: the detection latency floor is bounded
#      by the weekly-VM-image cadence (worst case ~7 days between
#      tamper-event and detection-possibility). Manual exports
#      improve this to monthly-or-better at the operator's
#      discretion. An operator that wants tighter detection latency
#      runs manual exports on a tighter cadence.
#
# SUPPORTING CONTROL:
#
#   • **SQLite WAL durability** (`PRAGMA journal_mode=WAL` set at
#     connection-open time in web/db.py + the dedicated-connection
#     path in this module). Atomic-commit semantics + WAL header CRC.
#
#     **Honest scope note**: WAL is an AVAILABILITY/DURABILITY
#     control, not an integrity-against-unauthorized-alteration
#     control. WAL prevents torn writes and disk-level corruption;
#     it does NOT prevent or detect deliberate tampering by an
#     actor with DB-write privilege. WAL's role in the EQM-04 EM is
#     SUPPORTING ONLY: it removes torn-write artifacts as a
#     confounder when an investigator runs reconciliation between
#     the audit chain (control 1) and the live table state — a
#     diverged row under WAL is almost certainly a real alteration,
#     not a half-written record. Without WAL, reconciliation
#     evidence would have a noise floor; with WAL, divergence is
#     signal. WAL alone IS NOT a §164.312(c)(2) integrity
#     mechanism, and is not counted as such in this EM.
#
# Rationale for choosing the equivalent measure over strict
# per-row HMAC on the PHI tables (the WHY for §164.306(d)(3)(ii)(B)):
#
#   (a) **Write-path cost.** The `flows` table is on the hot triage
#       path — every classification + every action-completion writes
#       this table. A per-row HMAC would add HKDF + HMAC-SHA256 cost
#       to every triage hop. The `log_entries` audit chain already
#       carries the keyed-MAC integrity claim for the OPERATION
#       that wrote the PHI; integrity-protecting the operation
#       record via the EQM-05 (c)(2)-class HMAC mechanism is
#       regulatorily stronger than integrity-protecting the resulting
#       at-rest state, because tampering with the at-rest state
#       without a matching audit-log event IS the reconcilable-via-
#       chain divergence signal. (Both surfaces contribute to the
#       same Standard §164.312(c) Integrity Required objective; the
#       (c)(2) Addressable implementation specification is the only
#       implementation-spec under it.)
#   (b) **Key-management surface.** A per-row HMAC on the PHI tables
#       would introduce a SECOND keyed-MAC surface needing the same
#       master-key + HKDF + rotation-preservation plumbing as the
#       audit-log chain (EQM-05). Doubling the cryptographic surface
#       doubles the §164.308(a)(4)(ii)(C) access-management audit
#       cost and creates an ambiguity ("which key signed this row?")
#       without proportionate integrity gain.
#   (c) **Threat-model coverage parity.** The insider-with-DB-write
#       threat model is addressed by the EQM-05 audit chain + the
#       reconciliation-evidence framing: an insider who tampers with
#       a PHI row WITHOUT emitting a matching audit entry leaves a
#       divergence between log_entries-derived expected-state and
#       the live table — investigator-detectable. An insider who
#       tampers with both the PHI row AND a synthetic audit entry
#       must forge an HMAC under the current master, which is the
#       §164.312(c) Integrity Standard failure mode that H-02a's
#       (c)(2)-class HMAC mechanism (EQM-05) already closes. Per-row
#       HMAC on the PHI table would NOT close any additional
#       threat-model surface that EQM-05 + backup-diff don't
#       already cover.
#   (d) **Backup-as-independent-corroborator.** §164.312(c)(2) names
#       "electronic mechanisms to corroborate" — the off-host backup
#       (weekly VM image floor + operator-driven manual export) IS
#       such an electronic mechanism, independent of the online
#       write path. A live row that diverges from the most-recent
#       backup without a matching audit-log explanation IS the
#       detectable alteration signature.
#
# Documented per 45 CFR §164.306(d)(3)(ii)(B). The EQM-04 row in
# ``internal documentation`` §5 is the central index;
# this docstring block is the AUTHORITATIVE TEXT per medical-scope
# drawer §2.6 (rationale-travels-with-code). Source: 45 CFR §164.312
# + §164.306 via Cornell LII, retrieved 2026-05-23
# (https://www.law.cornell.edu/cfr/text/45/164.312 +
# https://www.law.cornell.edu/cfr/text/45/164.306). NIST SP 800-66
# Rev. 2 §4.4 (Integrity) discusses composition-of-controls patterns
# as one acceptable §164.312(c)(2) implementation; retrieved
# 2026-05-23 from
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf.
#
# Periodic-review cadence: per `internal documentation`
# §6.1 (release-aligned + quarterly-minimum), this EM's continued
# adequacy is re-verified at every release-cut. As a durable
# Addressable EM (no sunset milestone — unlike EQM-05's legacy-SHA-256
# sunset, whose removal timeline is pending explicit operator directive
# per the 2026-07-06 correction; see `db/audit.py`), the periodic-review
# cadence IS the
# §164.316(b)(2)(iii) "review documentation periodically" surface for
# EQM-04. Triggers for re-verification:
#   - Any change to controls 1-3 or the WAL supporting control.
#   - Operator-reported reconciliation-investigation outcome (PASS
#     confirms the EM works as documented; any FAIL re-opens
#     H-02b/N-02).
#   - Tooling-gap closure (H-11 reconciliation tooling LANDED Cycle 7
#     via ``src/email_triage/db/reconciliation.py`` +
#     ``email-triage audit reconcile`` — see control-1 scope-note
#     above. Next periodic-review trigger on this surface: any
#     change to the reconciliation registry of PHI-bearing tables
#     OR the audit-chain emit pattern that the reconcile parses).
#   - OCR posture shift on §164.312(c)(2) (per drawer §2.2
#     calibration).
#
# CONSOLIDATION NOTE: H-02b (audit's missing §164.312(c)(2) framing
# for PHI tables) + N-02 (hipaa-sme-2 second-pass new finding on the
# same surface) are intentionally consolidated under this single
# EQM-04 rationale per DA-1 Bundle E6 triage 2026-05-23. The two
# findings have IDENTICAL §-anchor (§164.312(c)(2)) and IDENTICAL
# remediation shape; splitting them would create register noise
# without compliance gain.
#
# REVISION NOTE (2026-05-23): the original four-control framing in
# this doc-block was revised per db-sme-2 + DA-3 verify-don't-accept
# review. Four overclaims corrected: (1) WAL demoted from primary
# control to supporting (category-error: WAL is durability, not
# integrity-against-unauthorized-alteration); (2) audit-chain
# reconciliation downgraded from "automated check" to "forensic
# reconciliation evidence" language with explicit H-11 tooling-gap
# disclosure (the regulatory test is mechanism-EXISTS, not
# mechanism-runs-continuously). **Cycle 7 update (2026-05-24)**:
# H-11 tooling now LANDED (see control-1 scope-note above + new
# `src/email_triage/db/reconciliation.py` + `email-triage audit
# reconcile` CLI per DA verify-don't-accept R-Surface-2 staleness-
# fix); the "forensic reconciliation evidence" framing remains the
# regulatorily-defensible floor under literal §164.312(c)(2)
# Addressable doctrine, with operator-driven cadence tooling now
# available atop it (mechanism-EXISTS bar satisfied via audit chain;
# tooling makes the mechanism cheaper to operate, regulatorily-
# neutral); (3) access_log scope qualified as HTTP-mediated only
# (direct-DB-write bypasses HTTP entirely — the CLI gap is H-03/
# H-03-auto); (4) backup cadence corrected from "daily" to "weekly
# host VM image + operator-driven manual export at monthly floor"
# per the backup & restore notes actual posture. The revisions preserve
# the §164.312(c)(2) compliance claim while being honest about
# scope.

_FLOWS_DDL = """\
CREATE TABLE IF NOT EXISTS flows (
    flow_id           TEXT PRIMARY KEY,
    message_id        TEXT NOT NULL,
    provider          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'created',
    revision          INTEGER NOT NULL DEFAULT 0,
    classification_json TEXT,
    actions_completed_json TEXT NOT NULL DEFAULT '[]',
    actions_pending_json   TEXT NOT NULL DEFAULT '[]',
    state_bag_json    TEXT NOT NULL DEFAULT '{}',
    error             TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE(provider, message_id)
);

CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
CREATE INDEX IF NOT EXISTS idx_flows_provider_message ON flows(provider, message_id);
"""


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def _parse_dt(s: str) -> datetime:
    # N-263b R31 fromisoformat sweep — route through `_isotime.parse_iso`
    # SSOT while preserving the raise-on-unparseable contract callers
    # depend on (all five callers pass stored-column-values or
    # freshly-emitted `now`, so the raise-arm is a defensive fallback,
    # not a normal path).
    from email_triage._isotime import parse_iso
    dt = parse_iso(s)
    if dt is None:
        raise ValueError(f"Unparseable datetime: {s!r}")
    return dt


def redact_reason(reason: str, *, account_hipaa: bool) -> str:
    """SSOT for Classification.reason redaction at write time.

    N-74 / §164.312(a)(2)(iv) — redact when EITHER the install-wide HIPAA
    mode OR the per-account HIPAA flag is set (fail-closed: either condition
    alone is sufficient; combining never loosens — PD#8 /
    feedback_most_restrictive_wins). Previously the store layer gated only
    on ``is_hipaa_mode()`` (install-wide), so a per-account-HIPAA mailbox
    on a non-HIPAA install wrote cleartext PHI to flows.classification_json.

    The cache layer (cache/classification.py) and web layer (triage_one.py)
    already gate on per-account hipaa; this SSOT aligns the store layer.

    Callers: ``_cls_to_json`` (the only site that writes classification_json
    to the DB) — all other reason-serialization goes through here.
    """
    from email_triage.triage_logging import is_hipaa_mode
    if account_hipaa or is_hipaa_mode():
        return ""
    return reason


def _cls_to_json(cls: Classification | None, *, account_hipaa: bool = False) -> str | None:
    """Serialise ``Classification`` for the ``flows.classification_json``
    column.

    HIPAA redaction
    ────────────────────────────────────
    ``Classification.reason`` is the LLM's free-text justification for
    the assigned category and typically cites email content (sender,
    subject snippets, body excerpts). In HIPAA mode that text is PHI.
    When ``is_hipaa_mode()`` OR ``account_hipaa`` is True we persist an
    empty ``reason`` so no PHI lands at rest in this column.

    N-74 fix: the previous gate checked only ``is_hipaa_mode()`` (the
    install-wide flag). A per-account-HIPAA mailbox on a non-HIPAA
    install therefore wrote cleartext PHI here. The new gate delegates
    to ``redact_reason`` (the SSOT) which checks EITHER condition —
    fail-closed. The ``account_hipaa`` value flows from
    ``_capture_baseline`` via ``flow.state_bag["account_hipaa"]`` (set
    by the triage runner / caller that has account context).

    This mirrors the existing redaction precedent at two other layers:
      * ``engine/models.py`` ``Classification.log_repr(hipaa=True)``
        omits ``reason`` from log lines.
      * ``cache/classification.py`` ``cache_store_for_message`` omits
        ``reason`` from cache values when ``is_hipaa=True``.

    Regulatory framing — 45 CFR §164.306(d)(3)(ii)(B)
    ──────────────────────────────────────────────────
    §164.312(a)(2)(iv) "Encryption and decryption" is an Addressable
    implementation specification, satisfied EITHER by encryption OR by
    a documented equivalent alternative measure. Redact-at-write is the
    equivalent alternative measure here. Rationale:
      (a) ``Classification.reason`` is the only PHI-vector field in
          this column; stripping it at write leaves only category +
          confidence + source — non-PHI install-metadata.
      (b) Stripped PHI cannot be recovered by master-key compromise,
          key-management error, or backup leak.
    Documented per §164.306(d)(3)(ii)(B). Source: 45 CFR §164.312 via
    Cornell LII, fetched 2026-05-23.
    """
    if cls is None:
        return None
    reason = redact_reason(cls.reason, account_hipaa=account_hipaa)
    return dump_json_col({
        "category": cls.category,
        "confidence": cls.confidence,
        "reason": reason,
        "source": cls.source,
    })


def _cls_from_json(s: str | None) -> Classification | None:
    if s is None:
        return None
    # census  SSOT — a corrupt/wrong-shape classification_json degrades
    # to None (flow loads, classification absent) instead of raising out of
    # _row_to_flow and crashing the engine load — the same corruption
    # survival _safe_json_load_dict (C4) gives the sibling state_bag_json.
    d = load_json_col(s, default=None)
    return Classification(**d) if isinstance(d, dict) else None


#  — list of the 4 JSON-serialized FlowState columns the baseline-
# compare path inspects. Hardcoded constant — never user-controlled — so
# the dynamic-SQL construction in ``update_flow`` carries zero SQLi-style
# injection surface.
_TRACKED_JSON_COLUMNS: tuple[str, ...] = (
    "classification_json",
    "actions_completed_json",
    "actions_pending_json",
    "state_bag_json",
)


def _capture_baseline(flow: "FlowState") -> dict[str, str | None]:
    """Compute the on-write serialized form of the 4 tracked JSON columns.

    Returned dict maps column name → serialized string. ``None`` is
    legal for ``classification_json`` (when ``flow.classification is
    None``); the other three are always strings (``"[]"`` / ``"{}"``
    for empty containers).

    Called by ``_row_to_flow`` to stamp ``flow._baseline`` post-load,
    and by ``update_flow`` to compute the post-write current form for
    the dirty-column comparison.

    N-74 — ``account_hipaa`` is read from ``flow.state_bag`` so the
    per-account HIPAA flag reaches ``_cls_to_json`` without threading
    through every caller's signature. The WRITER of this key is
    ``FlowEngine.classify`` (engine/flow.py), which stamps
    ``flow.state_bag["account_hipaa"] = bool(message.hipaa)`` from the
    provider-resolved per-account flag (engine/models.py
    ``EmailMessage.hipaa`` = system_hipaa OR account.hipaa) BEFORE the
    first ``update_flow`` of the classification — so the value is present
    on every code path that persists ``classification_json``. (The
    original L8-4 fix wired only the READ here and relied on a setter that
    never ran on the FlowEngine DB-write path; the stamp in ``classify``
    closes that vacuum — proven by
    tests/test_n74_flowengine_per_account_redaction_integration.py.)
    Flows whose classification is written without ever entering
    ``classify`` (none exist today — ``classify`` is the sole
    classification writer) would default to ``False``, which is still
    safe: global ``is_hipaa_mode()`` independently fires the redaction
    on a HIPAA install — the per-account gate is additive, not the only
    gate.
    """
    # N-74: extract per-account hipaa flag from state_bag (safe default False).
    account_hipaa = bool(flow.state_bag.get("account_hipaa", False))
    return {
        "classification_json": _cls_to_json(flow.classification, account_hipaa=account_hipaa),
        "actions_completed_json": dump_json_col(flow.actions_completed),
        "actions_pending_json": dump_json_col(flow.actions_pending),
        "state_bag_json": dump_json_col(flow.state_bag),
    }


def _safe_json_load_dict(
    raw: str | None, *, label: str, flow_id: str,
) -> tuple[dict, str | None]:
    """Parse a JSON-blob column, surviving corruption.

    PR 7 / C4. Plain ``json.loads`` on a corrupted ``state_bag_json``
    column raised JSONDecodeError out of ``_row_to_flow``, which
    bubbled all the way up and crashed the engine — leaving the
    operator with a flow that couldn't be loaded, retried, or
    fixed without a hand-edit of the row in SQLite.

    New behaviour: catch the parse error, log the raw blob for
    forensics (truncated to 256 chars), return ``({}, error_msg)``.
    The engine sees an empty dict and an error string; downstream
    can mark the flow ``FAILED`` with a clear reason instead of
    crashing the loop.
    """
    if raw is None or raw == "":
        return {}, None
    try:
        out = json.loads(raw)
        if not isinstance(out, dict):
            # JSON valid but wrong shape (e.g. ``"null"``). Treat as
            # corruption — every column we use this for is a JSON
            # object by contract.
            return {}, (
                f"{label}: expected object, got {type(out).__name__}"
            )
        return out, None
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        from email_triage._errfmt import scrub_class_error_for_persist
        snippet = (raw[:256] if isinstance(raw, str) else str(raw)[:256])
        return {}, (
            f"{label}_corrupt: "
            f"{scrub_class_error_for_persist(exc)}; "
            f"raw_snippet={snippet!r}"
        )


def _row_to_flow(row: sqlite3.Row) -> FlowState:
    sb_raw = row["state_bag_json"]
    state_bag, sb_err = _safe_json_load_dict(
        sb_raw, label="state_bag", flow_id=row["flow_id"],
    )
    flow = FlowState(
        flow_id=row["flow_id"],
        message_id=row["message_id"],
        provider=row["provider"],
        status=FlowStatus(row["status"]),
        revision=row["revision"],
        classification=_cls_from_json(row["classification_json"]),
        actions_completed=load_json_col(row["actions_completed_json"], default=[]),
        actions_pending=load_json_col(row["actions_pending_json"], default=[]),
        state_bag=state_bag,
        error=row["error"],
        created_at=_parse_dt(row["created_at"]),
        updated_at=_parse_dt(row["updated_at"]),
    )
    if sb_err is not None:
        # Stash the corruption note on state_bag so the engine /
        # admin UI can detect-and-skip cleanly without re-parsing.
        flow.state_bag["__corruption__"] = sb_err
    #  — stamp the baseline AFTER any corruption mutation above so
    # the corruption marker is part of the on-load reference; an
    # update that didn't change state_bag won't falsely re-serialize
    # to overwrite the corruption marker. The 4-column serialized
    # snapshot lets ``update_flow`` skip the SQLite write for any
    # JSON column whose serialized form matches the baseline.
    flow._baseline = _capture_baseline(flow)
    return flow


# ---------------------------------------------------------------------------
# FlowStore
# ---------------------------------------------------------------------------

class FlowStore:
    """SQLite persistence layer for triage flows.

    All mutations use optimistic concurrency via a revision counter:
    ``UPDATE ... WHERE flow_id = ? AND revision = ?``
    If no row is affected the caller holds a stale copy.
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        connection: sqlite3.Connection | None = None,
    ):
        """Construct a ``FlowStore``.

        Preferred form::

            FlowStore(connection=app.state.db)

        The injected connection is the canonical web-app connection
        owned by ``email_triage.web.db.init_db``. ``FlowStore`` will
        use it directly — no second writer connection is opened,
        which eliminates the stale-read / expected_revision-regress
        window between two independent connections to the same file.

        Legacy fallback (DEPRECATED)::

            FlowStore("/path/to/triage.db")

        Used only by the standalone CLI / one-shot triage entry
        points that run without a web-app lifespan. A WARNING is
        logged on this path. The connection opened here is owned by
        ``FlowStore`` and ``close()`` will release it.

        Parameters
        ----------
        db_path:
            Path to the SQLite database. Used only when
            ``connection`` is None. Ignored otherwise.
        connection:
            An already-open ``sqlite3.Connection`` (typically the
            one from ``init_db``). When provided, ``FlowStore`` uses
            it directly and does NOT call ``sqlite3.connect``.
            ``close()`` does NOT close an injected connection — the
            caller (web-app lifespan) owns its lifecycle.
        """
        if connection is not None:
            # Canonical path — reuse the caller's connection.
            self._db_path = ""
            self._conn = connection
            self._owns_connection = False
        else:
            # Legacy fallback — open our own. Warn so this path is
            # visible in operator logs; new callers must not land
            # here against a web-app DB path.
            self._db_path = str(db_path)
            log.warning(
                "FlowStore opened its own SQLite connection — "
                "legacy CLI / one-shot path. New callers should "
                "inject the canonical web.db connection via "
                "FlowStore(connection=app.state.db). "
                "See engine/store.py module docstring.",
                db_path=self._db_path,
            )
            self._conn = self._connect()
            self._owns_connection = True
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a new SQLite connection (legacy fallback only).

        Called when no ``connection`` was injected — that's the
        standalone CLI / one-shot triage path. The canonical web-app
        path injects the connection from ``init_db`` and never
        reaches this method.
        """
        # N-17: route through the encrypted-aware shared opener. This
        # legacy/one-shot CLI path opens its OWN connection on the live DB
        # file — on an encrypted install a raw sqlite3.connect could not
        # read it. open_dedicated_conn self-selects encrypted-vs-plaintext
        # from the boot-/CLI-stamped context + applies the same
        # WAL/busy_timeout=30000/FK PRAGMAs this site set inline. The CLI
        # entrypoints (run/watch) stamp the context before constructing
        # FlowStore; the web path injects the conn and never reaches here.
        from email_triage.db._engine import open_dedicated_conn

        conn = open_dedicated_conn(self._db_path, check_same_thread=True)
        # N-16: factory from the conn's own dbapi module (sqlite3.Row vs
        # sqlcipher3.dbapi2.Row) — open_dedicated_conn may return either.
        apply_compatible_row_factory(conn)
        return conn

    def _ensure_schema(self) -> None:
        #  — construction-time only: this runs once in __init__
        # before the app starts serving requests, so no concurrent
        # db_call threadpool worker can be touching the shared
        # connection yet. Every other FlowStore mutator already wraps
        # its connection touch in get_write_lock(); this one is
        # provably contention-free and does not need the lock.
        # async-db-ok: __init__-time, provably no concurrency.
        self._conn.executescript(_FLOWS_DDL)

    # -- create ---------------------------------------------------------------

    def create_flow(self, message_id: str, provider: str) -> FlowState:
        """Insert a new flow. Raises DuplicateFlow if (provider, message_id) exists."""
        flow_id = FlowState.new_id()
        now = _now_iso()
        #  — FlowStore shares ``app.state.db`` with every db.py
        # write helper. Hold the same process-wide write lock so the
        # INSERT + commit cannot have a foreign commit/rollback slice
        # through it on a threadpool worker.
        with get_write_lock():
            try:
                self._conn.execute(
                    """INSERT INTO flows
                       (flow_id, message_id, provider, status, revision, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 0, ?, ?)""",
                    (flow_id, message_id, provider, FlowStatus.CREATED.value, now, now),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                raise DuplicateFlow(provider, message_id)

        flow = FlowState(
            flow_id=flow_id,
            message_id=message_id,
            provider=provider,
            status=FlowStatus.CREATED,
            revision=0,
            created_at=_parse_dt(now),
            updated_at=_parse_dt(now),
        )
        #  — stamp the baseline so the FIRST ``update_flow`` call
        # on this freshly-created flow can detect no-op JSON-column
        # writes. Without this, an update with no JSON-column changes
        # would safe-fail to "treat all-dirty" and re-write the
        # empty-list / empty-dict serialized forms unnecessarily.
        flow._baseline = _capture_baseline(flow)
        return flow

    def get_or_create_flow(
        self, message_id: str, provider: str
    ) -> tuple[FlowState, bool]:
        """Idempotent create. Returns (flow, was_created)."""
        try:
            flow = self.create_flow(message_id, provider)
            return flow, True
        except DuplicateFlow:
            existing = self.find_flows(provider=provider, message_id=message_id)
            return existing[0], False

    # -- read -----------------------------------------------------------------

    def get_flow(self, flow_id: str) -> FlowState:
        """Load a flow by ID. Raises FlowNotFound.

         — reads the SHARED ``app.state.db`` connection. The
        sqlite3 driver rejects two threads using one ``Connection``
        concurrently even for two reads, so this SELECT serialises on
        the same process-wide DB lock the FlowStore mutators use. The
        lock is reentrant: ``update_flow`` already holds it when it
        calls ``get_flow`` for the conflict re-read.
        """
        with get_write_lock():
            row = self._conn.execute(
                "SELECT * FROM flows WHERE flow_id = ?", (flow_id,)
            ).fetchone()
        if row is None:
            raise FlowNotFound(flow_id)
        return _row_to_flow(row)

    def find_flows(
        self,
        status: FlowStatus | None = None,
        provider: str | None = None,
        message_id: str | None = None,
        limit: int = 100,
    ) -> list[FlowState]:
        """Query flows with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if provider is not None:
            clauses.append("provider = ?")
            params.append(provider)
        if message_id is not None:
            clauses.append("message_id = ?")
            params.append(message_id)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM flows{where} ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        #  — serialise the read on the shared connection's lock
        # (see get_flow).
        with get_write_lock():
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_flow(r) for r in rows]

    # -- update ---------------------------------------------------------------

    def update_flow(
        self, flow: FlowState, expected_revision: int
    ) -> FlowState:
        """Persist changes with optimistic concurrency.

        Raises RevisionConflict if the stored revision doesn't match
        ``expected_revision``.  On success the returned flow has
        ``revision = expected_revision + 1``.

         — only the JSON columns whose serialized form differs
        from the on-load baseline are included in the UPDATE. A flow
        whose status changed but whose 4 JSON columns are byte-
        identical to load-time skips re-writing those columns; the
        SQLite UPDATE still runs (status / revision / error /
        updated_at always need a write) but the dominant cost (the
        4 JSON column updates + WAL journal pages they would dirty)
        is elided. ``json.dumps`` is still called to compute the
        current serialized form for the baseline-compare; the win is
        the SQLite write skip, not the dumps CPU. Honest framing
        deviation from the spec — see commit body.

        Dirty-tracking is shape-agnostic: in-place mutations
        (``state_bag["k"] = v``, ``actions_completed.append(...)``)
        change the serialized form and trip the dirty check exactly
        like a scalar reassign would. The dynamic SQL constructs
        column names from the hardcoded ``_TRACKED_JSON_COLUMNS``
        constant — never user-controlled — so the string-build pattern
        carries zero SQLi-style injection surface.
        """
        now = _now_iso()
        current_serialized = _capture_baseline(flow)
        #  — derive dirty columns from baseline-compare. Safe-fail:
        # a flow constructed in-test (not via ``_row_to_flow`` or
        # ``create_flow``) has no ``_baseline`` attr. Treat that as
        # "every column dirty" — the pre-fix behavior — equivalent to
        # writing the full row. Distinguishing "missing baseline" from
        # "baseline column is None" matters because ``classification_
        # json`` legitimately serializes to None when classification
        # is unset; ``baseline.get(col, _SENTINEL)`` would otherwise
        # collide with a real None and treat an absent baseline as
        # "clean" for the classification column.
        _baseline_attr = getattr(flow, "_baseline", None)
        if _baseline_attr is None:
            dirty_cols = list(_TRACKED_JSON_COLUMNS)
        else:
            dirty_cols = [
                col for col in _TRACKED_JSON_COLUMNS
                if _baseline_attr.get(col) != current_serialized[col]
            ]

        # The non-JSON columns (status / revision / error / updated_at)
        # always go in the UPDATE — they're scalar so the cost is
        # negligible AND the optimistic-revision bump (``revision =
        # revision + 1``) is what guards the conflict re-read.
        set_clauses = [
            "status = ?",
            "revision = revision + 1",
        ]
        params: list[Any] = [flow.status.value]
        for col in dirty_cols:
            set_clauses.append(f"{col} = ?")
            params.append(current_serialized[col])
        set_clauses.extend(["error = ?", "updated_at = ?"])
        params.extend([flow.error, now, flow.flow_id, expected_revision])

        sql = (
            "UPDATE flows SET "
            + ", ".join(set_clauses)
            + " WHERE flow_id = ? AND revision = ?"
        )

        #  — the UPDATE + commit + the conflict re-read must be one
        # critical section: a foreign commit between the UPDATE and the
        # re-read could otherwise make the optimistic-revision check
        # observe an inconsistent revision.
        with get_write_lock():
            cur = self._conn.execute(sql, params)
            self._conn.commit()

            if cur.rowcount == 0:
                # Was it not-found or a genuine conflict?
                try:
                    current = self.get_flow(flow.flow_id)
                    raise RevisionConflict(
                        flow.flow_id, expected_revision, current.revision
                    )
                except FlowNotFound:
                    raise FlowNotFound(flow.flow_id)

        flow.revision = expected_revision + 1
        flow.updated_at = _parse_dt(now)
        # Rebase the baseline to the post-write snapshot so the NEXT
        # update_flow call sees the just-persisted form as the
        # comparison reference. Without this, the second update would
        # think every column was dirty again.
        flow._baseline = current_serialized
        return flow

    # -- convenience ----------------------------------------------------------

    def count_by_status(self) -> dict[str, int]:
        """Return {status: count} for all flows.

         — serialise the read on the shared connection's lock
        (see get_flow).
        """
        with get_write_lock():
            rows = self._conn.execute(
                "SELECT status, COUNT(*) as cnt FROM flows GROUP BY status"
            ).fetchall()
        return {row["status"]: row["cnt"] for row in rows}

    def close(self) -> None:
        """Close the connection if owned by this ``FlowStore``.

        When ``connection`` was injected at construction, the caller
        owns the connection lifecycle (web-app lifespan) and we do
        NOT close it here — closing the canonical app connection
        underneath the web-app would orphan every other handler.
        """
        if self._owns_connection:
            self._conn.close()
