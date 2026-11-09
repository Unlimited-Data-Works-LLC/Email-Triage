"""Proposal-1b pin: audit_phi_access SSOT + Shape-A consolidation ban.

Three goals:
1. TRUTH-TABLE unit test of ``audit_phi_access`` covering the four
   PD#14 gate cases (HIPAA/non-HIPAA x actor-owner/non-owner x system-actor).
   Drives the REAL helper; does NOT mock the gate itself (no mock-the-seam —
   the N-74/N-77 trap).

2. STRUCTURAL (count-agnostic, alias-aware): ban a direct call to
   ``record_hipaa_access_event`` in the web/routers/ui/ tree OUTSIDE an
   explicit ALLOW_LIST.  Any new hand-rolled actor-not-owner bookend that
   bypasses ``audit_phi_access`` trips CI immediately.

   The ALLOW_LIST keys are derived from ground truth (AST walk of HEAD,
   2026-06-10) and each carries a one-line justification of why the site
   is NOT a Shape-A actor-not-owner read.

3. TEETH: assert ``audit_phi_access`` is importable + that the 4 routed
   Shape-A sites reference it (AST: their enclosing functions call
   ``audit_phi_access``) so a future inline re-hand-roll is caught.
"""
from __future__ import annotations

import ast
import importlib
import sqlite3
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch, call as _call

import pytest

from _pin_harness import SRC_ROOT, iter_src_files, relpath, parse_module, parse_source  # N-178a

# The package root — the shared-harness SSOT (R5b). The relpath base is
# ``relative_to(SRC_ROOT)`` → ``web/db.py`` form, which is exactly the form the
# ALLOW_LIST keys below were already written in, so no re-key.
SRC = SRC_ROOT


# ---------------------------------------------------------------------------
# 1. TEETH — SSOT importable and callable
# ---------------------------------------------------------------------------

def test_audit_phi_access_importable():
    """The SSOT helper must be importable from _shared."""
    from email_triage.web.routers.ui._shared import audit_phi_access  # noqa: F401
    assert callable(audit_phi_access)


# ---------------------------------------------------------------------------
# 2. Truth-table unit pin for audit_phi_access
# ---------------------------------------------------------------------------

def _fake_hipaa_account(owner_id: int) -> dict:
    return {"id": 42, "user_id": owner_id, "hipaa": 1}


def _fake_non_hipaa_account(owner_id: int) -> dict:
    return {"id": 99, "user_id": owner_id, "hipaa": 0}


def _run(*, account: dict, actor_user_id, operation: str = "test_op",
         outcome: str = "ok", detail: str | None = None):
    """Call the REAL audit_phi_access; capture what record_hipaa_access_event
    would receive.  Returns list of captured call kwargs.

    The helper lazily imports ``record_hipaa_access_event`` inside its try
    block via ``from email_triage.web.db import record_hipaa_access_event``.
    We patch at ``email_triage.web.db.record_hipaa_access_event`` — the
    module-level name that the lazy import resolves to.
    """
    from email_triage.web.routers.ui._shared import audit_phi_access

    captured = []

    def fake_record(conn, a_uid, acct_id, op, outcome="ok", detail=None):
        captured.append({"actor_user_id": a_uid, "account_id": acct_id,
                         "operation": op, "outcome": outcome, "detail": detail})
        return 1  # fake rowid

    fake_db = object()  # sentinel — should never be inspected by the helper
    with patch(
        "email_triage.web.db.record_hipaa_access_event",
        side_effect=fake_record,
    ):
        audit_phi_access(
            fake_db,
            actor_user_id=actor_user_id,
            account=account,
            operation=operation,
            outcome=outcome,
            detail=detail,
        )
    return captured


# --- Case 1: HIPAA account, actor != owner → EMITS ---
def test_hipaa_non_owner_emits():
    acct = _fake_hipaa_account(owner_id=10)
    captured = _run(account=acct, actor_user_id=99, operation="label_apply",
                    outcome="ok", detail="slug=foo")
    assert len(captured) == 1
    row = captured[0]
    assert row["actor_user_id"] == 99
    assert row["account_id"] == 42
    assert row["operation"] == "label_apply"
    assert row["outcome"] == "ok"
    assert row["detail"] == "slug=foo"


# --- Case 2: HIPAA account, actor == owner → NO EMIT (owner-self exempt) ---
def test_hipaa_owner_self_no_emit():
    acct = _fake_hipaa_account(owner_id=10)
    captured = _run(account=acct, actor_user_id=10)
    assert captured == [], "owner self-access must NOT emit (§164.502(a) carve-out)"


# --- Case 3: HIPAA account, actor=None (system) → EMITS (None != owner_id) ---
def test_hipaa_system_actor_emits():
    """PD#14: system actor (None) is NOT the owner; must emit.

    The N-72 bug added ``actor_user_id is not None`` as a guard — that
    silently dropped system-initiated PHI reads from the audit trail.
    This case verifies the SSOT does NOT reproduce that bug.
    """
    acct = _fake_hipaa_account(owner_id=10)
    captured = _run(account=acct, actor_user_id=None, operation="digest_archive")
    assert len(captured) == 1, (
        "system actor (None) must emit: None != owner_id, not exempt"
    )
    assert captured[0]["actor_user_id"] is None


# --- Case 4: Non-HIPAA account, any actor → NO EMIT ---
def test_non_hipaa_no_emit():
    acct = _fake_non_hipaa_account(owner_id=10)
    captured = _run(account=acct, actor_user_id=99)
    assert captured == [], "non-HIPAA account must never emit"


# --- Case 5: detail=None default passthrough ---
def test_detail_none_passthrough():
    acct = _fake_hipaa_account(owner_id=7)
    captured = _run(account=acct, actor_user_id=99, detail=None)
    assert len(captured) == 1
    assert captured[0]["detail"] is None


# --- Case 6: detail non-None passthrough ---
def test_detail_passthrough():
    acct = _fake_hipaa_account(owner_id=7)
    captured = _run(account=acct, actor_user_id=99, detail="slug=test bulk_n=5")
    assert len(captured) == 1
    assert captured[0]["detail"] == "slug=test bulk_n=5"


# --- Case 7: write failure → logs warning, does NOT raise ---
@pytest.mark.audit_failure_expected(
    match='audit_phi_access test_op account_id=42',
    count=1,
)
def test_write_failure_logs_not_raises():
    """Best-effort audit: a record write failure must log a warning and
    return cleanly — never propagate the exception (the access itself
    proceeds; only the audit row is lost, and it's visible in logs).
    """
    from email_triage.web.routers.ui._shared import audit_phi_access
    acct = _fake_hipaa_account(owner_id=7)

    def boom(*a, **kw):
        raise RuntimeError("DB exploded")

    with patch("email_triage.web.db.record_hipaa_access_event", side_effect=boom):
        # Must NOT raise:
        audit_phi_access(object(), actor_user_id=99, account=acct,
                         operation="test_op")


# ---------------------------------------------------------------------------
# 3. Structural ban — direct record_hipaa_access_event calls in
#    web/routers/ui/ outside the ALLOW_LIST
# ---------------------------------------------------------------------------

# ALLOW_LIST: "path/stem (relative to src/email_triage):function_name" → justification.
# Every key was DERIVED FROM GROUND TRUTH — an alias-aware AST walk of HEAD that
# matches BOTH the direct call form AND the db_call(record_hipaa_access_event, …)
# SEAM (PD#2: the pin must key on the seam where the emit hops through the
# dispatcher, not just the source — a UI-only / direct-call-only pin is blind by
# construction, and N-72/N-73 lived in exactly the service layer this now covers).
# Each enclosing-fn name was read from the AST output, NOT hand-guessed
# (the N-77 build shipped fabricated allow-list names — do not repeat).
#
# None of these sites is a raw single-emit actor≠owner PHI-read bookend (those
# now route through audit_phi_access). They are: the SSOT itself; Shape-B
# unconditional config/system/lifecycle events (no actor≠owner gate); and
# Shape-A+C start→finalise BRACKET sites (need the event_id for the finalise
# UPDATE, so they cannot use the single-emit helper — their GATE is routed
# through the phi_access_audit_required predicate SSOT instead).
ALLOW_LIST: dict[str, str] = {
    # --- THE SSOT — the one permitted direct emit (the bookend helper) ---
    "web/routers/ui/_shared:audit_phi_access":
        "SSOT: the actor≠owner PHI-read bookend; every single-emit site routes here",
    # --- Shape-B: unconditional-on-HIPAA config / system / lifecycle events ---
    "web/routers/ui/accounts:_style_backend_db_work":
        "Shape-B: admin style-learning backend config-change audit (is_account_hipaa only)",
    "web/routers/ui/accounts:_m1m2_optin_db_work":
        "Shape-B: owner-only M-1/M-2 opt-in + refused-non-owner write-consent audit",
    "web/routers/ui/profile:_record_clock_def_governance":
        "Shape-B: actor≠owner clock-def governance config-change audit (#34, "
        "feedback_hipaa_actor_owner_gate) — a point-in-time config change "
        "alongside the access_log governance row, NOT a span PHI-read bookend; "
        "allow-list went stale when #34 landed (re-keyed 2026-06-20)",
    "actions/draft_reply:_generate_body":
        "Bracket site: actor≠owner draft-generation PHI-read audit (EQM-12). "
        "Routes through the gate SSOT (phi_access_audit_required) + emitter SSOT "
        "(record_hipaa_access_event) directly — NOT the audit_phi_access wrapper "
        "— because it gates on the STRONGER MESSAGE-AWARE account_hipaa_effective "
        "verdict; the wrapper gates only on account-level is_account_hipaa, which "
        "would MISS a message-flagged-HIPAA draft on a non-HIPAA account (the DA "
        "'FATAL' this session). Making audit_phi_access message-aware is the "
        "deeper SSOT improvement (tracked, hipaa-sme-gated). Added 2026-06-20",
    "actions/digest:_emit":
        "Shape-B: system digest_archive_failed event (H-06 §164.308(a)(7)), actor=None",
    "baa_expiry:auto_disable_expired_for_hipaa_accounts":
        "Shape-B: system BAA-expiry auto-disable event, actor=None",
    "db/reconciliation:emit_divergence_event":
        "Shape-B: system reconcile-divergence-detected event, actor=None",
    "web/digest:_fire_one_digest":
        "Shape-B: system recipient-digest-sent event (N-73), actor=None [db_call seam]",
    "web/topic_digest_sender:_fire_topic_digest":
        "Shape-B: system topic-digest-sent event (N-33-B), actor=None [db_call seam]",
    # Re-keyed 2026-11-06 (N-520 step 2, s2 panel M-N1): the in_progress
    # emit moved out of the _digest_sent_db_work closure into the route
    # itself, so the witness lands BEFORE the egress. Same emit, new scope.
    "web/routers/ui/accounts:recipient_digest_send_now":
        "Shape-B: operator-initiated recipient-digest-sent DISCLOSURE (N-125, the "
        "MANUAL sibling of web/digest:_fire_one_digest) — always-emit on HIPAA, "
        "actor=the triggering user. A known-actor PHI DISCLOSURE, NOT an actor≠owner "
        "READ: it must NOT route through audit_phi_access, which exempts owner-self "
        "and would re-open N-125 for an owner-triggered send (the disclosure still "
        "happens). hipaa-sme-blessed in census run15 #8 (actor=triggering user, "
        "always-emit). Direct emit through db_call in the route, before the send.",
    "web/watcher:_audit":
        "Shape-B: account_purged termination/lifecycle event (N-64), both outcomes [db_call seam]",
    # --- Shape-A+C: actor≠owner PHI-read but a start→finalise BRACKET ---
    # (gate routed through phi_access_audit_required; can't use single-emit helper)
    "web/routers/ui/triage_classify:_discover_gate_db_work":
        "Shape-C bracket: discover in_progress start row (owner-exempt gate-divergence flagged for SME)",
    "actions/hipaa_style_distill:distill_hipaa_style":
        "Shape-C bracket: HIPAA style-distill start row [db_call seam]",
    "jobs/topic_backscan:run_topic_backscan_job":
        "Shape-A+C bracket: topic_backscan start row, gate via phi_access_audit_required [db_call seam]",
    "web/triage_runner:run_triage":
        "Shape-A+C bracket: manual_triage start row, gate via phi_access_audit_required [db_call seam]",
    "web/triage_runner_bulk:run_style_mine_job":
        "Shape-A+C bracket: style_mine_bulk start row, gate via phi_access_audit_required [db_call seam]",
    "web/triage_runner_bulk:run_triage_all":
        "Shape-A+C bracket: bulk_triage start row, gate via phi_access_audit_required [db_call seam]",
}


_TARGET = "record_hipaa_access_event"

# Convenience for the routed-site teeth tests below (the UI handler layer).
_UI_DIR = SRC / "web" / "routers" / "ui"


class _Violation(NamedTuple):
    file: str
    lineno: int
    fn_name: str


def _emit_sites(tree: ast.Module) -> list[tuple[ast.Call, str | None]]:
    """Return (call_node, enclosing_fn) for every record_hipaa_access_event
    emit in ``tree`` — BOTH the direct call form AND the
    ``db_call(record_hipaa_access_event, …)`` SEAM (PD#2). Alias-aware (PD#6)."""
    parent_fn: dict[int, str | None] = {}

    def _tag(node: ast.AST, fn: str | None) -> None:
        parent_fn[id(node)] = fn
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _tag(child, child.name)
            else:
                _tag(child, fn)

    _tag(tree, None)

    aliases: set[str] = {_TARGET}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == _TARGET:
                    aliases.add(a.asname or a.name)

    out: list[tuple[ast.Call, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        direct = (
            (isinstance(func, ast.Name) and func.id in aliases)
            or (isinstance(func, ast.Attribute) and func.attr == _TARGET)
        )
        # SEAM (PD#2): the emit hops through a threadpool/async dispatcher as a
        # pass-by-reference. ``db_call`` is the sole dispatcher today, but
        # ``to_thread`` / ``run_in_executor`` are recognised too so a future
        # swap can't silently evade the ban (DA evasion-vector nit). Match by
        # ANY positional arg being the target name (robust to arg position —
        # run_in_executor puts the callable second). NOTE on wrapper-laundering
        # (DA nit): a function that WRAPS record_hipaa_access_event is itself
        # still caught — its internal emit is a direct call flagged unless the
        # wrapper fn is explicitly ALLOW_LISTed (e.g. db/reconciliation:
        # emit_divergence_event). So a wrapper is a conscious allow-list
        # decision, not an evasion.
        dispatch_name = (
            func.id if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute) else None
        )
        seam = (
            dispatch_name in {"db_call", "to_thread", "run_in_executor"}
            and any(
                isinstance(a, ast.Name) and a.id in aliases for a in node.args
            )
        )
        if direct or seam:
            out.append((node, parent_fn.get(id(node))))
    return out


def _collect_violations() -> list[_Violation]:
    """AST-walk ALL of src/email_triage (no file excluded) for
    record_hipaa_access_event emits (direct OR db_call seam) outside ALLOW_LIST."""
    violations: list[_Violation] = []

    for fpath in iter_src_files():
        rel = relpath(fpath)
        text = fpath.read_text(encoding="utf-8")
        if _TARGET not in text:
            continue
        tree = parse_source(text, filename=str(fpath))
        rel_stem = rel[:-3] if rel.endswith(".py") else rel

        for call_node, fn_name in _emit_sites(tree):
            fn_name = fn_name or "__module__"
            key = f"{rel_stem}:{fn_name}"
            if key in ALLOW_LIST:
                continue
            violations.append(_Violation(
                file=rel,
                lineno=call_node.lineno,
                fn_name=fn_name,
            ))

    return violations


def test_no_hand_rolled_record_hipaa_access_event():
    """Every record_hipaa_access_event emit anywhere in src/email_triage
    (direct call OR db_call seam) must be either the SSOT (audit_phi_access)
    or an explicitly allow-listed Shape-B / Shape-A+C bracket site.

    A new hand-rolled actor≠owner bookend that bypasses audit_phi_access —
    in the UI layer OR the service layer (where N-72/N-73 lived) — fails here.
    """
    violations = _collect_violations()
    if violations:
        lines = [
            f"\n  {v.file}:{v.lineno}  fn={v.fn_name}"
            for v in violations
        ]
        pytest.fail(
            "record_hipaa_access_event emit(s) found outside ALLOW_LIST. Route "
            "single-emit actor≠owner reads through audit_phi_access, or add the "
            "Shape-B/bracket site to ALLOW_LIST with a justification:"
            + "".join(lines)
        )


# ---------------------------------------------------------------------------
# 4. Delegation teeth — the 4 routed Shape-A sites call audit_phi_access
# ---------------------------------------------------------------------------

# For each routed site we check that their enclosing function contains a Call
# to audit_phi_access.  This catches a future in-place re-hand-roll.
_ROUTED_SITES = [
    # (relative path within web/routers/ui/, function name)
    ("labels.py", "_label_add_db_work"),
    ("labels.py", "_label_remove_db_work"),
    ("labels.py", "_bulk_label_db_work"),
    ("triage_classify.py", "_preview_gate_db_work"),
]

_AUDIT_PHI_SSOT = "audit_phi_access"


def _calls_audit_phi_access(fpath: Path, fn_name: str) -> bool:
    """Return True if ``fn_name`` in ``fpath`` contains a call to audit_phi_access."""
    text = fpath.read_text(encoding="utf-8")
    tree = parse_source(text, filename=str(fpath))

    # Collect aliases for audit_phi_access (handles _shared.audit_phi_access attr form).
    aliases: set[str] = {_AUDIT_PHI_SSOT}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == _AUDIT_PHI_SSOT:
                    aliases.add(a.asname or a.name)

    # Find the target function definition.
    for top in ast.walk(tree):
        if not isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if top.name != fn_name:
            continue
        # Walk all nodes within this function body.
        for node in ast.walk(top):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Direct call: audit_phi_access(...)
            if isinstance(func, ast.Name) and func.id in aliases:
                return True
            # Attribute call: _shared.audit_phi_access(...)
            if (
                isinstance(func, ast.Attribute)
                and func.attr in aliases
            ):
                return True
    return False


@pytest.mark.parametrize("rel_path,fn_name", _ROUTED_SITES)
def test_routed_site_calls_audit_phi_access(rel_path: str, fn_name: str):
    """Each of the 4 routed Shape-A sites must contain a call to
    audit_phi_access (direct or via _shared.audit_phi_access).

    If this test fails, a site has been re-hand-rolled and must be re-routed
    through the SSOT.
    """
    fpath = _UI_DIR / rel_path
    assert fpath.exists(), f"Source file not found: {fpath}"
    found = _calls_audit_phi_access(fpath, fn_name)
    assert found, (
        f"{rel_path}:{fn_name} does not call audit_phi_access. "
        "Route it through the SSOT (web/routers/ui/_shared.py:audit_phi_access)."
    )


# ---------------------------------------------------------------------------
# 5. phi_access_audit_required — the PD#14 gate predicate SSOT (truth table)
# ---------------------------------------------------------------------------

def test_phi_access_audit_required_importable():
    from email_triage.db.audit import phi_access_audit_required  # noqa: F401
    assert callable(phi_access_audit_required)


@pytest.mark.parametrize("account_hipaa,actor,owner,expected", [
    # HIPAA account, non-owner human → required
    (True, 99, 10, True),
    # HIPAA account, owner-self → exempt (§164.502(a))
    (True, 10, 10, False),
    # HIPAA account, SYSTEM actor (None) → REQUIRED (None != owner; the N-72 bug
    # was adding `actor is not None` here, which dropped system PHI reads)
    (True, None, 10, True),
    # non-HIPAA account, any actor → never
    (False, 99, 10, False),
    (False, None, 10, False),
])
def test_phi_access_audit_required_truth_table(account_hipaa, actor, owner, expected):
    from email_triage.db.audit import phi_access_audit_required
    got = phi_access_audit_required(
        account_hipaa=account_hipaa, actor_user_id=actor, owner_id=owner,
    )
    assert got is expected, (
        f"phi_access_audit_required(hipaa={account_hipaa}, actor={actor}, "
        f"owner={owner}) = {got}, expected {expected}"
    )


def test_phi_access_audit_required_has_no_actor_is_not_none_guard():
    """Source-level guard: the predicate body must NOT contain an
    `actor_user_id is not None` test — that is the N-72 bug it exists to kill.
    A future edit that re-adds it (re-dropping system-initiated PHI reads from
    the audit trail) fails here.
    """
    audit_src = (SRC / "db" / "audit.py").read_text(encoding="utf-8")
    tree = parse_source(audit_src)
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == "phi_access_audit_required"),
        None,
    )
    assert fn is not None, "phi_access_audit_required not found in db/audit.py"
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and any(
            isinstance(op, (ast.IsNot, ast.Is)) for op in node.ops
        ):
            # an `x is not None` / `x is None` involving actor_user_id is banned
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            assert "actor_user_id" not in names, (
                "phi_access_audit_required reintroduced an `actor_user_id is "
                "(not) None` guard — the N-72 bug. A system actor (None) is a "
                "non-owner read and MUST audit; use `!=` only."
            )


# ---------------------------------------------------------------------------
# 6. Bracket-gate delegation teeth — the 4 start→finalise bracket sites must
#    gate through phi_access_audit_required (not a hand-rolled inline gate that
#    could re-grow the `actor is not None` divergence, N-79).
# ---------------------------------------------------------------------------

_BRACKET_GATE_SITES = [
    ("web/triage_runner.py", "run_triage"),
    ("web/triage_runner_bulk.py", "run_style_mine_job"),
    ("web/triage_runner_bulk.py", "run_triage_all"),
    ("jobs/topic_backscan.py", "run_topic_backscan_job"),
]


@pytest.mark.parametrize("rel_path,fn_name", _BRACKET_GATE_SITES)
def test_bracket_gate_uses_predicate_ssot(rel_path, fn_name):
    """Each actor≠owner start→finalise bracket site must gate its emit through
    phi_access_audit_required, so the PD#14 gate logic stays in ONE place and
    the `actor_user_id is not None` divergence (N-72/N-79) cannot recur inline.
    """
    fpath = SRC / rel_path
    tree = parse_module(fpath)
    assert tree is not None, f"parse_module returned None for {fpath}"
    target = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == fn_name),
        None,
    )
    assert target is not None, f"{fn_name} not found in {rel_path}"
    calls_predicate = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "phi_access_audit_required"
        for n in ast.walk(target)
    )
    assert calls_predicate, (
        f"{rel_path}:{fn_name} no longer gates through phi_access_audit_required "
        "— a hand-rolled inline actor≠owner gate risks re-growing the N-72 "
        "`actor_user_id is not None` bug. Route the gate through the predicate SSOT."
    )
