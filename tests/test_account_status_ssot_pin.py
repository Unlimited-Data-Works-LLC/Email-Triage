"""N-411 (2026-07-13) — account_states SSOT structural pin.

Closes the ``feedback_divergence_audit_and_ssot_pin`` violation left open
when :meth:`WatcherManager.account_states` was introduced with a DOCSTRING
promise (``watcher.py:268-278``) but no count-agnostic interprocedural pin.
The docstring explicitly names itself the *"Single source of truth for 'is
this account ingesting?'"* and calls out that *"Every operator-facing
surface (/health, dashboard chip, daily digest) folds over this list rather
than rebuilding the join — keeps the surfaces consistent and shrinks each
new-provider rollout to one branch in this method."*

The docstring was aspirational — nothing enforced it. Three surfaces were
migrated (``routers/health.py::account_states = ...``,
``routers/ui/_shared.py::_dashboard_health_chips`` per-provider aggregate,
``web/daily_health.py::_daily_health_ingestion_rollup``); a fourth
(``routers/ui/_shared.py::_admin_stats_snapshot`` — the /admin/stats
"Watcher state (current snapshot)" table) was NEVER migrated. The result
shipped to production: every Gmail-API + Office-365 account rendered
``status=stopped`` + ``Started="-"`` on the operator's /admin/stats page
even while the Pub/Sub / Graph subscription was healthy and delivering
mail. Operator flagged 2026-07-12 21:19 EDT from two side-by-side
screenshots (see ``STATE_2026-07-13_early_am_watcher_status_mismatch_investigating``).

Root cause of the miss (why the SSOT layer didn't catch it):
    1. Prime Directive 1 violated at SSOT introduction — SSOT method
       shipped, count-agnostic pin never shipped alongside.
    2. Docstring enumerated 3 surfaces; 4th was invisible without a
       count-agnostic sweep.
    3. Playbook §3 registry never got a row for the account_states SSOT,
       so the quarterly true-up couldn't find it.
    4. Incomplete migration sweep (feedback_root_cause_scope) — 3 of 4
       consumer sites migrated; the obscure 4th escaped.
    5. Existing tests (``test_watch.py``, ``test_dashboard_redesign.py``,
       ``test_daily_health_email.py``) pin the OLD ``all_statuses()``
       return shape, not the NEW SSOT invariant.

THE PIN.
    Every ``.all_statuses()`` call in ``src/email_triage/web/**/*.py`` MUST
    be inside an enclosing function on the deliberate allow-list —
    documented IMAP-IDLE-specific stuck-watcher detection sites, each
    paired with a separate Gmail arm at the same seam. Any other caller
    is a per-account watcher-status renderer that will silently drop the
    Gmail-API + O365 accounts. Renderers with cross-provider intent MUST
    call ``WatcherManager.account_states(db)`` (or a future
    ``render_snapshot(db)`` wrapper).

    The allow-list is keyed on ``(relpath, enclosing_fn)`` — line-shift
    stable per the shared harness's ``enclosing_fn`` idiom (R38 anti-drift
    line-key stability). Each entry carries a reason.

Count-agnostic + interprocedural per PD#2 — walks the whole subtree, keyed
on call-site enclosing function (survives helper reshuffles). Routes the
walk through ``_pin_harness`` per PD#6 (pins obey the SSOT rule too).
"""

from __future__ import annotations

import ast

from _pin_harness import (
    assert_pin_has_teeth,
    enclosing_fn,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)


# Deliberate allow-list of IMAP-IDLE-specific stuck-watcher detection seams.
# Each entry is (relpath, enclosing_fn) — line-shift stable. Each entry MUST
# carry a stated reason. The scoping is intentional: an IMAP watcher stuck
# in a non-``watching`` state past the 15-min stale threshold is an alert
# even though the Gmail Pub/Sub / O365 Graph accounts don't have IDLE state
# at all — the Gmail/O365 arm is a SIBLING seam right next to each of these
# (``_gmail_push_counts`` for health, ``_render_gmail_watch_chip`` for the
# dashboard), so per-provider counting is by-design here.
_ALL_STATUSES_ALLOW: frozenset[tuple[str, str]] = frozenset({
    (
        "web/routers/health.py",
        "_watcher_counts",
    ),
    # ^^ IMAP-IDLE stuck detection for the /health JSON endpoint. The Gmail
    # arm is a SIBLING function ``_gmail_push_counts`` in the same file
    # (:281), the O365 arm is ``_o365_push_counts``. Per-provider seam by
    # design — do NOT collapse to account_states here; the per-provider
    # health-chip semantics differ (an IMAP IDLE drop with poll fallback is
    # non-degraded but a Gmail Pub/Sub expiry with poll fallback is; the
    # per-arm counters preserve that distinction).
    (
        "web/routers/ui/_shared.py",
        "_admin_stats_snapshot",
    ),
    # ^^ N-411 paired hydration seam: `_admin_stats_snapshot` folds over
    # `wm.account_states(db)` (the SSOT) for the per-provider status +
    # started_at; the paired `all_statuses()` call is ONLY hydrating IMAP
    # per-mailbox `processed`/`errors` COUNTS (the per-provider count union
    # — Gmail-API + O365 counts come from `push_deliveries` filtered by
    # account_id). This is the LEGITIMATE mixed-hydration shape; SSOT-
    # violating shape would be using `all_statuses()` for the STATUS field
    # itself. Locked in place by the fold-over-`account_states` primary
    # loop above the count hydration.
    (
        "web/routers/ui/_shared.py",
        "_build_dashboard_context",
    ),
    # ^^ Sibling of the above — IMAP stuck-watcher list for the header
    # degraded pill on the dashboard (inlined into `_build_dashboard_context`
    # around :822, filter values `{reconnecting, error, disconnected}` are
    # IMAP-only status vocab from `_aggregate_status`). Gmail arm is
    # `_render_gmail_watch_chip` (:3938 in the same file) and O365 arm is
    # `_render_o365_push_chip` (:4019). Same per-provider design as
    # `_watcher_counts`. RESIDUAL — a dropped Gmail Pub/Sub with no poll
    # fallback would not raise a "stuck watcher" banner from THIS site; the
    # separate per-provider chips are what surface it. Acceptable per S3
    # narrowing (banner is a header-degraded signal, the per-account chip
    # is the operator's actionable surface).
})


def _all_statuses_call_sites():
    """Yield ``(relpath, enclosing_fn, lineno)`` for every ``<x>.all_statuses()``
    call site under ``src/email_triage/web/`` — interprocedural, count-agnostic.

    Scoped to ``web/`` because the pin's invariant is about OPERATOR-FACING
    per-account watcher-status renderers, which live under the web tree.
    """
    for path in iter_src_files("web"):
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute):
                continue
            if fn.attr != "all_statuses":
                continue
            yield rel, enclosing_fn(node), node.lineno


def test_all_statuses_callsites_confined_to_allowlist():
    """Every ``.all_statuses()`` call site in ``src/email_triage/web/`` MUST
    be inside an allow-listed enclosing function.

    ``all_statuses()`` iterates ``_mb_state`` which is IMAP-only — Gmail-API
    and Office-365 accounts have zero ``_mb_state`` entries so ``_aggregate_
    status`` returns ``status="stopped"`` + ``started_at=None`` by default
    (``watcher.py:128-137``). Any operator-facing per-account watcher-status
    renderer that calls ``all_statuses()`` silently drops those providers.

    Fix: call ``WatcherManager.account_states(db)`` — the SSOT method that
    unifies IMAP ``_mb_state`` + Gmail ``gmail_watches`` rows + O365
    ``office365_subscriptions`` rows into one per-account verdict
    (``watcher.py:280-409``). Its docstring names /health, dashboard chip,
    daily digest as the surfaces that MUST fold over it — this pin makes
    that promise executable.
    """
    violations: list[str] = []
    for rel, fn_name, lineno in _all_statuses_call_sites():
        if (rel, fn_name) in _ALL_STATUSES_ALLOW:
            continue
        violations.append(f"  {rel}:{lineno}  (in {fn_name}())")
    assert not violations, (
        "N-411 SSOT violation — `all_statuses()` called outside the IMAP-IDLE-"
        "specific stuck-watcher-detection allow-list. `all_statuses()` returns "
        "IMAP-only per-mailbox state (via `_mb_state`); Gmail-API and Office-365 "
        "accounts render as `status=stopped` / `Started=None` even when their "
        "Pub/Sub / Graph subscription is healthy. Operator-facing renderers must "
        "call `WatcherManager.account_states(db)` — the SSOT that unifies IMAP "
        "+ Gmail + O365 into one per-account verdict (see `watcher.py:268-278` "
        "docstring). To exempt a NEW IMAP-IDLE-specific detection seam, add "
        "`(relpath, enclosing_fn)` to `_ALL_STATUSES_ALLOW` with a stated reason "
        "AND confirm a sibling Gmail/O365 arm exists in the same file.\n\n"
        "Sites off the allow-list:\n"
        + "\n".join(violations)
    )


def _detector(tree: ast.AST) -> list[int]:
    """Detector for :func:`assert_pin_has_teeth` — return lineno of every
    ``<x>.all_statuses()`` call in ``tree`` (any receiver, any enclosing
    scope). Teeth-fn for the ARM-4 teeth-probe meta-pin (N-237 R23)."""
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not isinstance(fn, ast.Attribute):
            continue
        if fn.attr == "all_statuses":
            hits.append(node.lineno)
    return hits


def test_pin_has_teeth():
    """ARM-4 teeth probe (N-237 R23 via ``_pin_harness.assert_pin_has_teeth``)
    — the detector MUST flag a planted bad shape and MUST NOT flag the
    remediated shape (``account_states`` call instead of ``all_statuses``)."""
    assert_pin_has_teeth(
        _detector,
        bad_source="""
def _admin_stats_snapshot(db, request, window):
    wm = request.app.state.watcher_manager
    watcher_states = []
    for acct_id, s in wm.all_statuses().items():
        watcher_states.append({
            "account_id": acct_id,
            "status": s.get("status", "unknown"),
            "processed": s.get("processed", 0),
        })
    return {"watcher_states": watcher_states}
""",
        good_source="""
def _admin_stats_snapshot(db, request, window):
    wm = request.app.state.watcher_manager
    watcher_states = []
    for row in wm.account_states(db):
        watcher_states.append({
            "account_id": row["account_id"],
            "status": row["primary"],
            "processed": row.get("processed", 0),
        })
    return {"watcher_states": watcher_states}
""",
    )


def test_allowlist_has_no_stale_entries():
    """N-206 R22-style rot-guard — every ``(relpath, fn)`` in
    ``_ALL_STATUSES_ALLOW`` MUST correspond to an ACTUAL call site on HEAD.
    A stale entry (function renamed / call removed) silently exempts a
    FUTURE call site if a new one lands under the same (relpath, fn) key.

    This is the PD#7 rot-guard the pin harness meta-pin
    (``test_ssot_registry_bijection_pin.py::test_harness_import_allow_is_
    not_stale``) sibling requires for every allow-list carried by a
    structural pin.
    """
    live_sites = {(rel, fn) for rel, fn, _ in _all_statuses_call_sites()}
    stale = sorted(_ALL_STATUSES_ALLOW - live_sites)
    assert not stale, (
        "N-411 rot-guard: `_ALL_STATUSES_ALLOW` entries no longer match a live "
        "call site (function renamed / call removed / file moved). Remove the "
        "stale entry OR restore the intentional call. Stale entries:\n  "
        + "\n  ".join(f"{rel}::{fn}" for rel, fn in stale)
    )
