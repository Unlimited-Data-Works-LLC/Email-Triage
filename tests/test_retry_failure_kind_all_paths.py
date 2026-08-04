""" — every ingestion path stamps ``failure_kind='llm_unreachable'``.

The retry drainer's LLM-breaker gate (``_recover_one_retry_row`` /
``_watcher_retry_sweeper`` in ``web/app.py``) only skips the doomed
classify round-trip for retry rows whose ``failure_kind ==
'llm_unreachable'``. Before  only ONE of the ingestion paths — the
IMAP IDLE watcher (``_watch_account``) — stamped that kind when it
enqueued a retry after an ``LLMBackendUnreachableError``. The other
paths enqueued retries with a generic (NULL) ``failure_kind``, so the
gate never engaged and the drainer kept hammering a dead LLM endpoint
at full connect-timeout cost on every due row.

The ingestion paths that enqueue per-message retries:

  1. IMAP IDLE watcher        — ``_watch_account``               (reference)
  2. Gmail push consumer      — ``_process_push_item``
  3. O365 push consumer       — ``_process_office365_push_item``
  4. O365 unified-poll        — ``_poll_once`` (Graph branch)
  5. IMAP unified-poll        — ``_poll_once_imap``

The triage runner (``triage_runner.py``) and bulk runner
(``triage_runner_bulk.py``) deliberately have NO per-message retry
queue — they record per-message error entries directly — so there is
no enqueue site to stamp there.

Two layers of coverage:

* :class:`TestIngestionEnqueueSitesStampFailureKind` — a STRUCTURAL
  GLOB walk over the whole ``web/`` tree (``src/email_triage/web/**/*.py``)
  that AST-collects every ``enqueue_watcher_retry`` call and asserts
  each forwards a conditional ``failure_kind``. This is the exhaustive
  check: it fails if a future ingestion path is added without the stamp.

  Glob discovery, NOT a hardcoded module list: the
  decomposition of ``web/app.py`` spread the ingestion enqueue sites
  across siblings — the IMAP IDLE watcher moved to ``web/watcher.py``
  (carve 47d7eb1) and the Gmail/O365 push consumers to
  ``web/ingestion_push.py`` (carve #277d). A single-file walk over
  ``app.py`` alone went stale on the first carve and would have gone
  DARK on the moved PHI-ingestion paths after the second; a hardcoded
  module *list* only relocates that rot — it re-arms the
  §164.308(a)(8) dark-guard the moment a future author carves a NEW
  ingestion module (the coming poll-ingestion / sweeper carves) and
  forgets to append it. A glob puts every web module IN SCOPE
  structurally, so a new under-stamped enqueue site goes RED
  automatically. Per ``pattern_count_agnostic_structural_drift_catch.md``:
  pin "every enqueue site stamps the kind", discovered structurally —
  never a module roll-call.

  The module that *defines* ``enqueue_watcher_retry`` (currently
  ``web/watcher_retry.py``) is excluded by DEF-SITE — it hosts the
  ``enqueue_watch_delivery_retry`` shim whose lone call stamps a
  non-LLM constant (``'watch_delivery_failure'``). Def-site exclusion
  (NOT a ``failure_kind``-shape filter, which would be circular and
  hide the very bug the per-site check exists to catch) survives a
  future relocation of the helper.
* :class:`TestEnqueuePathStampsLlmUnreachable` — a behavioural test
  that drives the shared call-site decision pattern
  (``isinstance(e, LLMBackendUnreachableError)`` → ``failure_kind``)
  through :func:`enqueue_watcher_retry` into a real DB, once per
  provider addressing shape, proving the row lands with the right
  ``failure_kind`` for an LLM-unreachable failure and NULL for a
  generic one.
"""

from __future__ import annotations
from _db_tracking import track

import ast
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from email_triage.llm_health import LLMBackendUnreachableError
from email_triage.web.db import get_retry, init_db
from email_triage.web.watcher_retry import enqueue_watcher_retry


# ---------------------------------------------------------------------------
# Layer 1 — AST: every enqueue_watcher_retry call across the GLOB-discovered
# web/ ingestion surface passes a conditional failure_kind. Exhaustive:
# catches a new ingestion path added without the stamp, AND survives the
# web/app.py decomposition that spread the sites across sibling modules
# — by discovering the surface (glob web/**/*.py minus the helper's
# def-site), never a hardcoded module roll-call that rots on the next carve.
# Per pattern_count_agnostic_structural_drift_catch.md.
# ---------------------------------------------------------------------------

from _pin_harness import SRC_ROOT, iter_src_files, parse_module  # N-350 R31

_WEB_DIR = SRC_ROOT / "web"  # harness-rooted (R5b)


def _ingestion_modules() -> list[Path]:
    """STRUCTURALLY DISCOVER the web modules that may host an ingestion-path
    ``enqueue_watcher_retry`` call site — instead of a hard-coded list that
    silently goes dark on the next carve.

    The #277d decomposition spread the 5 ingestion enqueue sites across
    ``web/app.py`` (O365 + IMAP unified-poll), ``web/watcher.py`` (IMAP IDLE,
    carve 47d7eb1) and ``web/ingestion_push.py`` (Gmail + O365 push). A
    hard-coded module tuple re-creates the exact §164.308(a)(8) dark-guard
    this pin exists to prevent: the coming poll-ingestion / sweeper carves
    will land new enqueue-site modules, and a forgotten append silently
    drops coverage on a PHI-ingestion path. So discover the surface, don't
    pin a list (``pattern_count_agnostic_structural_drift_catch.md``).

    Glob ``web/**/*.py`` — RECURSIVE, so it covers ``web/routers/``
    subpackages too (task #9 is actively moving handlers there; a future
    ingestion carve into a subpackage must not silently re-blind the guard).
    EXCLUDE — structurally, by ``def`` not by filename — the single module
    that *defines* ``enqueue_watcher_retry``
    (``web/watcher_retry.py``). Its only call is inside the
    ``enqueue_watch_delivery_retry`` shim, which stamps
    ``failure_kind='watch_delivery_failure'`` by design (a non-LLM path), not
    an ingestion-path classify-failure retry. Any future ingestion module is
    auto-covered with nothing to update.
    """
    mods: list[Path] = []
    for path in iter_src_files("web"):  # R5b harness walk
        tree = parse_module(path); assert tree is not None, f"parse failed: {path}"  # N-350 R31
        if any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "enqueue_watcher_retry"
            for n in ast.walk(tree)
        ):
            continue  # def-site module — excluded structurally
        mods.append(path)
    return mods


def _enqueue_watcher_retry_calls() -> list[tuple[Path, ast.Call]]:
    """Return every ``enqueue_watcher_retry(...)`` call node across the
    glob-discovered ingestion surface, paired with the module it lives in.

    The call sites import the helper under per-site aliases
    (``_wr_enqueue``, ``_wr_enqueue_g``, ``_wr_enqueue_o``,
    ``_wr_enqueue_p``). Collect the alias set per module from the
    ``from ... import enqueue_watcher_retry as <alias>`` statements,
    then match call nodes against it. Calls may be wrapped in
    ``db_call(<alias>, ...)`` (the -residual off-loop hop), so a
    bare ``db_call`` call whose first positional arg is one of the
    aliases counts too.
    """
    calls: list[tuple[Path, ast.Call]] = []
    for module in _ingestion_modules():
        tree = parse_module(module)
        if tree is None:
            continue  # skip unparseable modules (N-178 sweep)

        aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "enqueue_watcher_retry":
                        aliases.add(alias.asname or alias.name)
        # The canonical name itself is always a valid target.
        aliases.add("enqueue_watcher_retry")

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Direct call: <alias>(...)
            if isinstance(func, ast.Name) and func.id in aliases:
                calls.append((module, node))
                continue
            # Wrapped call: db_call(<alias>, ...) — the enqueue helper is
            # the first positional arg.
            if (
                isinstance(func, ast.Name)
                and func.id == "db_call"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in aliases
            ):
                calls.append((module, node))
    return calls


class TestIngestionEnqueueSitesStampFailureKind:
    """Structural guard — every ingestion-path enqueue site across the
    GLOB-discovered ``web/`` surface must forward a ``failure_kind``
    keyword.  added it to the four push/poll sites; the IMAP IDLE
    watcher already had it. If a future ingestion path enqueues a retry
    without the stamp, the LLM-breaker gate silently never engages for
    it — this test fails first.

    Discovers the surface by glob (``web/**/*.py`` minus the helper's
    def-site), not a hardcoded module list, so the #277d decomposition
    (which moved 3 of the sites to sibling modules) — and the coming
    poll-ingestion / sweeper carves — cannot silently drop coverage on a
    moved/new PHI-ingestion path."""

    def test_enqueue_sites_are_discovered(self):
        # Tripwire: at least ONE enqueue site must be discovered. A zero
        # result means the glob or the call-matcher drifted — fail loud
        # rather than vacuously pass. The per-site invariants below are
        # cardinality-independent (they check EVERY discovered site,
        # however many); this is the only count assertion and it is a
        # floor of 1, not a roll-call of N. Known sites today: IMAP IDLE
        # (watcher.py) + Gmail/O365 push (ingestion_push.py) + O365/IMAP
        # unified-poll (app.py).
        calls = _enqueue_watcher_retry_calls()
        assert len(calls) >= 1, (
            "found ZERO enqueue_watcher_retry call sites across the "
            f"glob-discovered web/ surface ({[m.name for m in _ingestion_modules()]}) "
            "— the glob or the enqueue-call matcher has drifted; the "
            " LLM-breaker stamp guard is now vacuous. Re-anchor the "
            "discovery."
        )

    def test_every_enqueue_site_passes_failure_kind(self):
        calls = _enqueue_watcher_retry_calls()
        missing: list[str] = []
        for module, call in calls:
            kw_names = {kw.arg for kw in call.keywords}
            if "failure_kind" not in kw_names:
                missing.append(f"{module.name}:{getattr(call, 'lineno', -1)}")
        assert not missing, (
            "enqueue_watcher_retry call(s) missing the failure_kind "
            f"keyword at {missing} — the retry drainer's LLM-breaker "
            "gate will never engage for that ingestion path."
        )

    def test_every_enqueue_site_derives_kind_from_llm_down_check(self):
        """The stamp must be conditional on an LLM-unreachable check —
        a hard-coded ``failure_kind='llm_unreachable'`` would wrongly
        gate ordinary fetch/process failures too. Each site passes a
        ternary ``'llm_unreachable' if <flag> else None``."""
        calls = _enqueue_watcher_retry_calls()
        for module, call in calls:
            fk = next(
                (kw.value for kw in call.keywords if kw.arg == "failure_kind"),
                None,
            )
            assert fk is not None, "call missing failure_kind (see sibling test)"
            # Accept either a conditional expression or a bare None
            # (e.g. a non-LLM-specific site) — but NOT a hard-coded
            # 'llm_unreachable' constant.
            if isinstance(fk, ast.Constant):
                assert fk.value != "llm_unreachable", (
                    f"enqueue site at {module.name}:{call.lineno} hard-codes "
                    "failure_kind='llm_unreachable' — non-LLM failures "
                    "would be wrongly gated."
                )


# ---------------------------------------------------------------------------
# Layer 2 — behavioural: the shared call-site decision pattern lands the
# correct failure_kind in a real retry row, per provider addressing shape.
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    c = track(init_db(":memory:"))
    yield c
    c.close()


@pytest.fixture
def account_id(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (uid, "Mailbox", "imap", "{}", now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _enqueue_like_call_site(conn, *, account_id, error, **addressing):
    """Reproduce the exact decision every ingestion path now uses:

        _is_llm_down = isinstance(e, LLMBackendUnreachableError)
        enqueue_watcher_retry(..., failure_kind=(
            "llm_unreachable" if _is_llm_down else None))

    Returns the new retry row id.
    """
    _is_llm_down = isinstance(error, LLMBackendUnreachableError)
    return enqueue_watcher_retry(
        conn,
        account_id=int(account_id),
        error=error,
        failure_kind=("llm_unreachable" if _is_llm_down else None),
        **addressing,
    )


class TestEnqueuePathStampsLlmUnreachable:
    """One pair of cases per ingestion path's addressing shape. The LLM
    backend re-raises ``LLMBackendUnreachableError`` through
    ``triage_single_message`` unchanged, so each call site's bare
    ``except Exception as e`` sees the real type — the
    ``isinstance`` check fires and stamps ``llm_unreachable``."""

    def test_imap_idle_watcher_llm_unreachable(self, conn, account_id):
        """Path 1 — reference path (already correct before )."""
        err = LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="imap", mailbox="INBOX", uid="42", uidvalidity="1",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"

    def test_gmail_push_consumer_llm_unreachable(self, conn, account_id):
        """Path 2 — Gmail push consumer (_process_push_item)."""
        err = LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="gmail_api", gmail_msg_id="msg_abc",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"

    def test_gmail_push_consumer_generic_error_is_null(
        self, conn, account_id,
    ):
        """A non-LLM failure on the Gmail push path keeps NULL kind —
        the drainer must still retry an ordinary fetch hiccup."""
        rid = _enqueue_like_call_site(
            conn, account_id=account_id,
            error=TimeoutError("graph fetch timed out"),
            provider_type="gmail_api", gmail_msg_id="msg_xyz",
        )
        assert get_retry(conn, rid)["failure_kind"] is None

    def test_o365_push_consumer_llm_unreachable(self, conn, account_id):
        """Path 3 — O365 push consumer (_process_office365_push_item)."""
        err = LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="office365", o365_msg_id="AAMkAGI=",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"

    def test_o365_push_consumer_generic_error_is_null(
        self, conn, account_id,
    ):
        rid = _enqueue_like_call_site(
            conn, account_id=account_id,
            error=RuntimeError("graph backend hiccup"),
            provider_type="office365", o365_msg_id="AAMkBBB=",
        )
        assert get_retry(conn, rid)["failure_kind"] is None

    def test_o365_unified_poll_llm_unreachable(self, conn, account_id):
        """Path 4 — O365 unified-poll (_poll_once, Graph branch)."""
        err = LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="office365", o365_msg_id="AAMkPOLL=",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"

    def test_imap_unified_poll_llm_unreachable(self, conn, account_id):
        """Path 5 — IMAP unified-poll (_poll_once_imap)."""
        err = LLMBackendUnreachableError(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="imap", mailbox="Archive", uid="9001",
            uidvalidity="1",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"

    def test_imap_unified_poll_generic_error_is_null(
        self, conn, account_id,
    ):
        rid = _enqueue_like_call_site(
            conn, account_id=account_id,
            error=TimeoutError("network blip"),
            provider_type="imap", mailbox="Archive", uid="9002",
            uidvalidity="1",
        )
        assert get_retry(conn, rid)["failure_kind"] is None

    def test_llm_unreachable_subclass_also_stamps(self, conn, account_id):
        """``isinstance`` is the gate — a subclass of
        ``LLMBackendUnreachableError`` (should one ever exist) is still
        treated as LLM-down. Guards against an over-narrow ``type(e) is``
        check creeping into a call site."""

        class _DerivedUnreachable(LLMBackendUnreachableError):
            pass

        err = _DerivedUnreachable(
            backend="ollama", host="llm-host", port=11434,
        )
        rid = _enqueue_like_call_site(
            conn, account_id=account_id, error=err,
            provider_type="imap", mailbox="INBOX", uid="5", uidvalidity="1",
        )
        assert get_retry(conn, rid)["failure_kind"] == "llm_unreachable"
