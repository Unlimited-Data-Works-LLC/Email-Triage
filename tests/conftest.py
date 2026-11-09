"""Shared test fixtures."""

import logging
from datetime import datetime, timezone

import pytest

import _e2e_isolation_guard
import _network_guard


# N-431 (2026-07-19) — reset the module-level SSOT probe cache in
# ``email_triage._ollama_reuse`` between tests. The cache is per-process
# and per-base_url; without a reset a mock in test A pollutes the cache
# for test B when they hit the same base_url (default ``http://localhost:
# 11434``). Autouse + repo-wide because ANY test that instantiates an
# ``OllamaClassifier`` or ``OllamaEmbeddingBackend`` may drive the probe
# transitively (via ``_resolve_model`` / ``merge_reuse_options`` on
# ``_chat`` / ``_chat_topics`` / ``_chat_safety`` / ``_complete_once`` /
# ``embed_text``). Also resets the per-URL ``asyncio.Lock`` so a Lock
# created in a prior loop can't leak into the next test's loop (Lock
# construction defers loop-binding to first acquire, but the RuntimeError
# recovery inside ``_ollama_reuse._get_lock`` needs a clean slate to be
# a no-cost fast path).
@pytest.fixture(autouse=True)
def _reset_ollama_reuse_probe_cache():
    from email_triage._ollama_reuse import _reset_for_tests

    _reset_for_tests()
    yield
    _reset_for_tests()

import email_triage.triage_logging as _triage_logging
from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.engine.store import FlowStore


# ---------------------------------------------------------------------------
# Test-warnings bucket 3 (internal documentation): Starlette TestClient's
# per-request ``cookies=`` is deprecated by httpx, and ~832 call sites across the
# suite switch identity (admin/user/anon) PER REQUEST that way. Rather than
# rewrite every call site (the "large tracked refactor" the pyproject comment
# named), wrap ``TestClient.request`` ONCE: a per-request ``cookies=`` is merged
# into the client jar for THAT one call (httpx's documented merge semantics),
# then restored — so the cookies still authenticate exactly as before, but the
# deprecated httpx per-request-cookies path is never reached. One funnel; every
# TestClient instance (the shared fixture AND every ad-hoc ``TestClient(app)``)
# is covered, and the call sites stay unchanged. Idempotent (patched once).
# ---------------------------------------------------------------------------
def _install_cookie_tolerant_testclient() -> None:
    from starlette.testclient import TestClient as _TC

    if getattr(_TC, "_et_cookie_tolerant", False):
        return
    _orig_request = _TC.request

    def request(self, method, url, *args, cookies=None, **kwargs):
        if cookies is None:
            return _orig_request(self, method, url, *args, **kwargs)
        saved = dict(self.cookies)
        try:
            self.cookies.update(cookies)
            return _orig_request(self, method, url, *args, **kwargs)
        finally:
            self.cookies.clear()
            self.cookies.update(saved)

    _TC.request = request
    _TC._et_cookie_tolerant = True


_install_cookie_tolerant_testclient()


# ---------------------------------------------------------------------------
# Order-dependent O365 flake fix (db-sme, 2026-06-20): keep a stub ``msal``
# permanently in ``sys.modules`` for the whole test session.
#
# ROOT CAUSE of the flake (test_o365_probe_ui / test_o365_push_ui happy-path
# tests intermittently rendering "the Office 365 provider isn't installed"):
# ``msal`` is NOT installed in CI, so several O365 tests inject a mock via
# ``patch.dict(sys.modules, {"msal": _mock_msal})`` (test_office365.py,
# test_log_no_token_leak.py, test_privacy_invariants_oauth.py,
# test_search_iter.py, test_office365_calendar.py, ...). Because ``msal`` is
# absent originally, ``patch.dict``'s teardown DELETES the ``msal`` key from
# the process-global ``sys.modules`` dict. The probe/push happy-path handlers
# build the provider on a ``to_thread`` worker (``db_call`` →
# ``asyncio.to_thread``) driven by the request's TestClient/anyio portal loop.
# Under ``pytest -n auto --dist=loadfile`` the worker process is REUSED across
# files, so a polluter file's ``patch.dict`` teardown can churn ``sys.modules``
# (clear + repopulate) concurrently with a later file's threaded provider
# construction. During that window the construction's MSAL-availability view
# collapses and the handler renders the not-installed chip — even though the
# victim's own ``force_msal_present`` fixture set ``HAS_MSAL=True``.
# Empirically: deterministic <polluter, victim> ordering reproduces it; the
# perceived "intermittency" is loadfile's non-deterministic file→worker
# assignment. Verified the fix: with a stub ``msal`` always present, every
# ``patch.dict(sys.modules, {"msal": ...})`` overlay RESTORES TO THE STUB
# instead of deleting — the churn disappears and all polluter×victim combos
# go green.
#
# This is the SSOT fix for the whole class: any current or future test that
# overlays ``sys.modules['msal']`` now restores to a stub, not a hole. It does
# NOT disturb ``HAS_MSAL``-based tests (e.g. test_office365.py::
# test_msal_not_installed flips the module global ``HAS_MSAL`` False and asserts
# ImportError — the guard reads the global, not ``sys.modules``).
def _install_stub_msal_module() -> None:
    import sys
    from unittest.mock import MagicMock

    if isinstance(sys.modules.get("msal"), MagicMock):
        return
    try:  # if the real package IS installed, leave it alone
        import msal  # noqa: F401
        return
    except ImportError:
        pass
    stub = MagicMock(name="stub_msal")
    stub.SerializableTokenCache = MagicMock
    stub.PublicClientApplication = MagicMock
    stub.ConfidentialClientApplication = MagicMock
    sys.modules["msal"] = stub


_install_stub_msal_module()


@pytest.fixture(autouse=True)
def _provision_audit_chain_hmac_key_for_tests():
    """Autouse fixture — install a deterministic HMAC key + clear after each test.

    H-02a (Cycle 6, 2026-05-23) made the audit-chain hash D1-fail-closed
    per hipaa-sme-2 + DA-3 regulatory verdict: ``compute_log_row_hash``
    raises ``RuntimeError`` if no HMAC key is provisioned. Real
    deployments wire the registry via
    :func:`email_triage.secrets.wire_audit_chain_hmac_keys` at lifespan
    startup (web/app.py + CLI bootstrap), but every test that touches
    log_entries would otherwise need to opt-in explicitly.

    Per the consolidated H-02a verdict's "MITIGATION for test-infra
    cost" point: include an explicit test helper rather than letting
    the primitive fall back to SHA-256. This fixture is that explicit
    helper, applied autouse so existing test suites stay green without
    surgery on every fixture.

    Tests that need to verify the D1 fail-closed behavior itself
    (e.g., ``TestH02aFailClosed`` in test_log_chain.py) call
    ``_clear_hmac_keys_for_test()`` inside the test body and then
    expect a RuntimeError. The autouse fixture re-clears after every
    test so the next test sees a clean registry baseline.

    The 32-byte deterministic key is NOT used in production —
    real deployments derive their key via HKDF over a per-install
    random Fernet master. Determinism here is only for test isolation
    (two tests running back-to-back see the same chain key and could
    in principle assert on row-hash bytes if useful).
    """
    from email_triage.db.audit import (
        _clear_hmac_keys_for_test,
        _set_hmac_key_for_test,
    )
    # 32 bytes of "for-testing-only" — repeated label keeps the test
    # key easily identifiable in dumps if anyone greps for it.
    _TEST_HMAC_KEY = b"H-02a-test-key-32-bytes-32bytes!"
    assert len(_TEST_HMAC_KEY) == 32
    _set_hmac_key_for_test(_TEST_HMAC_KEY, version=0)
    try:
        yield
    finally:
        _clear_hmac_keys_for_test()


@pytest.fixture(autouse=True)
def _restore_hipaa_mode_around_each_test():
    """Autouse function-scope snapshot+restore of ``triage_logging._hipaa_mode``.

    Bundle E5  — channel-2 contamination closure. ``_hipaa_mode`` is a
    module-global mutated by tests that call
    ``setup_logging(LoggingConfig(hipaa=...))``, by tests that assign the
    attribute directly, and by handlers routed through
    ``_apply_runtime_settings`` with ``allow_hipaa_change=True``. Without
    a per-test save/restore, a test that mutates this leaks the value
    into the next test's baseline; the  caller-intent gate at
    ``web/routers/ui/_shared.py:5472`` SURFACES the leak by raising on
    a cross-test flip.

    Complementary to the ``setup_method`` hooks at
    ``tests/test_actions/test_actions.py:71`` (``TestNotifyAction``) and
    ``:274`` (``TestEscalateAction``): those guard against OUTSIDE
    contamination entering this class's tests; this fixture guards
    against INSIDE contamination leaking out. Both are needed.

    Mirrors the precedent at ``tests/test_web/conftest.py:56-81``
    (``_reset_app_state``, ``_drain_audit_writes_after_test``) — same
    shape: autouse function-scope snapshot+restore for module-global
    cleanup.
    """
    prior = _triage_logging._hipaa_mode
    try:
        yield
    finally:
        _triage_logging._hipaa_mode = prior


@pytest.fixture(autouse=True)
def _restore_triage_log_handlers_around_each_test(monkeypatch):
    """Autouse function-scope snapshot+restore of the ``email_triage`` logger's
    handler list and level.

    Every CLI command calls ``setup_logging``, which clears that logger's
    handlers and adds a ``StreamHandler(sys.stderr)``: under ``capsys`` that is
    the RUNNING test's capture stream, closed when the test ends. A later test
    in the same worker that logs then gets a "--- Logging error ---
    ValueError: I/O operation on closed file" block in ITS stderr (cycle P:
    ``test_cli_audit``'s verify tests failed whenever
    ``test_punch709_emergency_surfaces.py`` ran first). The list is replaced by
    a copy, so ``setup_logging``'s ``clear()`` and ``addHandler`` mutate the
    copy and the original comes back at teardown. Companion of
    ``_restore_hipaa_mode_around_each_test``, the other half of
    ``setup_logging``'s process-global state.
    """
    log = logging.getLogger("email_triage")
    monkeypatch.setattr(log, "handlers", list(log.handlers))
    monkeypatch.setattr(log, "level", log.level)


@pytest.fixture(autouse=True)
def _reset_tick_health_registry():
    """Autouse function-scope reset of ``task_supervisor._tick_health``.

    ``web.task_supervisor._tick_health`` is a MODULE GLOBAL (keyed by loop
    name) that ``supervised_interval_loop`` writes and
    ``TaskSupervisor.health_snapshot()`` reads via
    ``any(th.is_stale() for th in _tick_health.values())`` — it is NOT
    per-supervisor state. The per-test ``tests/test_web/conftest.py`` ``db``
    fixture installs a fresh ``TaskSupervisor()`` (resetting ``self._states``)
    but never touches this global, so a test that starts a supervised loop
    leaves a ``TickHealth`` entry behind. Over a long full-suite run that
    entry's ``last_tick_ts`` ages past its staleness budget, and a LATER
    test's ``/health/detail`` then reads ``any_loop_tick_stale=True`` →
    ``degraded`` → HTTP 503, breaking every test that asserts
    ``status_code == 200`` on the health surface (test_office365_push /
    test_webhook / test_retry_queue_health). These pass alone and only fail
    after the full run — the signature of exactly this leak.

    Snapshot+restore (mirrors ``_restore_hipaa_mode_around_each_test`` and
    the HMAC-key fixture above) so the registry is empty at the start of
    every test and any test-registered entries can't cross the boundary. The
    session app never enters the lifespan, so nothing registers loops at
    session scope; ``prior`` is virtually always empty but is preserved for
    safety.
    """
    from email_triage.web import task_supervisor as _ts
    prior = dict(_ts._tick_health)
    _ts._tick_health.clear()
    try:
        yield
    finally:
        _ts._tick_health.clear()
        _ts._tick_health.update(prior)


@pytest.fixture(autouse=True)
def _close_tracked_test_conns():
    """Autouse teardown — close every test-opened DB connection/store.

    ``internal documentation`` bucket 1 (``ResourceWarning: unclosed
    database``): test fixtures/helpers that funnel through
    ``_db_tracking.tracked_db`` / ``track`` register their connection here, and
    this fixture closes them after each test so GC never has to (which is what
    emitted the warning). One funnel, one teardown — see ``tests/_db_tracking.py``.
    Product code is not a leaker (every ``open_dedicated_conn`` site closes via
    try/finally); this is purely test-fixture hygiene. No-op for tests that open
    nothing through the funnel."""
    from _db_tracking import _close_all
    yield
    _close_all()


@pytest.fixture
def memory_store() -> FlowStore:
    """FlowStore backed by in-memory SQLite (tracked → autouse-closed)."""
    from _db_tracking import track
    return track(FlowStore(":memory:"))


@pytest.fixture
def sample_email() -> EmailMessage:
    return EmailMessage(
        message_id="msg-001",
        provider="gmail_api",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Q3 budget review",
        body_text="Please review the attached budget spreadsheet.",
        date=datetime(2026, 4, 14, 10, 30, tzinfo=timezone.utc),
        labels=["INBOX"],
    )


@pytest.fixture
def sample_classification() -> Classification:
    return Classification(
        category="action-required",
        confidence=0.92,
        reason="Email requests a review action with deadline context.",
    )


# ---------------------------------------------------------------------------
# Cross-worker serialization for the file-DB / audit-global suites
# ---------------------------------------------------------------------------
#
# test_single_flight / test_cli_audit / test_audit_strict_mode / test_request_id
# share a file-backed SQLite DB + the process-global audit chain, so they flake
# when run concurrently across xdist workers (SQLite file-lock contention +
# load-amplified async-audit timing). They carry
# ``pytest.mark.xdist_group("file_db_audit_serial")`` intending to be pinned to
# one worker — but that marker is INERT under ``--dist=loadfile`` (the runner
# mode in scripts/test-fast.sh + test-broad.sh; ``xdist_group`` only takes
# effect under ``--dist=loadgroup``, which would forfeit loadfile's per-file
# isolation for every OTHER suite). That mismatch is why the markers were
# "reported but never fixed". Rather than change the dist mode, we serialize the
# group with a real cross-process ``FileLock`` on the shared xdist tmp root:
# only one ``file_db_audit_serial`` test runs at a time regardless of which
# worker holds it, under any dist mode. No-op on a serial (non-xdist) run.
# See the ``testinfra_full_tree_xdist_flakes`` drawer.


@pytest.fixture
def _file_db_audit_serial_lock(tmp_path_factory, worker_id):
    if worker_id == "master":
        # Serial run (no xdist) — the suites already run one-at-a-time.
        yield
        return
    from filelock import FileLock
    # getbasetemp() is per-worker; ``.parent`` is the ONE session root shared
    # across all xdist workers (the documented pytest-xdist shared-lock idiom).
    lock_path = (
        tmp_path_factory.getbasetemp().parent / "file_db_audit_serial.lock"
    )
    with FileLock(str(lock_path)):
        yield


def pytest_collection_modifyitems(config, items):
    """Auto-apply the cross-worker serial lock to ``file_db_audit_serial`` tests.

    Keyed off the existing ``xdist_group("file_db_audit_serial")`` marker so the
    four suites — and any future suite that joins the group — serialize under
    loadfile with no per-file fixture wiring. The ``xdist_group`` marker is kept
    (harmless under loadfile, still correct under loadgroup).
    """
    for item in items:
        marker = item.get_closest_marker("xdist_group")
        if marker and marker.args and marker.args[0] == "file_db_audit_serial":
            item.add_marker(
                pytest.mark.usefixtures("_file_db_audit_serial_lock")
            )


# ---------------------------------------------------------------------------
# N-151-tail (2026-07-09) — repo-wide autouse fake-Fernet master key.
#
# Post-N-151, ``Office365Provider._save_cache`` REFUSES to write when
# ``_msal_cache_crypto._get_master_key()`` is unavailable. That correctly
# fail-CLOSES production, but breaks any test that drives the real writer
# seam without provisioning a master key. The initial N-151-tail fix put an
# autouse fixture in ``tests/test_providers/conftest.py`` — CI on abb4d359
# then surfaced ``tests/test_web/test_account_delete_purge.py::
# TestPurgeAccountLocalState::test_real_writer_path_equals_purge_path`` red
# because the seam is exercised from ``test_web/`` too. Promoting the
# autouse to the REPO-ROOT conftest is the root-cause fix (per
# feedback_root_cause_scope): every current + future call site that
# exercises ``_save_cache`` gets the fake key without a per-tree opt-in.
#
# ``no_master_key`` marker (DA fold N-151-tail #1) is registered here so
# a test at any level can opt out to exercise the fail-CLOSED refuse-write
# path directly.
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``no_master_key`` opt-out marker for N-151-tail, the guard that keeps
    the sync-Playwright e2e tier out of every other test process (flk; ``_e2e_isolation_guard``),
    and the guard that refuses a connect or DNS lookup to a non-loopback host (t20;
    ``_network_guard``)."""
    _e2e_isolation_guard.register(config)
    _network_guard.register(config)
    config.addinivalue_line(
        "markers",
        "no_master_key: opt out of the autouse fake-master-key fixture "
        "so the test exercises the fail-CLOSED refuse-write path when "
        "`_get_master_key()` is unavailable.",
    )
    config.addinivalue_line(
        "markers",
        "audit_failure_expected(match, count=None, reason=None): the test makes an audit "
        "write fail on purpose. Only the swallowed audit-write stashes whose description "
        "contains `match` (a str or a tuple of str) are excused; with `count`, exactly that "
        "many must match. Any other stashed failure still fails the test (punch 629, panel "
        "F2a r4; `_a_failed_background_task_fails_the_test`).",
    )


@pytest.fixture(autouse=True)
def _n151_msal_master_key_autouse(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch,
):
    """Provide a fake Fernet master key to every test — UNLESS the test
    carries the ``no_master_key`` marker (opt-OUT for tests that
    intentionally exercise the fail-CLOSED refuse-write path).

    Root-cause promotion of the fixture originally at
    ``tests/test_providers/conftest.py``. The test_providers/-scoped
    duplicate remains harmless (its monkeypatch overrides ours with the
    same shape; ``_reset_master_key_cache_for_tests`` is idempotent).
    """
    if request.node.get_closest_marker("no_master_key"):
        yield
        return
    try:
        from cryptography.fernet import Fernet
        from email_triage.providers import _msal_cache_crypto
    except ImportError:
        # cryptography or the provider module isn't installed on this
        # test leg — nothing to patch; let individual tests skip.
        yield
        return

    key = Fernet.generate_key()
    _msal_cache_crypto._reset_master_key_cache_for_tests()
    monkeypatch.setattr(
        _msal_cache_crypto, "_get_master_key", lambda: key,
    )
    try:
        yield
    finally:
        _msal_cache_crypto._reset_master_key_cache_for_tests()


# --- Punch 629 fold (panel F2a r2 item 4, r3 items 1-3): a background task that
# FAILS fails its test, in every app any test builds. --------------------------------
# The app drops a finished task from its registry with
# ``task.add_done_callback(pending.discard)``, and the web drains read only
# ``done()``: a task that raised was gone before any teardown looked, so it could
# never fail a test.

_TASK_REGISTRIES = ("_audit_pending", "_fire_and_forget_pending")


class _FailureRecordingSet(set):
    """A background-task registry that remembers every task that ENDED IN AN EXCEPTION.

    ``discard`` records the failure before dropping the task. ``failures()`` also
    reads a finished task whose discard callback has not run yet (``done()`` turns
    true before the loop runs the callback). A cancelled task is cleanup, not a
    failure."""

    def __init__(self) -> None:
        super().__init__()
        self.failed: list[str] = []

    @staticmethod
    def _failure(task) -> str | None:
        if not hasattr(task, "done") or not task.done() or task.cancelled():
            return None
        exc = task.exception()
        if exc is None:
            return None
        return f"{task.get_name()}: {type(exc).__name__}: {exc}"

    def discard(self, task) -> None:
        failure = self._failure(task)
        if failure:
            self.failed.append(failure)
        super().discard(task)

    def failures(self) -> list[str]:
        return self.failed + [f for t in list(self) if (f := self._failure(t))]

    def unfinished(self) -> list[str]:
        """Registered tasks that have not finished (punch 636 R-b). A task that is
        not done is not cancelled either: ``cancelled()`` implies ``done()``."""
        return [t.get_name() for t in list(self) if hasattr(t, "done") and not t.done()]


# The previous test's recorders and how many failures its teardown read: a LAGGING
# task (it ends after that teardown) is read at the next test's setup (panel F2a r4 db F1).
_PRIOR_RECORDERS: list[tuple[str, _FailureRecordingSet, int]] = []
# The previous test's audit_failure_expected keys: its own EXPECTED write may lag past
# its teardown too, and is excused here rather than failing an innocent next test
# (panel F2a r5 devils-advocate (4), the fail-closed flake edge).
_PRIOR_KEYS: list[str] = []
# Every audit stash made BETWEEN tests (punch 636 R-a, panel F2a r6 devils-advocate).
# The session fixture installs a recording setter for the whole session; while a test
# runs, its own recorder sits on top and this list stays out of it. So between one
# teardown and the next setup, this list holds every stash, not just the last one
# ``_LAST_AUDIT_EXC`` keeps: an unexpected lagged failure followed by the prior test's
# expected one is no longer reduced to the expected one.
_SESSION_STASHES: list[tuple[BaseException, str]] = []


def _late_failures(prior, last, cancelled, keys=(), gap=()) -> list[str]:
    """Failures that landed after their test's teardown: new entries in a prior
    recorder, every non-cancellation stash made between the tests (``gap``), and a
    non-cancellation exception on the audit stash, which every teardown leaves
    empty; each unless the prior test's marker names its description."""
    out = [f"{name}: {f}" for name, rec, seen in prior for f in rec.failures()[seen:]]
    out += [f"_audit stash between tests ({where}): {type(exc).__name__}: {exc}"
            for exc, where in gap
            if not isinstance(exc, cancelled) and not any(k in where for k in keys)]
    if (last is not None and not isinstance(last[0], cancelled)
            and not any(k in last[1] for k in keys)
            and not any(last[0] is exc for exc, _ in gap)):
        out.append(f"_audit._LAST_AUDIT_EXC ({last[1]}): {type(last[0]).__name__}: {last[0]}")
    return out


def _session_end_check(prior=None, keys=None, gap=None) -> None:
    """The lagging-task read, once more after the LAST test (devils-advocate r5 (4)):
    without it, a failure landing after the last teardown on a worker is never read.
    A task still UNFINISHED here fails too (punch 636 R-b): it never ended, so
    neither its write nor its loss record happened, and no later read exists."""
    import asyncio

    from email_triage.web import _audit

    prior = _PRIOR_RECORDERS if prior is None else prior
    cancelled = (asyncio.CancelledError, _audit._AsyncCancelledMarker)
    late = _late_failures(prior, _audit.get_last_audit_exc(), cancelled,
                          tuple(_PRIOR_KEYS) if keys is None else keys,
                          list(_SESSION_STASHES) if gap is None else gap)
    unfinished = [f"{name}: {task}" for name, rec, _seen in prior for task in rec.unfinished()]
    message = []
    if late:
        message.append("a background task FAILED after the LAST test's teardown on this "
                       "worker (a lagging task):\n  " + "\n  ".join(late))
    if unfinished:
        message.append("a background task was unfinished at session end (it never "
                       "completed, so its write and its loss record never happened):\n  "
                       + "\n  ".join(unfinished))
    if message:
        pytest.fail("\n".join(message), pytrace=False)


@pytest.fixture(scope="session", autouse=True)
def _a_lagging_background_failure_fails_the_session():
    """Session-scoped, so its teardown runs inside the last test's teardown and the
    error is reported against that test on every worker. A pytest_sessionfinish
    exit status does not cross xdist; a teardown error does.

    It also installs the session's recording stash setter (punch 636 R-a): every
    stash made while no test's own recorder is installed lands in
    ``_SESSION_STASHES``, which the next setup (or the check below) reads."""
    from email_triage.web import _audit

    raw = _audit._stash_last_audit_exc

    def _session_stash(exc, description):
        _SESSION_STASHES.append((exc, description))
        raw(exc, description)

    _session_stash.raw = raw
    patcher = pytest.MonkeyPatch()
    patcher.setattr(_audit, "_stash_last_audit_exc", _session_stash)
    try:
        yield
        _session_end_check()
    finally:
        patcher.undo()


def _audit_marker_keys(marker) -> tuple[str, ...]:
    match = marker.kwargs.get("match") if marker is not None else None
    if not match:
        return ()
    return (match,) if isinstance(match, str) else tuple(match)


@pytest.fixture(autouse=True)
def _a_failed_background_task_fails_the_test(request, monkeypatch):
    """Install a failure-recording registry wherever the app CREATES one, and fail
    the test if any registered task raised.

    * ``app.state`` registries (``_audit_pending``, ``_fire_and_forget_pending``):
      the app reads each with ``getattr(app.state, name, None)`` and makes a plain
      set when that is None (access_audit.py, app.py, routers/ui/embedding_install.py).
      While a test runs, a MISSING one on any Starlette ``State`` reads as a fresh
      recorder, so every app a test builds adopts one. A test that assigns its own
      registry opts that registry out.
    * ``routers/backup.py`` ``_BACKUP_BG_TASKS``, the module-level registry of the
      PHI-backup path, is swapped for a recorder.
    * The swallowed audit-write stash must hold no failure at teardown: a failed
      audit write converts its exception into that stash, so it is the task-failure
      signal for the audit class. ``_audit._LAST_AUDIT_EXC`` keeps the LAST exception
      only, so the setter ``_audit._stash_last_audit_exc`` (every writer resolves it
      at call time) is wrapped to record EVERY stash: a failure followed by a
      cancellation in one test is still seen. ``audit_failure_expected(match=...)``
      excuses only the stashes whose description contains ``match`` (with
      ``count``, exactly that many); a marker without ``match`` fails the test.
    * A failure that lands AFTER its test's teardown (a lagging task) fails the next
      test's setup: the prior recorders and EVERY stash made between the tests (the
      session fixture's recorder, punch 636 R-a) are read there, and a lagged write
      the prior test's own marker names is excused. After the last test, the session
      fixture ``_a_lagging_background_failure_fails_the_session`` reads them once
      more, and also fails on a registered task still unfinished (punch 636 R-b).
    * A cancellation (``CancelledError``, the audit module's ``_AsyncCancelledMarker``)
      is not a failure here, the same rule as the registries. An audit write lost by
      CANCELLATION is the production loss recorder's to record (punch 582/636); a
      stop that cancels one is proven to record it by
      ``tests/test_636_shutdown_last_close.py``.

    Root-level, so it is set up before, and torn down after, every directory
    conftest's drains (tests/test_web/conftest.py)."""
    import asyncio

    from starlette.datastructures import State

    from email_triage.web import _audit
    from email_triage.web.routers import backup as _backup

    cancelled = (asyncio.CancelledError, _audit._AsyncCancelledMarker)
    gap = list(_SESSION_STASHES)
    _SESSION_STASHES.clear()
    late = _late_failures(_PRIOR_RECORDERS, _audit.get_last_audit_exc(), cancelled,
                          tuple(_PRIOR_KEYS), gap)
    _PRIOR_RECORDERS.clear()
    _PRIOR_KEYS.clear()
    _audit.clear_last_audit_exc()
    if late:
        pytest.fail(
            "a background task of an EARLIER test failed after that test's teardown "
            "(a lagging task; it is reported here because no test was running):\n  "
            + "\n  ".join(late),
            pytrace=False,
        )

    recorders: list[tuple[str, _FailureRecordingSet]] = []
    original_getattr = State.__getattr__

    def _getattr(self, key):
        try:
            return original_getattr(self, key)
        except AttributeError:
            if key not in _TASK_REGISTRIES:
                raise
            recorder = _FailureRecordingSet()
            self._state[key] = recorder
            recorders.append((key, recorder))
            return recorder

    monkeypatch.setattr(State, "__getattr__", _getattr)
    backup_recorder = _FailureRecordingSet()
    monkeypatch.setattr(_backup, "_BACKUP_BG_TASKS", backup_recorder)
    recorders.append(("backup._BACKUP_BG_TASKS", backup_recorder))

    # The setter in place when no test runs: the session's recorder (punch 636 R-a),
    # restored at teardown. This test's recorder writes past it to the raw setter, so
    # ``_SESSION_STASHES`` holds only what lands BETWEEN tests.
    original_stash = _audit._stash_last_audit_exc
    raw_stash = getattr(original_stash, "raw", original_stash)

    def _recording_stash(exc, description):
        _recording_stash.stashed.append((exc, description))
        raw_stash(exc, description)

    def _stash_failures(marker=None) -> list[str]:
        entries = [("_audit stash", exc, where)
                   for exc, where in _recording_stash.stashed if not isinstance(exc, cancelled)]
        last = _audit.get_last_audit_exc()  # a direct assignment bypasses the setter
        if (last is not None and not isinstance(last[0], cancelled)
                and not any(last[0] is exc for exc, _ in _recording_stash.stashed)):
            entries.append(("_audit._LAST_AUDIT_EXC", last[0], last[1]))
        out = []
        if marker is not None:
            keys = _audit_marker_keys(marker)
            if not keys:
                return ["`audit_failure_expected` needs match= (a substring of the stash "
                        "description), so it excuses only the expected write; this test "
                        f"stashed: {[where for _, _, where in entries]}"]
            hit = [e for e in entries if any(k in e[2] for k in keys)]
            entries = [e for e in entries if not any(e is h for h in hit)]
            count = marker.kwargs.get("count")
            if count is not None and len(hit) != count:
                out.append(f"`audit_failure_expected(count={count})` matched {len(hit)} "
                           f"stash(es): {[where for _, _, where in hit]}")
        return [f"{label} ({where}): {type(exc).__name__}: {exc}"
                for label, exc, where in entries] + out

    _recording_stash.stashed = []
    _recording_stash.failures = _stash_failures
    _recording_stash.late_failures = (
        lambda prior, last=None, keys=(), gap=(): _late_failures(prior, last, cancelled, keys, gap))
    _recording_stash.session_end_check = _session_end_check
    _recording_stash.between_tests = original_stash
    _recording_stash.session_stashes = _SESSION_STASHES
    monkeypatch.setattr(_audit, "_stash_last_audit_exc", _recording_stash)
    yield recorders
    failed = [f"{name}: {f}" for name, recorder in recorders for f in recorder.failures()]
    marker = request.node.get_closest_marker("audit_failure_expected")
    failed += _stash_failures(marker)
    _audit.clear_last_audit_exc()
    _SESSION_STASHES.clear()  # the gap starts here
    _PRIOR_RECORDERS[:] = [(name, rec, len(rec.failures())) for name, rec in recorders]
    _PRIOR_KEYS[:] = _audit_marker_keys(marker)
    if failed:
        pytest.fail(
            "a background task FAILED during this test, and its exception would otherwise "
            "be dropped with the task (mark a deliberate audit-write failure "
            "`audit_failure_expected`):\n  " + "\n  ".join(failed),
            pytrace=False,
        )
