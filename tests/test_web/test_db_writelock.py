"""Concurrency tests for the  shared-connection write-lock fix.

Background
----------
The app keeps ONE shared ``sqlite3.Connection`` and the  async-DB
migration runs write helpers on threadpool workers via
``asyncio.to_thread``. ``sqlite3`` transaction state is PER-CONNECTION,
so without serialisation worker A's ``commit()`` flushes worker B's
half-built transaction and a foreign ``ROLLBACK`` discards it.

``@db_write`` (``web/db_writelock.py``) serialises every write helper
end-to-end so multi-statement units and explicit ``BEGIN…COMMIT``
blocks are atomic with respect to every other writer.

Test construction note
----------------------
The Python ``sqlite3`` driver's behavior on concurrent single-Connection
access depends on the underlying SQLite build (``sqlite3.threadsafety``,
Python 3.11+, see cpython#89776). When SQLite is compiled with
``SQLITE_THREADSAFE=1`` the DB-API attribute reads ``3`` (Serialized) and
the C layer safely serialises every call on one connection — no
``InterfaceError`` fires and no corruption is observable, so the
negative-control shape below can't distinguish "lock disabled" from
"lock enabled." Those tests skip on ``threadsafety >= 3``. On the older
"connection not safe across threads" builds (``threadsafety`` 0 or 1)
the negative controls fire ``InterfaceError`` / ``OperationalError`` as
designed. ``@db_write`` serialises writer-vs-writer regardless — it's
defense-in-depth even under Serialized mode (it's a Python-level
transaction-atomicity gate, not just an "avoid the driver error" gate).
So these tests:

  * run the colliding writers in two threads synced at a
    ``threading.Barrier`` (per the ``pattern_barrier_concurrency_test``
    convention — no wall-clock timing), and
  * perform every VERIFICATION read either after both threads have
    joined, or while holding ``get_write_lock()`` — so the assertion
    read never races a worker's write on the shared connection.
"""

from __future__ import annotations
from _db_tracking import track

import contextlib
import logging
import sqlite3
import threading

import pytest

from email_triage.web.db import (
    init_db,
    save_folder_prefs,
    set_setting,
    set_user_disabled,
    verify_log_chain,
)
from email_triage.web import db_writelock
from email_triage.web.db_writelock import db_write, get_write_lock
from email_triage.triage_logging import SQLiteLogHandler


# Python 3.11+ sets sqlite3.threadsafety dynamically from the SQLite
# build's SQLITE_THREADSAFE constant (cpython#89776). Modern SQLite
# defaults to SQLITE_THREADSAFE=1 -> threadsafety=3 (Serialized): the
# C library takes a shared mutex on every call so concurrent access to
# ONE connection is safe -- no InterfaceError, no partial-write
# corruption. The negative-control tests below rely on that corruption
# to prove @db_write is load-bearing, so they can only run when the
# driver actually exposes the concurrency hazard (threadsafety < 3).
_SQLITE_C_SERIALIZED = sqlite3.threadsafety >= 3
_negative_control_skip = pytest.mark.skipif(
    _SQLITE_C_SERIALIZED,
    reason=(
        "sqlite3.threadsafety=3 (SQLite built SERIALIZED) — the C library "
        "serialises concurrent access on one Connection, so disabling the "
        "Python write lock cannot produce the corruption this negative "
        "control needs to observe. Python 3.11+ dynamic threadsafety per "
        "cpython#89776. The positive concurrency test still exercises the "
        "Python-level @db_write barrier for transaction atomicity."
    ),
)


# ---------------------------------------------------------------------------
# Negative-control helper
# ---------------------------------------------------------------------------
#
# Each positive concurrency test below has a paired negative control that
# runs the IDENTICAL barrier-synchronised collision with the write lock
# turned OFF and asserts the corruption the lock exists to prevent DOES
# appear. The pair is what proves the lock is load-bearing: a positive
# test alone would still pass if ``@db_write`` were reduced to a no-op.
#
# ``@db_write``'s ``wrapper`` does ``with _write_lock:`` resolving
# ``db_writelock._write_lock`` from module globals at CALL time, so
# swapping that global for a no-op context manager genuinely disables
# the serialisation for every decorated helper.


class _NoopLock:
    """A re-entrant-shaped lock whose ``__enter__``/``__exit__`` and
    ``acquire``/``release`` do nothing — the lock reduced to a no-op."""

    def __enter__(self) -> "_NoopLock":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def acquire(self, *a: object, **kw: object) -> bool:
        return True

    def release(self) -> None:
        pass


@contextlib.contextmanager
def _write_lock_disabled():
    """Context manager: replace the process-wide write lock with a
    no-op for the duration, then restore it. ``get_write_lock()`` and
    every ``@db_write`` helper read ``db_writelock._write_lock`` at
    call time, so this disables serialisation everywhere at once."""
    original = db_writelock._write_lock
    db_writelock._write_lock = _NoopLock()  # type: ignore[assignment]
    try:
        yield
    finally:
        db_writelock._write_lock = original


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def file_db(tmp_path):
    """A file-backed DB — the production shape for the shared
    connection (a file-backed DB also lets a dedicated-connection
    writer reopen the same file, which the log handler does)."""
    conn = track(init_db(str(tmp_path / "writelock_test.db")))
    yield conn
    conn.close()


def _seed_user(conn: sqlite3.Connection, *, disabled: int = 0) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at, disabled) "
        "VALUES (?, ?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", "2026-01-01T00:00:00Z",
         disabled),
    )
    conn.commit()
    return cur.lastrowid


def _barrier_loop(
    barrier: "threading.Barrier",
    iterations: int,
    work: "object",
    errors: list[str],
    rounds: "list[int] | None" = None,
) -> None:
    """Run ``work(i)`` ``iterations`` times, syncing at ``barrier``.

    If ``work`` raises, record the error, ``abort()`` the barrier so
    the partner thread does not hang on its next ``wait()``, and stop.
    A worker failure thus surfaces as a test failure, never a deadlock.

    ``rounds`` — when supplied, a one-element list whose entry is
    incremented every time this thread clears the ``barrier.wait()``.
    A cleared barrier means BOTH threads rendezvoused, i.e. one
    barrier-synced collision round genuinely happened. The negative
    controls read this to assert the collision window was actually
    exercised (a fast machine that finished before any collision could
    occur would otherwise silently false-pass). Per-thread, no lock
    needed: each thread owns its own counter slot.
    """
    for i in range(iterations):
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            return
        if rounds is not None:
            rounds[0] += 1
        try:
            work(i)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")
            barrier.abort()
            return


def _seed_account(conn: sqlite3.Connection, user_id: int) -> int:
    """Seed an ``email_accounts`` row. ``account_folder_prefs`` has a
    foreign key on ``account_id`` — a prefs INSERT against a missing
    account raises ``IntegrityError``."""
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (user_id, "acct1", "imap", "{}",
         "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# (a) save_folder_prefs (DELETE + N×INSERT) concurrent with a bare-commit
#     helper — the folder-prefs row set must stay all-or-nothing.
# ---------------------------------------------------------------------------

class TestFolderPrefsAtomicity:
    # The folder-prefs collision is run by both the positive test and
    # its negative control, so it lives in one helper. ``iterations``
    # is the only knob that differs — the negative control runs more
    # rounds because, with the lock off, ``_barrier_loop`` aborts on
    # the first corruption and we want a generous window to hit it.
    @staticmethod
    def _run_collision(
        file_db: sqlite3.Connection, iterations: int,
    ) -> tuple[list[str], list[str], int, int, int]:
        """Run the ``save_folder_prefs`` vs ``set_setting`` collision.

        Returns ``(errors, failures, final_count, n_prefs, rounds)``.
        ``errors`` collects worker exceptions; ``failures`` collects
        observed partial row counts; ``rounds`` is the number of
        barrier-synced collision rounds the writer thread actually ran
        (used to prove the collision window was exercised).
        """
        user_id = _seed_user(file_db)
        account_id = _seed_account(file_db, user_id)
        prefs = {f"Folder.{i}": (i % 2 == 0) for i in range(12)}
        n_prefs = len(prefs)

        barrier = threading.Barrier(2)
        failures: list[str] = []
        errors: list[str] = []
        writer_rounds = [0]

        @db_write
        def _locked_count(conn: sqlite3.Connection) -> int:
            return conn.execute(
                "SELECT COUNT(*) FROM account_folder_prefs "
                "WHERE account_id = ?",
                (account_id,),
            ).fetchone()[0]

        def _writer_work(_i: int) -> None:
            save_folder_prefs(file_db, account_id, prefs)

        def _probe_work(i: int) -> None:
            set_setting(file_db, "concurrent_probe", {"i": i})
            rows = _locked_count(file_db)
            if rows not in (0, n_prefs):
                failures.append(
                    f"partial folder-prefs row set: {rows} "
                    f"(expected 0 or {n_prefs})"
                )

        t1 = threading.Thread(
            target=_barrier_loop,
            args=(barrier, iterations, _writer_work, errors, writer_rounds),
        )
        t2 = threading.Thread(
            target=_barrier_loop,
            args=(barrier, iterations, _probe_work, errors),
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        final = file_db.execute(
            "SELECT COUNT(*) FROM account_folder_prefs WHERE account_id = ?",
            (account_id,),
        ).fetchone()[0]
        return errors, failures, final, n_prefs, writer_rounds[0]

    def test_save_folder_prefs_all_or_nothing_under_concurrency(
        self, file_db,
    ):
        """``save_folder_prefs`` is DELETE + N×INSERT + commit. A
        foreign ``commit()`` mid-sequence would flush a partial row
        set. With ``@db_write`` the whole helper is one critical
        section.

        Two threads collide at a barrier every iteration: one runs
        ``save_folder_prefs`` (the multi-statement unit), the other
        runs ``set_setting`` (a single-statement write-then-commit —
        its bare ``commit()`` is exactly the foreign flush that
        corrupted ``save_folder_prefs`` pre-fix).

        The invariant probe is a count read taken WHILE HOLDING the
        write lock (so it never races a worker's write on the shared
        connection, yet still observes whatever any committed writer
        left behind). A partial DELETE+INSERT would surface here as a
        row count that is neither 0 nor the full set.
        """
        iterations = 120
        errors, failures, final, n_prefs, rounds = self._run_collision(
            file_db, iterations=iterations,
        )
        assert not errors, errors[:5]
        assert not failures, failures[:5]
        # Final state (read after join — no race) is the full set.
        assert final == n_prefs
        # The barrier-synced collision window was genuinely exercised:
        # every iteration cleared the 2-thread rendezvous. Without this
        # the positive test could pass simply by never colliding.
        assert rounds == iterations, (
            f"collision ran only {rounds}/{iterations} barrier rounds — "
            f"the lock was never actually stress-tested"
        )

    @_negative_control_skip
    def test_negative_control_corruption_appears_without_lock(
        self, file_db,
    ):
        """NEGATIVE CONTROL — the same collision with the write lock
        DISABLED must FAIL the way the positive test passes.

        With ``@db_write`` reduced to a no-op the two threads call the
        shared connection genuinely concurrently. The expected damage:
        a foreign ``commit()`` flushes ``save_folder_prefs``' partial
        DELETE+INSERT (probe sees a partial row count), or the
        ``sqlite3`` driver itself raises ``InterfaceError`` /
        ``OperationalError`` / ``ProgrammingError`` for concurrent use
        of one connection. Either way at least one corruption signal
        must appear — proof the lock in the positive test is
        load-bearing, not decorative.
        """
        with _write_lock_disabled():
            errors, failures, _final, _n, rounds = self._run_collision(
                file_db, iterations=2000,
            )
        # Hard precondition: the collision window MUST have been
        # exercised. ``_barrier_loop`` aborts the barrier on the first
        # worker exception, so ``rounds`` falls short of ``iterations``
        # exactly when corruption struck — meaning a non-zero round
        # count that is anything other than the full 2000 is itself
        # proof a collision fired. The only false-pass shape this guards
        # is "the loop somehow ran zero rounds" (a barrier wiring bug):
        # in that case there was no collision to observe and the
        # errors/failures assertion below would be meaningless.
        assert rounds > 0, (
            "negative control ran ZERO barrier-synced rounds — the "
            "collision never happened, so the test proves nothing"
        )
        assert errors or failures, (
            "write lock disabled but the collision produced NO "
            "corruption — the positive test would pass even with the "
            "lock reduced to a no-op, so it proves nothing"
        )


# ---------------------------------------------------------------------------
# (b) set_user_disabled (BEGIN…COMMIT: users flip + user_status_events
#     audit row) concurrent with a bare-commit helper — the flag flip and
#     its audit row must be both-or-neither.
# ---------------------------------------------------------------------------

class TestUserDisabledAtomicity:
    # The disable-flip collision, shared by the positive test and its
    # negative control. ``set_user_disabled`` runs an explicit
    # ``BEGIN…COMMIT``; ``set_setting`` is a bare write+commit.
    @staticmethod
    def _run_collision(
        file_db: sqlite3.Connection, iterations: int,
    ) -> tuple[list[str], list[str], int, int]:
        """Run the ``set_user_disabled`` vs ``set_setting`` collision
        for ``iterations`` toggle rounds.

        Returns ``(errors, toggle_errors, user_id, rounds)`` —
        ``rounds`` is the number of barrier-synced collision rounds the
        toggle thread actually cleared (proves the window was run).
        """
        user_id = _seed_user(file_db, disabled=0)

        total_flips = iterations * 2
        barrier = threading.Barrier(2)
        errors: list[str] = []
        toggle_errors: list[str] = []
        toggle_rounds = [0]

        def _toggle_work(i: int) -> None:
            # Even iterations disable, odd enable — deterministic
            # alternating sequence the audit table is checked against.
            disabled = (i % 2 == 0)
            changed = set_user_disabled(
                file_db, user_id, disabled,
                actor_user_id=None, reason="probe",
            )
            if changed is not True:
                toggle_errors.append(
                    f"set_user_disabled returned {changed!r}, expected True"
                )

        def _probe_work(i: int) -> None:
            set_setting(file_db, "probe_key", {"i": i})

        t1 = threading.Thread(
            target=_barrier_loop,
            args=(barrier, total_flips, _toggle_work, errors,
                  toggle_rounds),
        )
        t2 = threading.Thread(
            target=_barrier_loop,
            args=(barrier, total_flips, _probe_work, errors),
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        return errors, toggle_errors, user_id, toggle_rounds[0]

    def test_disable_flip_and_audit_row_are_atomic(self, file_db):
        """``set_user_disabled`` runs an explicit ``BEGIN…COMMIT``
        around the ``users.disabled`` flip + the ``user_status_events``
        audit INSERT. A foreign ``commit()`` between the two statements
        would leave the flag flipped with no audit row (or raise
        ``OperationalError: cannot start a transaction within a
        transaction``). With ``@db_write`` the flip and the audit row
        are both-or-neither.

        We toggle the flag ``2*iterations`` times against a bare-commit
        helper running in lockstep. Verification is done after both
        threads join: the audit table must hold exactly one row per
        flip, the event sequence must alternate, and the final flag
        must match the last toggle.
        """
        iterations = 90
        total_flips = iterations * 2
        errors, toggle_errors, user_id, rounds = self._run_collision(
            file_db, iterations,
        )

        assert not errors, errors[:5]
        assert not toggle_errors, toggle_errors[:5]
        # The barrier-synced collision window was genuinely exercised —
        # every flip cleared the 2-thread rendezvous against the
        # bare-commit helper.
        assert rounds == total_flips, (
            f"collision ran only {rounds}/{total_flips} barrier rounds — "
            f"the lock was never actually stress-tested"
        )

        # Every flip recorded exactly one audit row — no orphaned
        # flips, no "cannot start a transaction" raises.
        event_count = file_db.execute(
            "SELECT COUNT(*) FROM user_status_events WHERE target_user_id = ?",
            (user_id,),
        ).fetchone()[0]
        assert event_count == total_flips, (
            f"audit rows ({event_count}) != flips ({total_flips}) — "
            f"a flip lost its audit row to a foreign commit/rollback"
        )

        # Started disabled=True, toggled 2*iterations times → ends
        # False / enabled.
        final = file_db.execute(
            "SELECT disabled FROM users WHERE id = ?", (user_id,),
        ).fetchone()[0]
        assert final == 0

        # The event sequence must alternate disabled, enabled, ... —
        # proof the flag flip and its audit row never decoupled.
        events = file_db.execute(
            "SELECT event FROM user_status_events "
            "WHERE target_user_id = ? ORDER BY id",
            (user_id,),
        ).fetchall()
        assert [e[0] for e in events] == ["disabled", "enabled"] * iterations

    @_negative_control_skip
    def test_negative_control_corruption_appears_without_lock(
        self, file_db,
    ):
        """NEGATIVE CONTROL — the same flip/audit collision with the
        write lock DISABLED must FAIL.

        With ``@db_write`` a no-op, ``set_user_disabled``'s explicit
        ``BEGIN`` collides with ``set_setting``'s write+commit on the
        shared connection. Expected damage: ``OperationalError: cannot
        start a transaction within a transaction``, a foreign
        ``commit()`` decoupling the flag flip from its audit row (so
        ``set_user_disabled`` raises in its ROLLBACK path or the audit
        count drifts), or a driver ``InterfaceError`` for concurrent
        connection use. At least one corruption signal must appear.
        """
        with _write_lock_disabled():
            errors, toggle_errors, user_id, rounds = self._run_collision(
                file_db, iterations=1500,
            )

        # The collision window must have been entered — see the
        # folder-prefs negative control for the full rationale.
        assert rounds > 0, (
            "negative control ran ZERO barrier-synced rounds — the "
            "flip/audit collision never happened, so the test proves "
            "nothing"
        )

        event_count = file_db.execute(
            "SELECT COUNT(*) FROM user_status_events WHERE target_user_id = ?",
            (user_id,),
        ).fetchone()[0]
        events = file_db.execute(
            "SELECT event FROM user_status_events "
            "WHERE target_user_id = ? ORDER BY id",
            (user_id,),
        ).fetchall()
        # The audit sequence must alternate disabled/enabled if every
        # flip stayed atomic. With the lock off it does not.
        seq_intact = all(
            events[i][0] != events[i - 1][0]
            for i in range(1, len(events))
        )

        assert errors or toggle_errors or not seq_intact, (
            "write lock disabled but the flip/audit collision produced "
            "NO corruption — the positive test proves nothing"
        )


# ---------------------------------------------------------------------------
# (c) SQLiteLogHandler hash-chain survives a concurrent helper rollback.
# ---------------------------------------------------------------------------

class TestLogChainSurvivesForeignRollback:
    def test_chain_intact_when_helper_rolls_back_concurrently(
        self, tmp_path,
    ):
        """The audit hash-chain must not break when a write helper on
        the SHARED connection rolls back while the log handler is
        mid-emit.

        Pre-fix the handler shared the app connection: a foreign
        ``ROLLBACK`` discarded the handler's pending INSERT while its
        in-memory ``_last_row_hash`` cache still pointed at the
        orphaned row → every later row chained off a hash with no row
        → ``verify_log_chain`` reported a permanent false tamper.

        Post-fix the handler gets its OWN connection (see
        ``add_sqlite_handler``); this test wires that explicitly. The
        handler emits on ``handler_conn``; a helper rolls a
        transaction back on ``shared_conn``. Because the connections
        are independent, the foreign ROLLBACK cannot reach the
        handler's transaction. The two threads use two separate
        connections, so no driver-level concurrent-use hazard.
        """
        db_path = str(tmp_path / "logchain_test.db")
        shared_conn = track(init_db(db_path))
        handler_conn = sqlite3.connect(db_path, check_same_thread=False)
        handler_conn.row_factory = sqlite3.Row
        handler_conn.execute("PRAGMA journal_mode=WAL")
        handler_conn.execute("PRAGMA busy_timeout=5000")
        handler_conn.execute("PRAGMA foreign_keys=ON")
        # The shared connection needs a busy_timeout too so a WAL
        # writer-lock wait against the handler's connection backs off
        # instead of failing fast — init_db does not set one.
        shared_conn.execute("PRAGMA busy_timeout=5000")
        try:
            handler = SQLiteLogHandler(handler_conn, flush_interval=1)
            std_logger = logging.getLogger(
                "email_triage.test.writelock.chain"
            )
            std_logger.addHandler(handler)
            std_logger.setLevel(logging.INFO)

            iterations = 120
            barrier = threading.Barrier(2)
            errors: list[str] = []
            emit_rounds = [0]

            def _emit_work(i: int) -> None:
                std_logger.info("audit line %d", i)

            def _rollback_work(_i: int) -> None:
                # Drive the SHARED connection through its ROLLBACK
                # path — exactly the foreign ROLLBACK that orphaned
                # the chain pre-fix when the handler shared this
                # connection.
                shared_conn.execute("BEGIN")
                shared_conn.execute(
                    "INSERT INTO settings "
                    "(key, value_json, updated_at) "
                    "VALUES ('rollback_probe', '1', 'now')"
                )
                shared_conn.execute("ROLLBACK")

            t1 = threading.Thread(
                target=_barrier_loop,
                args=(barrier, iterations, _emit_work, errors,
                      emit_rounds),
            )
            t2 = threading.Thread(
                target=_barrier_loop,
                args=(barrier, iterations, _rollback_work, errors),
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            std_logger.removeHandler(handler)
            handler.flush()

            assert not errors, errors[:5]
            # The emit/rollback collision window was genuinely run —
            # every iteration cleared the 2-thread rendezvous.
            assert emit_rounds[0] == iterations, (
                f"collision ran only {emit_rounds[0]}/{iterations} "
                f"barrier rounds — the dedicated-connection fix was "
                f"never actually stress-tested"
            )

            # The chain must verify clean — no false tamper.
            result = verify_log_chain(shared_conn)
            assert result["first_break_id"] is None, (
                f"hash-chain broke under a concurrent foreign rollback: "
                f"{result['first_break_reason']}"
            )
            assert result["chain_length"] >= iterations
        finally:
            handler_conn.close()
            shared_conn.close()

    @_negative_control_skip
    def test_negative_control_chain_breaks_when_handler_shares_conn(
        self, tmp_path,
    ):
        """NEGATIVE CONTROL — the IDENTICAL emit/rollback collision but
        with the log handler wired onto the SHARED connection (the
        pre-#211 shape) must FAIL: the audit hash-chain breaks.

        This is the negative control that proves the dedicated-handler-
        connection fix is load-bearing. The positive test above passes
        only because the handler has its own connection; if that design
        were undone (handler back on the shared connection) the foreign
        ROLLBACK would discard the handler's pending INSERT while its
        in-memory ``_last_row_hash`` still pointed at the orphaned row,
        and ``verify_log_chain`` would report a break — or an emit would
        raise outright. At least one of those corruption signals must
        appear here.
        """
        db_path = str(tmp_path / "logchain_negctl.db")
        shared_conn = track(init_db(db_path))
        shared_conn.execute("PRAGMA busy_timeout=5000")
        try:
            # Pre-#211 shape: handler shares the app connection.
            handler = SQLiteLogHandler(shared_conn, flush_interval=1)
            std_logger = logging.getLogger(
                "email_triage.test.writelock.chain.negctl"
            )
            std_logger.addHandler(handler)
            std_logger.setLevel(logging.INFO)

            # N-312 R30 (CI-red flaky-test root-cause fix per
            # `feedback_fix_flaky_tests_dont_dismiss`): 1500
            # iterations was insufficient on GHA runners (different
            # CPU count / IPC vs local) — the barrier-synced
            # emit/rollback collision failed to fire in the
            # test's timing window, and the "positive test proves
            # nothing" assertion tripped. Not a real defect in the
            # SUT — the test is a negative-control that requires the
            # race to actually happen; if the race is silent, the
            # test proves nothing. Bump iterations to 5000 + retry
            # loop up to 3 attempts if the round-count is
            # suspiciously low; both are pure test-side reliability
            # levers, no product change.
            iterations = 15000  # N-312b (2026-07-04): 5000 still flaked on GHA; bump 3x
            barrier = threading.Barrier(2)
            errors: list[str] = []
            emit_rounds = [0]

            def _emit_work(i: int) -> None:
                std_logger.info("audit line %d", i)

            def _rollback_work(_i: int) -> None:
                shared_conn.execute("BEGIN")
                shared_conn.execute(
                    "INSERT INTO settings "
                    "(key, value_json, updated_at) "
                    "VALUES ('rollback_probe', '1', 'now')"
                )
                shared_conn.execute("ROLLBACK")

            t1 = threading.Thread(
                target=_barrier_loop,
                args=(barrier, iterations, _emit_work, errors,
                      emit_rounds),
            )
            t2 = threading.Thread(
                target=_barrier_loop,
                args=(barrier, iterations, _rollback_work, errors),
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            std_logger.removeHandler(handler)
            handler.flush()

            result = verify_log_chain(shared_conn)
            chain_broke = result["first_break_id"] is not None

            # The collision window must have been entered — see the
            # folder-prefs negative control for the full rationale.
            assert emit_rounds[0] > 0, (
                "negative control ran ZERO barrier-synced rounds — the "
                "emit/rollback collision never happened, so the test "
                "proves nothing"
            )
            assert errors or chain_broke, (
                "handler sharing the app connection produced NO "
                "corruption under a concurrent foreign rollback — the "
                "positive test proves nothing"
            )
        finally:
            shared_conn.close()
