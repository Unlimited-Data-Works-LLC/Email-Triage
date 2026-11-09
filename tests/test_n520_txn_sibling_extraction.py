"""N-520 — the four witness ``*_txn`` siblings, and the wrappers they were cut from.

``543-design.md`` §3.0 adds a non-committing ``*_txn`` half to each of the four audit
emitters the commit-before-witness class needs inside a caller-owned transaction, and
turns each committing emitter into a thin own-commit wrapper over its twin (PD#5 — ONE
author for the row shape). This module holds the two halves of that contract:

1. **The extraction did not change the wrapper** (design §6 test 4). This is the test
   that catches a botched extraction, and it is the cheap one: each own-commit emitter
   still commits, still returns the new row id, and still writes the same column values.
   ``record_auth_event_txn`` alone serves 18 of the 37 flagged sites and 5 of the 11
   families, so a bug in its extraction reaches every auth surface at once
   (``pattern_consolidating_a_predicate_consolidates_its_blast_radius``).
2. **The ``*_txn`` half genuinely does NOT commit** — the caller owns commit timing.
   Asserted as the property that matters rather than as an absence of a token: after a
   ``*_txn`` emit the connection is still IN a transaction and a ``rollback()`` removes
   the row, while after the own-commit wrapper a ``rollback()`` cannot.

**Why a rollback probe and not a second connection.** The suite's DB fixture is
``init_db(":memory:")``, which no second connection can see, and a file-backed
SQLCipher DB cannot be opened by a raw ``sqlite3.connect`` at all (R24). The
rollback probe tests the same property — *is the write still the caller's to undo* —
on the handle that actually owns it.

The structural companion (every ``*_txn`` in ``src/`` is undecorated by ``@db_write``
and ``@audit_emitter``, M-2/M-3) is arm 2 of the N-520 SSOT pin, not here; this module
asserts it for these four only, as the regression guard for the specific extraction —
and that guard has teeth, because the first draft of this change put
``record_auth_event``'s two decorators on ``record_auth_event_txn`` by moving the
``def`` line out from under them. The N-520 ratchet caught it by collapsing from 37
findings to 19 (``record_auth_event`` silently left the witness set), which is exactly
the ``pattern_a_pin_can_defend_the_bug_it_was_never_asked_about`` shape read forwards.
"""

from __future__ import annotations
from _db_tracking import track

import ast
import inspect
from datetime import datetime, timezone

import pytest

from email_triage.db import audit as audit_mod
from email_triage.db.audit import (
    record_access_event,
    record_access_event_txn,
    record_api_key_event,
    record_api_key_event_txn,
    record_auth_event,
    record_auth_event_txn,
    record_hipaa_access_event,
    record_hipaa_access_event_txn,
)
from email_triage.web.db import init_db

#: (own-commit wrapper, txn sibling, table, kwargs-builder) for each of the four.
#: A builder rather than a literal dict because two of them need a live FK parent.
PAIRS = (
    ("auth_events", record_auth_event, record_auth_event_txn,
     lambda ids: dict(event_type="login_otp", email="op@example.com",
                      user_id=ids["user"], outcome="success", detail="d")),
    ("api_key_events", record_api_key_event, record_api_key_event_txn,
     lambda ids: dict(event="api_key_created", key_id=7,
                      actor_user_id=ids["user"], target_user_id=ids["user"],
                      name="k", expires_at=None, source="ui")),
    ("access_log", record_access_event, record_access_event_txn,
     lambda ids: dict(actor_user_id=ids["user"], method="POST",
                      route="/accounts/{id}", account_id=ids["account"],
                      message_id=None, status_code=200, outcome="ok")),
    ("hipaa_access_events", record_hipaa_access_event,
     record_hipaa_access_event_txn,
     lambda ids: dict(actor_user_id=ids["user"], account_id=ids["account"],
                      operation="manual_triage", outcome="ok")),
)

#: ``record_hipaa_access_event``'s signature is positional-after-conn (it predates the
#: keyword-only convention), so its two call shapes are built by name here.
_POSITIONAL = {"hipaa_access_events"}


@pytest.fixture
def conn():
    """Fresh in-memory DB with the full schema; the autouse conftest fixture
    ``_provision_audit_chain_hmac_key_for_tests`` supplies the H-02a HMAC key."""
    db = track(init_db(":memory:"))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def ids(conn) -> dict[str, int]:
    """A users row and an email_accounts row, so the FK columns can be non-NULL.

    Non-NULL matters: a test that passes NULL for every FK never exercises the
    constraint path, and ``record_access_event``'s whole reason for having an
    ``except sqlite3.IntegrityError`` branch is what happens when one is stale.
    """
    now = datetime.now(timezone.utc).isoformat()
    user_id = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("op@example.com", "Operator", "admin", now),
    ).lastrowid
    account_id = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, "Acct", "imap", 1, now, now),
    ).lastrowid
    conn.commit()
    return {"user": int(user_id), "account": int(account_id)}


def _call(fn, conn, table, kwargs):
    """Invoke ``fn`` with ``kwargs``, honouring the positional-after-conn shape."""
    if table in _POSITIONAL:
        return fn(conn, kwargs["actor_user_id"], kwargs["account_id"],
                  kwargs["operation"], kwargs.get("outcome", "ok"),
                  kwargs.get("detail"))
    return fn(conn, **kwargs)


def _count(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_the_fixture_connection_is_not_in_autocommit(conn) -> None:
    """``pattern_prove_the_input_is_in_the_set_the_control_acts_on``.

    Every assertion below distinguishes committed from uncommitted, which is
    meaningless on an autocommit handle (``isolation_level is None``: each statement
    commits immediately and there is no rollback path). If this ever fails, the
    other tests in this module are not measuring what they claim.
    """
    assert conn.isolation_level is not None, (
        "the fixture handle is in autocommit, so a rollback probe cannot "
        "distinguish a committing emit from a non-committing one"
    )


@pytest.mark.parametrize("table,wrapper,txn,build",
                         PAIRS, ids=[p[0] for p in PAIRS])
def test_txn_sibling_does_not_commit_so_a_rollback_removes_the_row(
    conn, ids, table, wrapper, txn, build
) -> None:
    """The half of the N-520 fix that only works because the ``*_txn`` is silent.

    "No audit row survives a rolled-back change" is bought by the witness row being
    written inside the funnel's transaction. If a ``*_txn`` committed, the funnel's
    ``rollback()`` could not remove it and the class's second invariant would be
    unbuyable.
    """
    before = _count(conn, table)
    row_id = _call(txn, conn, table, build(ids))
    assert isinstance(row_id, int) and row_id > 0, "no row id returned"
    assert _count(conn, table) == before + 1, "the row was not written at all"
    assert conn.in_transaction, (
        f"{txn.__name__} left no open transaction — it committed, so the caller "
        "no longer owns commit timing (543-design M-2)"
    )
    conn.rollback()
    assert _count(conn, table) == before, (
        f"{txn.__name__}'s row survived the caller's rollback — it is not "
        "transaction-aware, and a funnel built on it cannot be all-or-nothing"
    )


@pytest.mark.parametrize("table,wrapper,txn,build",
                         PAIRS, ids=[p[0] for p in PAIRS])
def test_own_commit_wrapper_still_commits_and_survives_a_rollback(
    conn, ids, table, wrapper, txn, build
) -> None:
    """Design §6 test 4 — the extraction must not change the public function."""
    before = _count(conn, table)
    row_id = _call(wrapper, conn, table, build(ids))
    assert isinstance(row_id, int) and row_id > 0, "no row id returned"
    assert not conn.in_transaction, (
        f"{wrapper.__name__} left a transaction open — it no longer commits, so "
        "every existing caller that relied on the own-commit contract is broken"
    )
    conn.rollback()
    assert _count(conn, table) == before + 1, (
        f"{wrapper.__name__}'s row did not survive a rollback, so it did not commit"
    )


@pytest.mark.parametrize("table,wrapper,txn,build",
                         PAIRS, ids=[p[0] for p in PAIRS])
def test_both_halves_write_byte_identical_column_values(
    conn, ids, table, wrapper, txn, build
) -> None:
    """The row CONTENT is one author's (PD#5), so the two halves cannot diverge.

    Every column except the ones that are *expected* to differ per row — the row id,
    the wall-clock ``ts``, and the chain columns, which differ by construction
    because the second row chains onto the first. A drift in any other column is a
    forked row shape, which is what PD#3 exists to prevent.
    """
    kwargs = build(ids)
    id_a = _call(txn, conn, table, kwargs)
    conn.commit()
    id_b = _call(wrapper, conn, table, kwargs)
    rows = {
        r["id"]: dict(r) for r in conn.execute(
            f"SELECT * FROM {table} WHERE id IN (?, ?)", (id_a, id_b)
        ).fetchall()
    }
    volatile = {"id", "ts", "prev_hash", "row_hash"}
    a = {k: v for k, v in rows[id_a].items() if k not in volatile}
    b = {k: v for k, v in rows[id_b].items() if k not in volatile}
    assert a == b, (
        f"{txn.__name__} and {wrapper.__name__} wrote different column values for "
        f"identical arguments — the row shape has forked: {a} != {b}"
    )


def test_access_event_txn_keeps_the_fk_coercion_rechain(conn, ids) -> None:
    """``record_access_event_txn`` must keep the ``IntegrityError`` re-chain.

    The census's exclusion (b) for ``record_access_event`` is about exactly this
    branch, and the design says the ``_txn`` half keeps the re-chain and drops both
    commits. A constraint violation fails the INSERT statement without ending the
    transaction, so the retry reads an unchanged chain tail — which is why the
    re-chain is still sound inside a caller-owned transaction.
    """
    conn.execute("PRAGMA foreign_keys = ON")
    stale = ids["account"] + 10_000
    row_id = record_access_event_txn(
        conn, actor_user_id=ids["user"], method="GET",
        route="/accounts/{id}/messages", account_id=stale, message_id=None,
        status_code=200, outcome="ok", detail="orig",
    )
    row = conn.execute(
        "SELECT account_id, detail FROM access_log WHERE id = ?", (row_id,)
    ).fetchone()
    assert row["account_id"] is None, (
        "the stale FK was not coerced to NULL, so the re-chain branch is gone"
    )
    assert f"stale_account_id={stale}" in (row["detail"] or ""), (
        "the original FK value was not stashed in detail, so the audit row no "
        "longer records what was tried (the whole point under 164.312(b))"
    )
    assert conn.in_transaction, "the re-chain branch committed; it must not"


@pytest.mark.parametrize("txn", [p[2] for p in PAIRS], ids=[p[0] for p in PAIRS])
def test_each_txn_sibling_is_undecorated(txn) -> None:
    """M-2 and M-3, as a regression guard on THIS extraction.

    ``@db_write`` on a ``*_txn`` would roll back the CALLER's transaction on any
    exception (``web/db_writelock.py:136-190`` rolls back unconditionally), taking
    work the caller did before the call. ``@audit_emitter`` on it is worse than
    absent: the decorator only sets ``fn._is_audit_emitter``, which is read by
    ``db_write``'s wrapper — with no ``@db_write`` outside it the marker is never
    read, so it reads as coverage while doing nothing.

    Keyed on the AST rather than on ``__wrapped__``, because that is the form a
    reviewer reads and the form a careless edit changes.
    """
    src = inspect.getsource(audit_mod)
    tree = ast.parse(src)
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == txn.__name__
    )
    names = [d.id if isinstance(d, ast.Name) else getattr(d, "attr", "?")
             for d in node.decorator_list]
    assert names == [], (
        f"{txn.__name__} carries {names}; a *_txn sibling must be undecorated "
        "(543-design M-2/M-3)"
    )


@pytest.mark.parametrize("wrapper", [p[1] for p in PAIRS],
                         ids=[p[0] for p in PAIRS])
def test_each_own_commit_wrapper_kept_both_decorators(wrapper) -> None:
    """The other edge of the same mistake, and the one that actually happened.

    Moving the ``def`` line out from under the decorators leaves them on whatever
    ``def`` now follows. That silently strips ``@db_write`` (the RLock held across
    the read-tail/insert window ``_chain_insert`` needs) and ``@audit_emitter`` (the
    ``audit_gap_events`` row on an emit failure) from the public emitter — and it
    removes the emitter from the N-520 pin's witness set, so 18 real findings
    disappear and the ratchet reads greener than the tree is.
    """
    src = inspect.getsource(audit_mod)
    tree = ast.parse(src)
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == wrapper.__name__
    )
    names = {d.id if isinstance(d, ast.Name) else getattr(d, "attr", "?")
             for d in node.decorator_list}
    assert {"db_write", "audit_emitter"} <= names, (
        f"{wrapper.__name__} lost a decorator; it carries {sorted(names)}"
    )
