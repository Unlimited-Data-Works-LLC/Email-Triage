"""Punch  fold 3 — a chain-break reason names only causes that can exist.

The shared walker ``_verify_chain_rows`` writes the break reason for every
chained audit table. Its rule (hipaa-529, db-529, da-529 fold-checks,
2026-09-25), extended at fold 3: a reason may NAME only causes that have a
producer on THAT table and whose precondition the row satisfies, and may
EXCLUDE a cause only when the benign-cause set for that table is complete.

What this file pins:

- BEHAVIOUR, registry chains (no writer produces an unlinked row): a deleted
  predecessor is described as a deletion needing only table write access, and
  a failed chain-tail read is never offered.
- BEHAVIOUR, the gap chain (its writer can write an unlinked row), on every
  row-level branch a benign  row can reach: keyed with the marker
  (evidenced), keyed without it (neither confirmed nor excluded), keyless with
  or without it (unauthenticated, neither confirmed nor excluded), key no
  longer provisioned (same), and a non-empty stored ``prev_hash`` — which at
  fold 3 stopped EXCLUDING the cause and became an observation (hipaa-529-2
  withdrew its fold-2 tie-break: reading the chain tail and INSERTing are not
  one atomic step, so a concurrent write leaves a non-empty prev_hash that was
  already stale). A content mismatch never names it. The whole branch space of
  ``_gap_break_note`` is swept for the exclusion phrasing, not just the arms a
  DB state reaches.
- BEHAVIOUR, the raced STATE on both chain kinds: a row self-consistent under a
  stale, non-empty ``prev_hash`` has the concurrent write NAMED as a cause, and
  ``_prev_hash_placement`` says whether that prev_hash still names a row of the
  table (only THIS row's own linkage target is then cleared — a deletion
  elsewhere in the chain stays open, pinned by its own arm) or names none
  (deletion and forgery both still open). The gap text says a second process demonstrably
  writes that table; the registry text says the exposure is architecturally
  open and NOT demonstrated.
- STRUCTURE (added fold 3): every ``src/`` call to ``_chain_mismatch_reason``
  passes ``hash_index``. Its None default makes an omission silent, so the pin
  is on the SEAM (PD-2), not on the helper.
- STRUCTURE: only ``verify_gap_chain`` passes ``row_note``; every site in
  ``src/`` that writes a ``first_break_reason`` value is in a classified
  function; nothing in ``src/`` calls the swallowing ``get_last_gap_row_hash``;
  every shared-walker result carries ``break_count``.

What this file does NOT pin, and cannot: whether a cause the text names
carries a false precondition (fold 1 said deleting a predecessor needs the
key; it does not). Of the three defects the fold-checks found on this one
sentence, these pins reach two; the third class stays a review obligation.
``verify_log_chain`` has its own walker, stops at its first break and carries
no ``break_count``; it is out of this file's scope.

The race arms build the raced STATE inside ONE process (a stale tail value
handed to the real gap writer, or a stale prev written in place on a registry
row). They pin the TEXT for that state; they are not a reachability proof for
the cross-process race, which is recorded in N-467 and N-508 instead. They also
pin nothing about the WRITE path: fold 3 left the race open deliberately, since
a ``BEGIN IMMEDIATE`` or cross-process lock on the gap writer would propagate
``SQLITE_BUSY`` out of the recovery path and lose the row (N-467 again).
"""

from __future__ import annotations

import ast
import re

import pytest

import email_triage.db.audit as A
from _pin_harness import (
    assert_pin_has_teeth,
    innermost_fn_at_lineno,
    walk_src,
)
from email_triage.web.db import init_db

KEY_1 = b"\x11" * 32
MARKER = A.GAP_TAIL_UNREADABLE_MARKER
TAIL = "chain-tail read"


@pytest.fixture
def conn(tmp_path):
    from _db_tracking import track

    c = track(init_db(str(tmp_path / "t.db")))
    yield c


def _no_version():
    with A._hmac_keys_lock:
        A._HMAC_KEYS.clear()
        A._HMAC_CURRENT_VERSION = None


def _write(conn, helper, exc=None):
    A._write_audit_gap_event(
        conn, helper_name=helper, args=(), kwargs={"event_type": "x"},
        exc=exc if exc is not None else RuntimeError("emit failed"),
    )


def _fail_tail(monkeypatch):
    def boom(_conn):
        raise RuntimeError("tail read failed")

    monkeypatch.setattr(A, "_read_gap_chain_tail", boom)


def _insert_unlinked(conn, helper, exc_msg, *, keyed):
    """A gap row written against an empty prev_hash WITHOUT the marker: the
    shape a pre-marker writer left after a failed tail read."""
    alg, ver = ("hmac-sha256-v1", 1) if keyed else ("sha256", None)
    vals = ("2026-01-01T00:00:00+00:00", helper, "{}", "", "RuntimeError", exc_msg)
    row_hash = A.compute_gap_row_hash("", *vals, hash_alg=alg, master_key_version=ver)
    conn.execute(
        "INSERT INTO audit_gap_events (ts, helper_name, original_args_redacted, "
        "original_args_hash, exc_type, exc_msg, prev_hash, row_hash, hash_alg, "
        "master_key_version) VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?)",
        (*vals, row_hash, alg, ver),
    )
    conn.commit()


def _gap_reason(conn):
    res = A.verify_gap_chain(conn)
    assert not res["intact"], res
    return res["first_break_reason"]


def _ids(conn, table="audit_gap_events"):
    return [r[0] for r in conn.execute(f"SELECT id FROM {table} ORDER BY id")]


def _seed_registry(conn, n=3, table="hipaa_boundary_events"):
    A._set_hmac_key_for_test(KEY_1, version=1)
    for i in range(n):
        A.record_hipaa_boundary(
            conn, scope=f"account:{i}", direction="on", actor_id=None, reason=f"r{i}",
        )
    return _ids(conn, table)


def _relink_registry_row(conn, victim_id, stale_hash, table="hipaa_boundary_events"):
    """Re-point one registry row at ``stale_hash`` and re-hash it so it stays
    SELF-CONSISTENT: the state a writer leaves when it read the chain tail
    before another writer's row landed. Built in one process."""
    fields = A._AUDIT_CHAIN_CANONICAL_FIELDS[table]
    row = conn.execute(
        f"SELECT {', '.join(fields)}, hash_alg FROM {table} WHERE id = ?",
        (victim_id,),
    ).fetchone()
    new_hash = A.compute_audit_row_hash(
        stale_hash, tuple(row[n] for n in fields),
        hash_alg=row["hash_alg"], master_key_version=1,
    )
    conn.execute(
        f"UPDATE {table} SET prev_hash = ?, row_hash = ? WHERE id = ?",
        (stale_hash, new_hash, victim_id),
    )
    conn.commit()


def _row_hash(conn, row_id, table="hipaa_boundary_events"):
    return conn.execute(
        f"SELECT row_hash FROM {table} WHERE id = ?", (row_id,),
    ).fetchone()[0]


def _stale_tail(monkeypatch, conn):
    """Make the next gap write link to the FIRST row's hash: writer A read the
    chain tail before writer B's row landed. The real writer does the INSERT."""
    first = conn.execute(
        "SELECT row_hash FROM audit_gap_events ORDER BY id LIMIT 1"
    ).fetchone()[0]
    monkeypatch.setattr(A, "_read_gap_chain_tail", lambda _c: first)
    return first


class TestRegistryChainsNeverOfferATailRead:
    def test_deletion_is_a_deletion(self, conn):
        ids = _seed_registry(conn)
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (ids[1],))
        conn.commit()
        reason = A.verify_audit_chain(conn, "hipaa_boundary_events")["first_break_reason"]
        assert "No writer on this table produces an unlinked row" in reason, reason
        assert "not the key" in reason and TAIL not in reason, reason

    def test_content_edit_never_offers_a_tail_read(self, conn):
        ids = _seed_registry(conn)
        conn.execute("UPDATE hipaa_boundary_events SET reason = 'x' WHERE id = ?", (ids[1],))
        conn.commit()
        reason = A.verify_audit_chain(conn, "hipaa_boundary_events")["first_break_reason"]
        assert "content does not match" in reason and TAIL not in reason, reason


class TestGapChainNamesTheCauseOnEveryReachableBranch:
    def test_keyed_with_marker_is_evidenced(self, conn, monkeypatch):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write(conn, "h1")
        _fail_tail(monkeypatch)
        _write(conn, "h2")
        reason = _gap_reason(conn)
        assert "self-consistent under HMAC key version 1" in reason, reason
        assert f"{MARKER}RuntimeError]" in reason and "that cause is evidenced" in reason, reason

    def test_keyed_without_marker_is_not_excluded(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write(conn, "h1")
        _insert_unlinked(conn, "h2", "emit failed", keyed=True)
        reason = _gap_reason(conn)
        assert "self-consistent under HMAC key version 1" in reason, reason
        assert "neither confirmed nor excluded" in reason and "excluded:" not in reason, reason

    def test_keyless_with_marker_is_unauthenticated(self, conn, monkeypatch):
        _no_version()
        _write(conn, "h1")
        _fail_tail(monkeypatch)
        _write(conn, "h2")
        reason = _gap_reason(conn)
        assert "keyless" in reason and "not authenticated" in reason, reason
        assert "neither confirmed nor excluded" in reason, reason
        assert "which the writer sets only when" not in reason, reason

    def test_keyless_without_marker_is_not_excluded(self, conn):
        _no_version()
        _write(conn, "h1")
        _insert_unlinked(conn, "h2", "emit failed", keyed=False)
        reason = _gap_reason(conn)
        assert "no tail-read marker" in reason and "neither confirmed nor excluded" in reason, reason

    def test_key_no_longer_provisioned_reports_the_marker_unauthenticated(self, conn, monkeypatch):
        _no_version()
        _write(conn, "h1")  # keyless, verifies with no key
        A._set_hmac_key_for_test(KEY_1, version=1)
        _fail_tail(monkeypatch)
        _write(conn, "h2")  # keyed, marked, empty prev
        _no_version()
        reason = _gap_reason(conn)
        assert reason.startswith("hash recompute failed"), reason
        assert f"{MARKER}RuntimeError]" in reason and "not authenticated" in reason, reason

    @pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
    def test_non_empty_prev_does_not_exclude_it(self, conn, keyed):
        """Fold 3, hipaa-529-2 amendment: a non-empty stored prev_hash is an
        OBSERVATION about the writer's tail read, never an exclusion — the read
        and the INSERT are not one atomic step, so a concurrent write leaves a
        non-empty prev_hash that was already stale. The keyless arm additionally
        must not assert the observation flatly: that byte is unauthenticated."""
        if keyed:
            A._set_hmac_key_for_test(KEY_1, version=1)
        else:
            _no_version()
        for h in ("h1", "h2", "h3"):
            _write(conn, h)
        conn.execute("DELETE FROM audit_gap_events WHERE id = ?", (_ids(conn)[1],))
        conn.commit()
        reason = _gap_reason(conn)
        assert "is excluded" not in reason and "excluded:" not in reason, reason
        assert "neither confirmed nor excluded" in reason, reason
        assert "its stored prev_hash is not empty" in reason, reason
        if keyed:
            assert "inside its keyed hash" in reason, reason
        else:
            assert "not authenticated here" in reason, reason

    def test_content_mismatch_never_names_it(self, conn, monkeypatch):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write(conn, "h1")
        _fail_tail(monkeypatch)
        _write(conn, "h2")
        conn.execute("UPDATE audit_gap_events SET helper_name = 'x' WHERE id = ?", (_ids(conn)[1],))
        conn.commit()
        reason = _gap_reason(conn)
        assert "content does not match" in reason and TAIL not in reason, reason

    @pytest.mark.parametrize(
        "exc_msg", ["emit failed", f"{MARKER}RuntimeError] emit failed"],
        ids=["no-marker", "marker"],
    )
    @pytest.mark.parametrize(
        "authenticated", [True, False], ids=["authenticated", "unauthenticated"])
    @pytest.mark.parametrize("prev", ["", "somehash"], ids=["empty-prev", "non-empty-prev"])
    def test_no_note_branch_excludes_the_tail_read(self, prev, authenticated, exc_msg):
        """The whole branch space of ``_gap_break_note``, not only the arms a DB
        state reaches: exactly one combination may SETTLE the cause — a keyed
        row carrying the marker with an empty prev_hash, where it is EVIDENCED.
        Every other combination says "neither confirmed nor excluded", and none
        may exclude it. This is the pin hipaa-529-2 said fold 2 lacked, and it
        goes red if any branch re-acquires an exclusion."""
        note = A._gap_break_note({"prev_hash": prev, "exc_msg": exc_msg}, authenticated)
        assert "is excluded" not in note and "excluded:" not in note, note
        if prev == "" and authenticated and MARKER in exc_msg:
            assert "that cause is evidenced" in note, note
        else:
            assert "neither confirmed nor excluded" in note, note

    def test_a_failed_second_recompute_accuses_nothing(self):
        row = {"prev_hash": "p", "row_hash": "h", "master_key_version": 1}

        def hasher(*_a):
            raise RuntimeError("boom")

        reason = A._chain_mismatch_reason(row, (), "hmac-sha256-v1", hasher, None)
        assert "could not be completed (RuntimeError)" in reason, reason
        assert "altered" not in reason and "forged" not in reason, reason


class TestTheRacedStateNamesTheConcurrentWrite:
    """db-529-2 item 1 / hipaa-529-2 H1 / da-529-2 NEW-6. Reading the chain tail
    and INSERTing are not one atomic step, and the write lock is process-wide
    only (``db_writelock``), so a BENIGN concurrent write leaves a row that is
    self-consistent under a stale, non-empty prev_hash. Fold 2 named only
    hostile causes in that state. Direction of the defect: false ACCUSATION —
    an operator could "repair" a raced row by rewriting it."""

    def test_the_gap_chain_names_it_and_says_the_pair_is_demonstrated(
        self, conn, monkeypatch,
    ):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write(conn, "h1")
        _write(conn, "h2")
        _stale_tail(monkeypatch, conn)
        _write(conn, "h3")
        ids = _ids(conn)
        res = A.verify_gap_chain(conn)
        assert res["first_break_id"] == ids[2], res
        reason = res["first_break_reason"]
        assert "self-consistent under HMAC key version 1" in reason, reason
        assert "a concurrent write left it linked to a chain tail that was " \
               "already stale" in reason, reason
        assert "a second process does write this table" in reason, reason
        assert "is excluded" not in reason, reason

    def test_a_registry_chain_names_it_as_not_demonstrated(self, conn):
        """hipaa-529-2 correction: ``record_cli_admin_op`` writes ``log_entries``
        (its own walker), so N-157 gives no cross-process pair for the nine
        registry chains. The text must fix the absoluteness WITHOUT claiming the
        registry half was measured."""
        ids = _seed_registry(conn)
        _relink_registry_row(conn, ids[2], _row_hash(conn, ids[0]))
        res = A.verify_audit_chain(conn, "hipaa_boundary_events")
        assert res["first_break_id"] == ids[2], res
        reason = res["first_break_reason"]
        assert "with writes serialised by the process-wide write lock" in reason, reason
        assert "a concurrent write from a second process is not excluded" in reason, reason
        assert "architecturally open, NOT demonstrated" in reason, reason
        assert TAIL not in reason, reason


class TestThePrevHashPlacementDiscriminator:
    """db-529-2 ADDENDUM 7 as the lead ruled it: narrow the cause set on the
    VERIFIER side, touching no write path. Observation only — a key holder can
    manufacture any placement and on a keyless row anyone with write access can,
    so no arm here asserts a row is CLEARED or any cause excluded, only what the
    placement itself shows."""

    def test_a_present_lower_row_clears_only_this_rows_linkage_target(self, conn):
        """hipaa-529-2 Amendment 2: a match proves the removal of THIS row's own
        linkage target did not happen, and nothing more."""
        ids = _seed_registry(conn)
        _relink_registry_row(conn, ids[2], _row_hash(conn, ids[0]))
        reason = A.verify_audit_chain(conn, "hipaa_boundary_events")["first_break_reason"]
        assert f"names row id={ids[0]}, still in the table" in reason, reason
        assert "this row's own linkage target was not removed" in reason, reason
        assert "a deletion elsewhere in the chain is not excluded" in reason, reason
        assert "who could also have manufactured this match" in reason, reason
        assert "consistent with a concurrent write" in reason, reason
        assert "ruled out" not in reason, reason

    def test_a_deletion_elsewhere_coexists_with_a_matched_raced_row(self, conn):
        """hipaa-529-2 Amendment 2, the case that makes "deletion ruled out"
        false: the described break is a raced row whose prev_hash names a
        still-present row, AND a different row of the same chain really was
        deleted. The reason must not claim deletion is excluded.

        Construction note. The raced row is EARLY (id 3, pointing at id 1) and
        the deleted row is LATER (id 5). Racing the LAST row onto its
        grandparent and then deleting the row between them does NOT reach this
        branch: the deletion makes the named row the effective predecessor, the
        raced row verifies, and the walk reports the chain INTACT (measured
        2026-09-25: intact=True, first_break_id=None, break_count=0). That
        cancellation is a detection gap in its own right and is NOT what this
        arm pins."""
        ids = _seed_registry(conn, n=6)
        _relink_registry_row(conn, ids[2], _row_hash(conn, ids[0]))
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (ids[4],))
        conn.commit()
        res = A.verify_audit_chain(conn, "hipaa_boundary_events")
        assert res["first_break_id"] == ids[2], res
        reason = res["first_break_reason"]
        assert f"names row id={ids[0]}, still in the table" in reason, reason
        assert "a deletion elsewhere in the chain is not excluded" in reason, reason
        assert "ruled out" not in reason, reason
        # No POSITIVE exclusion anywhere: every use of the word in this reason is
        # a negated clause. Both negations are named, so the check cannot pass on
        # a reason that simply dropped one.
        assert "is excluded" not in reason, reason
        assert "a concurrent write from a second process is not excluded" in reason, reason

    def test_no_match_keeps_deletion_and_forgery_open(self, conn):
        ids = _seed_registry(conn)
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (ids[1],))
        conn.commit()
        reason = A.verify_audit_chain(conn, "hipaa_boundary_events")["first_break_reason"]
        assert "names no row in this table" in reason, reason
        assert "a deleted predecessor or a forged row" in reason, reason
        assert "still in the table, which is not its predecessor" not in reason, reason

    def test_a_named_later_row_is_reported_out_of_chain_order(self, conn):
        """The index is built over EVERY row, not the rows walked so far, so a
        row pointing FORWARD is reported as that and not as "names no row"."""
        ids = _seed_registry(conn)
        _relink_registry_row(conn, ids[1], _row_hash(conn, ids[2]))
        res = A.verify_audit_chain(conn, "hipaa_boundary_events")
        assert res["first_break_id"] == ids[1], res
        assert f"names row id={ids[2]}, which is not an earlier row" \
               in res["first_break_reason"], res
        assert "names no row in this table" not in res["first_break_reason"], res

    def test_an_empty_prev_hash_gets_no_placement_text(self, conn, monkeypatch):
        """An empty prev_hash is the chain's genesis value, not a hash that
        names a row, so the placement text is omitted rather than reading
        "names no row in this table"."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write(conn, "h1")
        _fail_tail(monkeypatch)
        _write(conn, "h2")
        reason = _gap_reason(conn)
        assert "its stored prev_hash is empty" in reason, reason
        assert "names no row in this table" not in reason, reason
        assert "still in the table" not in reason, reason

    def test_the_keyless_branch_carries_it_as_unauthenticated(self, conn, monkeypatch):
        """db-529-2: on a keyless row anyone with write access can manufacture
        the placement, so the observation ships with that caveat, not dropped."""
        _no_version()
        _write(conn, "h1")
        _write(conn, "h2")
        _stale_tail(monkeypatch, conn)
        _write(conn, "h3")
        ids = _ids(conn)
        reason = _gap_reason(conn)
        assert "proves nothing" in reason, reason
        assert f"Unauthenticated observation: its stored prev_hash names row " \
               f"id={ids[0]}, still in the table" in reason, reason


# ---------------------------------------------------------------- structure

def _row_note_callers(tree) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_verify_chain_rows"
                and any(k.arg == "row_note" for k in node.keywords)):
            fn = innermost_fn_at_lineno(tree, node.lineno)
            out.add(fn.name if fn is not None else "<module>")
    return out


class TestOnlyTheGapVerifierPassesRowNote:
    def test_set_is_exactly_the_gap_verifier(self):
        found = set()
        for _p, _rel, tree in walk_src():
            found |= _row_note_callers(tree)
        assert found == {"verify_gap_chain"}, found

    def test_has_teeth(self):
        assert_pin_has_teeth(
            lambda t: _row_note_callers(t) - {"verify_gap_chain"},
            "def verify_audit_chain():\n    _verify_chain_rows(1, 2, 3, 4, row_note=f)\n",
            "def verify_gap_chain():\n    _verify_chain_rows(1, 2, 3, 4, row_note=f)\n",
        )


# Every function in src/ that WRITES a first_break_reason value, classified.
# Domain = assignments to the name UNION dict-literal keys (a Name scan alone
# misses _not_verified). Attribution is the innermost enclosing function by
# source span, chosen explicitly: ast.walk's order is documented as unspecified.
_REASON_PRODUCERS = {
    ("db/audit.py", "_verify_chain_rows"):
        "row-level, shared walker (its text comes from _chain_mismatch_reason, "
        "_gap_break_note and _prev_hash_placement — all three RETURN text "
        "rather than writing the field, so they are not sites themselves and "
        "are pinned by behaviour above)",
    ("db/audit.py", "_not_verified"):
        "table-level, shared by verify_gap_chain and (since punch #524) "
        "verify_audit_chain; it writes the caller's text. The gap caller's "
        "'a restart will NOT recreate it' text is coupled to the punch "
        "#528/#529 repair shape and must change with it; the registry "
        "caller's text names no cause",
    ("db/audit.py", "verify_log_chain"):
        "outside this walker: log_entries has its own walk",
    ("db/audit.py", "_blank_row"):
        "outside this walker: verify_log_chain's blank-row classifier (panel P "
        "G1, N-609); covered by "
        "tests/test_web/test_punch625_log_keyed_floor_pin.py::TestBlankRows",
}


def _reason_sites(tree, rel):
    sites = []
    for node in ast.walk(tree):
        lines = []
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            lines += [t.lineno for t in targets
                      if isinstance(t, ast.Name) and t.id == "first_break_reason"]
        elif isinstance(node, ast.Dict):
            lines += [k.lineno for k in node.keys
                      if isinstance(k, ast.Constant) and k.value == "first_break_reason"]
        for ln in lines:
            fn = innermost_fn_at_lineno(tree, ln)
            sites.append((rel, fn.name if fn is not None else "<module>", ln))
    return sites


class TestEveryReasonProducerIsClassified:
    def test_domain_is_classified_and_not_vacuous(self):
        sites = []
        for _p, rel, tree in walk_src():
            sites += _reason_sites(tree, rel)
        unclassified = [s for s in sites if s[:2] not in _REASON_PRODUCERS]
        assert not unclassified, (
            f"new first_break_reason writer(s) {unclassified}: classify each in "
            "_REASON_PRODUCERS and, if row-level, cover it with a behaviour test"
        )
        seen = {s[:2] for s in sites}
        assert seen == set(_REASON_PRODUCERS), set(_REASON_PRODUCERS) - seen

    def test_has_teeth(self):
        def detector(tree):
            return [s for s in _reason_sites(tree, "db/audit.py") if s[:2] not in _REASON_PRODUCERS]

        assert_pin_has_teeth(
            detector,
            "def new_verifier():\n    return {'first_break_reason': 'x'}\n",
            "def _not_verified(reason):\n    return {'first_break_reason': reason}\n",
        )


def _mismatch_reason_calls_without_index(tree):
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "_chain_mismatch_reason"
        and not any(k.arg == "hash_index" for k in n.keywords)
    ]


class TestEveryMismatchReasonCallPassesTheIndex:
    """PD-2, the seam not the source: ``hash_index`` defaults to None and with
    None ``_prev_hash_placement`` returns nothing, so a call that forgets it
    loses the discriminator SILENTLY and reads exactly like a healthy one
    (``pattern_a_bare_return_is_a_silent_pass``). Pinned at the call site.

    Scope: ``src/`` only — this file's own direct call in
    ``test_a_failed_second_recompute_accuses_nothing`` passes five positionals
    deliberately, to prove the default is safe rather than absent."""

    def test_no_src_call_omits_it(self):
        offenders = [(rel, ln) for _p, rel, tree in walk_src()
                     for ln in _mismatch_reason_calls_without_index(tree)]
        assert offenders == [], offenders

    def test_has_teeth(self):
        assert_pin_has_teeth(
            _mismatch_reason_calls_without_index,
            "def w():\n    _chain_mismatch_reason(r, v, a, h, n)\n",
            "def w():\n    _chain_mismatch_reason(r, v, a, h, n, hash_index=i)\n",
        )


def _swallowing_tail_callers(tree):
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and (
            (isinstance(n.func, ast.Name) and n.func.id == "get_last_gap_row_hash")
            or (isinstance(n.func, ast.Attribute) and n.func.attr == "get_last_gap_row_hash")
        )
    ]


class TestNothingInSrcUsesTheSwallowingTailRead:
    """db-529 NEW-4: get_last_gap_row_hash turns a failed read into "" (an
    empty table). A writer that called it would lose punch 's marker."""

    def test_no_src_caller(self):
        callers = [(rel, ln) for _p, rel, tree in walk_src() for ln in _swallowing_tail_callers(tree)]
        assert callers == [], callers

    def test_has_teeth(self):
        assert_pin_has_teeth(
            _swallowing_tail_callers,
            "def w(c):\n    return get_last_gap_row_hash(c)\n",
            "def w(c):\n    return _read_gap_chain_tail(c)\n",
        )


def test_every_shared_walker_result_carries_break_count(conn):
    A._set_hmac_key_for_test(KEY_1, version=1)
    chains = A.verify_all_audit_chains(conn)
    assert chains and all("break_count" in c for c in chains.values()), chains



# Punch  (N-510): the id-gap signal sees the pair the hash walk cannot.
class TestMissingIdSignal:
    def test_race_plus_deletion_verifies_intact_but_the_ids_are_missing(self, conn):
        """The N-510 construction: race the LAST row onto its grandparent, delete
        the row between. The walk reports intact; the id gap does not.

        The ``intact is True`` half pins a KNOWN GAP (N-510, open). If N-510 is
        ever fixed that assertion goes red, and the red is correct: update the
        test, do not restore the gap to make it green."""
        ids = _seed_registry(conn, n=4)
        _relink_registry_row(conn, ids[3], _row_hash(conn, ids[1]))
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (ids[2],))
        conn.commit()
        res = A.verify_audit_chain(conn, "hipaa_boundary_events")
        assert res["intact"] is True and res["break_count"] == 0, res
        assert res["missing_id_count"] == 1, res

    def test_an_untouched_chain_reports_zero(self, conn):
        _seed_registry(conn, n=4)
        assert A.verify_audit_chain(conn, "hipaa_boundary_events")["missing_id_count"] == 0

    def test_deleting_the_newest_row_is_still_counted(self, conn):
        """sqlite_sequence remembers the highest id issued, so a trailing
        deletion leaves a gap even though MAX(id) moved down."""
        ids = _seed_registry(conn, n=4)
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (ids[3],))
        conn.commit()
        assert A.verify_audit_chain(conn, "hipaa_boundary_events")["missing_id_count"] == 1

    def test_every_chain_result_carries_the_signal(self, conn):
        chains = A.verify_all_audit_chains(conn)
        assert chains and all("missing_id_count" in c for c in chains.values()), chains

    def test_the_gap_chain_counts_a_deleted_row(self, conn, monkeypatch):
        A._set_hmac_key_for_test(KEY_1, version=1)
        for i in range(3):
            _write(conn, f"h{i}")
        mid = conn.execute(
            "SELECT id FROM audit_gap_events ORDER BY id LIMIT 1 OFFSET 1").fetchone()[0]
        conn.execute("DELETE FROM audit_gap_events WHERE id = ?", (mid,))
        conn.commit()
        assert A.verify_gap_chain(conn)["missing_id_count"] == 1


# Punch  fold: the premises the id-gap signal rests on, pinned.
def _chained_tables():
    return [*A._AUDIT_CHAIN_CANONICAL_FIELDS, A.GAP_CHAIN_TABLE]


def test_every_chained_table_declares_autoincrement(conn):
    """da 531-F1: without AUTOINCREMENT there is no high-water mark, a trailing
    deletion leaves no gap, and the signal would be blind. Count-agnostic over
    the registry plus the gap table."""
    missing = []
    for table in _chained_tables():
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        assert row is not None, table
        if "AUTOINCREMENT" not in (row[0] or "").upper():
            missing.append(table)
    assert not missing, missing


def test_an_empty_table_with_no_sequence_row_is_unmeasured_not_zero(conn):
    """Nothing ever issued: None ("not measured"), never 0."""
    conn.execute("CREATE TABLE no_autoinc (id INTEGER PRIMARY KEY, v TEXT)")
    assert A._missing_id_count(conn, "no_autoinc", []) is None


def test_deleting_the_sequence_row_does_not_silence_the_signal(conn):
    """db-529-2 NEW-1: the actor who deletes rows can also delete the table's
    sqlite_sequence row. The count must fall back to MAX(id) - COUNT(*), not
    go dark."""
    ids = _seed_registry(conn, n=5)
    for i in (ids[1], ids[2]):
        conn.execute("DELETE FROM hipaa_boundary_events WHERE id = ?", (i,))
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'hipaa_boundary_events'")
    conn.commit()
    assert A.verify_audit_chain(conn, "hipaa_boundary_events")["missing_id_count"] == 2


_ID_CONSUMING = re.compile(
    r"\b(?:INSERT\s+OR\s+(?:IGNORE|REPLACE)|REPLACE)\s+INTO\s+[\"'`\[]?(\w+)",
    re.IGNORECASE,
)


def _id_consuming_writes(text, chained):
    return [m.group(1) for m in _ID_CONSUMING.finditer(text) if m.group(1) in chained]


def test_no_insert_or_ignore_or_replace_on_a_chained_table():
    """hipaa 531 / db 531: INSERT OR IGNORE and INSERT OR REPLACE advance
    sqlite_sequence without a row, a benign gap indistinguishable from a
    deletion. None writes a chained table today; this keeps that true."""
    chained = set(_chained_tables())
    hits = []
    for p, rel, _tree in walk_src():
        hits += [(rel, t) for t in _id_consuming_writes(p.read_text(encoding="utf-8"), chained)]
    assert not hits, hits


def test_id_consuming_scan_has_teeth():
    chained = {"audit_gap_events", "auth_events"}
    assert _id_consuming_writes("x = 'INSERT OR IGNORE INTO audit_gap_events (a) VALUES (?)'", chained)
    assert _id_consuming_writes('REPLACE INTO "auth_events" VALUES (1)', chained)
    assert not _id_consuming_writes("INSERT OR IGNORE INTO message_labels VALUES (1)", chained)
    assert not _id_consuming_writes("INSERT INTO audit_gap_events VALUES (1)", chained)
