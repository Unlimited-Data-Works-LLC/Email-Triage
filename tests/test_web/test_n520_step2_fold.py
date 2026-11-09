"""N-520 step 2, s2 panel fold: the funnel's entry guards and its exit edge.

* db N1-M1 / hipaa M-N4: a settings-backed ``state_txn`` must invalidate the
  settings cache on EVERY exit edge (the funnel's own ``finally``), or a value cached inside the
  rolled-back transaction (or the pre-revoke ACK) is served for the TTL and the
  BAA gate fails OPEN.
* db S1: a ``state_txn`` that commits and then writes again is still refused
  (BEGIN + SAVEPOINT + RELEASE), and a second connection never sees the state
  before the funnel returns.
* db S2: a connection already inside a transaction is refused at entry.
* db S4: an autocommit connection is refused with no row written.
"""
from __future__ import annotations

import sqlite3

import pytest

import email_triage.db.audit as audit_mod
import email_triage.web.db as webdb
from email_triage.classify.baa_gate import (
    baa_ack_key, classifier_baa_status, get_baa_ack, revoke_baa_ack_txn, set_baa_ack,
    set_baa_ack_txn,
)
from email_triage.db.audit import record_witnessed_state_change

_DOWN = "audit storage exploded"


def _boom(*_a, **_kw):
    raise RuntimeError(_DOWN)


class OpenAICompatClassifier:
    """Stand-in external classifier: backend ``openaicompat``, host ``x.invalid``."""
    is_local = False
    _base_url = "https://x.invalid/v1"


_BACKEND, _HOST = "openaicompat", "x.invalid"


@pytest.fixture
def cache_on(monkeypatch):
    monkeypatch.setattr(webdb, "_SETTINGS_CACHE_TTL_SECONDS", 60.0)
    webdb.invalidate_setting_cache()
    yield
    webdb.invalidate_setting_cache()


def _witness(admin_user):
    return lambda c, _r: audit_mod.record_auth_event_txn(
        c, event_type="baa_ack", email=admin_user["email"],
        user_id=admin_user["id"], outcome="success", detail="probe",
    )


def _ack_and_read(user_id):
    def state(c):
        set_baa_ack_txn(c, _BACKEND, _HOST, user_id=user_id)
        # A reader on the shared connection inside the open transaction caches
        # the UNCOMMITTED ACK: the race set_setting_txn's precondition names.
        assert get_baa_ack(c, _BACKEND, _HOST)["acked"] is True
    return state


class TestSettingsCacheExitEdge:
    """The funnel clears the settings cache UNCONDITIONALLY in its ``finally``
    (DA final verdict: the rule lives in one place, no caller hook)."""

    def test_a_rolled_back_ack_reads_not_acked(
            self, db, admin_user, cache_on, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_witnessed_state_change(
                db, operation="baa_ack", state_txn=_ack_and_read(admin_user["id"]),
                witness_txn=_witness(admin_user),
            )
        assert classifier_baa_status(db, OpenAICompatClassifier())["baa_acked"] is False

    def test_control_without_the_exit_edge_clear_the_cache_lies(
            self, db, admin_user, cache_on, monkeypatch):
        """The rig can say FAIL: with the funnel's clear no-opped the BAA gate reads ACKED."""
        real = webdb.invalidate_setting_cache
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        monkeypatch.setattr(webdb, "invalidate_setting_cache", lambda key=None: None)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_witnessed_state_change(
                db, operation="baa_ack", state_txn=_ack_and_read(admin_user["id"]),
                witness_txn=_witness(admin_user),
            )
        try:
            assert classifier_baa_status(db, OpenAICompatClassifier())["baa_acked"] is True
        finally:
            real()

    def test_a_revoke_reads_not_acked_at_once(self, db, admin_user, cache_on):
        set_baa_ack(db, _BACKEND, _HOST, user_id=admin_user["id"])
        assert classifier_baa_status(db, OpenAICompatClassifier())["baa_acked"] is True
        record_witnessed_state_change(
            db, operation="baa_ack_revoke",
            state_txn=lambda c: revoke_baa_ack_txn(c, _BACKEND, _HOST),
            witness_txn=_witness(admin_user),
        )
        assert classifier_baa_status(db, OpenAICompatClassifier())["baa_acked"] is False

    def test_a_failing_cache_clear_does_not_replace_the_propagating_error(
            self, db, admin_user, monkeypatch):
        real = webdb.invalidate_setting_cache
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)

        def bad_clear(key=None):
            # Only the funnel's whole-cache clear fails; keyed clears by the
            # settings writers inside state_txn still run for real.
            if key is not None:
                return real(key)
            raise ValueError("cache down")
        monkeypatch.setattr(webdb, "invalidate_setting_cache", bad_clear)
        try:
            with pytest.raises(RuntimeError, match=_DOWN):
                record_witnessed_state_change(
                    db, operation="baa_ack", state_txn=_ack_and_read(admin_user["id"]),
                    witness_txn=_witness(admin_user),
                )
        finally:
            real()


class TestEntryGuards:
    def test_commit_then_write_inside_state_txn_is_refused_before_the_witness(
            self, db, admin_user):
        ran = []

        def state(c):
            set_baa_ack_txn(c, _BACKEND, _HOST, user_id=admin_user["id"])
            c.commit()
            revoke_baa_ack_txn(c, _BACKEND, "y.invalid")  # in_transaction is True again
        with pytest.raises(RuntimeError, match="committed its own write"):
            record_witnessed_state_change(
                db, operation="probe", state_txn=state,
                witness_txn=lambda c, _r: ran.append(True),
            )
        assert ran == []

    def test_an_open_transaction_is_refused_at_entry(self, db, admin_user):
        webdb.set_setting_txn(db, "n520_probe", {"v": 1})
        assert db.in_transaction
        try:
            with pytest.raises(RuntimeError, match="already holds an open transaction"):
                record_witnessed_state_change(
                    db, operation="probe",
                    state_txn=lambda c: None, witness_txn=lambda c, _r: None,
                )
            # The funnel never COMMITS the foreign pending write. (``@db_write``
            # rolls the connection back on any raise from an audit emitter, so
            # the pending row is discarded, not made durable.)
            db.rollback()
            webdb.invalidate_setting_cache("n520_probe")
            assert webdb.get_setting(db, "n520_probe") is None
        finally:
            db.rollback()

    def test_autocommit_is_refused_with_no_row_written(self, tmp_path, admin_user):
        conn = sqlite3.connect(tmp_path / "ac.db", isolation_level=None)
        conn.execute("CREATE TABLE t (v INTEGER)")
        with pytest.raises(RuntimeError, match="isolation_level=None"):
            record_witnessed_state_change(
                conn, operation="probe",
                state_txn=lambda c: c.execute("INSERT INTO t VALUES (1)"),
                witness_txn=lambda c, _r: None,
            )
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
        conn.close()

    def test_a_second_connection_never_sees_the_state_before_the_witness(
            self, tmp_path):
        path = tmp_path / "iso.db"
        setup = sqlite3.connect(path)
        setup.execute("CREATE TABLE t (v INTEGER)")
        setup.commit()
        setup.close()
        conn = sqlite3.connect(path, timeout=0.1)
        other = sqlite3.connect(path, timeout=0.1)
        seen = []
        record_witnessed_state_change(
            conn, operation="probe",
            state_txn=lambda c: c.execute("INSERT INTO t VALUES (1)"),
            witness_txn=lambda c, _r: seen.append(
                other.execute("SELECT COUNT(*) FROM t").fetchone()[0]),
        )
        assert seen == [0]
        assert other.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1
        conn.close()
        other.close()


# ---------------------------------------------------------------------------
# hipaa M-N1 (E11): recipient digest send-now writes its witness BEFORE egress.
# ---------------------------------------------------------------------------


@pytest.fixture
def digest_route(client, db, admin_user, monkeypatch):
    import email_triage.actions.recipient_digest as rd
    import email_triage.triage_logging as tl
    from email_triage.web.db import create_email_account
    acct_id = create_email_account(
        db, admin_user["id"], "digest", "imap",
        {"host": "x.invalid", "port": 993, "username": "owner@x.invalid"},
    )
    client.app.state.config.smtp.host = "smtp.x.invalid"
    sent: list[int] = []
    monkeypatch.setattr(rd, "gather_digest_rows", lambda *_a, **_kw: [{"id": 1}])
    monkeypatch.setattr(rd, "send_recipient_digest", lambda **_kw: sent.append(1))
    monkeypatch.setattr(tl, "account_hipaa_effective", lambda **_kw: True)
    url = f"/accounts/{acct_id}/recipient-digest/send-now"
    return acct_id, url, sent, rd


def _stamp(db, rd, acct_id):
    webdb.invalidate_setting_cache()
    return webdb.get_setting(db, rd._state_key(acct_id))


def _hipaa_rows(db, acct_id):
    return db.execute(
        "SELECT outcome FROM hipaa_access_events WHERE account_id = ? "
        "AND operation = 'recipient_digest_sent' ORDER BY id", (acct_id,),
    ).fetchall()


class TestDigestWitnessBeforeEgress:
    def test_happy_path_witness_then_send_then_stamp(
            self, client, db, admin_cookies, digest_route):
        acct_id, url, sent, rd = digest_route
        resp = client.post(url, cookies=admin_cookies)
        assert resp.status_code == 200 and "Sent 1 row" in resp.text
        assert sent == [1]
        assert [r["outcome"] for r in _hipaa_rows(db, acct_id)] == ["ok"]
        assert _stamp(db, rd, acct_id)["row_count"] == 1

    @pytest.mark.audit_failure_expected(
        match="recipient_digest_send_started", count=2,
    )
    def test_a_failed_pre_send_witness_refuses_the_send(
            self, client, db, admin_cookies, digest_route, monkeypatch):
        acct_id, url, sent, rd = digest_route
        monkeypatch.setattr(webdb, "record_access_event", _boom)
        for _ in range(2):  # chain down across ticks: never a send, never a loop
            resp = client.post(url, cookies=admin_cookies)
            assert resp.status_code == 200  # DA N5: a clean refusal, not a raw 500
            assert "Send refused" in resp.text
        assert sent == []
        assert _stamp(db, rd, acct_id) is None

    @pytest.mark.audit_failure_expected(
        match="recipient_digest_sent finalise", count=1,
    )
    def test_a_failed_finalise_keeps_the_stamp_and_sends_once(
            self, client, db, admin_cookies, digest_route, monkeypatch):
        acct_id, url, sent, rd = digest_route
        monkeypatch.setattr(webdb, "update_hipaa_access_event", _boom)
        resp = client.post(url, cookies=admin_cookies)
        assert resp.status_code == 200 and "Sent 1 row" in resp.text
        assert sent == [1]
        # The in_progress row witnesses the disclosure; the stamp is durable,
        # so the scheduler's idempotence guard cannot re-send.
        assert [r["outcome"] for r in _hipaa_rows(db, acct_id)] == ["in_progress"]
        assert _stamp(db, rd, acct_id)["row_count"] == 1


# ---------------------------------------------------------------------------
# hipaa MUST 4 (E6/E7/E9/E10/E20): credential burns. SUCCESS edge: the burn,
# the stamp and the success row are ONE transaction, the cookie only after it,
# so a failed witness leaves the credential as it was and mints no session.
# FAILURE edge: the TIGHTENING burn commits on its own, whatever the row does.
# ---------------------------------------------------------------------------


def _post_or_raise(client, *a, **kw):
    """The route either answers or lets the funnel's error escape the test
    client; both are a refusal. Returns the response, or None on a raise."""
    try:
        return client.post(*a, **kw)
    except RuntimeError as exc:
        assert _DOWN in str(exc), exc
        return None


def _no_session(resp) -> bool:
    from email_triage.web.auth import SESSION_COOKIE_NAME
    return resp is None or SESSION_COOKIE_NAME not in resp.cookies


def _otp_used(db, email):
    return [r["used"] for r in db.execute(
        "SELECT used FROM otp_codes WHERE email = ? ORDER BY id", (email,))]


def _assert_spent_code_is_invalid(client, db, email, code):
    """After recovery the same code is refused as invalid and mints no session."""
    resp = client.post("/login/verify", data={"email": email, "code": code},
                       follow_redirects=False)
    assert _no_session(resp)
    assert resp.status_code == 200
    assert "Invalid or expired code" in resp.text
    assert _otp_used(db, email) == [1]


class TestCredentialBurnEdges:
    def test_otp_success_with_a_failed_witness_burns_the_code_and_mints_no_session(
            self, client, db, regular_user, monkeypatch):
        """hipaa-sme 2026-11-06 (s2 N1 fold, option A, §164.312(d)): a failed
        success-edge witness burns the matched code in its own transaction, so
        the 500-vs-"invalid" split leaves nothing to replay after recovery.
        (Inverts the s2 ruling (i) test, which left the code unburned.)"""
        from email_triage.web.auth import generate_otp, store_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        resp = _post_or_raise(client, "/login/verify", data={"email": email, "code": code})
        assert _no_session(resp)
        assert _otp_used(db, email) == [1], "a failed witness must still burn the matched code"
        monkeypatch.undo()
        _assert_spent_code_is_invalid(client, db, email, code)

    def test_otp_lost_race_refuses_with_a_lockout_neutral_denied_row(
            self, client, db, regular_user, monkeypatch):
        """s2h-order DA M1/M2: a verify that loses the burn race to a concurrent
        verify is refused as invalid, mints no session, and is witnessed by one
        ``denied:otp_already_used`` row and no ``failure`` row (a second use of a
        spent code is never silent, and never counts toward the lockout)."""
        import email_triage.web.auth as auth_mod
        from email_triage.web.auth import generate_otp, store_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)

        monkeypatch.setattr(auth_mod, "burn_otp_txn", lambda *_a, **_kw: False)
        resp = client.post("/login/verify", data={"email": email, "code": code},
                           follow_redirects=False)
        assert _no_session(resp)
        rows = [r[0] for r in db.execute(
            "SELECT outcome FROM auth_events WHERE event_type = 'login_otp' "
            "AND email = ?", (email,)).fetchall()]
        assert rows.count("denied:otp_already_used") == 1, rows
        assert "failure" not in rows and "success" not in rows, rows

        # The boundary (hipaa-sme NIT-1): once the code is spent, a later
        # replay no longer matches and writes a counting failure row.
        monkeypatch.undo()
        db.execute("UPDATE otp_codes SET used = 1 WHERE email = ?", (email,))
        db.commit()
        client.post("/login/verify", data={"email": email, "code": code},
                    follow_redirects=False)
        rows = [r[0] for r in db.execute(
            "SELECT outcome FROM auth_events WHERE event_type = 'login_otp' "
            "AND email = ?", (email,)).fetchall()]
        assert rows.count("denied:otp_already_used") == 1, rows
        assert "failure" in rows, rows

    def test_otp_success_with_a_failed_post_match_read_burns_the_code(
            self, client, db, regular_user, monkeypatch):
        """s2h DA gap 2: a read that raises after the code matched (the user
        lookup) must burn the code too, never leave a valid code unburned."""
        import email_triage.web.routers.ui.users as users_mod
        from email_triage.web.auth import generate_otp, store_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)

        def _locked(*_a, **_kw):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(users_mod, "get_user_by_email", _locked)
        try:
            resp = client.post("/login/verify", data={"email": email, "code": code},
                               follow_redirects=False)
        except sqlite3.OperationalError as exc:
            assert "database is locked" in str(exc), exc
            resp = None
        assert _no_session(resp)
        assert _otp_used(db, email) == [1], "a failed post-match read must still burn the code"
        monkeypatch.undo()
        _assert_spent_code_is_invalid(client, db, email, code)

    def test_otp_success_with_a_non_audit_failure_burns_the_code(
            self, client, db, regular_user, monkeypatch):
        """Any cause opens the oracle (hipaa-sme Q2): a DB error inside the
        success transaction (here the last_login stamp) burns the code too."""
        import email_triage.web.auth as auth_mod
        from email_triage.web.auth import generate_otp, store_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)

        def _locked(*_a, **_kw):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(auth_mod, "update_last_login_txn", _locked)
        try:
            resp = client.post("/login/verify", data={"email": email, "code": code},
                               follow_redirects=False)
        except sqlite3.OperationalError as exc:
            assert "database is locked" in str(exc), exc
            resp = None
        assert _no_session(resp), (resp.status_code, resp.text[:300])
        assert _otp_used(db, email) == [1], "a DB error must still burn the matched code"
        monkeypatch.undo()
        _assert_spent_code_is_invalid(client, db, email, code)

    @pytest.mark.audit_failure_expected(match="login_otp", count=1)
    def test_an_expired_otp_stays_burned_when_its_refusal_row_fails(
            self, client, db, regular_user, monkeypatch):
        from email_triage.web.auth import generate_otp, store_otp
        email = regular_user["email"]
        code = generate_otp()
        store_otp(db, email, code)
        db.execute("UPDATE otp_codes SET expires_at = '2000-01-01T00:00:00+00:00' "
                   "WHERE email = ?", (email,))
        db.commit()
        monkeypatch.setattr(webdb, "record_auth_event", _boom)
        resp = _post_or_raise(client, "/login/verify", data={"email": email, "code": code})
        assert _no_session(resp)
        assert _otp_used(db, email) == [1], "the tightening burn must not depend on the row"

    def test_recovery_code_success_with_a_failed_witness_burns_nothing(
            self, client, db, regular_user, monkeypatch):
        from email_triage.web.mfa import issue_recovery_codes, lookup_recovery_code
        code = issue_recovery_codes(
            db, user_id=regular_user["id"], count=1, actor_email="cli:tester")[0]
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        resp = _post_or_raise(client, "/auth/mfa/recovery",
                              json={"email": regular_user["email"], "code": code})
        assert _no_session(resp)
        assert lookup_recovery_code(db, user_id=regular_user["id"], code=code) is not None

    def test_operator_token_success_with_a_failed_witness_burns_nothing(
            self, client, db, regular_user, admin_user, monkeypatch):
        from email_triage.web.mfa import (
            issue_operator_recovery_token, lookup_operator_recovery_token,
        )
        token = issue_operator_recovery_token(
            db, target_user_id=regular_user["id"], operator_user_id=admin_user["id"],
            actor_email="cli:tester")
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        resp = _post_or_raise(client, "/auth/mfa/recovery", json={"token": token})
        assert _no_session(resp)
        assert lookup_operator_recovery_token(db, token=token) is not None

    @pytest.mark.audit_failure_expected(match="login_operator_recovery", count=1)
    def test_a_disabled_users_operator_token_stays_burned_when_its_row_fails(
            self, client, db, regular_user, admin_user, monkeypatch):
        from email_triage.web.mfa import (
            issue_operator_recovery_token, lookup_operator_recovery_token,
        )
        token = issue_operator_recovery_token(
            db, target_user_id=regular_user["id"], operator_user_id=admin_user["id"],
            actor_email="cli:tester")
        import email_triage.web.routers.auth_keys as ak
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (regular_user["id"],))
        db.commit()
        # The router binds record_auth_event at import; fail ITS refusal row.
        monkeypatch.setattr(ak, "record_auth_event", _boom)
        resp = _post_or_raise(client, "/auth/mfa/recovery", json={"token": token})
        assert _no_session(resp)
        assert lookup_operator_recovery_token(db, token=token) is None

    def test_webauthn_challenge_survives_a_failed_success_witness(
            self, db, regular_user, monkeypatch):
        """E6/E7 at the funnel: the challenge burn rides the success
        transaction, so a failed witness leaves the challenge in place."""
        from email_triage.db.users import (
            consume_webauthn_challenge_txn, store_webauthn_challenge,
        )
        store_webauthn_challenge(
            db, user_id=regular_user["id"], email=None, kind="authenticate",
            challenge=b"c" * 32, require_user_verification=True)
        with pytest.raises(RuntimeError, match=_DOWN):
            record_witnessed_state_change(
                db, operation="login_webauthn",
                state_txn=lambda c: consume_webauthn_challenge_txn(
                    c, user_id=regular_user["id"], email=None, kind="authenticate"),
                witness_txn=lambda c, _r: _boom(),
            )
        assert db.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0] == 1

    def test_webauthn_refusal_commits_the_burn_with_no_success_row(
            self, db, regular_user):
        """E6/E7 refusal: state_txn returns the verify error instead of
        raising, so the funnel commits the TIGHTENING burn and writes no
        success row (the route then writes the refusal row on its own)."""
        import email_triage.web.webauthn_auth as wa
        from email_triage.db.users import store_webauthn_challenge
        store_webauthn_challenge(
            db, user_id=regular_user["id"], email=None, kind="authenticate",
            challenge=b"c" * 32, require_user_verification=True)
        before = db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]

        def state(c):
            try:
                wa.finish_authentication_txn(
                    c, user_id=regular_user["id"], rp_id="testserver",
                    origin="https://testserver", response_json="{not json")
            except wa.WebAuthnAuthError as refused:
                return (None, refused)
            return (1, None)
        key_id, refused = record_witnessed_state_change(
            db, operation="login_webauthn", state_txn=state,
            witness_txn=lambda c, r: r[0] is not None and _boom(),
        )
        assert key_id is None and isinstance(refused, wa.WebAuthnAuthError)
        assert db.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0] == before


# ---------------------------------------------------------------------------
# hipaa MUST 9, E5/E8 compensating control. The dev-key and hw-key revokes now
# fail CLOSED (a broken chain refuses the revoke, reversing N-121's
# degraded-but-proceed). The compensating control is the emergency CLI user
# disable (punch 709), which commits on a broken chain. These prove it is
# enough: a disabled user's still-unrevoked keys are refused at login, before
# any signature or assertion is checked.
# ---------------------------------------------------------------------------


class TestDisabledUsersKeysAreRefused:
    def _disable(self, db, user):
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user["id"],))
        db.commit()

    def test_an_unrevoked_dev_key_of_a_disabled_user_is_refused(
            self, client, db, regular_user):
        from email_triage.db.users import add_dev_key_txn
        add_dev_key_txn(
            db, name="k", public_key="ssh-ed25519 AAAA", fingerprint="SHA256:n520-e5",
            email_allowlist=[regular_user["email"]], created_by_user_id=None,
            expires_at="2999-01-01T00:00:00+00:00")
        db.commit()
        self._disable(db, regular_user)
        from email_triage.web.routers.auth_keys import _DEV_KEYPAIR_CHALLENGE_COOKIE
        client.cookies.set(_DEV_KEYPAIR_CHALLENGE_COOKIE, "AAAAAAAAAAAAAAAAAAAAAA")
        r = client.post("/login/dev-keypair", data={
            "email": regular_user["email"], "signature": "AAAA",
            "fingerprint": "SHA256:n520-e5"}, follow_redirects=False)
        assert r.status_code == 403 and "Account disabled." in r.text
        assert _no_session(r)

    def test_an_unrevoked_hw_key_of_a_disabled_user_is_refused_even_with_a_valid_assertion(
            self, client, db, regular_user, monkeypatch):
        import json
        import email_triage.web.webauthn_auth as wa
        db.execute(
            "INSERT INTO hardware_keys (user_id, credential_id, public_key, sign_count, "
            "nickname, created_at) VALUES (?, ?, ?, 0, 'k', datetime('now'))",
            (regular_user["id"], b"cred-n520-e8", b"pub"))
        db.commit()
        self._disable(db, regular_user)
        client.app.state.config.webauthn.rp_id = "testserver"
        called: list[int] = []
        monkeypatch.setattr(wa, "finish_authentication_txn",
                            lambda *_a, **_kw: called.append(1) or 1)
        r = client.post(
            "/login/webauthn/finish",
            content=json.dumps({"email": regular_user["email"], "response": {"id": "x"}}),
            headers={"content-type": "application/json"})
        assert r.status_code == 404
        assert _no_session(r)
        assert called == [], "the disabled check must come before the assertion"
