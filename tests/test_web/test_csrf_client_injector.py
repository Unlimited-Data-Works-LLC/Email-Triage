"""Step 1 of the CSRF-test-enforcement migration: the opt-in csrf_client
injector + the csrf.py by-route reject tracker. Nothing flipped — the shared
`client` fixture stays soft-launch.
"""

from __future__ import annotations


def _make_account(db, user_id: int, name: str) -> int:
    from email_triage.db.accounts import create_email_account
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "imap.example.invalid", "username": f"{name}@example.com"},
        hipaa=False, is_active=True,
    )


_GUARDED = "/profile/regulatory-clocks/create"


def _form(aid):
    return {"account_id": str(aid), "title": "Inj", "regime": "IRB",
            "duration_value": "0", "duration_unit": "working_day"}


class TestCsrfClientInjector:
    def test_csrf_client_injects_valid_token_under_enforce(
        self, csrf_client, user_cookies, regular_user, db,
    ):
        """The injecting client runs with enforce=True yet a guarded POST is NOT
        a CSRF 403 — the token is minted + injected transparently."""
        aid = _make_account(db, regular_user["id"], "c")
        r = csrf_client.post(_GUARDED, data=_form(aid), cookies=user_cookies,
                             follow_redirects=False)
        assert r.status_code != 403           # not a csrf rejection
        assert r.status_code == 303           # the route's success redirect

    def test_enforce_on_without_token_is_403(
        self, raw_client, app, user_cookies, regular_user, db,
    ):
        """Proves the injector is load-bearing: the SAME route, enforce on, with
        the PLAIN (non-injecting) client + no token => 403 csrf_token_invalid."""
        app.state.csrf_enforce = True
        aid = _make_account(db, regular_user["id"], "c")
        r = raw_client.post(_GUARDED, data=_form(aid), cookies=user_cookies,
                            follow_redirects=False)
        assert r.status_code == 403
        assert "csrf_token_invalid" in r.text

    def test_injector_is_idempotent_when_header_present(
        self, csrf_client, user_cookies, regular_user, db,
    ):
        """If the caller already set X-CSRF-Token, the injector does NOT replace
        it (so test_csrf.py's hand-rolled negative tests stay intact). A garbage
        header therefore still 403s."""
        aid = _make_account(db, regular_user["id"], "c")
        r = csrf_client.post(
            _GUARDED, data=_form(aid), cookies=user_cookies,
            headers={"X-CSRF-Token": "garbage-not-a-real-token"},
            follow_redirects=False)
        assert r.status_code == 403           # injector didn't overwrite it

    def test_no_session_cookie_injects_nothing(self, csrf_client, db):
        """No session => no token minted; the anonymous short-circuit applies
        (the request reaches the handler, which handles auth — not a csrf 403)."""
        r = csrf_client.post(_GUARDED, data={"title": "x"},
                             follow_redirects=False)
        assert r.status_code != 403           # not rejected by CSRF


class TestCsrfRejectTracker:
    def test_normalize_redacts_ids_and_keys_by_shape(self):
        from email_triage.web.csrf import _normalize_route
        assert _normalize_route("POST", "/accounts/5/save") == "POST /accounts/:id/save"
        assert _normalize_route("POST", "/accounts/123") == "POST /accounts/:id"
        assert _normalize_route("POST", "/profile/x/create") == "POST /profile/x/create"

    def test_record_report_reset(self):
        from email_triage.web.csrf import (
            csrf_reject_report, record_csrf_reject, reset_csrf_reject_tracker,
        )
        reset_csrf_reject_tracker()
        record_csrf_reject("POST", "/accounts/5/save", enforced=False)
        record_csrf_reject("POST", "/accounts/9/save", enforced=False)  # same shape
        record_csrf_reject("DELETE", "/accounts/2", enforced=True)
        rep = csrf_reject_report()
        assert rep["would-reject POST /accounts/:id/save"] == 2   # ids collapsed
        assert rep["rejected DELETE /accounts/:id"] == 1
        reset_csrf_reject_tracker()
        assert csrf_reject_report() == {}

    def test_middleware_records_a_would_reject(
        self, raw_client, app, user_cookies, regular_user, db,
    ):
        """End-to-end: a token-less POST under SOFT-LAUNCH lands in the
        process-global tracker (the migration attention log)."""
        from email_triage.web.csrf import (
            csrf_reject_report, reset_csrf_reject_tracker,
        )
        app.state.csrf_enforce = False        # soft-launch => "would-reject"
        reset_csrf_reject_tracker()
        aid = _make_account(db, regular_user["id"], "c")
        raw_client.post(_GUARDED, data=_form(aid), cookies=user_cookies,
                        follow_redirects=False)  # plain client, no token
        rep = csrf_reject_report()
        assert any("would-reject" in k and "regulatory-clocks/create" in k
                   for k in rep), rep
