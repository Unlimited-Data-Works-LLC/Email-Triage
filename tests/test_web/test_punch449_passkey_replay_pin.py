"""Punch  — the passkey login consumes a SERVER-SIDE single-use challenge.

Before this change, ``begin_passkey_authentication`` took no connection and
stored nothing: it returned the challenge BYTES, the login route put them in an
itsdangerous-signed cookie, and ``finish_passkey_authentication`` took the
challenge as a PARAMETER. Nothing was ever consumed. The cookie's ``max_age``
and the success path's ``delete_cookie`` are both instructions to a compliant
browser; a script replaying a captured (cookie, assertion) pair presents the
cookie value directly, and ``URLSafeSerializer`` does no age check on ``loads``.
The library's sign-count guard does not close it either — py_webauthn skips the
comparison entirely when both counters are 0, which is what every synced passkey
(iCloud Keychain, Google Password Manager) reports on every assertion, i.e. the
exact credential class this discoverable-credential flow exists for. So a
correctly-signed assertion was replayable for as long as the signature held.

The fix is the shape the hardware-key path already used: store at begin, delete
on read at finish. The cookie now carries only the row's id — a signed handle to
a single-use row — so the second presentation finds nothing to consume and is
refused before the library runs, regardless of signature validity and regardless
of ``sign_count``.

This file pins it at three levels:

- STRUCTURE, over every file in ``src/email_triage`` (count-agnostic, no count
  or site list): for every WebAuthn begin/finish pair, the challenge a
  ``verify_*_response`` call trusts comes from a ``consume_webauthn_challenge``
  result and never from a parameter; every ``generate_*_options`` challenge is
  handed to ``store_webauthn_challenge`` in the same function; and no function
  RETURNS the challenge bytes, which is what made a cookie-carried challenge
  expressible in the first place. Each detector has a teeth test both ways and a
  seen-count guard against a vacuous pass.
- BEHAVIOUR, through the real ``/login/webauthn/passkey/begin`` and ``/finish``
  routes with a TestClient, with only the library verify call replaced by a
  recorder that ACCEPTS: the first finish mints a session, and a second finish
  presenting the SAME cookie and the SAME assertion is refused — which is the
  claim, since the recorder would have accepted it again.
- AUDIT: the replay refusal writes an ``auth_events`` row through the login-guard
  failure funnel under its own reason slug, and the pre-v53 stale-challenge
  refusal writes ``outcome='denied:stale_challenge'`` through the emitter SSOT
  without counting as a failed login, the same way punch  records it on the
  hardware-key path.

What this file does NOT prove:

* that py_webauthn rejects a bad signature — the library call is replaced by a
  recorder in every behaviour test here, on purpose: the point is that the
  refusal does not DEPEND on signature validity.
* that a replay is distinguishable from an expiry. Both are "the row is not
  there", and the audit row says so (``reason='no_active_challenge'``); telling
  them apart would need a consumed-challenge tombstone, i.e. a schema change.
* anything about the userHandle cross-check — the assertions here carry no
  userHandle, so that branch is not exercised.
* the structural detectors do not follow a challenge through a helper call or a
  dict/list; they are per-function. A finish step that took its challenge from
  another module's return value would pass them (the behaviour tests are the
  backstop for the routes that exist).
"""

from __future__ import annotations

import ast
import json
from types import SimpleNamespace

import pytest

from tests._pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    innermost_fn_at_lineno,
    parse_module,
    walk_src,
)

VERIFY_FUNCS = {"verify_registration_response", "verify_authentication_response"}
OPTIONS_FUNCS = {"generate_registration_options", "generate_authentication_options"}
CONSUME = "consume_webauthn_challenge"
#: The single-use DELETE ... RETURNING lives in the non-committing ``_txn`` form
#: (N-520 step 2: the login funnel commits the burn with its witness row); the
#: committing form delegates to it. Both are the SAME consume SSOT, so a verify
#: may trust a challenge bound from either, and the SQL pins below read the body.
CONSUME_TXN = "consume_webauthn_challenge_txn"
STORE = "store_webauthn_challenge"
CHALLENGE_KW = "expected_challenge"


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _kw(node: ast.Call, name: str) -> ast.keyword | None:
    return next((k for k in node.keywords if k.arg == name), None)


def _calls(tree: ast.AST, names: set[str]):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in names:
            yield node


def _scope_of(tree: ast.AST, node: ast.AST) -> ast.AST:
    """The innermost function containing ``node``, or the module."""
    return innermost_fn_at_lineno(tree, node.lineno) or tree


def _names_bound_from_call(scope: ast.AST, fn_names: set[str]) -> set[str]:
    """Names assigned the RESULT of a call to one of ``fn_names`` in ``scope``."""
    out: set[str] = set()
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign):
            continue
        if isinstance(node.value, ast.Call) and _call_name(node.value) in fn_names:
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return out


def _is_challenge_of(node: ast.AST, holders: set[str]) -> bool:
    """``<holder>.challenge`` for one of ``holders``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "challenge"
        and isinstance(node.value, ast.Name)
        and node.value.id in holders
    )


def _names_bound_from_challenge_of(scope: ast.AST, holders: set[str]) -> set[str]:
    """Names assigned ``<holder>.challenge`` — the one-hop alias form."""
    out: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and _is_challenge_of(node.value, holders):
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return out


# --- detectors: each takes a parsed tree and returns a list of linenos --------

def verify_challenge_not_consumed(tree: ast.AST) -> list[int]:
    """A ``verify_*_response`` whose ``expected_challenge`` does not come from a
    consumed server-side row.

    Accepted: ``stored.challenge`` where ``stored`` was assigned from a
    ``consume_webauthn_challenge`` call in the same scope, or a name assigned
    that attribute. Everything else is flagged — in particular a bare parameter,
    which is how the caller used to carry a cookie-held challenge in."""
    bad = []
    for call in _calls(tree, VERIFY_FUNCS):
        scope = _scope_of(tree, call)
        consumed = _names_bound_from_call(scope, {CONSUME, CONSUME_TXN})
        aliases = _names_bound_from_challenge_of(scope, consumed)
        kw = _kw(call, CHALLENGE_KW)
        ok = kw is not None and (
            _is_challenge_of(kw.value, consumed)
            or (isinstance(kw.value, ast.Name) and kw.value.id in aliases)
        )
        if not ok:
            bad.append(call.lineno)
    return bad


def options_challenge_not_stored(tree: ast.AST) -> list[int]:
    """A ``generate_*_options`` call whose challenge is not handed to
    ``store_webauthn_challenge`` in the same scope."""
    bad = []
    for call in _calls(tree, OPTIONS_FUNCS):
        scope = _scope_of(tree, call)
        holders = _names_bound_from_call(scope, OPTIONS_FUNCS)
        stored = any(
            _is_challenge_of(kw.value, holders)
            for s in _calls(scope, {STORE})
            for kw in s.keywords
            if kw.arg == "challenge"
        )
        if not stored:
            bad.append(call.lineno)
    return bad


def challenge_bytes_returned(tree: ast.AST) -> list[int]:
    """A ``return`` that hands the freshly generated challenge BYTES back to the
    caller. The old passkey begin did exactly this, and a caller with the bytes
    is a caller that can hold them somewhere nothing consumes."""
    bad = []
    for call in _calls(tree, OPTIONS_FUNCS):
        scope = _scope_of(tree, call)
        holders = _names_bound_from_call(scope, OPTIONS_FUNCS)
        if not holders:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            if any(_is_challenge_of(sub, holders) for sub in ast.walk(node.value)):
                bad.append(node.lineno)
    return sorted(set(bad))


def _src_offenders(detector) -> list[str]:
    out = []
    for _path, rel, tree in walk_src():
        out += [f"{rel}:{line}" for line in detector(tree)]
    return out


class TestStructure:
    def test_every_verify_trusts_a_consumed_challenge(self):
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, VERIFY_FUNCS))
        assert seen > 0, "no verify_*_response call found in src; the pin sees nothing"
        assert _src_offenders(verify_challenge_not_consumed) == []

    def test_every_generated_challenge_is_stored(self):
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, OPTIONS_FUNCS))
        assert seen > 0, "no generate_*_options call found in src; the pin sees nothing"
        assert _src_offenders(options_challenge_not_stored) == []

    def test_no_function_returns_the_challenge_bytes(self):
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, OPTIONS_FUNCS))
        assert seen > 0
        assert _src_offenders(challenge_bytes_returned) == []

    def test_verify_detector_has_teeth(self):
        # The pre-fix shape: the challenge arrives as a parameter.
        assert_pin_has_teeth(
            verify_challenge_not_consumed,
            "def finish(conn, *, challenge):\n"
            "    return verify_authentication_response(expected_challenge=challenge)\n",
            "def finish(conn, *, challenge_id):\n"
            "    stored = consume_webauthn_challenge(conn, challenge_id=challenge_id)\n"
            "    return verify_authentication_response(expected_challenge=stored.challenge)\n",
        )
        # A consumed row whose challenge is aliased through one name is fine.
        assert_pin_has_teeth(
            verify_challenge_not_consumed,
            "def finish(conn):\n"
            "    stored = fetch_challenge(conn)\n"
            "    ch = stored.challenge\n"
            "    return verify_authentication_response(expected_challenge=ch)\n",
            "def finish(conn):\n"
            "    stored = consume_webauthn_challenge(conn)\n"
            "    ch = stored.challenge\n"
            "    return verify_authentication_response(expected_challenge=ch)\n",
        )
        # Omitting the argument entirely is flagged too.
        assert_pin_has_teeth(
            verify_challenge_not_consumed,
            "def finish(conn):\n"
            "    stored = consume_webauthn_challenge(conn)\n"
            "    return verify_registration_response(credential=c)\n",
        )

    def test_store_detector_has_teeth(self):
        assert_pin_has_teeth(
            options_challenge_not_stored,
            "def begin(rp_id):\n"
            "    opts = generate_authentication_options(rp_id=rp_id)\n"
            "    return options_to_json(opts)\n",
            "def begin(conn, rp_id):\n"
            "    opts = generate_authentication_options(rp_id=rp_id)\n"
            "    store_webauthn_challenge(conn, challenge=opts.challenge)\n"
            "    return options_to_json(opts)\n",
        )

    def test_return_detector_has_teeth(self):
        assert_pin_has_teeth(
            challenge_bytes_returned,
            "def begin(conn, rp_id):\n"
            "    opts = generate_authentication_options(rp_id=rp_id)\n"
            "    store_webauthn_challenge(conn, challenge=opts.challenge)\n"
            "    return options_to_json(opts), opts.challenge\n",
            "def begin(conn, rp_id):\n"
            "    opts = generate_authentication_options(rp_id=rp_id)\n"
            "    cid = store_webauthn_challenge(conn, challenge=opts.challenge)\n"
            "    return options_to_json(opts), cid\n",
        )


class TestPasskeyRouteShape:
    """The passkey login route separates the two refusal classes: the pre-v53
    stale challenge is recorded and NOT counted (punch 's rule), while the
    absent/consumed row IS counted, because a replay is attacker-reachable."""

    def test_no_challenge_handler_counts_and_precedes_the_base_handler(self):
        tree = parse_module(SRC_ROOT / "web" / "routers" / "auth_keys.py")
        found = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            names = [
                ast.unparse(h.type) if h.type is not None else "" for h in node.handlers
            ]
            if "wa.WebAuthnNoChallengeError" not in names:
                continue
            found = True
            i = names.index("wa.WebAuthnNoChallengeError")
            assert "wa.WebAuthnAuthError" in names[i + 1:], names
            handler = node.handlers[i]
            calls = {c for c in ast.walk(handler) if isinstance(c, ast.Call)}
            named = {_call_name(c) for c in calls}
            assert "record_login_failure" in named, named
            reasons = {
                k.value.value for c in calls
                if _call_name(c) == "record_login_failure"
                for k in c.keywords
                if k.arg == "reason" and isinstance(k.value, ast.Constant)
            }
            assert reasons == {"no_active_challenge"}, reasons
        assert found, "no handler for WebAuthnNoChallengeError in auth_keys.py"


# --- behaviour, through the real routes --------------------------------------

_PASSKEY_COOKIE = "et_passkey_challenge"


def _accepting_recorder():
    calls: list[dict] = []

    def _verify(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(new_sign_count=0, user_verified=True)

    _verify.calls = calls  # type: ignore[attr-defined]
    return _verify


def _assertion_for(cred_id: bytes) -> dict:
    from webauthn.helpers import bytes_to_base64url

    b64 = bytes_to_base64url(cred_id)
    return {
        "response": {
            "id": b64,
            "rawId": b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": "Y2Q",
                "authenticatorData": "YWQ",
                "signature": "c2ln",
                # No userHandle: the owner cross-check branch is not the subject
                # of this file, and omitting it keeps the fixture honest about
                # what is exercised.
                "userHandle": None,
            },
        },
    }


@pytest.fixture
def passkey_env(client, db, regular_user, monkeypatch):
    """A configured passkey surface: rp_id set, one registered credential, and
    the library verify call replaced by a recorder that ACCEPTS every time."""
    from email_triage.web import webauthn_auth as wa

    cred = b"\x49" * 32
    db.execute(
        "INSERT INTO hardware_keys "
        "(user_id, credential_id, public_key, sign_count, nickname, created_at) "
        "VALUES (?, ?, ?, 0, 'passkey', datetime('now'))",
        (regular_user["id"], cred, b"pub_bytes"),
    )
    db.commit()
    client.app.state.config.webauthn.rp_id = "testserver"
    client.app.state.config.webauthn.origin = "http://testserver"
    rec = _accepting_recorder()
    monkeypatch.setattr(wa, "verify_authentication_response", rec)
    return SimpleNamespace(cred=cred, recorder=rec, user=regular_user)


def _begin(client) -> str:
    """POST begin and return the RAW challenge cookie value.

    Read off the Set-Cookie header rather than the client's jar: the success
    path deletes the cookie, and a jar that honours that would make the replay
    test pass for the wrong reason (the attacker still holds the value)."""
    r = client.post("/login/webauthn/passkey/begin")
    assert r.status_code == 200, r.text
    val = r.cookies.get(_PASSKEY_COOKIE)
    assert val, f"begin set no {_PASSKEY_COOKIE} cookie: {r.headers}"
    return val


def _finish(client, cookie_val: str, assertion: dict):
    """POST finish, presenting the cookie EXPLICITLY — the attacker model."""
    return client.post(
        "/login/webauthn/passkey/finish",
        content=json.dumps(assertion),
        headers={
            "content-type": "application/json",
            "cookie": f"{_PASSKEY_COOKIE}={cookie_val}",
        },
    )


class TestReplayIsRefused:
    def test_the_second_presentation_of_the_same_assertion_is_refused(
        self, client, db, passkey_env,
    ):
        """MUST: a passkey assertion that succeeded once is refused on replay,
        even though the library call accepts it both times.

        The recorder stands in for py_webauthn and never fails, so a 200 on the
        second POST would mean nothing server-side refused the replay. Its call
        count is asserted too: the refusal must happen BEFORE the library."""
        cookie = _begin(client)
        assertion = _assertion_for(passkey_env.cred)

        first = _finish(client, cookie, assertion)
        assert first.status_code == 200, first.text
        assert first.json().get("ok") is True, first.text
        assert len(passkey_env.recorder.calls) == 1

        replay = _finish(client, cookie, assertion)
        assert replay.status_code == 403, (
            f"the replay was not refused: {replay.status_code} {replay.text}"
        )
        assert "no_active_challenge" in replay.text, replay.text
        assert len(passkey_env.recorder.calls) == 1, (
            "the replay reached the library; the refusal must precede verify"
        )

    def test_the_challenge_row_is_gone_after_one_finish(
        self, client, db, passkey_env,
    ):
        """MUST: the row is deleted on read, so single-use is a property of the
        store and not of the route remembering to delete a cookie."""
        cookie = _begin(client)
        rows = db.execute(
            "SELECT COUNT(*) AS n FROM webauthn_challenges WHERE kind = 'passkey'",
        ).fetchone()["n"]
        assert rows == 1, "begin stored no server-side passkey challenge"

        assert _finish(client, cookie, _assertion_for(passkey_env.cred)).status_code == 200
        after = db.execute(
            "SELECT COUNT(*) AS n FROM webauthn_challenges WHERE kind = 'passkey'",
        ).fetchone()["n"]
        assert after == 0, "the challenge row survived its finish step"

    def test_the_cookie_carries_a_row_handle_not_the_challenge(
        self, client, db, passkey_env,
    ):
        """MUST: the server does not take its record of the ceremony back
        FROM the client. The cookie's signed payload is the row id, and it names
        the row begin just wrote.

        NOT claimed: that the challenge never reaches the browser. WebAuthn
        requires the client to sign over it, so it is in the options JSON by
        construction. The property here is that the value the finish step TRUSTS
        comes from the server's own row, not from anything the client hands back."""
        from itsdangerous import URLSafeSerializer

        cookie = _begin(client)
        secret = client.app.state.session_secret
        payload = URLSafeSerializer(
            secret, salt="email-triage-passkey-challenge",
        ).loads(cookie)
        assert int(payload) > 0, payload
        row = db.execute(
            "SELECT id, challenge, require_uv FROM webauthn_challenges "
            "WHERE kind = 'passkey'",
        ).fetchone()
        assert int(payload) == int(row["id"])
        assert int(row["require_uv"]) == 1, "a passkey ceremony must store UV=required"

    def test_the_replay_refusal_is_audited_as_a_login_failure(
        self, client, db, passkey_env,
    ):
        """MUST: the refusal writes an auth_events row through the login-guard
        failure funnel, under a reason slug of its own, and it COUNTS (a replay
        is attacker-reachable, unlike the pre-v53 stale class)."""
        cookie = _begin(client)
        assertion = _assertion_for(passkey_env.cred)
        assert _finish(client, cookie, assertion).status_code == 200
        assert _finish(client, cookie, assertion).status_code == 403

        rows = db.execute(
            "SELECT outcome, detail FROM auth_events "
            "WHERE outcome = 'failure' ORDER BY id DESC",
        ).fetchall()
        details = [r["detail"] or "" for r in rows]
        assert any("no_active_challenge" in d for d in details), details


class TestStaleChallengeIsRecordedNotCounted:
    def test_a_pre_v53_passkey_row_is_refused_and_recorded(
        self, client, db, passkey_env,
    ):
        """MUST: a challenge row with no stored UV requirement (written by a
        pre-v53 image) is refused with 409 and recorded as
        ``denied:stale_challenge``, not as a counted login failure."""
        from itsdangerous import URLSafeSerializer

        cur = db.execute(
            "INSERT INTO webauthn_challenges (user_id, email, kind, challenge, expires_at) "
            "VALUES (NULL, NULL, 'passkey', ?, '9999-01-01T00:00:00+00:00')",
            (b"old-challenge",),
        )
        db.commit()
        cookie = URLSafeSerializer(
            client.app.state.session_secret, salt="email-triage-passkey-challenge",
        ).dumps(str(cur.lastrowid))

        r = _finish(client, cookie, _assertion_for(passkey_env.cred))
        assert r.status_code == 409, r.text
        assert "challenge_expired" in r.text, r.text
        assert passkey_env.recorder.calls == [], (
            "the stale row reached the library; it must be refused before verify"
        )
        outcomes = [
            row["outcome"] for row in db.execute(
                "SELECT outcome FROM auth_events ORDER BY id DESC",
            ).fetchall()
        ]
        assert "denied:stale_challenge" in outcomes, outcomes
        assert "failure" not in outcomes, (
            "a pre-v53 challenge must not count as a failed login"
        )
# --- panel fold: F16 (the refusal a site-count ratchet cannot see) -----------
#
# F16 moved `int(s.loads(cookie_val))` out of its try/except to satisfy the
# N-219 ratchet. That ratchet counts SITES. It cannot see whether the refusal
# the guard used to produce survived the move, and a refactor that let an
# unparseable handle fall through to -- or past -- the consume would turn a
# fail-closed authentication path fail-OPEN while the pin went green. These
# arms assert the refusal itself.


def _signed(secret: str, payload: str) -> str:
    from itsdangerous import URLSafeSerializer

    return URLSafeSerializer(
        secret, salt="email-triage-passkey-challenge",
    ).dumps(payload)


class TestAMalformedOrForgedHandleIsRefused:
    def test_a_forged_handle_is_refused_and_consumes_nothing(
        self, client, db, passkey_env,
    ):
        """MUST: a handle signed with the wrong secret is refused 400
        challenge_invalid, and the live challenge row is still there."""
        _begin(client)
        row = db.execute(
            "SELECT id FROM webauthn_challenges WHERE kind = 'passkey'",
        ).fetchone()
        forged = _signed("not-the-session-secret", str(row["id"]))

        r = _finish(client, forged, _assertion_for(passkey_env.cred))
        assert r.status_code == 400, r.text
        assert "challenge_invalid" in r.text, r.text
        assert passkey_env.recorder.calls == []
        still = db.execute(
            "SELECT COUNT(*) AS n FROM webauthn_challenges WHERE kind = 'passkey'",
        ).fetchone()["n"]
        assert still == 1, "a forged handle consumed the row"

    def test_a_correctly_signed_non_integer_handle_is_refused(
        self, client, db, passkey_env,
    ):
        """MUST: a payload this server signed but which is not an integer handle
        is refused 400 challenge_invalid -- the parse now sits OUTSIDE the
        try/except, so nothing but this assertion proves it still refuses."""
        _begin(client)
        bad = _signed(client.app.state.session_secret, "not-a-number")

        r = _finish(client, bad, _assertion_for(passkey_env.cred))
        assert r.status_code == 400, r.text
        assert "challenge_invalid" in r.text, r.text
        assert passkey_env.recorder.calls == []

    def test_a_garbled_cookie_is_refused_not_a_500(
        self, client, db, passkey_env,
    ):
        """MUST: raw garbage in the cookie is a 400, not an unhandled 500.

        This is the arm that the old `(BadSignature, ValueError, Exception)`
        tuple covered by accident and that narrowing to `BadData` had to keep:
        itsdangerous raises BadPayload (not BadSignature) for some malformed
        values, and BadPayload is not a subclass of BadSignature."""
        _begin(client)

        for junk in ("garbage", "a.b.c", "....", "%%%"):
            r = _finish(client, junk, _assertion_for(passkey_env.cred))
            assert r.status_code == 400, f"{junk!r} -> {r.status_code} {r.text}"
            assert "challenge_invalid" in r.text, (junk, r.text)
        assert passkey_env.recorder.calls == []


# --- panel fold: F15 (a single-use store proves it consumed exactly one row) --


class TestConsumeProvesASingleUse:
    def test_the_consume_ssot_deletes_and_returns_in_one_statement(self):
        """MUST (PD#1, structural): the consume funnel issues no SELECT against
        the challenge table and every statement it does issue is a DELETE with
        RETURNING, so the read and the delete cannot be interleaved.

        A SELECT-then-DELETE is single-use only while one process-wide lock
        serialises it; under workers>1 two consumers both see the row, which is
        a replay -- the exact defect 449 exists to close."""
        import ast as _ast

        from tests._pin_harness import SRC_ROOT, parse_module

        tree = parse_module(SRC_ROOT / "db" / "users.py")
        fn = next(
            n for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef)
            and n.name == CONSUME_TXN  # the body; the committing form delegates
        )
        sql = [
            s.value for s in _ast.walk(fn)
            if isinstance(s, _ast.Constant) and isinstance(s.value, str)
            and "webauthn_challenges" in s.value
        ]
        assert sql, "the consume funnel names no SQL against the table"
        joined = " ".join(sql).upper()
        assert "SELECT ID, CHALLENGE" not in joined, joined
        assert joined.count("DELETE FROM WEBAUTHN_CHALLENGES") >= 1, joined
        assert "RETURNING" in joined, joined

    def test_the_consume_ssot_refuses_a_multi_row_consume(self):
        """MUST: the funnel raises rather than returning a challenge when more
        than one row came back. Unreachable by construction today; it is the
        fail-CLOSED arm, so it is asserted structurally rather than driven."""
        import ast as _ast

        from tests._pin_harness import SRC_ROOT, parse_module

        tree = parse_module(SRC_ROOT / "db" / "users.py")
        fn = next(
            n for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef)
            and n.name == CONSUME_TXN  # the body; the committing form delegates
        )
        raisers = [
            n for n in _ast.walk(fn)
            if isinstance(n, _ast.Raise) and n.exc is not None
        ]
        assert raisers, "no fail-closed raise in the consume funnel"
        guards = [
            _ast.unparse(n.test) for n in _ast.walk(fn)
            if isinstance(n, _ast.If)
        ]
        assert any("len(rows) != 1" in g for g in guards), guards

    def test_a_second_consume_of_the_same_handle_returns_none(self, db):
        """MUST: the row is gone after one consume, so the second call returns
        None rather than the same challenge."""
        from email_triage.web.db_auth_helpers import (
            consume_webauthn_challenge,
            store_webauthn_challenge,
        )

        cid = store_webauthn_challenge(
            db, user_id=None, email=None, kind="passkey",
            challenge=b"ch", require_user_verification=True,
        )
        first = consume_webauthn_challenge(
            db, user_id=None, email=None, kind="passkey", challenge_id=cid,
        )
        assert first is not None and first.challenge == b"ch"
        second = consume_webauthn_challenge(
            db, user_id=None, email=None, kind="passkey", challenge_id=cid,
        )
        assert second is None

    def test_a_handle_cannot_name_an_owned_row(self, db, regular_user):
        """MUST: the challenge_id branch refuses a row that belongs to a user or
        an email, so a passkey handle cannot redeem somebody else's ceremony.

        Latent today -- only the passkey flow mints handles, and its rows are
        unowned -- which is why it is asserted rather than left to inspection.

        The owner is a REAL user: webauthn_challenges.user_id carries a foreign
        key to users(id), so a made-up id cannot even be inserted."""
        from email_triage.web.db_auth_helpers import (
            consume_webauthn_challenge,
            store_webauthn_challenge,
        )

        owned = store_webauthn_challenge(
            db, user_id=regular_user["id"], email=None, kind="passkey",
            challenge=b"someone-elses", require_user_verification=True,
        )
        assert consume_webauthn_challenge(
            db, user_id=None, email=None, kind="passkey", challenge_id=owned,
        ) is None
        survived = db.execute(
            "SELECT COUNT(*) AS n FROM webauthn_challenges WHERE id = ?",
            (owned,),
        ).fetchone()["n"]
        assert survived == 1, "the owned row was consumed by an unowned handle"

    def test_a_handle_cannot_cross_ceremony_kinds(self, db):
        """MUST: kind is matched, so a handle minted for one ceremony kind is not
        redeemable at another kind's finish step."""
        from email_triage.web.db_auth_helpers import (
            consume_webauthn_challenge,
            store_webauthn_challenge,
        )

        cid = store_webauthn_challenge(
            db, user_id=None, email=None, kind="passkey",
            challenge=b"ch", require_user_verification=True,
        )
        assert consume_webauthn_challenge(
            db, user_id=None, email=None, kind="register", challenge_id=cid,
        ) is None
