"""Punch  — user verification is ENFORCED where it is requested.

Before this change, the hardware-key REGISTRATION finish and hardware-key LOGIN
finish called py_webauthn's ``verify_*_response`` without
``require_user_verification``. That argument defaults to False, so a response
whose authenticator skipped the PIN / biometric was accepted even when the
begin step had asked for it. ``config.webauthn.require_user_verification_for_admin``
changed the browser prompt and nothing the server checked.

``begin_*`` and ``finish_*`` are separate HTTP requests, so the fix stores the
requirement WITH the challenge (``webauthn_challenges.require_uv``, migration
v53) and the finish step enforces the stored value. A row with no stored value
(written before v53) is refused, not read as "not required".

This file pins it at three levels:

- STRUCTURE, over every file in ``src/email_triage`` (count-agnostic):
  every ``verify_registration_response`` / ``verify_authentication_response``
  call passes ``require_user_verification`` and never a literal False; every
  ``store_webauthn_challenge`` call passes it; every hardware-key
  ``begin_registration`` / ``begin_authentication`` call takes it from
  ``_webauthn_uv_required``; nothing reads the config key outside that funnel
  except the one config-save serializer, allow-listed by path. Each detector
  has a teeth test and a seen-count guard against a vacuous pass.
- BEHAVIOUR, through the real ``begin_*`` -> DB -> ``finish_*`` path with only
  the library verify call replaced by a recorder: the value the begin step was
  given is the value the finish step passes to the library, for both True and
  False, at both sites; a response whose user-verified flag is clear is refused
  when UV was required, even though the (replaced) library accepted it; a pre-v53
  row is refused before the library is called, with the stale-challenge error
  that the login route does not count as a failed login.
- LIBRARY CONTRACT: the installed py_webauthn still defaults the argument to
  False, which is why omitting it is not neutral.

What this file does NOT prove: that py_webauthn itself rejects a UV-clear
response when given True. The finish steps no longer depend on that alone: they
also check the returned ``user_verified`` flag, which these tests do exercise.
"""

from __future__ import annotations

import ast
import inspect
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests._pin_harness import annotate_parents, assert_pin_has_teeth, enclosing_fn, walk_src

VERIFY_FUNCS = {"verify_registration_response", "verify_authentication_response"}
HW_BEGIN_FUNCS = {"begin_registration", "begin_authentication"}
UV_KW = "require_user_verification"
FUNNEL = "_webauthn_uv_required"
CONFIG_KEY = "require_user_verification_for_admin"


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


# --- detectors: each takes a parsed tree and returns a list of offenders ---

def verify_calls_without_uv(tree: ast.AST) -> list[int]:
    """A verify call with no require_user_verification, or a literal False/None."""
    bad = []
    for call in _calls(tree, VERIFY_FUNCS):
        kw = _kw(call, UV_KW)
        if kw is None:
            bad.append(call.lineno)
        elif isinstance(kw.value, ast.Constant) and kw.value.value in (False, None):
            bad.append(call.lineno)
    return bad


def store_calls_without_uv(tree: ast.AST) -> list[int]:
    return [c.lineno for c in _calls(tree, {"store_webauthn_challenge"}) if _kw(c, UV_KW) is None]


def begin_calls_not_via_funnel(tree: ast.AST) -> list[int]:
    """A hardware-key begin call whose requirement is not _webauthn_uv_required(...)."""
    bad = []
    for call in _calls(tree, HW_BEGIN_FUNCS):
        kw = _kw(call, UV_KW)
        ok = (
            kw is not None
            and isinstance(kw.value, ast.Call)
            and _call_name(kw.value) == FUNNEL
        )
        if not ok:
            bad.append(call.lineno)
    return bad


# The one file allowed to carry the config value into a dict literal: the
# config-save serializer. Keyed by path so the exemption cannot travel.
_SERIALIZER_ALLOW = frozenset({"web/routers/ui/_shared.py"})


def _is_dict_value(node: ast.AST) -> bool:
    """A read whose parent is a dict literal and which is one of its values."""
    parent = getattr(node, "_ph_parent", None)
    return isinstance(parent, ast.Dict) and any(v is node for v in parent.values)


def config_key_reads_outside_funnel(tree: ast.AST, rel: str = "") -> list[int]:
    """A read of the config key that could DECIDE something, outside the funnel.
    A bare dict-value read is exempt only in an allow-listed serializer file."""
    annotate_parents(tree)
    return [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == CONFIG_KEY
        and enclosing_fn(node) != FUNNEL
        and not (rel in _SERIALIZER_ALLOW and _is_dict_value(node))
    ]


def _src_offenders(detector, subdir: str | None = None) -> list[str]:
    out = []
    for _path, rel, tree in walk_src(subdir):
        out += [f"{rel}:{line}" for line in detector(tree)]
    return out


class TestStructure:
    def test_every_verify_call_passes_uv(self):
        # Guard against a vacuous pass: the scan must SEE the known call sites.
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, VERIFY_FUNCS))
        assert seen > 0, "no verify_*_response call found in src; the pin sees nothing"
        assert _src_offenders(verify_calls_without_uv) == []

    def test_every_challenge_store_passes_uv(self):
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, {"store_webauthn_challenge"}))
        assert seen > 0
        assert _src_offenders(store_calls_without_uv) == []

    def test_every_hardware_key_begin_uses_the_funnel(self):
        seen = sum(1 for _p, _r, t in walk_src() for _c in _calls(t, HW_BEGIN_FUNCS))
        assert seen > 0
        assert _src_offenders(begin_calls_not_via_funnel) == []

    def test_config_key_is_read_only_in_the_funnel(self):
        seen = sum(
            1 for _p, _r, t in walk_src() for n in ast.walk(t)
            if isinstance(n, ast.Attribute) and n.attr == CONFIG_KEY
        )
        assert seen > 0, "config key read nowhere in src; the pin sees nothing"
        out = []
        for _path, rel, tree in walk_src():
            out += [f"{rel}:{line}" for line in config_key_reads_outside_funnel(tree, rel)]
        assert out == []

    def test_verify_detector_has_teeth(self):
        assert_pin_has_teeth(
            verify_calls_without_uv,
            "verify_authentication_response(credential=c, expected_challenge=x)\n",
            "verify_authentication_response(credential=c, require_user_verification=uv)\n",
        )
        assert_pin_has_teeth(
            verify_calls_without_uv,
            "wa.verify_registration_response(credential=c, require_user_verification=False)\n",
        )

    def test_store_detector_has_teeth(self):
        assert_pin_has_teeth(
            store_calls_without_uv,
            "store_webauthn_challenge(conn, user_id=1, email=None, kind='k', challenge=b'c')\n",
            "store_webauthn_challenge(conn, kind='k', challenge=b'c', require_user_verification=x)\n",
        )

    def test_begin_detector_has_teeth(self):
        assert_pin_has_teeth(
            begin_calls_not_via_funnel,
            "wa.begin_authentication(db, require_user_verification=cfg.x and u.get('role') == 'admin')\n",
            "wa.begin_authentication(db, require_user_verification=_webauthn_uv_required(config, u))\n",
        )
        assert_pin_has_teeth(begin_calls_not_via_funnel, "wa.begin_registration(db, user=u)\n")

    def test_config_key_detector_has_teeth(self):
        assert_pin_has_teeth(
            config_key_reads_outside_funnel,
            "def route():\n    return config.webauthn.require_user_verification_for_admin\n",
            "def _webauthn_uv_required(c, u):\n    return c.webauthn.require_user_verification_for_admin\n",
        )


    def test_dict_value_exemption_does_not_hide_a_decision(self):
        """The serializer exemption covers a bare value only. A decision that
        happens to sit inside a dict literal is still flagged."""
        # The dict-value exemption covers serialization only, not a decision
        # that happens to sit inside a dict.
        assert_pin_has_teeth(
            config_key_reads_outside_funnel,
            "def f(w, u):\n    return {'x': w.require_user_verification_for_admin and is_admin(u)}\n",
        )

    def test_serializer_exemption_is_path_bound(self):
        import ast as _ast
        src = "def f(w):\n    return {'x': w.require_user_verification_for_admin}\n"
        assert config_key_reads_outside_funnel(_ast.parse(src), "web/routers/ui/_shared.py") == []
        assert config_key_reads_outside_funnel(_ast.parse(src), "web/routers/other.py") == [2]

class TestLibraryContract:
    @pytest.mark.parametrize("name", sorted(VERIFY_FUNCS))
    def test_library_default_is_not_enforce(self, name):
        import webauthn

        param = inspect.signature(getattr(webauthn, name)).parameters.get(UV_KW)
        assert param is not None, f"py_webauthn {name} no longer takes {UV_KW}; re-read the library"
        assert param.default is False, (
            f"py_webauthn {name} default changed to {param.default!r}; the reasoning in "
            "punch #450 (omission == not enforced) needs re-checking"
        )


# --- behaviour ---

@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    from _db_tracking import track
    from email_triage.web.db import init_db

    return track(init_db(str(tmp_path / "test.db")))


@pytest.fixture
def user(db) -> dict:
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("admin@example.com", "Admin", "admin", datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return {"id": cur.lastrowid, "email": "admin@example.com", "name": "Admin", "role": "admin"}


class _Recorder:
    def __init__(self, result):
        self.calls: list[dict] = []
        self.result = result

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def _registration_result(user_verified: bool = True):
    return SimpleNamespace(
        credential_id=b"\xaa" * 32, credential_public_key=b"pk", sign_count=0, aaguid=None,
        user_verified=user_verified,
    )


def _assertion_for(cred_id: bytes) -> dict:
    from webauthn.helpers import bytes_to_base64url

    b64 = bytes_to_base64url(cred_id)
    return {
        "id": b64, "rawId": b64, "type": "public-key",
        "response": {"authenticatorData": "YWQ", "clientDataJSON": "Y2Q", "signature": "c2ln"},
    }


class TestFinishEnforcesWhatBeginAsked:
    @pytest.mark.parametrize("uv", [True, False])
    def test_registration(self, db, user, monkeypatch, uv):
        from email_triage.web import webauthn_auth as wa

        wa.begin_registration(
            db, user=user, rp_id="example.com", rp_name="ET", require_user_verification=uv,
        )
        rec = _Recorder(_registration_result())
        monkeypatch.setattr(wa, "verify_registration_response", rec)
        wa.finish_registration(
            db, user=user, rp_id="example.com", origin="https://example.com",
            response_json={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
            nickname="k",
        )
        assert [c[UV_KW] for c in rec.calls] == [uv]

    @pytest.mark.parametrize("uv", [True, False])
    def test_authentication(self, db, user, monkeypatch, uv):
        from email_triage.web import webauthn_auth as wa
        from email_triage.web.db_auth_helpers import add_hardware_key

        cred = b"\xcc" * 32
        add_hardware_key(
            db, user_id=user["id"], credential_id=cred, public_key=b"pk", sign_count=0,
            transports=[], aaguid=None, nickname="yk",
        )
        wa.begin_authentication(
            db, user_id=user["id"], email=user["email"], rp_id="example.com",
            require_user_verification=uv,
        )
        rec = _Recorder(SimpleNamespace(new_sign_count=1, user_verified=True))
        monkeypatch.setattr(wa, "verify_authentication_response", rec)
        wa.finish_authentication(
            db, user_id=user["id"], rp_id="example.com", origin="https://example.com",
            response_json=_assertion_for(cred),
        )
        assert [c[UV_KW] for c in rec.calls] == [uv]

    @pytest.mark.parametrize("site", ["register", "authenticate"])
    def test_uv_clear_response_is_refused_when_required(self, db, user, monkeypatch, site):
        """The library is replaced by a recorder that ACCEPTS; the finish step
        must still refuse a response whose user-verified flag is clear."""
        from email_triage.web import webauthn_auth as wa
        from email_triage.web.db_auth_helpers import add_hardware_key

        if site == "register":
            wa.begin_registration(
                db, user=user, rp_id="example.com", rp_name="ET", require_user_verification=True,
            )
            monkeypatch.setattr(wa, "verify_registration_response", _Recorder(_registration_result(False)))
            with pytest.raises(wa.WebAuthnAuthError, match="User verification was required"):
                wa.finish_registration(
                    db, user=user, rp_id="example.com", origin="https://example.com",
                    response_json={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
                    nickname="k",
                )
        else:
            cred = b"\xee" * 32
            add_hardware_key(
                db, user_id=user["id"], credential_id=cred, public_key=b"pk", sign_count=0,
                transports=[], aaguid=None, nickname="yk",
            )
            wa.begin_authentication(
                db, user_id=user["id"], email=user["email"], rp_id="example.com",
                require_user_verification=True,
            )
            monkeypatch.setattr(
                wa, "verify_authentication_response",
                _Recorder(SimpleNamespace(new_sign_count=1, user_verified=False)),
            )
            with pytest.raises(wa.WebAuthnAuthError, match="User verification was required"):
                wa.finish_authentication(
                    db, user_id=user["id"], rp_id="example.com", origin="https://example.com",
                    response_json=_assertion_for(cred),
                )

    @pytest.mark.parametrize("kind", ["register", "authenticate"])
    def test_pre_v53_row_is_refused_before_the_library_runs(self, db, user, monkeypatch, kind):
        from email_triage.web import webauthn_auth as wa
        from email_triage.web.db_auth_helpers import add_hardware_key

        cred = b"\xdd" * 32
        add_hardware_key(
            db, user_id=user["id"], credential_id=cred, public_key=b"pk", sign_count=0,
            transports=[], aaguid=None, nickname="yk",
        )
        # A row as a pre-v53 image wrote it: no require_uv value.
        db.execute(
            "INSERT INTO webauthn_challenges (user_id, email, kind, challenge, expires_at) "
            "VALUES (?, NULL, ?, ?, '9999-01-01T00:00:00+00:00')",
            (user["id"], kind, b"old"),
        )
        db.commit()
        rec_r = _Recorder(_registration_result())
        rec_a = _Recorder(SimpleNamespace(new_sign_count=1))
        monkeypatch.setattr(wa, "verify_registration_response", rec_r)
        monkeypatch.setattr(wa, "verify_authentication_response", rec_a)
        with pytest.raises(wa.WebAuthnStaleChallengeError, match="predates"):
            if kind == "register":
                wa.finish_registration(
                    db, user=user, rp_id="example.com", origin="https://example.com",
                    response_json={"id": "x", "rawId": "x", "type": "public-key", "response": {}},
                    nickname="k",
                )
            else:
                wa.finish_authentication(
                    db, user_id=user["id"], rp_id="example.com", origin="https://example.com",
                    response_json=_assertion_for(cred),
                )
        assert rec_r.calls == [] and rec_a.calls == []


class TestStaleChallengeIsNotAFailedLogin:
    def test_absent_challenge_is_not_the_stale_class(self, db, user):
        """An absent/expired challenge is attacker-reachable and must keep
        counting toward the login guard, so it must NOT be the stale class."""
        from email_triage.web import webauthn_auth as wa

        with pytest.raises(wa.WebAuthnAuthError) as ei:
            wa.finish_authentication(
                db, user_id=user["id"], rp_id="example.com", origin="https://example.com",
                response_json={"id": "x"},
            )
        assert not isinstance(ei.value, wa.WebAuthnStaleChallengeError)

    def test_login_route_records_but_does_not_count_a_stale_challenge(self):
        """In the login route, the stale handler comes before the generic one
        in the same try (a base handler listed first would swallow it), does
        NOT call record_login_failure, and DOES record a
        ``denied:stale_challenge`` auth event through safe_audit_write."""
        from tests._pin_harness import SRC_ROOT, parse_module

        tree = parse_module(SRC_ROOT / "web" / "routers" / "auth_keys.py")
        found = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            names = [ast.unparse(h.type) if h.type is not None else "" for h in node.handlers]
            if "wa.WebAuthnStaleChallengeError" not in names:
                continue
            found = True
            stale = names.index("wa.WebAuthnStaleChallengeError")
            assert "wa.WebAuthnAuthError" in names[stale + 1:], names
            calls = {
                _call_name(c) for c in ast.walk(node.handlers[stale]) if isinstance(c, ast.Call)
            }
            assert "record_login_failure" not in calls
            assert {"safe_audit_write", "record_auth_event"} <= calls, calls
            outcomes = {
                k.value.value for c in ast.walk(node.handlers[stale])
                if isinstance(c, ast.Call) and _call_name(c) == "record_auth_event"
                for k in c.keywords if k.arg == "outcome" and isinstance(k.value, ast.Constant)
            }
            assert outcomes == {"denied:stale_challenge"}, outcomes
        assert found, "no handler for WebAuthnStaleChallengeError in auth_keys.py"


class TestStaleRowIsRecordedNotCounted:
    def test_login_guard_counts_failure_rows_only(self, db, user):
        """The premise the stale handler rests on, measured: a
        ``denied:stale_challenge`` row lands in auth_events and does not move
        the login-guard counter, while an ordinary failure row does."""
        from email_triage.db.audit import record_auth_event
        from email_triage.web.login_guard import _count_failures_since

        since = "2000-01-01T00:00:00+00:00"
        record_auth_event(db, event_type="login_webauthn", email=user["email"],
                          user_id=user["id"], outcome="denied:stale_challenge")
        rows = db.execute(
            "SELECT outcome FROM auth_events WHERE email = ?", (user["email"],)
        ).fetchall()
        assert [r[0] for r in rows] == ["denied:stale_challenge"]
        assert _count_failures_since(db, column="email", value=user["email"], since_iso=since) == 0
        record_auth_event(db, event_type="login_webauthn", email=user["email"],
                          user_id=user["id"], outcome="failure")
        assert _count_failures_since(db, column="email", value=user["email"], since_iso=since) == 1


class TestRoutePredicate:
    @pytest.mark.parametrize(
        ("flag", "user", "expected"),
        [
            (False, {"role": "admin"}, False),
            (True, {"role": "admin"}, True),
            (True, {"role": "user"}, False),
            (True, None, False),
            (True, {"role": None}, False),
        ],
    )
    def test_truth_table(self, flag, user, expected):
        from email_triage.web.routers.auth_keys import _webauthn_uv_required

        cfg = SimpleNamespace(webauthn=SimpleNamespace(require_user_verification_for_admin=flag))
        assert _webauthn_uv_required(cfg, user) is expected


class TestMigration:
    def test_fresh_install_has_the_column(self, db):
        cols = {r[1] for r in db.execute("PRAGMA table_info(webauthn_challenges)")}
        assert "require_uv" in cols

    def test_v53_adds_the_column_to_a_pre_v53_table_and_is_idempotent(self):
        from email_triage.web.migrations import _v53_webauthn_challenges_add_require_uv as v53

        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE webauthn_challenges (id INTEGER PRIMARY KEY, user_id INTEGER, "
            "email TEXT, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO webauthn_challenges (user_id, kind, challenge, expires_at) "
            "VALUES (1, 'register', x'00', 'z')"
        )
        v53(conn)
        v53(conn)
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(webauthn_challenges)")}
        assert "require_uv" in cols
        # Nullable, no default: an existing row reads NULL, which finish refuses.
        assert cols["require_uv"][3] == 0 and cols["require_uv"][4] is None
        assert conn.execute("SELECT require_uv FROM webauthn_challenges").fetchone()[0] is None
        conn.close()
