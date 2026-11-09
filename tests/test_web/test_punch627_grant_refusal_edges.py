"""Panel P (punch 627, register N-611): the credential-grant refusal edges.

F3 (PD-17): both refusal edges of ``POST /admin/dev-keys/add`` render (no 500;
   the duplicate edge used ``_html`` before the only import of it, in the
   other branch) and each leaves its denied row.
F4: a gap row means the WITNESS failed, never a refused business write. A
   racing duplicate dev key comes back from the funnel as a witnessed refusal
   with no ``audit_gap_events`` row; ``store_api_key`` leaves a gap row when its
   witness fails and none when its insert is refused.
F5: the API answers 503 and never returns the key.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from email_triage.db.audit import DEV_KEY_DUPLICATE, GrantRefused, record_dev_key_registration
from email_triage.web import dev_keypair as dk
from email_triage.web.auth import (
    ApiKeyGrantError,
    generate_api_key,
    hash_api_key,
    store_api_key,
    verify_api_key,
)


def _pubkey() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH).decode() + " test@host"


def _denied(db, outcome: str) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = 'dev_key_registered' "
        "AND outcome = ?", (outcome,)).fetchone()[0]


def _gaps(db, helper: str | None = None) -> int:
    if helper is None:
        return db.execute("SELECT COUNT(*) FROM audit_gap_events").fetchone()[0]
    return db.execute(
        "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = ?", (helper,)
    ).fetchone()[0]


def _add(csrf_client, admin_cookies, public_key: str, allowlist: str):
    return csrf_client.post(
        "/admin/dev-keys/add",
        data={"name": "laptop", "public_key": public_key, "ttl": "1d",
              "email_allowlist": allowlist},
        cookies=admin_cookies, follow_redirects=False,
    )


class TestRenderedRefusalEdges:
    def test_an_unknown_allowlist_email_is_refused_and_audited(
            self, csrf_client, admin_cookies, admin_user, db):
        r = _add(csrf_client, admin_cookies, _pubkey(), "nobody@example.invalid")
        assert r.status_code == 400, r.text
        assert "doesn&#x27;t match a known user" in r.text or "doesn't match a known user" in r.text
        assert _denied(db, "denied:unknown_allowlist_email") == 1
        assert db.execute("SELECT COUNT(*) FROM dev_keys").fetchone()[0] == 0

    def test_a_duplicate_fingerprint_is_refused_and_audited(
            self, csrf_client, admin_cookies, admin_user, db):
        key = _pubkey()
        first = _add(csrf_client, admin_cookies, key, admin_user["email"])
        assert first.status_code == 303, first.text
        gaps = _gaps(db)
        r = _add(csrf_client, admin_cookies, key, admin_user["email"])
        assert r.status_code == 409, r.text
        assert "Fingerprint already registered" in r.text
        assert _denied(db, "denied:duplicate_fingerprint") == 1
        assert _gaps(db) == gaps
        assert db.execute("SELECT COUNT(*) FROM dev_keys").fetchone()[0] == 1


class TestGapRowsMeanALostWitness:
    def _grant(self, db, admin_user, key: str):
        fp = dk.fingerprint(dk.parse_ssh_ed25519_pubkey(key))
        return record_dev_key_registration(
            db, name="race", public_key=key, fingerprint=fp,
            email_allowlist=[admin_user["email"]],
            created_by_user_id=admin_user["id"], expires_at="2099-01-01T00:00:00Z",
            email=admin_user["email"], ip=None,
        )

    def test_a_racing_duplicate_dev_key_is_a_witnessed_refusal_without_a_gap(
            self, db, admin_user):
        """The route's pre-check is bypassed, as a concurrent grant would."""
        key = _pubkey()
        assert isinstance(self._grant(db, admin_user, key), int)
        gaps = _gaps(db)
        got = self._grant(db, admin_user, key)
        assert got is DEV_KEY_DUPLICATE and isinstance(got, GrantRefused)
        assert _denied(db, "denied:duplicate_fingerprint") == 1
        assert _gaps(db) == gaps
        assert db.execute("SELECT COUNT(*) FROM dev_keys").fetchone()[0] == 1

    def test_a_failed_dev_key_denied_witness_still_leaves_a_gap(
            self, db, admin_user, monkeypatch):
        """Teeth for the rule: the refusal's own witness failing IS a lost
        audit row, so @audit_emitter records it."""
        import email_triage.db.audit as audit_mod
        key = _pubkey()
        self._grant(db, admin_user, key)
        gaps = _gaps(db, "record_dev_key_registration")

        def boom(*a, **kw):
            raise RuntimeError("witness down")

        monkeypatch.setattr(audit_mod, "record_auth_event_txn", boom)
        with pytest.raises(RuntimeError, match="witness down"):
            self._grant(db, admin_user, key)
        assert _gaps(db, "record_dev_key_registration") == gaps + 1

    def test_store_api_key_leaves_a_gap_when_its_witness_fails(
            self, db, admin_user, monkeypatch):
        import email_triage.db.audit as audit_mod

        def boom(*a, **kw):
            raise RuntimeError("audit storage exploded")

        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", boom)
        gaps = _gaps(db, "store_api_key")
        raw = generate_api_key()
        with pytest.raises(ApiKeyGrantError, match="audit storage exploded"):
            store_api_key(db, hash_api_key(raw), "w", admin_user["id"],
                          actor_user_id=admin_user["id"], source="ui")
        assert _gaps(db, "store_api_key") == gaps + 1
        assert verify_api_key(db, raw) is None

    def test_store_api_key_leaves_no_gap_when_its_insert_is_refused(self, db, admin_user):
        db.execute(
            "CREATE TEMP TRIGGER refuse_api_key BEFORE INSERT ON api_keys "
            "BEGIN SELECT RAISE(ABORT, 'refused by test'); END")
        try:
            gaps = _gaps(db)
            with pytest.raises(ApiKeyGrantError, match="refused by test"):
                store_api_key(db, hash_api_key(generate_api_key()), "r",
                              admin_user["id"], source="ui")
            assert _gaps(db) == gaps
        finally:
            db.execute("DROP TRIGGER IF EXISTS refuse_api_key")


def test_the_api_answers_503_and_never_returns_the_key(
        client, db, admin_user, admin_cookies, monkeypatch):
    import email_triage.db.audit as audit_mod

    def boom(*a, **kw):
        raise RuntimeError("audit storage exploded")

    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", boom)
    r = client.post("/api/keys", json={"name": "k"}, cookies=admin_cookies)
    assert r.status_code == 503, r.text
    body = r.json()
    assert "key" not in body
    assert "et_" not in r.text and "nothing was granted" in r.text
    assert "the key or its audit record could not be written" in r.text
    assert db.execute("SELECT COUNT(*) FROM api_keys WHERE name = 'k'").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# Panel P G3: a refusal is never read by truth value
# ---------------------------------------------------------------------------

import ast  # noqa: E402

from _pin_harness import HOP_DISPATCHERS, assert_pin_has_teeth, hop_target, innermost_fn_at_lineno, iter_src_files, parse_module, relpath  # noqa: E402


def test_a_refusal_is_falsy():
    assert not DEV_KEY_DUPLICATE
    assert DEV_KEY_DUPLICATE.outcome == "denied:duplicate_fingerprint"


def _refusal_funnels(trees) -> set[str]:
    """Every src function whose return annotation names GrantRefused."""
    out = set()
    for _path, tree in trees:
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.returns is not None:
                if "GrantRefused" in ast.unparse(fn.returns):
                    out.add(fn.name)
    return out


def _call_name(n) -> str | None:
    if not isinstance(n, ast.Call):
        return None
    f = n.func
    return f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)


def _truth_tests(scope) -> set[str]:
    """Names used directly as a truth value in ``scope``."""
    out = set()
    for n in ast.walk(scope):
        tests = []
        if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            tests.append(n.test)
        elif isinstance(n, ast.BoolOp):
            tests.extend(n.values)
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            tests.append(n.operand)
        out |= {t.id for t in tests if isinstance(t, ast.Name)}
    return out


def _isinstance_checked(scope) -> set[str]:
    """Names checked against the refusal type. A comparison with ``None`` checks
    nothing: a ``GrantRefused`` is a ``str``, never ``None`` (panel Q DA S3)."""
    out = set()
    for n in ast.walk(scope):
        if _call_name(n) == "isinstance" and n.args and isinstance(n.args[0], ast.Name):
            out.add(n.args[0].id)
        elif isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and any(
                isinstance(op, (ast.Is, ast.IsNot)) for op in n.ops) and not any(
                isinstance(c, ast.Constant) and c.value is None for c in n.comparators):
            out.add(n.left.id)
    return out


def _calls_funnel(node, funnels) -> bool:
    """A funnel call, direct or through a dispatcher (panel P fold 3 H2, PD-2):
    ``funnel(...)``, ``db_call(funnel, ...)``, ``asyncio.to_thread(funnel, ...)``,
    each possibly awaited. The dispatched funnel may be a bare name or an attribute
    (``db_call(audit.funnel, ...)``). The dispatcher set is N-520's
    ``HOP_DISPATCHERS`` (PD-6: reused, not re-rolled)."""
    if isinstance(node, ast.Await):
        node = node.value
    name = _call_name(node)
    if name in funnels:
        return True
    hop = hop_target(node, HOP_DISPATCHERS)  # punch 672: lambda, partial, executor too
    return hop is not None and hop.name in funnels


def _bound_names(n) -> list[str] | None:
    """Names an assignment binds, or None when it is not an assignment."""
    if isinstance(n, ast.Assign):
        return [t.id for t in n.targets if isinstance(t, ast.Name)]
    if isinstance(n, (ast.AnnAssign, ast.NamedExpr)):
        return [n.target.id] if isinstance(n.target, ast.Name) else []
    return None


def _refusal_call_offenders(trees, funnels) -> list[str]:
    out = []
    for path, tree in trees:
        for n in ast.walk(tree):
            names = _bound_names(n)
            if names is None or n.value is None or not _calls_funnel(n.value, funnels):
                continue
            scope = innermost_fn_at_lineno(tree, n.lineno) or tree
            if not names:
                out.append(f"{path}:{n.lineno} (result not bound to a name)")
                continue
            for name in names:
                if name in _truth_tests(scope) or name not in _isinstance_checked(scope):
                    out.append(f"{path}:{n.lineno} ({name})")
        for n in ast.walk(tree):
            # A funnel call used directly as a truth value, never bound.
            for t in ([n.test] if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)) else []):
                if _calls_funnel(t, funnels):
                    out.append(f"{path}:{n.lineno} (called as a truth value)")
    return out


def _src_trees():
    return [(relpath(p), t) for p in iter_src_files() if (t := parse_module(p)) is not None]


def test_every_refusal_funnel_caller_checks_isinstance():
    trees = _src_trees()
    funnels = _refusal_funnels(trees)
    assert "record_dev_key_registration" in funnels, funnels
    calls = [n for _, t in trees for n in ast.walk(t) if _call_name(n) in funnels]
    assert calls, "no src caller of a GrantRefused funnel: the scan sees nothing"
    assert _refusal_call_offenders(trees, funnels) == []


@pytest.mark.parametrize("bad", [
    "def f(db):\n    k = record_dev_key_registration(db)\n    if k:\n        return k\n",
    "def f(db):\n    k = record_dev_key_registration(db)\n    return k or None\n",
    "def f(db):\n    if record_dev_key_registration(db):\n        pass\n",
    "def f(db):\n    k = record_dev_key_registration(db)\n    return k\n",
    # fold 3 H2: through a dispatcher, awaited or not
    "async def f(db):\n    k = await db_call(record_dev_key_registration, db)\n"
    "    if k:\n        return k\n",
    "async def f(db):\n    k = await asyncio.to_thread(record_dev_key_registration, db)\n"
    "    return k or None\n",
    "def f(db):\n    k: int = db_call(record_dev_key_registration, db)\n    return k\n",
    "async def f(db):\n    if await db_call(record_dev_key_registration, db):\n        pass\n",
    # attribute-form dispatch arg (db_call(audit.funnel, ...))
    "async def f(db):\n    k = await db_call(audit.record_dev_key_registration, db)\n"
    "    return k\n",
    # panel Q db S2: every hop in N-520's HOP_DISPATCHERS reaches the funnel
    "async def f(db):\n    k = await db_call_async(record_dev_key_registration, db)\n    return k\n",
    "async def f(db):\n    k = await run_in_threadpool(audit.record_dev_key_registration, db)\n    return k\n",
    # panel Q DA S3: a GrantRefused is a str, never None, so a None comparison checks nothing
    "def f(db):\n    k = record_dev_key_registration(db)\n    if k is not None:\n        return k\n",
    "def f(db):\n    k = record_dev_key_registration(db)\n    if k is None:\n        return None\n    return k\n",
    "def f(db):\n    k = record_dev_key_registration(db)\n    if k != None:\n        return k\n",
    "def f(db):\n    k = record_dev_key_registration(db)\n    if k == None:\n        return None\n    return k\n",
])
def test_the_refusal_call_pin_has_teeth(bad):
    good = ("def f(db):\n    k = record_dev_key_registration(db)\n"
            "    if isinstance(k, GrantRefused):\n        return None\n    return k\n")
    assert_pin_has_teeth(
        lambda t: _refusal_call_offenders([("x.py", t)], {"record_dev_key_registration"}),
        bad, good)


@pytest.mark.parametrize(("src", "checked"), [
    ("if k is not None:\n    pass\n", set()),
    ("if k is None:\n    pass\n", set()),
    ("if k != None:\n    pass\n", set()),
    ("if k == None:\n    pass\n", set()),
    ("if k is _SENTINEL:\n    pass\n", {"k"}),
    ("if isinstance(k, GrantRefused):\n    pass\n", {"k"}),
])
def test_a_none_comparison_is_not_a_refusal_check(src, checked):
    assert _isinstance_checked(ast.parse(src)) == checked
