"""Behavioural pins for `GET /health/runtime-deps` and the admin card render.

Two things are pinned here that a structural pin cannot see (PD-17 — test the
RENDERED view and the LIVE route, not just the model):

1. **The route's auth tier and its CLOSED key set.** The safety argument for this
   route is payload narrowness plus the admin tier: a list of installed package
   VERSIONS is a targeting map, which is a different object from
   ``/health/build``'s single opaque sha. If a field creeps in, or the tier
   loosens, the argument silently stops being true while every other test passes.

2. **The admin AI-backends render touches nothing** (N-525 / punch 540). Opening
   that tab used to call ``is_runtime_ready()`` → ``add_runtime_to_sys_path()`` →
   ``sys.path.insert(0, <volume>/site-packages)`` in the SERVING process,
   regardless of whether the embedding feature was configured, with nothing ever
   removing the entry. A unit test of the probe cannot catch that; only driving
   the real handler can.

THE FIXTURE IS THE LOAD-BEARING PART of (2). With no valid ``INSTALLED.json`` in
the prefix, post-N-524 ``add_runtime_to_sys_path`` refuses anyway — so a test
built on a bare directory would observe "sys.path unchanged" whether or not the
render was ever fixed, and would read green forever. These tests therefore build
a VERIFIED prefix (``make_verified_prefix``), which is the only state in which
the pre-fix code WOULD have mutated sys.path. Mutation-checked by restoring the
``is_runtime_ready()`` call in ``admin.py``: the render test then goes RED.

ONLY the deploy host CAN PROVE: that a real pip run against the real manifest produces
exactly one dist-info per name, and which manifest names the image's own
site-packages actually satisfies. Everything here runs against a synthesised
prefix.
"""

from __future__ import annotations

import sys

import pytest

from _embedding_runtime_fixture import make_stale_prefix, make_verified_prefix
from _pin_harness import PHI_KEY_NEEDLES, phi_shaped_keys

from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    generate_api_key,
    hash_api_key,
)


def _issue_api_key(db, user_id: int, name: str = "cve-arc") -> str:
    """Mint a real API key for ``user_id`` and return the plaintext."""
    key = generate_api_key()
    db.execute(
        "INSERT INTO api_keys (user_id, name, key_hash, created_at) "
        "VALUES (?, ?, ?, datetime('now'))",
        (user_id, name, hash_api_key(key)),
    )
    db.commit()
    return key


@pytest.fixture
def verified_prefix(tmp_path, monkeypatch):
    """A prefix the drift gate accepts, with sys.path restored afterwards."""
    before = list(sys.path)
    prefix, site, manifest = make_verified_prefix(tmp_path, monkeypatch)
    try:
        yield prefix, site, manifest
    finally:
        sys.path[:] = before


# ---------------------------------------------------------------------------
# The route: auth tier
# ---------------------------------------------------------------------------

def test_unauthenticated_bearer_client_gets_401(client):
    resp = client.get(
        "/health/runtime-deps",
        headers={"Authorization": "Bearer not-a-real-key"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, resp.text
    assert "distributions" not in resp.text


def test_unauthenticated_browser_client_is_redirected(client):
    resp = client.get("/health/runtime-deps", follow_redirects=False)
    assert resp.status_code in (303, 401), resp.status_code
    assert "distributions" not in resp.text


def test_a_non_admin_api_key_is_refused(client, db, regular_user):
    """THE tier pin. /health/build is deliberately open to any authenticated
    principal because a 40-char sha is one opaque identifier. A package-version
    inventory is not that object — it tells an attacker which exploit to pick —
    so the lowest role that answers the question is admin.

    If this ever starts returning 200, the route has quietly become readable by
    every API client in the install.
    """
    key = _issue_api_key(db, regular_user["id"])
    resp = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 403, resp.text
    assert "distributions" not in resp.text


def test_an_admin_api_key_is_accepted(client, db, admin_user):
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    resp = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 200, resp.text
    assert "distributions" in resp.json()


# ---------------------------------------------------------------------------
# The route: closed payload
# ---------------------------------------------------------------------------

def test_response_carries_exactly_the_promised_key_set(client, db, admin_user):
    """The load-bearing pin — the closed set IS the security argument.

    The set was published to cve-arc in HANDOVER.md (RESPONSE 2026-09-29 16:05).
    A new key must be argued for here rather than arriving by drift.
    """
    from email_triage.web.routers.health import _RUNTIME_DEPS_KEYS

    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    body = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    ).json()

    assert set(body) == set(_RUNTIME_DEPS_KEYS), (
        f"/health/runtime-deps must return EXACTLY this closed set; got "
        f"{sorted(body)}"
    )
    forbidden = {
        # /health/detail's body — the object the 2026-06-13 review protected.
        "status", "degraded", "audit_failures", "csrf_rejects", "tasks",
        "watchers_failing", "ingestion", "schema_version", "uptime_secs",
        "last_triage", "baa_expired", "retry_dead", "office365_push", "db",
        # install-state row fields: a path, an error message, a timestamp and
        # attempt counts are operational footprint, not an inventory.
        "runtime_deps_path", "current_file", "last_error_msg",
        "last_error_class", "attempt_count", "installed_at",
    }
    assert not (forbidden & set(body)), (
        f"forbidden field leaked: {sorted(forbidden & set(body))}"
    )


def test_response_carries_no_filesystem_paths(
    client, db, admin_user, verified_prefix,
):
    """A path is infrastructure detail, and the point of the route is versions.

    Asserted against a prefix under a tmp dir so a leaked path would be visible
    as that directory's name rather than as a plausible-looking constant.
    """
    prefix, _site, _manifest = verified_prefix
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    resp = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 200, resp.text
    raw = resp.text
    assert str(prefix) not in raw
    assert prefix.name not in raw
    assert "site-packages" not in raw


def test_the_scan_reports_the_prefix_contents(
    client, db, admin_user, verified_prefix,
):
    """The answer comes from DISK, not from the install-state row.

    The row records an intention; the volume holds what would import. They
    disagree exactly when it matters (a half-finished install, a restored
    backup, an image rebuilt against a newer manifest), and the row is what every
    pre-existing surface already read.
    """
    _prefix, _site, _manifest = verified_prefix
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    body = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    ).json()
    assert body["runtime_deps_present"] is True
    assert body["distributions"]["fake-a"] == ["1.0"]
    assert body["distributions"]["fake-b"] == ["2.0"]
    assert body["installed_manifest_sha256"], "the marker's sha must surface"
    assert body["image_manifest_sha256"], "the image's sha must surface"
    assert body["python"] == (
        f"{sys.version_info.major}.{sys.version_info.minor}"
    )


def test_the_live_payload_is_phi_free_and_shaped(
    client, db, admin_user, verified_prefix,
):
    """The PHI-free pin the container health-endpoint standard requires, on the
    LIVE response — the structural arm reads the source, this reads what ships.

    Both halves are needed: a structural pin cannot see a key added by a wrapper
    or a middleware, and a behavioural one cannot see a key on a branch no test
    exercises.
    """
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    body = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    ).json()

    # The SHARED predicate, not a local copy — the structural arm in
    # tests/test_n524_runtime_deps_ssot_pin.py asks the same question of the
    # source, and two needle lists would drift (PD-5).
    offenders = phi_shaped_keys(body.keys())
    assert not offenders, (
        f"PHI / user-identity-shaped contract key in the payload: {offenders}"
    )

    # SHAPE, not needles, for the nested package map — that is what actually
    # forecloses a PHI field arriving there: a PHI value cannot be a version
    # string in a canonical-package-name map.
    dists = body["distributions"]
    assert isinstance(dists, dict)
    for name, versions in dists.items():
        assert isinstance(name, str) and name, name
        assert name == name.lower(), f"{name} is not PEP-503 canonical"
        assert "_" not in name, f"{name} is not PEP-503 canonical"
        assert isinstance(versions, list), name
        for version in versions:
            assert isinstance(version, str), (name, version)

    # No nested object anywhere else: a dict or list of dicts under a contract
    # key is how a record field would smuggle a person in.
    # Punch 734 / 647: the inventory keys nest, so each gets its EXACT shape:
    # fixed field names, every leaf a string (or None where the contract says
    # "unknown"). A PHI field has nowhere to land in a closed record shape.
    def _str_or_none(x):
        return x is None or isinstance(x, str)

    os_release = body["os_release"]
    assert os_release is None or (
        set(os_release) == {"id", "version_id"}
        and all(isinstance(x, str) for x in os_release.values())
    ), os_release
    os_packages = body["os_packages"]
    assert os_packages is None or isinstance(os_packages, dict), os_packages
    for src, entry in (os_packages or {}).items():
        assert isinstance(src, str) and set(entry) == {"versions", "binaries"}, (src, entry)
        assert all(isinstance(x, str) for x in entry["versions"] + entry["binaries"]), entry
    for row in body["os_packages_unstateable"] or []:
        assert set(row) == {"package", "status"} and all(
            isinstance(x, str) for x in row.values()), row
    assert _str_or_none(body["os_packages_error"])
    for row in body["vendored"] or []:
        assert set(row) == {"carrier", "name", "version", "purl", "source"}, row
        assert all(_str_or_none(x) for x in row.values()), row
    assert isinstance(body["vendored_error"], list)
    for row in body["vendored_error"]:
        assert set(row) == {"carrier", "error"} and all(
            isinstance(x, str) for x in row.values()), row
    # Punch 848: the bundled rows, same closed-record rule.
    for row in body["bundled"] or []:
        assert set(row) == {
            "source", "name", "version", "version_source", "purl", "carrier", "carrier_version",
        }, row
        assert all(_str_or_none(x) for x in row.values()), row
        assert row["source"] in ("dist-info-sbom", "auditwheel-libs"), row
        assert row["version_source"] in ("sbom", "binary_banner", "soname", None), row
    assert isinstance(body["bundled_error"], list)
    for row in body["bundled_error"]:
        assert set(row) == {"carrier", "error"} and all(
            isinstance(x, str) for x in row.values()), row
    nested = {
        "distributions", "os_release", "os_packages", "os_packages_unstateable",
        "os_packages_error", "vendored", "vendored_error", "bundled", "bundled_error",
    }

    for k, v in body.items():
        if k in nested:
            continue
        assert isinstance(v, (str, bool)), (
            f"{k} is {type(v).__name__}; every contract value but "
            f"'distributions' must be a plain string or bool, so there is "
            f"nowhere for a nested field to hide"
        )


def test_two_versions_of_a_name_are_both_reported(
    client, db, admin_user, tmp_path, monkeypatch,
):
    """Ambiguity is REPORTED, never resolved first-wins.

    More than one version of a name means which code imports depends on path
    order. A reader that saw one version would be told a definite answer to a
    question that has none — and this is the state a pre-fix "refresh" produced.
    """
    before = list(sys.path)
    prefix, site, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    stale = site / "fake_a-0.1.dist-info"
    stale.mkdir()
    (stale / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fake-a\nVersion: 0.1\n", encoding="utf-8",
    )
    try:
        key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
        body = client.get(
            "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
        ).json()
        assert body["distributions"]["fake-a"] == ["0.1", "1.0"]
    finally:
        sys.path[:] = before


def test_build_sha_ignores_the_env_override(
    client, db, admin_user, app, monkeypatch,
):
    """``build_sha`` comes from the BAKED /app/VERSION only.

    ``app.state.version`` USED TO prefer ``EMAIL_TRIAGE_VERSION``/``GIT_SHA`` (removed
    2026-09-29, N-523), which whoever starts the container chooses. A comparator given an operator-supplied
    string is not comparing against what was built, so this route reads the file
    the BUILD wrote and nothing else. In the test environment /app/VERSION does
    not exist, so the honest answer is "" — absent beats wrong.
    """
    monkeypatch.setenv("EMAIL_TRIAGE_VERSION", "a" * 40)
    app.state.version = "b" * 40
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    body = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    ).json()
    assert body["build_sha"] == "", (
        "neither the env var nor app.state.version may reach build_sha"
    )


# ---------------------------------------------------------------------------
# The admin render (N-525 / punch 540)
# ---------------------------------------------------------------------------

def test_rendering_the_ai_backends_tab_does_not_touch_sys_path(
    client, db, admin_cookies, verified_prefix,
):
    """THE render pin. Embedding is NOT configured in the test config, and the
    prefix IS verified — the exact state in which the pre-fix code would have
    put volume packages at ``sys.path[0]`` of the serving process for good.

    Mutation-checked: restoring the ``is_runtime_ready()`` call in
    ``admin.py``'s ai_backends branch turns this RED.
    """
    _prefix, site, _manifest = verified_prefix
    client.cookies.set(
        SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
    )
    before = list(sys.path)
    resp = client.get("/config?tab=ai_backends")
    assert resp.status_code == 200, resp.text
    # The card really rendered — otherwise this test proves nothing about it.
    assert "embedding-install-card" in resp.text
    assert sys.path == before, (
        "rendering an admin page must not mutate the serving process's import "
        "path. Added: "
        f"{[p for p in sys.path if p not in before]}"
    )
    assert str(site) not in sys.path


def test_the_card_says_unverified_when_the_install_drifted(
    client, db, admin_cookies, tmp_path, monkeypatch,
):
    """The wording follows the marker check (N-525).

    Pre-fix the installed state printed "Files verified against the pinned
    manifest baked into this image" unconditionally — so the 2026-05-18 tree,
    18 stale distributions with 104 OSV records, was described to the operator as
    verified.
    """
    before = list(sys.path)
    prefix, _site, _manifest = make_stale_prefix(tmp_path, monkeypatch)
    from email_triage import embedding_bits as eb

    eb._update_state(
        db,
        status="installed",
        install_method="auto",
        manifest_sha256="deadbeef" * 8,
        runtime_deps_path=str(prefix),
        set_installed_now=True,
    )
    db.commit()
    try:
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config?tab=ai_backends")
        assert resp.status_code == 200, resp.text
        flat = " ".join(resp.text.split())
        assert "NOT verified against the manifest in the current image" in flat
        assert "installed packages match this image's pinned manifest" not in flat
        assert sys.path == before
    finally:
        sys.path[:] = before


@pytest.mark.parametrize("builder, expected", [
    (make_stale_prefix, False),
    (make_verified_prefix, True),
])
def test_the_route_reports_the_drift_gates_verified_bool(
    client, db, admin_user, tmp_path, monkeypatch, builder, expected,
):
    """Punch 552 / N-555: ``runtime_verified`` is the bool the warn-only the monitoring system
    check alarms on, so both arms are measured — a key that read False for every
    prefix would page forever, and one that read True would never page."""
    builder(tmp_path, monkeypatch)
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    body = client.get(
        "/health/runtime-deps", headers={"Authorization": f"Bearer {key}"},
    ).json()
    assert body["runtime_deps_present"] is True
    assert body["runtime_verified"] is expected


# ---------------------------------------------------------------------------
# The removal route (N-526 / punch 541)
# ---------------------------------------------------------------------------

def test_remove_route_is_admin_only(client, user_cookies):
    client.cookies.set(
        SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
    )
    resp = client.post("/config/ai-backends/embedding-remove")
    assert resp.status_code == 403, resp.status_code


def test_remove_route_is_anonymous_denied(client):
    resp = client.post(
        "/config/ai-backends/embedding-remove", follow_redirects=False,
    )
    assert resp.status_code in (303, 401, 403), resp.status_code


def test_remove_route_deletes_the_tree_and_audits(
    client, db, admin_cookies, verified_prefix,
):
    """The admin half of the removal funnel, end to end.

    The audit assertion is not decoration: PD-3 requires the row to go through
    the emitter SSOT (``record_auth_event``), because a raw INSERT into an audit
    table forks the HMAC chain and makes the operation invisible to §164.312(b)
    reconciliation.
    """
    prefix, _site, _manifest = verified_prefix
    from email_triage import embedding_bits as eb

    eb._update_state(
        db,
        status="installed",
        install_method="auto",
        runtime_deps_path=str(prefix),
        set_installed_now=True,
    )
    db.commit()
    assert prefix.exists()

    client.cookies.set(
        SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
    )
    resp = client.post(
        "/config/ai-backends/embedding-remove", follow_redirects=False,
    )
    assert resp.status_code in (200, 303), resp.text
    assert not prefix.exists(), "the prefix must be gone"
    row = eb.get_install_status(db)
    assert row["status"] == "not_installed"
    assert row["runtime_deps_path"] is None
    assert row["installed_at"] is None

    events = db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = ?",
        ("embedding_install_remove",),
    ).fetchone()[0]
    assert events >= 1, (
        "the removal must emit an auth_events row through the emitter SSOT"
    )


def _installed_row(db, prefix) -> None:
    from email_triage import embedding_bits as eb

    eb._update_state(
        db,
        status="installed",
        install_method="auto",
        runtime_deps_path=str(prefix),
        set_installed_now=True,
    )
    db.commit()


def _remove_rows(db, outcome: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM auth_events WHERE event_type = ?"
    params: list = ["embedding_install_remove"]
    if outcome is not None:
        sql += " AND outcome = ?"
        params.append(outcome)
    return db.execute(sql, params).fetchone()[0]


def test_remove_route_writes_the_intent_row_before_any_delete(
    client, db, admin_cookies, verified_prefix, monkeypatch,
):
    """N-543 (punch 539 fold-check, hipaa H539FC-3 / db DB-539FC-3): the INTENT
    row is written, and committed by the emitter, BEFORE ``remove_install`` is
    entered; the OUTCOME row comes after. A call-order spy on the module's own
    names, so the order asserted is the order the handler runs."""
    from email_triage.web.routers.ui import embedding_install as ei

    prefix, _site, _manifest = verified_prefix
    _installed_row(db, prefix)
    calls: list[tuple[str, str]] = []
    real_emit, real_remove = ei.record_auth_event, ei.remove_install

    def spy_emit(conn, **kw):
        calls.append(("audit", kw.get("outcome", "")))
        return real_emit(conn, **kw)

    def spy_remove(**kw):
        calls.append(("remove", ""))
        assert _remove_rows(db, "attempt") >= 1, (
            "the intent row must be durable before the funnel runs"
        )
        return real_remove(**kw)

    monkeypatch.setattr(ei, "record_auth_event", spy_emit)
    monkeypatch.setattr(ei, "remove_install", spy_remove)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    resp = client.post(
        "/config/ai-backends/embedding-remove", headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200, resp.text
    assert calls == [("audit", "attempt"), ("remove", ""), ("audit", "success")], calls
    assert not prefix.exists()
    assert "Nothing was removed" not in resp.text


@pytest.mark.parametrize("htmx", [True, False], ids=["htmx", "plain"])
@pytest.mark.audit_failure_expected(
    match='embedding_install_audit event=embedding_install_remove outcome=attempt',
    count=1,
)
def test_a_failed_intent_write_refuses_the_removal(
    client, db, admin_cookies, verified_prefix, monkeypatch, htmx,
):
    """The fail-closed half of N-543: when the intent row cannot be written,
    nothing is deleted, the row is not reset, and the admin SEES why. A raising
    emitter is planted only for the intent (``outcome="attempt"``)."""
    import sqlite3

    from email_triage import embedding_bits as eb
    from email_triage.web.routers.ui import embedding_install as ei

    prefix, _site, _manifest = verified_prefix
    _installed_row(db, prefix)
    before = eb.get_install_status(db)
    real_emit = ei.record_auth_event
    entered: list[bool] = []

    def failing_intent(conn, **kw):
        if kw.get("outcome") == "attempt":
            raise sqlite3.OperationalError("disk I/O error")
        return real_emit(conn, **kw)

    def must_not_run(**kw):
        entered.append(True)
        raise AssertionError("remove_install ran without an intent row")

    monkeypatch.setattr(ei, "record_auth_event", failing_intent)
    monkeypatch.setattr(ei, "remove_install", must_not_run)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    headers = {"HX-Request": "true"} if htmx else {}
    resp = client.post(
        "/config/ai-backends/embedding-remove", headers=headers,
        follow_redirects=False,
    )
    assert not entered, "the funnel must not be entered"
    assert prefix.exists(), "nothing may be deleted when the witness failed"
    after = eb.get_install_status(db)
    assert after["status"] == before["status"] == "installed"
    assert after["runtime_deps_path"] == before["runtime_deps_path"]
    assert _remove_rows(db) == 0
    flat = " ".join(resp.text.split())
    assert "Nothing was removed: the audit record of this removal could not be written" in flat
    if htmx:
        # HTMX 1.x does not swap a 4xx/5xx body: a refusal the admin can see is a 200.
        assert resp.status_code == 200, resp.status_code
        assert 'id="embedding-install-card"' in resp.text
        assert "disk I/O error" not in resp.text, "exception text must not reach the page"
    else:
        assert resp.status_code == 503, resp.status_code


def test_a_refused_target_is_recorded_by_the_intent_and_outcome_rows(
    client, db, admin_cookies, tmp_path, monkeypatch,
):
    """N-549 through the admin route: a runtime prefix the guard cannot identify
    (no installer marker) is refused BEFORE any delete, and the refusal is on the
    record as an intent row plus a failure outcome row (N-543 + N-549 land
    together in the one function).

    Since punch 547 the route's target is the FIXED default prefix, which the
    guard admits unless it is a link, the data volume or holds the database; the
    marker arm is reachable from here only by standing in the resolver. So the
    test stands in ``get_runtime_deps_path`` (``remove_install`` resolves its
    default through it). ``point_defaults_at`` would not do: it moves the
    default itself, which the guard admits. The recording under test is
    arm-agnostic: any ``RemoveTargetRefused`` takes this path."""
    from email_triage import embedding_bits as eb

    stray = tmp_path / "not-a-runtime"
    stray.mkdir()
    (stray / "keep.bin").write_text("x", encoding="utf-8")
    monkeypatch.setattr(eb, "get_runtime_deps_path", lambda: stray)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    resp = client.post(
        "/config/ai-backends/embedding-remove", headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200, resp.text
    assert (stray / "keep.bin").exists(), "an unidentified target must survive"
    assert _remove_rows(db, "attempt") == 1
    assert _remove_rows(db, "failure") == 1
    assert _remove_rows(db, "success") == 0
    flat = " ".join(resp.text.split())
    assert "could not be identified as the installed runtime" in flat


@pytest.mark.parametrize(
    ("planted", "served"),
    [("c" * 40, "c" * 40), ("c" * 40 + "junk", ""), ("v0.2.0", "")],
    ids=["sha", "sha-plus-junk", "tag"],
)
def test_both_build_identity_routes_serve_the_same_shaped_value(
    client, db, admin_user, app, planted, served,
):
    """DB-539FC-1 / DA-FC539-4 (punch 539 fold-check). ``/health/build`` and
    ``/health/runtime-deps`` must serve ONE ``build_sha``, shape-gated the same
    way. Planting ``app.state.build_sha`` puts the probe INSIDE the set the
    control acts on: with no ``/app/VERSION`` in the test environment every
    candidate reader returns "", so the pre-existing ``== ""`` test could not
    tell a per-request re-read or a ``[:40]`` truncation from the funnel."""
    app.state.build_sha = planted
    key = _issue_api_key(db, admin_user["id"], name="cve-arc-admin")
    auth = {"Authorization": f"Bearer {key}"}
    build = client.get("/health/build", headers=auth)
    deps = client.get("/health/runtime-deps", headers=auth)
    assert build.status_code == 200, build.text
    assert deps.status_code == 200, deps.text
    assert build.json()["build_sha"] == served
    assert deps.json()["build_sha"] == served
    assert build.json()["build_sha"] == deps.json()["build_sha"]


def test_the_phi_needle_predicate_has_teeth():
    """The shared predicate must FLAG a PHI-shaped contract key and must NOT
    flag a real package name — asserted here as well as in the structural pin,
    because this file is what the SSOT registry names for the live payload and a
    pin whose predicate is never adversarially exercised reads green by default.
    """
    assert phi_shaped_keys(["requested_by_email"]), (
        "the needle set missed a PHI-shaped contract key"
    )
    assert phi_shaped_keys(["owner_display_name", "subject_line"])
    assert not phi_shaped_keys(
        ["build_sha", "python", "runtime_deps_present", "distributions",
         "image_manifest_sha256", "installed_manifest_sha256",
         "runtime_on_sys_path"]
    ), "the shipped contract must be clean"
    assert "email" in PHI_KEY_NEEDLES, (
        "the needle set must carry the standard's named examples"
    )
    for needle in ("owner", "subject", "message"):
        assert needle in PHI_KEY_NEEDLES, needle
