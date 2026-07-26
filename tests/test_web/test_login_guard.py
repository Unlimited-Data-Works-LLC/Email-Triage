"""Tests for the login_guard module + its wiring at the OTP / WebAuthn /
dev-keypair / passkey login surfaces."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.config import AuthConfig, TriageConfig
from email_triage.web.db import init_db as _init_db, record_auth_event
from email_triage.web.login_guard import (
    LoginLocked,
    check_login_allowed,
    record_login_failure,
    record_login_lockout,
    record_login_success,
)


@pytest.fixture(name="guard_db")
def _guard_db():
    """Fresh in-memory DB independent of the conftest ``db`` fixture
    so unit-level guard tests don't pull in app/client wiring."""
    from _db_tracking import track
    return track(_init_db(":memory:"))


@pytest.fixture
def config_default():
    cfg = TriageConfig()
    cfg.auth = AuthConfig()
    return cfg


@pytest.fixture
def config_aggressive():
    """Tight thresholds so tests don't have to spam 30+ rows."""
    cfg = TriageConfig()
    cfg.auth = AuthConfig(
        login_per_email_max=3,
        login_per_email_window_secs=60,
        login_per_ip_max=5,
        login_per_ip_window_secs=60,
    )
    return cfg


class TestCheckLoginAllowed:
    def test_no_failures_allows(self, guard_db, config_default):
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_default,
        )

    def test_per_email_under_threshold(self, guard_db, config_aggressive):
        for _ in range(2):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_aggressive,
        )

    def test_per_email_at_threshold_locks(self, guard_db, config_aggressive):
        for _ in range(3):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email="alice@example.com", ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "email"
        assert exc.value.retry_after_secs == 60

    def test_per_email_lowercase_normalized(
        self, guard_db, config_aggressive,
    ):
        # Failures recorded under lowercase form; lookup with mixed
        # case still trips.
        for _ in range(3):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        with pytest.raises(LoginLocked):
            check_login_allowed(
                guard_db, email="Alice@Example.COM", ip=None,
                config=config_aggressive,
            )

    def test_per_ip_at_threshold_locks(self, guard_db, config_aggressive):
        for i in range(5):
            record_auth_event(
                guard_db, event_type="login_otp",
                email=f"u{i}@example.com",
                ip="1.2.3.4", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email="never-seen@example.com", ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "ip"

    def test_window_expiry_releases_lock(
        self, guard_db, config_aggressive,
    ):
        old_ts = (
            datetime.now(timezone.utc) - timedelta(seconds=120)
        ).isoformat()
        for _ in range(3):
            guard_db.execute(
                "INSERT INTO auth_events "
                "(ts, event_type, email, outcome) "
                "VALUES (?, 'login_otp', 'alice@example.com', 'failure')",
                (old_ts,),
            )
        guard_db.commit()
        check_login_allowed(
            guard_db, email="alice@example.com", ip=None,
            config=config_aggressive,
        )

    def test_success_rows_not_counted(self, guard_db, config_aggressive):
        for _ in range(10):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="1.2.3.4", outcome="success",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip="1.2.3.4",
            config=config_aggressive,
        )

    def test_max_zero_disables_email_scope(self, guard_db):
        cfg = TriageConfig()
        cfg.auth = AuthConfig(
            login_per_email_max=0,
            login_per_ip_max=5,
            login_per_email_window_secs=60,
            login_per_ip_window_secs=60,
        )
        for _ in range(100):
            record_auth_event(
                guard_db, event_type="login_otp",
                email="alice@example.com",
                ip="9.9.9.9", outcome="failure",
            )
        check_login_allowed(
            guard_db, email="alice@example.com", ip=None, config=cfg,
        )

    def test_email_none_skips_email_check(
        self, guard_db, config_aggressive,
    ):
        # Passkey path: email=None — only IP guard applies.
        for _ in range(10):
            record_auth_event(
                guard_db, event_type="login_passkey",
                email="alice@example.com",
                ip="1.2.3.4", outcome="failure",
            )
        with pytest.raises(LoginLocked) as exc:
            check_login_allowed(
                guard_db, email=None, ip="1.2.3.4",
                config=config_aggressive,
            )
        assert exc.value.scope == "ip"


class TestRecordLoginFailure:
    def test_writes_failure_row(self, guard_db):
        record_login_failure(
            guard_db, surface="otp", email="alice@example.com",
            ip="1.2.3.4", user_agent="curl/8", reason="invalid_code",
        )
        row = guard_db.execute(
            "SELECT event_type, email, ip, outcome, detail "
            "FROM auth_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["event_type"] == "login_otp"
        assert row["email"] == "alice@example.com"
        assert row["ip"] == "1.2.3.4"
        assert row["outcome"] == "failure"
        assert row["detail"] == "invalid_code"


class TestRecordLoginLockout:
    def test_writes_lockout_row(self, guard_db):
        record_login_lockout(
            guard_db, surface="otp", email="alice@example.com",
            ip="1.2.3.4", user_agent="curl/8",
            scope="email", threshold=600,
        )
        row = guard_db.execute(
            "SELECT event_type, email, outcome, detail "
            "FROM auth_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row["event_type"] == "login_lockout"
        assert row["email"] == "alice@example.com"
        assert row["outcome"] == "failure"
        assert "scope=email" in row["detail"]
        assert "threshold=600" in row["detail"]


# ---------------------------------------------------------------------------
# FIX B — et_auth_attempts_total failure-edge metric pin (observability).
#
# The counter was previously incremented ONLY on the success edge (inside each
# login handler). The failure edge is now co-located in ``record_login_failure``
# and ``record_login_lockout`` so every failure/lockout path increments it
# automatically.
#
# Structural pin: verify the metric increment lives inside the failure funnels
# (not scattered per-handler). Behavioural test: calling record_login_failure
# increments the failure-labelled counter.
# ---------------------------------------------------------------------------

import ast
from pathlib import Path

from _pin_harness import SRC_ROOT as _SRC  # census run15 #3 — harness SRC root, not a hand-rolled off-by-one
_LOGIN_GUARD = _SRC / "web" / "login_guard.py"
_METRIC_NAME = "et_auth_attempts_total"
_FAILURE_FUNNELS = {"record_login_failure", "record_login_lockout"}


def _fn_def_ranges(tree: ast.AST, names: set[str]) -> dict[str, tuple[int, int]]:
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names:
            out[n.name] = (n.lineno, getattr(n, "end_lineno", n.lineno))
    return out


def _string_constants_in_range(tree: ast.AST, lo: int, hi: int) -> list[str]:
    """All string constant values on lines lo..hi."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if hasattr(n, "lineno") and lo <= n.lineno <= hi:
                out.append(n.value)
    return out


def test_failure_metric_colocated_in_failure_funnels():
    """Count-agnostic structural pin: ``et_auth_attempts_total`` must appear
    as a string constant inside EACH failure funnel in login_guard.py.
    If a funnel loses the metric call, this fires regardless of how many
    funnels exist."""
    from _pin_harness import parse_module; tree = parse_module(_LOGIN_GUARD); assert tree is not None  # N-350 R31
    ranges = _fn_def_ranges(tree, _FAILURE_FUNNELS)
    missing = []
    for fn_name, (lo, hi) in ranges.items():
        consts = _string_constants_in_range(tree, lo, hi)
        if _METRIC_NAME not in consts:
            missing.append(fn_name)
    assert not missing, (
        f"FIX B: {_METRIC_NAME!r} metric increment missing from failure "
        f"funnel(s): {missing}. The failure edge must be co-located inside "
        "record_login_failure / record_login_lockout so every login surface "
        "is covered without per-handler duplication."
    )


_SUCCESS_FUNNEL = "record_login_success"

# Login surfaces that record a FAILURE but legitimately have NO success edge —
# each with a source-verified reason. The success/failure symmetry pin exempts
# these; a new entry is a conscious decision (PD#7 rot-guarded).
_NO_SUCCESS_EDGE = {
    # Requesting an OTP is rate-limited (a failure/lockout edge) but is NOT a
    # successful login — the success edge is the OTP *verify* surface ("otp").
    "otp_request": "OTP request: failure (rate-limit) edge only; success is the 'otp' verify surface",
}


def _surface_args_of_calls(tree: ast.AST, fn_names: set[str]) -> set[str]:
    """Every string ``surface=`` kwarg passed to a call of one of ``fn_names``
    (matched by the callable's bare name — Name or Attribute attr)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if name not in fn_names:
            continue
        for kw in node.keywords:
            if (
                kw.arg == "surface"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                out.add(kw.value.value)
    return out


def test_auth_attempts_metric_only_in_the_funnels():
    """Count-agnostic: the ``et_auth_attempts_total`` metric name must NOT
    appear in ANY src file outside login_guard.py. BOTH edges are now
    funnel-owned (failure → record_login_failure/record_login_lockout, success
    → record_login_success). A per-handler ``.inc(et_auth_attempts_total)`` is
    a drift re-introduction — it is exactly how the recovery_code success edge
    was MISSED (census run15 #6: every other surface hand-rolled the success
    increment, recovery_code forgot to)."""
    from _pin_harness import iter_src_files, relpath
    offenders = []
    for path in iter_src_files():
        if path.name == "login_guard.py":
            continue
        if _METRIC_NAME in path.read_text(encoding="utf-8"):
            offenders.append(relpath(path))
    assert not offenders, (
        f"{_METRIC_NAME!r} referenced outside login_guard.py (both the success "
        f"and failure edges are funnel-owned): {offenders}. Call "
        "record_login_success(surface=…) / record_login_failure(…) instead of "
        "hand-rolling the metric — a per-handler increment is exactly how the "
        "recovery_code success was silently dropped (census run15 #6)."
    )


def test_success_metric_colocated_in_success_funnel():
    """Success-edge twin of test_failure_metric_colocated_in_failure_funnels:
    ``et_auth_attempts_total`` must appear inside ``record_login_success`` in
    login_guard.py — else the funnel lost its increment and every surface's
    success goes uncounted."""
    from _pin_harness import parse_module; tree = parse_module(_LOGIN_GUARD); assert tree is not None  # N-350 R31
    ranges = _fn_def_ranges(tree, {_SUCCESS_FUNNEL})
    assert _SUCCESS_FUNNEL in ranges, (
        f"{_SUCCESS_FUNNEL} not found in login_guard.py — the success-metric "
        "funnel is missing."
    )
    lo, hi = ranges[_SUCCESS_FUNNEL]
    consts = _string_constants_in_range(tree, lo, hi)
    assert _METRIC_NAME in consts, (
        f"{_METRIC_NAME!r} increment missing from {_SUCCESS_FUNNEL} — the "
        "success edge must be co-located in the funnel so every login surface "
        "is counted without per-handler duplication."
    )


def test_login_surface_success_failure_symmetry():
    """Count-agnostic INTERPROCEDURAL symmetry pin: every login surface that
    records a FAILURE (record_login_failure / record_login_lockout) must ALSO
    record a SUCCESS (record_login_success), EXCEPT the documented
    _NO_SUCCESS_EDGE surfaces. Scans ALL of src (a new surface in any router is
    caught), keyed on the ``surface=`` string. This is the pin the recovery_code
    gap motivated — it incremented the failure metric but never the success."""
    from _pin_harness import iter_src_files, parse_module
    failure_surfaces: set[str] = set()
    success_surfaces: set[str] = set()
    for path in iter_src_files():
        source_text = path.read_text(encoding="utf-8")
        if "record_login_" not in source_text:
            continue
        tree = parse_module(path)
        if tree is None:
            pytest.fail(
                f"{path} did not parse — a non-parsing src module is a "
                "defect this guard must surface, not skip"
            )
        failure_surfaces |= _surface_args_of_calls(tree, _FAILURE_FUNNELS)
        success_surfaces |= _surface_args_of_calls(tree, {_SUCCESS_FUNNEL})
    # Anti-vacuity (DA, census run15 #6): the live scan must actually find
    # surfaces — a broken iter_src_files / extractor would otherwise pass
    # VACUOUSLY (empty − anything = ∅). The teeth test proves the extractor on a
    # synthetic tree; this proves the REAL walk is non-empty.
    assert failure_surfaces, "no record_login_failure surfaces found in src — vacuous scan"
    assert success_surfaces, "no record_login_success surfaces found in src — vacuous scan"
    missing = (failure_surfaces - set(_NO_SUCCESS_EDGE)) - success_surfaces
    assert not missing, (
        f"login surface(s) record a FAILURE but no SUCCESS metric: {sorted(missing)}. "
        "Call record_login_success(surface=…) on the success terminus, or — if the "
        "surface genuinely has no success edge — add it to _NO_SUCCESS_EDGE with a "
        "reason (that's the recovery_code gap, census run15 #6)."
    )
    # PD#7 rot-guard: every _NO_SUCCESS_EDGE entry must really be a failure
    # surface at HEAD (else the exemption is stale).
    stale = set(_NO_SUCCESS_EDGE) - failure_surfaces
    assert not stale, (
        f"_NO_SUCCESS_EDGE names non-failure surface(s): {sorted(stale)} — stale "
        "exemption, drop them."
    )


def test_success_failure_symmetry_pin_has_teeth():
    """Teeth: the surface extractor sees the surface kwarg on each funnel, and
    a failure-only surface (absent from the success set) is detectable."""
    f_tree = ast.parse("record_login_failure(db, surface='newthing', reason='x')\n")
    assert _surface_args_of_calls(f_tree, _FAILURE_FUNNELS) == {"newthing"}
    assert _surface_args_of_calls(f_tree, {_SUCCESS_FUNNEL}) == set()
    s_tree = ast.parse("record_login_success(surface='newthing')\n")
    assert _surface_args_of_calls(s_tree, {_SUCCESS_FUNNEL}) == {"newthing"}
    # The asymmetry the pin catches: failure-only minus exemptions is non-empty.
    assert ({"newthing"} - set(_NO_SUCCESS_EDGE)) - set() == {"newthing"}


class TestFailureMetricIncrement:
    """Behavioural: record_login_failure increments the failure counter."""

    def setup_method(self, _method):
        from email_triage import metrics as metrics_mod
        metrics_mod.reset_all()

    def teardown_method(self, _method):
        from email_triage import metrics as metrics_mod
        metrics_mod.reset_all()

    def test_record_login_failure_increments_failure_counter(self, guard_db):
        """FIX B behavioural: a failed login via record_login_failure must
        increment et_auth_attempts_total with outcome='failure'."""
        from email_triage import metrics as metrics_mod
        before = metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="failure",
        )
        record_login_failure(
            guard_db, surface="otp", email="evil@example.com",
            ip="1.2.3.4", user_agent="curl/8", reason="invalid_code",
        )
        after = metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="failure",
        )
        assert after == before + 1, (
            "FIX B: record_login_failure must increment "
            f"{_METRIC_NAME}{{surface='otp', outcome='failure'}}; "
            f"got {after} (expected {before + 1})."
        )

    def test_record_login_failure_uses_correct_surface_label(self, guard_db):
        """Surface label must match the surface arg (webauthn, passkey, etc.)."""
        from email_triage import metrics as metrics_mod
        record_login_failure(
            guard_db, surface="webauthn", email="eve@example.com",
            ip="2.2.2.2", user_agent=None, reason="verify_failed",
        )
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="webauthn", outcome="failure",
        ) == 1
        # Other surfaces unaffected.
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="failure",
        ) == 0

    def test_record_login_lockout_increments_lockout_counter(self, guard_db):
        """FIX B behavioural: a lockout via record_login_lockout must
        increment et_auth_attempts_total with outcome='lockout'."""
        from email_triage import metrics as metrics_mod
        record_login_lockout(
            guard_db, surface="otp", email="attacker@example.com",
            ip="3.3.3.3", user_agent=None,
            scope="email", threshold=600,
        )
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="lockout",
        ) == 1

    def test_multiple_surfaces_tracked_independently(self, guard_db):
        """Separate surface labels accumulate separately."""
        from email_triage import metrics as metrics_mod
        for _ in range(3):
            record_login_failure(
                guard_db, surface="passkey", email=None,
                ip="4.4.4.4", user_agent=None, reason="verify_failed",
            )
        record_login_failure(
            guard_db, surface="dev_keypair", email="op@example.com",
            ip="5.5.5.5", user_agent=None, reason="signature_invalid",
        )
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="passkey", outcome="failure",
        ) == 3
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="dev_keypair", outcome="failure",
        ) == 1
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="failure",
        ) == 0

    def test_record_login_success_increments_success_counter(self, guard_db):
        """census run15 #6 behavioural: record_login_success increments
        et_auth_attempts_total{outcome='success'} for the given surface — the
        success-edge twin of the failure funnel (recovery_code included, the
        surface that previously had no success increment)."""
        from email_triage import metrics as metrics_mod
        surfaces = ("otp", "webauthn", "passkey", "dev_keypair", "recovery_code")
        for surface in surfaces:
            record_login_success(surface=surface)
        for surface in surfaces:
            assert metrics_mod.counter(_METRIC_NAME).value(
                surface=surface, outcome="success",
            ) == 1, f"record_login_success({surface!r}) must increment the success counter"
        # The failure edge is untouched.
        assert metrics_mod.counter(_METRIC_NAME).value(
            surface="otp", outcome="failure",
        ) == 0


class TestVerifyEndpointGuard:
    """End-to-end: POST /login/verify must lock after threshold."""

    def test_three_invalid_codes_locks_email(
        self, client, db, regular_user,
    ):
        # Tighten thresholds on the live config the app is using.
        db_app = client.app.state.config
        db_app.auth.login_per_email_max = 3
        db_app.auth.login_per_email_window_secs = 60
        db_app.auth.login_per_ip_max = 100
        db_app.auth.login_per_ip_window_secs = 60

        # Use the conftest regular_user; verify_otp will reject
        # without a stored code, writing a failure row each time.
        email = regular_user["email"]

        for _ in range(3):
            r = client.post(
                "/login/verify",
                data={"email": email, "code": "000000"},
            )
            assert r.status_code == 200

        # 4th attempt — guard trips before verify_otp runs.
        r = client.post(
            "/login/verify",
            data={"email": email, "code": "000000"},
        )
        assert r.status_code == 200
        assert "Too many login attempts" in r.text

        # Lockout audit row landed.
        n = db.execute(
            "SELECT COUNT(*) FROM auth_events "
            "WHERE event_type='login_lockout'"
        ).fetchone()[0]
        assert n >= 1

    def test_max_zero_admin_disables_guard(
        self, client, db, regular_user,
    ):
        db_app = client.app.state.config
        db_app.auth.login_per_email_max = 0
        db_app.auth.login_per_ip_max = 0

        email = regular_user["email"]
        # 20 attempts, no lockout text ever surfaces.
        for _ in range(20):
            r = client.post(
                "/login/verify",
                data={"email": email, "code": "000000"},
            )
            assert "Too many login attempts" not in r.text

        n = db.execute(
            "SELECT COUNT(*) FROM auth_events "
            "WHERE event_type='login_lockout'"
        ).fetchone()[0]
        assert n == 0
