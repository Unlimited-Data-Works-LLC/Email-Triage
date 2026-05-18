"""Tests for the in-process ACME issuance job-state singleton (#75)."""

import time

import pytest

from email_triage.web import acme_job_state


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset between tests; the singleton is module-global state."""
    acme_job_state.reset()
    yield
    acme_job_state.reset()


def test_initial_state_is_idle():
    s = acme_job_state.current_state()
    assert s["phase"] == "idle"
    assert s["in_flight"] is False
    assert s["started_at"] is None
    assert s["finished_at"] is None
    assert s["domains"] == []


def test_start_marks_in_flight():
    acme_job_state.start(
        domains=["a.example.com", "b.example.com"],
        directory_url="https://acme-staging/",
        max_attempts=3,
    )
    s = acme_job_state.current_state()
    assert s["phase"] == "starting"
    assert s["in_flight"] is True
    assert s["domains"] == ["a.example.com", "b.example.com"]
    assert s["max_attempts"] == 3
    assert s["directory_url"] == "https://acme-staging/"
    assert s["started_at"] is not None
    # Visibility map pre-populated.
    assert "a.example.com" in s["visibility"]
    assert s["visibility"]["a.example.com"]["local"] is False
    assert s["visibility"]["a.example.com"]["authoritative"] is False


def test_transition_updates_phase():
    acme_job_state.start(
        domains=["x.test"], directory_url="d", max_attempts=2,
    )
    acme_job_state.transition("publishing", attempt=1)
    s = acme_job_state.current_state()
    assert s["phase"] == "publishing"
    assert s["attempt"] == 1
    assert s["in_flight"] is True


def test_transition_unknown_phase_raises():
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=1)
    with pytest.raises(ValueError, match="unknown phase"):
        acme_job_state.transition("nope")


def test_visibility_flags_per_domain():
    acme_job_state.start(
        domains=["a.test", "b.test"], directory_url="d", max_attempts=1,
    )
    acme_job_state.visibility("a.test", local=True)
    acme_job_state.visibility("a.test", authoritative=True)
    acme_job_state.visibility("b.test", local=True)
    s = acme_job_state.current_state()
    assert s["visibility"]["a.test"] == {
        "local": True, "authoritative": True, "public_count": 0,
    }
    assert s["visibility"]["b.test"]["local"] is True
    assert s["visibility"]["b.test"]["authoritative"] is False


def test_finish_success():
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=1)
    acme_job_state.transition("finalizing")
    cert_meta = {
        "subject_cn": "x.test",
        "sans": ["x.test"],
        "not_after": "2026-07-30",
    }
    acme_job_state.finish_success(cert_meta)
    s = acme_job_state.current_state()
    assert s["phase"] == "done"
    assert s["in_flight"] is False
    assert s["finished_at"] is not None
    assert s["result"] == cert_meta
    assert s["last_error"] is None


def test_finish_failure_carries_kind():
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=2)
    acme_job_state.transition("retrying")
    acme_job_state.finish_failure("CAA blocks letsencrypt.org", kind="CAA")
    s = acme_job_state.current_state()
    assert s["phase"] == "failed"
    assert s["in_flight"] is False
    assert s["last_error"] == "CAA blocks letsencrypt.org"
    assert s["last_error_kind"] == "CAA"


def test_start_clears_terminal_state():
    """A new start() resets prior done/failed state. Ensures the
    singleton doesn't leak data across consecutive issuances."""
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=1)
    acme_job_state.finish_failure("first run died", kind="boom")

    acme_job_state.start(
        domains=["y.test"], directory_url="d2", max_attempts=2,
    )
    s = acme_job_state.current_state()
    assert s["phase"] == "starting"
    assert s["in_flight"] is True
    assert s["domains"] == ["y.test"]
    assert s["last_error"] is None
    assert s["finished_at"] is None
    assert "x.test" not in s["visibility"]


def test_elapsed_secs_advances():
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=1)
    s1 = acme_job_state.current_state()
    time.sleep(0.05)
    s2 = acme_job_state.current_state()
    assert s2["elapsed_secs"] >= s1["elapsed_secs"]


def test_in_flight_phases():
    """Every PHASE except idle/done/failed reports in_flight=True."""
    acme_job_state.start(domains=["x.test"], directory_url="d", max_attempts=1)
    for phase in (
        "publishing", "polling_local", "polling_authoritative",
        "grace", "answering", "finalizing", "retrying",
    ):
        acme_job_state.transition(phase)
        s = acme_job_state.current_state()
        assert s["in_flight"] is True, f"phase {phase!r} should be in_flight"
    acme_job_state.finish_success({"subject_cn": "x"})
    assert acme_job_state.current_state()["in_flight"] is False
