"""Render-side tests for the self-sent event triage path (#107).

Verifies the ``triage/_results.html`` partial paints the calendar
icon + start time on a self-event row when the action's data envelope
declares a successful calendar write, and redacts the event detail
in HIPAA mode.
"""

from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader

# Resolve the templates dir relative to the package source so the
# test isn't coupled to the test-runner's cwd.
_TEMPLATE_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src" / "email_triage" / "web" / "templates"
)


@pytest.fixture
def env():
    e = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    return e


def _render(env, *, hipaa, action_data):
    """Render ``_results.html`` with one self-event row.

    ``hipaa`` toggles the effective_hipaa branch in the template.
    ``action_data`` is the envelope the action returns (becomes
    ``r.actions[0].data``).
    """
    tpl = env.get_template("triage/_results.html")
    results = [{
        "message_id": "m1",
        "status": "ok",
        "sender": "user@example.com",
        "subject": "Coffee Tuesday 3pm",
        "category": "self-event",
        "confidence": 0.85,
        "reason": "self-sent note",
        "actions": [{
            "name": "self_sent_event",
            "result": "completed",
            "data": action_data,
            "error": None,
        }],
    }]
    return tpl.render(
        results=results,
        errors=[],
        total=1,
        query="self-event",
        elapsed=0.1,
        acct={"name": "Test Account", "id": 1, "hipaa": hipaa},
        hipaa_mode=False,
        dry_run=False,
    )


class TestSelfEventRender:
    def test_calendar_icon_and_start_painted(self, env):
        html = _render(env, hipaa=False, action_data={
            "calendar_write": "ok",
            "event_id": "ev-123",
            "summary": "Coffee Tuesday 3pm",
            "start": "2026-06-02T15:00:00+00:00",
            "end": "2026-06-02T15:30:00+00:00",
        })
        # Calendar emoji renders.
        assert "📅" in html
        assert "added" in html
        # Start ts (date+time portion, with T replaced by space).
        assert "2026-06-02 15:00" in html

    def test_no_time_branch_paints_warning(self, env):
        html = _render(env, hipaa=False, action_data={
            "calendar_write": "skipped",
            "reason": "no_parseable_time",
            "summary": "Random thought",
        })
        assert "no time found" in html
        # No calendar emoji on the skip branch.
        assert "📅" not in html

    def test_hipaa_redacts_event_detail(self, env):
        html = _render(env, hipaa=True, action_data={
            "calendar_write": "ok",
            "event_id": "ev-123",
            "summary": "Coffee Tuesday 3pm",
            "start": "2026-06-02T15:00:00+00:00",
        })
        # No calendar emoji + no start time leaked under HIPAA.
        assert "📅" not in html
        assert "2026-06-02" not in html
        # Sender + subject also redacted (existing behaviour).
        assert "user@example.com" not in html
        assert "Coffee Tuesday" not in html
        # Action name still visible (system label) + a "done" status
        # so the operator knows something fired.
        assert "self_sent_event" in html
        assert "done" in html
