"""Punch 727 (PD-17): render smoke for the ``/compliance`` api-key table's "(recorded as ...)" branch.

``compliance.html`` shows WHO granted or revoked a key from the address resolved off the hashed
``actor_user_id`` and, when the stored copy differs, ``(recorded as <stored copy>)`` beside it
(punch 710, panel AB C2-display). The branch was covered only through the daily-health helper
``_api_key_actor_display``; a template error on it would 500 the compliance page with every unit
test green. These tests drive the real route and the real template under ``StrictUndefined`` (the
shared ``strict_undefined_templates`` fixture), through the same ``list_api_key_events`` rows the
page reads.
"""

from __future__ import annotations

import re

import pytest
from jinja2 import Environment, StrictUndefined, UndefinedError

from _pin_harness import TEMPLATES_ROOT
from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key

TEMPLATE = TEMPLATES_ROOT / "compliance.html"


def _grant(db, admin_user, name, *, stored_email, actor_user_id="admin"):
    uid = admin_user["id"] if actor_user_id == "admin" else actor_user_id
    key_id = store_api_key(
        db, hash_api_key(generate_api_key()), name, admin_user["id"],
        actor_user_id=uid, actor_email=stored_email, source="ui" if uid else "cli")
    return key_id


def _differing_copy(db, key_id, value):
    db.execute("UPDATE api_key_events SET actor_email = ? WHERE key_id = ?", (value, key_id))
    db.commit()


@pytest.mark.usefixtures("strict_undefined_templates")
class TestRecordedAsBranchRenders:
    def test_a_differing_stored_copy_renders_beside_the_resolved_actor(
            self, client, admin_cookies, db, admin_user):
        key_id = _grant(db, admin_user, "render-key", stored_email=admin_user["email"])
        _differing_copy(db, key_id, "mallory@x.invalid")
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "(recorded as mallory@x.invalid)" in resp.text
        assert f"{admin_user['email']} (recorded as mallory@x.invalid)" in resp.text

    def test_a_matching_stored_copy_shows_no_recorded_as(
            self, client, admin_cookies, db, admin_user):
        _grant(db, admin_user, "plain-key", stored_email=admin_user["email"])
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "plain-key" in resp.text and "(recorded as" not in resp.text

    def test_a_cli_row_with_no_user_shows_its_principal_and_no_recorded_as(
            self, client, admin_cookies, db, admin_user):
        _grant(db, admin_user, "cli-key", stored_email="cli:triage", actor_user_id=None)
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "cli:triage" in resp.text and "(recorded as" not in resp.text

    def test_a_hostile_stored_copy_is_escaped(self, client, admin_cookies, db, admin_user):
        key_id = _grant(db, admin_user, "xss-key", stored_email=admin_user["email"])
        _differing_copy(db, key_id, "<script>alert(1)</script>@x.invalid")
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "(recorded as &lt;script&gt;alert(1)&lt;/script&gt;@x.invalid)" in resp.text
        assert "<script>alert(1)</script>@x.invalid" not in resp.text


def _template_cell() -> str:
    """The real ``<td>`` of compliance.html that carries the branch."""
    (line,) = [ln for ln in TEMPLATE.read_text(encoding="utf-8").splitlines()
               if "(recorded as" in ln]
    return line


def _env() -> Environment:
    return Environment(undefined=StrictUndefined, autoescape=True)


_ROW = {"actor_email": "a@x.invalid", "actor_user_id": 1, "recorded_actor_email": "b@x.invalid"}


def test_the_real_cell_renders_under_strict_undefined():
    out = _env().from_string(_template_cell()).render(e=_ROW)
    assert "(recorded as b@x.invalid)" in out


def test_teeth_a_stale_key_in_that_cell_raises_under_strict_undefined():
    """The same cell with the key misspelled, as a rename-with-a-missed-consumer would leave it:
    StrictUndefined raises, which is the 500 the route tests above would then report."""
    stale = re.sub(r"recorded_actor_email", "recorded_actor_emial", _template_cell())
    assert stale != _template_cell()
    with pytest.raises(UndefinedError):
        _env().from_string(stale).render(e=_ROW)
