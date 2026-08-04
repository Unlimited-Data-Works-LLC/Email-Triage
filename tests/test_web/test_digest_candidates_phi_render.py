"""N-172 + owner-self-preview design point (2026-07-01) — digest "Show matches"
dry-run SUCCESS-render PHI leak pin, viewer-AWARE.

The success-path twin of N-162. The
``/accounts/<id>/digests/<digest_id>/candidates`` route is a cheap dry-run that
lists the messages a digest WOULD include. Its handler is gated by
``OwnedAccount`` → ``can_manage_account``, which admits site-admins AND
delegates — i.e. a MANAGING NON-OWNER. The template
``accounts/_digest_candidates.html`` rendered ``r.sender`` / ``r.subject``
VERBATIM (§164.502(b) / §164.514(d)(1) leak).

Operator ruling 2026-07-01 = viewer-AWARE display gate: the account OWNER
viewing THEIR OWN preview sees verbatim (no min-necessary rationale for
hiding their own PHI from themselves), a managing NON-OWNER sees
``[redacted]``. The gate is ``effective_hipaa AND NOT viewer_is_owner`` (both
handler ctx + template symbols).

This pin renders the template directly (FileSystemLoader + StrictUndefined,
MULTI-row fixture) and asserts the 4-cell matrix:
  effective_hipaa × viewer_is_owner → (verbatim | [redacted])
  * on × non-owner ⇒ [redacted] + banner
  * on × owner     ⇒ verbatim   + no banner
  * off × either   ⇒ verbatim   + no banner (no over-redaction)

``effective_hipaa`` = the account's HIPAA flag; ``viewer_is_owner`` = the
actor==owner check. actor≠owner is the separate AUDIT gate (§164.312(b)
access_log row).
"""

from __future__ import annotations

from pathlib import Path

import jinja2
import pytest

from email_triage.actions.recipient_digest import format_digest_datetime


TEMPLATES_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "email_triage"
    / "web"
    / "templates"
)

# Distinctive PHI tokens — a patient sender + a subject naming a patient.
PHI_SENDER = "patient.zero@clinic.example"
PHI_SUBJECT = "MRI results for John Q. Patient"
PHI_SENDER_2 = "lab-results@oncology.example"
PHI_SUBJECT_2 = "Biopsy report — Jane Roe"


@pytest.fixture
def env():
    e = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
        undefined=jinja2.StrictUndefined,
    )
    # Mirror web/app.py's filter registration (run18 ).
    e.filters["format_digest_dt"] = lambda entry: format_digest_datetime(entry, "")
    # SSOT: us_datetime filter registration via install_filter (2026-07-14  fanout).
    from email_triage._us_datetime import install_filter as _install_us_datetime
    _install_us_datetime(e)
    return e


def _ctx(**overrides):
    """A MULTI-row candidate-render ctx. ``win.truncated`` is False so the
    shared pager macro short-circuits (no ``page_url`` global needed)."""
    ctx = {
        "rows": [
            {
                "date": "2026-06-27T14:30:00+00:00",
                "sender": PHI_SENDER,
                "subject": PHI_SUBJECT,
                "category": "lab-results",
            },
            {
                "date": "2026-06-27T15:00:00+00:00",
                "sender": PHI_SENDER_2,
                "subject": PHI_SUBJECT_2,
                "category": "lab-results",
            },
        ],
        "win": {"truncated": False, "total": 2},
        "eta_line": "",
        "send_note": "",
        "effective_hipaa": False,
        "viewer_is_owner": False,  # default = a managing NON-owner is viewing (the seam that leaked)
        "cand_url": "/accounts/3/digests/5/candidates",
        "request": object(),
    }
    ctx.update(overrides)
    return ctx


def _render(env, **overrides):
    tmpl = env.get_template("accounts/_digest_candidates.html")
    return tmpl.render(**_ctx(**overrides))


def test_hipaa_on_non_owner_sees_redacted(env):
    """HIPAA ON × NON-owner ⇒ EVERY row's sender + subject gone, replaced by
    [redacted] (§164.502(b) minimum-necessary / §164.514(d)(1)) + banner."""
    out = _render(env, effective_hipaa=True, viewer_is_owner=False)
    assert PHI_SENDER not in out, (
        "digest-candidates render leaked a verbatim sender under HIPAA "
        "to a NON-OWNER (§164.502(b))"
    )
    assert PHI_SUBJECT not in out, (
        "digest-candidates render leaked a verbatim subject under HIPAA "
        "to a NON-OWNER (§164.514(d)(1))"
    )
    assert PHI_SENDER_2 not in out
    assert PHI_SUBJECT_2 not in out
    assert "[redacted]" in out
    assert "HIPAA privacy mode" in out, "banner missing for non-owner viewing HIPAA preview"


def test_hipaa_on_owner_sees_verbatim(env):
    """HIPAA ON × OWNER (viewer_is_owner=True) ⇒ verbatim (no over-redaction;
    the owner authored the mail into their own mailbox — no min-necessary
    rationale for hiding their own PHI from themselves) + NO banner."""
    out = _render(env, effective_hipaa=True, viewer_is_owner=True)
    assert PHI_SENDER in out, (
        "digest-candidates OVER-REDACTED the owner's own sender under HIPAA — "
        "owner-self-preview (b) unredact when actor==owner (operator ruling 2026-07-01)"
    )
    assert PHI_SUBJECT in out, "owner-self-preview: over-redacted subject on owner's own account"
    assert PHI_SENDER_2 in out
    assert PHI_SUBJECT_2 in out
    assert "[redacted]" not in out, "owner sees [redacted] on their own HIPAA preview (over-redaction)"
    assert "HIPAA privacy mode" not in out, "banner shown to owner (should be non-owner-only)"


def test_not_hipaa_non_owner_verbatim(env):
    """Non-HIPAA × non-owner ⇒ verbatim (no over-redaction; the gate is HIPAA-posture,
    not actor identity)."""
    out = _render(env, effective_hipaa=False, viewer_is_owner=False)
    assert PHI_SENDER in out, "non-HIPAA digest-candidates over-redacted the sender"
    assert PHI_SUBJECT in out, "non-HIPAA digest-candidates over-redacted the subject"
    assert PHI_SENDER_2 in out
    assert PHI_SUBJECT_2 in out
    assert "HIPAA privacy mode" not in out


def test_not_hipaa_owner_verbatim(env):
    """Non-HIPAA × owner ⇒ verbatim (unchanged; both false ⇒ never redacts)."""
    out = _render(env, effective_hipaa=False, viewer_is_owner=True)
    assert PHI_SENDER in out
    assert PHI_SUBJECT in out
    assert "HIPAA privacy mode" not in out
