"""run18 — multi-folder discover SUCCESS-render folder-name PHI leak pin.

The success-path twin of N-160 (the error-path folder-name redaction,
``_redact_folders_if_hipaa``). On a multi-folder discover run, the raw
IMAP folder name is a quasi-identifier (e.g. ``INBOX.Smith-Labs``).
``triage/_discover_results.html`` already redacts ``r.sender`` /
``r.subject`` on ``effective_hipaa`` (= system ``hipaa_mode`` OR per-account
``acct.hipaa``), but BOTH folder render sites shipped UNREDACTED:

  * ``:36-38`` — the "Folders with results" list (``folders_with_results``)
  * ``:111-113`` — the raw-results table folder cell AND its ``title=`` attr

Both sit behind a ``|length > 1`` count gate, so the pre-existing
single-folder render fixtures in ``test_template_phi_render.py`` never
exercised them — the leak was invisible to the suite. This pin uses a
MULTI-folder fixture with a patient-named folder and asserts every folder
render site is redacted under HIPAA (§164.502(b) minimum-necessary /
§164.514(d)(1)).

Redaction is the established viewer-INDEPENDENT display gate (matches the
sender/subject sites in this same template + the N-160 sibling, which
redacts on ``account_hipaa`` alone). The actor≠owner predicate lives on the
AUDIT row (``phi_access_audit_required``), a deliberately separate gate.
"""

from __future__ import annotations

from pathlib import Path

import jinja2
import pytest


TEMPLATES_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "email_triage"
    / "web"
    / "templates"
)

# A patient-/lab-named relative IMAP mailbox — a quasi-identifier that the
# address/path scrubber provably does NOT catch (the N-42 residual).
PHI_FOLDER = "INBOX.Smith-Labs"


@pytest.fixture
def env():
    e = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
        undefined=jinja2.StrictUndefined,
    )
    # SSOT: us_datetime filter registration via install_filter (2026-07-14  fanout).
    from email_triage._us_datetime import install_filter as _install_us_datetime
    _install_us_datetime(e)
    return e


def _multi_folder_ctx(**overrides):
    """A MULTI-folder discover render ctx (>1 folder ⇒ the folder render
    sites are actually emitted)."""
    ctx = {
        "errors": [],
        "total": 2,
        "consolidated": [
            {
                "slug": "lab-results",
                "description": "benign description",
                "count": 2,
                "is_new": True,
                "merged_from": [],
            },
        ],
        "raw_results": [
            {
                "sender": "a@example.com",
                "subject": "subject one",
                "raw_category": "lab-results",
                "raw_description": "d1",
                "folder": "INBOX",
            },
            {
                "sender": "b@example.com",
                "subject": "subject two",
                "raw_category": "lab-results",
                "raw_description": "d2",
                "folder": PHI_FOLDER,
            },
        ],
        "elapsed": 0.1,
        "acct": {"name": "test-acct", "hipaa": 0},
        "query": "ALL",
        "new_count": 1,
        "existing_count": 0,
        "folders_scanned": ["INBOX", PHI_FOLDER],
        "folders_with_results": ["INBOX", PHI_FOLDER],
        "hipaa_mode": False,
    }
    ctx.update(overrides)
    return ctx


def _render(env, **overrides):
    tmpl = env.get_template("triage/_discover_results.html")
    return tmpl.render(**_multi_folder_ctx(**overrides))


def test_folder_name_redacted_when_system_hipaa_on(env):
    """System privacy mode ON ⇒ folder names gone from EVERY site (list,
    cell text, AND the title= attr)."""
    out = _render(env, hipaa_mode=True)
    assert PHI_FOLDER not in out, (
        "multi-folder discover render leaked a quasi-identifier folder name "
        "under system HIPAA mode (§164.502(b) minimum-necessary)"
    )
    assert "[redacted]" in out


def test_folder_name_redacted_when_account_hipaa_on(env):
    """Per-account HIPAA flag ON (system mode OFF) ⇒ folder names gone."""
    out = _render(env, hipaa_mode=False, acct={"name": "test-acct", "hipaa": 1})
    assert PHI_FOLDER not in out, (
        "multi-folder discover render leaked a quasi-identifier folder name "
        "on a per-account HIPAA-flagged account (§164.514(d)(1))"
    )
    assert "[redacted]" in out


def test_folder_name_shown_when_not_hipaa(env):
    """Non-HIPAA account, system mode OFF ⇒ folder names ARE shown (no
    over-redaction; the display gate is viewer-independent and keyed on the
    HIPAA posture, NOT on actor identity)."""
    out = _render(env, hipaa_mode=False)
    assert PHI_FOLDER in out, (
        "non-HIPAA discover render over-redacted folder names"
    )


def test_folder_title_attr_not_leaking_under_hipaa(env):
    """The raw-table folder cell carries a title= tooltip; assert the
    attribute itself does not echo the raw name under HIPAA. (Belt-and-
    suspenders vs. the cell text: a title= leak is invisible on screen but
    present in the DOM/source.)"""
    out = _render(env, hipaa_mode=True)
    assert f'title="{PHI_FOLDER}"' not in out
    assert f"title=\"{PHI_FOLDER}\"" not in out
