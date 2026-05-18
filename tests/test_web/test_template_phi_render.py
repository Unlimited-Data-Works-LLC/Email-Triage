"""Per-template PHI redaction regressions for audit finding NEW-4.

Renders each template directly with the Jinja environment used by
the web app. Two-state per template: HIPAA on should hide the real
values; HIPAA off should show them. The CI guard test
(``test_template_phi_guard.py``) enforces that every PHI render is
wrapped; this test enforces that the wrap actually redacts.
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


@pytest.fixture
def env():
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
    )


# ---------------------------------------------------------------------------
# classify/_result.html
# ---------------------------------------------------------------------------


class _Parsed:
    sender = "real.sender@example.com"
    recipients = ["me@example.com"]
    subject = "real subject with PHI"
    date = "2026-01-01"
    body_text = "real body text PHI"


class _Classification:
    category = "invoices"
    confidence = 0.9
    reason = "reason with PHI patient Jane Doe"
    source = "llm"


def _classify_ctx(**overrides):
    ctx = {
        "parsed": _Parsed(),
        "classification": _Classification(),
        "timing": 0.5,
        "model": "ollama",
        "hipaa_mode": False,
    }
    ctx.update(overrides)
    return ctx


def test_classify_result_hides_phi_when_hipaa_on(env):
    tmpl = env.get_template("classify/_result.html")
    out = tmpl.render(**_classify_ctx(hipaa_mode=True))
    assert "real.sender@example.com" not in out
    assert "real subject with PHI" not in out
    assert "real body text PHI" not in out
    assert "reason with PHI patient Jane Doe" not in out
    assert "[redacted" in out


def test_classify_result_shows_phi_when_hipaa_off(env):
    tmpl = env.get_template("classify/_result.html")
    out = tmpl.render(**_classify_ctx(hipaa_mode=False))
    assert "real.sender@example.com" in out
    assert "real subject with PHI" in out
    assert "real body text PHI" in out
    assert "reason with PHI patient Jane Doe" in out


# ---------------------------------------------------------------------------
# triage/_results.html
# ---------------------------------------------------------------------------


def _triage_ctx(**overrides):
    ctx = {
        "errors": [],
        "total": 1,
        "results": [
            {
                "status": "ok",
                "sender": "real.sender@example.com",
                "subject": "real subject PHI",
                "category": "invoices",
                "confidence": 0.9,
                "reason": "real reason PHI patient Jane",
                "actions": [],
            },
        ],
        "elapsed": 0.1,
        "acct": {"name": "test-acct", "hipaa": 0},
        "query": "UNSEEN",
        "dry_run": False,
        "hipaa_mode": False,
    }
    ctx.update(overrides)
    return ctx


def test_triage_results_hides_phi_when_system_hipaa_on(env):
    tmpl = env.get_template("triage/_results.html")
    out = tmpl.render(**_triage_ctx(hipaa_mode=True))
    assert "real.sender@example.com" not in out
    assert "real subject PHI" not in out
    assert "real reason PHI patient Jane" not in out
    assert "[redacted]" in out


def test_triage_results_hides_phi_when_account_hipaa_on(env):
    tmpl = env.get_template("triage/_results.html")
    ctx = _triage_ctx(hipaa_mode=False)
    ctx["acct"] = {"name": "test-acct", "hipaa": 1}
    out = tmpl.render(**ctx)
    assert "real.sender@example.com" not in out
    assert "real subject PHI" not in out
    assert "real reason PHI patient Jane" not in out
    assert "[redacted]" in out


def test_triage_results_shows_phi_when_hipaa_off(env):
    tmpl = env.get_template("triage/_results.html")
    out = tmpl.render(**_triage_ctx(hipaa_mode=False))
    assert "real.sender@example.com" in out
    assert "real subject PHI" in out
    assert "real reason PHI patient Jane" in out


# ---------------------------------------------------------------------------
# triage/_discover_results.html
# ---------------------------------------------------------------------------


def _discover_ctx(**overrides):
    ctx = {
        "errors": [],
        "total": 1,
        "consolidated": [
            {
                "slug": "lab-results",
                "description": "LLM description echoing patient Jane Doe",
                "count": 1,
                "is_new": True,
                "merged_from": ["raw-merged-from-phi-cat"],
            },
        ],
        "raw_results": [
            {
                "sender": "real.sender@example.com",
                "subject": "real discover subject PHI",
                "raw_category": "lab-results",
                "raw_description": "raw description PHI",
                "folder": "INBOX",
            },
        ],
        "elapsed": 0.1,
        "acct": {"name": "test-acct", "hipaa": 0},
        "query": "ALL",
        "new_count": 1,
        "existing_count": 0,
        "folders_scanned": ["INBOX"],
        "folders_with_results": ["INBOX"],
        "hipaa_mode": False,
    }
    ctx.update(overrides)
    return ctx


def test_discover_results_hides_phi_when_system_hipaa_on(env):
    tmpl = env.get_template("triage/_discover_results.html")
    out = tmpl.render(**_discover_ctx(hipaa_mode=True))
    assert "real.sender@example.com" not in out
    assert "real discover subject PHI" not in out
    assert "LLM description echoing patient Jane Doe" not in out
    assert "raw-merged-from-phi-cat" not in out
    assert "[redacted" in out


def test_discover_results_hides_phi_when_account_hipaa_on(env):
    tmpl = env.get_template("triage/_discover_results.html")
    ctx = _discover_ctx(hipaa_mode=False)
    ctx["acct"] = {"name": "test-acct", "hipaa": 1}
    out = tmpl.render(**ctx)
    assert "real.sender@example.com" not in out
    assert "real discover subject PHI" not in out
    assert "LLM description echoing patient Jane Doe" not in out
    assert "[redacted" in out


def test_discover_results_shows_phi_when_hipaa_off(env):
    tmpl = env.get_template("triage/_discover_results.html")
    out = tmpl.render(**_discover_ctx(hipaa_mode=False))
    assert "real.sender@example.com" in out
    assert "real discover subject PHI" in out
    assert "LLM description echoing patient Jane Doe" in out


def test_discover_results_hides_add_button_when_hipaa(env):
    """The Add button's hx-vals embed cat.description; in HIPAA we
    must not emit it (would round-trip PHI into categories on POST)."""
    tmpl = env.get_template("triage/_discover_results.html")
    out = tmpl.render(**_discover_ctx(hipaa_mode=True))
    assert "/categories/add-discovered" not in out
    assert "LLM description echoing patient Jane Doe" not in out
