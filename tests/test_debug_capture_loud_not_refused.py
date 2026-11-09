"""Operator ruling A4 (2026-10-21): the classify debug capture is a troubleshooting
mode. It is never refused (HIPAA mode and HIPAA accounts included) and it is loud
while on: a "DEBUG CAPTURE ON" WARNING at start and on every capture, and an admin
banner. Also renders the two new template pieces under StrictUndefined (PD-17).
"""

from __future__ import annotations

import logging
from pathlib import Path

import jinja2
import pytest

from email_triage.classify import ollama

TEMPLATES = Path(ollama.__file__).resolve().parents[1] / "web" / "templates"


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(ollama, "_debug_capture_requested", False)


def test_on_under_hipaa_is_not_refused_and_is_loud(monkeypatch, caplog):
    import email_triage.triage_logging as tl

    monkeypatch.setattr(tl, "is_hipaa_mode", lambda: True)
    with caplog.at_level(logging.WARNING):
        assert ollama.configure_debug_capture(True, any_hipaa_account=True) is True
    assert ollama._debug_capture_enabled() is True
    assert ollama.debug_capture_active() is True
    assert any("DEBUG CAPTURE ON" in r.getMessage() for r in caplog.records)
    # Panel M H8(a): says where the excerpts go and that they stay.
    assert any("kept with the audit trail" in r.getMessage() for r in caplog.records)


def test_each_capture_is_loud(monkeypatch, caplog):
    ollama.configure_debug_capture(True)
    caplog.clear()
    with caplog.at_level(logging.WARNING), pytest.raises(ValueError):
        ollama._parse_llm_json("no json here at all")
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("DEBUG CAPTURE ON") for m in msgs), msgs
    # Panel M H8(b): the capture row carries a PHI-free message reference.
    caplog.clear()
    with caplog.at_level(logging.WARNING), pytest.raises(ValueError):
        ollama._parse_llm_json("still no json",
                               log_ref={"message_id": "m-123", "provider": "imap"})
    rows = [r for r in caplog.records if r.getMessage().startswith("DEBUG CAPTURE ON")]
    assert rows and getattr(rows[-1], "message_id", None) == "m-123"
    assert getattr(rows[-1], "provider", None) == "imap"


def test_off_by_default_and_silent(caplog):
    with caplog.at_level(logging.WARNING):
        assert ollama.configure_debug_capture(False) is False
    assert not any("DEBUG CAPTURE ON" in r.getMessage() for r in caplog.records)
    assert ollama._debug_capture_enabled() is False


def test_no_hipaa_refusal_remains():
    assert not hasattr(ollama, "refuse_debug_capture_for_hipaa")
    src = (Path(ollama.__file__).resolve().parents[1] / "db" / "accounts.py").read_text(
        encoding="utf-8")
    assert "refuse_debug_capture_for_hipaa" not in src


def _env():
    from email_triage._us_datetime import install_filter as _install_us_datetime

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)),
                             undefined=jinja2.StrictUndefined, autoescape=True)
    _install_us_datetime(env)
    return env


def test_banner_renders_only_when_on():
    t = _env().get_template("admin/_debug_capture_banner.html")
    assert "Troubleshooting capture is on" in t.render(debug_capture_banner=True)
    assert "does not remove them" in t.render(debug_capture_banner=True)
    assert "Troubleshooting capture is on" not in t.render(debug_capture_banner=False)
    assert t.render().strip() == ""  # undefined (non-admin render paths)


@pytest.mark.parametrize("stored,selected", [
    ({}, "inherit"), ({"cert_check": True}, "on"), ({"cert_check": False}, "off"),
])
def test_imap_account_cert_fields_render(stored, selected):
    t = _env().get_template("accounts/_fields_imap.html")
    from collections import defaultdict

    # The partial reads further account fields; a defaultdict answers them with
    # "" so the render runs under StrictUndefined without a full page.
    acct = defaultdict(str, {"config": defaultdict(str, {"host": "h.invalid", "port": 993, **stored}),
                             "has_password": False})
    html = t.render(acct=acct, drafts_folder_candidates=[])
    assert 'name="cert_check"' in html and 'name="cert_enforce"' in html
    import re
    m = re.search(r'name="cert_check".*?</select>', html, re.S)
    assert re.search(rf'value="{selected}" selected', m.group(0)), m.group(0)
