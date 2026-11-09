"""Punch 664 — an install record that names no set (a pre-569 record) must still
get the right security wording on every surface the admin reads.

``tests/test_n569_runtime_update_pin.py`` pins the STATUS (``security_drift`` /
``SECURITY_FIX``). This file pins what the admin actually SEES for that state,
through the real status funnel and a real prefix, rendered under StrictUndefined
(PD-17): the email (text and HTML), the banner on every admin page, and the AI
Backends install card. The row's complaint was that "the admin prompt may not
say 'security fix: yes' for a security-driven manifest bump".

Three arms, one per direction of failure (PD-18):
  * the history says a later step is a security fix  -> the surfaces say so;
  * the history says no later step is one            -> they do NOT claim it
    (the flag is set only where the history says security) and stay "unknown";
  * the history cannot be read                       -> "unknown", never "no".
"""

from __future__ import annotations

import json
import sys

import pytest

from _embedding_runtime_fixture import make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts

YES = "yes — this release fixes a security problem"
UNKNOWN = "unknown — treated as a security fix"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    # The CLICK notices (auto_update off): the automatic wording is
    # tests/test_web/test_autoupd_notices.py.
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


def _unplace(prefix) -> None:
    """Strip the install record to a pre-569 one: it no longer names its set."""
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    for key in ("set_version", "set_digest", "record_digests", "models_digest"):
        marker.pop(key)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()


@pytest.fixture
def unplaced_security(tmp_path, monkeypatch):
    prefix, _site, mpath = make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0664",),
    )
    _unplace(prefix)
    return mpath


@pytest.fixture
def unplaced_non_security(tmp_path, monkeypatch):
    prefix, _site, mpath = make_versioned_prefix(tmp_path, monkeypatch, steps=(False, False))
    _unplace(prefix)
    return mpath


@pytest.fixture
def unplaced_unreadable_history(tmp_path, monkeypatch):
    prefix, _site, mpath = make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    _unplace(prefix)
    m = json.loads(mpath.read_text(encoding="utf-8"))
    del m[eb.SET_CHANGES_KEY]
    mpath.write_text(json.dumps(m), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()
    return mpath


def _email():
    active, ctx = admin_alerts._embedding_runtime_probe()
    assert active
    ctx["app_url"] = "https://triage.example.test"
    return admin_alerts._assemble_embedding_runtime_alert(ctx)


# ---------------------------------------------------------------------------
# The email
# ---------------------------------------------------------------------------

def test_the_email_for_an_unplaced_record_under_a_security_bump_says_security_yes(
    unplaced_security,
):
    html, text = _email()
    assert f"Security:  {YES}" in text
    assert f"<strong>Security:</strong> {YES}" in html
    assert "CVE-2099-0664" in text and "CVE-2099-0664" in html
    assert "security fix" in text.splitlines()[0]
    assert UNKNOWN not in text and UNKNOWN not in html


def test_the_email_for_an_unplaced_record_under_a_non_security_bump_does_not_claim_one(
    unplaced_non_security,
):
    html, text = _email()
    assert f"Security:  {UNKNOWN}" in text
    assert f"<strong>Security:</strong> {UNKNOWN}" in html
    assert YES not in text and YES not in html
    assert "security fix" not in text.splitlines()[0]


def test_the_email_for_an_unplaced_record_with_an_unreadable_history_says_unknown(
    unplaced_unreadable_history,
):
    html, text = _email()
    assert f"Security:  {UNKNOWN}" in text
    assert YES not in text and YES not in html
    assert "no (not marked as a security fix at release)" not in text


# ---------------------------------------------------------------------------
# The banner (every admin page) and the AI Backends card
# ---------------------------------------------------------------------------

def _flat(resp) -> str:
    assert resp.status_code == 200, resp.text[:600]
    return " ".join(resp.text.split())


@pytest.mark.parametrize("page", ["/config?tab=general", "/config?tab=ai_backends"])
def test_the_banner_for_an_unplaced_security_bump_says_security_fix(
    client, admin_cookies, strict_undefined_templates, unplaced_security, page,
):
    flat = _flat(client.get(page, cookies=admin_cookies))
    assert 'id="embedding-runtime-banner"' in flat
    assert "Embedding runtime update required (security fix)" in flat
    assert "fixes a security problem in the embedding runtime" in flat
    assert "CVE-2099-0664" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' in flat


def test_the_banner_for_an_unplaced_non_security_bump_does_not_say_security_fix(
    client, admin_cookies, strict_undefined_templates, unplaced_non_security,
):
    flat = _flat(client.get("/config?tab=general", cookies=admin_cookies))
    assert "Embedding runtime update required" in flat
    assert "Embedding runtime update required (security fix)" not in flat
    assert "fixes a security problem" not in flat
    # The apostrophe is HTML-escaped on the page, so stop before it.
    assert "cannot show that this release" in flat
    assert "is not a security fix, so it is refused" in flat


def test_the_card_for_an_unplaced_security_bump_says_security_fix(
    client, admin_cookies, strict_undefined_templates, unplaced_security, db,
):
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    flat = _flat(client.get(
        "/config/ai-backends/embedding-install-status", cookies=admin_cookies,
    ))
    assert 'id="embedding-install-card"' in flat
    assert "NOT verified" in flat
    # The card prints the status reason. Both readings contain the words
    # "security fix", so pin the TOKEN and the history-derived sentence.
    assert "security_drift: the recorded install does not match" in flat
    assert "a change after set v1 is a security fix" in flat
    assert "set_mismatch" not in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' in flat


def test_the_auto_update_notice_for_an_unplaced_security_bump_says_security_fix(
    unplaced_security,
):
    """With the automatic updater ON (the default) the headline carries it too."""
    n = eb.update_notice(auto=True)
    assert n["kind"] == "auto"
    assert "security fix" in n["headline"]
    assert n["security"] == eb.SECURITY_FIX
