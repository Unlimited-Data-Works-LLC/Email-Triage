"""Silent-swallow class, panel r15 fold, hipaa FIX: a failed BAA status read
must SHOW an unavailable state on both admin pages, never hide the card.

Before the fold the snapshot left ``baa_status = None`` and both templates
skip their BAA block on a falsy value: the "NOT on file" warning vanished
while the log said "showing unknown". Rendered under StrictUndefined (PD-17:
test the rendered view, not the snapshot dict).
"""

from __future__ import annotations

import pytest


@pytest.fixture
def baa_read_fails(monkeypatch):
    import email_triage.classify.baa_gate as baa_gate

    def boom(db, config):
        raise RuntimeError("baa_acks table unreadable")

    monkeypatch.setattr(baa_gate, "classifier_baa_status_from_config", boom)


def test_config_general_tab_shows_unavailable_baa(
    client, admin_cookies, baa_read_fails, strict_undefined_templates,
):
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[-2000:]
    assert 'data-baa-status="unavailable"' in resp.text
    assert "NOT on file" in resp.text


def test_admin_security_shows_unavailable_baa(
    client, admin_cookies, baa_read_fails, strict_undefined_templates,
):
    resp = client.get("/admin/security", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[-2000:]
    assert 'data-baa-status="unavailable"' in resp.text
    assert "No classifier configured." not in resp.text
