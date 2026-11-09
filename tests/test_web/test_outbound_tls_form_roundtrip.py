"""Panel M M-DA-8 (PD-17) and M-DA-10, 2026-10-22.

M-DA-8: form round-trips for the operator certificate-mode settings. Each test
POSTs, then GETs, then asserts the value redisplays: the admin General tab's
outbound_tls block (checkboxes, including the unchecked path, and the SMTP
inherit/on/off selects) and the IMAP account form's cert_check / cert_enforce
(inherit/on/off; inherit stores nothing).

M-DA-10: the admin warning banner for recent certificate-check failures that
connected anyway: the read helper and a render smoke through the real page.
"""

from __future__ import annotations

import json
import re

from email_triage.db.accounts import get_email_account, list_email_accounts

BASE = {
    "log_level": "INFO", "classifier_backend": "ollama",
    "classifier_model": "qwen3.5:35b",
    "classifier_ollama_url": "http://localhost:11434",
    "smtp_port": "587", "logging_format": "text",
}


def _checkbox(page: str, name: str) -> str:
    m = re.search(rf'<input[^>]*name="{name}"[^>]*>', page, re.S)
    assert m, name
    return m.group(0)


def _selected(page: str, name: str) -> str:
    m = re.search(rf'name="{name}".*?</select>', page, re.S)
    assert m, name
    sel = re.findall(r'value="(\w+)"\s+selected', m.group(0))
    assert len(sel) == 1, (name, sel)
    return sel[0]


# ---- admin General tab --------------------------------------------------------

def test_general_outbound_tls_round_trip(client, app, admin_cookies):
    data = {**BASE, "outbound_tls_present": "1", "outbound_cert_check": "1",
            # outbound_cert_enforce left unchecked: off
            "outbound_proxy_url": "http://proxy.example.invalid:3128",
            "outbound_no_proxy": "localhost,.lan",
            "outbound_ca_bundle": "/app/config/private-ca.pem",
            "outbound_ignore_env": "1",
            "smtp_cert_check": "off", "smtp_cert_enforce": "inherit"}
    assert client.post("/config/save", data=data, cookies=admin_cookies).status_code == 200
    o = app.state.config.outbound_tls
    assert (o.cert_check, o.cert_enforce, o.ignore_env) == (True, False, True)
    assert o.proxy_url == "http://proxy.example.invalid:3128"
    assert (o.no_proxy, o.ca_bundle) == ("localhost,.lan", "/app/config/private-ca.pem")
    assert app.state.config.smtp.cert_check is False
    assert app.state.config.smtp.cert_enforce is None

    page = client.get("/config", cookies=admin_cookies).text
    assert "checked" in _checkbox(page, "outbound_cert_check")
    assert "checked" not in _checkbox(page, "outbound_cert_enforce")
    assert "checked" in _checkbox(page, "outbound_ignore_env")
    assert 'value="http://proxy.example.invalid:3128"' in page
    assert 'value="localhost,.lan"' in page
    assert 'value="/app/config/private-ca.pem"' in page
    assert _selected(page, "smtp_cert_check") == "off"
    assert _selected(page, "smtp_cert_enforce") == "inherit"

    # Flip: check unchecked (off), enforce checked, SMTP back to inherit / on.
    data2 = {**BASE, "outbound_tls_present": "1", "outbound_cert_enforce": "1",
             "smtp_cert_check": "inherit", "smtp_cert_enforce": "on"}
    assert client.post("/config/save", data=data2, cookies=admin_cookies).status_code == 200
    o = app.state.config.outbound_tls
    assert (o.cert_check, o.cert_enforce, o.ignore_env) == (False, True, False)
    assert (o.proxy_url, o.no_proxy, o.ca_bundle) == ("", "", "")
    assert app.state.config.smtp.cert_check is None
    assert app.state.config.smtp.cert_enforce is True
    page = client.get("/config", cookies=admin_cookies).text
    assert "checked" not in _checkbox(page, "outbound_cert_check")
    assert "checked" in _checkbox(page, "outbound_cert_enforce")
    assert _selected(page, "smtp_cert_check") == "inherit"
    assert _selected(page, "smtp_cert_enforce") == "on"


def test_a_form_without_the_block_leaves_outbound_tls_alone(client, app, admin_cookies):
    # No outbound_tls_present sentinel: absent checkboxes must not flip anything.
    o = app.state.config.outbound_tls
    before = (o.cert_check, o.cert_enforce, o.ignore_env, o.proxy_url)
    assert client.post("/config/save", data=BASE, cookies=admin_cookies).status_code == 200
    o = app.state.config.outbound_tls
    assert (o.cert_check, o.cert_enforce, o.ignore_env, o.proxy_url) == before


# ---- IMAP account form ----------------------------------------------------------

# Loopback port 1: the edit page's live folder probe fails at once (no network).
_ACCT = {"provider_type": "imap", "host": "127.0.0.1", "port": "1",
         "username": "u@example.com", "mailbox": "INBOX", "use_ssl": "1"}


def _acct_cfg(db, account_id):
    return get_email_account(db, account_id)["config"] or {}


def test_account_cert_override_round_trip(client, admin_cookies, admin_user, db):
    r = client.post("/accounts/create", data={
        **_ACCT, "name": "CertRoundTrip", "user_id": str(admin_user["id"]),
        "password": "pw", "cert_check": "inherit", "cert_enforce": "inherit",
    }, cookies=admin_cookies, follow_redirects=False)
    assert r.status_code == 303
    aid = next(a["id"] for a in list_email_accounts(db) if a["name"] == "CertRoundTrip")
    cfg = _acct_cfg(db, aid)
    assert "cert_check" not in cfg and "cert_enforce" not in cfg  # inherit stores nothing

    for check, enforce, stored in (
        ("off", "on", {"cert_check": False, "cert_enforce": True}),
        ("on", "off", {"cert_check": True, "cert_enforce": False}),
        ("inherit", "inherit", {}),
    ):
        r = client.post(f"/accounts/{aid}/save", data={
            **_ACCT, "name": "CertRoundTrip", "is_active": "1",
            "cert_check": check, "cert_enforce": enforce,
        }, cookies=admin_cookies, follow_redirects=False)
        assert r.status_code in (200, 303), r.text[:300]
        cfg = _acct_cfg(db, aid)
        assert {k: cfg[k] for k in ("cert_check", "cert_enforce") if k in cfg} == stored
        page = client.get(f"/accounts/{aid}/edit", cookies=admin_cookies).text
        assert _selected(page, "cert_check") == check
        assert _selected(page, "cert_enforce") == enforce


# ---- M-DA-10: recent-failure banner ----------------------------------------------

def _insert_event(db, ts, **extra):
    from email_triage.tls import CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE
    db.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at) "
        "VALUES (?, 'WARNING', ?, ?, ?, ?)",
        (ts, CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE, json.dumps(extra), ts),
    )
    db.commit()


def _iso(hours_ago: float) -> str:
    from datetime import datetime, timedelta, timezone

    from email_triage._isotime import to_utc_iso
    return to_utc_iso(datetime.now(timezone.utc) - timedelta(hours=hours_ago))


def test_recent_failures_read(db):
    from email_triage.db.audit import recent_cert_check_failures
    from email_triage.tls import CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE

    _insert_event(db, _iso(1), host="imap.a.invalid", port=993, protocol="imap",
                  action="connected_unverified")
    _insert_event(db, _iso(0.5), host="imap.a.invalid", port=993, protocol="imap",
                  action="connected_unverified")
    _insert_event(db, _iso(0.5), host="smtp.b.invalid", port=587,
                  protocol="smtp-starttls", action="refused")
    _insert_event(db, _iso(48), host="old.c.invalid", port=993, protocol="imap",
                  action="connected_unverified")
    rows = recent_cert_check_failures(db, logger=CERT_FAIL_LOGGER,
                                      message=CERT_FAIL_MESSAGE, since_iso=_iso(24))
    assert [(r["host"], r["port"], r["protocol"]) for r in rows] == [
        ("imap.a.invalid", 993, "imap")]


def test_recent_failures_read_does_not_scan_the_audit_table(db):
    """Panel M M-DA-12: the banner read runs on every admin render, on the
    db_call writer thread. Its real statement (captured, not copied) must be an
    index search on log_entries, never a full scan."""
    from email_triage.db.audit import recent_cert_check_failures
    from email_triage.tls import CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE

    seen = []
    db.set_trace_callback(seen.append)
    try:
        recent_cert_check_failures(db, logger=CERT_FAIL_LOGGER, message=CERT_FAIL_MESSAGE,
                                   since_iso="2026-01-01T00:00:00Z")
    finally:
        db.set_trace_callback(None)
    sql = [s for s in seen if "FROM log_entries" in s]
    assert len(sql) == 1, seen
    plan = " ".join(str(r[-1]) for r in db.execute("EXPLAIN QUERY PLAN " + sql[0]))
    assert "SCAN log_entries" not in plan, plan
    assert "log_entries" in plan, plan


def test_banner_renders_on_admin_pages_and_not_for_users(
    client, admin_cookies, user_cookies, db,
):
    _insert_event(db, _iso(0.2), host="imap.banner.invalid", port=993,
                  protocol="imap", action="connected_unverified")
    page = client.get("/config", cookies=admin_cookies).text
    assert "Certificate check failed for" in page
    assert "imap.banner.invalid:993" in page
    assert "connections continued because enforcement is off" in page
    user_page = client.get("/", cookies=user_cookies).text
    assert "imap.banner.invalid" not in user_page


def test_banner_partial_is_silent_without_events():
    from pathlib import Path

    import jinja2

    import email_triage.web as web
    from email_triage._us_datetime import install_filter as _install_us_datetime
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(Path(web.__file__).parent / "templates")),
        undefined=jinja2.StrictUndefined, autoescape=True,
    )
    _install_us_datetime(env)
    t = env.get_template("admin/_cert_check_failed_banner.html")
    assert t.render().strip() == ""
    assert t.render(cert_check_failed_banner=None).strip() == ""
    html = t.render(cert_check_failed_banner=[
        {"host": "h.invalid", "port": 993, "protocol": "imap", "ts": "2026-10-22T07:00:00+00:00"}])
    assert "h.invalid:993" in html and "enforcement is off" in html
