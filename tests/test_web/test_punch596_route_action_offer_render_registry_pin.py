"""Punch 596 — the routes editor's OFFER, its RENDER and the live REGISTRY agree.

``b778e0a60`` added five names to ``_AVAILABLE_ROUTE_ACTIONS`` (escalate,
accept_invite, decline_invite, tentative_invite, self_sent_event) and registered
``EscalateAction`` (SMS egress) in ``build_default_registry``. Its message and the
feature report said operators "can now select" them. They could not:
``accounts/_routes_body.html`` hardcodes its checkboxes and never iterated
``available_actions``, and no web writer sets ``config.notify_email``, so a
route-fired escalate always returned SKIPPED. The only pin compared the tuple to
the registry, never to the rendered view (PD-17), so it stayed green.

The fix un-offers what the web editor cannot configure, de-registers escalate
from the web registry, and makes the route writers refuse an un-offered action.

INVARIANTS (count-agnostic — sets derived from the live tuple, the live registry
and the RENDERED editor, never a hardcoded count):

1. Every category card in the rendered ``/accounts/{id}/routes`` page offers
   exactly ``set(_AVAILABLE_ROUTE_ACTIONS)`` as ``name="actions"`` checkboxes
   (offer == render). Rendered under StrictUndefined through the real handler.
2. ``registry - offer == _REGISTERED_NOT_OFFERED`` (a justified allowlist, one
   reason per entry), so a NEW registered-but-unoffered action fails here. The
   offer ⊆ registry direction stays in
   ``test_regulatory_clock_action.py::test_available_actions_in_live_registry``.
3. ``escalate`` is not registered on the web path; a hand-crafted route row that
   names it (even with a ``notify_email``) never reaches ``EscalateAction.execute``.
4. ``/routes/save`` and ``/routes/save-all`` refuse an un-offered action name with
   a 400 and persist nothing (fail-closed against a hand-posted ``escalate``).

SCOPE CAVEAT: this pins the web routes editor and the web ingestion registry.
It does not cover ``cli.py``'s serve-path registry (YAML config routes, where
``notify_email`` IS configurable), nor a route row written straight into the DB
or restored from a backup (those still resolve through the registry, which is
why invariant 3 is behavioural).
"""

from __future__ import annotations

from html.parser import HTMLParser

import pytest

from email_triage.web.db import create_email_account, list_account_routes


# Registered on the web path but deliberately NOT offered in the routes editor.
# Each entry needs a reason; an entry that stops being registered-and-unoffered
# fails ``test_registered_not_offered_allowlist_is_not_stale``.
_REGISTERED_NOT_OFFERED: dict[str, str] = {
    # Registered on every web ingestion path since  (pre-b778e0a60). The
    # RSVP goes to the organizer through the calendar API with no HIPAA gate in
    # actions/invite.py, and HIPAA accounts can carry a calendar; that egress
    # has had no SME review on the web path (punch 596). Offering it is a
    # feature decision, not a v0.2.0 bug fix.
    "accept_invite": "RSVP egress unreviewed on the web path (punch 596)",
    "decline_invite": "RSVP egress unreviewed on the web path (punch 596)",
    "tentative_invite": "RSVP egress unreviewed on the web path (punch 596)",
    # Registered since  via include_self_event=True. Writes a calendar
    # event; never offered by the editor in any shipped version.
    "self_sent_event": "calendar write; never offered by any shipped editor",
}


def _create_account(db, user_id, name="acct596"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.invalid", "username": "user@example.com"},
    )


class _ActionCheckboxes(HTMLParser):
    """Collect ``<input name="actions" value=...>`` per route-row form slug."""

    def __init__(self):
        super().__init__()
        self.by_slug: dict[str, set[str]] = {}
        self._slug: str | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and "route-row-form" in (a.get("class") or ""):
            self._slug = a.get("data-slug") or ""
            self.by_slug.setdefault(self._slug, set())
        elif tag == "input" and a.get("name") == "actions" and self._slug is not None:
            self.by_slug[self._slug].add(a.get("value") or "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._slug = None


def _rendered_offer_by_slug(html: str) -> dict[str, set[str]]:
    p = _ActionCheckboxes()
    p.feed(html)
    return p.by_slug


def _offer_render_mismatch(html: str, offered) -> dict[str, tuple]:
    """Per-slug (missing-from-render, rendered-but-not-offered). Empty == agree."""
    want = set(offered)
    out = {}
    for slug, got in _rendered_offer_by_slug(html).items():
        if got != want:
            out[slug] = (sorted(want - got), sorted(got - want))
    return out


def _live_registry_names() -> set[str]:
    from email_triage.web.triage_one import build_default_registry
    return set(
        build_default_registry(include_add_label=True, include_self_event=True).names
    )


# ---------------------------------------------------------------------------
# 1. offer == render (PD-17: the RENDERED view, through the real handler)
# ---------------------------------------------------------------------------

def test_rendered_editor_offers_exactly_the_offer_tuple(
    client, db, regular_user, user_cookies, strict_undefined_templates,
):
    from email_triage.web.routers.ui._shared import _AVAILABLE_ROUTE_ACTIONS
    aid = _create_account(db, regular_user["id"])
    resp = client.get(f"/accounts/{aid}/routes", cookies=user_cookies)
    assert resp.status_code == 200, resp.text[:500]
    by_slug = _rendered_offer_by_slug(resp.text)
    # Prove the probe is in the set: at least one category card rendered, and
    # every card carries checkboxes (an empty page would pass vacuously).
    assert by_slug, "no route-row forms rendered; the probe saw no editor"
    assert all(by_slug.values()), f"a card rendered no action checkboxes: {by_slug}"
    mismatch = _offer_render_mismatch(resp.text, _AVAILABLE_ROUTE_ACTIONS)
    assert not mismatch, (
        "routes editor OFFER and RENDER disagree (slug: (offered-not-rendered, "
        f"rendered-not-offered)): {mismatch}"
    )


def test_offer_render_check_has_teeth(
    client, db, regular_user, user_cookies, monkeypatch,
):
    """Plant an offered-but-unrendered name: the comparison must flag it, and
    must not flag the true tuple."""
    from email_triage.web.routers.ui import _shared
    aid = _create_account(db, regular_user["id"])
    html = client.get(f"/accounts/{aid}/routes", cookies=user_cookies).text
    assert not _offer_render_mismatch(html, _shared._AVAILABLE_ROUTE_ACTIONS)
    planted = tuple(_shared._AVAILABLE_ROUTE_ACTIONS) + ("escalate",)
    mismatch = _offer_render_mismatch(html, planted)
    assert mismatch and all("escalate" in m[0] for m in mismatch.values())
    # And the other direction: a rendered name dropped from the offer.
    shrunk = tuple(a for a in _shared._AVAILABLE_ROUTE_ACTIONS if a != "move")
    mismatch = _offer_render_mismatch(html, shrunk)
    assert mismatch and all("move" in m[1] for m in mismatch.values())


# ---------------------------------------------------------------------------
# 2. registry - offer == the justified allowlist
# ---------------------------------------------------------------------------

def test_registered_but_unoffered_actions_are_justified():
    from email_triage.web.routers.ui._shared import _AVAILABLE_ROUTE_ACTIONS
    unoffered = _live_registry_names() - set(_AVAILABLE_ROUTE_ACTIONS)
    unjustified = sorted(unoffered - set(_REGISTERED_NOT_OFFERED))
    assert not unjustified, (
        "registered on the web ingestion path but not offered in the routes "
        f"editor, with no reason in _REGISTERED_NOT_OFFERED: {unjustified}. "
        "Either render it in accounts/_routes_body.html and add it to "
        "_AVAILABLE_ROUTE_ACTIONS, de-register it, or justify it here."
    )


def test_registered_not_offered_allowlist_is_not_stale():
    from email_triage.web.routers.ui._shared import _AVAILABLE_ROUTE_ACTIONS
    live = _live_registry_names()
    stale = sorted(
        n for n in _REGISTERED_NOT_OFFERED
        if n not in live or n in _AVAILABLE_ROUTE_ACTIONS
    )
    assert not stale, f"_REGISTERED_NOT_OFFERED entries no longer apply: {stale}"


# ---------------------------------------------------------------------------
# 3. escalate is not reachable on the web path (behavioural)
# ---------------------------------------------------------------------------

def test_escalate_not_in_web_registry():
    assert "escalate" not in _live_registry_names()


@pytest.mark.asyncio
async def test_hand_crafted_escalate_route_never_executes(monkeypatch):
    """A route row naming escalate WITH a notify_email (only reachable by a
    direct DB write or restore) must not reach EscalateAction.execute on the
    web path: the real build_default_registry is used, not a fake."""
    from datetime import datetime, timezone

    from _db_tracking import track
    from email_triage.actions.escalate import EscalateAction
    from email_triage.engine.models import Classification, EmailMessage
    from email_triage.web.db import get_email_account, init_db
    from email_triage.web.triage_one import (
        TriageContext, build_default_registry, triage_single_message,
    )

    calls: list[dict] = []

    async def _record(self, flow, message, classification, provider, config=None):
        calls.append(dict(config or {}))
        raise AssertionError("EscalateAction.execute reached on the web path")

    monkeypatch.setattr(EscalateAction, "execute", _record)

    class _Cls:
        async def classify(self, message, categories, hints):
            return Classification(category="urgent", confidence=0.9, reason="t")

    conn = track(init_db(":memory:"))
    try:
        now = datetime.now(timezone.utc).isoformat()
        uid = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES ('op@x.com','Op','user',?)", (now,),
        ).lastrowid
        aid = conn.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (uid, "M", "imap", "{}", now, now),
        ).lastrowid
        conn.commit()
        routes = {"urgent": [
            {"action": "escalate", "config": {"notify_email": "pager@example.com"}},
        ]}
        ctx = TriageContext(
            db=conn, config=None, secrets=None, acct=get_email_account(conn, aid),
            classifier=_Cls(), provider=None,
            registry=build_default_registry(
                include_add_label=True, include_self_event=True,
            ),
            categories={}, routes_by_cat=routes, durable_dedup=True,
            mark_triaged_on_success=True, set_keyword_on_success=False,
            fire_watches=False,
        )
        msg = EmailMessage(
            message_id="7", provider="imap", sender="alice@example.com",
            recipients=["op@x.com"], subject="s", body_text="b",
            date=datetime.now(timezone.utc),
            headers={"Message-ID": "<m7@example.com>"},
        )
        await triage_single_message(ctx, msg, "7")
    finally:
        conn.close()
    assert calls == [], f"escalate executed on the web path with config {calls}"


# ---------------------------------------------------------------------------
# 4. the writers refuse an un-offered action (fail-closed hand-post)
# ---------------------------------------------------------------------------

def test_save_refuses_unoffered_action(client, db, regular_user, user_cookies):
    aid = _create_account(db, regular_user["id"])
    resp = client.post(
        f"/accounts/{aid}/routes/save",
        data={"category": "newsletters", "actions": ["label", "escalate"]},
        cookies=user_cookies,
    )
    assert resp.status_code == 400, resp.text
    assert "escalate" in resp.text
    assert list_account_routes(db, aid) == []


def test_save_all_refuses_unoffered_action(client, db, regular_user, user_cookies):
    aid = _create_account(db, regular_user["id"])
    resp = client.post(
        f"/accounts/{aid}/routes/save-all",
        data={
            "row_count": "1",
            "row_0_category": "newsletters",
            "row_0_actions": ["move", "accept_invite"],
            "row_0_move_folder": "",
        },
        cookies=user_cookies,
    )
    assert resp.status_code == 400, resp.text
    # Prove the refusal fired (not the unknown-category guard, which also 400s).
    assert "accept_invite" in resp.text and "unknown category" not in resp.text
    assert list_account_routes(db, aid) == []


def test_refusal_escapes_the_posted_name(client, db, regular_user, user_cookies):
    aid = _create_account(db, regular_user["id"])
    resp = client.post(
        f"/accounts/{aid}/routes/save",
        data={"category": "newsletters", "actions": ["<script>x</script>"]},
        cookies=user_cookies,
    )
    assert resp.status_code == 400
    assert "<script>" not in resp.text


def test_save_still_accepts_every_offered_action(
    client, db, regular_user, user_cookies,
):
    """The refusal must not catch a legitimate save of the full offer."""
    from email_triage.web.routers.ui._shared import _AVAILABLE_ROUTE_ACTIONS
    aid = _create_account(db, regular_user["id"])
    resp = client.post(
        f"/accounts/{aid}/routes/save",
        data={"category": "newsletters", "actions": list(_AVAILABLE_ROUTE_ACTIONS)},
        cookies=user_cookies,
    )
    assert resp.status_code == 200, resp.text
    saved = {a["action"] for a in list_account_routes(db, aid)[0]["actions"]}
    assert saved == set(_AVAILABLE_ROUTE_ACTIONS)
