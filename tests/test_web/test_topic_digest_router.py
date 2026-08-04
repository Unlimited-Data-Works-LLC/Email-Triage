""" Topic Digest router — tab + CRUD + preview auth-intersection + NCT.

Covers the four contract behaviours the router owns
(``web/routers/ui/profile.py`` topic-digest handlers):

* **Tab resolves** — ``topic-digest`` is on ``_PROFILE_TABS`` so
  ``/profile?tab=topic-digest`` lands on the master card list (not the
  silent ``notifications`` fallback).
* **CRUD round-trip** — ``POST /profile/topic-digest/save`` creates a
  :class:`TopicConfig` that survives serialization, and a re-GET of the
  editor reflects the stored fields.
* **Preview per-account auth intersection (§5 fail-closed)** — the
  preview DROPS an account the requester can't manage *before any
  provider round-trip* (the §5 gate) and renders hits only for the
  managed account. ``match_topics_for_message`` is mocked at its REAL
  async signature (per
  ``pattern_parallel_build_mock_the_boundary_not_the_seam``); the
  provider fetch + classifier build are stubbed so no live IMAP / Ollama.
* **search-details renders the NCT confirm card** — the handler detects
  an NCT id and resolves it via the REAL
  ``actions.clinicaltrials.resolve_nct`` (only the HTTP boundary
  underneath is mocked, per
  ``pattern_parallel_build_mock_the_boundary_not_the_seam``), then
  renders ``profile/_topic_nct_result.html`` — the §3d confirm card with
  Replace / Append / Cancel. A non-NCT / unknown id renders the
  "no public study found" search-error copy instead.

The whole suite runs against the in-memory FastAPI ``TestClient`` (the
``client`` / ``user_cookies`` / ``db`` fixtures from ``conftest``), whose
``init_db`` applies the v40 topics migration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Local helpers / fixtures
# ---------------------------------------------------------------------------

def _make_account(db, user_id: int, name: str, *, hipaa: bool = False) -> int:
    """Create an active IMAP account owned by ``user_id``; return its id."""
    from email_triage.db.accounts import create_email_account
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "imap.example.com", "username": f"{name}@example.com"},
        hipaa=hipaa, is_active=True,
    )


def _make_other_user(db) -> dict:
    """A SECOND regular user the requester does NOT manage accounts for."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("other@test.com", "Other User", "user", now),
    )
    db.commit()
    return {"id": cur.lastrowid, "email": "other@test.com", "role": "user"}


class _FakeMsg:
    """Synthetic provider-normalised message (duck-typed headers)."""
    def __init__(self, mid: str, subject: str = "Hi", frm: str = "sender@example.com",
                 et_header: str | None = None):
        self.headers = {
            "Message-ID": mid,
            "Subject": subject,
            "From": frm,
            "Date": "2026-06-01T00:00:00Z",
        }
        # email-triage's OWN generated content carries the X-Email-Triage
        # loop-prevention header — Topic matching must skip it.
        if et_header:
            self.headers["X-Email-Triage"] = et_header
        self.sender = frm
        self.folder = "INBOX"
        self.body_keywords = []


class _FakeProvider:
    """Minimal provider for Preview tests. The Preview now does a SERVER-SIDE
    Subject search (operator 2026-06-12 "very slow / spinning" fix): it calls
    ``search_all_folders(filter=MailFilter(subject=chip))`` and fetches ONLY the
    matches. This fake honours that — search returns the ``_FakeMsg``\\s whose
    Subject contains the term, ``fetch_messages_batch`` returns them by UID.
    Mock the BOUNDARY (the provider), not the seam
    (pattern_parallel_build_mock_the_boundary_not_the_seam)."""

    def __init__(self, msgs, *, account_id: int = 0, recorder=None):
        self._uids = {str(i): m for i, m in enumerate(msgs)}
        if recorder is not None:
            recorder.append(int(account_id))

    async def search_all_folders(self, query, limit, *, filter=None,
                                 exclude_special_use=False):
        term = (getattr(filter, "subject", "") or "").lower()
        out = []
        for uid, m in self._uids.items():
            subj = ((getattr(m, "headers", None) or {}).get("Subject") or "").lower()
            if term and term in subj:
                out.append((getattr(m, "folder", "INBOX"), uid))
                if len(out) >= limit:
                    break
        return out

    async def fetch_messages_batch(self, uids, *, folder=None, headers_only=False):
        return [self._uids[u] for u in uids if u in self._uids]

    async def fetch_message(self, uid, *, folder=None, headers_only=False):
        return self._uids.get(str(uid))

    def close(self):
        pass


# ---------------------------------------------------------------------------
# 1. Tab resolves
# ---------------------------------------------------------------------------

class TestTabResolves:
    def test_topic_digest_on_allowlist(self):
        from email_triage.web.routers.ui._shared import _PROFILE_TABS
        assert "topic-digest" in _PROFILE_TABS

    def test_tab_lands_on_topic_digest_pane(self, client, user_cookies):
        resp = client.get("/profile?tab=topic-digest", cookies=user_cookies)
        assert resp.status_code == 200
        # The tab pane is active (not the silent notifications fallback).
        assert "tab-pane-active" in resp.text
        # The card-list surface + the New Topic affordance are present.
        assert "/profile/topic-digest/new" in resp.text

    def test_unknown_tab_falls_back_but_topic_digest_does_not(
        self, client, user_cookies,
    ):
        # Control: a bogus tab silently falls back; topic-digest does not.
        from email_triage.web.routers.ui._shared import _resolve_profile_tab

        class _Req:
            query_params = {"tab": "topic-digest"}

        assert _resolve_profile_tab(_Req()) == "topic-digest"

        class _Bogus:
            query_params = {"tab": "does-not-exist"}

        assert _resolve_profile_tab(_Bogus()) == "notifications"


# ---------------------------------------------------------------------------
# 1b. Editor "Mailboxes to watch" multiselect renders real labels
# ---------------------------------------------------------------------------

class TestEditorAccountMultiselect:
    """Regression for the 2026-06-07 "multi-select is blank" blocker.

    The editor multiselect was fed raw ``list_email_accounts`` rows but
    the template read ``acct.display_name`` / ``acct.is_hipaa`` — keys
    that don't exist on those rows (the columns are ``name`` / ``hipaa``,
    email is ``email_address``). Every <option> rendered with an empty
    label, so the whole feature was untestable. These assert the option
    text actually carries the mailbox identity.
    """

    def test_new_editor_lists_manageable_accounts_with_labels(
        self, client, user_cookies, regular_user, db,
    ):
        _make_account(db, regular_user["id"], "primary")
        resp = client.get(
            "/profile/topic-digest/new", cookies=user_cookies,
        )
        assert resp.status_code == 200
        body = resp.text
        # The multiselect is present (not the empty-state fallback).
        assert 'name="selected_account_ids"' in body
        assert "You don't manage any mailboxes yet" not in body
        # The option label carries the mailbox name AND its email —
        # proving the labels aren't blank (the bug).
        assert "primary" in body
        assert "primary@example.com" in body

    def test_hipaa_mailbox_gets_lock_marker(
        self, client, user_cookies, regular_user, db,
    ):
        _make_account(db, regular_user["id"], "phi-box", hipaa=True)
        resp = client.get(
            "/profile/topic-digest/new", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # The 🔒 marker keys off the real ``hipaa`` column.
        assert "phi-box" in resp.text
        assert "🔒" in resp.text


class TestSearchLabelMode:
    """The lookup field's label is mode-aware: an OPEN
    Topic does a free-text web search → "Internet search"; a protected (HIPAA)
    Topic is registry-only → "Study lookup". Asserts the RENDERED label, not
    just the handler (feedback_test_the_view_not_just_machinery)."""

    def test_open_topic_editor_shows_internet_search(
        self, client, user_cookies, regular_user, db,
    ):
        _make_account(db, regular_user["id"], "primary")   # non-HIPAA
        body = client.get(
            "/profile/topic-digest/new", cookies=user_cookies,
        ).text
        assert "Internet search" in body          # the open-mode label
        assert "Study lookup" not in body         # registry-only label absent

    def test_protected_topic_editor_shows_study_lookup(
        self, client, user_cookies, regular_user, db,
    ):
        from email_triage.actions.topic_configs import (
            TopicConfig, upsert_topic,
        )
        acct = _make_account(db, regular_user["id"], "phi-box", hipaa=True)
        t = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="Protected", subjects=["x"],
            selected_account_ids=[acct],
        ))
        body = client.get(
            f"/profile/topic-digest/{t.id}/edit", cookies=user_cookies,
        ).text
        assert "Study lookup" in body             # registry-only label
        assert "Internet search" not in body      # open-mode label absent


# ---------------------------------------------------------------------------
# 1c. Multiple-digests FULL form round-trip (the test-net that the
#     2026-06-07 silent digest-save bug slipped past).
#
#     The editor renders a repeatable digest block per digest, posted as
#     indexed fields ``digest-{i}-<field>``. These assert EVERY posted
#     value round-trips through save -> reload -> render, so a parser that
#     drops a field (the original bug: _parse_topic_form hardcoded
#     DigestSchedule()/DigestFormat()) or a template that reads a
#     non-existent attr (topic.digest.* — TopicConfig has no .digest)
#     fails LOUDLY instead of silently showing defaults.
# ---------------------------------------------------------------------------

class TestMultipleDigestsRoundTrip:
    def _post_two_digests(self, client, user_cookies, acct_id):
        return client.post(
            "/profile/topic-digest/save",
            data={
                "name": "SELENA Lupus Study",
                "subjects": ["SELENA"],
                "selected_account_ids": [str(acct_id)],
                "retention_days": "60",
                "enabled": "1",
                # Digest 0 — daily incremental on weekdays at 22:00.
                "digest-0-name": "Daily incremental",
                "digest-0-enabled": "1",
                "digest-0-mode": "differential",
                "digest-0-cadence": "daily",
                "digest-0-time": "22:00",
                "digest-0-days": ["0", "1", "2", "3", "4"],
                "digest-0-render_as": "table",
                "digest-0-group_by": "none",
                # Digest 1 — weekly full on Monday at 07:00.
                "digest-1-name": "Weekly full",
                "digest-1-enabled": "1",
                "digest-1-mode": "full",
                "digest-1-cadence": "weekly",
                "digest-1-time": "07:00",
                "digest-1-days": ["0"],
                "digest-1-render_as": "grouped_list",
                "digest-1-group_by": "none",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )

    def test_save_persists_both_digests_with_all_fields(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")
        resp = self._post_two_digests(client, user_cookies, acct_id)
        assert resp.status_code == 303

        from email_triage.actions.topic_configs import list_topics
        topics = list_topics(db, regular_user["id"])
        assert len(topics) == 1
        t = topics[0]
        assert len(t.digests) == 2, (
            f"expected 2 digests to round-trip, got {len(t.digests)} "
            "(parser is dropping the digest blocks)"
        )
        d0, d1 = t.digests[0], t.digests[1]
        assert d0.name == "Daily incremental"
        assert d0.mode == "differential"
        assert d0.schedule.cadence == "daily"
        assert d0.schedule.time_local == "22:00"
        assert sorted(d0.schedule.days_of_week) == [0, 1, 2, 3, 4]
        assert d0.format.render_as == "table"
        assert d1.name == "Weekly full"
        assert d1.mode == "full"
        assert d1.schedule.cadence == "weekly"
        assert d1.schedule.time_local == "07:00"
        assert d1.schedule.days_of_week == [0]
        assert d1.format.render_as == "grouped_list"

    def test_editor_redisplays_saved_digest_values(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")
        self._post_two_digests(client, user_cookies, acct_id)
        from email_triage.actions.topic_configs import list_topics
        t = list_topics(db, regular_user["id"])[0]

        resp = client.get(
            f"/profile/topic-digest/{t.id}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200
        body = resp.text
        # Both digest names render (proves the editor reads topic.digests,
        # not the non-existent topic.digest).
        assert "Daily incremental" in body
        assert "Weekly full" in body
        # A distinctive saved value renders (the 22:00 send time) — proves
        # the schedule round-trips to the view, not a reset default.
        assert "22:00" in body
        assert "07:00" in body


class TestPerTopicFloorRoundTrip:
    """The per-Topic confidence floor (operator 2026-06-15) round-trips through
    save -> reload -> render; an out-of-range typo is BOUNCED (200 + error),
    not silently persisted/reverted; blank inherits the global default (None)."""

    def _save(self, client, user_cookies, acct_id, floor):
        data = {
            "name": "Lupus study",
            "subjects": ["SELENA"],
            "selected_account_ids": [str(acct_id)],
            "retention_days": "90",
            "enabled": "1",
        }
        if floor is not None:
            data["confidence_floor"] = floor
        return client.post(
            "/profile/topic-digest/save", data=data,
            cookies=user_cookies, follow_redirects=False,
        )

    def test_floor_value_round_trips_and_renders(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")
        resp = self._save(client, user_cookies, acct_id, "0.6")
        assert resp.status_code == 303
        from email_triage.actions.topic_configs import list_topics
        t = list_topics(db, regular_user["id"])[0]
        assert t.confidence_floor == 0.6
        # PD#17 — the saved value renders back into the editor field.
        body = client.get(
            f"/profile/topic-digest/{t.id}/edit", cookies=user_cookies,
        ).text
        assert 'name="confidence_floor"' in body
        assert 'value="0.6"' in body

    def test_blank_floor_inherits_default(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")
        resp = self._save(client, user_cookies, acct_id, None)
        assert resp.status_code == 303
        from email_triage.actions.topic_configs import list_topics
        t = list_topics(db, regular_user["id"])[0]
        assert t.confidence_floor is None        # inherit, not 0.0
        # The field renders BLANK (placeholder = system default), no value=.
        body = client.get(
            f"/profile/topic-digest/{t.id}/edit", cookies=user_cookies,
        ).text
        assert 'name="confidence_floor"' in body
        assert 'placeholder="system default"' in body

    def test_out_of_range_floor_is_bounced_not_persisted(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")
        resp = self._save(client, user_cookies, acct_id, "1.5")
        # Bounced: re-render with the actionable error (200), NOT a 303 redirect,
        # and NOT persisted.
        assert resp.status_code == 200
        assert "between 0 and 1" in resp.text
        from email_triage.actions.topic_configs import list_topics
        assert list_topics(db, regular_user["id"]) == []


# ---------------------------------------------------------------------------
# 1d. StrictUndefined render net — the general catch for template->handler
#     contract drift (the bug class behind the blank multiselect + the
#     topic.digest display bug). Under StrictUndefined a template that
#     reads an attribute the handler never provides RAISES (500) instead
#     of rendering blank, so the test fails LOUDLY at build time.
# ---------------------------------------------------------------------------

class TestEditorStrictUndefinedRender:
    def test_new_editor_renders_clean_under_strict_undefined(
        self, client, db, regular_user, user_cookies,
        strict_undefined_templates,
    ):
        _make_account(db, regular_user["id"], "primary")
        resp = client.get(
            "/profile/topic-digest/new", cookies=user_cookies,
        )
        assert resp.status_code == 200, (
            "Topic editor hit a Jinja UndefinedError under StrictUndefined "
            "— a template reads an attribute the handler never provides "
            "(contract drift). Body: " + resp.text[:200]
        )

    def test_edit_editor_renders_clean_under_strict_undefined(
        self, client, db, regular_user, user_cookies,
        strict_undefined_templates,
    ):
        # A saved Topic exercises the digest-options section with real
        # values (the part that read the non-existent topic.digest).
        from email_triage.actions.topic_configs import (
            TopicConfig, TopicDigest, upsert_topic,
        )
        from email_triage.actions.digest_configs import (
            DigestSchedule, DigestFormat,
        )
        acct_id = _make_account(db, regular_user["id"], "primary")
        saved = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="Lupus",
            subjects=["SELENA"], selected_account_ids=[acct_id],
            digests=[TopicDigest(
                name="Daily", mode="differential",
                schedule=DigestSchedule(
                    cadence="weekly", time_local="22:00",
                    days_of_week=[0, 2, 4],
                ),
                format=DigestFormat(render_as="table"),
            )],
        ))
        resp = client.get(
            f"/profile/topic-digest/{saved.id}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200, (
            "Topic editor (edit) hit a Jinja UndefinedError under "
            "StrictUndefined. Body: " + resp.text[:200]
        )


# ---------------------------------------------------------------------------
# 2. CRUD save round-trips a TopicConfig
# ---------------------------------------------------------------------------

class TestCrudRoundTrip:
    def test_save_creates_topic_and_persists_fields(
        self, client, user_cookies, regular_user, db,
    ):
        acct_id = _make_account(db, regular_user["id"], "primary")

        resp = client.post(
            "/profile/topic-digest/save",
            data={
                "name": "SELENA Lupus Study",
                "subjects": ["SELENA", "NCT00000419", "lupus HRT"],
                "details": "Phase 3 hormone-therapy safety in lupus.",
                "selected_account_ids": [str(acct_id)],
                #  v2 — mode is per-digest now; post a single digest block.
                "digest-0-name": "Main",
                "digest-0-mode": "both",
                "digest-0-cadence": "daily",
                "digest-0-time": "08:00",
                "retention_days": "60",
                "enabled": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "/profile?tab=topic-digest" in resp.headers["location"]

        # The TopicConfig round-trips through the JSON-blob columns.
        from email_triage.actions.topic_configs import list_topics
        topics = list_topics(db, regular_user["id"])
        assert len(topics) == 1
        t = topics[0]
        assert t.name == "SELENA Lupus Study"
        assert t.subjects == ["SELENA", "NCT00000419", "lupus HRT"]
        assert t.selected_account_ids == [acct_id]
        assert len(t.digests) == 1
        assert t.digests[0].name == "Main"
        assert t.digests[0].mode == "both"
        assert t.retention_days == 60
        assert t.enabled is True
        # A fresh save bumps topic_version off the default 1 -> 2.
        assert t.topic_version >= 2

        # The editor re-GET reflects the stored name.
        resp2 = client.get(
            f"/profile/topic-digest/{t.id}/edit", cookies=user_cookies,
        )
        assert resp2.status_code == 200
        assert "SELENA Lupus Study" in resp2.text

    def test_save_rejects_blank_name(self, client, user_cookies, db):
        # validate() bounces a nameless Topic — handler re-renders the
        # editor (200) rather than persisting an unnamed row.
        resp = client.post(
            "/profile/topic-digest/save",
            data={"name": "  "},
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 200
        from email_triage.web.db import list_email_accounts  # noqa: F401
        from email_triage.actions.topic_configs import list_topics
        # No row created.
        rows = db.execute("SELECT COUNT(*) AS c FROM topics").fetchone()
        assert (rows["c"] if hasattr(rows, "keys") else rows[0]) == 0
        assert list_topics(db, 1) == []

    def test_save_drops_unauthorized_account_from_multiselect(
        self, client, user_cookies, regular_user, db,
    ):
        # §5 at the WRITE boundary: a forged selected_account_ids naming a
        # foreign account is intersected away before the Topic is stored.
        mine = _make_account(db, regular_user["id"], "mine")
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")

        resp = client.post(
            "/profile/topic-digest/save",
            data={
                "name": "Mixed",
                "subjects": ["x"],
                "selected_account_ids": [str(mine), str(theirs)],
                "mode": "full",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 303

        from email_triage.actions.topic_configs import list_topics
        t = list_topics(db, regular_user["id"])[0]
        # The foreign account was dropped; only the managed one survives.
        assert t.selected_account_ids == [mine]

    def test_enabled_only_autosave_toggles_without_full_save(
        self, client, user_cookies, regular_user, db,
    ):
        # The master card's per-row autosave posts enabled_only=1; the
        # handler flips just the flag and returns an inline chip (200,
        # not a redirect / not a full re-validate).
        from email_triage.actions.topic_configs import (
            TopicConfig, upsert_topic, list_topics,
        )
        cfg = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="Toggle me", enabled=True,
        ))

        resp = client.post(
            "/profile/topic-digest/save",
            data={"enabled_only": "1", "topic_id": str(cfg.id)},  # no enabled
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 200
        t = list_topics(db, regular_user["id"])[0]
        assert t.enabled is False


# ---------------------------------------------------------------------------
# 3. Preview — per-account auth intersection (§5 fail-closed)
# ---------------------------------------------------------------------------

class TestPreviewAuthIntersection:
    def _patch_preview_seams(self, monkeypatch, *, fetched_accounts: list):
        """Patch the three preview seams: classifier build, provider
        fetch, and the matcher — at their REAL signatures.

        ``fetched_accounts`` records every account_id the provider fetch
        is invoked for, so the test can assert an unauthorized account is
        NEVER reached (the §5 drop happens upstream, before any fetch).
        """
        import email_triage.jobs.topic_backscan as backscan
        import email_triage.actions.topic_matcher as matcher
        import email_triage.web.routers.ui.profile as profile_mod

        # Classifier build → a non-None sentinel so the preview loop runs.
        monkeypatch.setattr(
            backscan, "_build_classifier", lambda app: object(),
        )

        # Provider BOUNDARY — the Preview searches Subject chips server-side and
        # is built ONCE per authorized account. Recording the account_id at
        # build time proves the §5 drop happened upstream (a foreign account is
        # never even built a provider for / round-tripped).
        def _fake_provider(account, secrets):
            aid = account["id"]
            return _FakeProvider(
                [
                    _FakeMsg(f"<m1@{aid}>", subject="SELENA enrollment update"),
                    _FakeMsg(f"<m2@{aid}>", subject="SELENA enrollment update"),
                ],
                account_id=aid, recorder=fetched_accounts,
            )

        monkeypatch.setattr(
            profile_mod, "_create_provider_from_account", _fake_provider,
        )

        # The matcher — mocked at its REAL async signature:
        #   async match_topics_for_message(message, active_topics,
        #       classifier, *, body_keywords=None, categories=None, k=K)
        # ``categories`` MUST be in the mock's
        # signature — the real preview/back-scan/live calls pass it; a mock
        # that omits it TypeErrors → the scan degrades to no-hits silently
        # (pattern_parallel_build_mock_the_boundary_not_the_seam).
        async def _fake_match(
            message, active_topics, classifier, *,
            body_keywords=None, categories=None, k=6,
        ):
            # One synthetic matched verdict per message (duck-typed dict).
            return [{
                "topic_id": active_topics[0].id,
                "matched": True,
                "confidence": 0.82,
                "reason_terms": ["SELENA", "lupus"],
            }]

        monkeypatch.setattr(
            matcher, "match_topics_for_message", _fake_match,
        )

    def test_preview_drops_unauthorized_account_and_renders_managed(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        mine = _make_account(db, regular_user["id"], "mine")
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")

        # A Topic whose selected_account_ids names BOTH the managed and a
        # foreign account (simulating a stale/tampered row).
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="SELENA",
            subjects=["SELENA"], selected_account_ids=[mine, theirs],
            mode="full",
        ))

        fetched: list[int] = []
        self._patch_preview_seams(monkeypatch, fetched_accounts=fetched)

        resp = client.post(
            f"/profile/topic-digest/{topic.id}/preview",
            # The rendered Preview form posts group_by_account (checked by
            # default) + lookback_days; the handler now HONORS them (was
            # hardcoded). Post what the real form posts so the grouped render
            # (which shows the mailbox NAME) is exercised — a body-less POST
            # would default to the flat list and not render "mine".
            data={"group_by_account": "1"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200

        # §5 fail-closed: the foreign account was DROPPED before any
        # provider round-trip — the fetcher only ever saw the managed one.
        assert fetched == [mine]
        assert theirs not in fetched

        # Hits rendered for the managed account (2 synthetic messages).
        body = resp.text
        assert "mine" in body            # managed mailbox name shown
        assert "theirs" not in body      # foreign mailbox never surfaces
        # The why-matched chip cites the user's OWN public terms.
        assert "SELENA" in body or "lupus" in body
        # Match summary line present.
        assert "match" in body.lower()

    def test_preview_404_on_foreign_topic(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        # A Topic owned by someone else 404s (ownership gate) — never
        # leaks even an empty preview.
        other = _make_other_user(db)
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        foreign = upsert_topic(db, TopicConfig(
            user_id=other["id"], name="Theirs", subjects=["x"],
        ))
        resp = client.post(
            f"/profile/topic-digest/{foreign.id}/preview",
            cookies=user_cookies,
        )
        assert resp.status_code == 404

    def test_include_drops_unauthorized_account(
        self, client, user_cookies, regular_user, db,
    ):
        # §5 at the INCLUDE write boundary: a forged account_id the
        # requester can't manage is refused (403) — no topic_hits row.
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/hits/include",
            data={"account_id": str(theirs), "message_id": "<m@x>"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403
        c = db.execute("SELECT COUNT(*) AS c FROM topic_hits").fetchone()
        assert (c["c"] if hasattr(c, "keys") else c[0]) == 0

    def test_remove_drops_unauthorized_account(
        self, client, user_cookies, regular_user, db,
    ):
        # N-371 §5 at the DELETE hit-remove boundary
        # (`profile.py::profile_topic_digest_hit_remove` — `is_manageable`
        # gate at profile.py:5858). This closes the behavioral-coverage
        # gap sibling of `test_include_drops_unauthorized_account` (POST
        # /hits/include) + `test_feedback_403_on_foreign_account` (POST
        # /hits/feedback). All three actuators route their client-submitted
        # `account_id` through the manageable-set intersection SSOT
        # (`web/account_scope.py::is_manageable`) per PD #9; the DELETE
        # boundary was structurally verified but never BEHAVIORALLY
        # exercised — a router refactor that dropped the `is_manageable`
        # branch would fail the structural pin but a purely stale-branch
        # regression (e.g. topic ownership passes but manageability check
        # is short-circuited by a dev-mode ENV) would slip a structural-
        # only net. This test drives the whole stack: mint a topic owned
        # by the requester, seed a topic_hit on a FOREIGN account, DELETE
        # via the requester's session → expect quiet-200 (per DESIGN NOTE
        # below — the DELETE actuator intentionally suppresses the 403
        # signal on the wire) + `removed_at IS NULL` (the row is
        # untouched, not soft-removed — the load-bearing invariant,
        # asserted against the database rather than the wire status).
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")
        from email_triage.actions.topic_configs import (
            TopicConfig, insert_topic_hit, upsert_topic,
        )
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))
        # Also seed a topic_hit on the REQUESTER'S OWN account. This is
        # the POSITIVE CONTROL leg (DA F1): without a mirror-authorized
        # DELETE that DOES flip `removed_at`, the negative leg alone is
        # vacuous — a semantic bypass making `_remove_db_work` always
        # return False (upstream `get_topic` or `can_modify_owned_resource`
        # refactor bug, `db_call` swallowing) would also pass the negative
        # leg. Pinning both legs together makes the test interprocedural
        # per PD #2 — it fails iff the `is_manageable` intersection is
        # BOTH the reason the foreign row survives AND absent as the
        # reason the owned row is soft-removed.
        mine = _make_account(db, regular_user["id"], "mine")
        # Seed both topic_hit rows through the storage SSOT
        # `insert_topic_hit` (its `@db_write` decoration composes safely
        # with the test's synchronous conn — verified by the surrounding
        # test class's sibling `test_include_drops_unauthorized_account`
        # using the same pattern via `db_call`).
        insert_topic_hit(
            db,
            topic_id=topic.id,
            account_id=theirs,
            rfc822_message_id="<foreign@x>",
            folder="INBOX",
            source="live",
        )
        insert_topic_hit(
            db,
            topic_id=topic.id,
            account_id=mine,
            rfc822_message_id="<owned@x>",
            folder="INBOX",
            source="live",
        )
        # Confirm neither row is soft-removed at the seed.
        pre_foreign = db.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
            (topic.id, theirs, "<foreign@x>"),
        ).fetchone()
        pre_owned = db.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
            (topic.id, mine, "<owned@x>"),
        ).fetchone()
        assert pre_foreign is not None, "foreign seed row missing"
        assert pre_owned is not None, "owned seed row missing"
        assert (pre_foreign["removed_at"] if hasattr(pre_foreign, "keys")
                else pre_foreign[0]) is None
        assert (pre_owned["removed_at"] if hasattr(pre_owned, "keys")
                else pre_owned[0]) is None

        # URL-encode the msgid segment (db-sme F2). The `:path` FastAPI
        # converter accepts the raw `<foreign@x>` too, but percent-
        # encoding the seed's stored `rfc822_message_id` is the safer
        # test contract — a future msgid picker/router shape (e.g. a
        # migration to strict-slug msgids) that normalized the raw form
        # would otherwise create a `msgid_url != stored_msgid` silent
        # miss, and the negative leg would pass VACUOUSLY (no matched
        # row, no UPDATE, quiet-200 either way).
        from urllib.parse import quote as _q
        foreign_url = (
            f"/profile/topic-digest/{topic.id}/hits/"
            f"{theirs}/{_q('<foreign@x>', safe='')}"
        )
        owned_url = (
            f"/profile/topic-digest/{topic.id}/hits/"
            f"{mine}/{_q('<owned@x>', safe='')}"
        )

        # NEGATIVE LEG — foreign account DELETE.
        # DESIGN NOTE (`profile.py:5872-5887`): idempotent / not-found /
        # unauthorized all collapse to a quiet 200 with an empty body so
        # the HTMX row-swap removes the chip regardless. The 403 signal
        # is INTENTIONALLY suppressed on the wire (an attacker cannot
        # distinguish "row didn't exist" from "not authorized" — a small
        # info-leak-hardening posture). The behavioral invariant PD #9
        # pins here is the DATABASE STATE, not the status code: the
        # foreign row's `removed_at` MUST stay NULL when the requester
        # can't manage the target account.
        resp_foreign = client.delete(foreign_url, cookies=user_cookies)
        assert resp_foreign.status_code == 200, (
            "DELETE hit-remove design is quiet-200 for idempotency; a "
            "different status shape means the router changed."
        )
        post_foreign = db.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
            (topic.id, theirs, "<foreign@x>"),
        ).fetchone()
        assert post_foreign is not None, "foreign row disappeared (unexpected)"
        assert (post_foreign["removed_at"] if hasattr(post_foreign, "keys")
                else post_foreign[0]) is None, (
            "removed_at was set — the DELETE actuator soft-removed a "
            "foreign account's row despite the manageability gate "
            "returning False. N-371 §5 fail-closed invariant violated "
            "at profile.py:5858."
        )

        # POSITIVE CONTROL LEG — owned account DELETE (DA F1 mirror leg).
        # The gate MUST allow the requester to soft-remove a hit on THEIR
        # OWN account. Without this leg, an upstream fail-closed regression
        # unrelated to `is_manageable` (a get_topic bug, a db_call swallow)
        # would silently pass the negative leg — the pin would rot into
        # false comfort. This mirror leg pins the two-sided contract.
        resp_owned = client.delete(owned_url, cookies=user_cookies)
        assert resp_owned.status_code == 200
        post_owned = db.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
            (topic.id, mine, "<owned@x>"),
        ).fetchone()
        assert post_owned is not None, "owned row disappeared (unexpected)"
        assert (post_owned["removed_at"] if hasattr(post_owned, "keys")
                else post_owned[0]) is not None, (
            "removed_at STAYED NULL on the owned-account DELETE — either "
            "the gate is failing closed for the WRONG reason (e.g. "
            "get_topic swallowed the topic_id, db_call swallowed, or the "
            "`_remove_db_work` closure regressed to always return False). "
            "The negative-leg assertion would then pass VACUOUSLY. "
            "N-371 positive-control invariant violated at profile.py:5858."
        )
        # And the foreign row is STILL untouched after the owned-leg
        # DELETE — a broader UPDATE would have soft-removed both.
        post_foreign_after = db.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id = ? AND account_id = ? AND rfc822_message_id = ?",
            (topic.id, theirs, "<foreign@x>"),
        ).fetchone()
        assert (post_foreign_after["removed_at"]
                if hasattr(post_foreign_after, "keys")
                else post_foreign_after[0]) is None, (
            "foreign row was soft-removed by the SECOND (owned-leg) "
            "DELETE — the UPDATE WHERE clause is too broad, or the "
            "actuator is scanning across the whole topic. N-371 §5 "
            "row-scope invariant violated."
        )


# ---------------------------------------------------------------------------
# 4. search-details calls resolve_nct
# ---------------------------------------------------------------------------

class TestSearchDetailsNct:
    """search-details exercises the REAL import path
    (``actions.clinicaltrials.normalize_nct`` + ``resolve_nct``) and the
    REAL render of ``profile/_topic_nct_result.html`` — only the HTTP
    boundary underneath ``resolve_nct`` is mocked.

    The previous version injected a FAKE ``email_triage.actions.topic_search``
    module, which masked TWO production bugs: (1) the handler imported a
    module that does not exist, and (2) it rendered the preview template,
    which ignores ``nct_result`` and always says "No matches yet". Mocking
    the boundary, not the seam (``pattern_parallel_build_mock_the_boundary
    _not_the_seam``), forces both the real import and the real card render.
    """

    # A realistic NCT00000419 (SELENA) v2 payload — the same study the
    # resolver-unit fixture uses. Only the whitelisted modules matter for
    # the render assertions, but a couple of PII-bearing extras are kept
    # so the render can't accidentally surface them.
    SELENA_PAYLOAD = {
        "protocolSection": {
            "identificationModule": {
                "officialTitle": (
                    "Safety of Estrogens in Lupus Erythematosus - National "
                    "Assessment (SELENA): Hormone Replacement Therapy"
                ),
            },
            "statusModule": {"overallStatus": "TERMINATED"},
            "sponsorCollaboratorsModule": {
                "leadSponsor": {"name": "NYU Langone Health"},
            },
            "descriptionModule": {
                "briefSummary": (
                    "SELENA tests whether postmenopausal women with lupus "
                    "can safely use hormone therapy."
                ),
            },
            "conditionsModule": {"conditions": ["Systemic Lupus Erythematosus"]},
            "designModule": {"phases": ["PHASE3"]},
            "armsInterventionsModule": {
                "interventions": [{"name": "Premarin and Provera"}],
            },
            # PII-bearing module that must never reach the rendered card.
            "contactsLocationsModule": {
                "overallOfficials": [{"name": "Dr. Jane Investigator"}],
            },
        },
    }

    def _mock_http(self, *, status_code, payload):
        """Patch the HTTP boundary INSIDE the real resolver — exactly the
        seam the resolver-unit tests patch (``clinicaltrials._http.get``).
        The real ``resolve_nct`` import path, normalisation, whitelist
        flatten, and the router's render all run for real.

        Returns the patcher context manager; use it as ``with ...:``.
        """
        from email_triage.actions import clinicaltrials as ct

        resp = MagicMock()
        resp.status_code = status_code
        if payload is None:
            resp.json.side_effect = json.JSONDecodeError("no body", "", 0)
        else:
            resp.json.return_value = payload

        fake_client = MagicMock()
        fake_client.get = AsyncMock(return_value=resp)
        # Empty the resolver cache so a prior test's hit can't mask the
        # boundary (and so this fetch actually runs).
        ct._clear_cache()
        return patch.object(ct._http, "get", AsyncMock(return_value=fake_client))

    def test_search_details_renders_confirm_card_for_valid_nct(
        self, client, user_cookies, regular_user, db,
    ):
        # SELENA fixture: NCT00000419 → 'Safety of Estrogens in Lupus...',
        # TERMINATED, lead sponsor NYU Langone. Drive the route through the
        # REAL resolver (HTTP boundary mocked) and assert the §3d confirm
        # card actually rendered — title + sponsor + Replace/Append.
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="SELENA", subjects=["SELENA"],
        ))

        with self._mock_http(status_code=200, payload=self.SELENA_PAYLOAD):
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "NCT00000419", "details": "existing text"},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text

        # The confirm CARD rendered — the study's whitelisted fields are
        # present in the response body (the old preview template would
        # have said "No matches yet" and dropped all of these).
        assert "Safety of Estrogens in Lupus" in body
        assert "NYU Langone Health" in body
        assert "TERMINATED" in body
        assert "Systemic Lupus Erythematosus" in body
        assert "NCT00000419" in body
        # The confirm affordances are present.
        assert "Replace Details" in body
        assert "Append" in body
        assert "Cancel" in body
        # The Study ID is RETAINED: it LEADS the fill text (so Replace /
        # Append write it into Details) and is exposed for the client-side
        # subject-add — the lookup used to drop the typed number entirely.
        assert "Study NCT00000419:" in body
        assert 'id="topic-nct-id-value"' in body
        # The canonical id is reflected back into the lookup field — BOTH
        # via a server-driven OOB swap (robust even if the inline script
        # doesn't run in the htmx swap) AND the inline script. The OOB
        # element carries the normalised id and targets #topic-search-query.
        assert 'hx-swap-oob="true"' in body
        assert "topic-search-query" in body
        import re as _re
        assert _re.search(
            r'id="topic-search-query"[^>]*hx-swap-oob="true"[^>]*'
            r'value="NCT00000419"',
            body, _re.DOTALL,
        ) or _re.search(
            r'hx-swap-oob="true"[^>]*id="topic-search-query"[^>]*'
            r'value="NCT00000419"',
            body, _re.DOTALL,
        ), "OOB lookup-field input missing the canonical id value"
        # The whole point: NOT the preview "no matches" copy.
        assert "No matches yet" not in body
        # PII-bearing fields must not leak into the card.
        assert "Jane Investigator" not in body

    def test_search_details_not_found_renders_search_error(
        self, client, user_cookies, regular_user, db,
    ):
        # A well-formed but unknown registry number (registry 404s) →
        # the search-error branch, not a confirm card.
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))

        with self._mock_http(status_code=404, payload={"message": "not found"}):
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "NCT99999999"},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # The §3d not-found copy, echoing the typed number.
        assert "No public study found for NCT99999999" in body
        assert "type Details by hand" in body
        # No confirm-card affordances on a miss.
        assert "Replace Details" not in body

    def test_search_details_non_nct_query_no_searxng_shows_setup_message(
        self, client, user_cookies, regular_user, db,
    ):
        # A non-registry query routes to the free-text path. With no
        # SearXNG configured (default) and a non-HIPAA Topic, it renders the
        # self-explaining "not set up" copy — and never touches the NCT
        # registry HTTP boundary.
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))
        # Ensure NOT configured (the settings cache is process-global —
        # clear so a prior test that set a URL can't leak in).
        set_web_search_searxng_url(db, None)

        from email_triage.actions import clinicaltrials as ct
        ct._clear_cache()
        with patch.object(ct._http, "get") as http_get:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "just some free text"},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        # No registry number detected → the NCT HTTP boundary is untouched.
        http_get.assert_not_called()
        body = resp.text
        # "isn't" autoescapes to "isn&#39;t" — match apostrophe-free.
        assert "Internet search" in body and "set up on this install" in body
        # Self-explaining — never an admin-path hint.
        assert "ask your administrator" not in body.lower()
        assert "Replace Details" not in body

    def test_search_details_404_on_foreign_topic(
        self, client, user_cookies, regular_user, db,
    ):
        other = _make_other_user(db)
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        foreign = upsert_topic(db, TopicConfig(
            user_id=other["id"], name="Theirs", subjects=["x"],
        ))

        from email_triage.actions import clinicaltrials as ct
        ct._clear_cache()
        # The ownership gate must fire BEFORE any resolver work — if the
        # HTTP boundary is touched at all on a foreign topic, that's a leak.
        with patch.object(ct._http, "get") as http_get:
            resp = client.post(
                f"/profile/topic-digest/{foreign.id}/search-details",
                data={"query": "NCT00000419"},
                cookies=user_cookies,
            )
        assert resp.status_code == 404
        http_get.assert_not_called()


# ---------------------------------------------------------------------------
# 5b. search-details free-text path (SearXNG) — non-HIPAA only
# ---------------------------------------------------------------------------

class TestSearchDetailsWebSearch:
    """The free-text (non-NCT) branch: SearXNG when configured + the Topic
    is non-HIPAA; registry-only (no web egress) when a HIPAA mailbox is in
    the Topic. The fetched bundle feeds a LOCAL-LLM summary (the summary
    card, with the result URLs as a Sources list); a None summary (LLM
    slow/unhealthy) falls back to the raw-results card."""

    _BUNDLE = {
        "results": [
            {"title": "SELENA estrogen lupus", "url": "https://ex.com/a",
             "content": "A phase 3 study."},
            {"title": "Second hit", "url": "https://ex.com/b", "content": "More."},
        ],
        "corrections": [], "suggestions": [], "answers": [],
    }

    def _patch(self, *, bundle=Ellipsis, summary=None):
        """Patch BOTH the provider bundle fetch AND the LLM summarizer.
        Returns (bundle_patcher, summary_patcher) — enter both with ``with``."""
        from unittest.mock import AsyncMock
        b = self._BUNDLE if bundle is Ellipsis else bundle
        return (
            patch("email_triage.actions.web_search.web_search_bundle",
                  AsyncMock(return_value=b)),
            patch("email_triage.web.topic_search_summary.summarize_web_results",
                  AsyncMock(return_value=summary)),
        )

    def test_summary_card_when_llm_available(
        self, client, user_cookies, regular_user, db,
    ):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        acct = _make_account(db, regular_user["id"], "plain")  # non-HIPAA
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
            selected_account_ids=[acct],
        ))
        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch(summary="A phase 3 lupus estrogen safety study.")
        with p_b as mb, p_s as ms:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "selena lupus"}, cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # The summary card: the AI draft + Replace + a Sources list of URLs.
        assert "Suggested Details" in body
        assert "A phase 3 lupus estrogen safety study." in body
        assert "Replace Details" in body
        assert "Sources" in body
        assert "https://ex.com/a" in body          # source url listed
        assert 'hx-swap-oob="true"' in body         # query retained
        mb.assert_awaited()
        _, kwargs = mb.await_args
        assert kwargs.get("base_url") == "http://lan:8080"
        ms.assert_awaited()

    def test_fallback_raw_results_when_summary_unavailable(
        self, client, user_cookies, regular_user, db,
    ):
        # Summarizer returns None (LLM slow / unhealthy / air-gapped) → the
        # editor degrades to the raw-results card (today's behavior).
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        acct = _make_account(db, regular_user["id"], "plain")
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
            selected_account_ids=[acct],
        ))
        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch(summary=None)
        with p_b as mb, p_s as ms:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "selena lupus"}, cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        assert "Suggested Details" not in body       # NOT the summary card
        assert "Append to Details" in body           # the raw-results card
        assert "SELENA estrogen lupus" in body
        mb.assert_awaited()
        ms.assert_awaited()

    def test_hipaa_topic_is_registry_only_no_web_search(
        self, client, user_cookies, regular_user, db,
    ):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        phi = _make_account(db, regular_user["id"], "phi", hipaa=True)
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
            selected_account_ids=[phi],
        ))
        # Configured — but the HIPAA gate must block BEFORE any web egress.
        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch()
        with p_b as mb, p_s as ms:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "free text about a patient"},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # Most-restrictive-wins → registry-only copy; NO web search, NO LLM.
        assert "protected (HIPAA) mailbox" in body
        assert "registry" in body.lower()
        mb.assert_not_awaited()
        ms.assert_not_awaited()
        assert "Append to Details" not in body

    def test_unsaved_hipaa_mailbox_in_form_forces_registry_only(
        self, client, user_cookies, regular_user, db,
    ):
        # SME 2026-06-08 fail-open fix: the editor POSTs its LIVE mailbox
        # selection. A HIPAA mailbox added in the editor but NOT yet saved
        # must still close the gate (registry-only), even though the saved
        # Topic is non-HIPAA.
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        plain = _make_account(db, regular_user["id"], "plain")        # non-HIPAA
        phi = _make_account(db, regular_user["id"], "phi", hipaa=True)
        # SAVED topic is non-HIPAA (only the plain mailbox).
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
            selected_account_ids=[plain],
        ))
        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch()
        with p_b as mb, p_s as ms:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "free text",
                      "selected_account_ids": [str(plain), str(phi)]},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        assert "protected (HIPAA) mailbox" in resp.text
        mb.assert_not_awaited()
        ms.assert_not_awaited()

    def test_unmanaged_submitted_account_is_dropped_not_a_probe(
        self, client, user_cookies, regular_user, db,
    ):
        # hipaa-sme 2026-06-08: a submitted account id the requester does NOT
        # manage is intersected OUT before the gate, so it can't be used as
        # an is-HIPAA enumeration oracle. A foreign/bogus id therefore has NO
        # effect — the non-HIPAA Topic proceeds to web search as if it were
        # absent (it does NOT force registry-only).
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))
        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch(summary=None)
        with p_b as mb, p_s:
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "free text", "selected_account_ids": ["999999"]},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # The foreign id was dropped → NOT registry-only → web search ran.
        assert "protected (HIPAA) mailbox" not in body
        mb.assert_awaited()

    def test_new_unsaved_topic_lookup_does_not_404(
        self, client, user_cookies, regular_user, db,
    ):
        # Regression (walkthrough 2026-06-08): the editor's "Look up" on a
        # NEW Topic posts to /profile/topic-digest/NEW/search-details. The
        # route was `{topic_id:int}` so `new` 404'd — lookup never worked on
        # an unsaved Topic. It must now resolve (200) and run the free-text
        # path (no saved Topic, non-HIPAA, SearXNG configured).
        from email_triage.web.db import set_web_search_searxng_url

        set_web_search_searxng_url(db, "http://lan:8080")
        p_b, p_s = self._patch(summary="New topic summary draft.")
        with p_b as mb, p_s:
            resp = client.post(
                "/profile/topic-digest/new/search-details",
                data={"query": "lupus estrogen"},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        assert "New topic summary draft." in resp.text
        mb.assert_awaited()

    def test_route_drives_real_provider_through_http_boundary(
        self, client, user_cookies, regular_user, db,
    ):
        # Seam test: route → REAL web_search_bundle → mocked _http.get, so
        # the route↔provider contract (base_url build, JSON parse, whitelist,
        # render) runs for real. Summary mocked None → the raw-results card.
        from unittest.mock import AsyncMock, MagicMock
        from email_triage.actions import web_search as ws
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        plain = _make_account(db, regular_user["id"], "plain")
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
            selected_account_ids=[plain],
        ))
        set_web_search_searxng_url(db, "http://lan:8080")
        resp_obj = MagicMock()
        resp_obj.status_code = 200
        resp_obj.json.return_value = {"results": [
            {"title": "Real Seam Hit", "url": "https://e/x",
             "content": "a public snippet"},
        ]}
        fake_client = MagicMock()
        fake_client.get = AsyncMock(return_value=resp_obj)
        with patch.object(ws._http, "get", AsyncMock(return_value=fake_client)), \
             patch("email_triage.web.topic_search_summary.summarize_web_results",
                   AsyncMock(return_value=None)):
            resp = client.post(
                f"/profile/topic-digest/{topic.id}/search-details",
                data={"query": "seam test", "selected_account_ids": [str(plain)]},
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        assert "Real Seam Hit" in resp.text
        assert "Append to Details" in resp.text

    def test_search_cooldown_rate_limits_rapid_fire(
        self, client, user_cookies, regular_user, db,
    ):
        # Per-user Internet-Search cooldown: a 2nd "Look up" within the
        # window is rate-limited (protects the egress from rapid-fire). The
        # two POSTs share app.state (reset once per test), so the bucket set
        # by the 1st request rate-limits the 2nd.
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.db import set_web_search_searxng_url

        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="T", subjects=["x"],
        ))
        set_web_search_searxng_url(db, None)  # not-configured = fast path
        url = f"/profile/topic-digest/{topic.id}/search-details"
        r1 = client.post(url, data={"query": "first"}, cookies=user_cookies)
        assert r1.status_code == 200
        assert "a bit fast" not in r1.text          # 1st accepted
        r2 = client.post(url, data={"query": "second"}, cookies=user_cookies)
        assert r2.status_code == 200
        assert "a bit fast" in r2.text               # 2nd rate-limited

    def test_searxng_url_setting_round_trip(self, db):
        from email_triage.web.db import (
            get_web_search_searxng_url,
            set_web_search_searxng_url,
        )
        set_web_search_searxng_url(db, None)
        assert get_web_search_searxng_url(db) is None
        set_web_search_searxng_url(db, "http://h:8080")
        assert get_web_search_searxng_url(db) == "http://h:8080"
        # Blank/whitespace clears it.
        set_web_search_searxng_url(db, "   ")
        assert get_web_search_searxng_url(db) is None


# ---------------------------------------------------------------------------
# 6. Re-Triage endpoint — enqueues a STORING back-scan; §5 fail-closed
# ---------------------------------------------------------------------------

class TestRetriageEndpoint:
    def _topic(self, db, user_id, account_ids):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        return upsert_topic(db, TopicConfig(
            user_id=user_id, name="Watch", subjects=["X"],
            selected_account_ids=list(account_ids),
        ))

    def _jobs(self, db):
        import json as _json
        rows = db.execute(
            "SELECT account_id, query FROM triage_jobs "
            "WHERE kind='topic_backscan'"
        ).fetchall()
        out = []
        for r in rows:
            acct = r["account_id"] if hasattr(r, "keys") else r[0]
            q = r["query"] if hasattr(r, "keys") else r[1]
            out.append((acct, _json.loads(q)))
        return out

    def test_enqueues_backscan_for_authorized_account(
        self, client, db, regular_user, user_cookies,
    ):
        acct = _make_account(db, regular_user["id"], "primary")
        topic = self._topic(db, regular_user["id"], [acct])
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/retriage",
            data={"window_days": "60"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        jobs = self._jobs(db)
        assert len(jobs) == 1
        job_acct, payload = jobs[0]
        assert job_acct == acct
        assert payload["topic_id"] == topic.id
        assert payload["window_days"] == 60

    def test_all_window_maps_to_zero(
        self, client, db, regular_user, user_cookies,
    ):
        acct = _make_account(db, regular_user["id"], "primary")
        topic = self._topic(db, regular_user["id"], [acct])
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/retriage",
            data={"window_days": "0"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert self._jobs(db)[0][1]["window_days"] == 0

    def test_bad_window_falls_back_to_default(
        self, client, db, regular_user, user_cookies,
    ):
        acct = _make_account(db, regular_user["id"], "primary")
        topic = self._topic(db, regular_user["id"], [acct])
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/retriage",
            data={"window_days": "999"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert self._jobs(db)[0][1]["window_days"] == 30

    def test_drops_unauthorized_account_fail_closed(
        self, client, db, regular_user, user_cookies,
    ):
        # §5: a Topic whose selected_account_ids names a FOREIGN account
        # must enqueue ONLY the requester's manageable account.
        mine = _make_account(db, regular_user["id"], "mine")
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")
        topic = self._topic(db, regular_user["id"], [mine, theirs])
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/retriage",
            data={"window_days": "30"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        acct_ids = {a for a, _ in self._jobs(db)}
        assert mine in acct_ids
        assert theirs not in acct_ids

    def test_foreign_topic_404(
        self, client, db, regular_user, user_cookies,
    ):
        other = _make_other_user(db)
        foreign = self._topic(db, other["id"], [])
        resp = client.post(
            f"/profile/topic-digest/{foreign.id}/retriage",
            data={"window_days": "30"}, cookies=user_cookies,
        )
        assert resp.status_code == 404
        assert self._jobs(db) == []


# ---------------------------------------------------------------------------
# 7. Study lookup field retains the Study ID (OOB on lookup + reopen prefill)
# ---------------------------------------------------------------------------

class TestStudyLookupPrefill:
    def test_editor_prefills_lookup_field_from_nct_subject(
        self, client, db, regular_user, user_cookies,
    ):
        # A saved Topic stores its registry number as a Subject; on reopen
        # the lookup field must show it again (the operator expects the
        # Study ID to persist in the field, not only in Subjects).
        import re
        from email_triage.actions.topic_configs import (
            TopicConfig, upsert_topic,
        )
        acct = _make_account(db, regular_user["id"], "primary")
        topic = upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="Lupus",
            subjects=["SELENA", "NCT00000419"],
            selected_account_ids=[acct],
        ))
        resp = client.get(
            f"/profile/topic-digest/{topic.id}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert re.search(
            r'id="topic-search-query"[^>]*value="NCT00000419"',
            resp.text, re.DOTALL,
        ), "lookup field not prefilled from the NCT-shaped subject"

    def test_new_editor_lookup_field_is_empty(
        self, client, db, regular_user, user_cookies,
    ):
        # A brand-new Topic has no NCT subject → the lookup field is empty.
        import re
        _make_account(db, regular_user["id"], "primary")
        resp = client.get(
            "/profile/topic-digest/new", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert re.search(
            r'id="topic-search-query"[^>]*value=""',
            resp.text, re.DOTALL,
        ), "new-editor lookup field should render an empty value"


class TestPreviewKeywordVsDetails:
    """Operator 2026-06-12 — the Preview is a cheap keyword pass over the WHOLE
    window (NO 25-message-per-account starvation of mail filed in a non-INBOX
    folder — the mempalace `Tech/GitHub` miss); 'Test Details' is the bounded
    LLM pass over ONLY the keyword candidates."""

    def _patch(self, monkeypatch, msgs, *, llm_calls):
        import email_triage.jobs.topic_backscan as backscan
        import email_triage.actions.topic_matcher as matcher
        import email_triage.web.routers.ui.profile as profile_mod
        monkeypatch.setattr(backscan, "_build_classifier", lambda app: object())

        # Provider BOUNDARY — the Preview now searches Subject chips server-side
        # and fetches ONLY the matches. The fake's search returns the msgs whose
        # Subject contains the chip, so the noise messages are never even
        # returned (that's the whole point of the server-side search — no more
        # fetching every header in the window).
        monkeypatch.setattr(
            profile_mod, "_create_provider_from_account",
            lambda account, secrets: _FakeProvider(list(msgs)),
        )

        async def _fake_match(message, active_topics, classifier, *,
                              body_keywords=None, categories=None, k=6):
            llm_calls.append((getattr(message, "headers", {}) or {}).get("Message-ID"))
            return [{
                "topic_id": active_topics[0].id, "matched": True,
                "confidence": 0.9, "reason_terms": ["MemPalace"],
            }]
        monkeypatch.setattr(matcher, "match_topics_for_message", _fake_match)

    def _topic(self, db, regular_user, acct):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        return upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="MemPalace",
            subjects=["MemPalace"], selected_account_ids=[acct], mode="full",
        ))

    def test_keyword_preview_finds_match_past_the_old_25_cap_no_llm(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        # 40 non-matching messages BEFORE the matching one — the old 25-cap
        # would have starved it; the keyword pass must still find .
        msgs = [_FakeMsg(f"<noise{i}@x>", subject="Daily standup notes")
                for i in range(40)]
        msgs.append(_FakeMsg("<mem@x>", subject="[MemPalace/mempalace] Release v3.3.0"))
        llm_calls: list = []
        self._patch(monkeypatch, msgs, llm_calls=llm_calls)

        resp = client.post(
            f"/profile/topic-digest/{topic.id}/preview",
            data={"group_by_account": "1"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "MemPalace" in resp.text          # the 41st message IS surfaced
        assert llm_calls == []                    # keyword mode never calls the LLM

    def test_keyword_preview_renders_real_subject_not_placeholder(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        """Regression (prod 2026-06-12, caught in the live Playwright review):
        the keyword scan ALREADY fetched headers, so each row MUST render the
        real Subject/From — not the fail-open "(metadata unavailable)"
        placeholder. The bug: display metadata came from a SECOND per-hit fetch
        keyed on ``provider_uid``, which a live IMAP ``EmailMessage`` never
        carries (only ``message_id`` = the UID), so the fetch's ``uid is None``
        guard tripped and EVERY row degraded. The old tests only asserted the
        matched-TERM chip ("MemPalace"), which renders regardless — so they
        stayed green while the view was broken. Assert the VIEW carries the
        Subject sourced straight off the in-hand message (#feedback_test_the_view).
        """
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        # Subject carries the Topic term (so it matches) PLUS a unique token that
        # is NOT a matched_term — proving the SUBJECT itself (not just the
        # why-chip) is rendered from the in-hand headers.
        msgs = [_FakeMsg("<mem@x>", subject="MemPalace release UNIQ-SUBJ-7F3")]
        llm_calls: list = []
        self._patch(monkeypatch, msgs, llm_calls=llm_calls)

        resp = client.post(
            f"/profile/topic-digest/{topic.id}/preview",
            data={"group_by_account": "1"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "UNIQ-SUBJ-7F3" in resp.text            # the real Subject renders
        assert "sender@example.com" in resp.text        # the real From renders
        assert "metadata unavailable" not in resp.text  # NOT the fail-open ph.
        assert llm_calls == []                          # keyword mode: no LLM

    def test_test_details_runs_llm_only_on_keyword_candidates(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        msgs = [
            _FakeMsg("<noise@x>", subject="unrelated lunch thread"),
            _FakeMsg("<mem@x>", subject="[MemPalace] Release"),
        ]
        llm_calls: list = []
        self._patch(monkeypatch, msgs, llm_calls=llm_calls)

        resp = client.post(
            f"/profile/topic-digest/{topic.id}/test-details",
            data={"group_by_account": "1"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        # The LLM ran ONLY on the keyword candidate, never the noise message.
        assert llm_calls == ["<mem@x>"]


class TestTopicFeedbackRoute:
    """Operator 2026-06-12 'curation + reinforcement loop' — the thumbs route
    + the matcher honoring the learned sender signal end-to-end."""

    def _topic(self, db, regular_user, acct):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        return upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="MemPalace",
            subjects=["MemPalace"], selected_account_ids=[acct], mode="full",
        ))

    def test_thumbs_down_records_sender_signal(
        self, client, user_cookies, regular_user, db,
    ):
        from email_triage.actions.topic_configs import get_topic_sender_signals
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/hits/feedback",
            data={"vote": "down", "account_id": str(acct),
                  "message_id": "<m@x>", "sender": "Fred <fred@fireflies.ai>"},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Dropped" in resp.text
        assert get_topic_sender_signals(db, topic.id) == {"fred@fireflies.ai": -1}

    def test_feedback_403_on_foreign_account(
        self, client, user_cookies, regular_user, db,
    ):
        # §5 fail-closed: a forged POST naming a foreign account is rejected.
        other = _make_other_user(db)
        theirs = _make_account(db, other["id"], "theirs")
        topic = self._topic(db, regular_user, theirs)  # owned by requester
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/hits/feedback",
            data={"vote": "down", "account_id": str(theirs),
                  "message_id": "<m@x>", "sender": "fred@x.com"},
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_preview_auto_drops_muted_sender(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        import email_triage.jobs.topic_backscan as backscan
        import email_triage.web.routers.ui.profile as profile_mod
        from email_triage.actions.topic_configs import record_topic_feedback

        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        # Mute fred@fireflies.ai for this Topic.
        record_topic_feedback(db, topic_id=topic.id, account_id=acct,
                              vote=-1, sender="fred@fireflies.ai")

        # Two matching messages — one from the muted sender, one kept.
        msgs = [
            _FakeMsg("<muted@x>", subject="[MemPalace] Release",
                     frm="Fred <fred@fireflies.ai>"),
            _FakeMsg("<kept@x>", subject="[MemPalace] Release",
                     frm="Ben <ben@github.com>"),
        ]
        monkeypatch.setattr(backscan, "_build_classifier", lambda app: object())
        monkeypatch.setattr(
            profile_mod, "_create_provider_from_account",
            lambda account, secrets: _FakeProvider(msgs),
        )

        resp = client.post(
            f"/profile/topic-digest/{topic.id}/preview",
            data={"group_by_account": "1"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        # The muted sender's message is auto-dropped; the kept one surfaces.
        assert "ben@github.com" in resp.text
        assert "fred@fireflies.ai" not in resp.text


class TestTopicFeedbackUnmute:
    """The un-mute path — the ONLY undo for a muted sender (its mail never
    reappears to thumbs-up, so the editor list + this route is the reverse)."""

    def _topic(self, db, regular_user, acct):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        return upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="MemPalace",
            subjects=["MemPalace"], selected_account_ids=[acct], mode="full",
        ))

    def test_unmute_clears_signal(self, client, user_cookies, regular_user, db):
        from email_triage.actions.topic_configs import (
            record_topic_feedback, get_topic_sender_signals,
        )
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        record_topic_feedback(db, topic_id=topic.id, account_id=acct,
                              vote=-1, sender="fred@fireflies.ai")
        assert get_topic_sender_signals(db, topic.id) == {"fred@fireflies.ai": -1}
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/feedback/unmute",
            data={"sender": "fred@fireflies.ai"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert get_topic_sender_signals(db, topic.id) == {}

    def test_editor_lists_muted_senders_with_unmute(
        self, client, user_cookies, regular_user, db,
    ):
        from email_triage.actions.topic_configs import record_topic_feedback
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        record_topic_feedback(db, topic_id=topic.id, account_id=acct,
                              vote=-1, sender="fred@fireflies.ai")
        resp = client.get(
            f"/profile/topic-digest/{topic.id}/edit", cookies=user_cookies,
        )
        assert resp.status_code == 200
        body = resp.text
        assert "Muted senders" in body
        assert "fred@fireflies.ai" in body
        assert "un-mute" in body
        assert "/feedback/unmute" in body


class TestSkipSelfGeneratedContent:
    """Operator 2026-06-12: the Preview (and the whole Topic system) must never
    surface or match email-triage's OWN generated content — flagged with the
    X-Email-Triage loop-prevention header."""

    def _topic(self, db, regular_user, acct):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        return upsert_topic(db, TopicConfig(
            user_id=regular_user["id"], name="MemPalace",
            subjects=["MemPalace"], selected_account_ids=[acct], mode="full",
        ))

    def test_preview_skips_email_triage_generated_message(
        self, client, user_cookies, regular_user, db, monkeypatch,
    ):
        import email_triage.jobs.topic_backscan as backscan
        import email_triage.web.routers.ui.profile as profile_mod
        acct = _make_account(db, regular_user["id"], "mine")
        topic = self._topic(db, regular_user, acct)
        msgs = [
            # email-triage's own digest that happens to match the Subject term.
            _FakeMsg("<self@x>", subject="[MemPalace] your digest",
                     frm="triage@myinstall.example",
                     et_header="recipient_digest"),
            # A genuine external match.
            _FakeMsg("<real@x>", subject="[MemPalace] Release",
                     frm="ben@github.com"),
        ]
        monkeypatch.setattr(backscan, "_build_classifier", lambda app: object())
        monkeypatch.setattr(
            profile_mod, "_create_provider_from_account",
            lambda account, secrets: _FakeProvider(msgs),
        )
        resp = client.post(
            f"/profile/topic-digest/{topic.id}/preview",
            data={"group_by_account": "1"}, cookies=user_cookies,
        )
        assert resp.status_code == 200
        # The genuine match surfaces; the self-generated one is skipped.
        assert "&lt;real@x&gt;" in resp.text or "real@x" in resp.text
        assert "self@x" not in resp.text


def test_topic_digest_sender_drops_self_generated_rows():
    """The send-time backstop: a hit whose ephemeral header carries
    X-Email-Triage is dropped from the rendered digest rows even if a stale
    topic_hits row exists."""
    from email_triage.web.topic_digest_sender import _topic_rows_from_hits

    class _T:
        name = "MemPalace"

    hits = [
        {"rfc822_message_id": "<real@x>", "reason_terms": ["MemPalace"],
         "first_seen_at": "2026-06-01T00:00:00Z", "account_id": 1},
        {"rfc822_message_id": "<self@x>", "reason_terms": ["MemPalace"],
         "first_seen_at": "2026-06-02T00:00:00Z", "account_id": 1},
    ]
    metas = {
        "<real@x>": {"sender": "ben@github.com", "subject": "Release",
                     "self_generated": False},
        "<self@x>": {"sender": "triage@x", "subject": "your digest",
                     "self_generated": True},
    }
    rows = _topic_rows_from_hits(_T(), hits, metas)
    subjects = [r["subject"] for r in rows]
    assert "Release" in subjects
    assert "your digest" not in subjects
    assert len(rows) == 1
