"""N-109: deactivated (is_active=0, creds-purged) accounts are HIDDEN from
operational PICKERS but stay visible in MANAGEMENT / audit / re-enable / purge
views.

Operator ruling 2026-06-20: "disable AND hide them" — this is the *hide* half
(the disable + audit-preservation half is N-108). The SSOT reader
``db/accounts.py::list_email_accounts`` gained an ``active_only`` param
(default False, preserving every management/audit/purge caller); operational
pickers pass ``active_only=True``.
"""
from __future__ import annotations

from email_triage.web.db import create_email_account, list_email_accounts
from email_triage.db.accounts import set_account_active


def _mk(db, user_id, name, active=True):
    aid = create_email_account(db, user_id, name, "imap", {"host": "x.com"})
    if not active:
        set_account_active(db, aid, False)
    db.commit()
    return aid


class TestSsotActiveOnlyParam:
    def test_default_returns_both_active_and_inactive(self, db, admin_user):
        """Default active_only=False MUST return ALL — every management /
        audit / re-enable / background-purge caller depends on this."""
        a = _mk(db, admin_user["id"], "N109ActiveA", active=True)
        d = _mk(db, admin_user["id"], "N109DeadA", active=False)
        ids = {r["id"] for r in list_email_accounts(db, user_id=admin_user["id"])}
        assert a in ids and d in ids

    def test_active_only_excludes_inactive_user_scoped(self, db, admin_user):
        a = _mk(db, admin_user["id"], "N109ActiveB", active=True)
        d = _mk(db, admin_user["id"], "N109DeadB", active=False)
        ids = {
            r["id"]
            for r in list_email_accounts(
                db, user_id=admin_user["id"], active_only=True
            )
        }
        assert a in ids
        assert d not in ids

    def test_active_only_excludes_inactive_admin_view(self, db, admin_user):
        """user_id=None (admin all-accounts) branch honors active_only too."""
        a = _mk(db, admin_user["id"], "N109ActiveC", active=True)
        d = _mk(db, admin_user["id"], "N109DeadC", active=False)
        ids = {r["id"] for r in list_email_accounts(db, active_only=True)}
        assert a in ids
        assert d not in ids

    def test_is_active_not_null_invariant(self, db):
        """The ``COALESCE(is_active, 1) = 1`` in the active_only filter is
        DEFENSIVE: ``email_accounts.is_active`` is NOT NULL today, so a NULL row
        can't occur — but COALESCE matches the consumer-side
        ``acct.get('is_active', True)`` convention and keeps the filter correct
        if the constraint is ever relaxed. Pin the NOT NULL invariant so that
        relaxation is a conscious choice that re-examines this filter."""
        cols = db.execute("PRAGMA table_info(email_accounts)").fetchall()
        is_active = [c for c in cols if c["name"] == "is_active"]
        assert is_active, "email_accounts must have an is_active column"
        assert is_active[0]["notnull"] == 1, (
            "is_active is NOT NULL — the COALESCE in list_email_accounts' "
            "active_only filter is defensive; revisit it if this changes"
        )


class TestTopicDigestCarveOut:
    """The Topic-digest multiselect hides deactivated accounts EXCEPT any the
    Topic already selected — so a now-deactivated selected account stays checked
    and Save round-trips it (no silent data loss). The auth set + decoration keep
    the FULL manageable set; only the rendered options are narrowed."""

    def test_selected_inactive_account_retained_unselected_hidden(self, db, admin_user):
        from email_triage.actions.topic_configs import TopicConfig, upsert_topic
        from email_triage.web.routers.ui.profile import _topic_editor_snapshot

        active = _mk(db, admin_user["id"], "N109CarveActive", active=True)
        sel_dead = _mk(db, admin_user["id"], "N109CarveSelDead", active=False)
        unsel_dead = _mk(db, admin_user["id"], "N109CarveUnselDead", active=False)

        saved = upsert_topic(db, TopicConfig(
            user_id=admin_user["id"], name="CarveTopic",
            selected_account_ids=[sel_dead],
        ))
        db.commit()

        ctx = _topic_editor_snapshot(db, admin_user, saved.id)
        picker_ids = {int(a["id"]) for a in ctx["manageable_accounts"]}

        assert active in picker_ids, "active account is offered"
        assert sel_dead in picker_ids, (
            "a deactivated account ALREADY SELECTED by the Topic must stay in "
            "the options so Save round-trips it (no silent drop)"
        )
        assert unsel_dead not in picker_ids, (
            "a deactivated account NOT selected by the Topic is hidden"
        )

    def test_new_topic_hides_all_inactive(self, db, admin_user):
        """A blank (new) Topic has no selected ids → every deactivated account
        is hidden; only active accounts are offered."""
        from email_triage.web.routers.ui.profile import _topic_editor_snapshot
        active = _mk(db, admin_user["id"], "N109NewActive", active=True)
        dead = _mk(db, admin_user["id"], "N109NewDead", active=False)
        ctx = _topic_editor_snapshot(db, admin_user, None)
        picker_ids = {int(a["id"]) for a in ctx["manageable_accounts"]}
        assert active in picker_ids
        assert dead not in picker_ids


class TestPurgeLoopsKeepInactive:
    """The user-offboard purge MUST enumerate deactivated accounts too — a
    deactivated account still owns credentials that must be purged
    (§164.310(d)(2)(i)); filtering the purge enumeration would orphan them. The
    preflight uses list_email_accounts WITHOUT active_only — pin that call shape."""

    def test_offboard_enumeration_call_shape_includes_inactive(self, db, admin_user):
        active = _mk(db, admin_user["id"], "N109PurgeActive", active=True)
        dead = _mk(db, admin_user["id"], "N109PurgeDead", active=False)
        # The EXACT call _delete_user_preflight (api.py) + _offboard_user
        # (users.py) use — no active_only, so the deactivated account's creds
        # still get purged on offboard.
        ids = {
            a["id"]
            for a in list_email_accounts(
                db, user_id=admin_user["id"], include_delegated=False
            )
        }
        assert active in ids
        assert dead in ids, (
            "purge enumeration MUST include deactivated accounts or their "
            "credentials orphan (§164.310(d)(2)(i))"
        )
