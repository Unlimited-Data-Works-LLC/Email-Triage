"""Tests for the ``add-label`` route action — punch-list item #129 tail.

Covers:
  * /accounts/{id}/routes/save persists the add-label config
    (internal slugs + provider-native names).
  * The body partial renders the per-row add-label picker chips
    + free-text provider input.
  * Save-All bulk path persists the same config shape.
"""

from email_triage.web.db import (
    create_email_account, list_account_routes,
)


def _create_account(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "user@example.com"},
    )


class TestRouteSaveAddLabel:
    def test_save_persists_internal_and_provider_labels(
        self, client, db, regular_user, user_cookies,
    ):
        """POSTing actions=[add-label] with internal + provider names
        round-trips through ``upsert_account_route`` and lands on the
        action's ``config`` JSON. Shape matches what
        :class:`AddLabelAction` expects to read at execute time."""
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "newsletters",
                "actions": ["add-label"],
                "add_label_internal": ["newsletters", "tax-2026"],
                "add_label_provider": "Receipts/2026, Tax",
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200, f"body={resp.text!r}"
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        actions = nl["actions"]
        add_lbl = next(a for a in actions if a["action"] == "add-label")
        cfg = add_lbl["config"]
        assert set(cfg["labels"]) == {"newsletters", "tax-2026"}
        assert cfg["provider_labels"] == ["Receipts/2026", "Tax"]

    def test_save_internal_only_omits_provider_labels_key(
        self, client, db, regular_user, user_cookies,
    ):
        """When the operator only picks internal chips, the saved
        config should not carry an empty ``provider_labels`` list —
        the action treats absent + empty identically but the saved
        shape stays minimal."""
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "newsletters",
                "actions": ["add-label"],
                "add_label_internal": ["newsletters"],
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        add_lbl = next(a for a in nl["actions"] if a["action"] == "add-label")
        assert add_lbl["config"]["labels"] == ["newsletters"]
        assert "provider_labels" not in add_lbl["config"]

    def test_save_provider_only_omits_internal_labels_key(
        self, client, db, regular_user, user_cookies,
    ):
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save",
            data={
                "category": "newsletters",
                "actions": "add-label",
                "add_label_provider": "Tax",
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        add_lbl = next(a for a in nl["actions"] if a["action"] == "add-label")
        assert add_lbl["config"]["provider_labels"] == ["Tax"]
        assert "labels" not in add_lbl["config"]


class TestRouteSaveAllAddLabel:
    def test_save_all_persists_add_label_config(
        self, client, db, regular_user, user_cookies,
    ):
        """Save-All path's per-row form keys
        ``row_<i>_add_label_internal`` + ``row_<i>_add_label_provider``
        round-trip through the bulk save handler."""
        a1 = _create_account(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a1}/routes/save-all",
            data={
                "row_count": "1",
                "row_0_category": "newsletters",
                "row_0_actions": ["add-label"],
                "row_0_add_label_internal": ["newsletters", "tax-2026"],
                "row_0_add_label_provider": "Tax, Receipts/2026",
            },
            cookies=user_cookies,
        )
        assert resp.status_code == 200, f"body={resp.text!r}"
        routes = list_account_routes(db, a1)
        nl = next(r for r in routes if r["category"] == "newsletters")
        add_lbl = next(a for a in nl["actions"] if a["action"] == "add-label")
        assert set(add_lbl["config"]["labels"]) == {"newsletters", "tax-2026"}
        assert add_lbl["config"]["provider_labels"] == ["Tax", "Receipts/2026"]


class TestRoutesBodyPartial:
    """File-level assertions on the body partial — same pattern as
    ``test_routes_autosave.py`` for the no-Save-button + pending-class
    invariants. Catches accidental removal of the picker scaffolding
    without spinning up a full client request."""

    def _partial_text(self) -> str:
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        return path.read_text(encoding="utf-8")

    def test_partial_offers_add_label_picker(self):
        text = self._partial_text()
        # The picker fieldset declares the internal-chip checkbox name
        # the save handler reads via form.getlist().
        assert 'name="add_label_internal"' in text
        # The free-text provider field declares the single form key
        # the save handler reads via form.get().
        assert 'name="add_label_provider"' in text

    def test_partial_includes_descriptive_help_text(self):
        """Per audience rule — descriptive page text + tooltips that
        explain the picker WITHOUT pointing at admin paths or jargon.
        Strips Jinja comments + the AUDIENCE block before scanning so
        the rule documentation inside that block (which mentions
        ``/admin`` / ``/config`` BY name as forbidden surfaces) doesn't
        false-positive."""
        import re
        text = self._partial_text()
        assert "Labels to add" in text
        # Strip Jinja comments — those describe the rule, not the UI.
        body = re.sub(r"\{#.*?#\}", "", text, flags=re.DOTALL)
        # No admin-path references in the actual rendered surface.
        assert "/admin" not in body
        assert "/config" not in body
        # End-user copy, not jargon.
        assert "language model" not in body.lower()
        assert "RFC " not in body
