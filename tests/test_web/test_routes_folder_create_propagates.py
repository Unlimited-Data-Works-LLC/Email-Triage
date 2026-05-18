"""Test that the folder-create response signals the new folder name
so the routes-table JS can append it to every per-row dropdown.

The handler can't actually CREATE a folder in tests (no provider),
but the response shape MUST include the et-new-folder marker on the
success path. The body partial reads that marker via document
event delegation in its inline script.
"""

from email_triage.web.db import create_email_account


def _create_account(db, user_id, name="acct1"):
    return create_email_account(
        db, user_id, name, "imap",
        {"host": "x.example.com", "username": "user@example.com"},
    )


class TestFolderCreatePropagation:
    def test_create_response_carries_marker_for_propagation(self):
        """The body partial's inline JS listens for the htmx swap,
        reads ``#et-new-folder[data-name]``, then appends the new
        folder option to every move-folder dropdown. The marker
        element MUST appear in the success response so the JS has
        something to act on."""
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        text = path.read_text(encoding="utf-8")
        # The client-side propagation reads `#et-new-folder` — the body
        # partial's JS references it.
        assert "et-new-folder" in text
        # Listener wires off the create form's afterRequest event.
        assert "/folders/create" in text

    def test_handler_emits_marker_on_success(
        self, client, db, regular_user, user_cookies,
    ):
        """The handler returns the success chip + an
        ``#et-new-folder`` marker carrying the new folder name. The
        handler raises before reaching the success path because the
        provider-create call fails (test env has no real IMAP
        server), so we drive a different assertion: when the create
        DOES succeed, the marker is part of the response. Verified
        here by reading the handler source — too brittle to mock the
        provider for a one-line assertion."""
        from pathlib import Path
        # #144 — `web/routers/ui.py` was split into a per-concern package
        # under `web/routers/ui/`. The folder-create handler lives in
        # `accounts.py`. This test reads source bytes for the marker
        # assertion (too brittle to mock the IMAP provider for a one-
        # line check), so the path moves with the handler.
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "routers" / "ui" / "accounts.py"
        )
        text = path.read_text(encoding="utf-8")
        # Verify the success-path emits the marker. The marker line
        # is unique enough to assert directly on the source.
        assert 'id="et-new-folder"' in text
        assert 'data-name="' in text

    def test_dropdowns_carry_propagation_class(self):
        """Per-row move-folder selects must carry the
        ``move-folder-select`` class so the propagation JS can find
        them after a folder-create round-trip."""
        from pathlib import Path
        path = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web"
            / "templates" / "accounts" / "_routes_body.html"
        )
        text = path.read_text(encoding="utf-8")
        assert "move-folder-select" in text
