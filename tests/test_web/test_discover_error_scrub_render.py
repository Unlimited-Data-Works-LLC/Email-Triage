"""run18 #3 — operator-rendered error-list PHI scrub (§164.502(b) / §164.514(d)(1)).

The triage + discover result pages render an ``errors`` list straight into the
operator's authenticated, PHI-bearing admin session. Before run18 #3 the build
sites interpolated the RAW exception — and ``discover_run`` interpolated the
IMAP FOLDER NAME (a patient-named mailbox = a PHI shape) directly — a CIDI
divergence from the sibling ``triage_preview`` which already routes its error
text through ``scrub_error_for_persist``.

These tests exercise the REAL code:
* ``_scrub_folder_scan_error`` — the discover folder-scan funnel (scrub SSOT +
  HIPAA folder-name redaction) — directly, both HIPAA and non-HIPAA.
* the REAL templates (``_discover_results.html`` / ``_results.html``) rendered
  with a scrubbed errors list — proving the patient folder name + a leaked
  address are absent from the rendered VIEW (feedback_test_the_view_not_just_
  machinery).
* ``run_triage`` — the provider-error build site — proving ``result["errors"]``
  is scrubbed end to end.

No real domains: abstract typed placeholders only.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.config import SmtpConfig, TriageConfig
from email_triage.web.app import create_app
from email_triage.web.routers.ui.triage_classify import _scrub_folder_scan_error

# A synthetic patient-named mailbox folder (a relative IMAP name — NOT
# path-shaped, so the generic scrub SSOT cannot catch it; the HIPAA
# folder-redaction leg must).
_PHI_FOLDER = "INBOX.Patient-Smith-Labs"
_PHI_ADDR = "jane.doe@clinic.invalid"


# ---------------------------------------------------------------------------
# 1. The discover folder-scan funnel — scrub SSOT + HIPAA folder redaction
# ---------------------------------------------------------------------------

class TestScrubFolderScanError:
    def test_hipaa_redacts_folder_in_prose_and_exception_echo(self):
        """On a HIPAA account the folder name is redacted EVERYWHERE — the
        explicit interpolation AND any echo inside the exception text (which
        the path-shape scrubber can't catch for a relative mailbox name)."""
        exc = ValueError(
            f"SELECT '{_PHI_FOLDER}' failed for {_PHI_ADDR}"
        )
        msg = _scrub_folder_scan_error(
            "Could not peek", _PHI_FOLDER, exc, account_hipaa=True,
        )
        assert _PHI_FOLDER not in msg, f"patient folder leaked: {msg!r}"
        assert _PHI_ADDR not in msg, f"address leaked: {msg!r}"
        assert "[redacted]" in msg
        # The address gets the SSOT's address placeholder.
        assert "[redacted-addr]" in msg

    def test_non_hipaa_keeps_readable_folder(self):
        """Fail-closed only for HIPAA: a non-HIPAA account keeps the readable
        folder name (and the rest of the message), matching the sibling."""
        exc = TimeoutError("connection timed out")
        msg = _scrub_folder_scan_error(
            "Error selecting", "Work", exc, account_hipaa=False,
        )
        assert "Work" in msg
        assert "connection timed out" in msg

    def test_non_hipaa_still_scrubs_address_phi(self):
        """The scrub SSOT runs UNCONDITIONALLY (like the sibling): an address
        is stripped even for a non-HIPAA account; only the FOLDER readability
        is HIPAA-gated."""
        exc = ValueError(f"refused rcpt {_PHI_ADDR}")
        msg = _scrub_folder_scan_error(
            "Could not peek", "Work", exc, account_hipaa=False,
        )
        assert _PHI_ADDR not in msg
        assert "[redacted-addr]" in msg
        assert "Work" in msg  # folder still readable (non-HIPAA)

    def test_empty_folder_does_not_splice_placeholder(self):
        """The empty-string ``replace`` trap is guarded — an empty folder must
        not splice ``[redacted]`` between every character."""
        msg = _scrub_folder_scan_error(
            "Could not peek", "", ValueError("boom"), account_hipaa=True,
        )
        # No per-character splicing.
        assert "[redacted]b[redacted]" not in msg
        assert "boom" in msg


# ---------------------------------------------------------------------------
# 2. The rendered VIEW — patient folder + address absent from the HTML
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _env():
    return create_app().state.templates.env


def test_discover_results_view_scrubs_patient_folder(_env):
    exc = ValueError(f"SELECT '{_PHI_FOLDER}' failed for {_PHI_ADDR}")
    errors = [
        _scrub_folder_scan_error(
            "Could not peek", _PHI_FOLDER, exc, account_hipaa=True,
        )
    ]
    html = _env.get_template("triage/_discover_results.html").render(
        errors=errors,
        consolidated=[],
        raw_results=[],
        total=0,
        elapsed=0.0,
        query="ALL",
        acct={"name": "Clinic Inbox", "hipaa": True},
        new_count=0,
        existing_count=0,
        folders_scanned=["INBOX"],
        folders_with_results=[],
        hipaa_mode=True,
    )
    assert _PHI_FOLDER not in html, "patient folder name rendered to operator page"
    assert _PHI_ADDR not in html, "PHI address rendered to operator page"
    assert "[redacted]" in html
    # The error article shell is still rendered (operator sees that something
    # failed) — the message is scrubbed, not suppressed.
    assert "Error:" in html


def test_triage_results_view_renders_scrubbed_provider_error(_env):
    from email_triage._errfmt import scrub_error_for_persist

    errors = [
        scrub_error_for_persist(
            f"Provider error: SMTP refused rcpt {_PHI_ADDR}"
        )
    ]
    html = _env.get_template("triage/_results.html").render(
        results=[],
        errors=errors,
        total=0,
        query="ALL",
        acct={"name": "acct1", "hipaa": True},
        elapsed=0.0,
        hipaa_mode=True,
        dry_run=False,
        all_labels=[],
    )
    assert _PHI_ADDR not in html
    assert "[redacted-addr]" in html
    assert "Provider error" in html  # the readable prefix survives


# ---------------------------------------------------------------------------
# 3. run_triage build site — result["errors"] is scrubbed end to end
# ---------------------------------------------------------------------------

def _seed_categories(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO categories (slug, description, created_at, updated_at) "
        "VALUES (?, ?, ?, ?)",
        ("unknown", "", now, now),
    )
    conn.commit()


def _build_config() -> TriageConfig:
    cfg = TriageConfig()
    cfg.smtp = SmtpConfig(
        host="smtp.install.test", port=587,
        username="triage@install.test", from_addr="triage@install.test",
    )
    return cfg


@pytest.mark.asyncio
async def test_run_triage_provider_error_scrubs_phi_address(monkeypatch, tmp_path):
    """The provider-creation failure path builds ``errors`` from the raw
    exception — it must route through the scrub SSOT so a PHI address in the
    provider error never reaches the operator results page."""
    from _db_tracking import track

    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = track(init_db(str(tmp_path / "t.db")))
    _seed_categories(conn)

    def _boom(acct, secrets):
        raise RuntimeError(f"SMTP refused rcpt {_PHI_ADDR}")

    monkeypatch.setattr(ui_mod, "_create_provider_from_account", _boom)

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "imap", "config": {"username": "u@watched.test"},
    }
    result = await run_triage(
        conn, _build_config(), None, acct, query="ALL", limit=5, trigger="t",
    )

    assert result["error"] == "provider_error"
    assert result["errors"], "provider-error path produced no errors entry"
    joined = " ".join(result["errors"])
    assert _PHI_ADDR not in joined, f"PHI address leaked into errors: {joined!r}"
    assert "[redacted-addr]" in joined
    assert "Provider error" in joined  # readable prefix preserved


# ---------------------------------------------------------------------------
# 4. The discover_run OUTER ``except`` — single-folder selected scope (DA must-
#    fix). §1 above drives the per-folder FUNNEL directly; the SINGLE-folder
#    ``select_folder`` failure bubbles PAST the funnel to the outer ``except``,
#    whose redaction the structural pin cannot prove (pin-green ≠ folder-
#    redacted). This is the load-bearing end-to-end proof of the must-fix: a
#    patient-named relative mailbox (which the scrub SSOT can't catch — N-42)
#    must NOT reach the rendered operator page.
# ---------------------------------------------------------------------------


class _SelectBoomProvider:
    """A fake provider whose ``select_folder`` raises with the patient folder
    name (and a PHI address) in the message — the single-folder discover path's
    UNGUARDED select. Carries ``peek_recent_uids`` + ``select_folder`` so
    ``can_peek`` is True (the branch that calls ``select_folder`` directly)."""

    async def peek_recent_uids(self, query, n):  # presence → can_peek True
        return []

    async def select_folder(self, folder):
        raise RuntimeError(
            f"SELECT '{folder}' failed for {_PHI_ADDR}: mailbox gone"
        )

    async def search(self, query, limit):  # not reached (select raises first)
        return []

    async def close(self):
        return None


def _make_hipaa_account(db, user_id, *, name="PHI Inbox"):
    import json as _json
    from datetime import datetime as _dt, timezone as _tz

    now = _dt.now(_tz.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id, name, "imap",
            _json.dumps({"host": "mail.unreachable.invalid", "username": "t@t.com"}),
            1, now, now,
        ),
    )
    db.commit()
    return cur.lastrowid


def test_discover_single_folder_select_failure_redacts_patient_folder(
    monkeypatch, client, db, admin_cookies, admin_user
):
    """run18 #3 (DA) — HIPAA account, ``scan_scope=selected`` with a single
    patient-named folder whose ``select_folder`` raises. The error bubbles to
    discover_run's OUTER ``except`` (not the per-folder funnel); the patient
    folder name — a RELATIVE mailbox name the scrub SSOT provably can't catch
    (N-42) — must be ABSENT from the rendered operator page and present only as
    ``[redacted]``. The default test config classifier is local Ollama, so the
    HIPAA BAA gate passes and the scan is actually reached."""
    # Inject a provider whose select_folder raises (no real IMAP). The bare name
    # is snapshotted into triage_classify's globals from _shared, so patch it
    # where discover_run resolves it.
    monkeypatch.setattr(
        "email_triage.web.routers.ui.triage_classify._create_provider_from_account",
        lambda acct, secrets: _SelectBoomProvider(),
    )

    acct_id = _make_hipaa_account(db, admin_user["id"])

    resp = client.post(
        "/triage/discover/run",
        data={
            "account_id": str(acct_id),
            "limit": "10",
            "query": "ALL",
            "scan_scope": "selected",
            "folders": _PHI_FOLDER,
        },
        cookies=admin_cookies,
    )

    assert resp.status_code == 200
    # The OUTER-catch redaction closed the leak end to end.
    assert _PHI_FOLDER not in resp.text, (
        "patient folder leaked to the operator page via the outer catch"
    )
    assert _PHI_ADDR not in resp.text, "PHI address leaked to the operator page"
    assert "[redacted]" in resp.text  # the folder-name redaction landed
    # The error is scrubbed, not suppressed — the operator still sees a failure.
    assert "Error:" in resp.text
