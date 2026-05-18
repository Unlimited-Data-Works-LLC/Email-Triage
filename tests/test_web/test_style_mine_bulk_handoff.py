"""#161 item 5 — bulk-worker handoff when resolved limit > 50.

Covers:

  * POST /profile/style-data/mine-now with limit > 50 creates a
    ``triage_jobs`` row with ``kind='style_mine'`` and returns the
    bulk-runs-page link fragment.
  * The bulk runner branches on ``kind`` and dispatches the style-mine
    runner instead of the legacy classify-then-act path.
  * The style-mine runner writes a style profile via
    :func:`set_style_profile` and finishes the job ``status='done'``.
  * Limit <= 50 keeps the inline path (no job row created).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from email_triage.web.db import (
    create_email_account,
    get_email_account,
    get_style_profile,
    get_triage_job,
    list_triage_jobs,
    set_setting,
    set_style_learning_mine_limit_default,
    update_account_config_keys,
)


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


def _ensure_classifier_config(app):
    """The mine-now path needs ``app.state.config`` to be present so
    the classifier can be built. The conftest sets up a TriageConfig
    on the app already, but the inline path also pulls config from
    request.app.state.config — make sure it's there."""
    if not getattr(app.state, "config", None):
        from email_triage.config import TriageConfig
        app.state.config = TriageConfig()


class TestInlineCutoff:
    def test_small_limit_stays_inline(
        self, client, user_cookies, db, regular_user, app, monkeypatch,
    ):
        """Limit == 50 (default) stays inline — no job row created.

        Stub the heavy work so the inline path returns quickly. We
        assert the absence of a triage_jobs row of kind='style_mine'.
        """
        a = _make_acct(db, regular_user["id"], "Personal")
        _ensure_classifier_config(app)

        from email_triage.web.routers.ui import profile as _profile_mod

        # Stub provider build + classifier build + extract_style_profile
        # so the inline path returns quickly without touching the
        # network or LLM. We just want to verify no job was queued.
        class _StubProv:
            async def search(self, q, limit, *, filter=None):
                return []  # zero results -> "empty" fragment, no error
            async def fetch_message(self, mid, **_kw):
                raise RuntimeError("unreachable in this stub")
            async def close(self):
                pass

        monkeypatch.setattr(
            _profile_mod, "_create_provider_from_account",
            lambda acct, secrets: _StubProv(),
        )

        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            data={},
            cookies=user_cookies,
        )
        # 200 with inline result fragment ("Nothing to learn from yet").
        assert resp.status_code == 200
        # No style_mine job row was created.
        jobs = list_triage_jobs(db, account_id=a)
        assert not any(
            (j.get("kind") or "triage") == "style_mine" for j in jobs
        )

    def test_large_limit_creates_style_mine_job(
        self, client, user_cookies, db, regular_user, app, monkeypatch,
    ):
        """Per-account override of 100 + commit press → queued job."""
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(db, a, mine_limit_override=200)
        _ensure_classifier_config(app)

        from email_triage.web.routers.ui import profile as _profile_mod

        class _StubProv:
            async def search(self, *a, **kw):
                raise RuntimeError("should not be called on handoff branch")
            async def close(self):
                pass

        monkeypatch.setattr(
            _profile_mod, "_create_provider_from_account",
            lambda acct, secrets: _StubProv(),
        )

        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            data={},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Bulk handoff fragment surfaces a link to the bulk runs page.
        assert "background" in resp.text.lower()

        jobs = list_triage_jobs(db, account_id=a)
        style_jobs = [
            j for j in jobs if (j.get("kind") or "triage") == "style_mine"
        ]
        assert len(style_jobs) == 1
        job = style_jobs[0]
        assert job["status"] == "queued"
        # The query column encodes the resolved limit.
        assert "limit=200" in job["query"]


@pytest.mark.asyncio
async def test_runner_dispatches_style_mine_kind(
    app, db, regular_user, monkeypatch,
):
    """The bulk runner picks the style-mine kind and writes the profile.

    Wire stubs for provider + classifier + extract_style_profile so the
    runner exercises its dispatch + profile-write path without needing
    a real LLM. Asserts:

      * Job status flips to 'done'.
      * A style_profile row exists for the account afterwards.
    """
    from email_triage.web import triage_runner_bulk as _bulk
    from email_triage.actions import style_profile as _sp_mod
    from email_triage.engine.models import EmailMessage
    from email_triage.web.db import create_triage_job

    a = _make_acct(db, regular_user["id"], "Personal")
    _ensure_classifier_config(app)

    # Stub provider build + classifier build + extract_style_profile.
    # NOTE: the bulk runner calls ``fetch_message(mid, folder=folder)``
    # (added in the multi-folder fan-out commit 1a7f4c4). Accept and
    # ignore ``folder`` + ``headers_only`` via ``**_kw`` so the stub
    # matches the canonical provider interface in providers/base.py.
    class _StubProv:
        async def search(self, q, limit, *, filter=None):
            return ["m1"]
        async def fetch_message(self, mid, **_kw):
            return EmailMessage(
                message_id="m1",
                provider="stub",
                sender="me@example.com",
                recipients=["a@example.com"],
                subject="s",
                body_text="hi",
                date=datetime.now(timezone.utc),
            )
        async def close(self):
            pass

    class _StubCls:
        model = "stub"
        async def complete(self, prompt):
            return "Persona: friendly. Greeting: Hi. Signoff: Thanks."
        async def close(self):
            pass

    from email_triage.web.routers import ui as _ui
    monkeypatch.setattr(
        _ui, "_create_provider_from_account",
        lambda acct, secrets: _StubProv(),
    )
    monkeypatch.setattr(
        _ui, "_build_classifier_from_config",
        lambda cfg: _StubCls(),
    )

    class _FakeProfile:
        sample_count = 1
        model_used = "stub"
        def to_dict(self):
            return {"persona_summary": "friendly", "sample_count": 1}

    async def _fake_extract(messages, classifier, *, captured_message_ids=None):
        return _FakeProfile()

    monkeypatch.setattr(
        _sp_mod, "extract_style_profile", _fake_extract,
    )

    job_id = create_triage_job(
        db,
        account_id=a,
        actor_user_id=regular_user["id"],
        query="style_mine:limit=100",
        rate_msg_per_min=100,
        concurrency=1,
        kind="style_mine",
    )

    # Pull the job row + run it directly through the style-mine runner.
    job = get_triage_job(db, job_id)
    # The runner expects status='running' (claim_next_queued flipped it).
    db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?",
        (job_id,),
    )
    db.commit()
    job = get_triage_job(db, job_id)
    await _bulk.run_style_mine_job(app, db, job)

    # Job finished.
    job_after = get_triage_job(db, job_id)
    assert job_after["status"] == "done"

    # Style profile written.
    prof = get_style_profile(db, a)
    assert prof is not None
    assert prof.get("persona_summary") == "friendly"

    # 2026-05-18 regression — operator caught the bulk-runs progress
    # column displaying ``1 / 100`` on a completed style_mine job
    # where 100 messages were actually mined. Pre-fix the worker
    # bumped ``total_processed`` by 1 (the "one logical output"
    # semantic), but the UI renders ``total_processed / total_seen``
    # as a progress fraction — 1/100 reads as "half-broken".
    # Post-fix the worker bumps by ``len(messages)``; total_processed
    # should equal total_seen at done.
    #
    # The stub here serves a single message (``search`` returns
    # ``["m1"]``), so total_processed should be 1 (not 0; pre-fix
    # this was 1 for the wrong reason — "one descriptor" — but the
    # right reason now is "one message mined"). The denominator
    # (total_seen) is also 1, so the UI would correctly display
    # ``1 / 1`` instead of e.g. ``0 / 1``.
    assert job_after["total_processed"] == job_after["total_seen"], (
        f"progress mismatch: total_processed={job_after['total_processed']} "
        f"vs total_seen={job_after['total_seen']} — UI would render "
        f"'X/Y' with X != Y on a completed job, looks half-broken"
    )
    assert job_after["total_processed"] >= 1, (
        "single-message stub run should record at least 1 processed"
    )
