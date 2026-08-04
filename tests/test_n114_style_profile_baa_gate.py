"""N-114 — style-profile HIPAA+BAA egress gate (§164.308(b)(1)).

The class-wide egress pin (test_classify_egress_baa_gate_pin) ENUMERATED the
PHI→LLM egress class and surfaced a live leak: `actions/style_profile.py::
extract_style_profile` ships raw quote-stripped sent-mail BODIES to
`classifier.complete()`. The style opt-in (`is_style_knobs_hipaa_allow`) governs
the M-1/M-2 typed knobs only — it wrongly lifted the M-3 body-mine, so a HIPAA
account + style opt-in ON + an external non-BAA'd classifier egressed raw PHI
to the subprocessor. (The de-id scrubber it was thought to use — hipaa_style_
distill — is dormant scaffold with zero production callers.)

CLOSED via the shared SSOT `classify.baa_gate.baa_block_status`: an in-fn gate in
`extract_style_profile` (the chokepoint all callers route through) returns the
empty distillation profile — bodies NOT sent — for a HIPAA account on an
external non-BAA'd classifier; plus a run-level gate in `run_style_mine_job` and
threaded `account_hipaa`/`conn` from the profile + cli callers.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _msgs():
    from email_triage.engine.models import EmailMessage
    return [EmailMessage(
        message_id="m1", provider="imap", sender="me@example.com",
        recipients=["a@b.com"], subject="Re: case", body_text="PHI body text here "
        "that is long enough to survive quote-stripping and the length floor.",
        date=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )]


def _external_non_baa_classifier():
    c = MagicMock()
    c.is_local = False
    c._base_url = "https://api.openai.com/v1"
    c.model = "gpt-x"
    c.complete = AsyncMock(return_value='{"tone": "formal"}')
    return c


@pytest.mark.asyncio
async def test_extract_style_profile_blocks_hipaa_external_classifier():
    """HIPAA account + external non-BAA classifier → distillation SKIPPED, the
    classifier's complete() is NEVER called (raw bodies never egress)."""
    from email_triage.actions.style_profile import extract_style_profile
    conn = _make_db()
    ext = _external_non_baa_classifier()
    profile = await extract_style_profile(
        _msgs(), ext, account_hipaa=True, conn=conn,
    )
    ext.complete.assert_not_called()  # PHI never egressed
    assert profile is not None  # an empty/baseline profile is still returned


@pytest.mark.asyncio
async def test_extract_style_profile_runs_for_local_classifier():
    """Teeth/control: a LOCAL classifier is the BAA carve-out — the gate does NOT
    fire, so complete() IS called (proving the block above is the gate, not an
    empty corpus)."""
    from email_triage.actions.style_profile import extract_style_profile
    conn = _make_db()
    local = MagicMock()
    local.is_local = True
    local.model = "ollama"
    local.complete = AsyncMock(return_value='{"tone": "formal"}')
    await extract_style_profile(_msgs(), local, account_hipaa=True, conn=conn)
    local.complete.assert_called()  # local → distillation ran (no block)


@pytest.mark.asyncio
async def test_per_alias_blocks_hipaa_external_classifier():
    """The per-alias wrapper (extract_style_profiles_per_alias → the inner
    extract_style_profile) is the path the hipaa+db SMEs flagged — it must thread
    the gate so the inline /profile alias branch can't leak. HIPAA + external →
    complete() NEVER called via the per-alias path."""
    from email_triage.actions.style_profile import extract_style_profiles_per_alias
    conn = _make_db()
    ext = _external_non_baa_classifier()
    descriptors, _unknown = await extract_style_profiles_per_alias(
        _msgs(), ext, account_hipaa=True, conn=conn,
    )
    ext.complete.assert_not_called()  # per-alias path gated (no PHI egress)


@pytest.mark.asyncio
async def test_per_alias_runs_for_local_classifier():
    """Teeth/control: the per-alias path DOES reach complete() for a local
    classifier (proving the block above is the gate, not an empty partition)."""
    from email_triage.actions.style_profile import extract_style_profiles_per_alias
    conn = _make_db()
    local = MagicMock()
    local.is_local = True
    local.model = "ollama"
    local.complete = AsyncMock(return_value='{"tone": "formal"}')
    await extract_style_profiles_per_alias(_msgs(), local, account_hipaa=True, conn=conn)
    local.complete.assert_called()


def test_every_style_profile_caller_threads_account_hipaa():
    """PD#2 interprocedural pin (the hipaa+DA transitive-seam residual): the in-fn
    gate defaults to ``account_hipaa=False`` (disarmed), so the marker-based
    class-wide egress pin can't see whether a CALLER threads it — a future caller
    that drops the kwarg leaks silently while the pin stays green ("blind by
    construction"). Assert every call site of ``extract_style_profile`` /
    ``extract_style_profiles_per_alias`` in src passes the ``account_hipaa`` kwarg.
    A dropped kwarg → RED. (The egress goes through these two; the wrapper forwards
    its own ``account_hipaa`` into the inner call, so it counts.)"""
    import ast
    from _pin_harness import walk_src

    targets = {"extract_style_profile", "extract_style_profiles_per_alias"}
    offenders = []
    for _path, rel, tree in walk_src():
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id in targets):
                continue
            if "account_hipaa" not in {k.arg for k in n.keywords}:
                offenders.append(f"{rel}:{n.lineno} {n.func.id}() missing account_hipaa=")
    assert not offenders, (
        "style-profile egress call site(s) NOT threading the HIPAA+BAA gate kwarg "
        f"(account_hipaa): {offenders}. The in-fn gate is disarmed without it — a "
        "HIPAA account's raw sent-mail bodies would egress to a non-BAA classifier "
        "un-gated (§164.308(b)(1), N-114). Pass account_hipaa=<the account's HIPAA "
        "flag> + conn=<conn> at every call site."
    )


@pytest.mark.asyncio
async def test_extract_style_profile_non_hipaa_unaffected():
    """A non-HIPAA account is never gated (the corpus carries no PHI)."""
    from email_triage.actions.style_profile import extract_style_profile
    conn = _make_db()
    ext = _external_non_baa_classifier()
    await extract_style_profile(_msgs(), ext, account_hipaa=False, conn=conn)
    ext.complete.assert_called()  # non-HIPAA external is fine
