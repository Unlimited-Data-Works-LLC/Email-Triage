"""hipaa-sme MUST-FIX (CR-02 / 2026-06-19): the M-6 ``X-Email-Triage-Draft-Body``
header carries a base64 copy of the (now LLM-generated) draft body. On a HIPAA
account that is a PHI duplicate in message metadata with NO consumer (the M-6
scanner is hard-off for HIPAA) — a §164.502(b) minimum-necessary violation.
``execute()`` must SUPPRESS the draft-body header on HIPAA while keeping the
non-PHI ``X-Email-Triage`` loop-prevention stamp. These pin the rendered
outbound-draft headers (PD-17: test the rendered view, not just the model)."""

from __future__ import annotations

import asyncio
import types

from email_triage.actions.draft_reply import DraftReplyAction
from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_DRAFT_BODY_HEADER,
    X_EMAIL_TRIAGE_HEADER,
)


class _Provider:
    name = "gmail"

    def __init__(self):
        self.created = None

    async def create_draft(self, *, to, subject, body, in_reply_to=None,
                           thread_id=None, extra_headers=None):
        self.created = {
            "body": body,
            "extra_headers": dict(extra_headers or {}),
        }
        return "draft-1"


def _flow(hipaa: bool):
    return types.SimpleNamespace(
        flow_id="f1",
        state_bag={
            "account": {"id": 1, "user_id": 7, "hipaa": hipaa},
            "account_hipaa": hipaa,
            "account_name": "acct",
            "db": object(),
            "config": types.SimpleNamespace(),
            "secrets": None,
            "actor_user_id": 7,
            "self_email": "me@example.com",
        },
    )


def _msg(hipaa: bool):
    return types.SimpleNamespace(
        sender="a@b.com", subject="hi", thread_id="t", hipaa=hipaa,
    )


def _cls():
    return types.SimpleNamespace(category="meeting")


def _patch_execute_env(monkeypatch):
    async def _no_prior(*a, **k):
        return None

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(
        "email_triage.actions.base.check_idempotent_already_done", _no_prior,
    )
    monkeypatch.setattr(
        "email_triage.actions.base.record_idempotent_done", _noop,
    )
    monkeypatch.setattr(
        "email_triage.mail_headers.get_message_rfc_id",
        lambda m: "<rfc-id@x>",
    )

    async def _gen(self, flow, message, classification):
        return "Generated reply body with PHI."

    monkeypatch.setattr(DraftReplyAction, "_generate_body", _gen)


def test_hipaa_draft_omits_draft_body_header(monkeypatch):
    _patch_execute_env(monkeypatch)
    prov = _Provider()
    asyncio.run(DraftReplyAction().execute(
        _flow(hipaa=True), _msg(hipaa=True), _cls(), prov,
    ))
    hdrs = prov.created["extra_headers"]
    # The non-PHI loop-prevention stamp still rides...
    assert X_EMAIL_TRIAGE_HEADER in hdrs
    # ...but the PHI-bearing M-6 draft-body snapshot is SUPPRESSED on HIPAA.
    assert X_EMAIL_TRIAGE_DRAFT_BODY_HEADER not in hdrs
    assert prov.created["body"] == "Generated reply body with PHI."


def test_nonhipaa_draft_includes_draft_body_header(monkeypatch):
    _patch_execute_env(monkeypatch)
    prov = _Provider()
    asyncio.run(DraftReplyAction().execute(
        _flow(hipaa=False), _msg(hipaa=False), _cls(), prov,
    ))
    hdrs = prov.created["extra_headers"]
    assert X_EMAIL_TRIAGE_HEADER in hdrs
    # Non-HIPAA keeps the M-6 capture header — the scanner consumes it there.
    assert X_EMAIL_TRIAGE_DRAFT_BODY_HEADER in hdrs
