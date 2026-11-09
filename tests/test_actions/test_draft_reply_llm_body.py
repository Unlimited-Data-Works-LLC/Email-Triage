"""#N-01-forward — DraftReplyAction._generate_body control-flow.

The LLM draft body landed (was a static placeholder). These pin the
control flow of ``_generate_body``: it FAILS CLOSED on a BAA/secret error
(no draft), DEGRADES to the safe placeholder on a non-security generation
failure, and emits the actor!=owner PHI-access audit row on a HIPAA account.

The ONLY stub here is the Ollama adapter (the true external boundary, not
available locally). ``build_prompt_messages`` is stubbed to a fixed message
list so these tests isolate the NEW _generate_body wiring — the prompt
builder itself is covered by test_draft_reply_m5_stitch.py, and the full
real-stack path (real Ollama + SQLCipher + provider draft) is the deploy host e2e
per feedback_test_on_deploy_host_when_local_cant.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from email_triage.actions.draft_reply import DraftReplyAction
from email_triage.ai_backends.base import BackendBAARequiredError, BackendError


def _flow(state_bag: dict):
    return types.SimpleNamespace(flow_id="f1", state_bag=state_bag)


def _cls(category: str = "meeting"):
    return types.SimpleNamespace(category=category)


def _msg():
    return types.SimpleNamespace(
        subject="Re: hi", sender="a@b.com", body_text="hello",
        thread_id="t", hipaa=False,
    )


class _Adapter:
    def __init__(self, text: str = "", raises: Exception | None = None):
        self._text = text
        self._raises = raises

    async def chat_complete(self, messages, *, max_tokens=None, **kw):
        if self._raises is not None:
            raise self._raises
        return self._text


def _wire(monkeypatch, *, adapter=None, load_exc=None, audit_calls=None):
    """Stub the boundary: build_prompt_messages + load_backend + audit."""
    monkeypatch.setattr(
        "email_triage.actions.draft_reply._DRAFT_RUNTIME", {},
    )

    async def _fake_bpm(**kw):
        return [{"role": "user", "content": "x"}]

    monkeypatch.setattr(
        "email_triage.actions.draft_reply.build_prompt_messages", _fake_bpm,
    )

    def _fake_load(backend_id, *, db_conn=None, secrets=None, config=None,
                   require_baa_certified=False):
        if load_exc is not None:
            raise load_exc
        return adapter

    monkeypatch.setattr(
        "email_triage.ai_backends.loader.load_backend", _fake_load,
    )

    if audit_calls is not None:
        def _spy(conn, actor_user_id, account_id, operation,
                 outcome="ok", detail=None):
            audit_calls.append(
                (actor_user_id, account_id, operation, outcome)
            )
            return 1

        monkeypatch.setattr(
            "email_triage.db.audit.record_hipaa_access_event", _spy,
        )


def _sb(*, hipaa=False, actor=7, owner=7, config=True, db=True):
    return {
        "db": object() if db else None,
        "account": {"id": 1, "user_id": owner, "hipaa": hipaa},
        "secrets": None,
        "actor_user_id": actor,
        "config": types.SimpleNamespace() if config else None,
        "self_email": "me@example.com",
    }


def _run(coro):
    return asyncio.run(coro)


def test_generate_body_returns_llm_text(monkeypatch):
    _wire(monkeypatch, adapter=_Adapter(text="Thanks, see you then."))
    act = DraftReplyAction()
    out = _run(act._generate_body(_flow(_sb()), _msg(), _cls()))
    assert out == "Thanks, see you then."


def test_unwired_runtime_degrades_to_placeholder(monkeypatch):
    _wire(monkeypatch, adapter=_Adapter(text="should-not-be-used"))
    act = DraftReplyAction()
    # config missing AND _DRAFT_RUNTIME empty -> non-decisional degradation.
    out = _run(act._generate_body(
        _flow(_sb(config=False)), _msg(), _cls("invoice"),
    ))
    assert out.startswith("[Auto-drafted reply for invoice email]")


def test_fail_closed_on_baa_required(monkeypatch):
    _wire(monkeypatch, load_exc=BackendBAARequiredError("no BAA"))
    act = DraftReplyAction()
    # HIPAA account + BAA refusal -> REFUSE (raise), no placeholder.
    with pytest.raises(BackendBAARequiredError):
        _run(act._generate_body(_flow(_sb(hipaa=True)), _msg(), _cls()))


def test_hipaa_backend_error_degrades(monkeypatch):
    # Right-sized 2026-06-19: a non-BAA BackendError builds no adapter, so NO
    # PHI egressed — degrade to the safe non-PHI placeholder on HIPAA too (not
    # refuse). Only BackendBAARequiredError refuses (the genuine egress
    # boundary); refusing on a transient/config error gains zero PHI safety.
    _wire(monkeypatch, load_exc=BackendError("boom"))
    act = DraftReplyAction()
    out = _run(act._generate_body(_flow(_sb(hipaa=True)), _msg(), _cls("x")))
    assert out.startswith("[Auto-drafted reply for x email]")


def test_nonhipaa_backend_error_degrades(monkeypatch):
    _wire(monkeypatch, load_exc=BackendError("boom"))
    act = DraftReplyAction()
    out = _run(act._generate_body(_flow(_sb(hipaa=False)), _msg(), _cls("x")))
    assert out.startswith("[Auto-drafted reply for x email]")


def test_hipaa_actor_not_owner_emits_audit(monkeypatch):
    calls: list = []
    _wire(monkeypatch, adapter=_Adapter(text="ok body"), audit_calls=calls)
    act = DraftReplyAction()
    out = _run(act._generate_body(
        _flow(_sb(hipaa=True, actor=99, owner=7)), _msg(), _cls(),
    ))
    assert out == "ok body"
    assert len(calls) == 1
    actor, account_id, operation, outcome = calls[0]
    assert actor == 99 and account_id == 1
    assert operation == "draft_reply_generate" and outcome == "ok"


def test_hipaa_owner_self_draft_no_audit(monkeypatch):
    calls: list = []
    _wire(monkeypatch, adapter=_Adapter(text="ok body"), audit_calls=calls)
    act = DraftReplyAction()
    out = _run(act._generate_body(
        _flow(_sb(hipaa=True, actor=7, owner=7)), _msg(), _cls(),
    ))
    assert out == "ok body"
    assert calls == []  # owner self-access is exempt


def test_nonhipaa_no_audit(monkeypatch):
    calls: list = []
    _wire(monkeypatch, adapter=_Adapter(text="ok"), audit_calls=calls)
    act = DraftReplyAction()
    _run(act._generate_body(_flow(_sb(hipaa=False, actor=99, owner=7)),
                            _msg(), _cls()))
    assert calls == []


def test_empty_llm_output_degrades(monkeypatch):
    _wire(monkeypatch, adapter=_Adapter(text="   "))
    act = DraftReplyAction()
    out = _run(act._generate_body(_flow(_sb()), _msg(), _cls("note")))
    assert out.startswith("[Auto-drafted reply for note email]")


def test_llm_timeout_degrades(monkeypatch):
    _wire(monkeypatch, adapter=_Adapter(raises=TimeoutError("slow")))
    act = DraftReplyAction()
    out = _run(act._generate_body(_flow(_sb()), _msg(), _cls("note")))
    assert out.startswith("[Auto-drafted reply for note email]")
