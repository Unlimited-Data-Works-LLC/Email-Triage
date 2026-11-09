"""Style-learning UI gate (resolve_embedding_gate) unit tests.

The function is pure (string-typed inputs + a runtime probe); these
tests cover the three cases the spec calls out without spinning up
a full FastAPI app.
"""

from __future__ import annotations

import pytest

from email_triage.web.routers.ui._shared import resolve_embedding_gate


def test_gate_blocks_when_backend_unset():
    """Unset backend → required=True, ready=False, end-user copy."""
    g = resolve_embedding_gate(
        configured_backend_type="",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "Style learning is disabled" in g["reason"]
    assert "AI Backends config page" in g["reason"]
    # MUST NOT contain admin URL path
    assert "/config" not in g["reason"]
    assert "/admin" not in g["reason"]


def test_gate_blocks_when_sentence_transformers_runtime_not_ready(monkeypatch):
    """sentence_transformers + runtime not ready → block."""
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: False,
    )
    g = resolve_embedding_gate(
        configured_backend_type="sentence_transformers",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "local embedding backend" in g["reason"]
    assert "AI Backends config page" in g["reason"]
    assert "/config" not in g["reason"]


def test_gate_ready_when_sentence_transformers_runtime_ready(monkeypatch):
    """The runtime probe is the one source of readiness."""
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: True,
    )
    g = resolve_embedding_gate(
        configured_backend_type="sentence_transformers",
    )
    assert g["ready"] is True
    assert g["reason"] == ""


def test_gate_passes_for_ollama():
    """Ollama backend → ready (live-call failures show on its metrics)."""
    g = resolve_embedding_gate(
        configured_backend_type="ollama",
    )
    assert g["required"] is True
    assert g["ready"] is True
    assert g["reason"] == ""


def test_gate_unknown_backend_blocks():
    g = resolve_embedding_gate(
        configured_backend_type="anthropic-via-cloud",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "not recognised" in g["reason"]


def test_gate_blocks_a_refused_runtime_whatever_the_yaml_still_says(monkeypatch):
    """Punch 552 / N-555 — the failure must be VISIBLE.

    Pre-fix a configured ``embedding.fallback`` made this gate read
    "ready" while the local runtime was refused, and the wrapper then
    embedded with a different model (on the deploy host, the chat model qwen3.6:35b),
    whose vectors score zero against the index. The chain is gone, so the
    gate takes no fallback input at all: the signature is the pin.
    """
    import inspect

    params = set(inspect.signature(resolve_embedding_gate).parameters)
    assert params == {"configured_backend_type"}, (
        "resolve_embedding_gate grew an input; a fallback or live-type "
        f"argument re-opens the silent path. params={sorted(params)}"
    )
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: False,
    )
    g = resolve_embedding_gate(
        configured_backend_type="sentence_transformers",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "local embedding backend" in g["reason"]


def test_gate_reason_avoids_protocol_jargon():
    """End-user audience copy: no RFC/OData/LLM/embedding-store jargon."""
    for cfg in ("", "sentence_transformers", "unknown_x"):
        # If sentence_transformers, force runtime-not-ready to get a blocked reason
        if cfg == "sentence_transformers":
            import email_triage.embedding_bits as eb
            orig = eb.is_runtime_ready
            eb.is_runtime_ready = lambda: False
            try:
                g = resolve_embedding_gate(
                    configured_backend_type=cfg,
                )
            finally:
                eb.is_runtime_ready = orig
        else:
            g = resolve_embedding_gate(
                configured_backend_type=cfg,
            )
        reason = g["reason"]
        for jargon in ("RFC", "OData", "language model", "LLM",
                       "vector embedding", "ISO 8601"):
            assert jargon not in reason, (
                f"Reason {reason!r} for cfg={cfg!r} contains "
                f"protocol jargon {jargon!r} — end-user audience"
            )
