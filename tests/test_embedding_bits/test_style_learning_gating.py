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
        live_backend_type=None, configured_backend_type="",
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
        live_backend_type=None,
        configured_backend_type="sentence_transformers",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "local embedding backend" in g["reason"]
    assert "AI Backends config page" in g["reason"]
    assert "/config" not in g["reason"]


def test_gate_passes_when_live_backend_already_sentence_transformers():
    """If live backend is sentence_transformers, runtime is ready by
    construction — no false negative on a stale cache."""
    g = resolve_embedding_gate(
        live_backend_type="sentence_transformers",
        configured_backend_type="sentence_transformers",
    )
    assert g["ready"] is True
    assert g["reason"] == ""


def test_gate_passes_for_ollama():
    """Ollama backend → ready (live-call failures handled by fallback)."""
    g = resolve_embedding_gate(
        live_backend_type="ollama", configured_backend_type="ollama",
    )
    assert g["required"] is True
    assert g["ready"] is True
    assert g["reason"] == ""


def test_gate_unknown_backend_blocks():
    g = resolve_embedding_gate(
        live_backend_type=None, configured_backend_type="anthropic-via-cloud",
    )
    assert g["required"] is True
    assert g["ready"] is False
    assert "not recognised" in g["reason"]


def test_gate_passes_when_primary_not_ready_but_fallback_configured(monkeypatch):
    """2026-05-18 regression — operator's prod config has
    primary=sentence_transformers + fallback=ollama. The bits aren't
    installed yet, so the local primary can't fire, but the
    FallbackEmbeddingBackend wrapper routes embed_text calls to the
    Ollama backup. Pre-fix the gate blocked despite the working
    fallback chain. Post-fix the gate returns ready when a fallback
    is configured.
    """
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: False,
    )
    g = resolve_embedding_gate(
        live_backend_type=None,
        configured_backend_type="sentence_transformers",
        fallback_backend_type="ollama",
    )
    assert g["required"] is True, "feature still needs a backend"
    assert g["ready"] is True, (
        "fallback chain absorbs the primary's ImportError; "
        "subsystem is functionally available"
    )
    assert g["reason"] == ""


def test_gate_still_blocks_when_no_fallback_and_no_runtime(monkeypatch):
    """Primary unloadable + no fallback → block (the original case 1
    behavior; fallback-aware fix did not regress the no-fallback path).
    """
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: False,
    )
    g = resolve_embedding_gate(
        live_backend_type=None,
        configured_backend_type="sentence_transformers",
        fallback_backend_type=None,
    )
    assert g["ready"] is False
    assert "local embedding backend" in g["reason"]


def test_gate_passes_when_live_is_fallback_wrapper():
    """Live backend type ``fallback`` is the FallbackEmbeddingBackend
    composite wrapper. If it loaded successfully, the subsystem is up
    regardless of the runtime probe for the local primary.
    """
    g = resolve_embedding_gate(
        live_backend_type="fallback",
        configured_backend_type="sentence_transformers",
        fallback_backend_type="ollama",
    )
    assert g["ready"] is True
    assert g["reason"] == ""


def test_gate_empty_fallback_string_treated_as_no_fallback(monkeypatch):
    """Defensive: empty-string fallback_backend_type behaves the same
    as None (no fallback). Guards against a config layer that
    propagates "" instead of None for an unset fallback section.
    """
    monkeypatch.setattr(
        "email_triage.embedding_bits.is_runtime_ready", lambda: False,
    )
    g = resolve_embedding_gate(
        live_backend_type=None,
        configured_backend_type="sentence_transformers",
        fallback_backend_type="",
    )
    assert g["ready"] is False


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
                    live_backend_type=None, configured_backend_type=cfg,
                )
            finally:
                eb.is_runtime_ready = orig
        else:
            g = resolve_embedding_gate(
                live_backend_type=None, configured_backend_type=cfg,
            )
        reason = g["reason"]
        for jargon in ("RFC", "OData", "language model", "LLM",
                       "vector embedding", "ISO 8601"):
            assert jargon not in reason, (
                f"Reason {reason!r} for cfg={cfg!r} contains "
                f"protocol jargon {jargon!r} — end-user audience"
            )
