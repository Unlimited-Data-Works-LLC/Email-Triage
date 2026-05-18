"""Tests for the :data:`BACKEND_TYPES` registry.

Pinning every enum value in the ``ai_backends.type`` CHECK constraint
has a corresponding registry entry guards against the foot-gun where
a migration adds a new type but ships without a placeholder — the
loader would otherwise raise ``KeyError`` at instantiation time
instead of the explicit "not implemented" message.
"""

from __future__ import annotations

import pytest

from email_triage.ai_backends.base import BackendAdapter
from email_triage.ai_backends.registry import BACKEND_TYPES, register_backend


# The four values listed in the CHECK constraint of migration v26.
# Synced manually; ``test_check_constraint_in_sync`` reads the constraint
# back from a fresh DB to catch drift.
_EXPECTED_TYPES = {
    "ollama", "openai", "azure_openai", "gemini",
}


def test_every_enum_value_has_registered_adapter():
    """Each ``type`` enum value must have a class in BACKEND_TYPES."""
    for t in _EXPECTED_TYPES:
        assert t in BACKEND_TYPES, f"missing registry entry for {t!r}"
        cls = BACKEND_TYPES[t]
        assert isinstance(cls, type)
        assert issubclass(cls, BackendAdapter)


def test_registry_has_no_anthropic_entry():
    """Per ``feedback_no_anthropic``, Anthropic must never appear in
    the backend list. This test pins the exclusion at the registry
    layer; the SQL CHECK constraint pins it at the schema layer."""
    assert "anthropic" not in BACKEND_TYPES


def test_check_constraint_in_sync():
    """The set of types in BACKEND_TYPES must match the set allowed by
    the SQL CHECK constraint on ``ai_backends.type``. Drift between
    the two layers would mean a row can exist that the registry can't
    load (or vice versa)."""
    from email_triage.web.db import init_db
    conn = init_db(":memory:")
    try:
        # Read the table's CREATE SQL and extract the CHECK list.
        sql = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='ai_backends'"
        ).fetchone()[0]
        # The relevant CHECK clause uses ``type IN (...)``. Find the
        # parenthesised allowlist via a naive scan rather than
        # parsing — fragile if the migration rewrites the column
        # definition, but cheap and obvious.
        marker = "type IN ("
        idx = sql.find(marker)
        assert idx != -1, "CHECK constraint not found in CREATE SQL"
        rest = sql[idx + len(marker):]
        end = rest.find(")")
        assert end != -1
        literal = rest[:end]
        types_in_sql = {
            tok.strip().strip("'").strip('"')
            for tok in literal.split(",")
        }
        assert types_in_sql == _EXPECTED_TYPES
        assert set(BACKEND_TYPES.keys()) == _EXPECTED_TYPES
    finally:
        conn.close()


def test_register_backend_replaces_placeholder():
    """Wave 1-B / Wave 1-C land their adapter by calling
    :func:`register_backend`. The function must overwrite the
    placeholder cleanly."""

    class MyAzure(BackendAdapter):
        backend_type = "azure_openai"

        async def chat_complete(self, messages, *, response_format=None,
                                max_tokens=None, **kwargs):
            return "azure-ok"

    original = BACKEND_TYPES["azure_openai"]
    try:
        register_backend("azure_openai", MyAzure)
        assert BACKEND_TYPES["azure_openai"] is MyAzure
    finally:
        BACKEND_TYPES["azure_openai"] = original


def test_register_backend_rejects_unknown_type():
    """Adding a brand-new type requires a migration first; the registry
    refuses to grow on the fly."""
    class Stub(BackendAdapter):
        async def chat_complete(self, messages, *, response_format=None,
                                max_tokens=None, **kwargs):
            return ""

    with pytest.raises(KeyError, match="unknown backend type"):
        register_backend("anthropic", Stub)


def test_register_backend_rejects_non_adapter():
    """The factory must subclass :class:`BackendAdapter`."""
    class NotAnAdapter:
        pass

    with pytest.raises(TypeError):
        register_backend("ollama", NotAnAdapter)  # type: ignore[arg-type]
