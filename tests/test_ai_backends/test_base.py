"""Tests for the :class:`BackendAdapter` ABC contract."""

from __future__ import annotations

import asyncio

import pytest

from email_triage.ai_backends.base import (
    BackendAdapter,
    BackendDisabledError,
    BackendError,
    BackendNotFoundError,
    NotImplementedAdapter,
)


def test_abc_cannot_be_instantiated_directly():
    """:class:`BackendAdapter` is abstract; concrete subclasses must
    implement :meth:`chat_complete`."""
    with pytest.raises(TypeError):
        BackendAdapter()  # type: ignore[abstract]


def test_subclass_without_chat_complete_cannot_instantiate():
    """A subclass that forgets to implement ``chat_complete`` is still
    abstract — ABC enforcement holds."""
    class Incomplete(BackendAdapter):
        pass

    with pytest.raises(TypeError):
        Incomplete()  # type: ignore[abstract]


def test_minimal_concrete_subclass_works():
    """A subclass that implements ``chat_complete`` instantiates and
    its method is reachable."""
    class Echo(BackendAdapter):
        backend_type = "test"

        async def chat_complete(self, messages, *, response_format=None,
                                max_tokens=None, **kwargs):
            return messages[-1]["content"][::-1]  # reverse last message

    a = Echo()
    out = asyncio.run(a.chat_complete([{"role": "user", "content": "hello"}]))
    assert out == "olleh"


def test_embed_default_raises_not_implemented():
    """Default :meth:`embed` raises so non-embedding adapters surface
    a clear error rather than silently returning a stub vector."""
    class NoEmbed(BackendAdapter):
        async def chat_complete(self, messages, *, response_format=None,
                                max_tokens=None, **kwargs):
            return ""

    a = NoEmbed()
    with pytest.raises(NotImplementedError):
        asyncio.run(a.embed("hello"))


def test_close_default_is_noop():
    """Default :meth:`close` is a no-op so adapters without long-lived
    resources don't need to override."""
    class NoClose(BackendAdapter):
        async def chat_complete(self, messages, *, response_format=None,
                                max_tokens=None, **kwargs):
            return ""

    a = NoClose()
    # Should not raise.
    asyncio.run(a.close())


def test_not_implemented_adapter_raises_clearly_on_chat_complete():
    """Placeholder adapter for an un-shipped backend type fails fast
    with a message that points at the missing wave, not at a stack
    trace from a half-initialised HTTP client."""
    a = NotImplementedAdapter(backend_type="azure_openai")
    with pytest.raises(NotImplementedError, match="azure_openai"):
        asyncio.run(a.chat_complete([{"role": "user", "content": "x"}]))


def test_error_hierarchy_pins_subclasses():
    """:class:`BackendNotFoundError` + :class:`BackendDisabledError`
    both inherit from :class:`BackendError` so callers can catch the
    base class once."""
    assert issubclass(BackendNotFoundError, BackendError)
    assert issubclass(BackendDisabledError, BackendError)
