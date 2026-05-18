"""Type-name → adapter-class registry.

The ``ai_backends.type`` column (see migration v26) is a CHECK-constrained
enum: ``ollama`` / ``openai`` / ``azure_openai`` / ``gemini``. Every enum
value MUST appear in :data:`BACKEND_TYPES` so the loader doesn't raise
``KeyError`` on a row whose type was added to the schema before a
concrete adapter shipped.

GitHub Copilot was evaluated 2026-05-15 and discarded — ToS scope-
restricts Copilot Chat to coding tasks. Not in the enum, not registered.

Adapters that don't have a concrete subclass yet get a
:class:`NotImplementedAdapter` subclass with the right
``backend_type`` — instantiation succeeds (loader doesn't trip), but
the first :meth:`chat_complete` call raises a clear error pointing at
the missing wave. As of #171-A every enum value has a concrete adapter
shipped, so the placeholder mechanism is unused in practice — the
:class:`NotImplementedAdapter` base remains as the contract for future
migrations that add a new enum value before the concrete adapter lands.

Test :func:`tests.test_ai_backends.test_registry` pins that every
CHECK-enum value has an entry, so a future migration that adds a new
type without registering a placeholder fails CI at the test layer
rather than at runtime.
"""

from __future__ import annotations

from email_triage.ai_backends.azure_openai import AzureOpenAIAdapter
from email_triage.ai_backends.base import BackendAdapter, NotImplementedAdapter
from email_triage.ai_backends.gemini_adapter import GeminiAdapter
from email_triage.ai_backends.ollama_adapter import OllamaAdapter
from email_triage.ai_backends.openai_direct import OpenAIAdapter


# Source of truth — keep keys in sync with the CHECK constraint in
# migration v26. The test_registry pin enforces this.
BACKEND_TYPES: dict[str, type[BackendAdapter]] = {
    "ollama": OllamaAdapter,
    "openai": OpenAIAdapter,
    "azure_openai": AzureOpenAIAdapter,
    "gemini": GeminiAdapter,
}


def register_backend(type_name: str, adapter_cls: type[BackendAdapter]) -> None:
    """Replace a registry entry with a concrete adapter.

    Called by future waves at module-import time when their concrete
    adapter ships. Replacing a placeholder is the expected path;
    overwriting an existing concrete adapter is allowed but logs the
    swap so tests / operators can see it.

    Constraints:
      * ``type_name`` must already exist in :data:`BACKEND_TYPES`
        (i.e. must be a CHECK-allowed value). Adding a brand-new
        type requires a migration first.
      * ``adapter_cls`` must subclass :class:`BackendAdapter`.
    """
    import logging
    if type_name not in BACKEND_TYPES:
        raise KeyError(
            f"Cannot register adapter for unknown backend type "
            f"{type_name!r}; add a migration extending the "
            f"ai_backends CHECK constraint first."
        )
    if not (isinstance(adapter_cls, type) and issubclass(adapter_cls, BackendAdapter)):
        raise TypeError(
            f"register_backend expected a BackendAdapter subclass, "
            f"got {adapter_cls!r}"
        )
    old = BACKEND_TYPES[type_name]
    BACKEND_TYPES[type_name] = adapter_cls
    if old is not adapter_cls and not issubclass(old, NotImplementedAdapter):
        logging.getLogger("email_triage.ai_backends").info(
            "AI backend registry swap",
            extra={"_extra": {
                "type": type_name,
                "old": old.__name__,
                "new": adapter_cls.__name__,
            }},
        )
