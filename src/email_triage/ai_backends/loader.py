"""Factory: ``ai_backends`` row → :class:`BackendAdapter` instance.

The single public surface is :func:`load_backend`. Pattern:

  * ``backend_id is None`` — return the install-default adapter
    (Ollama with the YAML-configured base URL + model, or the
    hard-coded defaults if YAML is unavailable). This is the
    fallback when an account row has ``style_learning_backend_id IS
    NULL``.
  * ``backend_id`` non-None — SELECT the row from ``ai_backends``,
    instantiate the right adapter for its ``type``, fetch the API
    key via :class:`DbSecrets` (if a ``api_key_secret_ref`` is set),
    return the adapter.

Errors
------
  * ``BackendNotFoundError`` — id present, no matching row.
  * ``BackendDisabledError`` — row exists, ``enabled = 0``.
  * ``BackendError`` (or subclass) — secrets-store miss, registry
    miss (shouldn't happen — placeholder covers every enum value),
    other DB / construction failures.

HIPAA / API-key handling
------------------------
The plaintext API key is fetched from :class:`DbSecrets` (Fernet-
decrypted in memory) and handed to the adapter ``__init__`` via
``api_key=``. The loader does NOT return the key to the caller and
does NOT log it. The adapter instance is the only reference; when
it falls out of scope, the plaintext is no longer in memory.

Wave 2 — the admin UI for ai_backends CRUD — will use a separate
helper (``add_backend``) that takes the plaintext key as a request
field, stores via ``DbSecrets.set``, and inserts the row. That
helper does NOT live in this module (CRUD is out of scope here).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from email_triage.ai_backends.base import (
    BackendAdapter,
    BackendDisabledError,
    BackendError,
    BackendNotFoundError,
)
from email_triage.ai_backends.ollama_adapter import (
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OLLAMA_MODEL,
    OllamaAdapter,
)
from email_triage.ai_backends.registry import BACKEND_TYPES

logger = logging.getLogger("email_triage.ai_backends.loader")


def load_backend(
    backend_id: int | None,
    *,
    db_conn: sqlite3.Connection,
    secrets: Any = None,
    config: Any = None,
) -> BackendAdapter:
    """Instantiate the adapter for the given ``ai_backends`` row.

    Parameters
    ----------
    backend_id:
        Primary key of the ``ai_backends`` row, or ``None`` for the
        install default.
    db_conn:
        Open SQLite connection; ``row_factory`` may be ``sqlite3.Row``
        or unset, both are handled.
    secrets:
        :class:`DbSecrets` (or any object with a ``.get(key)`` method)
        used to resolve ``api_key_secret_ref`` to a plaintext API key.
        May be ``None`` when ``backend_id`` is for a key-less type
        (Ollama). When required and missing, the loader raises
        :class:`BackendError` rather than instantiate without a key.
    config:
        Optional :class:`TriageConfig` (or compatible object exposing
        ``.classifier`` + ``.tls``). When ``backend_id is None`` and
        ``config`` is provided, the install-default Ollama adapter
        mirrors ``config.classifier`` settings instead of the hard-
        coded defaults. When ``None`` the hard-coded defaults apply.

    Returns
    -------
    A :class:`BackendAdapter` ready to receive ``chat_complete`` calls.

    Raises
    ------
    BackendNotFoundError, BackendDisabledError, BackendError.
    """
    if backend_id is None:
        return _build_install_default(config)

    row = _fetch_row(db_conn, backend_id)
    if row is None:
        raise BackendNotFoundError(
            f"ai_backends row id={backend_id!r} not found. The FK "
            f"target may have been deleted; clear the per-account "
            f"override or pick a different backend."
        )

    enabled = int(_row_get(row, "enabled") or 0)
    if not enabled:
        name = _row_get(row, "name") or "<unnamed>"
        raise BackendDisabledError(
            f"ai_backends row id={backend_id!r} ({name!r}) is "
            f"disabled. Re-enable it via the admin UI or pick a "
            f"different backend."
        )

    type_name = _row_get(row, "type")
    if type_name not in BACKEND_TYPES:
        # Defensive — the CHECK constraint should prevent this, but a
        # future migration that drops or renames an enum value could
        # leave a row with an unknown type. Fail closed.
        raise BackendError(
            f"ai_backends row id={backend_id!r} has unknown type "
            f"{type_name!r}; not in BACKEND_TYPES registry."
        )

    adapter_cls = BACKEND_TYPES[type_name]
    api_key = _resolve_api_key(row, secrets)
    local_url_suffixes = _local_url_suffixes_from_config(config)

    try:
        adapter = adapter_cls(
            endpoint=_row_get(row, "endpoint"),
            model=_row_get(row, "model"),
            api_key=api_key,
            local_url_suffixes=local_url_suffixes,
            backend_type=type_name,
        )
    except TypeError:
        # NotImplementedAdapter subclasses + simple adapters may not
        # accept every kwarg; retry with the minimal set.
        adapter = adapter_cls(backend_type=type_name)
    return adapter


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_install_default(config: Any) -> BackendAdapter:
    """Return the install-default Ollama adapter.

    Reads ``config.classifier.ollama_url`` + ``.model`` when ``config``
    is supplied; falls back to the module-level defaults otherwise so
    test contexts that don't carry a config object still resolve to
    a usable adapter (the call site can then mock the underlying HTTP
    if it doesn't actually want network IO).
    """
    base_url = DEFAULT_OLLAMA_BASE_URL
    model = DEFAULT_OLLAMA_MODEL
    if config is not None:
        try:
            base_url = getattr(config.classifier, "ollama_url", base_url)
            model = getattr(config.classifier, "model", model)
        except AttributeError:
            pass
    local_url_suffixes = _local_url_suffixes_from_config(config)
    return OllamaAdapter(
        endpoint=base_url,
        model=model,
        api_key=None,
        local_url_suffixes=local_url_suffixes,
    )


def _local_url_suffixes_from_config(config: Any) -> list[str]:
    if config is None:
        return []
    try:
        return list(getattr(config.tls, "local_url_suffixes", []) or [])
    except AttributeError:
        return []


def _fetch_row(conn: sqlite3.Connection, backend_id: int) -> Any:
    cur = conn.execute(
        "SELECT id, name, type, endpoint, api_key_secret_ref, model, "
        "baa_certified, baa_expires_at, enabled, created_by, created_at "
        "FROM ai_backends WHERE id = ?",
        (backend_id,),
    )
    return cur.fetchone()


def _row_get(row: Any, key: str) -> Any:
    """Read a column from either a tuple or sqlite3.Row.

    The shared ``conn`` fixture in conftest.py uses ``sqlite3.Row``,
    but callers under different fixtures may not — be tolerant.
    """
    if hasattr(row, "keys"):
        return row[key]
    # Tuple ordering matches the SELECT in _fetch_row.
    order = [
        "id", "name", "type", "endpoint", "api_key_secret_ref", "model",
        "baa_certified", "baa_expires_at", "enabled", "created_by",
        "created_at",
    ]
    try:
        idx = order.index(key)
    except ValueError:
        return None
    return row[idx]


def _resolve_api_key(row: Any, secrets: Any) -> str | None:
    ref = _row_get(row, "api_key_secret_ref")
    if not ref:
        return None  # key-less backend (e.g. Ollama)
    if secrets is None:
        raise BackendError(
            f"ai_backends row references api_key_secret_ref={ref!r} "
            f"but no secrets provider was passed to load_backend(). "
            f"Pass the install's DbSecrets instance."
        )
    try:
        key = secrets.get(ref)
    except Exception as exc:
        # Wrap to keep the secrets-backend exception out of caller
        # traces (avoids leaking backend-specific error shape).
        raise BackendError(
            f"failed to read api_key_secret_ref={ref!r} from secrets "
            f"store: {type(exc).__name__}"
        ) from exc
    if not key:
        raise BackendError(
            f"api_key_secret_ref={ref!r} not present in secrets "
            f"store. Add the secret or clear the FK on the row."
        )
    return key
