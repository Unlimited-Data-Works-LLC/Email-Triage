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

from email_triage.secrets import read_secret
from email_triage.triage_logging import get_logger  # N-196b R21_4

import logging
import sqlite3
from typing import Any

from email_triage.ai_backends.base import (
    BackendAdapter,
    BackendBAARequiredError,
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

logger = get_logger("email_triage.ai_backends.loader")  # N-196b R21_4


def load_backend(
    backend_id: int | None,
    *,
    db_conn: sqlite3.Connection,
    secrets: Any = None,
    config: Any = None,
    require_baa_certified: bool = False,
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
    require_baa_certified:
        When ``True`` (a HIPAA account's PHI-egress path — e.g. the
        style-learning distill), refuse to return an adapter for an
        explicit ``ai_backends`` row that is not BAA-certified or whose
        BAA has expired, raising :class:`BackendBAARequiredError`. This
        is the RUNTIME reciprocal of the account-setup selector gate so
        a backend whose BAA lapsed AFTER selection can't silently egress
        PHI (census N-63). The install default (``backend_id is None``)
        is local-only and therefore BAA-exempt regardless of this flag.

    Returns
    -------
    A :class:`BackendAdapter` ready to receive ``chat_complete`` calls.

    Raises
    ------
    BackendNotFoundError, BackendDisabledError, BackendBAARequiredError,
    BackendError.
    """
    if backend_id is None:
        adapter = _build_install_default(config)
        # Census N-63 (install-default egress hole) — the install default
        # points at ``config.classifier.ollama_url``, which is operator-
        # configurable and NOT guaranteed local (the classifier BAA gate
        # exists precisely because that URL can be remote). A HIPAA account
        # with a NULL backend FK must not egress its PHI style corpus to a
        # NON-LOCAL install default with no BAA. Mirror the classifier-path
        # gate: local → exempt (no egress); non-local → require a BAA ack on
        # file for that (backend, host). Fail closed. ``config is None`` means
        # the hard-coded localhost default, which is local → exempt.
        if require_baa_certified and not bool(
            getattr(adapter, "is_local", False)
        ):
            acked = False
            host = ""
            if config is not None:
                from email_triage.classify.baa_gate import (
                    classifier_baa_status_from_config,
                )
                status = classifier_baa_status_from_config(db_conn, config)
                acked = bool(status.get("baa_acked"))
                host = status.get("host") or ""
            if not acked:
                raise BackendBAARequiredError(
                    f"the install-default classifier endpoint ({host or '?'}) "
                    f"is non-local and has no BAA acknowledgment on file; a "
                    f"HIPAA account's PHI may not be sent to it. Acknowledge a "
                    f"BAA on /config, or point the account at a local Ollama / "
                    f"BAA-certified backend."
                )
        return adapter

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

    # Runtime BAA chokepoint (census N-63) — a HIPAA account's PHI-egress
    # caller sets ``require_baa_certified``; refuse to hand back an adapter
    # for a backend that is not BAA-certified or whose BAA has expired so the
    # style-learning distill path can't egress PHI to an uncertified
    # subprocessor (§164.502(a)(1) / §164.308(b)(1)). The single BAA-validity
    # rule lives in baa_expiry.is_backend_baa_valid_for_phi — the same
    # predicate the account-setup selector gate uses (one SSOT, no inline
    # re-derivation). Fail closed.
    if require_baa_certified:
        from email_triage.baa_expiry import is_backend_baa_valid_for_phi
        if not is_backend_baa_valid_for_phi(
            baa_certified=_row_get(row, "baa_certified"),
            baa_expires_at=_row_get(row, "baa_expires_at"),
        ):
            name = _row_get(row, "name") or "<unnamed>"
            raise BackendBAARequiredError(
                f"ai_backends row id={backend_id!r} ({name!r}) is not "
                f"BAA-certified or its BAA has expired; a HIPAA account's PHI "
                f"may not be sent to it. Re-certify the BAA with a future "
                f"expiry on the admin Backends page, or switch the account to "
                f"a local Ollama backend."
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

    adapter_kwargs: dict[str, Any] = dict(
        endpoint=_row_get(row, "endpoint"),
        model=_row_get(row, "model"),
        api_key=api_key,
        local_url_suffixes=local_url_suffixes,
        backend_type=type_name,
    )
    if type_name == "ollama":
        #  — thread the per-account backup-model list ONLY for Ollama (its
        # backups are same-endpoint models, so failover crosses no BAA
        # boundary). Passing it to OpenAI/Gemini would trip the unexpected-
        # kwarg TypeError fallback below — which drops EVERY kwarg — so scope
        # it to the adapter that consumes it.
        from email_triage.web.db import decode_backup_models_value
        adapter_kwargs["backup_models"] = decode_backup_models_value(
            _row_get(row, "backup_models_json")
        )

    try:
        adapter = adapter_cls(**adapter_kwargs)
    except TypeError as exc:
        # NotImplementedAdapter subclasses + simple adapters may not
        # accept every kwarg; retry with the minimal set. But ONLY
        # when the TypeError is an argument-signature mismatch — a
        # TypeError raised from *inside* the adapter's __init__ (a
        # real bug) must not be masked by a silent minimal-kwargs
        # retry that then constructs a half-configured adapter.
        if "unexpected keyword argument" not in str(exc):
            raise
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
    #  — the install-default Ollama path honours config.classifier.backup_models
    # too, so the global style-learning complete() path gets failover like classify.
    backup_models: list[str] = []
    if config is not None:
        try:
            backup_models = list(
                getattr(config.classifier, "backup_models", []) or []
            )
        except AttributeError:
            pass
    return OllamaAdapter(
        endpoint=base_url,
        model=model,
        api_key=None,
        local_url_suffixes=local_url_suffixes,
        backup_models=backup_models,
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
        "backup_models_json, "
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
        "backup_models_json",
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
        key = read_secret(secrets, ref)
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
