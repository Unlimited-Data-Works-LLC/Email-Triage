"""HIPAA BAA acknowledgment gate.

A Business Associate Agreement is required by HIPAA §164.308(b)(1)
between a covered entity and any subprocessor that handles PHI. When
the email-triage operator configures an external LLM backend
(api.openai.com, Google Gemini, any non-local OpenAI-compatible
endpoint, etc.) and processes mail from a HIPAA-flagged account, the
classifier prompt would otherwise stream PHI to that vendor — an
unauthorised disclosure under HIPAA unless a BAA is in force.

This module is the single source of truth for the gate: it persists
BAA acknowledgments per ``(backend, vendor_host)`` tuple and exposes
``classify_or_skip_for_hipaa`` so the triage runner doesn't need to
know the policy details.

Persistence shape: a settings row per tuple, key
``baa_ack:<backend>:<host>``, value::

    {"acked": true, "acked_at": "<ISO>", "acked_by_user_id": <int>}

Re-acknowledgment is required whenever ``backend`` or ``host``
changes, because the operator is sub-processing PHI through a
different vendor.
"""

from __future__ import annotations

import sqlite3
from email_triage._isotime import now_utc_iso
from urllib.parse import urlparse
from typing import Any


def _vendor_host_for_classifier(classifier: Any) -> str:
    """Best-effort hostname for the classifier's outbound endpoint.

    Used as the second half of the BAA ack key. Local classifiers
    return an empty string (no BAA needed).
    """
    base = getattr(classifier, "_base_url", "") or ""
    if not base:
        return ""
    try:
        host = (urlparse(base).hostname or "").lower()
    except Exception:
        return ""
    return host


def _backend_for_classifier(classifier: Any) -> str:
    """Stable backend identifier for the BAA ack key."""
    return type(classifier).__name__.replace("Classifier", "").lower()


def baa_ack_key(backend: str, host: str) -> str:
    return f"baa_ack:{backend}:{host}"


def get_baa_ack(
    conn: sqlite3.Connection,
    backend: str,
    host: str,
) -> dict | None:
    from email_triage.web.db import get_setting
    return get_setting(conn, baa_ack_key(backend, host))


def set_baa_ack(
    conn: sqlite3.Connection,
    backend: str,
    host: str,
    user_id: int,
) -> None:
    from email_triage.web.db import set_setting
    set_setting(conn, baa_ack_key(backend, host), {
        "acked": True,
        "acked_at": now_utc_iso(),
        "acked_by_user_id": user_id,
    })


def revoke_baa_ack(
    conn: sqlite3.Connection,
    backend: str,
    host: str,
) -> None:
    from email_triage.web.db import set_setting
    set_setting(conn, baa_ack_key(backend, host), {
        "acked": False,
        "revoked_at": now_utc_iso(),
    })


def classifier_baa_status(
    conn: sqlite3.Connection,
    classifier: Any,
) -> dict[str, Any]:
    """Inspect the active classifier and return a status dict.

    Keys:
        is_local        — True if endpoint hostname is local-only.
        backend         — short backend id (ollama / openaicompat / gemini).
        host            — endpoint hostname (empty when local).
        baa_required    — True when external (i.e. PHI processing
                          requires a BAA).
        baa_acked       — True when an acknowledgment is on file for
                          this (backend, host) tuple.
        ack_record      — full ack settings row (or None).
    """
    is_local = bool(getattr(classifier, "is_local", False))
    backend = _backend_for_classifier(classifier)
    host = _vendor_host_for_classifier(classifier)
    if is_local:
        return {
            "is_local": True,
            "backend": backend,
            "host": host,
            "baa_required": False,
            "baa_acked": True,  # local is never PHI egress
            "ack_record": None,
        }
    rec = get_baa_ack(conn, backend, host)
    acked = bool(rec and rec.get("acked"))
    return {
        "is_local": False,
        "backend": backend,
        "host": host,
        "baa_required": True,
        "baa_acked": acked,
        "ack_record": rec,
    }


def _endpoint_info_from_config(config: Any) -> tuple[str, str, bool]:
    """Derive ``(backend, host, is_local)`` straight from the config.

    Mirrors what :func:`classifier_baa_status` reads off a built
    classifier (``type(cls).__name__``, ``cls._base_url``,
    ``cls.is_local``) — but without instantiating one. The admin
    Config / Security snapshots only need this metadata, so building
    (and then having to ``close()``) a real classifier just to read
    three attributes is needless work and a leak risk.

    The backend ids match :func:`_backend_for_classifier`'s output:
    ``ollama`` / ``openaicompat`` / ``gemini``.
    """
    from email_triage.classify.base import _is_local_host

    backend = config.classifier.backend
    local_suffixes = tuple(
        getattr(config.tls, "local_url_suffixes", []) or []
    )
    if backend == "ollama":
        base = (config.classifier.ollama_url or "").rstrip("/")
        cls_id = "ollama"
    elif backend == "openai":
        base = (config.classifier.openai_base_url or "").rstrip("/")
        cls_id = "openaicompat"
    elif backend == "gemini":
        # GeminiClassifier hard-codes GEMINI_BASE; it is always external.
        from email_triage.classify.gemini import GEMINI_BASE
        base = GEMINI_BASE.rstrip("/")
        cls_id = "gemini"
    else:
        raise ValueError(f"Unknown classifier backend: {backend}")

    is_local = (
        False if backend == "gemini"
        else _is_local_host(base, extra_suffixes=local_suffixes)
    )
    host = (urlparse(base).hostname or "").lower() if base else ""
    return cls_id, host, is_local


def classifier_baa_status_from_config(
    conn: sqlite3.Connection,
    config: Any,
) -> dict[str, Any]:
    """:func:`classifier_baa_status` without instantiating a classifier.

    Same return shape; reads endpoint metadata from ``config`` via
    :func:`_endpoint_info_from_config` so callers that only need the
    BAA status (the admin Config + Security snapshots) don't build —
    and then leak — a real classifier instance.
    """
    backend, host, is_local = _endpoint_info_from_config(config)
    if is_local:
        return {
            "is_local": True,
            "backend": backend,
            "host": host,
            "baa_required": False,
            "baa_acked": True,  # local is never PHI egress
            "ack_record": None,
        }
    rec = get_baa_ack(conn, backend, host)
    acked = bool(rec and rec.get("acked"))
    return {
        "is_local": False,
        "backend": backend,
        "host": host,
        "baa_required": True,
        "baa_acked": acked,
        "ack_record": rec,
    }


def is_safe_for_hipaa(
    conn: sqlite3.Connection,
    classifier: Any,
) -> bool:
    """Return True when the classifier may receive PHI.

    Local classifier -> always True (PHI never leaves the install).
    External classifier -> only when a BAA ack is on file for the
    exact (backend, host) tuple in use right now.
    """
    status = classifier_baa_status(conn, classifier)
    if status["is_local"]:
        return True
    return bool(status["baa_acked"])


def baa_block_status(
    conn: sqlite3.Connection,
    classifier: Any,
    account_hipaa: bool,
) -> dict[str, Any] | None:
    """The ONE decision behind every classify-egress gate (PD#5, §164.308(b)(1)).

    Returns the classifier's :func:`classifier_baa_status` dict when a HIPAA
    account's PHI must NOT egress to ``classifier`` (the account is HIPAA-flagged
    AND the classifier is external with no BAA ack on file), else ``None``.

    Every code path that ships HIPAA-account message content to a classifier —
    the live runner (``web/triage_runner``), the durable back-scan
    (``jobs/topic_backscan``), and the synchronous Topic preview
    (``web/routers/ui/profile._preview_account_hits``) — routes its refuse
    decision through THIS predicate so the gate cannot drift between them. Callers
    decide HOW to refuse (fail the job / degrade the preview / block the run); the
    decision lives here once. The count-agnostic pin
    ``test_n113_topic_backscan_baa_gate`` asserts every ``match_topics_for_message``
    call site references this gate (or is upstream-gated + allow-listed)."""
    if not account_hipaa:
        return None
    if is_safe_for_hipaa(conn, classifier):
        return None
    return classifier_baa_status(conn, classifier)
