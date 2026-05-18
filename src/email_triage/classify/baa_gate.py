"""HIPAA BAA acknowledgment gate (#59).

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
from datetime import datetime, timezone
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
        "acked_at": datetime.now(timezone.utc).isoformat(),
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
        "revoked_at": datetime.now(timezone.utc).isoformat(),
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
