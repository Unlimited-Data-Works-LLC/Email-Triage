"""Bulk-operation helpers for mail.

The webhook API endpoints (and any future internal caller) use these to
apply a single operation across a list of message ids, gathering
per-item results without aborting on the first failure.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from email_triage.engine.models import BulkItemResult, BulkResult
from email_triage.providers.base import EmailProvider
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

log = get_logger("web.bulk")

ALLOWED_OPERATIONS = {
    "label", "move", "archive",
}


def validate_operation(operation: str, args: dict | None) -> str | None:
    """Return None if the (operation, args) pair is valid; else an error string."""
    if operation not in ALLOWED_OPERATIONS:
        return f"unknown_operation: {operation!r}"
    args = args or {}
    if operation == "label" and not args.get("label"):
        return "missing_args: label"
    if operation == "move" and not args.get("folder"):
        return "missing_args: folder"
    return None


async def _apply_one(
    provider: EmailProvider,
    operation: str,
    args: dict,
    message_id: str,
    *,
    hipaa: bool = False,
) -> BulkItemResult:
    try:
        if operation == "label":
            # §164.502(e) egress gate via the provider-label SSOT.
            # Defense-in-depth: the only caller (the webhook-API bulk
            # endpoint) already 403s a HIPAA account at
            # ``_require_webhook_account`` before bulk runs, so for a
            # HIPAA account this is unreachable in practice — but routing
            # through the SSOT means that if that upstream block is ever
            # removed, the per-write gate still holds (fail-closed).
            from email_triage.actions.provider_labels import push_provider_labels

            applied, skipped, errors = await push_provider_labels(
                provider, message_id, [args["label"]], hipaa=hipaa,
            )
            if errors:
                return BulkItemResult(
                    message_id=message_id, status="error",
                    error="; ".join(f"{lbl}: {d}" for lbl, d, _ in errors),
                )
            if skipped and not applied:
                return BulkItemResult(
                    message_id=message_id, status="skipped",
                    data={"reason": "hipaa_mode" if hipaa else "labels_unsupported"},
                )
            return BulkItemResult(message_id=message_id, status="ok")
        if operation == "move":
            await provider.move_message(message_id, args["folder"])
            return BulkItemResult(message_id=message_id, status="ok")
        if operation == "archive":
            # H-06 sister-site sweep (per hipaa-sme-3 R-3 verify-don't-accept
            # review 2026-05-24): per-item BulkItemResult below carries
            # structured "error" status to the caller on archive failure;
            # the HTTP caller sees the failure inline and no PHI state-
            # divergence is buried. NOT a H-06 surface — see
            # actions/digest.py:486 for the divergence-visibility primary
            # site (§164.308(a)(7) Contingency Plan).
            await provider.archive(message_id)
            return BulkItemResult(message_id=message_id, status="ok")
        return BulkItemResult(
            message_id=message_id, status="error",
            error=f"unknown_operation: {operation!r}",
        )
    except Exception as e:
        return BulkItemResult(message_id=message_id, status="error", error=fmt_exc(e))


async def bulk_apply(
    provider: EmailProvider,
    operation: str,
    args: dict | None,
    message_ids: list[str],
    *,
    hipaa: bool = False,
) -> BulkResult:
    """Run ``operation`` against each id; aggregate per-item results.

    Items run sequentially — providers vary in their tolerance for
    parallel writes (Gmail labels are forgiving; IMAP keyword stores
    on a single connection are not). Sequential is also predictable
    for the rate-limit budget on the webhook side.
    """
    args = args or {}
    t0 = time.monotonic()
    items: list[BulkItemResult] = []
    for mid in message_ids:
        items.append(await _apply_one(provider, operation, args, mid, hipaa=hipaa))
    elapsed = time.monotonic() - t0
    succeeded = sum(1 for it in items if it.status == "ok")
    failed = sum(1 for it in items if it.status == "error")
    return BulkResult(
        requested=len(message_ids),
        succeeded=succeeded,
        failed=failed,
        items=items,
        elapsed_secs=elapsed,
    )
