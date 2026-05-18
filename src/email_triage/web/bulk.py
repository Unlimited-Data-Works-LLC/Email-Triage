"""Bulk-operation helpers for mail.

The OpenClaw endpoints (and any future internal caller) use these to
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
) -> BulkItemResult:
    try:
        if operation == "label":
            await provider.apply_label(message_id, args["label"])
            return BulkItemResult(message_id=message_id, status="ok")
        if operation == "move":
            await provider.move_message(message_id, args["folder"])
            return BulkItemResult(message_id=message_id, status="ok")
        if operation == "archive":
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
) -> BulkResult:
    """Run ``operation`` against each id; aggregate per-item results.

    Items run sequentially — providers vary in their tolerance for
    parallel writes (Gmail labels are forgiving; IMAP keyword stores
    on a single connection are not). Sequential is also predictable
    for the rate-limit budget on the OpenClaw side.
    """
    args = args or {}
    t0 = time.time()
    items: list[BulkItemResult] = []
    for mid in message_ids:
        items.append(await _apply_one(provider, operation, args, mid))
    elapsed = time.time() - t0
    succeeded = sum(1 for it in items if it.status == "ok")
    failed = sum(1 for it in items if it.status == "error")
    return BulkResult(
        requested=len(message_ids),
        succeeded=succeeded,
        failed=failed,
        items=items,
        elapsed_secs=elapsed,
    )
