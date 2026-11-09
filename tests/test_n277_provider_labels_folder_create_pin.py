"""N-277 R29 structural pin — folder-create UX invalidates provider_labels cache (2026-07-03).

R29 census MED-HIGH #3 (provider_labels cache invalidate): the
operator-facing folder-create UX at
`web/routers/ui/accounts.py::accounts_folder_create` (POST
`/accounts/{id}/folders/create`) rendered a response literally saying
"Available in the move-folder picker now" but the 5-min-TTL provider-
labels cache meant the next picker read served stale (pre-create)
labels — the response was a LIVE correctness lie.

N-277 wires `invalidate_cache_for_account(account_id)` right after
the `provider.create_folder(...)` success + before the response.
Sibling to N-247 (delete) + N-271 (purge + OAuth).

WHAT IT PINS (anti-vacuity):

`accounts_folder_create` textually calls `invalidate_cache_for_account`.
A refactor that drops the call re-opens the "picker lies about
availability" gap.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_accounts_folder_create_invalidates_cache():
    """`accounts_folder_create` MUST invalidate the provider-labels
    cache after the create_folder call. Without this, the response's
    "Available in the move-folder picker now" line is FALSE for up
    to 5 min."""
    path = SRC_ROOT / "web" / "routers" / "ui" / "accounts.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    idx = source.find("async def accounts_folder_create")
    assert idx >= 0, "accounts_folder_create route missing"
    # scope: until next `@router.` decorator or next async def
    end_a = source.find("@router.", idx + 1)
    end_b = source.find("\nasync def ", idx + 1)
    end = min(x for x in (end_a, end_b, len(source)) if x > 0)
    body = source[idx:end]
    assert "provider.create_folder" in body, (
        "accounts_folder_create no longer calls create_folder — "
        "re-verify the pin's target."
    )
    assert "invalidate_cache_for_account" in body, (
        "N-277 R29 REGRESSION: accounts_folder_create no longer "
        "invalidates the provider-labels cache after create_folder. "
        "The response's 'Available in the move-folder picker now' "
        "line becomes a lie for up to 5 min (cache TTL)."
    )
