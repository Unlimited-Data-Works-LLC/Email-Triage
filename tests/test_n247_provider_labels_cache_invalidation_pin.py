"""N-247 R24 structural pin — provider_labels cache invalidation on account delete (2026-07-03).

Census R24 discovered LOW (provider_labels module cache lifecycle): the
5-min-TTL cache keyed on `(account_id, provider_type)` was NOT flushed
on `delete_email_account` — a deleted account's label list kept
rendering to the picker for up to 5 minutes.

N-247 fix: `providers/provider_labels.py::invalidate_cache_for_account`
(PUBLIC) added + wired into `db/accounts.py::delete_email_account`
success path.

WHAT IT PINS (anti-vacuity + behavior):

- `invalidate_cache_for_account` must import + drop only the target
  account's entries + return the drop count.
- `db/accounts.py::delete_email_account` textually calls
  `invalidate_cache_for_account`.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def _fn_body(source: str, fn_name: str) -> str:
    """N-335 R31 (2026-07-04) — FUNNEL-DEDUPE per PD #6.

    Return the source lines belonging to ``def <fn_name>`` (or
    ``async def <fn_name>``) — the region from its ``def`` line to
    just before the next ``def`` / ``async def`` at the module level.
    Textual fn-scope walker (not AST) matching the sibling test's
    existing pattern for consistency across this file.

    Replaces the N-294b fixed-count ``source[idx:idx + 2000]`` window
    in ``test_delete_email_account_calls_invalidate`` — that shape
    was a PD #1 count-agnostic violation flagged by the 2026-07-03
    trust-audit damage report (widening 800 → 2000 as band-aid on a
    docstring insertion). The fn-scope walker is drift-immune.

    Raises AssertionError if ``def <fn_name>`` is not found so the
    caller sees a clear failure rather than a silent empty slice.
    """
    idx = source.find(f"def {fn_name}(")
    assert idx >= 0, f"function `{fn_name}` not found in the source"
    # Rewind to include the ``async `` prefix if this is an async def.
    if idx >= len("async ") and source[idx - len("async "):idx] == "async ":
        idx -= len("async ")
    end_a = source.find("\ndef ", idx + 1)
    end_b = source.find("\nasync def ", idx + 1)
    end = min(
        (x for x in (end_a, end_b, len(source)) if x > 0),
        default=len(source),
    )
    return source[idx:end]


def test_invalidate_cache_public_api():
    """`invalidate_cache_for_account` imports + returns the count of
    dropped entries; leaves untouched entries alone."""
    from email_triage.providers.provider_labels import (
        _cache,
        invalidate_cache_for_account,
    )
    # Empty cache — no error, returns 0.
    _cache.clear()
    assert invalidate_cache_for_account(99999) == 0
    # Seed 2 accounts.
    _cache[(1, "gmail")] = (0.0, [{"name": "INBOX"}])
    _cache[(2, "gmail")] = (0.0, [{"name": "INBOX"}])
    assert invalidate_cache_for_account(1) == 1
    assert (1, "gmail") not in _cache
    assert (2, "gmail") in _cache
    # Idempotent — second call drops 0.
    assert invalidate_cache_for_account(1) == 0
    _cache.clear()


def test_delete_email_account_calls_invalidate():
    """Anti-vacuity: `db/accounts.py::delete_email_account` textually
    calls the invalidator. If a refactor drops it, deleted accounts'
    labels re-appear for 5 min."""
    path = SRC_ROOT / "db" / "accounts.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    # N-335 R31 (2026-07-04) — fn-scope walker replaces N-294b's
    # fixed-count ``source[idx:idx + 2000]`` window (PD #1 violation).
    body = _fn_body(source, "delete_email_account")
    assert "invalidate_cache_for_account" in body, (
        "N-247 R24: `delete_email_account` no longer calls "
        "`invalidate_cache_for_account`. A deleted account's picker "
        "labels will re-appear for up to 5 minutes (cache TTL)."
    )


def test_credential_flip_sites_call_invalidate():
    """N-271 R28 anti-vacuity: the 3 credential-flip sites census R28
    flagged (purge_account_local_state + 2 OAuth completions) must
    textually call `invalidate_cache_for_account`. A refactor that
    drops any of them silently re-opens the stale-labels-after-
    OAuth-re-auth window."""
    from _pin_harness import SRC_ROOT
    checks = [
        (SRC_ROOT / "db" / "accounts.py", "purge_account_local_state"),
        (SRC_ROOT / "web" / "routers" / "ui" / "oauth.py",
         "gmail_api_auth_complete_manual"),
        (SRC_ROOT / "web" / "routers" / "ui" / "oauth.py",
         "oauth_google_callback"),
    ]
    for path, fn in checks:
        source = path.read_text(encoding="utf-8", errors="replace")
        # N-335 R31 (2026-07-04) — routed through the shared
        # ``_fn_body`` helper so both tests in this file use ONE
        # walker (PD #6 funnel dedupe). Previously an inline copy.
        body = _fn_body(source, fn)
        assert "invalidate_cache_for_account" in body, (
            f"N-271 R28 REGRESSION: `{fn}` in {path.name} no longer "
            "calls `invalidate_cache_for_account`. Fresh credentials "
            "or a full account purge must invalidate the 5-min-TTL "
            "provider-labels cache so the picker doesn't serve labels "
            "drawn under OLD credentials."
        )
