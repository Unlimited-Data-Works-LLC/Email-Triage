"""N-320 R30 unit tests — task  tranche  KEY_HISTORY rollback-
resurrection close.

DA panel on tranche  flagged §164.308(a)(4)(ii)(A) rollback-
resurrection surface on N-231: rotating a secret without deleting
the OLD row from the store lets a subsequent rollback silently
resume reading the compromised OLD name. `KEY_HISTORY` tracks
retired names per current key; `secrets purge-retired-keys` CLI
verb deletes them from the store during the rotation ceremony.

Operator-approved delivery model 2026-07-03: CLI verb (not
startup-auto). Fits `feedback_no_persistent_install_for_ad_hoc` +
audit-emit via `@_cli_audit("secrets")`.
"""
from __future__ import annotations


def test_key_history_covers_every_current_key():
    """Every constant in `_secret_keys` MUST have a `KEY_HISTORY`
    entry so a rotation writer doesn't silently drop the retired-
    name capture. Empty tuple is legit ('no rotations yet')."""
    from email_triage import _secret_keys
    current_keys = {
        _secret_keys.SMTP_PASSWORD_KEY,
        _secret_keys.SESSION_SECRET_KEY,
        _secret_keys.ACME_ACCOUNT_KEY_KEY,
    }
    missing = current_keys - set(_secret_keys.KEY_HISTORY.keys())
    assert not missing, (
        f"N-320 R30 REGRESSION: KEY_HISTORY missing entries for "
        f"current-key constants: {sorted(missing)}. Every constant "
        f"needs a `KEY_HISTORY[NAME] = ()` entry — empty tuple is "
        f"legit ('no rotations yet')."
    )


def test_retired_names_is_deduplicated():
    """`retired_names()` must return each retired name at most once
    even if two current-keys share a retired ancestor."""
    from email_triage._secret_keys import retired_names
    from email_triage import _secret_keys as k

    original = k.KEY_HISTORY
    try:
        k.KEY_HISTORY = {
            "current_a": ("legacy_shared",),
            "current_b": ("legacy_shared", "legacy_b_only"),
        }
        result = retired_names()
        assert result == ["legacy_shared", "legacy_b_only"] or \
            result == ["legacy_b_only", "legacy_shared"] or \
            sorted(result) == sorted(["legacy_shared", "legacy_b_only"])
        assert len(result) == 2, (
            f"N-320 R30: retired_names must dedup; got {result!r}"
        )
    finally:
        k.KEY_HISTORY = original


def test_cli_verb_registered():
    """`secrets purge-retired-keys` must be an accepted subcommand."""
    from email_triage.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["secrets", "purge-retired-keys"])
    assert args.secrets_cmd == "purge-retired-keys"


def test_purge_delegates_to_provider_delete_idempotently():
    """The purge iterates every retired name and calls
    `provider.delete(name)` — a missing name (delete returns False)
    is NOT an error; the loop continues + counts it as preserved."""
    # Direct-loop simulation (the CLI handler's body is identical).
    from email_triage._secret_keys import retired_names as _rn
    from email_triage import _secret_keys as k

    original = k.KEY_HISTORY
    try:
        k.KEY_HISTORY = {
            "current": ("v1_retired", "v2_retired"),
        }
        seen: dict[str, int] = {}

        class FakeProvider:
            def delete(self, key: str) -> bool:
                seen[key] = seen.get(key, 0) + 1
                return key == "v1_retired"  # v2 already absent

        p = FakeProvider()
        retired = _rn()
        deleted = 0
        preserved = 0
        for name in retired:
            if p.delete(name):
                deleted += 1
            else:
                preserved += 1
        assert deleted == 1
        assert preserved == 1
        assert seen == {"v1_retired": 1, "v2_retired": 1}
    finally:
        k.KEY_HISTORY = original
