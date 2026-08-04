"""N-280 R29 structural pin — removed-mailbox settings sweep (2026-07-03).

R29 census #7 (digest_state / watch_hwm / mailbox_routes orphan):
`update_email_account` did NOT compute `removed_mailboxes` between
the OLD config and the NEW config, so `watch_hwm:<id>:mailbox:
<removed>` + `mailbox_routes:<id>:<removed>` orphaned across the
update boundary. Bidirectional PD#18 gap.

N-280 wires the sweep in `update_email_account`: read the old
config_json, diff mailboxes, delete_setting for each per-mailbox key
prefix on the removed set.

WHAT IT PINS (anti-vacuity):

`update_email_account` body textually references
`removed_mailboxes` + calls `delete_setting` for both
`watch_hwm:...:mailbox:...` and `mailbox_routes:...:...` prefixes.
"""
from __future__ import annotations

from _pin_harness import SRC_ROOT


def test_update_email_account_sweeps_removed_mailbox_settings():
    """The `update_email_account` primitive must textually compute
    `removed_mailboxes` + call `delete_setting` on both per-mailbox
    key prefixes on the removed set. A refactor that drops the sweep
    re-opens the orphan."""
    path = SRC_ROOT / "db" / "accounts.py"
    source = path.read_text(encoding="utf-8", errors="replace")
    idx = source.find("def update_email_account(")
    assert idx >= 0
    end = source.find("\ndef ", idx + 1)
    body = source[idx:end]
    assert "removed_mailboxes" in body, (
        "N-280 R29 REGRESSION: `update_email_account` no longer "
        "computes `removed_mailboxes` — the per-mailbox settings "
        "sweep is missing."
    )
    assert 'watch_hwm:' in body, (
        "N-280 R29 REGRESSION: the sweep no longer references "
        "the `watch_hwm:` per-mailbox key prefix."
    )
    assert 'mailbox_routes:' in body, (
        "N-280 R29 REGRESSION: the sweep no longer references "
        "the `mailbox_routes:` per-mailbox key prefix."
    )
    assert "delete_setting(" in body, (
        "N-280 R29 REGRESSION: the sweep no longer calls "
        "`delete_setting` on the removed-mailbox keys."
    )
