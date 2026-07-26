"""N-244 R24 structural pin — short-id minter SSOT anti-vacuity (2026-07-03).

Census R24 discovered MED (short-id minter unification): 11 sites forked
`uuid.uuid4().hex[:N]` / `secrets.token_hex(N)` across width families.
N-244 landed `email_triage/_ids.py::new_short_id(prefix, *, length=12)`
+ migrated the 3 non-migration-body prefix-carrying sites (topic_configs,
email_watches, acme_job_state).

The remaining sites are LEGIT:
- `web/app.py::_ensure_session_secret` — `token_hex(32)` = 256-bit session
  HMAC secret; NOT a short-id, different concern.
- `web/dependencies.py::get_session_secret` — same.
- `web/acme_renewer.py:1239` probe_value — random challenge value;
  entropy strength IS the point, not a short opaque ID.
- `web/acme_renewer.py:1726` attempt_id — 4-char attempt-index-like ID
  for a single-run session; extremely local scope.
- `email_watches.py:418` — `uuid.uuid4().hex` = full UUID for
  `watch_group_id`; different width class + persisted foreign-key
  contract per docstring at :417.
- 2 migration-body copies in `web/migrations.py` — frozen bodies per
  `incident_2026-06-11_migration_body_immutability`.

WHAT IT PINS (anti-vacuity):

`_ids.new_short_id` must import + return `<prefix>_<hex>` with the
right length + non-empty prefix + short-hex tail.
"""
from __future__ import annotations


def test_new_short_id_ssot_reachable():
    """Anti-vacuity: `_ids.new_short_id` must import + return the
    documented shape."""
    from email_triage._ids import new_short_id

    a = new_short_id("watch")
    assert a.startswith("watch_")
    assert len(a) == len("watch_") + 12  # default length
    # Tail is lowercase hex.
    tail = a.split("_", 1)[1]
    assert all(c in "0123456789abcdef" for c in tail)
    # Custom length
    b = new_short_id("acme", length=8)
    assert b.startswith("acme_")
    assert len(b) == len("acme_") + 8
    # Empty prefix → bare hex tail.
    c = new_short_id("")
    assert len(c) == 12
    assert "_" not in c
    # Randomness sanity (probability of collision on 48 bits × 2 = negligible).
    assert new_short_id("watch") != new_short_id("watch")
