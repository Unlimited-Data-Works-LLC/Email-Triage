"""Applied migrations are IMMUTABLE — freeze every body's normalized checksum.

Why this pin exists (the 2026-06-11 the deploy host deploy break)
------------------------------------------------------
``run_migrations`` records each migration's AST-normalized body checksum in
``schema_migrations.checksum`` when it is first applied, and RE-checks it on
every subsequent boot. If an already-applied migration's *executable* source
changes, the recorded checksum no longer matches and the runner raises
``MigrationError`` and **refuses to start** — the §164.312(c)(1) tamper-guard
doing its job.

On 2026-06-11 the A10 ``_isotime`` SSOT-adoption sweep (commit aec8d98) routed
the inline timestamp inside the *frozen* body of migration 5
(``datetime.now(timezone.utc).isoformat()`` → ``now_utc_iso()``) and dropped an
unused import from migration 35's body. Both are behavior-NEUTRAL — they write
byte-identical *values* — but the guard hashes *source*, not values, so each
edit changed the migration's checksum. The new image booted fine against a
*fresh* test DB (where the migration is applied BY the new source, so the
checksum matches by construction) and passed ~6300 tests, then failed to start
against the real upgraded DB on the deploy host and auto-rolled-back. The deploy's own
init_db / version-check upgrade smoke that would have caught it is SKIPPED on
encrypted (SQLCipher) installs (deploy.sh "F6"), so production was the first
real upgrade-path check.

The existing ``test_migrations_checksum_pin`` only pins the checksum *algorithm
shape* — it cannot detect an edited body. This pin closes that gap at the CI
layer: it freezes the normalized checksum of every shipped migration body, so
editing an applied body (or adding a new migration without pinning it) fails
here, before any deploy.

The rule this enforces
----------------------
- **Never edit the executable source of an already-shipped migration body.** A
  shipped migration is a frozen historical artifact. If behavior must change,
  add a NEW migration; do not rewrite an old one.
- **Migration bodies must be self-contained stdlib** — they must NOT be routed
  through a mutable app SSOT (``_isotime.now_utc_iso``/``now_utc_iso_z``,
  ``db._helpers.load_json_col``, …). A future format/impl change to that SSOT
  would silently change a frozen body's checksum. (The A10 inline-timestamp pin
  carries the reciprocal carve-out: an inline ``.now(tz).isoformat()`` inside a
  ``_vNN_*`` body is allowed precisely BECAUSE the body must stay self-contained.)

Why a normalized-checksum freeze is NOT the fragile golden-file that
``test_migrations_checksum_pin``'s docstring warns against: the *normalized*
checksum is computed from the AST-unparsed body with comments and docstrings
stripped (``migrations._normalize_body``). A docstring tweak, a comment, a
reflowed long line, or an added ``# json-col-ok`` marker does NOT change it —
only a change to the statements that actually run. So this fixture churns only
when a body's executable code changes, which is exactly when we want to be told.

Maintenance
-----------
Adding a migration is the one legitimate way this fixture grows: append the new
version's checksum (the failure message prints the exact line to paste). That
append is the deliberate "I am shipping a new, now-frozen migration" act.
"""

from __future__ import annotations

from email_triage.web import migrations as mig_mod

# Normalized-body SHA-256 of every shipped migration, keyed by version.
# Generated from the body source at the moment each migration shipped; once a
# row is here it is FROZEN. Do not edit an existing value to "make the test
# pass" after changing a body — that re-opens the 2026-06-11 deploy break. Add a
# new row only when you add a new migration.
_FROZEN_CHECKSUMS: dict[int, str] = {
    1: "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1",  # framework_bootstrap
    2: "66248aff9c7d6f6275b83ee2ab3e07362f0cb07fa9b87d6004b7a027746ec7bd",  # create_triage_jobs
    3: "bdcafe95cc89cb8bb56632e48cd2ec1e946b076b66c100d670ddc55155154327",  # create_triage_job_messages
    4: "a98af31378279e77b3084f179b10ebb0ea276c83f3450b8685aa817da5019f05",  # add_triage_jobs_cursor
    5: "c81dbc492f1e5650380c53e129582ee359ffaca163b7fc125ffaf9930504ec1d",  # digest_format_default_preview_off
    6: "50f1ccd27ac532ae7feb87b59bed6f0e1347181c9f7635108c2d6d6ad9a59a4e",  # backfill_account_tz_default
    7: "6f5340a296bdbf9416d7a36724b24b730d12ff2f5e462fed2a5a4752a0906c51",  # create_acme_jobs
    8: "35ecb012a8627ebde9a446b08c2f7ffa04800f8d20dc3122fc6a6caf896299f1",  # create_office365_subscriptions
    9: "964fbfcbe3d3de427e2edf3da64062373725fc1a06aae93880c8efbed2fb37f3",  # create_email_watches
    10: "66ae5151113ca65955c4f29b521d4c637dbd74d93967987aa293101bafd81df2",  # add_email_account_aliases
    11: "57d05c9d8f6b1ac0437711fbeb73ef1df19dc69d955343dca23e30857f6700f0",  # add_user_style_knobs
    12: "35bb23573ce24df275e656d640c9f11d3a88457065c90ba3830909eaf6180891",  # create_sent_mail_index
    13: "254c5bff2a14091b533280e63f058a3a8d71c4614b6dbf4f61dda0ff49a8192a",  # add_o365_subscriptions_delta_link
    14: "b7874aafd3d306e8d602beb8b4598f5f92bf93d213c44d84b30a578bff947317",  # add_sent_mail_index_captured_pair
    15: "9b4c2dbecd2502c2136a8664bf4444e1a8a78113de9dc59ebf20c5c4f9316c24",  # add_sent_mail_index_embedding_norm
    16: "2e93cdf918326295404c96ab7cf0826f93a69e2adc1ff8669afcee48dba8cef1",  # create_triage_retry_queue
    17: "cc7ce590ff930c39f59885d3989b8d6499e47b324020ed4e7c083bdbbbc554b8",  # watches_per_account_fanout
    18: "cd63b85821b5e74d26c3f29f6473b985a0c6375e3217abb88bedf85b2e7a91c1",  # create_labels
    19: "5c2bc1ef618cdec02f5168fddc052751cd0a7b40bc0baa6e643b79569eae9a63",  # add_user_anti_ai_style_guide
    20: "4a4a0f86013d6b8c9a9896c478836846efe0076d87a23b17d1540f32ce9c90e9",  # sent_folder_override_string_to_list
    21: "87313c0cc90c66be5518cc1ad1a45bcd3f9f74d0c454dfd78986133b3c47e1f9",  # add_triage_jobs_kind
    22: "9df2e2dc16dd93a0f4200d4058b204405b12208f6015093c64e6b2b9d51940a2",  # add_list_rules_provider_labels
    23: "7cd597443db0e54ed43dfb16a60a6f4324f29c0bbecd569224c130117a274dae",  # add_account_style_per_alias
    24: "710a4df148822155256b653f9e2b938ee289cc45538ffa38c8df7342c47efd44",  # create_push_deliveries
    25: "afbd6f6256821ca837369eb409730ec6953c48d97860262491ce435cbd5c2f64",  # add_hipaa_style_descriptor
    26: "8a8ef113f61773208baef5bc7a5e287790e903b1dedc36147e5fa6c9b95355bc",  # create_ai_backends
    27: "f47d9156da5dc1e914dcd6563302b1f25b81abff33bce40baf9daef775a94e4b",  # create_style_distill_audit_and_queue
    28: "7f50658ee4e7d41c65d57cf7e692c6537d966d2dd9b9aff0fca77889f383372b",  # create_per_contact_style_hipaa
    29: "72c648fe8937ac7efa24e64322ea666b2e5de64920a873b0513149a720b10270",  # create_hipaa_send_counters
    30: "15f4e1a8b869d17e979dca362a68d07404bf30f26dbc89407977ddeb469e2f48",  # create_watcher_retry_queue
    31: "f7ca8ebf7b05ec11b50cfaa6894720fecca27168129d2297ac973abfcb03d367",  # create_embedding_bits_install_state
    32: "a1e3f66dbe0c4d9eb8367a1fec72d49a24b2fcf62538a1070b4a8e48b29226b8",  # add_sent_mail_index_embedding_dimension
    33: "0bfe1bf332c20672f9d7731e39ddff7772924af940b28d29458e9c095436eee3",  # create_hipaa_sent_dedup
    34: "9a385d58768af043474f021f9f86effee22218e6e8bb01f5caff034a9b78f069",  # create_action_idempotency
    35: "07c293a3b75fc3abc309848115441145f56ca58ab7833f513ed7a27b9f8629ae",  # consolidate_retry_queues
    36: "829203078368043e410296970c907d8f0047d8a62a140b9d4b98a0d7484b1cbe",  # create_watch_fire_idempotency
    37: "a6e881379d653823d39aa1dcd60782788810d4f99feb12c4fc270ee1110fc6c6",  # rekey_watch_fire_idempotency
    38: "f9aecac0e6a63bdd9844a477f05ac42bb413612492e15d5921562e9790dd8bd0",  # create_audit_gap_events
    39: "034baa655e1fa4cbe15ebac8daeaee696b90c50da24053d465f8813944d0bc89",  # add_ai_backends_backup_models
    40: "80845ec892c7450002081970951aaea94ecf8fcf91955ffdd25e94f2c6c53f38",  # create_topic_digest_tables
    41: "0094aeb708d5ba8c3ffe61ff44c0090c0c9e653d557c8e348e2c8551197027ec",  # topics_add_digests_json
    42: "adcf730e30f69ce9e3e619b741f3b7131495e952a5fb3a9bddf976a8512f6824",  # create_topic_feedback
    43: "afe22e43ab825cf738c3f8e30ceabe7f22e2de79a1518a7be1090e000cc53b82",  # audit_chain_columns
    44: "e0b82086dd5f048f474db0d09401907909061aa065ef3ba85573435750ed9813",  # triage_jobs_backscan_ceiling_and_cache_skipped
    45: "71f1d79e29b782604d4fa9d0b2398c0bd76b9c1c972c99b2b432932a9b01497f",  # study_match_cache_match_fingerprint
    46: "187e51410ea88216e0645c3565f6580aa9b78f058770d085337bf2f95124319a",  # regulatory_clock_tables
    47: "1590c3f9b26828aa026f8020cc64589c5bfacd4cf1c30377cbda1629b472db2b",  # regulatory_clock_event_chain_columns
    48: "33eea61be1ceec14f51d9c594cc9cdc771940a1a06b66fac6e08d0f2d6c94c7d",  # regulatory_clock_instance_calendar_written_at
    49: "46b60e2e8d2ec467f6c04ab642b577e31e6e68a32bb8fb8d3460423d9cb2d26e",  # topics_add_confidence_floor
    50: "a24ad9f789030a5a069682cd5fc7d445e949deddd217923a5f6f57498d42a03c",  # gmail_watches_add_status_columns
    51: "fdd6303cacf435a1323ce11e6d74eff500528ec141e93b3c634f90f95ebcd5f2",  # regulatory_clock_instance_uq_case_partial
    52: "19e9b58901062287679f3a4d26746c9acc2a08f5737d6ff3e130a4efbaea2aa5",  # gmail_watches_lower_email_functional_index
    53: "b2999571d0a51d09cf0a77275ee5fe0cfa9e9141e01747be13384b55bb1d5406",  # webauthn_challenges_add_require_uv
    54: "01d3f8aaf93cb62944319d898d1b893b5ec1eba3923d514f53018a7152f26c61",  # api_key_events_add_actor_email
    55: "9c9c29d0b70a4df0c8280b6ff5a9dcca6e79d67be18689fcac611c6f82cf7493",  # api_keys_add_scope
}


def _current() -> dict[int, str]:
    """version -> current normalized checksum, for every registered migration."""
    return {m.version: mig_mod._checksum_for(m.body) for m in mig_mod.MIGRATIONS}


def test_applied_migration_bodies_are_immutable():
    """Every shipped migration body's normalized checksum must match its frozen
    value. A mismatch means an already-applied migration was edited — which
    would refuse-to-boot on any DB that already recorded the old checksum."""
    current = _current()
    drifted = []
    for version, frozen in _FROZEN_CHECKSUMS.items():
        got = current.get(version)
        if got is None:
            drifted.append(
                f"  v{version}: FROZEN but no longer registered — a shipped "
                f"migration was DELETED. Migrations are append-only; restore it."
            )
        elif got != frozen:
            drifted.append(
                f"  v{version} ({_name(version)}): body checksum changed\n"
                f"      frozen:  {frozen}\n"
                f"      current: {got}"
            )
    assert not drifted, (
        "An already-applied migration body changed (or was deleted). Applied "
        "migrations are IMMUTABLE — the recorded checksum is re-verified on "
        "every boot, so an edited body makes the app refuse to start against "
        "any DB that recorded the old value (the 2026-06-11 production deploy "
        "break).\n" + "\n".join(drifted) + "\n\n"
        "If you meant to change behavior, REVERT this edit and add a NEW "
        "migration instead. Do NOT update the frozen value to match — that "
        "defeats the guard. (If you are routing the body through an app SSOT "
        "like now_utc_iso()/load_json_col(), undo it: migration bodies must be "
        "self-contained stdlib.)"
    )


def test_every_migration_is_frozen():
    """A newly added migration must be pinned here in the same change. This makes
    the freeze complete-by-construction: you cannot ship a migration whose body
    isn't frozen, so the immutability guard above can never have a blind spot."""
    current = _current()
    unpinned = sorted(set(current) - set(_FROZEN_CHECKSUMS))
    lines = [
        f"    {v}: \"{current[v]}\",  # {_name(v)}" for v in unpinned
    ]
    assert not unpinned, (
        "New migration(s) are not frozen in _FROZEN_CHECKSUMS. Append the line(s) "
        "below to the fixture (this is the deliberate 'I am shipping a new, "
        "now-frozen migration' step):\n" + "\n".join(lines)
    )


def test_no_phantom_frozen_versions():
    """Guard the other direction: a frozen version with no live migration would
    silently never be checked. (Covered by the immutability test's delete branch
    too; this asserts it explicitly.)"""
    current = _current()
    phantom = sorted(set(_FROZEN_CHECKSUMS) - set(current))
    assert not phantom, (
        f"Frozen versions with no registered migration (deleted?): {phantom}"
    )


def test_freeze_pin_has_teeth():
    """The normalized checksum must actually change when a body's executable
    tokens change — otherwise the freeze would be vacuous."""
    from email_triage.web.migrations import _checksum_for

    def _v_a(conn):  # noqa: ANN001
        conn.execute("SELECT 1")

    def _v_b(conn):  # noqa: ANN001
        conn.execute("SELECT 2")

    def _v_a_comment(conn):  # noqa: ANN001
        # a comment-only difference must NOT change the normalized checksum
        conn.execute("SELECT 1")

    assert _checksum_for(_v_a) != _checksum_for(_v_b), (
        "normalized checksum is insensitive to an executable change — vacuous"
    )
    assert _checksum_for(_v_a) == _checksum_for(_v_a_comment), (
        "normalized checksum changed on a comment-only edit — would churn"
    )
    assert _FROZEN_CHECKSUMS, "freeze fixture is empty"


def _name(version: int) -> str:
    for m in mig_mod.MIGRATIONS:
        if m.version == version:
            return m.name
    return "?"
