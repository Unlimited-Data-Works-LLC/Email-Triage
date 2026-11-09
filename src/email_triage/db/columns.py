"""Column-list constants for the tables whose reads replaced ``SELECT *``.

One constant per table, in ``PRAGMA table_info`` order, so a later
``ALTER TABLE ... ADD COLUMN`` is one edit here instead of a silent miss in
every hand-typed copy (style guide PD#5). The pin
``tests/test_db_column_constants_pin.py`` walks every ``*_COLUMNS`` name in
this module and asserts it equals the live schema, so a stale constant fails
the suite (PD#1). Name rule: ``<TABLE>_COLUMNS`` with the table name upper-cased;
the pin derives the table from the name, so keep the rule.

These are fixed identifiers, never user input: interpolating one into SQL
with an f-string is safe.
"""

from __future__ import annotations

ACME_JOBS_COLUMNS = (
    "job_id, actor_user_id, domains_json, directory_url, order_url, phase, "
    "attempt, max_attempts, visibility_json, last_error, last_error_kind, "
    "cancel_requested, started_at, last_progress_at, ended_at, created_at"
)
ACME_RENEWAL_LOG_COLUMNS = (
    "id, ts, domain, outcome, not_before, not_after, error"
)
AUTH_EVENTS_COLUMNS = (
    "id, ts, event_type, user_id, email, key_id, ip, user_agent, outcome, "
    "detail, prev_hash, row_hash, hash_alg, master_key_version"
)
CLASSIFICATION_LISTS_COLUMNS = (
    "id, name, category, owner_id, is_global, created_at"
)
DEV_KEYS_COLUMNS = (
    "id, name, public_key, fingerprint, email_allowlist_json, "
    "created_by_user_id, created_at, expires_at, last_used_at, "
    "last_used_email, last_used_ip, revoked_at, revoked_by_user_id"
)
EMAIL_WATCHES_COLUMNS = (
    "watch_id, name, enabled, account_id, filter_json, actions_json, "
    "created_at, updated_at, watch_group_id, created_by_user_id"
)
EMBEDDING_BITS_INSTALL_STATE_COLUMNS = (
    "id, status, install_method, manifest_sha256, runtime_deps_path, "
    "progress_files_done, progress_files_total, progress_bytes_done, "
    "progress_bytes_total, current_file, attempt_count, last_attempt_at, "
    "installed_at, last_error_class, last_error_msg, last_error_at, "
    "created_at"
)
FLOWS_COLUMNS = (
    "flow_id, message_id, provider, status, revision, classification_json, "
    "actions_completed_json, actions_pending_json, state_bag_json, error, "
    "created_at, updated_at"
)
GMAIL_WATCHES_COLUMNS = (
    "account_id, email_address, topic_name, history_id, expires_at, "
    "status, error_count, error_last, created_at, updated_at"
)
HARDWARE_KEYS_COLUMNS = (
    "id, user_id, credential_id, public_key, sign_count, transports, "
    "aaguid, nickname, created_at, last_used_at, revoked_at"
)
LIST_RULES_COLUMNS = (
    "id, list_id, rule_type, pattern, skip_ai, created_at, adds_labels, "
    "provider_labels"
)
OFFICE365_SUBSCRIPTIONS_COLUMNS = (
    "account_id, subscription_id, expiration_at, last_renewed_at, "
    "last_notification_at, status, error_count, error_last, created_at, "
    "updated_at, delta_link"
)
REGULATORY_CLOCK_DEF_COLUMNS = (
    "id, code, regime, citation, title, severity_class, clock_kind, "
    "duration_value, duration_unit, calendar_tz, clock_start_kind, "
    "pausable, duration_overridable, ack_required, escalation_lead_pcts, "
    "action_target, config_owner_account_id, enabled, created_at"
)
STYLE_DISTILL_EVENTS_COLUMNS = (
    "id, ts, account_id, actor_user_id, backend_id, backend_type, "
    "was_cloud, outcome, latency_ms, layer1_drops, layer2_matches, "
    "layer3_entities, scrubber_degraded, error_class, kind, "
    "recipient_hash, prev_hash, row_hash, hash_alg, master_key_version"
)
STYLE_DISTILL_QUEUE_COLUMNS = (
    "account_id, attempt_count, next_retry_at, last_error, "
    "last_attempt_at, paused, created_at"
)
STYLE_DISTILL_QUEUE_CONTACTS_COLUMNS = (
    "account_id, recipient_hash, attempt_count, next_retry_at, last_error, "
    "last_attempt_at, paused, created_at"
)
TOPICS_COLUMNS = (
    "id, user_id, name, subjects_json, details, details_source, "
    "selected_account_ids_json, mode, retention_days, schedule_json, "
    "window_json, format_json, topic_version, enabled, created_at, "
    "updated_at, deleted_at, digests_json, confidence_floor"
)
TRIAGE_JOBS_COLUMNS = (
    "job_id, account_id, actor_user_id, query, status, total_seen, "
    "total_processed, total_skipped, total_errors, rate_msg_per_min, "
    "concurrency, started_at, last_progress_at, ended_at, error_text, "
    "created_at, cursor, kind, ceiling_hit, total_cache_skipped"
)
USER_STATUS_EVENTS_COLUMNS = (
    "id, ts, target_user_id, actor_user_id, event, reason, prev_hash, "
    "row_hash, hash_alg, master_key_version"
)
USERS_COLUMNS = (
    "id, email, name, role, notify_email, created_at, last_login, "
    "disabled, disabled_at, disabled_by_user_id, webauthn_user_handle, "
    "session_epoch, style_guide, style_tone, style_length, "
    "style_signature, style_greeting, style_greeting_custom, "
    "anti_ai_style_guide_user, anti_ai_style_guide_disable_global"
)
WATCHER_RETRY_QUEUE_COLUMNS = (
    "id, account_id, provider_type, mailbox, uid, uidvalidity, "
    "gmail_msg_id, o365_msg_id, state, attempt_count, first_seen_at, "
    "next_attempt_at, last_error_class, last_error_msg, last_error_at, "
    "resolved_at, dead_reason, created_at, failure_kind"
)
