#!/usr/bin/env bash
# Fast test tier — runs the FILES specified by the operator (or a sensible
# default subset) under pytest-xdist parallel workers.
#
# Intent: gate deploys + interactive iteration. Covers the touched-files
# + adjacent suites. Skips the slow O365 push consumer / subscription
# renewer / account wizard autochain heavies (those live in test-broad.sh).
#
# Usage:
#   ./scripts/test-fast.sh                 # default subset
#   ./scripts/test-fast.sh tests/foo.py    # explicit files
#   ./scripts/test-fast.sh -k pattern      # pytest -k expression
#
# Tier rationale: per feedback_strict_action_gating, deploy to deploy-host is
# Tier 2 (recoverable). A targeted fast tier is the right gate — broad
# sweep runs in background via test-broad.sh and failure produces a
# patch-forward, not a roll-back.

set -euo pipefail

cd "$(dirname "$0")/.."

# Default subset = touched-cluster heuristics. Operator can pass explicit
# paths to override. Picked to cover ~95% of regression surface at the
# cost of ~5-7 min vs the full ~50 min sweep.
DEFAULT_SUBSET=(
    tests/test_web/test_csrf.py
    tests/test_web/test_csrf_input_helper.py
    tests/test_web/test_config.py
    tests/test_web/test_template_phi_guard.py
    tests/test_web/test_health.py
    tests/test_web/test_admin_integrations_o365.py
    tests/test_web/test_integrations_admin.py
    tests/test_web/test_integrations_redis_section.py
    tests/test_web/test_o365_probe_ui.py
    tests/test_web/test_watches_profile.py
    tests/test_web/test_watches_migration.py
    tests/test_web/test_labels.py
    tests/test_web/test_labels_rule_apply.py
    tests/test_web/test_accounts.py
    tests/test_cache/
    tests/test_privacy_invariants_m_series.py
    tests/test_privacy_invariants_dep_review.py
    tests/test_privacy_invariants_log_scrub.py
    tests/test_privacy_invariants_no_customer_names.py
    tests/test_providers/test_factory.py
    tests/test_providers/test_office365.py
)

if [ $# -gt 0 ]; then
    ARGS=("$@")
else
    ARGS=("${DEFAULT_SUBSET[@]}")
fi

# -n auto picks worker count = CPU cores (typically 4-8 on dev boxes).
# --dist loadfile pins each test file to one worker so shared-mock
# state + concurrency tests don't race across workers (see
# scripts/test-broad.sh comment block for the observed flake).
# --maxfail=5 stops the run early if too many things break — there's
# no point churning workers when something fundamental is broken.
exec python -m pytest -n auto --dist=loadfile --maxfail=5 --no-header -q "${ARGS[@]}"
