#!/usr/bin/env bash
# Broad test tier — runs the full web + cache + privacy + providers
# sweep under pytest-xdist parallel workers, with the heaviest slow
# files excluded by default. Designed to run AFTER deploy, in the
# background, while the operator continues with the next task.
#
# Intent: catch any cross-suite regression that test-fast missed.
# Failure should NOT roll back the deploy — the operator patches
# forward + redeploys (Tier 2 SOFT recoverable). This is the safety
# net, not the gate.
#
# Usage:
#   ./scripts/test-broad.sh                       # default broad set
#   ./scripts/test-broad.sh --include-slow        # add O365 + wizard heavies
#
# Slow excludes:
#   - tests/test_web/test_office365_push.py
#   - tests/test_web/test_office365_push_consumer.py
#   - tests/test_web/test_office365_subscription_renewer.py
#   - tests/test_web/test_account_wizard_autochain.py
# These run nightly via cron or operator-explicit ``--include-slow``.

set -euo pipefail

cd "$(dirname "$0")/.."

INCLUDE_SLOW=0
if [ "${1:-}" = "--include-slow" ]; then
    INCLUDE_SLOW=1
fi

IGNORES=()
if [ $INCLUDE_SLOW -eq 0 ]; then
    IGNORES=(
        --ignore=tests/test_web/test_office365_push.py
        --ignore=tests/test_web/test_office365_push_consumer.py
        --ignore=tests/test_web/test_office365_subscription_renewer.py
        --ignore=tests/test_web/test_account_wizard_autochain.py
    )
fi

# -n auto -- parallel workers across CPU cores.
# --dist loadfile -- each test file binds to one worker. Preserves
# per-file isolation (so concurrency tests + shared-mock state
# don't race across workers). Slightly less aggressive parallelism
# than the default loadfile-less mode, but eliminates the
# cross-file flake observed on 0228b4e safety-net sweep:
#   test_db_threadpool::test_five_way_concurrency + test_imap::test_fetch_failure
# both pass serially + fail intermittently under default -n auto.
#
# Plain pytest still runs serially by default for single-test debug.
exec python -m pytest \
    tests/test_web/ \
    tests/test_cache/ \
    tests/test_privacy_invariants_*.py \
    tests/test_providers/ \
    -n auto --dist=loadfile \
    --no-header -q \
    "${IGNORES[@]}"
