#!/usr/bin/env bash
# Browser end-to-end tier — runs the Playwright specs in tests/e2e.
#
# Each spec boots a REAL uvicorn server (lifespan off, inert + seeded —
# no external IMAP/Graph egress) on a free port, injects a session
# cookie, and drives a real Chromium browser against it. This tier is
# OPT-IN: the default `pytest` / test-fast.sh / test-broad.sh runs skip
# tests/e2e entirely (pyproject `addopts = --ignore=tests/e2e`), so they
# never launch a browser or need Playwright installed.
#
# First-time setup (once):
#   pip install -e '.[e2e]'        # pytest-playwright + playwright
#   playwright install chromium    # the browser binary
#
# Usage:
#   ./scripts/test-e2e.sh                       # all e2e specs, headless
#   ./scripts/test-e2e.sh tests/e2e/test_x.py   # one spec
#   ./scripts/test-e2e.sh --headed              # watch it run
#
# Explicitly naming tests/e2e overrides the default --ignore, so no
# `-o addopts=` dance is needed.

set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=()
EXTRA=()
for arg in "$@"; do
    case "$arg" in
        tests/e2e*) TARGET+=("$arg") ;;
        *) EXTRA+=("$arg") ;;
    esac
done
if [ ${#TARGET[@]} -eq 0 ]; then
    TARGET=(tests/e2e)
fi

# --browser chromium: the one browser we install in CI. Serial (no
# xdist) — each spec shares a session-scoped server; parallel workers
# would each boot their own and contend for ports/CPU for little gain at
# this suite size.
exec python -m pytest "${TARGET[@]}" --browser chromium --no-header -q "${EXTRA[@]}"
