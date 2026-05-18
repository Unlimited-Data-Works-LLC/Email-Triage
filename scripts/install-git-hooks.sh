#!/usr/bin/env bash
#
# scripts/install-git-hooks.sh — point git at the repo-tracked
# hooks under .githooks/ so they actually run.
#
# Run once after cloning (or after a CI runner needs the hooks):
#     ./scripts/install-git-hooks.sh
#
# Reverts: git config --unset core.hooksPath
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "Git hooks installed:"
ls -1 .githooks/ | grep -v '^\.' | while read -r h; do
    echo "  - $h"
done
echo
echo "Bypass once (emergency only):  git push --no-verify"
echo "Disable repo hooks entirely:   git config --unset core.hooksPath"
