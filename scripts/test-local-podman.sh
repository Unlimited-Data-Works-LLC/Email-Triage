#!/usr/bin/env bash
# Run the email-triage test suite (or a specific target) in the local
# real-SQLCipher Podman image — fast iteration against the LIVE checkout.
#
# Why this exists: Windows-native Python has no sqlcipher3 wheel, so encrypted /
# HIPAA-path tests could previously only run on the deploy host. The Containerfile.test image
# bakes real SQLCipher 4.x + all deps; this runner mounts the live repo read-only
# so iteration cost is just the test time. See the memory drawer
# reference_podman_local_windows_testing for the WSL2 gotchas (machine-start,
# IPv6-no-route -> gai.conf IPv4, ro-mount build fail, MSYS path-mangling).
#
# One-time build (from the repo root):
#   MSYS_NO_PATHCONV=1 "$PODMAN" build -t email-triage-test:local -f Containerfile.test .
# Then run, e.g.:
#   ./scripts/test-local-podman.sh                                   # full unit+pin suite (mirrors CI)
#   ./scripts/test-local-podman.sh tests/test_cli_db_open_encryption_pin.py -q
#   ./scripts/test-local-podman.sh tests/test_cli.py -q
set -euo pipefail

# git-bash (MSYS) rewrites Unix-looking args like `/repo` and `/repo/src` into
# `C:/Program Files/Git/repo` before they reach podman.exe, breaking the
# container-side -w/-v/-e paths. Disable that conversion; the Windows -v SOURCE
# (REPO_WIN, backslashes) is passed through unchanged.
export MSYS_NO_PATHCONV=1

PODMAN="${PODMAN:-/c/Users/ExampleUser/AppData/Local/Programs/Podman/podman.exe}"
IMAGE="${IMAGE:-email-triage-test:local}"

# Derive the repo root from this script's location (scripts/..), as a Windows
# path for the podman -v source. No hardcoded per-user path. Override via REPO_WIN.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_WIN="${REPO_WIN:-$(cd "$SCRIPT_DIR/.." && pwd -W)}"

# Default target mirrors CI's `pytest tests/ -n auto -q`; override via args.
if [ "$#" -gt 0 ]; then TARGET=("$@"); else TARGET=(tests/ -n auto -q); fi

# Mount the live repo READ-ONLY; PYTHONPATH=/repo/src makes the checked-out
# source (not the image's baked copy) the one under test. Disable bytecode +
# pytest-cache writes so the ro mount needs no write access to the repo.
exec "$PODMAN" run --rm \
  -v "${REPO_WIN}:/repo:ro" \
  -e PYTHONPATH=/repo/src \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -w /repo \
  "$IMAGE" \
  python -m pytest -p no:cacheprovider "${TARGET[@]}"
