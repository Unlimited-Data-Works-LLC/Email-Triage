#!/usr/bin/env bash
#
# Runs INSIDE the email-triage container (or by an operator with
# shell access to /app/data/runtime-deps). Extracts a staged tarball
# into the sideload directory and triggers the installer.
#
# Two invocation modes:
#
#   ./scripts/install-embedding-bits.sh extract <TARBALL>
#       Verify sidecar sha256 + extract into /app/data/runtime-deps/
#       sideload/. Does NOT run the installer — operator triggers it
#       via the admin UI button or the CLI subcommand below.
#
#   ./scripts/install-embedding-bits.sh sideload
#       Run `email-triage embedding-bits sideload --source-dir
#       /app/data/runtime-deps/sideload`. Equivalent to clicking the
#       admin UI button.
#
#   ./scripts/install-embedding-bits.sh install
#       Run `email-triage embedding-bits install`. Auto-download path
#       (skips the tarball step entirely).
#
# Why two paths (UI button + CLI):
#   * Admin UI: best for the typical setup-then-walk-away flow.
#     Hash verification + progress are surfaced inline.
#   * CLI: best for ops automation or air-gap installs where the
#     operator doesn't want to web-shell in. Same code path under
#     the hood (both call email_triage.embedding_bits.install_*).

set -euo pipefail

SIDELOAD_DIR="${EMBEDDING_BITS_SIDELOAD_DIR:-/app/data/runtime-deps/sideload}"

usage() {
    cat <<EOF
Usage: $0 <command> [args]

Commands:
  extract <TARBALL>   Verify + extract into ${SIDELOAD_DIR}
  sideload            Run the sideload installer
  install             Run the auto-download installer
  status              Print the install_state row

Environment:
  EMBEDDING_BITS_SIDELOAD_DIR   override sideload extract path
                                (default: ${SIDELOAD_DIR})

EOF
    exit 1
}

cmd_extract() {
    local tarball="${1:-}"
    if [[ -z "${tarball}" || ! -f "${tarball}" ]]; then
        echo "ERROR: tarball not found: ${tarball}" >&2
        exit 2
    fi

    # Verify the sidecar sha256 before extracting. The sidecar lives
    # alongside the tarball; if it's missing we refuse rather than
    # extracting unverified bytes (mirrors the installer's no-skip-
    # hash policy).
    local sidecar="${tarball}.sha256"
    if [[ ! -f "${sidecar}" ]]; then
        echo "ERROR: sidecar not found: ${sidecar}" >&2
        echo "Refusing to extract un-verified tarball." >&2
        exit 3
    fi
    echo "==> Verifying sidecar sha256"
    ( cd "$(dirname "${tarball}")" \
      && sha256sum -c "$(basename "${sidecar}")" )

    echo "==> Extracting into ${SIDELOAD_DIR}"
    mkdir -p "${SIDELOAD_DIR}"
    zstd -d "${tarball}" -c | tar -x -C "${SIDELOAD_DIR}"

    echo ""
    echo "Done. Next step:"
    echo "  $0 sideload"
    echo "  OR click 'Sideload pre-staged bits' on the AI Backends"
    echo "  config tab in the admin UI."
}

cmd_sideload() {
    if [[ ! -d "${SIDELOAD_DIR}" ]]; then
        echo "ERROR: sideload dir not found: ${SIDELOAD_DIR}" >&2
        echo "Run '$0 extract <TARBALL>' first." >&2
        exit 2
    fi
    exec email-triage embedding-bits sideload \
        --source-dir "${SIDELOAD_DIR}"
}

cmd_install() {
    exec email-triage embedding-bits install
}

cmd_status() {
    exec email-triage embedding-bits status
}

case "${1:-}" in
    extract)  shift; cmd_extract "$@" ;;
    sideload) cmd_sideload ;;
    install)  cmd_install ;;
    status)   cmd_status ;;
    *)        usage ;;
esac
