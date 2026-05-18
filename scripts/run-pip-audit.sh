#!/usr/bin/env bash
#
# scripts/run-pip-audit.sh — canonical pip-audit invocation.
#
# Used by:
#   - .github/workflows/security.yml (CI gate on every push to main)
#   - .githooks/pre-push (local guard so CVEs don't ship to main)
#
# Both surfaces share this script so a single waiver list applies
# everywhere. Add new waivers ONLY after review and document the
# reason inline.
set -euo pipefail

#
# Waiver list — CVE id, why, expected resolution.
#
# CVE-2026-3219 (pip itself, 26.0.1)
#   GitHub Actions' setup-python ships pip 26.0.1; no fix version
#   listed by the advisory yet. Pip is a build-time tool, not a
#   runtime dep of email-triage, so this does not impact the
#   container image. Revisit when pip ships a patched release.
WAIVERS=(
    "--ignore-vuln=CVE-2026-3219"
)

# --skip-editable: project is private, not on PyPI; pip-audit
# would emit "couldn't resolve editable install" without this.
exec pip-audit --skip-editable "${WAIVERS[@]}" "$@"
