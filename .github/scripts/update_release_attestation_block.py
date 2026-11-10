#!/usr/bin/env python3
"""Update the operator-attestation block inside a GitHub Release body.

Reads the existing Release body on stdin, prints the updated body on
stdout. Inputs come from env vars set by the calling workflow step:

    INPUT_TAG, INPUT_HIPAA_SAFE, INPUT_NOTES,
    ACTOR, VALIDATED_AT, IMAGE_DIGEST, ATTESTATION_RUN_URL.

Idempotent: a managed block (bracketed by the HTML-comment markers
below) is replaced in place. Re-running the workflow against the same
tag updates the footer rather than appending another copy.

Lives in .github/scripts/ rather than inline in the workflow YAML so
multi-line markdown templates don't fight YAML block-scalar parsing.
"""

from __future__ import annotations

import os
import re
import sys

MARKER_START = "<!-- operator-attestation:start -->"
MARKER_END = "<!-- operator-attestation:end -->"
MANAGED_BLOCK = re.compile(
    re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END),
    re.DOTALL,
)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        # Hard fail. The workflow always sets these; an empty value
        # means the env wiring broke.
        raise SystemExit(f"missing required env var: {name}")
    return value


def render_block() -> str:
    hipaa_safe_raw = os.environ.get("INPUT_HIPAA_SAFE", "false").lower()
    hipaa_label = "yes" if hipaa_safe_raw == "true" else "no"
    notes = os.environ.get("INPUT_NOTES", "")
    actor = _required("ACTOR")
    validated_at = _required("VALIDATED_AT")
    image_digest = _required("IMAGE_DIGEST")
    attest_url = _required("ATTESTATION_RUN_URL")

    lines = [
        MARKER_START,
        "**Operator-attested**",
        "",
        f"- HIPAA-safe: `{hipaa_label}`",
        f"- Validated by: `{actor}`",
        f"- Validated at: `{validated_at}`",
        f"- Image digest: `{image_digest}`",
        f"- Attestation run: {attest_url}",
    ]
    if notes:
        lines.append(f"> Notes: {notes}")
    lines.append("")
    lines.append("Verify with cosign — see `docs/release-process.md`.")
    lines.append(MARKER_END)
    return "\n".join(lines)


def main() -> int:
    current = sys.stdin.read()
    block = render_block()
    if MANAGED_BLOCK.search(current):
        updated = MANAGED_BLOCK.sub(block, current)
    elif current.strip():
        updated = current.rstrip() + "\n\n" + block + "\n"
    else:
        updated = block + "\n"
    sys.stdout.write(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
