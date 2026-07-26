"""N-432 Path-3 bake gate — step 1: cipher_version floor probe.

Runs inside the freshly-built email-triage image and invokes the SSOT
`assert_cipher_version_floor()` from `email_triage.db._engine`. Fail-CLOSED
on SQLCipher < 4.14 (§164.312(a)(2)(iv) encryption-boundary regression).

Extracted from `scripts/deploy.sh` inline heredoc alongside step 3's
extraction (2026-07-21) to establish a single deploy-time SSOT: bake-gate
Python source lives in `scripts/n432-path3-bake-step*.py` files, never in
inline `python -c` heredocs — the syntax-error class that broke step 3 in
prod cannot re-emerge for step 1 either (Prime Directive #1 of the project
style guide: every SSOT ships its structural pin same-change; here the pin
is *shape* — no inline heredocs — enforced by grep-shape absence in the
bake-gate block).

The file is baked into the image via `Containerfile` COPY (alongside the
existing `scripts/embedding-bits-manifest.json` COPY at ~line 309). No
bind-mount — a bind-mount would silently break `--from-registry` mode
(which skips the `git archive HEAD | tar -x` staging step around
deploy.sh:242-249). Baking into the image works in BOTH build modes.
"""

import json

from email_triage.db._engine import assert_cipher_version_floor


s = assert_cipher_version_floor()
print(json.dumps(s, indent=2))
