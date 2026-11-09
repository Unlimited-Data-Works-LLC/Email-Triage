"""email-triage deploy-time bake gate — step 1: SQLCipher cipher-version floor.

Runs inside the freshly built image and calls the application's
``assert_cipher_version_floor()`` (from ``email_triage.db._engine``), which
fails CLOSED when the linked SQLCipher is below the required minimum — the
encryption-at-rest boundary must not silently regress across a rebuild.

Baked into the image via the ``Containerfile`` ``COPY`` (not bind-mounted, so it
works whether the image is built locally or from a registry pull) and invoked by
the deploy flow right after the build. Prints the resolved cipher state as JSON.
"""

import json
import re
import sys
from pathlib import Path

from email_triage.db._engine import assert_cipher_version_floor


s = assert_cipher_version_floor()
print(json.dumps(s, indent=2))

# N-616 / punch 634 (db fix 2): the STRICT amalgamation marker, written by the
# builder's own sha256 check and COPYed --from=builder. Its content goes into the
# §164.316 bake record through this output. Absent or malformed = refuse (exit 1).
marker = Path("/app/.amalg-sha256-verified")
if not marker.is_file():
    print(f"ERROR: {marker} missing: this image did not pass the STRICT amalgamation check")
    sys.exit(1)
text = marker.read_text(encoding="utf-8")
ok_lines = [ln for ln in text.splitlines() if re.fullmatch(r"sqlite3\.[ch]: OK", ln)]
pin_line = [ln for ln in text.splitlines() if re.fullmatch(r"pin-sha256 [0-9a-f]{64}", ln)]
if len(ok_lines) != 2 or len(pin_line) != 1:
    print(f"ERROR: {marker} is malformed:\n{text}")
    sys.exit(1)
print("== amalgamation sha256 marker (/app/.amalg-sha256-verified) ==")
print(text.rstrip("\n"))
