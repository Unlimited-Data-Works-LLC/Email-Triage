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

from email_triage.db._engine import assert_cipher_version_floor


s = assert_cipher_version_floor()
print(json.dumps(s, indent=2))
