"""N-432 Path-3 bake gate — step 3: PRAGMA parity + row-count snapshot.

Runs inside the freshly-built email-triage image against the live PHI DB
mounted read-only at ``/app/data/triage.db`` and prints a JSON snapshot of
four SQLCipher PRAGMAs + the ``log_entries`` row count + the linked SQLite
version. Baseline data for the OLD-vs-NEW binary parity comparison per
HIPAA MF-1(a) row-count parity, and the encryption-boundary evidence that
the freshly built binary can actually open the live PHI DB with the
production-derived storage key.

Baked into the image via ``Containerfile`` COPY (alongside step 1's file
at ~line 309) — NOT bind-mounted from ``/tmp/et-deploy/scripts``. A
bind-mount would silently break ``--from-registry`` mode because the
``git archive HEAD | tar -x`` staging step is skipped there
(deploy.sh:242-249). Baking works in BOTH build modes.

Uses the SSOT connection opener ``_make_encrypted_conn`` from
``email_triage.db._engine`` — the same private (leading-underscore) opener
the running app + ``email-triage audit verify`` step 2 use. Reusing it
inherits the exact PRAGMA key + connect-flag + read-only-mount behaviour
that step 2 has already proven works, instead of re-implementing (and,
as the 2026-07-21 deploy proved, drifting from) the open sequence in a
side-copy. Private opener import is deliberate — this is deploy-time
tooling INSIDE the same distribution, not an external consumer; the
alternative was three consecutive latent bugs in the hand-rolled path
(SyntaxError, ImportError, ``unable to open database file``).

Fold history (2026-07-21 same-drive):
    4983ebb4 - heredoc -> file (Python parses, but stale import)
    f5199f3d - derive_sqlcipher_storage_key -> derive_storage_key (real
                symbol resolves, but raw d.connect on RO mount fails)
    THIS    - _make_encrypted_conn SSOT (proven working via step 2)
"""

import json

from email_triage.config import load_config
from email_triage.db._engine import _make_encrypted_conn  # noqa: PLC2701 — deploy-time reuse of the app SSOT, not an external consumer
from email_triage.secrets import read_bootstrap_master_key


DB_PATH = "/app/data/triage.db"

cfg = load_config()
mk = read_bootstrap_master_key(cfg)
c = _make_encrypted_conn(DB_PATH, mk)

snap: dict[str, object] = {}

for p in ("cipher_page_size", "kdf_iter", "cipher_hmac_algorithm", "cipher_kdf_algorithm"):
    r = c.execute(f"PRAGMA {p}").fetchone()
    snap[p] = r[0] if r else None

snap["log_entries_count"] = c.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]

import sqlcipher3.dbapi2 as _d

snap["sqlite_version"] = _d.sqlite_version

print(json.dumps(snap, indent=2))
c.close()
