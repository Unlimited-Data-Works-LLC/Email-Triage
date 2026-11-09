"""email-triage deploy-time bake gate — step 3: PRAGMA + row-count parity.

Runs inside the freshly built image against the live database mounted read-only
at ``/app/data/triage.db`` and prints a JSON snapshot of four SQLCipher PRAGMAs,
the ``log_entries`` row count, and the linked SQLite version. This is the
baseline for an old-vs-new binary parity check across a rebuild, and proves the
freshly built binary can open the existing encrypted database with the
production-derived storage key.

The database is opened through the application's own connection helper
``_make_encrypted_conn`` (from ``email_triage.db._engine``) — the same opener the
running app and ``email-triage audit verify`` use — so it inherits the exact key
derivation, connect flags, and read-only-mount behaviour instead of
re-implementing (and drifting from) the open sequence.

Baked into the image via the ``Containerfile`` ``COPY`` (not bind-mounted, so it
works whether the image is built locally or from a registry pull).
"""

import json

from email_triage.config import load_config
from email_triage.db._engine import _make_encrypted_conn  # noqa: PLC2701 — deploy-time reuse of the app SSOT, not an external consumer
from email_triage.secrets import read_bootstrap_master_key


DB_PATH = "/app/data/triage.db"

cfg = load_config()
mk = read_bootstrap_master_key(cfg)
# mode=ro (N-559): the bake mounts the data dir :O since 2026-10-18, so EROFS no longer guards a
# read-write open; without read_only the RW open would copy the whole PHI DB into the upper layer.
# With it the main file is opened O_RDONLY and stays in the lower layer; an existing -wal/-shm
# (an unclean stop) is still copied up, as ciphertext, and removed with the container by --rm.
c = _make_encrypted_conn(DB_PATH, mk, read_only=True)

snap: dict[str, object] = {}

for p in ("cipher_page_size", "kdf_iter", "cipher_hmac_algorithm", "cipher_kdf_algorithm"):
    r = c.execute(f"PRAGMA {p}").fetchone()
    snap[p] = r[0] if r else None

snap["log_entries_count"] = c.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]

import sqlcipher3.dbapi2 as _d

snap["sqlite_version"] = _d.sqlite_version

print(json.dumps(snap, indent=2))
c.close()
