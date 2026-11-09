"""N-432 Path-3 bake gate — step 2a: whole-file page check of the PHI DB.

Punch 631 (db fix 1, DA P2). The step-2 audit-chain walk reads only the chain
tables, and this is the deploy where the PHI cipher bytes change (SQLCipher
4.17.0 -> 4.19.0, then 4.19.0 -> 4.20.0 (punch 731)). So before the swap the NEW image also reads EVERY page:

* ``PRAGMA cipher_integrity_check`` — SQLCipher's per-page HMAC check. Clean is
  ZERO rows, judged by ``backup._cipher_check_clean`` (the one predicate).
* ``PRAGMA integrity_check`` == ``"ok"`` — the structural check, because the
  cipher check alone is necessary-not-sufficient (``backup.py`` docstring).

The bake mounts the LIVE data dir as a podman OVERLAY (``:O``, ``deploy-gates.sh``),
inside the stop window, and this step opens the DB ``mode=ro``. Not ``:ro``
(2026-10-18): after punch 636's clean stop the WAL-mode DB has no ``-wal`` and no
``-shm``, and SQLite opens a read-only WAL database only if both exist or can be
created, or the open is immutable (sqlite.org/wal.html, "Read-Only Databases").
On ``:ro`` they cannot be created and the open fails with "unable to open database
file"; on ``:O`` SQLite creates them in the container's private upper layer, which
``--rm`` discards. After an UNCLEAN stop the existing ``-wal``/``-shm`` are COPIED UP
whole into that layer instead (SQLite opens them O_RDWR even on a ``mode=ro``
handle; ciphertext on the encrypted arm). The main DB file is opened O_RDONLY and is
not copied. That the host dir (the lower layer) is not written is measured, not
assumed: ``deploy-gates.sh`` records it before and after the bake and refuses on
any difference.

This step opens the DB exactly as step 2's ``email-triage audit verify`` does:
``load_config`` -> ``_cli_stamp_db_encryption`` ->
``open_dedicated_conn_readish(config.persistence.db_path)``. It deliberately does
NOT reuse ``backup._verify_snapshot_file``: that function unlinks the -wal/-shm
sidecars in its ``finally``. On the overlay the unlink would only hide them in the
upper layer, but deleting a live -wal deletes its frames, and nothing here may
depend on the mount to prevent that. Nothing here writes or removes anything.

A non-empty ``-wal`` is not refused (punch 631 round 4, db ruling E): the
``mode=ro`` open reads its frames. Any fault row, any non-"ok" integrity result, a
plaintext DB, or ANY exception exits non-zero, which aborts the deploy before the
swap. The JSON it prints lands in the §164.316 bake record.
"""
import json
import sys
import time
from pathlib import Path

from email_triage.backup import _cipher_check_clean  # noqa: PLC2701 — the one clean-predicate (PD-5)
from email_triage.cli import _cli_stamp_db_encryption  # noqa: PLC2701 — the same stamp step 2 runs
from email_triage.config import load_config
from email_triage.db._engine import SQLCIPHER_EXPECTED_MAJOR_MINOR, open_dedicated_conn_readish

cfg = load_config()
db_path = Path(cfg.persistence.db_path)
encrypted = _cli_stamp_db_encryption(cfg)
result: dict[str, object] = {"step": "2a", "db": str(db_path), "encrypted": encrypted}

wal = Path(str(db_path) + "-wal")
wal_bytes = wal.stat().st_size if wal.exists() else 0
result["wal_bytes"] = wal_bytes
if not encrypted:
    result["ok"] = False
    result["reason"] = "the configured DB is not encrypted; the Path-3 bake expects the encrypted PHI DB"
    print(json.dumps(result, indent=2))
    sys.exit(1)
# Punch 631 round 4 (db ruling E): a non-empty -wal is NOT refused. The mode=ro
# open reads the WAL (SQLite wal.html, "Read-Only Databases"; measured on this
# build, register N-615), so integrity_check reads the LATEST version of every
# reachable page, WAL frames included, and the codec checks each one's HMAC.
# Both states reach this step: an unclean stop leaves frames, and since punch 636
# a clean stop leaves NO -wal and NO -shm (the last close checkpoints and deletes
# both; corrected 2026-10-18, the earlier "a clean stop leaves frames" was the
# pre-636 image's behaviour). With no sidecars the open works only because the
# overlay mount lets SQLite create them (module docstring). The size is
# recorded; when frames exist, the connection must be in WAL mode (below).

t0 = time.monotonic()
conn = open_dedicated_conn_readish(str(db_path))
try:
    # db F1: prove THIS connection is SQLCipher on the expected line before
    # trusting a zero-row cipher_integrity_check (stdlib sqlite3 returns []
    # for that pragma too). The line comes from the SSOT in db/_engine.py.
    row = conn.execute("PRAGMA cipher_version").fetchone()
    cipher_version = str(row[0]) if row and row[0] else ""
    jm = conn.execute("PRAGMA journal_mode").fetchone()
    journal_mode = str(jm[0]).lower() if jm and jm[0] else ""
    faults = conn.execute("PRAGMA cipher_integrity_check").fetchall()
    t1 = time.monotonic()
    integrity = conn.execute("PRAGMA integrity_check").fetchall()
    t2 = time.monotonic()
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
finally:
    conn.close()

expected_line = ".".join(str(x) for x in SQLCIPHER_EXPECTED_MAJOR_MINOR) + "."
cipher_line_ok = bool(cipher_version) and cipher_version.split()[0].startswith(expected_line)
cipher_clean = _cipher_check_clean(faults)
integrity_ok = len(integrity) == 1 and integrity[0][0] == "ok"
# db fix B: frames in the -wal are only covered when this connection reads them.
wal_mode_ok = wal_bytes == 0 or journal_mode == "wal"
result.update({
    "cipher_version": cipher_version,
    "expected_line": expected_line + "x",
    "journal_mode": journal_mode,
    "page_count": pages,
    "cipher_integrity_check_rows": len(faults),
    "cipher_integrity_check_sample": [list(r) for r in faults[:3]],
    "integrity_check": [r[0] for r in integrity[:3]],
    "cipher_integrity_check_s": round(t1 - t0, 3),
    "integrity_check_s": round(t2 - t1, 3),
    "ok": cipher_line_ok and cipher_clean and integrity_ok and wal_mode_ok,
})
print(json.dumps(result, indent=2))
sys.exit(0 if result["ok"] else 1)
