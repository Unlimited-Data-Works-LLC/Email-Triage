#!/usr/bin/env python3
"""STAGE-0 VALIDATION SPIKE for  (ARM64 / apsw-sqlite3mc backend swap).

THROWAWAY spike — NOT production code. Run it, read the verdict, delete it
(or keep under scripts/ as the reproducible Stage-0 gate). It answers the
TWO operator-gating questions before any `db/_engine.py` change is made:

  (A) CIPHER COMPAT — can apsw-sqlite3mc (SQLite3 Multiple Ciphers, the only
      driver with an aarch64 wheel) OPEN + READ a database written by the
      current sqlcipher3-binary backend, BYTE-FOR-BYTE unchanged? And the
      reverse? If NO, the existing encrypted PROD DB would be unreadable
      after the swap → the whole single-backend plan changes.

  (B) WRITE-PATH PERF — is apsw-sqlite3mc's encrypted WRITE throughput
      >= sqlcipher3's, on BOTH (i) one-big-commit bulk and (ii) the
      per-row-commit / per-statement-fsync pattern that the audit handler
      uses (flush_interval=1) and that triggered the 2026-05-31 SQLCipher
      WAL lock-storm? The operator's hard condition: do NOT regress the
      already-sensitive DB write path.

ENVIRONMENT: Linux/x86_64 with BOTH drivers installed. The wheels are
Linux-only (sqlcipher3-binary has no Windows wheel), so this CANNOT run on
the Windows dev box — run it on a Linux host / throwaway container:

    pip install "sqlcipher3-binary>=0.5.4,<0.6" "apsw-sqlite3mc>=3.53"
    python scripts/spike_apsw_compat_perf.py

NO PROD DATA — the spike creates its own throwaway DBs in a tempdir and
deletes them. Faithful to db/_engine.py: raw-hex key form (x'<64hex>',
bypasses PBKDF2), PRAGMA key FIRST, then journal_mode=WAL /
busy_timeout=30000 / foreign_keys=ON. apsw-sqlite3mc opens SQLCipher-4
DBs via: PRAGMA cipher='sqlcipher'; PRAGMA legacy=4; PRAGMA key=...
(order per utelle.github.io/SQLite3MultipleCiphers SQL-pragmas doc).
"""

from __future__ import annotations

import os
import secrets as _secrets
import sys
import tempfile
import time

# 32-byte raw key rendered exactly as db/_engine.format_raw_hex_key does.
_KEY = _secrets.token_bytes(32)
_HEXKEY = f"x'{_KEY.hex()}'"

ROWS_BULK = 20_000        # one-commit bulk insert
ROWS_PERCOMMIT = 5_000    # per-row commit (audit-handler / flush_interval=1 shape)


# --------------------------------------------------------------------------
# Driver openers — each returns a DB-API-ish connection + an exec/commit shim
# --------------------------------------------------------------------------

def open_sqlcipher3(path: str):
    import sqlcipher3
    conn = sqlcipher3.dbapi2.connect(path, cached_statements=0)
    # ORDER-CRITICAL: PRAGMA key first (matches _make_encrypted_conn).
    conn.execute(f'PRAGMA key = "{_HEXKEY}"')
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def open_apsw_mc(path: str):
    """apsw-sqlite3mc in SQLCipher-v4-COMPAT mode (AES-256-CBC + HMAC) — reads
    the CURRENT prod format with zero re-encryption (the conservative path)."""
    import apsw  # apsw-sqlite3mc provides the apsw module w/ sqlite3mc built in
    conn = apsw.Connection(path)
    cur = conn.cursor()
    # sqlite3mc SQLCipher-v4 compat: cipher + legacy BEFORE key, key before any SQL.
    cur.execute("PRAGMA cipher='sqlcipher'")
    cur.execute("PRAGMA legacy=4")
    cur.execute(f'PRAGMA key = "{_HEXKEY}"')
    cur.execute("PRAGMA journal_mode = WAL")
    cur.execute("PRAGMA busy_timeout = 30000")
    cur.execute("PRAGMA foreign_keys = ON")
    return conn


def open_apsw_native(path: str):
    """apsw-sqlite3mc in its NATIVE format — default cipher = ChaCha20-Poly1305
    (sqleet scheme). NO cipher/legacy pragmas → sqlite3mc's own format. This is
    NOT cross-readable by sqlcipher3 and requires a one-time RE-ENCRYPTION
    migration of the existing prod DB. Faster on non-AES-NI (ARM); on x86_64
    with AES-NI the AES path may match or beat it."""
    import apsw
    conn = apsw.Connection(path)
    cur = conn.cursor()
    # No cipher select → sqlite3mc default (chacha20). Raw-hex key, key-first.
    cur.execute(f'PRAGMA key = "{_HEXKEY}"')
    cur.execute("PRAGMA journal_mode = WAL")
    cur.execute("PRAGMA busy_timeout = 30000")
    cur.execute("PRAGMA foreign_keys = ON")
    return conn


def _exec(conn, sql, params=()):
    """Uniform exec across DB-API (sqlcipher3) + apsw."""
    if hasattr(conn, "cursor") and "apsw" in type(conn).__module__:
        conn.cursor().execute(sql, params)
    else:
        conn.execute(sql, params)


def _commit(conn):
    if "apsw" in type(conn).__module__:
        pass  # apsw autocommits unless in an explicit BEGIN; handled by caller
    else:
        conn.commit()


def _rows(conn, sql):
    if "apsw" in type(conn).__module__:
        return list(conn.cursor().execute(sql))
    return list(conn.execute(sql))


# --------------------------------------------------------------------------
# (A) Cross-driver cipher compatibility
# --------------------------------------------------------------------------

def _write_table(opener, path, n):
    conn = opener(path)
    is_apsw = "apsw" in type(conn).__module__
    if is_apsw:
        c = conn.cursor()
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        c.execute("BEGIN")
        for i in range(n):
            c.execute("INSERT INTO t (id, v) VALUES (?, ?)", (i, f"row-{i}"))
        c.execute("COMMIT")
    else:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t (id, v) VALUES (?, ?)",
            [(i, f"row-{i}") for i in range(n)],
        )
        conn.commit()
    conn.close()


def _read_count_and_sample(opener, path):
    conn = opener(path)
    cnt = _rows(conn, "SELECT COUNT(*) FROM t")[0][0]
    sample = _rows(conn, "SELECT v FROM t WHERE id = 7")[0][0]
    conn.close()
    return cnt, sample


def compat_check(tmp):
    results = {}
    # sqlcipher3 writes → apsw-sqlite3mc reads
    p1 = os.path.join(tmp, "by_sqlcipher3.db")
    _write_table(open_sqlcipher3, p1, 50)
    try:
        cnt, sample = _read_count_and_sample(open_apsw_mc, p1)
        results["sqlcipher3_write__apsw_read"] = (
            "PASS" if (cnt == 50 and sample == "row-7") else f"FAIL cnt={cnt} sample={sample!r}"
        )
    except Exception as e:  # noqa: BLE001
        results["sqlcipher3_write__apsw_read"] = f"FAIL exc={type(e).__name__}: {e}"
    # apsw-sqlite3mc writes → sqlcipher3 reads (reverse direction)
    p2 = os.path.join(tmp, "by_apsw.db")
    _write_table(open_apsw_mc, p2, 50)
    try:
        cnt, sample = _read_count_and_sample(open_sqlcipher3, p2)
        results["apsw_write__sqlcipher3_read"] = (
            "PASS" if (cnt == 50 and sample == "row-7") else f"FAIL cnt={cnt} sample={sample!r}"
        )
    except Exception as e:  # noqa: BLE001
        results["apsw_write__sqlcipher3_read"] = f"FAIL exc={type(e).__name__}: {e}"
    return results


# --------------------------------------------------------------------------
# (B) Write-path performance
# --------------------------------------------------------------------------

def _bench_bulk(opener, path, n):
    conn = opener(path)
    is_apsw = "apsw" in type(conn).__module__
    if is_apsw:
        c = conn.cursor()
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, blob BLOB)")
    else:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, blob BLOB)")
    payload = os.urandom(256)  # ~ a small embedding-ish blob
    t0 = time.perf_counter()
    if is_apsw:
        c.execute("BEGIN")
        for i in range(n):
            c.execute("INSERT INTO t VALUES (?,?,?)", (i, f"row-{i}", payload))
        c.execute("COMMIT")
    else:
        conn.executemany(
            "INSERT INTO t VALUES (?,?,?)",
            [(i, f"row-{i}", payload) for i in range(n)],
        )
        conn.commit()
    dt = time.perf_counter() - t0
    conn.close()
    return dt


def _bench_percommit(opener, path, n):
    """Per-row commit = the audit-handler flush_interval=1 fsync pattern
    that triggered the 2026-05-31 SQLCipher WAL lock-storm. THE sensitive path."""
    conn = opener(path)
    is_apsw = "apsw" in type(conn).__module__
    if is_apsw:
        c = conn.cursor()
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, blob BLOB)")
    else:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, blob BLOB)")
    payload = os.urandom(256)
    t0 = time.perf_counter()
    for i in range(n):
        if is_apsw:
            # apsw autocommits a bare statement (its own txn + fsync per stmt)
            c.execute("INSERT INTO t VALUES (?,?,?)", (i, f"row-{i}", payload))
        else:
            conn.execute("INSERT INTO t VALUES (?,?,?)", (i, f"row-{i}", payload))
            conn.commit()
    dt = time.perf_counter() - t0
    conn.close()
    return dt


def _best_of(fn, opener, tmp, tag, n, runs=3):
    """Min wall-time over `runs` (least-noisy lower bound)."""
    best = None
    for r in range(runs):
        dt = fn(opener, os.path.join(tmp, f"{tag}_r{r}.db"), n)
        best = dt if best is None else min(best, dt)
    return best


def perf_check(tmp):
    out = {}
    openers = (
        ("sqlcipher3_AES", open_sqlcipher3),         # current engine, current format
        ("apsw_compat_AES", open_apsw_mc),           # new engine, CURRENT (SQLCipher) format
        ("apsw_native_chacha20", open_apsw_native),  # new engine, NATIVE format (needs migration)
    )
    for label, opener in openers:
        bulk = _best_of(_bench_bulk, opener, tmp, f"bulk_{label}", ROWS_BULK)
        pc = _best_of(_bench_percommit, opener, tmp, f"pc_{label}", ROWS_PERCOMMIT)
        out[label] = {
            "bulk_s": round(bulk, 4),
            "bulk_rows_per_s": int(ROWS_BULK / bulk) if bulk else 0,
            "percommit_s": round(pc, 4),
            "percommit_rows_per_s": int(ROWS_PERCOMMIT / pc) if pc else 0,
        }
    return out


def main():
    print("=" * 68)
    print("STAGE-0 SPIKE: apsw-sqlite3mc vs sqlcipher3 — compat + write perf")
    print("")
    print("=" * 68)
    try:
        import sqlcipher3  # noqa: F401
        import apsw  # noqa: F401
        print(f"apsw {apsw.apswversion()} / sqlite {apsw.sqlitelibversion()}")
    except Exception as e:  # noqa: BLE001
        print(f"\nMISSING DRIVER: {type(e).__name__}: {e}")
        print("Install on a LINUX host: pip install "
              "'sqlcipher3-binary>=0.5.4,<0.6' 'apsw-sqlite3mc>=3.53'")
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        print("\n--- (A) CROSS-DRIVER CIPHER COMPAT (SQLCipher v4, raw-hex key) ---")
        compat = compat_check(tmp)
        for k, v in compat.items():
            print(f"  {k:32s} : {v}")

        print("\n--- (B) ENCRYPTED WRITE-PATH PERF (best of 3 runs) ---")
        perf = perf_check(tmp)
        for label, m in perf.items():
            print(f"  {label:22s} bulk={m['bulk_s']}s ({m['bulk_rows_per_s']}/s)  "
                  f"per-commit={m['percommit_s']}s ({m['percommit_rows_per_s']}/s)")
        cur_ = perf["sqlcipher3_AES"]
        cmp_ = perf["apsw_compat_AES"]
        nat = perf["apsw_native_chacha20"]

        def _ratios(a, b, name):
            if b["bulk_s"] and b["percommit_s"]:
                print(f"  {name:36s} bulk={a['bulk_s']/b['bulk_s']:.2f}x  "
                      f"per-commit={a['percommit_s']/b['percommit_s']:.2f}x")
        print("\n  RATIOS (lower = first faster; <1.00 = first is faster):")
        print("  >>> THE OPERATOR'S QUESTION = native-format vs current-format:")
        _ratios(nat, cmp_, "  native(chacha20) / compat(AES)")
        _ratios(cmp_, cur_, "  apsw-compat(AES) / sqlcipher3(AES)")
        _ratios(nat, cur_, "  native(chacha20) / sqlcipher3(AES)")

    print("\n--- VERDICT (operator gates) ---")
    compat_ok = all(v == "PASS" for v in compat.values())
    print(f"  (A) cipher compat (both directions): "
          f"{'PASS — prod DB readable after swap' if compat_ok else 'FAIL — see above'}")
    print(f"  (B) write perf: per-commit is the sensitive path (audit handler).")
    print("  *** AES-NI CAVEAT: this host (x86_64) has AES-NI, so AES-256-CBC is")
    print("      HW-accelerated — native(chacha20) may look NEUTRAL or even SLOWER")
    print("      here. The native-format win is an ARM-WITHOUT-AES-NI phenomenon")
    print("      (the DGX Spark), which CANNOT be measured on this host. So if")
    print("      native<=compat on x86_64, the ARM gap is only WIDER in native's")
    print("      favor; if native is slower here, that does NOT rule it out for ARM.")
    print("  NOTE: relative numbers only (same host). native format ALSO needs a")
    print("      one-time prod re-encryption migration (not cross-readable w/ AES).")
    return 0 if compat_ok else 1


if __name__ == "__main__":
    sys.exit(main())
