#!/usr/bin/env python3
""" drop-in spike: is `sqlcipher3-wheels` (which HAS aarch64 wheels) a
drop-in for `sqlcipher3-binary` (x86_64-only)? THROWAWAY.

Both are packagings of coleifer's `sqlcipher3` (DB-API 2.0, SQLCipher AES-256).
If sqlcipher3-wheels (a) installs as the SAME `import sqlcipher3` module,
(b) reads a DB written by sqlcipher3-binary, and (c) supports row_factory,
then the  ARM encryption blocker is a one-line pyproject/Containerfile dep
swap — no apsw, no DB-API shim, no re-encryption migration.

Run (Linux): venv-1 installs sqlcipher3-binary + writes; venv-2 installs
sqlcipher3-wheels + reads the SAME file. Faithful to db/_engine.py: raw-hex
PRAGMA key first, then WAL. Fixed key so both phases match.
"""
import sys
import sqlcipher3  # provided by whichever package is installed in this venv

_KEY = "x'" + ("ab" * 32) + "'"   # fixed 32-byte raw-hex key (64 hex chars)


def main():
    phase, path = sys.argv[1], sys.argv[2]
    print(f"[{phase}] import sqlcipher3 -> {sqlcipher3.__file__}")
    print(f"[{phase}] sqlcipher3.version={getattr(sqlcipher3, 'version', '?')} "
          f"sqlite={getattr(sqlcipher3, 'sqlite_version', '?')}")
    conn = sqlcipher3.dbapi2.connect(path)
    conn.execute(f'PRAGMA key = "{_KEY}"')      # ORDER-CRITICAL: key first
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")

    if phase == "write":
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t VALUES (?,?)",
            [(i, f"row-{i}") for i in range(20)],
        )
        conn.commit()
        print("[write] sqlcipher3-binary wrote 20 rows (SQLCipher AES format)")
    else:
        n = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        # row_factory drop-in check (the codebase uses sqlcipher3.Row).
        conn.row_factory = sqlcipher3.Row
        row = conn.execute("SELECT v FROM t WHERE id = 7").fetchone()
        ok = (n == 20 and row["v"] == "row-7")
        print(f"[read] rows={n} row['v']={row['v']!r} row_factory=OK")
        print("[read] " + ("PASS — sqlcipher3-wheels is a DROP-IN: same "
                           "`import sqlcipher3`, reads the sqlcipher3-binary "
                           "AES DB, row_factory works. ZERO migration, ZERO "
                           "codebase change." if ok else f"FAIL n={n}"))
        sys.exit(0 if ok else 1)
    conn.close()


if __name__ == "__main__":
    main()
