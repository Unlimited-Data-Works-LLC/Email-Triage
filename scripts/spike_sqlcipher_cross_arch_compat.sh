#!/usr/bin/env bash
#
#  multi-arch — cross-arch / cross-version SQLCipher on-disk FORMAT-COMPAT proof.
#
# WHY: the  ARM64 plan installs SQLCipher differently per arch (x86_64 =
# prebuilt `sqlcipher3-binary` wheel; aarch64 = source-built `sqlcipher3==0.6.2`,
# vendored static SQLCipher 4.x). The one HIGH risk is whether a PHI DB written
# by one opens UNCHANGED under the other. The on-disk format is arch-NEUTRAL (it
# is the SQLCipher version's cipher params, not the CPU), so the cross-VERSION
# proof on a single arch is the load-bearing check; the cross-ARCH leg (step C)
# additionally exercises the actual arm64 binary when a working aarch64 runtime
# is available.
#
# This reproduces the proof using the PROD cipher parameters (db/_engine.py):
#   * raw-hex KDF-bypass key:  PRAGMA key = "x'<64-hex>'"   (format_raw_hex_key)
#   * WAL journal mode
#   * SQLCipher 4.x default cipher_compatibility=4 (AES-256-CBC + HMAC-SHA512,
#     PBKDF2-HMAC-SHA512 @ 256000, page 4096) — set explicitly here as a guard.
#
# RECORDED RESULT (the deploy host, 2026-06-13, gate wz2x7gy2o + SME panel re-run):
#   [A] x86_64 sqlcipher3-binary  -> SQLCipher 4.6.0  : wrote encrypted DB, header ciphertext
#   [B] x86_64 source sqlcipher3 0.6.2 -> SQLCipher 4.12.0 : opened it (raw-hex+WAL), read PHI row -> FORMAT-COMPAT-OK
#   [C] aarch64 source build (under emulation): DEFERRED — the deploy host qemu-user segfaults on the arm64
#       image (host limitation, NOT a Containerfile defect); authoritative arm64 validation is the
#       GHA multi-arch CI (the Containerfile runtime `import sqlcipher3` smoke makes a GREEN build
#       prove the binding loads), and native-hardware validation is deferred to the DGX Spark.
#
# REPRODUCE on a container host (the deploy host): bash scripts/spike_sqlcipher_cross_arch_compat.sh
#   (set RUN_ARM64=1 once a working aarch64 emulation / native host exists to enable step C).
set -uo pipefail
KEY="2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe"   # NON-secret test key
WORK="${WORK:-/tmp/et36-compat}"; rm -rf "$WORK"; mkdir -p "$WORK"
PODMAN="${PODMAN:-sudo podman}"

WRITE_PY='
import sqlcipher3
KEY="'"$KEY"'"
c=sqlcipher3.dbapi2.connect("/shared/test.db")
c.execute("PRAGMA key = \"x\x27%s\x27\"" % KEY)
c.execute("PRAGMA cipher_compatibility = 4")
c.execute("PRAGMA journal_mode = WAL")
print("WRITE cipher_version", c.execute("PRAGMA cipher_version").fetchone(),
      "journal", c.execute("PRAGMA journal_mode").fetchone())
c.execute("CREATE TABLE phi(id INTEGER, note TEXT)")
c.execute("INSERT INTO phi VALUES (1, ?)", ("patient-zero-secret-NOTE",))
c.commit(); c.close(); print("WROTE")
'
READ_PY='
import sqlcipher3, platform
KEY="'"$KEY"'"
print("OPEN arch", platform.machine(), "cipher",
      sqlcipher3.dbapi2.connect(":memory:").execute("PRAGMA cipher_version").fetchone())
c=sqlcipher3.dbapi2.connect("/shared/test.db")
c.execute("PRAGMA key = \"x\x27%s\x27\"" % KEY)
c.execute("PRAGMA cipher_compatibility = 4")
c.execute("PRAGMA journal_mode = WAL")
row=c.execute("SELECT note FROM phi WHERE id=1").fetchone()
assert row and row[0]=="patient-zero-secret-NOTE", repr(row)
print("FORMAT-COMPAT-OK", row[0]); c.close()
'

echo "=== [A] x86_64 sqlcipher3-binary writes encrypted PHI DB (raw-hex + WAL) ==="
$PODMAN run --rm --platform linux/amd64 -v "$WORK":/shared:z python:3.12-slim bash -c '
  set -e; pip install --no-cache-dir "sqlcipher3-binary>=0.5.4,<0.6" >/tmp/pa.log 2>&1 || { tail -20 /tmp/pa.log; exit 1; }
  python - <<PY
'"$WRITE_PY"'
PY'
echo "stepA rc=$?"
head -c 16 "$WORK/test.db" | grep -q "SQLite format 3" && { echo "FAIL plaintext header"; exit 5; } || echo "header ciphertext OK"

echo "=== [B] x86_64 SOURCE-built sqlcipher3 0.6.2 opens it (cross-version, raw-hex + WAL) ==="
$PODMAN run --rm --platform linux/amd64 -v "$WORK":/shared:z python:3.12-slim bash -c '
  set -e
  apt-get update >/tmp/ab.log 2>&1 && apt-get install -y --no-install-recommends gcc libssl-dev python3-dev >>/tmp/ab.log 2>&1
  pip install --no-cache-dir --no-binary sqlcipher3 "sqlcipher3==0.6.2" >/tmp/pb.log 2>&1 || { echo PIPFAIL; tail -40 /tmp/pb.log; exit 2; }
  python - <<PY
'"$READ_PY"'
PY'
echo "stepB rc=$?"

if [ "${RUN_ARM64:-0}" = "1" ]; then
  echo "=== [C] aarch64 source build opens the x86_64-written DB (needs working arm64 emulation/native) ==="
  $PODMAN run --rm --privileged docker.io/tonistiigi/binfmt --install arm64 2>&1 | tail -2
  $PODMAN run --rm --platform linux/arm64 -v "$WORK":/shared:z python:3.12-slim bash -c '
    set -e
    apt-get update >/tmp/ac.log 2>&1 && apt-get install -y --no-install-recommends gcc libssl-dev python3-dev >>/tmp/ac.log 2>&1
    pip install --no-cache-dir --no-binary sqlcipher3 "sqlcipher3==0.6.2" >/tmp/pc.log 2>&1 || { echo PIPFAIL; tail -40 /tmp/pc.log; exit 2; }
    python - <<PY
'"$READ_PY"'
PY'
  echo "stepC rc=$?"
else
  echo "=== [C] aarch64 leg SKIPPED (set RUN_ARM64=1 on a working arm64 host) ==="
fi
echo "=== DONE ==="
