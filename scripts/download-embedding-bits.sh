#!/usr/bin/env bash
#
# Operator runs this on a CONNECTED machine before shipping the
# air-gap tarball to the target host. Downloads every file listed
# in scripts/embedding-bits-manifest.json, verifies each against
# the manifest hash, and packages the result into a zstd tarball
# the target can sideload.
#
# Usage:
#   ./scripts/download-embedding-bits.sh [OUTPUT_TARBALL]
#
# Default OUTPUT_TARBALL: ./embedding-bits-v0.1.x.tar.zst (in CWD)
#
# Output:
#   * <OUTPUT_TARBALL>          — zstd-compressed tar of the staged
#                                 bits (wheels/ + hf-cache/)
#   * <OUTPUT_TARBALL>.sha256   — companion file (sha256 of the
#                                 tarball, for the operator to
#                                 verify against on the target)
#
# What gets staged:
#   <staging>/wheels/                      torch + sentence-
#                                          transformers wheels +
#                                          transitives
#   <staging>/hf-cache/<hf_cache_dir>/    one subtree per manifest
#                                          'models' entry (e.g.
#                                          sentence-transformers_all-
#                                          MiniLM-L6-v2/, intfloat_
#                                          multilingual-e5-base/)
#
# Sideload path on the target (inside the container or with shell
# access to /app/data/runtime-deps):
#   1. Copy <OUTPUT_TARBALL> + .sha256 to the target.
#   2. Verify: sha256sum -c <OUTPUT_TARBALL>.sha256
#   3. Extract: zstd -d <OUTPUT_TARBALL> -c | tar -x -C \
#        /app/data/runtime-deps/sideload
#   4. Trigger via the admin UI ("Sideload pre-staged bits" button
#      on AI Backends config tab) OR via CLI:
#        email-triage embedding-bits sideload --source-dir \
#          /app/data/runtime-deps/sideload
#
# The installer hash-verifies every file against the manifest the
# IMAGE was built against — operator-staged files that drift trip
# the same HashMismatch refusal as a poisoned PyPI mirror.

set -euo pipefail

# --- arg parsing ---
OUTPUT_TARBALL="${1:-./embedding-bits-v0.1.x.tar.zst}"

# Resolve script-relative paths so the script works from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST="${REPO_ROOT}/scripts/embedding-bits-manifest.json"

if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: manifest not found: ${MANIFEST}" >&2
    exit 2
fi

# --- staging dir (deterministic so re-runs are resumable) ---
STAGING="${EMBEDDING_BITS_STAGING:-${HOME}/.cache/email-triage-embedding-bits}"
mkdir -p "${STAGING}/wheels"
# Per-model hf-cache subdirs are created in the mirror step below (one
# per manifest 'models' entry); just create the shared parent here.
mkdir -p "${STAGING}/hf-cache"

echo "Staging dir: ${STAGING}"
echo "Manifest:    ${MANIFEST}"

# --- download via the Python builder (reuses streaming hash logic) ---
# We invoke the manifest builder in --dry-run mode against a per-
# file cache so the wheels + model files end up in <STAGING>/<file>.
# The builder is the single source of truth for hash verification.
echo ""
echo "==> Downloading + verifying via build-embedding-bits-manifest.py"
python3 "${SCRIPT_DIR}/build-embedding-bits-manifest.py" \
    --output "${MANIFEST}" \
    --cache-dir "${STAGING}/.builder-cache" \
    --dry-run

# The builder cache lays files flat by filename. Mirror them into
# the wheels/ + hf-cache/ structure the installer expects.
echo ""
echo "==> Mirroring into wheels/ + hf-cache/ layout"
python3 - <<PYEOF
import json
import shutil
from pathlib import Path

manifest = json.loads(Path("${MANIFEST}").read_text(encoding="utf-8"))
cache = Path("${STAGING}/.builder-cache")
out_wheels = Path("${STAGING}/wheels")
out_hf_root = Path("${STAGING}/hf-cache")

for w in manifest.get("wheels", []):
    src = cache / w["filename"]
    dst = out_wheels / w["filename"]
    if not src.exists():
        raise SystemExit(f"Missing in cache: {src}")
    if not dst.exists() or dst.stat().st_size != src.stat().st_size:
        shutil.copy2(src, dst)

hf_files = 0
for m in manifest.get("models", []):
    # Each model lands under its own hf_cache_dir/ — the layout the
    # installer's per-model verify/stage loops expect. A single shared
    # dir would collide two models' files.
    out_hf = out_hf_root / m["hf_cache_dir"]
    for f in m.get("files", []):
        # model files: cache layout flattens '/' to '_'; we restore
        # the original layout under each model's hf_cache_dir/
        flat = f["name"].replace("/", "_")
        src = cache / m["name"] / flat
        dst = out_hf / f["name"]
        if not src.exists():
            raise SystemExit(f"Missing in cache: {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists() or dst.stat().st_size != src.stat().st_size:
            shutil.copy2(src, dst)
        hf_files += 1

print(f"Staged {len(list(out_wheels.iterdir()))} wheels + "
      f"{hf_files} model files")
PYEOF

# --- package into a zstd tarball ---
echo ""
echo "==> Packaging into ${OUTPUT_TARBALL}"
# tar with zstd compression. -I "zstd -19" picks the high-compression
# setting that's tuned for one-shot archive (vs the default which
# trades compression for speed). The bits are decompressed once on
# the target so the time-up-front cost is OK.
tar -I "zstd -19 -T0" \
    -cf "${OUTPUT_TARBALL}" \
    -C "${STAGING}" \
    wheels hf-cache

# --- sidecar sha256 for operator-side verification ---
echo ""
echo "==> Computing sha256 sidecar"
( cd "$(dirname "${OUTPUT_TARBALL}")" \
  && sha256sum "$(basename "${OUTPUT_TARBALL}")" \
     > "${OUTPUT_TARBALL}.sha256" )

# --- summary ---
TARBALL_BYTES=$(stat -c%s "${OUTPUT_TARBALL}" 2>/dev/null \
              || stat -f%z "${OUTPUT_TARBALL}")
echo ""
echo "Done."
echo "  Tarball:        ${OUTPUT_TARBALL}"
echo "  Size:           $(printf %\\047d ${TARBALL_BYTES}) bytes"
echo "  Sha256 sidecar: ${OUTPUT_TARBALL}.sha256"
echo ""
echo "Copy both files to the target host. On the target:"
echo "  sha256sum -c ${OUTPUT_TARBALL}.sha256"
echo "  mkdir -p /app/data/runtime-deps/sideload"
echo "  zstd -d ${OUTPUT_TARBALL} -c \\"
echo "    | tar -x -C /app/data/runtime-deps/sideload"
echo "  # Then click 'Sideload pre-staged bits' on AI Backends tab"
echo "  # OR: email-triage embedding-bits sideload \\"
echo "  #       --source-dir /app/data/runtime-deps/sideload"
