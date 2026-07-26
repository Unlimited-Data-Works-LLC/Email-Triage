#!/usr/bin/env bash
# db-backup-relocate.sh — host-side relocation of verified encrypted DB
# snapshots to the SMB share (punch  phase 3).
#
# The in-app sweeper writes verified, integrity-checked SQLCipher snapshots to a
# LOCAL container-volume staging dir; this host-side job copies them onto the SMB
# share. The network share is therefore NEVER bind-mounted into the HIPAA
# container (the operator-chosen posture).
#
# FAIL-CLOSED, because a silently-failing backup is worse than none:
#   * refuse if the share target is not an actual mountpoint (else a copy lands
#     on the local-disk mountpoint dir = false backup + root-fill);
#   * refuse if the target is not writable or lacks 2x-largest-snapshot space;
#   * verify each file's sha256 ON THE SHARE after copy (catch a torn copy);
#   * write via .partial then atomic rename; relocate the marker LAST;
#   * prune the share to keep-N by the EMBEDDED filename timestamp (never mtime).
#
# Config via env (an EnvironmentFile in the systemd unit supplies these):
#   ET_BACKUP_SRC_DIR   host path of the container's <data_dir>/backups volume
#   ET_BACKUP_SMB_DIR   the SMB share target dir (must be a mountpoint)
#   ET_BACKUP_KEEP      retain newest N snapshots on the share (default 14)
#   ET_BACKUP_SMB_NO_MOUNTCHECK=1  skip the mountpoint guard (LOCAL TEST ONLY)
set -euo pipefail

SRC="${ET_BACKUP_SRC_DIR:?ET_BACKUP_SRC_DIR not set}"
DST="${ET_BACKUP_SMB_DIR:?ET_BACKUP_SMB_DIR not set}"
KEEP="${ET_BACKUP_KEEP:-14}"
MARKER="_LATEST.json"
RUN_STATUS="_LAST_RUN.json"

log()  { echo "[db-backup-relocate] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

[ -d "$SRC" ] || fail "source dir missing: $SRC"

# --- mount guard (fail-closed) ---------------------------------------------
if [ "${ET_BACKUP_SMB_NO_MOUNTCHECK:-0}" != "1" ]; then
    command -v mountpoint >/dev/null 2>&1 || fail "mountpoint(1) unavailable; refusing to write without a mount guard"
    mountpoint -q "$DST" || fail "SMB target is not a mountpoint: $DST (refusing to write to local disk)"
fi
mkdir -p "$DST"
[ -w "$DST" ] || fail "SMB target not writable: $DST"

# --- free-space precheck (>= 2x the largest source snapshot) ---------------
largest=$(find "$SRC" -maxdepth 1 \( -name 'triage-db-*.db' -o -name 'triage-db-*.etbk' \) ! -name '*.partial' -printf '%s\n' 2>/dev/null | sort -n | tail -1)
largest=${largest:-0}
if [ "$largest" -gt 0 ]; then
    avail=$(df -P "$DST" | awk 'NR==2 {print $4 * 1024}')
    need=$((largest * 2))
    [ "${avail:-0}" -ge "$need" ] || fail "insufficient space on share: avail=${avail:-0} need=$need"
fi

# --- copy + verify each not-yet-present snapshot (both formats) ------------
copied=0
for f in "$SRC"/triage-db-*.db "$SRC"/triage-db-*.etbk; do
    [ -e "$f" ] || continue
    case "$f" in *.partial) continue ;; esac
    base=$(basename "$f")
    [ -e "$DST/$base" ] && continue   # already relocated
    tmp="$DST/$base.partial"
    cp -f "$f" "$tmp"
    src_sha=$(sha256sum "$f"  | awk '{print $1}')
    dst_sha=$(sha256sum "$tmp" | awk '{print $1}')
    if [ "$src_sha" != "$dst_sha" ]; then
        rm -f "$tmp"
        fail "sha256 mismatch after copy for $base (src=$src_sha dst=$dst_sha)"
    fi
    mv -f "$tmp" "$DST/$base"
    copied=$((copied + 1))
done

# --- markers LAST (only after their referenced snapshots have landed) ------
# _LATEST.json (last GOOD) + _LAST_RUN.json (last run outcome — the freshness
# monitor reads both so a failed run is detectable, not hidden behind a stale
# success marker).
for m in "$MARKER" "$RUN_STATUS"; do
    if [ -f "$SRC/$m" ]; then
        cp -f "$SRC/$m" "$DST/$m.partial"
        mv -f "$DST/$m.partial" "$DST/$m"
    fi
done

# --- prune the share to keep-N by embedded ts (lexical == chronological) ----
pruned=0
i=0
while IFS= read -r name; do
    i=$((i + 1))
    if [ "$i" -gt "$KEEP" ]; then
        rm -f "$DST/$name"
        pruned=$((pruned + 1))
    fi
done < <(find "$DST" -maxdepth 1 \( -name 'triage-db-*.db' -o -name 'triage-db-*.etbk' \) ! -name '*.partial' -printf '%f\n' | sort -r)

log "relocated=$copied pruned=$pruned kept<=$KEEP target=$DST"
