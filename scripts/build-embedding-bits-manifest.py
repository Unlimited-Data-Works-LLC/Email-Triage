#!/usr/bin/env python3
"""Regenerate scripts/embedding-bits-manifest.json with real SHA-256 hashes.

Operator runs this on a CONNECTED machine before cutting an
email-triage release. Reads the manifest skeleton, downloads each
listed wheel + model file, computes SHA-256 + size, rewrites the
manifest in-place preserving the placeholder-name-to-file mapping.

Idempotent: re-running against an already-populated manifest re-checks
each URL and updates only the entries whose upstream bytes drifted.
Hash-match files are skipped (no re-download, no rewrite churn).

Output: manifest with real hashes + a one-line summary on stderr.

Implementation notes
--------------------
* Pure stdlib (argparse + urllib.request). No new install-time dep.
* Streaming hash computation — never materialises the full file in
  memory (torch CPU wheel is ~200 MB; the model bin is ~90 MB; total
  ~600 MB across the manifest).
* Uses a temp directory in --cache-dir (default ~/.cache/email-triage-
  manifest-build) so a partial run leaves no half-files behind in the
  repo. Resumed runs re-use cached downloads when the on-disk hash
  matches the manifest (saves the multi-GB re-fetch on retry).
* PyPI URLs in the skeleton carry ``PLACEHOLDER`` in the path. The
  builder resolves the real URL by hitting the PyPI JSON API
  (https://pypi.org/pypi/<name>/<version>/json) and matching against
  the manifest's ``filename`` field. PyTorch CPU wheels live on the
  pytorch.org index, not PyPI — we use the URL as-is for the torch
  entry.

Safety
------
* The installer module rejects any file whose SHA-256 doesn't match
  this manifest. A bad regenerator run can't ship a known-bad hash to
  customers — operator must inspect the diff before commit.
* Final summary prints the manifest's own SHA-256 so the operator can
  cross-check the value persisted in ``embedding_bits_install_state.
  manifest_sha256`` after the install runs.

Usage
-----
    python3 scripts/build-embedding-bits-manifest.py
        [--output scripts/embedding-bits-manifest.json]
        [--cache-dir ~/.cache/email-triage-manifest-build]
        [--dry-run]      # compute + report; don't rewrite output
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Chunk size for streaming download + hashing. 64 KiB is the sweet
# spot for socket-read throughput vs syscall overhead on most systems.
CHUNK = 64 * 1024

# Public PyPI JSON metadata endpoint. Returns the full release table
# including the canonical hosted-file URL for each wheel filename.
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"

# User-agent for our HTTPS fetches. Polite + identifiable (so an
# upstream that rate-limits sees us as a known build tool, not a bot).
UA = "email-triage-manifest-builder/1.0"


def _http_get(url: str, *, dest: Path) -> tuple[str, int]:
    """Stream ``url`` to ``dest``. Returns (sha256_hex, byte_count).

    Computes SHA-256 incrementally so we never need the full file in
    memory. Writes via a tempfile sibling + rename so a crash mid-
    download leaves the cache slot clean (no partial file masquerading
    as a completed download on the next run).
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    dest.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    size = 0
    # Sibling tempfile in the same dir so the rename is atomic.
    with tempfile.NamedTemporaryFile(
        delete=False, dir=str(dest.parent), prefix=".partial-",
    ) as tmp:
        tmp_path = Path(tmp.name)
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
                while True:
                    buf = resp.read(CHUNK)
                    if not buf:
                        break
                    hasher.update(buf)
                    tmp.write(buf)
                    size += len(buf)
        except Exception:
            tmp.close()
            tmp_path.unlink(missing_ok=True)
            raise
    tmp_path.replace(dest)
    return hasher.hexdigest(), size


def _hash_local(path: Path) -> tuple[str, int]:
    """Compute SHA-256 + size of an on-disk file without re-download."""
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            hasher.update(buf)
            size += len(buf)
    return hasher.hexdigest(), size


def _resolve_pypi_url(name: str, version: str, filename: str) -> str:
    """Look up the real PyPI download URL for ``filename``.

    PyPI's JSON API returns every distribution file for a release. We
    match against the manifest's ``filename`` exactly — no fuzzy match,
    so a future filename drift surfaces as a hard error rather than a
    silently-mismatched wheel.
    """
    url = PYPI_JSON_URL.format(name=name, version=version)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8"))
    for entry in data.get("urls", []):
        if entry.get("filename") == filename:
            return str(entry["url"])
    raise RuntimeError(
        f"PyPI release {name}=={version} does not include "
        f"filename {filename!r}. The pinned filename has drifted "
        f"(e.g. a new wheel tag for cp313); update the manifest "
        f"skeleton's filename field and re-run."
    )


def _resolve_wheel_url(entry: dict[str, Any]) -> str:
    """Return the real download URL for a wheel manifest entry.

    Three cases:
      1. URL is real (no PLACEHOLDER marker) — use as-is. PyTorch CPU
         wheels live on download.pytorch.org and aren't routed through
         PyPI; the skeleton's URL is canonical for them.
      2. URL is the PyPI placeholder shape
         (https://files.pythonhosted.org/packages/PLACEHOLDER/...) —
         resolve via the JSON API.
      3. URL is empty / malformed — error out; the skeleton is broken.
    """
    raw = entry.get("url", "")
    if not raw:
        raise RuntimeError(
            f"Manifest entry {entry.get('name')!r} has no URL. Update "
            f"the skeleton."
        )
    if "PLACEHOLDER" not in raw:
        return raw
    # PyPI placeholder path — go look it up.
    name = entry["name"].replace("-", "_") if "_" in entry.get(
        "filename", "",
    ) else entry["name"]
    # Some PyPI packages use the dashed name (e.g. "scikit-learn"); the
    # JSON API accepts both. Try the manifest's name verbatim first.
    try:
        return _resolve_pypi_url(entry["name"], entry["version"],
                                 entry["filename"])
    except urllib.error.HTTPError:
        # Fall back to underscore form (e.g. "sentence_transformers"
        # when manifest says "sentence-transformers").
        return _resolve_pypi_url(name, entry["version"],
                                 entry["filename"])


def _process_file(
    *,
    cache_dir: Path,
    url: str,
    filename: str,
    expected_sha256: str | None,
    label: str,
) -> tuple[str, int]:
    """Download (or re-use cached) ``url`` and return (sha256, size).

    Cache key is ``filename`` — we trust the manifest's filename field
    to be canonical. If the cache slot exists and its hash matches
    ``expected_sha256``, we skip the download. Mismatch or missing
    triggers re-fetch.
    """
    cache_path = cache_dir / filename
    if cache_path.exists() and expected_sha256 and "PLACEHOLDER" not in expected_sha256:
        sha, size = _hash_local(cache_path)
        if sha == expected_sha256:
            print(f"  {label} cached hit ({size:,} bytes)", file=sys.stderr)
            return sha, size
        print(
            f"  {label} cache MISS (existing hash {sha[:12]} != "
            f"expected {expected_sha256[:12]}); re-downloading",
            file=sys.stderr,
        )
    print(f"  {label} downloading from {url}", file=sys.stderr)
    sha, size = _http_get(url, dest=cache_path)
    print(f"  {label} downloaded ({size:,} bytes, sha256 {sha[:12]}…)",
          file=sys.stderr)
    return sha, size


def regenerate(
    manifest_path: Path,
    *,
    cache_dir: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Walk the manifest, download each listed file, update hashes
    + sizes in place. Returns a summary dict for stderr printing.
    """
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    cache_dir.mkdir(parents=True, exist_ok=True)
    print(f"Cache dir: {cache_dir}", file=sys.stderr)

    total_files = 0
    total_bytes = 0
    updated = 0

    # Wheels
    print(f"\nWheels ({len(manifest.get('wheels', []))} entries):",
          file=sys.stderr)
    for entry in manifest.get("wheels", []):
        label = f"{entry['name']}=={entry['version']}"
        url = _resolve_wheel_url(entry)
        sha, size = _process_file(
            cache_dir=cache_dir,
            url=url,
            filename=entry["filename"],
            expected_sha256=entry.get("sha256"),
            label=label,
        )
        if entry.get("sha256") != sha or entry.get("size_bytes") != size:
            updated += 1
        entry["sha256"] = sha
        entry["size_bytes"] = size
        entry["url"] = url  # rewrite resolved URL so installer can fetch
        total_files += 1
        total_bytes += size

    # Models (nested files-within-model shape)
    print(f"\nModels ({len(manifest.get('models', []))} entries):",
          file=sys.stderr)
    for model in manifest.get("models", []):
        for entry in model.get("files", []):
            label = f"{model['name']}/{entry['name']}"
            sha, size = _process_file(
                cache_dir=cache_dir / model["name"],
                url=entry["url"],
                filename=entry["name"].replace("/", "_"),
                expected_sha256=entry.get("sha256"),
                label=label,
            )
            if entry.get("sha256") != sha or entry.get("size_bytes") != size:
                updated += 1
            entry["sha256"] = sha
            entry["size_bytes"] = size
            total_files += 1
            total_bytes += size

    from datetime import datetime, timezone
    manifest["generated_at"] = datetime.now(timezone.utc).isoformat()

    # Stable serialised form for hash + write
    serialised = json.dumps(
        manifest, indent=2, ensure_ascii=False, sort_keys=False,
    )
    manifest_sha = hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    if dry_run:
        print(
            "\nDry-run: NOT writing manifest (--dry-run set)",
            file=sys.stderr,
        )
    else:
        # Atomic write: tempfile in the same dir + rename.
        manifest_dir = manifest_path.parent
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False,
            dir=str(manifest_dir), prefix=".manifest-",
        ) as tmp:
            tmp.write(serialised)
            tmp.write("\n")
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, manifest_path)
        print(f"\nWrote {manifest_path}", file=sys.stderr)

    return {
        "files": total_files,
        "bytes": total_bytes,
        "updated_entries": updated,
        "manifest_sha256": manifest_sha,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate scripts/embedding-bits-manifest.json with "
            "real SHA-256 hashes for the lazy embedding stack."
        ),
    )
    parser.add_argument(
        "--output",
        default="scripts/embedding-bits-manifest.json",
        help="Path to the manifest file (read + rewrite in place).",
    )
    parser.add_argument(
        "--cache-dir",
        default="",
        help="Directory to stash downloaded files for resume on retry. "
             "Default: ~/.cache/email-triage-manifest-build",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Compute hashes + print the summary; do NOT rewrite the "
             "manifest. Useful as a CI check for drift.",
    )
    args = parser.parse_args(argv)

    manifest_path = Path(args.output).resolve()
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    cache_dir = (
        Path(args.cache_dir).expanduser().resolve()
        if args.cache_dir
        else Path.home() / ".cache" / "email-triage-manifest-build"
    )

    try:
        summary = regenerate(
            manifest_path, cache_dir=cache_dir, dry_run=args.dry_run,
        )
    except Exception as e:  # noqa: BLE001
        print(f"\nFAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(
        f"\nDone.\n"
        f"  files:           {summary['files']}\n"
        f"  bytes total:     {summary['bytes']:,}\n"
        f"  entries updated: {summary['updated_entries']}\n"
        f"  manifest sha256: {summary['manifest_sha256']}\n",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
