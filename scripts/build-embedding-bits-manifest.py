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
* Every downloaded WHEEL is checked against the sha256 its PUBLISHER
  states — PyPI's JSON ``digests.sha256`` for the exact filename, or the
  ``#sha256=`` fragment on the download.pytorch.org simple index — and
  the run REFUSES on a mismatch or when no published value exists
  (punch 555; the fetched-artifact rule: verify against the publisher's
  value, not against the bytes we happened to receive). The refusal
  lands before the manifest write, and in ``--dry-run`` too, so the
  air-gap download path (``download-embedding-bits.sh``) is covered by
  the same check. Model files are NOT covered: Hugging Face states a
  sha256 only for LFS objects, and the model URLs resolve ``main``.
* Final summary prints the manifest's own SHA-256 so the operator can
  cross-check the value persisted in ``embedding_bits_install_state.
  manifest_sha256`` after the install runs.

Identity record (punch 514 / 515, register §3 "Runtime embedding package
set — identity review")
-----------------------------------------------------------------------
Hashes answer "are these the bytes we reviewed". They do not answer
"WHICH package pulls this wheel in" or "did this regeneration WIDEN the
runtime package set". Two records close that, both derived from the
downloaded wheels themselves — never from memory:

* ``wheels[].required_by`` / ``wheels_by_arch[*][].required_by`` — every
  manifest package whose ``METADATA`` ``Requires-Dist`` names this wheel,
  with ``extra == "…"``-gated requirements EXCLUDED (an extras-gated
  requirement is not installed by the ``pip --no-deps`` install this
  manifest drives, so it is not the real requirer). A wheel nothing in
  the manifest requires is a direct install target and records
  ``["email-triage"]``.
* ``regeneration_audit`` — the package set this manifest installs, the
  ``added``/``removed`` delta against the set the LAST regeneration
  recorded, and a network-capable-import scan of each wheel. A
  regeneration that ADDS a package with network-capable imports is
  REFUSED (fail closed) until the operator records the acceptance with
  ``--accept-network-import NAME``; the acceptance lands in the manifest,
  so THAT regeneration's diff carries the decision instead of the package
  inheriting a review silently. It is not a durable record: the next
  regeneration no longer sees the package as added and the map empties, so
  the lasting record is the reviewed-set entry in
  ``tests/_privacy_dep_funnel.py`` plus the accepting commit.

Scan bound (stated because it is load-bearing): the scan reads ``.py``
members only. A compiled extension (torch, tokenizers, regex, scipy,
scikit-learn, pillow, safetensors, hf-xet) can open a socket from native
code with no Python import to find, so an empty hit list for a binary
wheel is NOT proof of no network capability — it is the absence of a
Python-level import. ``tests/test_privacy_invariants_no_embedding_telemetry.py``
is the enforcing gate.

Usage
-----
    python3 scripts/build-embedding-bits-manifest.py
        [--output scripts/embedding-bits-manifest.json]
        [--cache-dir ~/.cache/email-triage-manifest-build]
        [--dry-run]          # compute + report; don't rewrite output
        [--metadata-only]    # no downloads: recompute required_by +
                             # regeneration_audit from the wheels already
                             # in --cache-dir (errors if any is missing)
        [--accept-network-import NAME]   # repeatable; record the operator's
                             # acceptance of an ADDED package whose .py
                             # members import a network module
        [--requirements-view]  # no network, no write: print the manifest
                             # as name==version lines for pip-audit
                             # (scripts/run-pip-audit.sh reads this)
        [--security-change true|false]   # punch 569: REQUIRED when the
                             # package set changed — is this change a
                             # security fix?
        [--advisory ID]      # repeatable; CVE/GHSA/PYSEC ids it fixes
        [--release vX.Y.Z]   # the release that ships this set

Set history (punch 569 D1)
--------------------------
The manifest carries ``set_changes``: one entry per change of the package set,
saying whether that change is a SECURITY fix. A running install whose set is
older keeps serving after a non-security change and is refused after a security
one, so the flag is decisional and is never defaulted: when this run changes the
set (``embedding_bits.manifest_set_digest`` differs from the newest entry's),
the write is REFUSED unless ``--security-change`` is given, and the refusal
lands before the write (``--dry-run`` prints what a real run would require).
``tests/test_n569_manifest_set_history_pin.py`` fails on a committed manifest
whose newest entry does not describe it, so a hand edit that skips this tool is
caught too.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

# Chunk size for streaming download + hashing. 64 KiB is the sweet
# spot for socket-read throughput vs syscall overhead on most systems.
CHUNK = 64 * 1024

# The value ``required_by`` carries for a wheel that nothing else in the
# manifest requires — i.e. a DIRECT install target of the app itself
# (``sentence-transformers`` today). One literal; the enforcing pin holds
# the only other copy, and its docstring names this line.
ROOT_REQUIRER = "email-triage"

# Network-capable imports the regeneration scan looks for in a wheel's
# ``.py`` members. Deliberately the STRONG needles (an HTTP client or a
# raw socket), not every stdlib module that touches a network concept:
# ``import asyncio`` and ``import ssl`` alone fired on jinja2 / setuptools
# in the 2026-09-25 baseline measurement, which would make every
# acceptance a rubber stamp. Widen only with the noise re-measured.
NETWORK_IMPORT_MODULES: tuple[str, ...] = (
    "socket",
    "http.client",
    "urllib.request",
    # A BARE ``import urllib`` too: on its own it only reaches
    # ``urllib.parse``, but paired with an ``urllib.request.urlopen`` call
    # it is a fetch the dotted needle above cannot see (mpmath's
    # ``functions/zeta.py``, found 2026-09-25). Measured cost of keeping
    # it: one package (mpmath); the other three bare-urllib packages
    # already hit a stronger needle.
    "urllib",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc.client",
)

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


def _pypi_release_file(name: str, version: str, filename: str) -> dict[str, Any]:
    """PyPI's JSON record for ``filename`` in release ``name==version``.

    PyPI's JSON API returns every distribution file for a release. We
    match against the manifest's ``filename`` exactly — no fuzzy match,
    so a future filename drift surfaces as a hard error rather than a
    silently-mismatched wheel. The record carries both the download
    ``url`` and the publisher's ``digests.sha256``.
    """
    url = PYPI_JSON_URL.format(name=name, version=version)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8"))
    for entry in data.get("urls", []):
        if entry.get("filename") == filename:
            return entry
    raise RuntimeError(
        f"PyPI release {name}=={version} does not include "
        f"filename {filename!r}. The pinned filename has drifted "
        f"(e.g. a new wheel tag for cp313); update the manifest "
        f"skeleton's filename field and re-run."
    )


def _resolve_pypi_url(name: str, version: str, filename: str) -> str:
    """Look up the real PyPI download URL for ``filename``."""
    return str(_pypi_release_file(name, version, filename)["url"])


# Hosts whose published sha256 the builder knows how to read. A wheel URL
# on any other host has no publisher value to verify against, so it is
# refused rather than trusted (fail closed).
PYPI_FILES_HOST = "files.pythonhosted.org"
PYTORCH_INDEX_HOST = "download.pytorch.org"

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _pytorch_index_sha256(url: str, name: str, filename: str) -> str | None:
    """The ``#sha256=`` fragment the pytorch simple index links ``filename`` with.

    The index for ``https://download.pytorch.org/whl/cpu/<file>`` is
    ``https://download.pytorch.org/whl/cpu/<name>/``; each link there is
    ``<path>/<url-quoted filename>#sha256=<hex>`` — the value pip itself
    verifies on install. Returns None when the file is listed without one.
    """
    parts = urllib.parse.urlsplit(url)
    index_dir = parts.path.rsplit("/", 1)[0]
    index_url = f"{parts.scheme}://{parts.netloc}{index_dir}/{name}/"
    req = urllib.request.Request(index_url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        html = resp.read().decode("utf-8", "replace")
    listed = False
    for href in re.findall(r'href="([^"]+)"', html):
        path, _, fragment = href.partition("#")
        if urllib.parse.unquote(path.rsplit("/", 1)[-1]) != filename:
            continue
        listed = True
        if fragment.startswith("sha256="):
            return fragment[len("sha256="):]
    if not listed:
        raise RuntimeError(f"{index_url} does not list {filename!r}.")
    return None


def _publisher_sha256(entry: dict[str, Any], url: str) -> str:
    """The sha256 the wheel's PUBLISHER states for ``entry``'s file.

    PyPI-hosted: the JSON API's ``digests.sha256`` for the exact filename.
    pytorch-hosted: the simple index's ``#sha256=`` fragment. Any other
    host, or a publisher that states no sha256, raises — a value we cannot
    check against the publisher is not verified, whatever TLS delivered.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    name, version, filename = entry["name"], entry["version"], entry["filename"]
    if host == PYPI_FILES_HOST:
        try:
            record = _pypi_release_file(name, version, filename)
        except urllib.error.HTTPError:
            record = _pypi_release_file(name.replace("-", "_"), version, filename)
        published = (record.get("digests") or {}).get("sha256")
    elif host == PYTORCH_INDEX_HOST:
        published = _pytorch_index_sha256(url, name, filename)
    else:
        raise RuntimeError(
            f"{name}=={version}: no publisher sha256 source for host "
            f"{host!r} ({url}). Only {PYPI_FILES_HOST} and "
            f"{PYTORCH_INDEX_HOST} are verifiable; refusing."
        )
    if not published or not _SHA256_HEX.fullmatch(published):
        raise RuntimeError(
            f"{name}=={version}: the publisher states no sha256 for "
            f"{filename!r} (got {published!r}); refusing an unverifiable file."
        )
    return published


def _verify_against_publisher(
    *, label: str, sha: str, published: str, cache_path: Path,
) -> None:
    """Refuse a wheel whose bytes differ from its publisher's sha256.

    The cache slot is deleted on a mismatch so a retry re-fetches instead
    of cache-hitting the bad bytes. Raises before the manifest is written.
    """
    if sha != published:
        cache_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"REFUSING {label}: downloaded sha256 {sha} does not match the "
            f"publisher's published sha256 {published}."
        )
    print(f"  {label} matches the publisher's sha256", file=sys.stderr)


# Model files (punch 555 / N-552). A model URL must name an IMMUTABLE commit:
# ``https://huggingface.co/<org>/<repo>/resolve/<40-hex sha>/<path>``. The
# publisher value is the repo tree at that commit: an LFS object states its
# sha256 (``lfs.oid``); a plain git file states only its git blob id (sha1 of
# ``blob <size>\0<bytes>``), so that is what a small file is checked against.
_HF_RESOLVE = re.compile(
    "^" + re.escape("https://huggingface.co/")
    + r"(?P<repo>[^/]+/[^/]+)/resolve/(?P<rev>[^/]+)/(?P<path>.+)$"
)
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_hf_tree_cache: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}


def _hf_tree(repo: str, rev: str) -> dict[str, dict[str, Any]]:
    """``path -> tree entry`` for ``repo`` at commit ``rev`` (cached per run)."""
    key = (repo, rev)
    if key not in _hf_tree_cache:
        url = f"https://huggingface.co/api/models/{repo}/tree/{rev}?recursive=true"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            _hf_tree_cache[key] = {e["path"]: e for e in json.loads(resp.read().decode("utf-8"))}
    return _hf_tree_cache[key]


def _hf_publisher_oid(url: str) -> tuple[str, str]:
    """``("sha256", hex)`` for an LFS object, ``("git-sha1", hex)`` for a git file.

    Refuses a URL that is not a pinned ``resolve/<commit>`` URL: ``main`` is
    a mutable ref, so a regeneration against it re-baselines silently.
    """
    m = _HF_RESOLVE.match(url)
    if not m:
        raise RuntimeError(f"not a huggingface.co resolve URL: {url!r}")
    repo, rev, path = m["repo"], m["rev"], urllib.parse.unquote(m["path"])
    if not _COMMIT_SHA.fullmatch(rev):
        raise RuntimeError(
            f"{url}: revision {rev!r} is a mutable ref; pin the model to a "
            f"40-hex commit sha (resolve/<sha>/)."
        )
    entry = _hf_tree(repo, rev).get(path)
    if entry is None:
        raise RuntimeError(f"{repo}@{rev} lists no {path!r}")
    lfs_oid = (entry.get("lfs") or {}).get("oid")
    if lfs_oid:
        return "sha256", str(lfs_oid)
    if entry.get("oid"):
        return "git-sha1", str(entry["oid"])
    raise RuntimeError(f"{repo}@{rev} states no object id for {path!r}")


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git's id


def _verify_model_file(*, label: str, url: str, sha256: str, path: Path) -> None:
    """Refuse a model file whose bytes differ from its publisher's object id."""
    kind, published = _hf_publisher_oid(url)
    actual = sha256 if kind == "sha256" else _git_blob_sha1(path.read_bytes())
    if actual != published:
        path.unlink(missing_ok=True)
        raise RuntimeError(
            f"REFUSING {label}: {kind} {actual} does not match the publisher's {published}."
        )
    print(f"  {label} matches the publisher's {kind}", file=sys.stderr)


def requirements_view(manifest: dict[str, Any]) -> list[str]:
    """The manifest as sorted ``name==version`` requirements for an auditor.

    A single requirement per package, over EVERY wheel on EVERY arch
    (``iter_wheel_entries`` — the walk over both surfaces), so the audit
    sees exactly what the installer can put in the PHI container.

    The PEP 440 local segment is dropped (``2.13.0+cpu`` -> ``2.13.0``).
    Advisories are keyed on the public version, and pip-audit's default
    PyPI service reports ``torch==2.12.0+cpu`` as "Dependency not found on
    PyPI and could not be audited" and exits 0 — measured 2026-09-30 on
    the pin that carried PYSEC-2025-194. A local version left in the view
    is a silent pass on the package that has the advisory.

    Raises ValueError when two arches pin different public versions of the
    same package (a single requirement cannot describe both, and auditing
    either would clear the other unseen) or when the manifest lists no
    wheels at all.
    """
    versions: dict[str, set[str]] = {}
    for _arch, entry in iter_wheel_entries(manifest):
        public = str(entry["version"]).split("+", 1)[0]
        versions.setdefault(_norm_pkg(entry["name"]), set()).add(public)
    disagree = {name: sorted(v) for name, v in versions.items() if len(v) > 1}
    if disagree:
        raise ValueError(
            f"arches pin different public versions: {disagree}; a single "
            f"requirement cannot describe both."
        )
    if not versions:
        raise ValueError("manifest lists no wheels; an empty view audits nothing.")
    return [f"{name}=={next(iter(v))}" for name, v in sorted(versions.items())]


def verify_publishers(manifest: dict[str, Any]) -> list[str]:
    """Re-derive every wheel's publisher sha256 and compare it to the manifest.

    The regeneration check (``_verify_against_publisher``) only covers a
    manifest THIS TOOL wrote. A hand-edited, merge-resolved or cherry-picked
    hash that no publisher states passes every other gate: the audits read
    versions, and the installer compares bytes against the manifest, i.e.
    against itself (punch 555, DA-555-2). This reads publisher metadata only
    — no wheel is downloaded — and returns one problem per wheel whose
    committed sha256 differs from, or cannot be checked against, the
    publisher's value. Unverifiable is a problem, never a pass.
    """
    problems: list[str] = []
    entries = list(iter_wheel_entries(manifest))
    if not entries:
        return ["manifest lists no wheels; nothing was verified"]
    for arch, entry in entries:
        label = f"{entry.get('name')}=={entry.get('version')} [{arch or 'neutral'}]"
        try:
            published = _publisher_sha256(entry, str(entry.get("url", "")))
        except Exception as e:  # noqa: BLE001 - every failure is a refusal
            problems.append(f"{label}: publisher value unavailable ({type(e).__name__}: {e})")
            continue
        if entry.get("sha256") != published:
            problems.append(
                f"{label}: committed sha256 {entry.get('sha256')} != publisher's {published}"
            )
    # Model files (N-552): an LFS object is compared by its stated sha256; a
    # small git file states only a git blob id, so its bytes are fetched
    # (at the pinned commit) and checked against BOTH that id and the
    # committed sha256.
    for model in manifest.get("models", []) or []:
        for entry in model.get("files", []) or []:
            label = f"{model.get('name')}/{entry.get('name')}"
            try:
                kind, published = _hf_publisher_oid(str(entry.get("url", "")))
                if kind == "sha256":
                    ok = entry.get("sha256") == published
                else:
                    req = urllib.request.Request(entry["url"], headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                        data = resp.read()
                    ok = (_git_blob_sha1(data) == published
                          and hashlib.sha256(data).hexdigest() == entry.get("sha256"))
            except Exception as e:  # noqa: BLE001 - every failure is a refusal
                problems.append(f"{label}: publisher value unavailable ({type(e).__name__}: {e})")
                continue
            if not ok:
                problems.append(f"{label}: committed sha256 does not match the publisher's {kind} {published}")
    return problems


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
    cache_path = _cache_slot(cache_dir, None, filename)
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


def _cache_slot(cache_dir: Path, arch: str | None, filename: str) -> Path:
    """The ONE download-cache path rule.

    Arch-neutral wheels sit in the cache root; an arch's binary wheels in
    a per-arch subdir so two same-named-but-different-arch wheels cannot
    collide in the cache. Both the download path and ``--metadata-only``
    resolve slots through here, so they cannot disagree about where a
    wheel was cached.
    """
    return (cache_dir if arch is None else cache_dir / arch) / filename


def _norm_pkg(name: str) -> str:
    """PEP-503 + lowercase. ``Foo_Bar.baz`` -> ``foo-bar-baz``.

    Same normalisation the privacy dep-review funnel applies, so a
    manifest entry spelled ``markdown_it_py`` and a ``Requires-Dist``
    spelled ``markdown-it-py`` are the same package here too.
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def iter_wheel_entries(manifest: dict[str, Any]):
    """Yield ``(arch, entry)`` for EVERY wheel the manifest installs.

    ``arch`` is ``None`` for the arch-neutral ``wheels`` list and the arch
    key for ``wheels_by_arch``. The one walk over both surfaces — a
    caller that iterates only ``wheels`` is blind to the binary wheels,
    which is the shape of the finding this field exists to close.
    """
    for entry in manifest.get("wheels", []) or []:
        yield None, entry
    for arch, entries in (manifest.get("wheels_by_arch") or {}).items():
        for entry in entries or []:
            yield arch, entry


def stage_sideload_layout(
    manifest: dict[str, Any], cache_dir: Path, staging_dir: Path,
) -> tuple[int, int]:
    """Mirror a regeneration cache into the air-gap sideload layout.

    Backs ``scripts/download-embedding-bits.sh``. Every wheel the manifest
    installs, on EVERY arch, lands flat at ``<staging>/wheels/<filename>``
    (binary filenames carry their arch tag, so the two arches cannot
    collide, and the installer's ``_load_manifest`` picks the running
    arch's set by filename). Each model file lands at
    ``<staging>/hf-cache/<hf_cache_dir>/<name>``. Sources resolve through
    ``_cache_slot`` — the path rule the download wrote them with.

    Before punch 555 the script walked ``manifest["wheels"]`` from the cache
    root only, so the tarball carried the arch-neutral wheels and none of
    the per-arch ones (torch, tokenizers, …): a sideload could never finish.
    A missing cached file raises; a partial tarball is not an air-gap kit.
    Returns ``(wheels_staged, model_files_staged)``.
    """
    import shutil

    def _mirror(src: Path, dst: Path) -> None:
        if not src.exists():
            raise FileNotFoundError(f"Missing in cache: {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists() or dst.stat().st_size != src.stat().st_size:
            shutil.copy2(src, dst)

    wheels = 0
    for arch, entry in iter_wheel_entries(manifest):
        _mirror(
            _cache_slot(cache_dir, arch, entry["filename"]),
            staging_dir / "wheels" / entry["filename"],
        )
        wheels += 1
    model_files = 0
    for model in manifest.get("models", []) or []:
        for entry in model.get("files", []) or []:
            # The download caches model files flattened ('/' -> '_') under
            # the model's name; the installer wants the original layout.
            _mirror(
                _cache_slot(cache_dir / model["name"], None,
                            entry["name"].replace("/", "_")),
                staging_dir / "hf-cache" / model["hf_cache_dir"] / entry["name"],
            )
            model_files += 1
    return wheels, model_files


def _wheel_metadata_text(whl: Path) -> str:
    """The wheel's ``*.dist-info/METADATA`` body."""
    with zipfile.ZipFile(whl) as zf:
        names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if not names:
            raise RuntimeError(
                f"{whl.name}: no .dist-info/METADATA member — cannot "
                f"determine what requires what without it."
            )
        return zf.read(names[0]).decode("utf-8", "replace")


def _requires_dist(metadata_text: str) -> set[str]:
    """Normalised names of the wheel's UNCONDITIONAL requirements.

    ``extra == "…"``-gated requirements are DROPPED: the install this
    manifest drives is ``pip --no-deps`` over the listed wheels with no
    extras, so an extras-gated line does not explain a wheel's presence.
    (Measured 2026-09-25: transformers names ``rich`` only under
    ``quality``/``serving``/``testing``/``dev`` — the real requirer of
    ``rich`` is ``typer``. Keeping extras would have recorded the wrong
    package.) Platform markers are KEPT (hf-xet is platform-gated and
    genuinely installed on both arches we ship).
    """
    out: set[str] = set()
    for line in metadata_text.splitlines():
        if not line.startswith("Requires-Dist:"):
            if not line.strip():
                break  # end of the RFC822 header block
            continue
        req = line.split(":", 1)[1].strip()
        marker = req.split(";", 1)[1] if ";" in req else ""
        if "extra ==" in marker:
            continue
        out.add(_norm_pkg(re.split(r"[\s<>=!~;\[(]", req, maxsplit=1)[0]))
    return out


def _network_import_hits(whl: Path) -> list[str]:
    """``NETWORK_IMPORT_MODULES`` imported by the wheel's ``.py`` members.

    Returns sorted ``"<member path>:<module>"`` strings — FILE granularity
    (punch 555, DA-555-1). A needle-only record (``"requests"``) cannot see a
    later version adding the same import to a NEW file (``tqdm/std.py``
    joining ``tqdm/contrib/telegram.py``): the record would not change, so
    an acceptance scoped to optional contrib modules would silently cover a
    core one.

    BOUND: Python members only. A compiled extension can open a socket
    with no Python import to find, so an empty list for a binary wheel is
    the absence of evidence, not evidence of absence.
    """
    hits: set[str] = set()
    patterns = [
        # Two exact arms — ``import <mod>`` and ``from <mod> import`` — and
        # NO dotted-suffix tolerance on either. Both details are measured,
        # not stylistic:
        #  * ``\b(?!\.)`` rather than ``[ \t]|$``, because a wheel can ship
        #    CRLF .py members where ``$`` sits after the ``\r`` and a plain
        #    ``import httpx`` line silently fails to match
        #    (sentence-transformers and mpmath both vanished from the hit
        #    list that way). ``(?!\.)`` keeps ``import socket`` off
        #    ``import socket.foo``; the word boundary keeps it off
        #    ``import socketserver``.
        #  * no ``(?:\.[\w.]+)?`` after the name on the ``from`` arm: with
        #    it, ``from urllib.parse import quote`` — pure string work —
        #    counted as a ``urllib`` network hit and lit up jinja2,
        #    markdown-it-py, mdurl and packaging. The cost is that
        #    ``from httpx._client import X`` alone is missed; a library
        #    using httpx imports the top-level name somewhere.
        (mod, re.compile(
            rf"^[ \t]*(?:import[ \t]+{re.escape(mod)}\b(?!\.)"
            rf"|from[ \t]+{re.escape(mod)}[ \t]+import\b)",
            re.MULTILINE,
        ))
        for mod in NETWORK_IMPORT_MODULES
    ]
    with zipfile.ZipFile(whl) as zf:
        for member in zf.namelist():
            if not member.endswith(".py"):
                continue
            src = zf.read(member).decode("utf-8", "replace")
            for mod, pat in patterns:
                if pat.search(src):
                    hits.add(f"{member}:{mod}")
    return sorted(hits)


def _hits_covered(current: list[str], recorded: list[str]) -> bool:
    """True when every current hit was already in ``recorded``.

    A pre-555 record is needle-only (``"requests"``, no ``:``); it covers a
    file-level hit with the same needle, so the first file-level
    regeneration migrates the record instead of refusing every package.
    From then on the comparison is per file.
    """
    exact = set(recorded)
    legacy = {h for h in recorded if ":" not in h}
    return all(h in exact or h.rsplit(":", 1)[-1] in legacy for h in current)


def _wheels_by_name(
    manifest: dict[str, Any], wheel_paths: dict[tuple[str | None, str], Path],
) -> dict[str, list[Path]]:
    """Normalised package name -> every downloaded wheel file for it.

    A binary package has one wheel per arch; both are read and their
    results UNIONed, so a per-arch metadata difference cannot hide a
    requirer or a network import.
    """
    out: dict[str, list[Path]] = {}
    for arch, entry in iter_wheel_entries(manifest):
        path = wheel_paths.get((arch, entry["filename"]))
        if path is None:
            continue
        out.setdefault(_norm_pkg(entry["name"]), []).append(path)
    return out


def record_required_by(
    manifest: dict[str, Any], wheel_paths: dict[tuple[str | None, str], Path],
) -> dict[str, list[str]]:
    """Set ``required_by`` on every wheel entry; return the name->value map.

    The value is every OTHER manifest package whose ``Requires-Dist``
    names this one (extras dropped), or ``[ROOT_REQUIRER]`` when nothing
    in the manifest does — a direct install target.
    """
    by_name = _wheels_by_name(manifest, wheel_paths)
    manifest_names = {
        _norm_pkg(e["name"]) for _arch, e in iter_wheel_entries(manifest)
    }
    missing = sorted(manifest_names - set(by_name))
    if missing:
        raise RuntimeError(
            f"cannot derive required_by: no downloaded wheel for "
            f"{missing} — required_by must come from package METADATA, "
            f"never from a hand-written guess. Run without "
            f"--metadata-only (or point --cache-dir at a cache holding "
            f"these wheels) and retry."
        )
    requires: dict[str, set[str]] = {}
    for name, paths in by_name.items():
        deps: set[str] = set()
        for path in paths:
            deps |= _requires_dist(_wheel_metadata_text(path))
        requires[name] = deps

    required_by: dict[str, list[str]] = {}
    for name in sorted(manifest_names):
        requirers = sorted(
            other for other, deps in requires.items()
            if other != name and name in deps
        )
        required_by[name] = requirers or [ROOT_REQUIRER]
    for _arch, entry in iter_wheel_entries(manifest):
        entry["required_by"] = list(required_by[_norm_pkg(entry["name"])])
    return required_by


def record_regeneration_audit(
    manifest: dict[str, Any],
    wheel_paths: dict[tuple[str | None, str], Path],
    *,
    accepted_network_imports: list[str] | None = None,
) -> dict[str, Any]:
    """Record the installed package set + this run's delta, FAIL CLOSED.

    Compares the live package set against the set the LAST regeneration
    recorded (``regeneration_audit.package_set``) and writes
    ``added``/``removed``. Every ADDED package is scanned for
    network-capable imports; an added package with hits that the operator
    has not accepted raises, so the manifest is NOT rewritten — the
    "a bump of an approved package widens the runtime set silently"
    failure mode becomes a refusal instead of an inheritance.
    """
    accepted = {_norm_pkg(n) for n in (accepted_network_imports or [])}
    prior = manifest.get("regeneration_audit") or {}
    previous = prior.get("package_set")
    prev_hits = {
        _norm_pkg(k): list(v)
        for k, v in (prior.get("network_import_hits") or {}).items()
    }
    prev_accepted = {
        _norm_pkg(k): list(v)
        for k, v in (prior.get("accepted_network_imports") or {}).items()
    }
    live = sorted({_norm_pkg(e["name"]) for _arch, e in iter_wheel_entries(manifest)})
    prev_set = set(previous) if previous is not None else None
    added = sorted(set(live) - prev_set) if prev_set is not None else []
    removed = sorted(prev_set - set(live)) if prev_set is not None else []

    by_name = _wheels_by_name(manifest, wheel_paths)
    hits: dict[str, list[str]] = {}
    for name in live:
        found: set[str] = set()
        for path in by_name.get(name, []):
            found |= set(_network_import_hits(path))
        if found:
            hits[name] = sorted(found)

    # A package needs a (re-)acceptance when it is NEW with network hits, or
    # when its file-level hit set GREW against the prior record — the
    # accepted one if it has one, else the prior scan (punch 555, DA-555-1:
    # before this only ADDED packages were ever checked, so a bump that put
    # a network import into a new core file of a present package passed).
    needs: dict[str, list[str]] = {}
    for name, current in hits.items():
        if name in added:
            needs[name] = current
        elif name in prev_accepted:
            if not _hits_covered(current, prev_accepted[name]):
                needs[name] = current
        elif prev_set is not None and not _hits_covered(current, prev_hits.get(name, [])):
            needs[name] = current
    unaccepted = {n: mods for n, mods in needs.items() if n not in accepted}
    if unaccepted:
        raise RuntimeError(
            "REFUSING to write: this regeneration ADDS package(s), or GROWS "
            "the file-level network-import set of a present package, and "
            "the inherited review argument is that it is NOT network-capable:\n  "
            + "\n  ".join(f"{n}: {mods}" for n, mods in sorted(unaccepted.items()))
            + "\nReview the package, then record the acceptance explicitly: "
            + " ".join(f"--accept-network-import {n}" for n in sorted(unaccepted))
        )
    carried = set(prev_accepted) & set(live)
    stale = sorted(accepted - set(needs) - carried)
    if stale:
        raise RuntimeError(
            f"--accept-network-import named package(s) this regeneration "
            f"neither added nor grew, and that carry no prior acceptance: "
            f"{stale}. An acceptance records a decision about a NEW or GROWN "
            f"network surface; naming another package would bank an "
            f"acceptance nothing asked for."
        )
    # Carry every prior acceptance forward (re-expressed at this run's file
    # level, which _hits_covered has just shown it covers), plus this run's.
    # Before 555 the record was rebuilt from the CLI args alone, so the
    # first later regeneration erased it.
    new_accepted = {
        name: hits[name]
        for name in sorted(carried | accepted)
        if hits.get(name)
    }

    from datetime import datetime, timezone
    audit = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "recorded_by": "scripts/build-embedding-bits-manifest.py",
        "required_by_source": (
            "Requires-Dist of the wheels in this manifest (extras-gated "
            "requirements excluded); a package no other entry requires "
            f"records {ROOT_REQUIRER!r}"
        ),
        "network_import_scan": (
            "import scan of each wheel's .py members for "
            + ", ".join(NETWORK_IMPORT_MODULES)
            + " — compiled extensions are NOT scanned, so an empty list "
            "for a binary wheel is not proof of no network capability"
        ),
        "previous_package_set": list(previous) if previous is not None else None,
        "package_set": live,
        "added": added,
        "removed": removed,
        "network_import_hits": hits,
        # The modules each acceptance covers, not a bare name: an operator
        # who accepts a package accepts the imports MEASURED in it, so a
        # later bump that adds a new network import to the same package
        # is visible in the diff rather than covered by a stale yes.
        "accepted_network_imports": new_accepted,
    }
    manifest["regeneration_audit"] = audit
    return audit


class SetChangeUnclassified(RuntimeError):
    """The package set changed and the run did not say whether the change is a
    security fix (punch 569 D1). Refused: the flag decides whether installs
    already in the field keep serving, so it is never defaulted."""


def _embedding_bits():
    """The app's own ``embedding_bits`` — the ONE digest and history parser
    (PD-5: a second copy of the digest here would drift from the one the
    running app compares against)."""
    try:
        from email_triage import embedding_bits
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from email_triage import embedding_bits
    return embedding_bits


def record_set_change(
    manifest: dict[str, Any],
    *,
    security_change: bool | None,
    advisories: list[str] | None = None,
    release: str | None = None,
) -> dict[str, Any] | None:
    """Append a ``set_changes`` entry when the package set changed; return it.

    ``None`` when the newest entry already describes this manifest (no change).
    Raises :class:`SetChangeUnclassified` when the set changed and
    ``security_change`` is None, and ``embedding_bits.ManifestHistoryError``
    when the existing history is malformed or the result would not parse.
    """
    eb = _embedding_bits()
    digest = eb.manifest_set_digest(manifest)
    history = list(manifest.get(eb.SET_CHANGES_KEY) or [])
    if history:
        eb.parse_set_changes(manifest, require_current=False)
        if history[-1].get("set_digest") == digest:
            if security_change is not None:
                print(
                    "--security-change ignored: the package set did not change",
                    file=sys.stderr,
                )
            return None
    if security_change is None:
        raise SetChangeUnclassified(
            f"the package set changed (digest {digest[:12]}) and this run did "
            f"not say whether the change is a security fix. Re-run with "
            f"--security-change true or --security-change false (and "
            f"--advisory ID for each advisory it fixes)."
        )
    from datetime import datetime, timezone
    entry = {
        "set_version": len(history) + 1,
        "set_digest": digest,
        "security_change": bool(security_change),
        "advisories": list(advisories or []),
        "release": release,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest[eb.SET_CHANGES_KEY] = history + [entry]
    eb.parse_set_changes(manifest)  # the full check, including "current"
    return entry


def _classify_set_change(
    manifest: dict[str, Any], set_change: dict[str, Any] | None, *, dry_run: bool,
) -> dict[str, Any] | None:
    """Run :func:`record_set_change` before a write. In ``--dry-run`` a refusal
    is printed as what a real run would require instead of raised."""
    opts = set_change or {}
    try:
        return record_set_change(
            manifest,
            security_change=opts.get("security_change"),
            advisories=opts.get("advisories"),
            release=opts.get("release"),
        )
    except SetChangeUnclassified as exc:
        if not dry_run:
            raise
        print(f"\nDry-run: a real run would REFUSE: {exc}", file=sys.stderr)
        return None


def _serialise(manifest: dict[str, Any]) -> str:
    """The ONE serialised form — hashed, written, and diffed.

    Key order is insertion order (``sort_keys=False``), so a new field
    lands after the fields already in the entry and a regeneration does
    not reorder the file.
    """
    return json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=False)


def _resolve_cached_wheels(
    manifest: dict[str, Any], cache_dir: Path,
) -> dict[tuple[str | None, str], Path]:
    """``(arch, filename) -> cached wheel path`` without downloading.

    Backs ``--metadata-only``: the identity fields are recomputed from
    the wheels a previous run already fetched. A missing FILE is reported
    and skipped; the fail-closed check is per PACKAGE NAME in
    ``record_required_by``, because the manifest carries the same package
    at the same version on both arches (the ``test_manifest_arch_v3``
    sibling pin), so one arch's cached wheel answers "what requires this"
    for the sibling entry. That is a real bound, stated here: a per-arch
    ``Requires-Dist`` difference would go unseen for the arch whose wheel
    is not cached. A package with NO cached wheel on either arch is a
    hard error, never a guess.
    """
    paths: dict[tuple[str | None, str], Path] = {}
    missing: list[str] = []
    for arch, entry in iter_wheel_entries(manifest):
        path = _cache_slot(cache_dir, arch, entry["filename"])
        if not path.exists() and arch is not None:
            # Pre-multi-arch cache layout: before manifest v3 the
            # binary wheels were arch-NEUTRAL entries and landed in the
            # cache root. An operator's long-lived cache still holds them
            # there, and a wheel file is identified by its arch-tagged
            # FILENAME, so reading it from the root is unambiguous.
            legacy = _cache_slot(cache_dir, None, entry["filename"])
            if legacy.exists():
                path = legacy
        if not path.exists():
            missing.append(f"{entry['name']} [{arch or 'neutral'}]: {path}")
            continue
        paths[(arch, entry["filename"])] = path
    if missing:
        print(
            "  NOT in cache (falling back to the sibling arch's wheel for "
            "these packages' metadata):\n    " + "\n    ".join(missing),
            file=sys.stderr,
        )
    return paths


def regenerate(
    manifest_path: Path,
    *,
    cache_dir: Path,
    dry_run: bool = False,
    metadata_only: bool = False,
    accepted_network_imports: list[str] | None = None,
    set_change: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Walk the manifest, download each listed file, update hashes
    + sizes in place. Returns a summary dict for stderr printing.

    ``set_change`` is ``{"security_change": bool | None, "advisories": [...],
    "release": str | None}`` (punch 569); it is applied before EVERY write.
    """
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    cache_dir.mkdir(parents=True, exist_ok=True)
    print(f"Cache dir: {cache_dir}", file=sys.stderr)

    total_files = 0
    total_bytes = 0
    updated = 0
    # (arch, filename) -> the wheel file on disk. Feeds the identity
    # records (required_by + the regeneration audit), which read the
    # wheels' own METADATA rather than trusting a hand-written note.
    wheel_paths: dict[tuple[str | None, str], Path] = {}

    if metadata_only:
        print(
            "\n--metadata-only: skipping every download; recomputing "
            "required_by + regeneration_audit from the cached wheels.",
            file=sys.stderr,
        )
        wheel_paths = _resolve_cached_wheels(manifest, cache_dir)
        required_by = record_required_by(manifest, wheel_paths)
        audit = record_regeneration_audit(
            manifest, wheel_paths,
            accepted_network_imports=accepted_network_imports,
        )
        _classify_set_change(manifest, set_change, dry_run=dry_run)
        _write_manifest(manifest, manifest_path, dry_run=dry_run)
        return {
            "files": 0,
            "bytes": 0,
            "updated_entries": 0,
            "manifest_sha256": hashlib.sha256(
                _serialise(manifest).encode("utf-8"),
            ).hexdigest(),
            "required_by": required_by,
            "audit": audit,
        }

    # Wheels
    print(f"\nWheels ({len(manifest.get('wheels', []))} entries):",
          file=sys.stderr)
    for entry in manifest.get("wheels", []):
        label = f"{entry['name']}=={entry['version']}"
        url = _resolve_wheel_url(entry)
        published = _publisher_sha256(entry, url)
        sha, size = _process_file(
            cache_dir=cache_dir,
            url=url,
            filename=entry["filename"],
            expected_sha256=entry.get("sha256"),
            label=label,
        )
        _verify_against_publisher(
            label=label, sha=sha, published=published,
            cache_path=_cache_slot(cache_dir, None, entry["filename"]),
        )
        if entry.get("sha256") != sha or entry.get("size_bytes") != size:
            updated += 1
        entry["sha256"] = sha
        entry["size_bytes"] = size
        entry["url"] = url  # rewrite resolved URL so installer can fetch
        wheel_paths[(None, entry["filename"])] = _cache_slot(
            cache_dir, None, entry["filename"],
        )
        total_files += 1
        total_bytes += size

    # Arch-specific wheels.
    # Each arch's binary wheels (torch / tokenizers / …) are refreshed the
    # same way as the neutral ``wheels`` list. Cached under a per-arch
    # subdir so the same-named-but-different-arch wheels don't collide in
    # the download cache. A connected (any-arch) machine can fill BOTH
    # arches — fetching an aarch64 wheel only downloads bytes, it doesn't
    # run them.
    for arch, entries in (manifest.get("wheels_by_arch") or {}).items():
        print(f"\nWheels[{arch}] ({len(entries)} entries):", file=sys.stderr)
        for entry in entries:
            label = f"{entry['name']}=={entry['version']} [{arch}]"
            url = _resolve_wheel_url(entry)
            published = _publisher_sha256(entry, url)
            sha, size = _process_file(
                cache_dir=cache_dir / arch,
                url=url,
                filename=entry["filename"],
                expected_sha256=entry.get("sha256"),
                label=label,
            )
            _verify_against_publisher(
                label=label, sha=sha, published=published,
                cache_path=_cache_slot(cache_dir, arch, entry["filename"]),
            )
            if entry.get("sha256") != sha or entry.get("size_bytes") != size:
                updated += 1
            entry["sha256"] = sha
            entry["size_bytes"] = size
            entry["url"] = url
            wheel_paths[(arch, entry["filename"])] = _cache_slot(
                cache_dir, arch, entry["filename"],
            )
            total_files += 1
            total_bytes += size

    # Models (nested files-within-model shape)
    print(f"\nModels ({len(manifest.get('models', []))} entries):",
          file=sys.stderr)
    for model in manifest.get("models", []):
        for entry in model.get("files", []):
            label = f"{model['name']}/{entry['name']}"
            _hf_publisher_oid(entry["url"])  # refuse an unpinned ref BEFORE downloading
            sha, size = _process_file(
                cache_dir=cache_dir / model["name"],
                url=entry["url"],
                filename=entry["name"].replace("/", "_"),
                expected_sha256=entry.get("sha256"),
                label=label,
            )
            _verify_model_file(
                label=label, url=entry["url"], sha256=sha,
                path=_cache_slot(cache_dir / model["name"], None,
                                 entry["name"].replace("/", "_")),
            )
            if entry.get("sha256") != sha or entry.get("size_bytes") != size:
                updated += 1
            entry["sha256"] = sha
            entry["size_bytes"] = size
            total_files += 1
            total_bytes += size

    from datetime import datetime, timezone
    manifest["generated_at"] = datetime.now(timezone.utc).isoformat()

    # The identity records LAST, over the wheels this run put on disk, so
    # they describe the manifest as written. record_regeneration_audit
    # RAISES on an unaccepted network-capable ADDED package — before the
    # write below, so the refusal leaves the manifest untouched.
    required_by = record_required_by(manifest, wheel_paths)
    audit = record_regeneration_audit(
        manifest, wheel_paths,
        accepted_network_imports=accepted_network_imports,
    )

    set_entry = _classify_set_change(manifest, set_change, dry_run=dry_run)
    manifest_sha = _write_manifest(manifest, manifest_path, dry_run=dry_run)

    return {
        "set_change": set_entry,
        "files": total_files,
        "bytes": total_bytes,
        "updated_entries": updated,
        "manifest_sha256": manifest_sha,
        "required_by": required_by,
        "audit": audit,
    }


def _write_manifest(
    manifest: dict[str, Any], manifest_path: Path, *, dry_run: bool,
) -> str:
    """Serialise, hash, and atomically write the manifest. Returns the sha256.

    ``newline="\\n"`` is REQUIRED, not cosmetic: ``.gitattributes`` pins
    this file to ``text eol=lf`` precisely so the on-disk sha256 matches
    the value the installer persists in
    ``embedding_bits_install_state.manifest_sha256`` on every platform.
    Without it a regeneration run on Windows writes CRLF and the hash the
    summary prints is not the hash a Linux container computes.
    """
    serialised = _serialise(manifest)
    manifest_sha = hashlib.sha256(serialised.encode("utf-8")).hexdigest()
    if dry_run:
        print("\nDry-run: NOT writing manifest (--dry-run set)", file=sys.stderr)
        return manifest_sha
    # Atomic write: tempfile in the same dir + rename.
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False,
        dir=str(manifest_path.parent), prefix=".manifest-",
    ) as tmp:
        tmp.write(serialised)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, manifest_path)
    print(f"\nWrote {manifest_path}", file=sys.stderr)
    return manifest_sha


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
             "manifest. As a drift check, read the summary's wheel/added/"
             "removed lines, NOT 'did the file change': a re-run always "
             "refreshes regeneration_audit.recorded_at, so a no-change run "
             "still produces a one-line diff.",
    )
    parser.add_argument(
        "--metadata-only", action="store_true",
        help="Do NOT download anything. Recompute the identity records "
             "(required_by + regeneration_audit) from the wheels already "
             "in --cache-dir; errors if any listed wheel is missing.",
    )
    parser.add_argument(
        "--accept-network-import", action="append", default=[],
        metavar="NAME",
        help="Record the operator's acceptance of an ADDED package whose "
             ".py members import a network module. Repeatable. Without it "
             "such a package is REFUSED rather than inheriting the "
             "'no network-capable package' review of the package that "
             "pulled it in.",
    )
    parser.add_argument(
        "--requirements-view", action="store_true",
        help="No network, no write: print the manifest as name==version "
             "requirements (every wheel, every arch, local version segment "
             "dropped) for pip-audit. Exit 2 if the arches disagree.",
    )
    parser.add_argument(
        "--verify-publishers", action="store_true",
        help="No download, no write: re-derive every wheel's publisher "
             "sha256 (PyPI JSON / pytorch index) and compare it to the "
             "COMMITTED manifest. Exit 1 on any mismatch or unverifiable "
             "entry. CI runs this (security.yml).",
    )
    parser.add_argument(
        "--security-change", choices=("true", "false"), default=None,
        help="Punch 569: REQUIRED when this run changes the package set. Is "
             "the change a security fix? Installs already in the field keep "
             "serving their old set after 'false' and refuse it after 'true'.",
    )
    parser.add_argument(
        "--advisory", action="append", default=[], metavar="ID",
        help="An advisory id (CVE-…, GHSA-…, PYSEC-…) this set change fixes. "
             "Repeatable. Shown to admins in the update banner and email.",
    )
    parser.add_argument(
        "--release", default=None, metavar="TAG",
        help="The release tag (vX.Y.Z) that ships this set.",
    )
    args = parser.parse_args(argv)
    set_change = {
        "security_change": (
            None if args.security_change is None
            else args.security_change == "true"
        ),
        "advisories": list(args.advisory),
        "release": args.release,
    }

    manifest_path = Path(args.output).resolve()
    if not manifest_path.exists():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    if args.verify_publishers:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        problems = verify_publishers(manifest)
        for problem in problems:
            print(f"REFUSED: {problem}", file=sys.stderr)
        checked = sum(1 for _ in iter_wheel_entries(manifest))
        model_files = sum(len(m.get("files", []) or []) for m in manifest.get("models", []) or [])
        print(f"verify-publishers: {checked} wheel entries + {model_files} model files, "
              f"{len(problems)} problem(s)", file=sys.stderr)
        return 1 if problems else 0

    if args.requirements_view:
        try:
            with manifest_path.open("r", encoding="utf-8") as fh:
                lines = requirements_view(json.load(fh))
        except (ValueError, KeyError) as e:
            print(f"REFUSED: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        sys.stdout.write("".join(f"{line}\n" for line in lines))
        return 0

    cache_dir = (
        Path(args.cache_dir).expanduser().resolve()
        if args.cache_dir
        else Path.home() / ".cache" / "email-triage-manifest-build"
    )

    try:
        summary = regenerate(
            manifest_path, cache_dir=cache_dir, dry_run=args.dry_run,
            metadata_only=args.metadata_only,
            accepted_network_imports=args.accept_network_import,
            set_change=set_change,
        )
    except Exception as e:  # noqa: BLE001
        print(f"\nFAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    audit = summary.get("audit") or {}
    print(
        f"\nDone.\n"
        f"  files:           {summary['files']}\n"
        f"  bytes total:     {summary['bytes']:,}\n"
        f"  entries updated: {summary['updated_entries']}\n"
        f"  packages:        {len(audit.get('package_set') or [])}\n"
        f"  added:           {audit.get('added')}\n"
        f"  removed:         {audit.get('removed')}\n"
        f"  net-import hits: {sorted((audit.get('network_import_hits') or {}))}\n"
        f"  manifest sha256: {summary['manifest_sha256']}\n",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
