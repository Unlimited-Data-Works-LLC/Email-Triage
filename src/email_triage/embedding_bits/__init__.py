"""Lazy-install runtime for the heavy embedding stack.

The v0.1.1+ container ships at ~250 MB by lifting torch + sentence-
transformers + the all-MiniLM-L6-v2 model weights out of the image
and downloading them on first use. This package is the consumer side
of the foundation laid in commit 96cb2f5:

* ``embedding_bits_install_state`` row (v31) — install lifecycle state.
* ``scripts/embedding-bits-manifest.json`` — pinned hashes baked into
  the image so the installer verifies against the manifest the image
  was built against, not whatever the operator's environment hands it.

Public API
----------
:func:`install_auto`
    Async installer that downloads each manifest-listed wheel +
    model file, hash-verifies, and pip-installs into the runtime
    deps target dir. Hard-refuses on any hash mismatch.

:func:`install_sideload`
    Async installer that consumes an operator-staged source dir
    (e.g. unpacked air-gap tarball) instead of downloading. Hash
    verification path is identical — sideload does NOT trust the
    operator-staged files either.

:func:`get_install_status`
    Read the embedding_bits_install_state row. Returns a dict the
    admin UI + status CLI render.

:func:`is_runtime_ready`
    Cheap check: can the embedding stack import from the runtime
    deps path? Used by FastAPI startup + the style-learning UI to
    gate features that need the embedding backend.

:func:`runtime_python_path`
    Filesystem paths the installer wrote to that need to live on
    ``sys.path`` for the lazy-installed packages to import.

:func:`add_runtime_to_sys_path`
    Idempotent ``sys.path.append(p)`` for each runtime path — and ONLY
    when :func:`runtime_marker_status` says the installed set matches
    the manifest this image was built against. Appends (never
    ``insert(0, …)``) so the image's own lock-pinned copy of any
    overlapping name keeps winning.

:func:`runtime_install_record`
    Non-mutating snapshot of what is actually installed on the volume
    (a dist-info scan, not the DB row). The one funnel behind the admin
    install card's wording and ``GET /health/runtime-deps``.

:func:`remove_install`
    The ONE removal funnel: deletes the runtime prefix and resets the
    install-state row in a single step. Refuses any target it cannot
    positively identify as a runtime prefix, and any target that is or
    contains the database.

:func:`get_runtime_deps_path`
    The fixed ``/app/data/runtime-deps`` prefix (punch 547: never read
    from the environment).

Cancel cooperation
------------------
:func:`request_cancel` / :func:`is_cancel_requested` form a tiny
process-local cancel flag. The installer checks it between files +
between pip-invoke phases. UI [Cancel] button POSTs to a route that
flips this flag.

Privacy
-------
* HF telemetry disabled via env: HF_HUB_DISABLE_TELEMETRY=1 +
  DO_NOT_TRACK=1 BEFORE pip + before any HF import.
* Every HTTP call is to a URL listed in the pinned manifest. Static
  test ``tests/test_privacy_invariants_no_embedding_telemetry.py``
  enforces this by scanning the module source.
"""

from __future__ import annotations

from email_triage.db.columns import EMBEDDING_BITS_INSTALL_STATE_COLUMNS
import asyncio
import json
import logging
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

#  — the install-state writer touches the SHARED app.state.db
# connection. ``db_writelock`` is stdlib-only (no web-package import
# cycle); decorating ``_update_state`` serialises it on the process-
# wide DB lock so an installer worker thread or a ``reverify`` thread
# does not race a ``db_call`` worker on the same sqlite3.Connection.
from email_triage.web.db_writelock import db_write as _db_write

# Telemetry-off env vars. Set at module import time so any later HF
# import in the same process inherits them (env vars set after the
# import are sometimes too late depending on HF's bootstrap order).
# Punch 547: FORCED, not setdefault — with setdefault a pre-set `0` in the
# environment won and switched the telemetry egress back on.
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["DO_NOT_TRACK"] = "1"
# Disable HF implicit downloads / progress bars / update checks.
os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ.setdefault("TRANSFORMERS_OFFLINE", "0")  # we DO need to fetch initially
# pip should never call home for version checks during our install.
os.environ["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

from email_triage._atomicio import atomic_write_text
from email_triage.triage_logging import get_logger  # N-196b R21_4
log = get_logger("email_triage.embedding_bits")  # N-196b R21_4


# -e (2026-07-11) — CONFIG-DRIVEN sentence_transformers probe budget.
# Pre-fix hardcoded ``timeout=60`` at the subprocess.run probe site.
# Compute-bound wait for a Python interpreter import probe (not network).
# Module-level SSOT with a boot-wired setter reading
# ``config.classifier.st_probe_timeout_secs``.
_ST_PROBE_TIMEOUT_SECS: float = 60.0


def configure_st_probe_timeout(timeout_secs: float) -> None:
    """-e — set the sentence_transformers subprocess probe budget.

    Called at boot from ``load_config._wire_module_singletons``.
    Rejects non-positive values.
    """
    global _ST_PROBE_TIMEOUT_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _ST_PROBE_TIMEOUT_SECS = float(timeout_secs)

CHUNK = 64 * 1024
DEFAULT_RUNTIME_DEPS = "/app/data/runtime-deps"
DEFAULT_MANIFEST_PATH = "/app/scripts/embedding-bits-manifest.json"

#: The two top-level directories the installer itself creates in a runtime
#: prefix: the staged, hash-verified wheels and the model cache. Every installer
#: write goes through these names, and :func:`runtime_prefix_layout` builds the
#: removal guard's "only runtime files here" set from them, so the guard cannot
#: drift from what the installer writes (N-549, punch 539 fold-check round 3).
WHEELS_DIRNAME = "wheels"
HF_CACHE_DIRNAME = "hf-cache"
DOWNLOAD_TIMEOUT_SECS = 300
PIP_TIMEOUT_SECS = 600


def hf_cache_dir_for_model(model_name: str) -> str:
    """The flat sentence-transformers cache-dir name for ``model_name`` — the
    repo-id with ``/`` → ``_``, prefixing the implicit ``sentence-transformers/``
    org for a bare name. THE SSOT for the on-disk staged-model dir
    (``$HF_HOME/<dir>/``): the OFFLINE installer stages a model here and
    ``engine.embedding_backend`` loads it from here by EXPLICIT PATH — modern
    sentence-transformers won't find a flat dir via its hub-cache resolution, so
    a true air-gap MUST load by path (verified on the deploy host 2026-06-11:
    flat-dir-only + offline → ST tries the network and fails; explicit-path
    load → OK). Mirrors ST's own legacy ``name.replace('/', '_')`` convention,
    so a manifest's ``hf_cache_dir`` and this derivation are pinned-equal.

    ``all-MiniLM-L6-v2`` → ``sentence-transformers_all-MiniLM-L6-v2``;
    ``intfloat/multilingual-e5-base`` → ``intfloat_multilingual-e5-base``.
    """
    name = (model_name or "").strip()
    if "/" not in name:
        name = f"sentence-transformers/{name}"
    return name.replace("/", "_")


def _model_hf_cache_dir(model: dict) -> str:
    """The staged hf-cache subdir for a manifest ``models`` entry: the explicit
    ``hf_cache_dir`` field when present (the SSOT), else derived from ``name``
    via :func:`hf_cache_dir_for_model` (back-compat for a pre-field manifest)."""
    explicit = model.get("hf_cache_dir")
    if explicit:
        return str(explicit)
    return hf_cache_dir_for_model(str(model.get("name") or ""))

# Retry schedule for hash-mismatch + network errors during a single
# file's download. After 3 attempts the file (and the whole install)
# fails. Aligned with the foundation commit's docstring promise.
RETRY_BACKOFF_SECS: tuple[int, ...] = (1, 4, 16)


# ---------------------------------------------------------------------------
# Cancel flag (process-local; UI cancel button flips this)
# ---------------------------------------------------------------------------

_cancel_lock = threading.Lock()
_cancel_flag = False


def request_cancel() -> None:
    """Signal the running installer to stop at the next file boundary."""
    global _cancel_flag
    with _cancel_lock:
        _cancel_flag = True


def clear_cancel() -> None:
    """Reset the cancel flag. Called at the start of each install run."""
    global _cancel_flag
    with _cancel_lock:
        _cancel_flag = False


def is_cancel_requested() -> bool:
    with _cancel_lock:
        return _cancel_flag


class InstallCancelled(Exception):
    """Raised when the operator cancels an in-flight install."""


class HashMismatch(Exception):
    """A file's SHA-256 did not match the manifest. Hard refusal — no
    skip-hash override. Surfaces the offending filename so the
    operator can investigate (transient mirror corruption vs upstream
    poisoning vs manifest drift on a fork)."""

    def __init__(self, filename: str, expected: str, actual: str) -> None:
        super().__init__(
            f"SHA-256 mismatch on {filename}: expected {expected[:12]}…, "
            f"got {actual[:12]}…"
        )
        self.filename = filename
        self.expected = expected
        self.actual = actual


class PipInstallError(Exception):
    """pip exited non-zero. Stderr is captured but scrubbed before it
    lands in the install_state row."""


@dataclass
class InstallResult:
    status: Literal["installed", "failed", "cancelled"]
    error_class: str | None = None
    error_msg: str | None = None
    bytes_downloaded: int = 0
    files_installed: int = 0
    duration_secs: float = 0.0


# ---------------------------------------------------------------------------
# Path helpers (used by FastAPI startup + the runtime-ready check)
# ---------------------------------------------------------------------------

def get_runtime_deps_path() -> Path:
    """Resolve the runtime-deps target dir.

    Punch 547: the FIXED ``DEFAULT_RUNTIME_DEPS`` — no environment override.
    This prefix is verified and ADDED TO sys.path, and (punch 541) is the
    default ``rmtree`` target of :func:`remove_install` (whose guard, N-549,
    still bounds what it deletes), so an env var choosing it chose which
    code the app imports.
    """
    return Path(DEFAULT_RUNTIME_DEPS)


def resolve_manifest_path() -> Path:
    """The manifest the RUNNING IMAGE was built against — the ONE resolver.

    Returns :data:`DEFAULT_MANIFEST_PATH`, the file the Containerfile COPYs into
    the image, and reads NO environment (punch 539 fold-check, hipaa H539FC-8 /
    da DA-FC539-1). The manifest is a baked image fact. An environment override
    of the manifest path used to win here, and this function is the default
    reference for the N-524 drift gate
    (:func:`runtime_marker_status`) and for the scanner-facing
    ``image_manifest_sha256`` (:func:`runtime_install_record`), so whoever could
    edit a quadlet could point the gate at an old manifest that matches a stale
    marker. An operator who wants a different manifest for one CLI run types
    ``--manifest``; the gate then compares against the image's manifest and
    refuses the mismatch, which is the correct answer.

    Hoisted here (N-524) because the drift gate needs it in the domain module.
    One resolver, and every importer uses it: ``web/routers/ui/embedding_install.
    _manifest_path`` and the CLI's ``_embedding_bits_paths`` (PD-5 — two mirrored
    copies of a path resolver will drift, and a gate whose manifest differs from
    the installer's manifest is a gate that compares the wrong two things).
    """
    return Path(DEFAULT_MANIFEST_PATH)


def runtime_site_packages_candidates(
    target_dir: Path | None = None,
) -> list[Path]:
    """Every site-packages layout pip's ``--prefix`` can produce, EXISTING OR
    NOT — the unfiltered candidate list.

    Distinct from :func:`runtime_python_path`, which filters to the dirs that
    exist. A scanner needs the candidates (so "the prefix holds nothing" is a
    measurable answer rather than an empty loop over an empty list); a sys.path
    mutator needs the filtered set.
    """
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return [
        # Standard --prefix install layout on POSIX:
        # <prefix>/lib/python<major>.<minor>/site-packages
        base / "lib" / pyver / "site-packages",
        # Windows --prefix layout: <prefix>/Lib/site-packages. We support this
        # path so dev runs on Windows exercise the same code path as the
        # production Linux container.
        base / "Lib" / "site-packages",
    ]


def runtime_python_path(target_dir: Path | None = None) -> list[str]:
    """sys.path additions for the lazy-installed bits — the ones that EXIST.

    pip is invoked with ``--prefix=<target>`` so the installed packages land in
    ``<target>/lib/pythonX.Y/site-packages``. We compute the site-packages path
    against the running interpreter's version and return the ones that exist.

    This function is deliberately side-effect-free and UNGATED: it answers
    "where WOULD the runtime live", which the record endpoint and the removal
    funnel both need even when the install is stale. The drift gate lives in
    :func:`runtime_marker_status`, and the only consumer that must obey it is
    :func:`add_runtime_to_sys_path`.

    ``target_dir`` overrides the default prefix, so a caller that was HANDED
    a prefix (``embedding-bits status --target-dir X``, ``reverify(target_dir=)``,
    the removal funnel) asks about THAT prefix rather than about the fixed
    default (``EMBEDDING_BITS_RUNTIME_DEPS`` is no longer read, punch 547).
    Without the parameter, every gate that
    accepted a ``target_dir`` honoured it for the dist-info scan and ignored it
    for the existence check — so a CLI run against an explicit prefix could read
    ``no_prefix`` for a prefix that is plainly there. Production never noticed
    because env and target are the same path there, which is exactly why a test
    built on the same fixture could not see it either.
    """
    out: list[str] = []
    for sp in runtime_site_packages_candidates(target_dir):
        if sp.exists():
            out.append(str(sp))
    return out


# ---------------------------------------------------------------------------
# The install RECORD (N-524 / punch 539) — what is actually on the volume
#
# THE DEFECT THIS CLOSES. ``manifest_sha256`` was written to the install-state
# row and only ever DISPLAYED: nothing compared the installed package set with
# the manifest the running image carries, and ``reverify`` never read it. A
# 2026-05-18 install (18 distributions, 104 OSV records, one CRITICAL) therefore
# stayed loadable on the persistent volume across every image rebuild, and every
# future CVE bump to the manifest would have done nothing to it. Drift failed
# OPEN, which on a HIPAA-class service means stale vulnerable code is importable
# in the PHI container with no signal while the dependency-CVE clock runs.
#
# WHY A MARKER FILE AND NOT THE DB ROW. The row records what the installer
# INTENDED; the volume holds what is actually importable. Those two disagree
# exactly when it matters (a half-finished install, a hand-edited volume, a
# restored backup, an image rebuilt against a newer manifest). The marker lives
# NEXT TO the thing it describes, so it travels with the volume and cannot be
# true-for-a-different-prefix.
# ---------------------------------------------------------------------------

#: The post-install record, written inside the runtime prefix.
INSTALLED_MARKER_NAME = "INSTALLED.json"

#: Bumped when the marker's shape changes. An unknown schema is REFUSED, not
#: best-effort parsed — a gate that guesses at an unrecognised record is a gate
#: that fails open on the next format change.
#:
#: Schema 2 (punch 569) adds ``set_version``, ``set_digest``,
#: ``record_digests`` and ``models_digest``: what an install needs to show that it is one specific,
#: unchanged set from the image manifest's history, which is the only way it can
#: keep serving after a non-security manifest change (``stale_ok``).
INSTALLED_MARKER_SCHEMA = 2

#: Every schema :func:`read_installed_marker` accepts. A schema-1 marker (every
#: install made before punch 569) still passes an EXACT match, as it always did;
#: it carries no set version, so it can never be ``stale_ok``. Re-verifying
#: rewrites it as the current schema (:func:`reverify`).
_ACCEPTED_MARKER_SCHEMAS = (1, INSTALLED_MARKER_SCHEMA)


class RuntimeRecordError(Exception):
    """The post-install dist-info scan did not match the manifest.

    Raised by :func:`write_installed_marker` so the install fails CLOSED (status
    ``failed``, no marker written, nothing added to ``sys.path``) rather than
    declaring success over a tree nobody has verified. A TYPED error that
    PROPAGATES, per PD-8: never a broad ``except`` that reads a verification
    failure as "verified".
    """


def canonical_dist_name(name: str) -> str:
    """The PEP 503 canonical form of a distribution name — the match key.

    ``scikit_learn``/``scikit-learn``/``SciKit.Learn`` all name one project, and
    a dist-info directory spells it with the PEP 427 escaping (``-`` → ``_``)
    while the manifest spells it with hyphens. Comparing the two raw would
    report drift on every such name, so every name on both sides of every
    comparison goes through HERE (PD-5).
    """
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _is_under(child: Path, parent: Path) -> bool:
    """True when ``child`` is ``parent`` or lives beneath it."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def scan_installed_distributions(
    target_dir: Path | None = None,
    *,
    site_dirs: list[Path] | None = None,
) -> dict[str, list[str]]:
    """Read the runtime prefix's ``*.dist-info`` dirs → ``{name: [versions]}``.

    EVERY version found is reported, sorted, never first-wins: more than one
    version of a name means the tree is AMBIGUOUS about what imports, and the
    whole point of this scan is that the ambiguity is visible instead of
    resolved by accident of path order. (Today's installer can produce exactly
    that — pip's ``--prefix`` run leaves an old dist-info in place beside a new
    one, which is how the 2026-05-18 set would have survived a "refresh".)

    IMPORTS NOTHING. The version comes from the dist-info directory name, with
    ``importlib.metadata.Distribution.at`` as the fallback for a dir whose name
    carries no version — that reads ``METADATA`` off disk and never executes the
    package. Importing a stale distribution to find out its version would be the
    very thing the caller is trying to avoid doing.

    ``site_dirs`` replaces the running interpreter's candidates: the orphan tree
    of ANOTHER interpreter (punch 732) is scanned through this same funnel.
    """
    found: dict[str, set[str]] = {}
    dirs = site_dirs if site_dirs is not None else runtime_site_packages_candidates(target_dir)
    for sp in dirs:
        if not sp.is_dir():
            continue
        try:
            entries = sorted(sp.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith(".dist-info"):
                continue
            stem = entry.name[: -len(".dist-info")]
            raw_name, _, raw_version = stem.partition("-")
            version = raw_version
            if not version:
                # A dist-info dir without a version in its name (non-standard,
                # but possible from a hand-built tree). Read METADATA rather
                # than guess — still no import.
                try:
                    import importlib.metadata as _md

                    version = _md.Distribution.at(entry).version or ""
                except Exception:  # noqa: BLE001
                    version = ""
            if not raw_name:
                continue
            found.setdefault(canonical_dist_name(raw_name), set()).add(version)
    return {name: sorted(vs) for name, vs in sorted(found.items())}


def manifest_expected_versions(manifest: dict[str, Any]) -> dict[str, str]:
    """``{canonical name: version}`` for every wheel THIS ARCH installs.

    Consumes the ARCH-RESOLVED manifest (``_load_manifest`` has already merged
    ``wheels_by_arch`` into ``wheels``), so the other arch's entries — which may
    legitimately carry placeholder hashes pre-release — are not compared.
    """
    out: dict[str, str] = {}
    for w in manifest.get("wheels", []):
        name = canonical_dist_name(str(w.get("name") or ""))
        if name:
            out[name] = str(w.get("version") or "")
    return out


def environment_provided_versions(
    names: Iterable[str], *, target_dir: Path | None = None,
) -> dict[str, str]:
    """``{canonical name: version}`` for the names already satisfied OUTSIDE the
    runtime prefix — i.e. the ones pip declines to install.

    WHY THIS EXISTS (measured 2026-09-29, and it is the reason the marker is not
    a flat "equals the manifest" compare). The installer passes BARE REQUIREMENT
    NAMES to ``pip install --prefix`` (see :func:`_run_pip_install` for why
    explicit paths and ``--upgrade`` are not an option: they make pip try to
    UNINSTALL the image's own copy of an overlapping name, out of a root-owned
    tree, as an unprivileged user). For any name the interpreter environment
    already provides, pip prints "Requirement already satisfied" and writes
    NOTHING into the prefix. Three manifest names are in ``requirements.lock``
    today — ``jinja2`` (3.1.6 both sides), ``packaging`` (manifest 26.2, lock
    26.3) and ``regex`` (manifest 2026.5.9, lock 2026.7.19) — so a strict
    prefix-equals-manifest assertion would refuse EVERY install, permanently,
    and the feature could never be installed at all.

    So the contract is: a manifest name is accounted for when it is in the
    prefix at the manifest's version, OR when the environment provides it. The
    set is DERIVED here, per install, rather than carried as a three-name
    allow-list — a hardcoded list is ``len(X)==N`` in disguise and is blind to
    the fourth overlapping name the next image adds (PD-1).

    Detection walks ``importlib.metadata.distributions()`` and DISCARDS anything
    resolving under ``target_dir``, so a prefix already on ``sys.path`` (an
    earlier probe in the same process) cannot make a prefix-installed package
    look image-provided.
    """
    wanted = {canonical_dist_name(n) for n in names}
    wanted.discard("")
    if not wanted:
        return {}
    prefix = (
        target_dir if target_dir is not None else get_runtime_deps_path()
    )
    try:
        prefix = prefix.resolve()
    except OSError as exc:  # pragma: no cover — defensive
        # Keep the unresolved prefix: the comparison below then errs toward
        # counting a prefix-installed copy as NOT image-provided, which makes the
        # drift gate stricter, never looser.
        log.debug(
            "embedding_bits: could not resolve the runtime prefix; using it as given",
            extra={"_extra": {"error_class": type(exc).__name__}},
        )
    # Punch 569: the LIVE prefix is excluded too, not only ``target_dir``. An
    # update records a staging prefix while the live one may be on sys.path
    # (stale_ok serves), and a name found there is the old runtime, not the
    # image: counting it as image-provided would vouch for a package the swap
    # is about to retire.
    excluded = [prefix]
    try:
        excluded.append(get_runtime_deps_path().resolve())
    except OSError as exc:  # pragma: no cover — defensive
        # The live prefix cannot be resolved, so nothing can be found under it;
        # the target exclusion above still applies.
        log.debug(
            "embedding_bits: could not resolve the live runtime prefix",
            extra={"_extra": {"error_class": type(exc).__name__}},
        )
    out: dict[str, str] = {}
    try:
        import importlib.metadata as _md

        dists = list(_md.distributions())
    except Exception:  # noqa: BLE001 — pragma: no cover
        return {}
    for dist in dists:
        try:
            name = canonical_dist_name(dist.metadata["Name"] or "")
        except Exception:  # noqa: BLE001
            continue
        if name not in wanted or name in out:
            continue
        root = _dist_root(dist)
        if root is not None and any(_is_under(root, p) for p in excluded):
            continue  # lives IN a runtime prefix — not environment-provided
        out[name] = str(dist.version or "")
    return out


def _dist_root(dist: Any) -> Path | None:
    """The directory an ``importlib.metadata`` distribution was found in."""
    raw = getattr(dist, "_path", None)
    try:
        if raw is not None:
            return Path(str(raw)).resolve().parent
        return Path(str(dist.locate_file(""))).resolve()
    except Exception:  # noqa: BLE001
        return None


def installed_marker_path(target_dir: Path | None = None) -> Path:
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    return base / INSTALLED_MARKER_NAME


def read_installed_marker(
    target_dir: Path | None = None,
) -> dict[str, Any] | None:
    """The marker as a dict, or ``None`` when absent / unreadable / unknown-schema.

    ``None`` is the FAIL-CLOSED answer: every caller treats it as "this install
    is not verified". Deliberately silent — the decision and its log line belong
    to :func:`runtime_marker_status`, which knows whether a missing marker is an
    anomaly or simply a not-installed system.
    """
    try:
        raw = installed_marker_path(target_dir).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    schema = data.get("schema")
    if isinstance(schema, bool) or schema not in _ACCEPTED_MARKER_SCHEMAS:
        return None
    if not isinstance(data.get("distributions"), dict):
        return None
    return data


def write_installed_marker(
    *,
    target_dir: Path,
    manifest: dict[str, Any],
    manifest_sha256: str,
    raw_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan the prefix, verify it against ``manifest``, and write the marker.

    Raises :class:`RuntimeRecordError` — so the install fails CLOSED — when the
    tree does not match: a name carrying more than one version, a version that
    differs from the manifest's, or a manifest name that is neither in the
    prefix nor provided by the environment. The marker is the LAST thing a
    successful install writes, after the import probe, so a marker can never
    vouch for a tree that does not import.

    ``raw_manifest`` is the file as read, before the arch merge; the set digest
    is computed over it (punch 569). Callers holding an arch-resolved
    ``manifest`` MUST pass it. Without it ``manifest`` is used, which is only
    right for a manifest with no ``wheels_by_arch``.
    """
    expected = manifest_expected_versions(manifest)
    on_disk = scan_installed_distributions(target_dir)

    ambiguous = sorted(n for n, vs in on_disk.items() if len(vs) > 1)
    if ambiguous:
        raise RuntimeRecordError(
            "the runtime prefix holds more than one version of: "
            f"{', '.join(ambiguous)}. Nothing wins by default, so which code "
            "imports depends on path order; refusing to record this tree as "
            "installed."
        )

    provided = environment_provided_versions(expected, target_dir=target_dir)
    wrong: list[str] = []
    missing: list[str] = []
    for name, want in sorted(expected.items()):
        got = on_disk.get(name)
        if got:
            if want and got[0] != want:
                wrong.append(f"{name} (manifest {want}, installed {got[0]})")
            continue
        if name in provided:
            continue
        missing.append(name)
    if wrong or missing:
        parts = []
        if missing:
            parts.append(
                "manifest packages absent from the prefix and not provided by "
                f"the image: {', '.join(missing)}"
            )
        if wrong:
            parts.append(f"version mismatch: {'; '.join(wrong)}")
        raise RuntimeRecordError("; ".join(parts))

    record = {
        "schema": INSTALLED_MARKER_SCHEMA,
        "written_at": _now_iso(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "manifest_sha256": manifest_sha256,
        # {name: version} — exactly one version per name, asserted above.
        "distributions": {n: vs[0] for n, vs in sorted(on_disk.items())},
        # The manifest names pip skipped because the image already provides
        # them. Recorded separately so a reader can tell "accounted for by the
        # image" from "installed here", and so the gate's arithmetic is
        # reconstructable from the record alone.
        "provided_by_image": dict(sorted(provided.items())),
    }
    # Punch 569 (schema 2): which set of the manifest's history this is, and a
    # digest of each distribution's dist-info, so that after the image moves on
    # the install can still show it is THAT set, unchanged.
    raw = raw_manifest if raw_manifest is not None else manifest
    try:
        set_version: int | None = parse_set_changes(raw)[-1].set_version
    except ManifestHistoryError:
        set_version = None  # this manifest has no usable history: never stale_ok
    record["set_version"] = set_version
    record["set_digest"] = manifest_set_digest(raw)
    record["models_digest"] = manifest_models_digest(raw)
    record["record_digests"] = dist_info_digests(target_dir)
    path = installed_marker_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Through the atomic-write SSOT (fsync, chmod-before-swap, temp cleanup on
    # failure): a torn marker is read as "marker_invalid", which refuses the
    # install, so a half-written file must never be observable.
    atomic_write_text(path, json.dumps(record, indent=2, sort_keys=True))
    return record


# ---------------------------------------------------------------------------
# The runtime SET history (punch 569) — which manifest changes were security
#
# WHY. N-524/N-555 refused an install on ANY difference from the image's
# manifest. The operator decided (2026-10-02) that a non-security change keeps
# the old set serving until the admin clicks [Update embedding runtime], and a
# security change refuses it. "Was this change a security fix" therefore has to
# be a fact the IMAGE carries, readable with the update check off and offline.
#
# ``manifest_version`` cannot carry it: it is the manifest FORMAT number (3 =
# the  multi-arch layout), not a per-release counter. So the manifest holds a
# history list, ``set_changes``, one entry per change of the package set. The
# CURRENT set is the newest entry and nothing else (PD-5: no second counter to
# drift from it), and that entry's ``set_digest`` must equal the digest of the
# manifest it sits in, so an edit to the package list that forgets to add an
# entry is caught here at runtime (fail closed) and by
# ``tests/test_n569_manifest_set_history_pin.py`` before it lands.
# ---------------------------------------------------------------------------

#: The manifest key holding the set history.
SET_CHANGES_KEY = "set_changes"

_DIGEST_SHAPE = re.compile(r"^[0-9a-f]{64}$")
#: A release tag as release.yml names it (``vX.Y.Z`` plus an optional suffix).
_RELEASE_SHAPE = re.compile(r"^v\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.-]+)?$")
#: An advisory id (``CVE-…``, ``GHSA-…``, ``PYSEC-…``). Bounded, no spaces, no
#: control characters: it is printed in the admin banner and the admin email.
_ADVISORY_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class ManifestHistoryError(ValueError):
    """The manifest's ``set_changes`` is absent, malformed, or does not describe
    the manifest it sits in. Every reader treats it as "this change may be a
    security fix" (fail closed, the rule 553 applies to its release marker)."""


@dataclass(frozen=True)
class SetChange:
    """One entry of the manifest's set history."""

    set_version: int
    set_digest: str
    security_change: bool
    advisories: tuple[str, ...]
    release: str | None


def manifest_set_digest(raw_manifest: dict[str, Any]) -> str:
    """The digest of the package SET a manifest installs — every arch, plus the
    model files. Arch-independent, so x86_64 and aarch64 hosts agree on it.

    Computed from the RAW manifest (:func:`_load_raw_manifest`): an
    arch-resolved one has one arch's wheels folded into ``wheels`` and digests
    differently. Rows are ``[slot, canonical name, version, filename, sha256]``
    sorted, so key order and list order in the file do not matter, while any
    change to what is installed does.
    """
    import hashlib

    rows: list[list[str]] = []

    def _wheel_row(slot: str, w: Any) -> list[str]:
        w = w if isinstance(w, dict) else {}
        return [
            slot,
            canonical_dist_name(str(w.get("name") or "")),
            str(w.get("version") or ""),
            str(w.get("filename") or ""),
            str(w.get("sha256") or ""),
        ]

    for w in raw_manifest.get("wheels") or []:
        rows.append(_wheel_row("any", w))
    by_arch = raw_manifest.get("wheels_by_arch") or {}
    if isinstance(by_arch, dict):
        for arch, wheels in by_arch.items():
            for w in wheels or []:
                rows.append(_wheel_row(f"arch:{arch}", w))
    rows.extend(_model_rows(raw_manifest))
    rows.sort()
    blob = json.dumps(rows, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _model_rows(manifest: dict[str, Any]) -> list[list[str]]:
    """One ``["model", name, "", file name, sha256]`` row per model file. Models are not
    split by arch, so a raw and an arch-resolved manifest give the same rows."""
    rows: list[list[str]] = []
    for model in manifest.get("models") or []:
        model = model if isinstance(model, dict) else {}
        for f in model.get("files") or []:
            f = f if isinstance(f, dict) else {}
            rows.append([
                "model", str(model.get("name") or ""), "",
                str(f.get("name") or ""), str(f.get("sha256") or ""),
            ])
    return rows


def manifest_models_digest(manifest: dict[str, Any]) -> str:
    """The digest of the MODEL files a manifest installs (punch 569).

    The installed record is otherwise package versions only, so a release that
    changes only a model file would read ``ok`` forever and the update notice
    would never fire. A schema-2 marker records this digest at install time and
    :func:`runtime_status` treats a difference as drift, exactly like a package
    change. It compares the MANIFEST's model hashes, not the bytes in hf-cache.
    """
    import hashlib

    blob = json.dumps(sorted(_model_rows(manifest)), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def parse_set_changes(
    raw_manifest: dict[str, Any], *, require_current: bool = True,
) -> tuple[SetChange, ...]:
    """The manifest's set history, strictly parsed. Raises
    :class:`ManifestHistoryError` on anything it cannot vouch for.

    Strict on purpose: ``security_change`` must be a real JSON boolean (a
    ``"false"`` string or a ``0`` is refused, not coerced), versions must run
    1, 2, 3 … with no gap or repeat, and with ``require_current`` the newest
    entry's digest must equal :func:`manifest_set_digest` of this manifest. A
    gap or a stale newest entry means a change nobody classified, which is
    exactly the case that must not read as "not security".
    ``require_current=False`` is for the release tool, which parses the history
    of a manifest it is about to append to.
    """
    entries = raw_manifest.get(SET_CHANGES_KEY)
    if entries is None:
        raise ManifestHistoryError(f"the manifest has no {SET_CHANGES_KEY}")
    if not isinstance(entries, list) or not entries:
        raise ManifestHistoryError(f"{SET_CHANGES_KEY} is not a non-empty list")
    out: list[SetChange] = []
    for i, e in enumerate(entries, start=1):
        if not isinstance(e, dict):
            raise ManifestHistoryError(f"entry {i} is not an object")
        version = e.get("set_version")
        if isinstance(version, bool) or not isinstance(version, int) or version != i:
            raise ManifestHistoryError(
                f"entry {i} has set_version {version!r}; versions must run "
                f"1, 2, 3 … in order with no gap"
            )
        digest = e.get("set_digest")
        if not isinstance(digest, str) or not _DIGEST_SHAPE.fullmatch(digest):
            raise ManifestHistoryError(f"set {i} has no valid set_digest")
        security = e.get("security_change")
        if not isinstance(security, bool):
            raise ManifestHistoryError(
                f"set {i} does not say true or false for security_change"
            )
        advisories = e.get("advisories")
        if not isinstance(advisories, list) or not all(
            isinstance(a, str) and _ADVISORY_SHAPE.fullmatch(a) for a in advisories
        ):
            raise ManifestHistoryError(f"set {i} has malformed advisories")
        release = e.get("release")
        if release is not None and (
            not isinstance(release, str) or not _RELEASE_SHAPE.fullmatch(release)
        ):
            raise ManifestHistoryError(f"set {i} has a malformed release tag")
        out.append(SetChange(
            set_version=version,
            set_digest=digest,
            security_change=security,
            advisories=tuple(advisories),
            release=release,
        ))
    if require_current and out[-1].set_digest != manifest_set_digest(raw_manifest):
        raise ManifestHistoryError(
            f"the newest {SET_CHANGES_KEY} entry (set {out[-1].set_version}) does "
            f"not describe this manifest: the package set changed without a new "
            f"entry saying whether the change is a security fix"
        )
    return tuple(out)


def _dist_info_digest(dist_info: Path) -> str:
    """Digest of one dist-info's ``RECORD`` (``METADATA`` when there is no
    ``RECORD``), or "" when it has neither. pip rewrites ``RECORD`` whenever it
    installs a distribution, so a re-install or a swapped distribution changes
    it; an in-place edit of a package file that leaves ``RECORD`` alone does
    not (see the SCOPE CAVEAT on :func:`runtime_status`)."""
    import hashlib

    for fname in ("RECORD", "METADATA"):
        p = dist_info / fname
        try:
            data = p.read_bytes()
        except OSError:
            continue
        return hashlib.sha256(fname.encode("ascii") + b"\0" + data).hexdigest()
    return ""


def dist_info_digests(
    target_dir: Path | None = None, *, site_dirs: list[Path] | None = None,
) -> dict[str, str]:
    """``{canonical name: dist-info digest}`` for every distribution in the
    prefix. Small files only: cheap enough for every status read, unlike
    re-hashing the ~600 MB the distributions install. ``site_dirs`` replaces
    the running interpreter's candidates (as in :func:`scan_installed_distributions`)."""
    out: dict[str, str] = {}
    dirs = site_dirs if site_dirs is not None else runtime_site_packages_candidates(target_dir)
    for sp in dirs:
        if not sp.is_dir():
            continue
        try:
            entries = sorted(sp.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith(".dist-info"):
                continue
            raw_name = entry.name[: -len(".dist-info")].partition("-")[0]
            if raw_name:
                out[canonical_dist_name(raw_name)] = _dist_info_digest(entry)
    return dict(sorted(out.items()))


# ---------------------------------------------------------------------------
# THE status funnel (N-524, punch 569)
# ---------------------------------------------------------------------------

#: ``RuntimeStatus.security`` for a change of the package set: a security fix,
#: not one, or not knowable (treated as one). Named constants, not "yes"/"no":
#: a comparison against a bool word is the A9 hand-rolled-bool shape.
SECURITY_FIX = "security_fix"
SECURITY_NONE = "not_security"
SECURITY_UNKNOWN = "unknown"

STATE_NO_PREFIX = "no_prefix"
STATE_OK = "ok"
STATE_STALE_OK = "stale_ok"
STATE_REFUSED = "refused"

#: The states in which the installed set may be loaded. ``stale_ok`` is the ONLY
#: serving state punch 569 adds, and it is reachable only through
#: :func:`_drift_status`'s non-security arm
#: (``tests/test_n569_runtime_update_pin.py`` pins both halves).
SERVING_STATES = frozenset({STATE_OK, STATE_STALE_OK})

#: The refusal tokens that mean the BYTES ON THE VOLUME are not what the last
#: verified install recorded (``disk_marker_mismatch``, ``duplicate_versions``),
#: or that the record / the trust anchor itself is unreadable (``marker_invalid``,
#: ``manifest_unreadable``). They are possible tamper evidence (§164.312(c)(1)),
#: so the app NEVER replaces such a prefix by itself (operator decision
#: 2026-10-25, hipaa-sme R3): it alerts and waits for an admin's click. Every
#: other refusal token is manifest-driven drift, which the automatic updater heals.
#: One home for the list (PD-5); ``tests/test_autoupd_integrity_pin.py`` pins that
#: every refusal token the status funnel can produce is classified.
INTEGRITY_TOKENS = frozenset({
    "disk_marker_mismatch",
    "duplicate_versions",
    "marker_invalid",
    "manifest_unreadable",
})


@dataclass(frozen=True)
class RuntimeStatus:
    """What the runtime prefix is, against this image's manifest.

    ``state`` is one of :data:`STATE_NO_PREFIX`, :data:`STATE_OK`,
    :data:`STATE_STALE_OK`, :data:`STATE_REFUSED`. ``reason`` is the path-free,
    PHI-free ``token: detail`` string the admin card, the logs and the monitoring system
    plugin (token only) read. For a change of the package set,
    ``installed_set_version`` / ``image_set_version`` say which sets (when the
    install can say), ``security`` is :data:`SECURITY_FIX`,
    :data:`SECURITY_NONE` or :data:`SECURITY_UNKNOWN` (and ``""`` when the set
    did not change), and ``advisories`` lists what the
    changes between the two sets name.
    """

    state: str
    reason: str
    installed_set_version: int | None = None
    image_set_version: int | None = None
    security: str = ""
    advisories: tuple[str, ...] = ()
    #: ``interpreter_mismatch`` with no loadable tree only (punch 732, panel py314
    #: hipaa SHOULD-3 / db SHOULD-2): whether the orphan tree the replace will wipe
    #: matched its marker's ``record_digests`` (False: no digests or no tree to
    #: check). ``None`` everywhere else. The update's audit row carries it.
    old_tree_verified: bool | None = None

    @property
    def serving(self) -> bool:
        """May the installed set be loaded? (``ok`` or ``stale_ok``.)"""
        return self.state in SERVING_STATES

    @property
    def verified(self) -> bool:
        """Is the installed set EXACTLY this image's? Drift-free, not CVE-free."""
        return self.state == STATE_OK

    @property
    def update_required(self) -> bool:
        """Should the admin be told to run [Update embedding runtime]?"""
        return self.state in (STATE_STALE_OK, STATE_REFUSED)

    @property
    def reason_token(self) -> str:
        return self.reason.split(":", 1)[0].strip()

    @property
    def integrity_refusal(self) -> bool:
        """Refused because of the prefix's / the record's integrity, not because
        the image's manifest moved (see :data:`INTEGRITY_TOKENS`)."""
        return self.state == STATE_REFUSED and self.reason_token in INTEGRITY_TOKENS

    @property
    def auto_updatable(self) -> bool:
        """May the app replace the runtime by itself? Manifest-driven staleness
        only: an integrity refusal waits for an admin."""
        return self.update_required and not self.integrity_refusal


def _tree_integrity_refusal(
    marker: dict[str, Any],
    recorded: dict[str, str],
    target_dir: Path | None,
    *,
    site_dirs: list[Path] | None = None,
) -> str:
    """Why the tree on disk is not the tree the marker recorded, or "".
    ``site_dirs`` checks another interpreter's orphan tree instead of the
    running interpreter's (punch 732)."""
    on_disk = scan_installed_distributions(target_dir, site_dirs=site_dirs)
    ambiguous = sorted(n for n, vs in on_disk.items() if len(vs) > 1)
    if ambiguous:
        return (
            "duplicate_versions: the prefix holds more than one version of "
            f"{', '.join(ambiguous)}, so which code imports depends on path "
            "order"
        )
    flat = {n: vs[0] for n, vs in on_disk.items()}
    if flat != recorded:
        # Name WHAT changed (package names, not PHI): the audit row of the update
        # that heals this carries the reason (hipaa-sme SHOULD-R3-2), and "the
        # tree changed" without a name is not a usable §164.312(b) record.
        added = sorted(n for n in flat if n not in recorded)
        removed = sorted(n for n in recorded if n not in flat)
        moved = sorted(n for n in flat if n in recorded and flat[n] != recorded[n])
        parts = []
        if added:
            parts.append(f"added: {', '.join(added)}")
        if removed:
            parts.append(f"missing: {', '.join(removed)}")
        if moved:
            parts.append(f"version changed: {', '.join(moved)}")
        return (
            "disk_marker_mismatch: the prefix's dist-info no longer matches "
            "what INSTALLED.json recorded, so the tree changed after the "
            f"install that verified it ({'; '.join(parts)})"
        )
    recorded_digests = marker.get("record_digests")
    if marker.get("schema") == INSTALLED_MARKER_SCHEMA:
        if not isinstance(recorded_digests, dict):
            return (
                "disk_marker_mismatch: INSTALLED.json is schema "
                f"{INSTALLED_MARKER_SCHEMA} but carries no record_digests"
            )
        current = dist_info_digests(target_dir, site_dirs=site_dirs)
        recorded_norm = {
            canonical_dist_name(str(n)): str(d) for n, d in recorded_digests.items()
        }
        if current != recorded_norm:
            changed = sorted(
                n for n in set(current) | set(recorded_norm)
                if current.get(n) != recorded_norm.get(n)
            )
            return (
                "disk_marker_mismatch: the dist-info of "
                f"{', '.join(changed)} changed after the install that verified it"
            )
    return ""


def _interpreter_mismatch(
    marker: dict[str, Any], target_dir: Path | None, *, tree_visible: bool,
) -> str:
    """Why the install in the prefix was built by another interpreter, or ""
    (punch 732). Two signals: the marker's ``python`` (written by
    :func:`write_installed_marker` as ``"<major>.<minor>"``; absent on a marker
    that predates it, which then says nothing) and, when no candidate
    site-packages of the running interpreter exists, a
    ``lib/python*/site-packages`` tree of another version."""
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    built = marker.get("python")
    if isinstance(built, str) and built and built != running:
        return (
            f"the install was built for Python {built} and this image runs "
            f"Python {running}"
        )
    if tree_visible:
        return ""
    others = [sp.parent.name for sp in _other_interpreter_site_dirs(target_dir)]
    if others:
        return (
            f"the prefix holds site-packages for {', '.join(others)} only and "
            f"this image runs Python {running}"
        )
    return ""


def _other_interpreter_site_dirs(target_dir: Path | None) -> list[Path]:
    """Every ``lib/python*/site-packages`` in the prefix that is not one of the
    running interpreter's candidates: the orphan tree a base-image bump leaves
    (punch 732). ONE glob, shared by the mismatch signal and the orphan's
    integrity check."""
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    own = {p.resolve() for p in runtime_site_packages_candidates(target_dir)}
    return sorted(
        sp for sp in (base / "lib").glob("python*/site-packages")
        if sp.is_dir() and sp.resolve() not in own
    )


def _drift_refusal(token: str, why: str, *, detail: str, **kw: Any) -> RuntimeStatus:
    """A drift refusal: ``token: <the set detail>; <why>``."""
    return RuntimeStatus(
        state=STATE_REFUSED,
        reason=(
            f"{token}: the recorded install does not match this image's "
            f"manifest — {detail}; {why}"
        ),
        **kw,
    )


def _unplaced_install_refusal(refuse: Any, raw_manifest: dict[str, Any]) -> RuntimeStatus:
    """Refusal for an install record that names no set (a pre-569 record).

    The record cannot place the install in the history, so the worst case is the
    one the history can price: every step after the first set may have been
    missed. If any of them is a security fix the refusal is ``security_drift``
    with the advisories (punch 664), so the admin prompt says "security fix"
    instead of the generic ``set_mismatch``; otherwise, or when the history
    cannot be read, it stays ``set_mismatch`` with an unknown security flag."""
    why = (
        "the install record does not say which set it is, so it cannot "
        "show the change is not a security fix"
    )
    try:
        history = parse_set_changes(raw_manifest)
    except ManifestHistoryError:
        return refuse("set_mismatch", why, security=SECURITY_UNKNOWN)
    steps = history[1:]
    if any(s.security_change for s in steps):
        return refuse(
            "security_drift",
            f"a change after set v{history[0].set_version} is a security fix "
            f"and the install record cannot show it has it",
            image_set_version=history[-1].set_version,
            security=SECURITY_FIX,
            advisories=tuple(dict.fromkeys(a for s in steps for a in s.advisories)),
        )
    return refuse("set_mismatch", why, security=SECURITY_UNKNOWN)


def _drift_status(
    *,
    marker: dict[str, Any],
    raw_manifest: dict[str, Any],
    recorded: dict[str, str],
    detail: str,
    target_dir: Path | None,
) -> RuntimeStatus:
    """The installed set differs from the image's: ``stale_ok`` or refused.

    ``stale_ok`` needs EVERY one of these; anything else refuses (fail closed):

    1. the marker is the current schema and names the set it was verified as
       (``set_version`` + ``set_digest``) — a pre-569 marker cannot say;
    2. the image's manifest carries a valid ``set_changes`` whose newest entry
       describes it (absent, malformed or stale history = "may be security");
    3. the installed set is OLDER than the image's and is the exact entry the
       history records under that version (same digest);
    4. no change between the two sets is marked ``security_change: true``;
    5. (the tree is the one the marker recorded: no duplicate versions, same
       dist-info set, same per-dist digests. This is checked by
       :func:`runtime_status` BEFORE any drift classification, so a tampered
       prefix reports its integrity token whatever the manifest does, and a call
       here is already past it.)
    6. every name the old install left to the image is still provided by this
       image (the new image may have dropped one).
    """
    from functools import partial

    refuse = partial(_drift_refusal, detail=detail)

    installed_v = marker.get("set_version")
    installed_digest = marker.get("set_digest")
    if (
        marker.get("schema") != INSTALLED_MARKER_SCHEMA
        or isinstance(installed_v, bool)
        or not isinstance(installed_v, int)
        or installed_v < 1  # panel B3 db F569-4: 0 or -1 would index history[-1]
        or not isinstance(installed_digest, str)
    ):
        return _unplaced_install_refusal(refuse, raw_manifest)
    try:
        history = parse_set_changes(raw_manifest)
    except ManifestHistoryError as exc:
        return refuse(
            "security_drift",
            f"this image's manifest cannot say whether the change is a "
            f"security fix ({exc}), so it is treated as one",
            installed_set_version=installed_v, security=SECURITY_UNKNOWN,
        )
    image_v = history[-1].set_version
    if installed_v >= image_v:
        return refuse(
            "set_mismatch",
            f"the installed set (v{installed_v}) is not older than this "
            f"image's (v{image_v})",
            installed_set_version=installed_v, image_set_version=image_v,
            security=SECURITY_UNKNOWN,
        )
    if history[installed_v - 1].set_digest != installed_digest:
        return refuse(
            "set_mismatch",
            f"the installed set is not the set v{installed_v} this image's "
            f"history records",
            installed_set_version=installed_v, image_set_version=image_v,
            security=SECURITY_UNKNOWN,
        )
    steps = history[installed_v:image_v]
    advisories = tuple(dict.fromkeys(a for s in steps for a in s.advisories))
    if any(s.security_change for s in steps):
        return refuse(
            "security_drift",
            f"a change between set v{installed_v} and v{image_v} is a "
            f"security fix",
            installed_set_version=installed_v, image_set_version=image_v,
            security=SECURITY_FIX, advisories=advisories,
        )
    left_to_image = sorted(
        canonical_dist_name(n) for n in (marker.get("provided_by_image") or {})
    )
    still = environment_provided_versions(left_to_image, target_dir=target_dir)
    gone = [n for n in left_to_image if n not in still]
    if gone:
        return refuse(
            "set_mismatch",
            f"this image no longer provides {', '.join(gone)}, which the "
            f"installed set relied on",
            installed_set_version=installed_v, image_set_version=image_v,
            security=SECURITY_NONE, advisories=advisories,
        )
    return RuntimeStatus(
        state=STATE_STALE_OK,
        reason=(
            f"stale_ok: the installed set (v{installed_v}) predates this "
            f"image's (v{image_v}) and no change between them is a security "
            f"fix, so it keeps serving until the update — {detail}"
        ),
        installed_set_version=installed_v, image_set_version=image_v,
        security=SECURITY_NONE, advisories=advisories,
    )


def runtime_status(
    *,
    target_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> RuntimeStatus:
    """THE status of the runtime prefix against this image's manifest.

    The ONE predicate every consumer derives from (PD-5): the serve gates read
    :attr:`RuntimeStatus.serving` (through :func:`runtime_marker_status`), the
    record behind the admin card, ``/health/runtime-deps`` and the monitoring system plugin
    reads :attr:`RuntimeStatus.verified` and the reason token, and the banner,
    the admin alert and the daily-health section read the whole object.

    Refuses (``refused``) when, in this order:
      * the marker is missing, unreadable, or written to an unknown schema;
      * the tree on disk holds more than one version of a name, or no longer
        matches what the marker recorded (names, versions, and for a schema-2
        marker each dist-info's digest); checked BEFORE the manifest, so an
        integrity token (:data:`INTEGRITY_TOKENS`) is never masked by drift;
      * the manifest cannot be read (no manifest ⇒ nothing to compare ⇒ refuse);
      * the installed set differs from the manifest's and :func:`_drift_status`
        cannot show the difference is a non-security change from a known set.

    ``stale_ok`` (punch 569, operator decision 2026-10-02): the set differs, the
    install is a known older set, and no change since is a security fix — it
    keeps serving until the admin updates it, and every notice surface says so.

    SCOPE CAVEAT — what ``ok`` / ``stale_ok`` does NOT prove: (1) that the
    packages import (that is ``runtime_imports_cleanly``, paid once at the
    install gate); (2) that the package FILE BYTES are unchanged (``reverify``
    re-hashes the staged wheels; the per-dist digest covers ``RECORD``, which
    pip rewrites on any re-install, not an in-place edit that leaves ``RECORD``
    alone); (3) anything about the versions the IMAGE provides; (4) the model BYTES
    in ``hf-cache`` — a schema-2 marker records the manifest's model digest, so
    a model-only release is drift, but the files on disk are not re-hashed
    (``reverify`` does that), and a schema-1 marker records no models. The trust model is
    N-524's: whoever can write the volume can write the marker too.
    """
    def interpreter_refusal(
        marker: dict[str, Any], built_for: str, *, old_tree_verified: bool | None = None,
    ) -> RuntimeStatus:
        # Punch 732: an install built by another interpreter cannot load here.
        # Manifest-driven (the image moved on), NOT an integrity token, so the
        # automatic updater replaces it. Built before any drift classification,
        # so the installed set version comes from the marker.
        v = marker.get("set_version")
        return _drift_refusal(
            "interpreter_mismatch",
            "its compiled packages cannot load under this interpreter, so it is "
            "refused until it is reinstalled",
            detail=built_for,
            installed_set_version=(
                v if isinstance(v, int) and not isinstance(v, bool) and v >= 1 else None
            ),
            old_tree_verified=old_tree_verified,
        )

    if not runtime_python_path(target_dir):
        # A marker beside no loadable tree is usually an install made by ANOTHER
        # interpreter (a base-image bump), not a fresh container. Without a
        # marker it stays no_prefix: the first install is the admin's click.
        marker = read_installed_marker(target_dir)
        built_for = _interpreter_mismatch(marker, target_dir, tree_visible=False) if marker else ""
        if built_for:
            # Panel py314 (hipaa SHOULD-3 / db SHOULD-2): the replace wipes the
            # orphan tree, so check it against its marker FIRST. A tree that no
            # longer matches is possible tamper evidence: refuse with the
            # integrity token (never healed automatically) instead.
            orphans = _other_interpreter_site_dirs(target_dir)
            recorded = {
                canonical_dist_name(n): str(v)
                for n, v in (marker.get("distributions") or {}).items()
            }
            if orphans:
                integrity = _tree_integrity_refusal(
                    marker, recorded, target_dir, site_dirs=orphans,
                )
                if integrity:
                    return RuntimeStatus(state=STATE_REFUSED, reason=integrity)
            return interpreter_refusal(
                marker, built_for,
                old_tree_verified=bool(orphans) and isinstance(
                    marker.get("record_digests"), dict,
                ),
            )
        return RuntimeStatus(state=STATE_NO_PREFIX, reason="no_prefix")
    marker = read_installed_marker(target_dir)
    if marker is None:
        return RuntimeStatus(state=STATE_REFUSED, reason=(
            "marker_invalid: no readable INSTALLED.json of a known schema in "
            "the runtime prefix, so the installed package set has never been "
            "recorded or verified"
        ))
    recorded = {
        canonical_dist_name(n): str(v)
        for n, v in (marker.get("distributions") or {}).items()
    }
    # Operator decision 2026-10-25 (hipaa-sme MUST-R3-1): the tree's integrity is
    # checked BEFORE any manifest comparison. It compares the prefix with its own
    # marker and does not depend on the manifest, so it must win: if drift were
    # classified first, a tampered prefix would read ``security_drift`` /
    # ``set_mismatch`` as soon as the manifest moved, and the automatic updater
    # (which heals manifest drift only) would overwrite the evidence as a routine
    # update. The serve decision is unchanged (every drift return is a refusal
    # already); only the reason token on those refusals changes.
    integrity = _tree_integrity_refusal(marker, recorded, target_dir)
    if integrity:
        return RuntimeStatus(state=STATE_REFUSED, reason=integrity)
    # Punch 732: a visible tree can still belong to another interpreter where the
    # layout is unversioned (Windows ``Lib/site-packages``); the marker's python
    # is then the only signal. Checked AFTER integrity, so a tampered prefix
    # keeps its integrity token rather than being healed automatically.
    built_for = _interpreter_mismatch(marker, target_dir, tree_visible=True)
    if built_for:
        return interpreter_refusal(marker, built_for)
    mpath = manifest_path if manifest_path is not None else resolve_manifest_path()
    try:
        raw = _load_raw_manifest(mpath)
        manifest = _resolve_manifest_arch(raw, label=mpath.name)
    except Exception as exc:  # noqa: BLE001
        return RuntimeStatus(
            state=STATE_REFUSED, reason=f"manifest_unreadable: {type(exc).__name__}",
        )

    expected = manifest_expected_versions(manifest)
    provided = {
        canonical_dist_name(n)
        for n in (marker.get("provided_by_image") or {})
    }
    wrong: list[str] = []
    missing: list[str] = []
    for name, want in sorted(expected.items()):
        got = recorded.get(name)
        if got is not None:
            if want and got != want:
                wrong.append(f"{name} (manifest {want}, installed {got})")
            continue
        if name in provided:
            continue
        missing.append(name)
    if missing or wrong:
        detail = []
        if missing:
            detail.append(f"not installed: {', '.join(missing)}")
        if wrong:
            detail.append(f"stale: {'; '.join(wrong)}")
        return _drift_status(
            marker=marker, raw_manifest=raw, recorded=recorded,
            detail="; ".join(detail), target_dir=target_dir,
        )

    # Punch 569: the package versions match; the MODEL files may not. A
    # schema-2 marker records the models it was installed with, so a model-only
    # release is drift like a package change (stale_ok or refused, by the same
    # history). A schema-1 marker cannot say, and an exact package match stays
    # ok for it (back-compat with every pre-569 install).
    if (
        marker.get("schema") == INSTALLED_MARKER_SCHEMA
        and marker.get("models_digest") != manifest_models_digest(raw)
    ):
        return _drift_status(
            marker=marker, raw_manifest=raw, recorded=recorded,
            detail="model files changed", target_dir=target_dir,
        )

    return RuntimeStatus(state=STATE_OK, reason="ok")


def runtime_marker_status(
    *,
    target_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> tuple[bool, str]:
    """The SERVE gate: ``(may this prefix be loaded, reason)``.

    A thin view of :func:`runtime_status` for the callers that only decide
    whether to load (``add_runtime_to_sys_path``, ``is_runtime_ready``,
    ``runtime_importable_probe``). ``True`` for ``ok`` AND ``stale_ok``
    (punch 569); ``"no_prefix"`` distinguishes "nothing is installed" (the
    ordinary state of a fresh container — never a warning) from a refusal.
    A caller asking "is this EXACTLY the image's set" reads
    ``runtime_status(...).verified`` instead.
    """
    status = runtime_status(target_dir=target_dir, manifest_path=manifest_path)
    return status.serving, status.reason


#: The banner reads the status on every admin page render; a short-lived memo
#: keeps that to one prefix scan per window. ONLY the banner uses it — every
#: decision (serve gates, the update funnel, the alert probe) reads uncached.
_STATUS_MEMO_SECS = 30.0
_status_memo: tuple[float, RuntimeStatus] | None = None
_status_memo_lock = threading.Lock()


def runtime_status_memo() -> RuntimeStatus:
    """:func:`runtime_status` for the default prefix, at most
    :data:`_STATUS_MEMO_SECS` old. Display only; cleared by
    :func:`invalidate_runtime_ready_cache`."""
    global _status_memo
    now = time.monotonic()
    with _status_memo_lock:
        memo = _status_memo
        if memo is not None and now - memo[0] < _STATUS_MEMO_SECS:
            return memo[1]
    status = runtime_status()
    with _status_memo_lock:
        _status_memo = (time.monotonic(), status)
    return status


# ---------------------------------------------------------------------------
# Restart pending (punch 569 D4)
#
# After an update swaps the prefix in a process that has already imported
# packages from it, the sys.path entry is the SAME string, so an already-loaded
# package (transformers is a lazy module) would import its not-yet-loaded
# submodules from the NEW tree: two versions of one package in one process.
# Python cannot unload torch, so the process stops using the runtime until it is
# restarted. Fail closed (PD-8): embedding refuses with a typed error that the
# backend counts, and every notice surface says "restart the container".
# ---------------------------------------------------------------------------

_restart_lock = threading.Lock()
_restart_pending = False


class RuntimeRestartRequired(RuntimeError):
    """The embedding runtime was updated after this process loaded the old one;
    restart the container to load the new runtime."""


def restart_pending() -> bool:
    """True once an update swapped the prefix under loaded packages."""
    with _restart_lock:
        return _restart_pending


def _mark_restart_pending() -> None:
    global _restart_pending
    with _restart_lock:
        _restart_pending = True


def runtime_install_record(
    *,
    target_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """A NON-MUTATING snapshot of the runtime prefix. Never touches ``sys.path``.

    The ONE funnel behind both read surfaces — the admin install card's wording
    and ``GET /health/runtime-deps`` — so the page and the route can never
    disagree about whether an install is verified (PD-5). Path-free and
    PHI-free by construction: no key here carries a filesystem path, an error
    message from the install row, or any field of ``/health/detail``.

    ``verified`` stays EXACT (drift-free): a ``stale_ok`` set reads
    ``verified: False`` with reason token ``stale_ok``, so the monitoring system plugin and
    ``runtime_verified`` WARN on it (punch 569 D5). ``serving`` says whether it
    still loads.
    """
    mpath = manifest_path if manifest_path is not None else resolve_manifest_path()
    marker = read_installed_marker(target_dir)
    status = runtime_status(target_dir=target_dir, manifest_path=mpath)
    try:
        image_sha = _manifest_sha256(mpath)
    except OSError:
        image_sha = ""
    paths = runtime_python_path(target_dir)
    return {
        "present": bool(paths),
        "distributions": scan_installed_distributions(target_dir),
        "image_manifest_sha256": image_sha,
        "installed_manifest_sha256": str(
            (marker or {}).get("manifest_sha256") or ""
        ),
        "verified": status.verified,
        "serving": status.serving,
        "state": status.state,
        "reason": status.reason,
        "restart_pending": restart_pending(),
        "integrity_refusal": status.integrity_refusal,
        "on_sys_path": any(p in sys.path for p in paths),
    }


def runtime_importable_probe(target_dir: Path | None = None) -> bool:
    """Is ``sentence_transformers`` importable from the runtime prefix — WITHOUT
    touching ``sys.path``?

    ``PathFinder.find_spec(name, path)`` searches the given entries only, so a
    display surface can answer "is it installed" without positioning volume
    code on the import path of the serving process. Gated on
    :func:`runtime_marker_status`: an unverified prefix reads False, because a
    surface that reports a stale install as ready is how the operator learns the
    wrong thing.
    """
    if restart_pending():
        return False  # punch 569 D4: this process must restart to load it
    ok, _reason = runtime_marker_status(target_dir=target_dir)
    if not ok:
        return False
    paths = runtime_python_path(target_dir)
    if not paths:
        return False
    try:
        import importlib.machinery

        spec = importlib.machinery.PathFinder.find_spec(
            "sentence_transformers", paths,
        )
    except Exception:  # noqa: BLE001
        return False
    return spec is not None


def add_runtime_to_sys_path() -> None:
    """APPEND the verified runtime prefix to ``sys.path``. Idempotent.

    Two changes from the pre-N-524 shape, both load-bearing:

    * **It refuses unless the install is verified.** A missing, unreadable or
      manifest-mismatched marker logs at WARNING and returns without touching
      ``sys.path`` — so a stale tree is not made importable, and every caller
      inherits the gate at once instead of each remembering to ask.
    * **It APPENDS instead of ``insert(0, …)``.** The old shape put the volume
      ahead of the image AND the stdlib for the rest of the process's life
      (nothing ever removes the entry), so any name the volume shadowed was
      served from the volume. Appending means the image's own, lock-pinned,
      CVE-scanned copy still wins, and only names the image does NOT provide
      come from the volume — which is the whole point of a lazy install.

    The docstring used to say "call at FastAPI startup"; no startup caller has
    ever existed (nothing in ``web/app.py`` calls it). It is called from the
    loader path and from the install's own verify step.
    """
    paths = runtime_python_path()
    if not paths:
        return  # nothing installed — the ordinary state, not an anomaly
    if restart_pending():
        # Punch 569 D4: the prefix was swapped under packages this process had
        # already loaded; nothing more may import from it until a restart.
        return
    ok, reason = runtime_marker_status()
    if not ok:
        log.warning(
            "embedding_bits: refusing to add the runtime-deps prefix to "
            "sys.path — the install is not verified against this image's "
            "manifest",
            extra={"_extra": {"reason": reason}},
        )
        return
    for p in paths:
        if p not in sys.path:
            sys.path.append(p)


def remove_runtime_from_sys_path(target_dir: Path | None = None) -> list[str]:
    """Drop every runtime-prefix entry from ``sys.path``; return what was removed.

    Used by the removal funnel. It cannot un-import a module already loaded from
    the prefix — that needs a restart, which the funnel says so — but it does
    stop a later import from resolving there.

    Keyed on the CANDIDATE paths (:func:`runtime_site_packages_candidates`,
    existing or not) rather than on :func:`runtime_python_path`, and that is not
    a detail: the caller has usually just DELETED the tree, so a list filtered on
    ``.exists()`` finds nothing and silently leaves the entry on ``sys.path`` —
    which is the one thing this function exists to prevent. Keying on the
    candidates makes it order-independent.
    """
    removed: list[str] = []
    for sp in runtime_site_packages_candidates(target_dir):
        p = str(sp)
        while p in sys.path:
            sys.path.remove(p)
            removed.append(p)
    return removed


def is_runtime_ready(*, runtime_deps_path: Path | None = None) -> bool:
    """Cheap probe: does ``sentence_transformers`` LOOK importable
    from the runtime path?

    Uses ``importlib.util.find_spec`` — returns True when the package
    directory exists on sys.path. Does NOT actually import, so does
    NOT catch the case where the package itself depends on a transitive
    that's missing from the install. The 2026-05-18 ``packaging``-
    missing regression bit because find_spec returned True even though
    ``import sentence_transformers`` raised ``ModuleNotFoundError``.

    Use this for:
      * FastAPI startup — log the install state, decide whether to
        wire the embedding backend or leave it None.
      * Style-learning UI gating — disable controls that need the
        embedding stack (per-page-render check; sub-ms cost matters).
      * Reindex job — refuse to run if False.

    For the install verify gate (hard check that "installed" actually
    means importable), use :func:`runtime_imports_cleanly` instead —
    that runs a real ``import sentence_transformers`` in a subprocess
    and catches missing-transitive failures.
    """
    global _runtime_ready_cache
    if restart_pending():
        return False  # punch 569 D4: not cached — only a restart clears it
    if _runtime_ready_cache is not None:
        return _runtime_ready_cache
    # N-524: the drift gate comes FIRST and is asked explicitly, not inferred
    # from whether the path got added. An unverified prefix is never "ready" —
    # if it were, a stale 2024 install would keep every gate open and every
    # caller (the reindex job, the style-learning gate, the install card) would
    # act on it. Fail CLOSED (PD-8).
    verified, _reason = runtime_marker_status()
    if not verified:
        _runtime_ready_cache = False
        return _runtime_ready_cache
    add_runtime_to_sys_path()
    try:
        import importlib.util
        spec = importlib.util.find_spec("sentence_transformers")
        _runtime_ready_cache = spec is not None
    except Exception:  # noqa: BLE001
        _runtime_ready_cache = False
    return _runtime_ready_cache


def runtime_imports_cleanly(
    *, runtime_deps_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Strong probe: actually IMPORT ``sentence_transformers`` and
    catch any transitive-dep failures.

    Returns ``(True, None)`` on clean import; ``(False, <error_msg>)``
    when the import raises (typically
    ``ModuleNotFoundError: No module named 'X'`` from a missing
    transitive).

    Cost: 1-2 seconds — torch + transformers + tokenizers all chain-
    import. Pay it ONCE at the install verify gate, not on every page
    render.

    Implementation: runs the import in a SUBPROCESS so the parent
    process's sys.modules cache doesn't pollute the result, and so a
    failed import doesn't leave half-loaded module shadows in the
    parent. Subprocess inherits the parent's PATH + the runtime_deps
    sys.path additions via the inline probe script.

    N-524: this no longer calls ``add_runtime_to_sys_path`` in the PARENT. It
    never needed to — the probe builds its own path in the child — and calling
    it here would either mutate the serving process's ``sys.path`` as a
    side effect of a *probe*, or (post-gate) log a spurious "refusing" warning
    on every install, because the install's own verify step runs BEFORE the
    marker the gate reads exists. The child appends rather than inserting, for
    the same reason the parent does: the image's own copy of an overlapping name
    must keep winning.
    """
    import subprocess as _sp
    rdp = str(runtime_deps_path) if runtime_deps_path else str(get_runtime_deps_path())
    # Inline probe — keeps the test self-contained without shipping
    # a separate script file in the image.
    probe = (
        "import sys, os\n"
        f"rdp = {rdp!r}\n"  # punch 547: no env read in the probe either
        "if rdp:\n"
        "    pyver = f'python{sys.version_info.major}.{sys.version_info.minor}'\n"
        "    sp = f'{rdp}/lib/{pyver}/site-packages'\n"
        "    if sp not in sys.path:\n"
        "        sys.path.append(sp)\n"
        "    spw = f'{rdp}/Lib/site-packages'\n"
        "    if spw not in sys.path:\n"
        "        sys.path.append(spw)\n"
        "import sentence_transformers\n"
        "print('OK')\n"
    )
    try:
        result = _sp.run(  # noqa: S603
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=_ST_PROBE_TIMEOUT_SECS,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        from email_triage._errfmt import scrub_class_error_for_persist
        return False, (
            f"probe subprocess failed: "
            f"{scrub_class_error_for_persist(exc)}"
        )
    if result.returncode == 0 and "OK" in (result.stdout or ""):
        return True, None
    err_tail = (result.stderr or "").strip().splitlines()
    msg = err_tail[-1] if err_tail else (
        f"probe exited {result.returncode}; no stderr captured"
    )
    return False, msg[:300]


_runtime_ready_cache: bool | None = None


def invalidate_runtime_ready_cache() -> None:
    """Reset the is_runtime_ready cache.

    Called after a successful install so the next probe reflects the
    new on-disk state without a process restart."""
    global _runtime_ready_cache, _status_memo
    _runtime_ready_cache = None
    with _status_memo_lock:
        _status_memo = None


# ---------------------------------------------------------------------------
# Status row helpers (read + write embedding_bits_install_state)
# ---------------------------------------------------------------------------

def get_install_status(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the singleton install-state row as a dict.

    Always returns a dict — the foundation migration's INSERT OR
    IGNORE seed guarantees the row exists. Defensive fallback emits
    a synthetic ``not_installed`` shape if the row is somehow missing
    so the UI never crashes on a None row.
    """
    row = conn.execute(
        f"SELECT {EMBEDDING_BITS_INSTALL_STATE_COLUMNS} FROM embedding_bits_install_state WHERE id = 1"
    ).fetchone()
    if row is None:
        return _synthetic_not_installed()
    return dict(row)


def _synthetic_not_installed() -> dict[str, Any]:
    return {
        "id": 1,
        "status": "not_installed",
        "install_method": None,
        "manifest_sha256": None,
        "runtime_deps_path": None,
        "progress_files_done": 0,
        "progress_files_total": 0,
        "progress_bytes_done": 0,
        "progress_bytes_total": 0,
        "current_file": None,
        "attempt_count": 0,
        "last_attempt_at": None,
        "installed_at": None,
        "last_error_class": None,
        "last_error_msg": None,
        "last_error_at": None,
        "created_at": "",
    }


def _now_iso() -> str:
    from email_triage._isotime import now_utc_iso
    return now_utc_iso()


def _scrub_error(text: str | None) -> str | None:
    """Token-scrub + PHI-scrub + collapse + clip an error message before writing
    the row. Census run13 #2: converged onto the shared persisted-error funnel
    ``_errfmt.scrub_error_for_persist`` (this was the ONE site that already
    composed both legs — redact_exc PHI + scrub_secrets_from_text token — so it
    became the SSOT). Behaviour-identical; now every persisted ``*error*`` field
    shares one funnel instead of this mirror."""
    from email_triage._errfmt import scrub_error_for_persist
    return scrub_error_for_persist(text)


@_db_write
def _update_state(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    install_method: str | None = None,
    manifest_sha256: str | None = None,
    runtime_deps_path: str | None = None,
    progress_files_done: int | None = None,
    progress_files_total: int | None = None,
    progress_bytes_done: int | None = None,
    progress_bytes_total: int | None = None,
    current_file: str | None = None,
    bump_attempt: bool = False,
    set_last_attempt_now: bool = False,
    set_installed_now: bool = False,
    last_error_class: str | None = None,
    last_error_msg: str | None = None,
    clear_error: bool = False,
    clear_install_record: bool = False,
) -> None:
    """Patch the install-state row. Only non-None fields are updated.

    SQL is built dynamically from the provided fields so the row's
    other columns retain their values across partial updates.

    ``clear_install_record`` (N-526 / punch 541) is the one way to write NULL.
    Because every other parameter uses None to mean "leave alone", there was NO
    way to un-set ``manifest_sha256`` / ``runtime_deps_path`` / ``installed_at``
    — so the removal funnel would have had to issue a raw UPDATE, and until it
    existed the operator's only route to correcting a stale row was hand-written
    SQL against the SQLCipher DB. An EXPLICIT flag, not a None-means-NULL
    overload, so a caller cannot clear a column by forgetting to pass it.
    """
    sets: list[str] = []
    params: list[Any] = []
    if clear_install_record:
        # PD-18: the 'installed' flag is SET on success across several paths, so
        # its CLEAR edge goes through one funnel that resets EVERY field the set
        # edge writes — a set-broad/clear-narrow flag silently lies (a row that
        # says not_installed while still naming a manifest sha and an
        # installed_at reads as "installed, mid-glitch" to every surface).
        sets.append("manifest_sha256 = NULL")
        sets.append("runtime_deps_path = NULL")
        sets.append("installed_at = NULL")
        sets.append("current_file = NULL")
        sets.append("progress_files_done = 0")
        sets.append("progress_files_total = 0")
        sets.append("progress_bytes_done = 0")
        sets.append("progress_bytes_total = 0")
        sets.append("attempt_count = 0")
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if install_method is not None:
        sets.append("install_method = ?")
        params.append(install_method)
    if manifest_sha256 is not None:
        sets.append("manifest_sha256 = ?")
        params.append(manifest_sha256)
    if runtime_deps_path is not None:
        sets.append("runtime_deps_path = ?")
        params.append(runtime_deps_path)
    if progress_files_done is not None:
        sets.append("progress_files_done = ?")
        params.append(int(progress_files_done))
    if progress_files_total is not None:
        sets.append("progress_files_total = ?")
        params.append(int(progress_files_total))
    if progress_bytes_done is not None:
        sets.append("progress_bytes_done = ?")
        params.append(int(progress_bytes_done))
    if progress_bytes_total is not None:
        sets.append("progress_bytes_total = ?")
        params.append(int(progress_bytes_total))
    if current_file is not None:
        sets.append("current_file = ?")
        params.append(current_file)
    if bump_attempt:
        sets.append("attempt_count = attempt_count + 1")
    if set_last_attempt_now:
        sets.append("last_attempt_at = ?")
        params.append(_now_iso())
    if set_installed_now:
        sets.append("installed_at = ?")
        params.append(_now_iso())
        # Reset attempt_count on success — the foundation docstring's
        # promise.
        sets.append("attempt_count = 0")
    if clear_error:
        sets.append("last_error_class = NULL")
        sets.append("last_error_msg = NULL")
        sets.append("last_error_at = NULL")
    if last_error_class is not None:
        sets.append("last_error_class = ?")
        params.append(last_error_class[:64])
        sets.append("last_error_at = ?")
        params.append(_now_iso())
    if last_error_msg is not None:
        sets.append("last_error_msg = ?")
        params.append(_scrub_error(last_error_msg))

    if not sets:
        return
    conn.execute(
        f"UPDATE embedding_bits_install_state SET {', '.join(sets)} "
        f"WHERE id = 1",
        params,
    )
    conn.commit()


def _emit_progress(
    callback: Callable[[dict], None] | None,
    payload: dict[str, Any],
) -> None:
    """Invoke a progress callback with a try/except guard.

    The UI router persists the payload to the DB row. We do NOT let a
    callback exception poison the install loop — log + continue.
    """
    if callback is None:
        return
    try:
        callback(dict(payload))
    except Exception:
        log.exception("install progress_callback raised; ignoring")


# ---------------------------------------------------------------------------
# Hashing + manifest loading
# ---------------------------------------------------------------------------

def _hash_file(path: Path) -> str:
    """Compute SHA-256 of a file on disk (streaming)."""
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def _manifest_sha256(manifest_path: Path) -> str:
    """Compute SHA-256 over the raw manifest JSON bytes.

    Used to fingerprint the manifest the install ran against; the
    admin re-verify path compares this against
    embedding_bits_install_state.manifest_sha256 to detect a drift
    (operator pulled a new image whose manifest differs from the
    one the install on disk was hash-built against).
    """
    return _hash_file(manifest_path)


def normalize_arch(machine: str | None = None) -> str:
    """Map ``platform.machine()`` to the manifest's arch key.

    x86_64 family (x86_64 / amd64 / AMD64 / x64) -> ``'x86_64'``;
    arm64 family (aarch64 / arm64 / ARM64) -> ``'aarch64'``. Raises on any
    other arch so the install fails LOUD rather than silently skipping the
    binary wheels (a silent skip would leave torch/tokenizers/etc. uninstalled
    and ``sentence_transformers`` un-importable with a confusing later error).
    THE SSOT for arch selection — used by ``_load_manifest`` and the manifest
    regenerator/completeness pin.
    """
    m = (machine or platform.machine() or "").lower()
    if m in ("x86_64", "amd64", "x64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    raise RuntimeError(
        f"embedding_bits: unsupported CPU arch {m!r}; the manifest ships "
        f"binary wheels for x86_64 + aarch64 only."
    )


def _load_manifest(
    manifest_path: Path, *, arch: str | None = None
) -> dict[str, Any]:
    """Load the manifest, resolving arch-specific binary wheels into ``wheels``.

    Manifest v2 (flat ``wheels`` only) loads unchanged. Manifest v3 (
    multi-arch) keeps the arch-NEUTRAL ``py3-none-any`` wheels in ``wheels``
    and the arch-SPECIFIC binary wheels (torch, tokenizers, safetensors,
    regex, scikit-learn, scipy, pillow, hf-xet) under
    ``wheels_by_arch.{x86_64,aarch64}``. This is the ONE resolution point:
    it merges the running arch's binary set into ``wheels`` so every
    downstream consumer (``_count_manifest_files`` / ``_install_common`` /
    ``_all_files_present_and_valid`` / ``reverify`` /
    ``_check_manifest_hashes_populated``) stays arch-unaware and validates /
    installs only THIS arch's wheels (so the other arch's entries — which may
    legitimately still carry placeholder hashes pre-release — never block the
    install we're actually running).
    """
    return _resolve_manifest_arch(
        _load_raw_manifest(manifest_path), arch=arch, label=manifest_path.name,
    )


def _load_raw_manifest(manifest_path: Path) -> dict[str, Any]:
    """The manifest exactly as the file holds it — arch NOT resolved.

    Punch 569: the set digest (:func:`manifest_set_digest`) is computed over
    every arch's wheels, so it must read the file before
    :func:`_resolve_manifest_arch` folds one arch into ``wheels``.
    """
    with manifest_path.open("r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest, dict):
        raise ValueError(f"manifest {manifest_path.name} is not a JSON object")
    return manifest


def _resolve_manifest_arch(
    raw: dict[str, Any], *, arch: str | None = None, label: str = "manifest",
) -> dict[str, Any]:
    """A COPY of ``raw`` with the running arch's binary wheels merged into
    ``wheels``. Never mutates ``raw``, so a caller can hold both views."""
    manifest = dict(raw)
    by_arch = raw.get("wheels_by_arch")
    if by_arch:
        key = normalize_arch(arch)
        arch_wheels = by_arch.get(key)
        if arch_wheels is None:
            raise RuntimeError(
                f"embedding_bits: manifest {label} declares "
                f"wheels_by_arch but has no entry for arch {key!r}; "
                f"available: {sorted(by_arch)}."
            )
        manifest["wheels"] = list(raw.get("wheels", [])) + list(arch_wheels)
    return manifest


def _check_manifest_hashes_populated(manifest: dict[str, Any]) -> None:
    """Refuse to run with a placeholder-hash manifest.

    The foundation commit ships a skeleton with PLACEHOLDER_*_SHA256
    strings. Running install_auto against that would download bytes,
    fail every hash check, and emit a wall of HashMismatch errors —
    clearer if we trip at the entry point.
    """
    for w in manifest.get("wheels", []):
        if "PLACEHOLDER" in str(w.get("sha256", "")):
            raise RuntimeError(
                f"Manifest entry {w.get('name')!r} has a placeholder "
                f"sha256. The release-cut process must run "
                f"scripts/build-embedding-bits-manifest.py to fill in "
                f"real hashes before an install can proceed."
            )
    for m in manifest.get("models", []):
        for f in m.get("files", []):
            if "PLACEHOLDER" in str(f.get("sha256", "")):
                raise RuntimeError(
                    f"Manifest model file {f.get('name')!r} has a "
                    f"placeholder sha256. Run "
                    f"scripts/build-embedding-bits-manifest.py."
                )


# ---------------------------------------------------------------------------
# Download primitives (auto path)
# ---------------------------------------------------------------------------

UA = "email-triage-installer/1.0"


def _http_download(url: str, dest: Path) -> int:
    """Stream ``url`` to ``dest`` and return the byte count.

    Atomic — writes to a sibling tempfile + renames. No partial
    files left behind on crash.

    Routes through the egress funnel (``egress_client`` /
    ``Intent.PUBLIC_FETCH``, run17 #5 — was a raw
    ``urllib.request.urlopen``). Streamed (``client.stream`` +
    ``iter_bytes(CHUNK)``) so a large binary is never buffered whole in
    memory; ``raise_for_status`` makes a non-2xx raise BEFORE any body is
    written (the old urllib.urlopen raised HTTPError the same way).
    """
    import httpx

    from email_triage._egress import Intent, egress_client

    dest.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    with tempfile.NamedTemporaryFile(
        delete=False, dir=str(dest.parent), prefix=".partial-",
    ) as tmp:
        tmp_path = Path(tmp.name)
        try:
            # follow_redirects=True preserves urllib.urlopen's default
            # redirect-following — model/wheel mirrors (HF, CDNs) routinely
            # 302 to a storage host. The funnel's SSRF hook re-runs on each
            # redirect hop, so this stays guarded.
            with egress_client(intent=Intent.PUBLIC_FETCH) as client:
                with client.stream(
                    "GET", url,
                    headers={"User-Agent": UA},
                    timeout=DOWNLOAD_TIMEOUT_SECS,
                    follow_redirects=True,
                ) as resp:
                    resp.raise_for_status()
                    for buf in resp.iter_bytes(CHUNK):
                        tmp.write(buf)
                        size += len(buf)
        except Exception:
            tmp.close()
            tmp_path.unlink(missing_ok=True)
            raise
    tmp_path.replace(dest)
    return size


def _fetch_with_retry(
    *,
    url: str,
    dest: Path,
    expected_sha256: str,
    filename: str,
) -> int:
    """Download ``url`` to ``dest`` and verify ``expected_sha256``.

    Retries up to len(RETRY_BACKOFF_SECS) times on network errors OR
    hash mismatches. The hash-mismatch retry is intentional: a flaky
    mirror can serve a partial file that decodes cleanly but hashes
    wrong; one retry usually clears it. After all retries: raises the
    final exception (HashMismatch or the network error).
    """
    import httpx

    last_exc: Exception | None = None
    for attempt, delay in enumerate(RETRY_BACKOFF_SECS):
        try:
            size = _http_download(url, dest)
            actual = _hash_file(dest)
            if actual != expected_sha256:
                raise HashMismatch(filename, expected_sha256, actual)
            return size
        # httpx.HTTPError = the run17 #5 funnel equivalent of the old
        # urllib.error.URLError (covers transport RequestError + a non-2xx
        # HTTPStatusError from _http_download's raise_for_status).
        except (httpx.HTTPError, HashMismatch, OSError) as e:
            last_exc = e
            # Don't sleep after the final attempt — we're about to raise.
            if attempt < len(RETRY_BACKOFF_SECS) - 1:
                log.warning(
                    "embedding_bits: fetch attempt failed, sleeping before retry",
                    extra={
                        "attempt": attempt + 1,
                        "error_type": type(e).__name__,
                        "seconds": delay,
                    },
                )
                time.sleep(delay)
            # Clean up partial file before retry so the next try starts
            # from scratch.
            dest.unlink(missing_ok=True)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# pip install
# ---------------------------------------------------------------------------

def _run_pip_install(
    *, wheels_dir: Path, target_dir: Path, wheel_names: list[str],
) -> None:
    """Invoke pip via subprocess to install the staged wheels.

    Why subprocess + the pip CLI (not pip's internal API): pip's
    internal API has NO stable interface — every minor version moves
    things around. The CLI is the supported surface.

    Flags:
      --no-index : refuse to contact PyPI. The wheels we want are all
                   in wheels_dir; anything pip wants beyond that is a
                   manifest gap we'd rather surface as an error than
                   silently fetch.
      --find-links wheels_dir : look here for the wheels.
      --prefix target_dir : land the installed packages under
                            target_dir/lib/pythonX.Y/site-packages.
                            We add that path to sys.path on next boot.
      --no-build-isolation : we're installing only pre-built wheels;
                             no PEP 517 backend invocation needed.

    WHY BARE REQUIREMENT NAMES, AND NOT EXPLICIT WHEEL PATHS OR ``--upgrade``
    (N-524, 2026-09-29). The obvious "make it actually replace things" fix is to
    pass ``str(wheels_dir / filename)`` instead of ``w["name"]``. Measured
    (pip 26.2.1 / CPython 3.13, scratch venv, these exact flags): with an
    explicit wheel path and no ``--ignore-installed``, pip tries to UNINSTALL the
    interpreter environment's own copy of the name — it printed "Attempting
    uninstall: packaging / Successfully uninstalled packaging-25.0" and left the
    venv with no ``packaging`` at all. ``--upgrade`` with bare names behaved the
    same way. In THIS container that environment is the image's ``/usr/local``,
    which is root-owned (``COPY --from=builder /install /usr/local``, before
    ``USER triage``), so the uninstall would hit EACCES and fail every install —
    and if the tree were ever writable it would delete the image's own package
    from the running layer. Three manifest names overlap the image's lock today
    (``jinja2``, ``packaging``, ``regex``), which is exactly the set that would
    be hit.

    The cost of bare names is that pip SKIPS those three ("Requirement already
    satisfied") and writes nothing for them into the prefix. That is accounted
    for, not ignored: :func:`environment_provided_versions` derives the skipped
    set per install and the marker records it separately, so the drift gate's
    arithmetic still adds up without ever passing a flag that reaches outside
    the prefix. Replacement inside the prefix is achieved by deleting the tree
    first (:func:`_prepare_prefix_for_install`) rather than by asking pip to
    uninstall.
    """
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        "--find-links", str(wheels_dir),
        "--prefix", str(target_dir),
        "--no-build-isolation",
        "--no-deps",  # we control transitives via the manifest
        "--disable-pip-version-check",
        "--isolated",  # punch 547: pip ignores PIP_* env + user config
        "--no-warn-script-location",
        *wheel_names,
    ]
    # Inherit the env vars set at module-import time (telemetry off,
    # pip version check off). subprocess inherits os.environ by default
    # so the setdefault calls at the top of this module propagate.
    proc = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        timeout=PIP_TIMEOUT_SECS,
        check=False,
    )
    if proc.returncode != 0:
        # Combine stderr + last 20 lines of stdout for context. Scrubbed
        # by _scrub_error before persistence.
        tail = "\n".join((proc.stdout or "").splitlines()[-20:])
        raise PipInstallError(
            f"pip exited {proc.returncode}: "
            f"stderr={proc.stderr or ''} stdout-tail={tail}"
        )


# ---------------------------------------------------------------------------
# REPLACE semantics + the post-install gate (N-524 / punch 539)
# ---------------------------------------------------------------------------

def _prepare_prefix_for_install(
    *, target_dir: Path, manifest: dict[str, Any],
) -> dict[str, int]:
    """Make the next install a REPLACE rather than an overlay. Returns counts.

    Three steps, each closing a measured hole in "re-install fixes it":

    1. **Remove the lib tree.** pip's ``--prefix`` run does not uninstall: a
       previous version's ``dist-info`` and its orphaned modules SURVIVE beside
       the new ones, so the prefix ends up holding two versions of a name and
       which one imports depends on path order. Wiping the tree first is what
       makes "one version per name" achievable at all.
    2. **Prune ``wheels/`` to exactly the manifest's filenames.** The installer
       hands pip BARE NAMES with ``--find-links wheels/``, so any leftover wheel
       from an older manifest is a candidate pip may legitimately resolve — a
       stale file could satisfy a name whose hash was never checked against the
       CURRENT manifest. After the prune, a bare name can only resolve to a file
       this manifest named and the staging step hash-verified.
    3. **Drop the install marker.** It describes the tree being deleted. Leaving
       it would let a FAILED install keep vouching for a wiped prefix, which is
       fail-open in the one direction that matters.

    ``hf-cache/`` is deliberately untouched: those are hash-verified model files,
    they are not on ``sys.path``, and re-downloading ~500 MB of weights is not
    part of replacing python packages.

    ``ignore_errors=True`` on the rmtree is deliberate here (unlike in
    :func:`remove_install`, which measures the post-state): a partial delete
    cannot pass silently, because the post-install scan then finds two versions
    of a name and :func:`write_installed_marker` refuses. The operator sees
    "the runtime prefix holds more than one version of …" rather than "could not
    delete", which is a less direct message for the same true refusal.
    """
    removed_trees = 0
    for name in ("lib", "Lib"):  # POSIX and Windows --prefix layouts
        tree = target_dir / name
        if tree.exists():
            shutil.rmtree(tree, ignore_errors=True)
            removed_trees += 1

    marker = installed_marker_path(target_dir)
    marker.unlink(missing_ok=True)

    keep = {
        str(w.get("filename") or "") for w in manifest.get("wheels", [])
    }
    keep.discard("")
    pruned = 0
    wheels_dir = target_dir / WHEELS_DIRNAME
    if wheels_dir.is_dir():
        for entry in sorted(wheels_dir.iterdir()):
            if entry.is_file() and entry.name not in keep:
                entry.unlink(missing_ok=True)
                pruned += 1
    log.info(
        "embedding_bits: prepared the runtime prefix for a replace install",
        extra={"_extra": {
            "removed_trees": removed_trees, "pruned_wheels": pruned,
        }},
    )
    return {"removed_trees": removed_trees, "pruned_wheels": pruned}


def _verify_and_record_install(
    *,
    target_dir: Path,
    manifest: dict[str, Any],
    manifest_sha256: str,
    raw_manifest: dict[str, Any] | None = None,
) -> tuple[bool, str, str]:
    """The ONE post-pip gate. Returns ``(ok, error_class, error_msg)``.

    ORDER IS THE POINT, and it is the opposite of the obvious one:

        pip → import probe → **write the marker** → add to ``sys.path``

    The marker is the LAST artifact a successful install produces. Written any
    earlier, a tree that fails the import probe would carry a valid record and
    every later gate — which trusts the marker — would read it as verified: the
    fail-open this whole change exists to close, re-created one function deeper.
    And nothing joins ``sys.path`` until there is a marker to justify it.

    Both install branches (the staged fast-path and the full download path) call
    this, so "installed" means the same thing on both (PD-5); before N-524 each
    carried its own copy of the verify block.
    """
    invalidate_runtime_ready_cache()
    import importlib as _il
    _il.invalidate_caches()
    # The strong probe (a real ``import sentence_transformers`` in a subprocess),
    # not the cheap find_spec: find_spec returns True when the package DIR
    # exists even if the package cannot import for want of a transitive — the
    # 2026-05-18 "No module named 'packaging'" regression with the gate saying
    # "imports successfully". One subprocess, 1-2 sec, paid once per install.
    ok, import_err = runtime_imports_cleanly(runtime_deps_path=target_dir)
    if not ok:
        return False, "PostInstallVerifyFailed", (
            f"sentence_transformers does not import: {import_err}. "
            f"Likely a manifest gap (missing transitive dep) or a "
            f"half-installed site-packages. Try [Re-install], or use "
            f"[Remove] to clear the runtime and start over."
        )
    try:
        record = write_installed_marker(
            target_dir=target_dir,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            raw_manifest=raw_manifest,
        )
    except RuntimeRecordError as exc:
        # A TYPED verification failure PROPAGATES as a failure (PD-8). It is
        # never read as "record absent, carry on": that is how an unverified
        # tree gets blessed.
        return False, "RuntimeRecordError", (
            f"the installed package set does not match this image's pinned "
            f"manifest, so the install is not recorded as verified: {exc}"
        )
    except OSError as exc:
        return False, "RuntimeRecordError", (
            f"could not write the install record into the runtime prefix "
            f"({type(exc).__name__}); refusing to report a verified install "
            f"with nothing recording what was installed."
        )
    log.info(
        "embedding_bits: recorded the installed runtime set",
        extra={"_extra": {
            "distributions": len(record.get("distributions") or {}),
            "provided_by_image": len(record.get("provided_by_image") or {}),
        }},
    )
    invalidate_runtime_ready_cache()
    if target_dir.resolve() == get_runtime_deps_path().resolve():
        # Only the LIVE prefix joins sys.path. The update funnel installs into
        # a staging prefix; it is live only after the swap (punch 569 D3).
        add_runtime_to_sys_path()
    return True, "", ""


# ---------------------------------------------------------------------------
# Already-installed fast-path
# ---------------------------------------------------------------------------

def _all_files_present_and_valid(
    *, manifest: dict[str, Any], target_dir: Path,
) -> bool:
    """True if every manifest file is on disk with the correct hash.

    Used by the idempotent fast-path: a second install_auto call
    against a target_dir that already has every file should be a
    no-op.
    """
    wheels_dir = target_dir / WHEELS_DIRNAME
    for w in manifest.get("wheels", []):
        p = wheels_dir / w["filename"]
        if not p.exists():
            return False
        if _hash_file(p) != w["sha256"]:
            return False
    for model in manifest.get("models", []):
        hf_dir = target_dir / HF_CACHE_DIRNAME / _model_hf_cache_dir(model)
        for f in model.get("files", []):
            # Preserve subdir structure in the model dir
            p = hf_dir / f["name"]
            if not p.exists():
                return False
            if _hash_file(p) != f["sha256"]:
                return False
    return True


# ---------------------------------------------------------------------------
# Public install API
# ---------------------------------------------------------------------------

async def install_auto(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None = None,
) -> InstallResult:
    """Download + hash-verify + pip-install the embedding stack.

    Hard-fails on any hash mismatch (no skip-hash option). Retries
    each file up to 3 times with exponential backoff. Updates the
    install_state row at every state transition.
    """
    return await asyncio.to_thread(
        _install_auto_sync,
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        progress_callback=progress_callback,
    )


def _install_auto_sync(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    return _install_common(
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        source_dir=None,
        method="auto",
        progress_callback=progress_callback,
    )


async def install_sideload(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    source_dir: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None = None,
) -> InstallResult:
    """Copy + hash-verify + pip-install from an operator-staged dir.

    ``source_dir`` must contain ``wheels/`` and a per-model
    ``hf-cache/<hf_cache_dir>/`` subtree (one per manifest ``models``
    entry, e.g. ``sentence-transformers_all-MiniLM-L6-v2/``) populated
    by scripts/download-embedding-bits.sh on a connected machine.

    Hash verification is IDENTICAL to the auto path — sideload does
    NOT trust the operator-staged files. A bit-corrupted tarball or
    a tampered air-gap drop trips the same HashMismatch refusal as
    a poisoned PyPI mirror.
    """
    return await asyncio.to_thread(
        _install_sideload_sync,
        conn=conn,
        manifest_path=manifest_path,
        source_dir=source_dir,
        target_dir=target_dir,
        progress_callback=progress_callback,
    )


def _install_sideload_sync(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    source_dir: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    return _install_common(
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        source_dir=source_dir,
        method="sideload",
        progress_callback=progress_callback,
    )


def _install_common(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    source_dir: Path | None,
    method: Literal["auto", "sideload"],
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    """Shared install pipeline for auto + sideload.

    The only difference between the two paths is the source of each
    file's bytes (HTTP fetch vs filesystem copy). Hash verify + pip
    invoke + state transitions are identical.
    """
    start = time.monotonic()
    clear_cancel()

    # N-549 defence in depth: never create or mark a runtime prefix inside a
    # directory that already holds something else. Checked before the first write.
    refusal = install_target_refusal(target_dir)
    if refusal:
        _update_state(
            conn,
            status="failed",
            install_method=method,
            bump_attempt=True,
            set_last_attempt_now=True,
            last_error_class="InstallTargetRefused",
            last_error_msg=refusal,
        )
        return InstallResult(
            status="failed",
            error_class="InstallTargetRefused",
            error_msg=refusal,
            duration_secs=time.monotonic() - start,
        )
    # A removal tombstone a crash left behind (N-543) is purged here: this runs
    # in the installer's worker thread, never on the DB writer.
    purge_removal_tombstones(target_dir)

    target_dir.mkdir(parents=True, exist_ok=True)
    wheels_dir = target_dir / WHEELS_DIRNAME
    wheels_dir.mkdir(parents=True, exist_ok=True)
    # Per-model hf-cache dirs are created in the staging loop (each model
    # lands under its own ``hf_cache_dir``); create the shared parent here.
    (target_dir / HF_CACHE_DIRNAME).mkdir(parents=True, exist_ok=True)

    try:
        raw_manifest = _load_raw_manifest(manifest_path)
        manifest = _resolve_manifest_arch(raw_manifest, label=manifest_path.name)
        _check_manifest_hashes_populated(manifest)
    except Exception as e:
        _update_state(
            conn,
            status="failed",
            install_method=method,
            bump_attempt=True,
            set_last_attempt_now=True,
            last_error_class=type(e).__name__,
            last_error_msg=_scrub_error(str(e)),
        )
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            duration_secs=time.monotonic() - start,
        )

    manifest_sha = _manifest_sha256(manifest_path)

    # Fast-path: if every wheel + model file is already on disk + hash-
    # valid, skip the slow download phase BUT still rerun pip-install +
    # the post-install verification. The 2026-05-18 bug this comment
    # used to lie about: pre-fix this block jumped straight to
    # ``status="installed"`` without ever calling ``_run_pip_install``,
    # so an operator clicking [Retry] after a failed-during-pip first
    # attempt (wheels staged, pip OOM'd) saw the state flip to
    # ``installed`` while ``/app/data/runtime-deps/lib/`` remained empty
    # and ``sentence_transformers`` still didn't import. Post-fix the
    # fast-path re-invokes pip + verifies the runtime is importable
    # before declaring installed; if the verify gate fails, status
    # flips to "failed" with a clear error.
    if _all_files_present_and_valid(
        manifest=manifest, target_dir=target_dir,
    ):
        log.info(
            "embedding_bits: all files already present + hash-valid; "
            "fast-path (still running pip + verify)",
        )
        _update_state(
            conn,
            status="installing",
            install_method=method,
            manifest_sha256=manifest_sha,
            runtime_deps_path=str(target_dir),
            current_file=None,
            bump_attempt=True,
            set_last_attempt_now=True,
            clear_error=True,
        )
        _emit_progress(progress_callback, {"status": "installing"})
        wheel_names = [w["name"] for w in manifest.get("wheels", [])]
        try:
            _prepare_prefix_for_install(
                target_dir=target_dir, manifest=manifest,
            )
            _run_pip_install(
                wheels_dir=target_dir / WHEELS_DIRNAME,
                target_dir=target_dir,
                wheel_names=wheel_names,
            )
        except Exception as e:  # noqa: BLE001
            _update_state(
                conn,
                status="failed",
                last_error_class=type(e).__name__,
                last_error_msg=_scrub_error(str(e)),
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": type(e).__name__,
            })
            return InstallResult(
                status="failed",
                error_class=type(e).__name__,
                error_msg=_scrub_error(str(e)),
                duration_secs=time.monotonic() - start,
            )
        # Verify pip actually wrote site-packages + sentence_transformers is
        # importable from the runtime path, THEN record what landed. Catches the
        # silent-no-op case where pip exits 0 but didn't install anything (all
        # packages already satisfied from the system interpreter). N-524 folded
        # both branches' copies of this block into one funnel.
        verified, err_class, err = _verify_and_record_install(
            target_dir=target_dir,
            manifest=manifest,
            manifest_sha256=manifest_sha,
            raw_manifest=raw_manifest,
        )
        if not verified:
            _update_state(
                conn,
                status="failed",
                last_error_class=err_class,
                last_error_msg=err,
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": err_class,
            })
            return InstallResult(
                status="failed",
                error_class=err_class,
                error_msg=err,
                duration_secs=time.monotonic() - start,
            )
        _update_state(
            conn,
            status="installed",
            install_method=method,
            manifest_sha256=manifest_sha,
            runtime_deps_path=str(target_dir),
            set_installed_now=True,
            current_file=None,
            clear_error=True,
        )
        _emit_progress(progress_callback, {"status": "installed"})
        return InstallResult(
            status="installed",
            files_installed=_count_manifest_files(manifest),
            duration_secs=time.monotonic() - start,
        )

    total_files = _count_manifest_files(manifest)
    total_bytes = _sum_manifest_bytes(manifest)

    _update_state(
        conn,
        status="downloading",
        install_method=method,
        manifest_sha256=manifest_sha,
        runtime_deps_path=str(target_dir),
        progress_files_done=0,
        progress_files_total=total_files,
        progress_bytes_done=0,
        progress_bytes_total=total_bytes,
        current_file=None,
        bump_attempt=True,
        set_last_attempt_now=True,
        clear_error=True,
    )
    _emit_progress(progress_callback, {
        "status": "downloading",
        "progress_files_total": total_files,
        "progress_bytes_total": total_bytes,
    })

    files_done = 0
    bytes_done = 0

    try:
        # 1. Wheels
        for w in manifest.get("wheels", []):
            if is_cancel_requested():
                raise InstallCancelled()
            dest = wheels_dir / w["filename"]
            _stage_one(
                source_dir=source_dir,
                source_subdir=WHEELS_DIRNAME,
                url=w.get("url", ""),
                dest=dest,
                expected_sha256=w["sha256"],
                filename=w["filename"],
            )
            files_done += 1
            bytes_done += int(w.get("size_bytes") or 0) or dest.stat().st_size
            _update_state(
                conn,
                current_file=w["filename"],
                progress_files_done=files_done,
                progress_bytes_done=bytes_done,
            )
            _emit_progress(progress_callback, {
                "status": "downloading",
                "current_file": w["filename"],
                "progress_files_done": files_done,
                "progress_files_total": total_files,
                "progress_bytes_done": bytes_done,
                "progress_bytes_total": total_bytes,
            })

        # 2. Model files
        for model in manifest.get("models", []):
            model_hf_dir = target_dir / HF_CACHE_DIRNAME / _model_hf_cache_dir(model)
            model_hf_dir.mkdir(parents=True, exist_ok=True)
            for f in model.get("files", []):
                if is_cancel_requested():
                    raise InstallCancelled()
                dest = model_hf_dir / f["name"]
                _stage_one(
                    source_dir=source_dir,
                    source_subdir=f"{HF_CACHE_DIRNAME}/{_model_hf_cache_dir(model)}",
                    url=f.get("url", ""),
                    dest=dest,
                    expected_sha256=f["sha256"],
                    filename=f["name"],
                )
                files_done += 1
                bytes_done += int(f.get("size_bytes") or 0) or dest.stat().st_size
                _update_state(
                    conn,
                    current_file=f"{model['name']}/{f['name']}",
                    progress_files_done=files_done,
                    progress_bytes_done=bytes_done,
                )
                _emit_progress(progress_callback, {
                    "status": "downloading",
                    "current_file": f"{model['name']}/{f['name']}",
                    "progress_files_done": files_done,
                    "progress_files_total": total_files,
                    "progress_bytes_done": bytes_done,
                    "progress_bytes_total": total_bytes,
                })

        # 3. Verify (after-the-fact full sweep — defence in depth; each
        #    file was already verified inline but a final pass catches
        #    e.g. an on-disk corruption between staging and pip-install)
        if is_cancel_requested():
            raise InstallCancelled()
        _update_state(conn, status="verifying", current_file=None)
        _emit_progress(progress_callback, {"status": "verifying"})
        for w in manifest.get("wheels", []):
            p = wheels_dir / w["filename"]
            actual = _hash_file(p)
            if actual != w["sha256"]:
                raise HashMismatch(w["filename"], w["sha256"], actual)
        for model in manifest.get("models", []):
            model_hf_dir = target_dir / HF_CACHE_DIRNAME / _model_hf_cache_dir(model)
            for f in model.get("files", []):
                p = model_hf_dir / f["name"]
                actual = _hash_file(p)
                if actual != f["sha256"]:
                    raise HashMismatch(f["name"], f["sha256"], actual)

        # 4. pip install
        if is_cancel_requested():
            raise InstallCancelled()
        _update_state(conn, status="installing", current_file=None)
        _emit_progress(progress_callback, {"status": "installing"})
        wheel_names = [w["name"] for w in manifest.get("wheels", [])]
        # REPLACE, not overlay — see _prepare_prefix_for_install. Runs AFTER the
        # staging + hash-verify loop above, so the wheels this prune keeps are
        # exactly the ones just verified against this manifest.
        _prepare_prefix_for_install(target_dir=target_dir, manifest=manifest)
        _run_pip_install(
            wheels_dir=wheels_dir,
            target_dir=target_dir,
            wheel_names=wheel_names,
        )

        # Point HF_HOME at the model cache so the embedding backend
        # finds the model files we just staged (each model under its own
        # ``hf_cache_dir``). The Containerfile sets this env var at image
        # build, but we also set it here so an installer-CLI invocation
        # outside the container (test runs) finds the models.
        os.environ["HF_HOME"] = str(target_dir / HF_CACHE_DIRNAME)  # forced (punch 547)

        # 5. Verify pip actually populated the runtime path, then record what
        # landed. Pip's exit 0 isn't enough — it can short-circuit on "already
        # satisfied" without writing anything. Both the import probe and the
        # dist-info-vs-manifest check live in the one funnel the fast-path also
        # calls, so "installed" means the same thing on both (N-524).
        verified, err_class, err = _verify_and_record_install(
            target_dir=target_dir,
            manifest=manifest,
            manifest_sha256=manifest_sha,
            raw_manifest=raw_manifest,
        )
        if not verified:
            _update_state(
                conn,
                status="failed",
                last_error_class=err_class,
                last_error_msg=err,
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": err_class,
            })
            return InstallResult(
                status="failed",
                error_class=err_class,
                error_msg=err,
                files_installed=total_files,
                bytes_downloaded=bytes_done,
                duration_secs=time.monotonic() - start,
            )

        # 6. Success
        _update_state(
            conn,
            status="installed",
            set_installed_now=True,
            current_file=None,
            clear_error=True,
            progress_files_done=total_files,
            progress_bytes_done=total_bytes,
        )
        _emit_progress(progress_callback, {
            "status": "installed",
            "progress_files_done": total_files,
            "progress_files_total": total_files,
            "progress_bytes_done": total_bytes,
            "progress_bytes_total": total_bytes,
        })
        return InstallResult(
            status="installed",
            files_installed=total_files,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )

    except InstallCancelled:
        _update_state(
            conn,
            status="not_installed",  # back to ready-to-retry state
            current_file=None,
            last_error_class="InstallCancelled",
            last_error_msg="Install cancelled by operator",
        )
        _emit_progress(progress_callback, {
            "status": "not_installed",
            "cancelled": True,
        })
        return InstallResult(
            status="cancelled",
            error_class="InstallCancelled",
            error_msg="Install cancelled by operator",
            files_installed=files_done,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )

    except Exception as e:  # noqa: BLE001
        err_class = type(e).__name__
        err_msg = str(e)
        _update_state(
            conn,
            status="failed",
            current_file=None,
            last_error_class=err_class,
            last_error_msg=err_msg,
        )
        _emit_progress(progress_callback, {
            "status": "failed",
            "last_error_class": err_class,
            "last_error_msg": _scrub_error(err_msg),
        })
        log.exception("embedding_bits install failed")
        return InstallResult(
            status="failed",
            error_class=err_class,
            error_msg=_scrub_error(err_msg),
            files_installed=files_done,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )


def _stage_one(
    *,
    source_dir: Path | None,
    source_subdir: str,
    url: str,
    dest: Path,
    expected_sha256: str,
    filename: str,
) -> None:
    """Materialise one manifest file at ``dest`` + verify the hash.

    Auto path (source_dir=None): downloads via _fetch_with_retry.
    Sideload path: copies from ``source_dir/source_subdir/<basename>``
    and then hash-checks.

    Either way, the file ends up at ``dest`` with verified bytes or
    the function raises.

    Fast-path: if ``dest`` already exists with the expected hash,
    return immediately (idempotent inner loop — relevant when a
    previous attempt got partway through, e.g. crashed mid-file 8 of
    18).
    """
    if dest.exists():
        try:
            if _hash_file(dest) == expected_sha256:
                return
        except OSError:
            pass
        # Stale partial / mismatched bytes — drop + re-stage.
        dest.unlink(missing_ok=True)

    if source_dir is None:
        # Auto path
        _fetch_with_retry(
            url=url, dest=dest,
            expected_sha256=expected_sha256, filename=filename,
        )
    else:
        # Sideload path
        # Last path component of the dest is the filename we look for
        # in source_dir; the source mirrors the dest layout.
        rel = dest.relative_to(dest.parent)
        src = source_dir / source_subdir / rel
        if not src.exists():
            raise FileNotFoundError(
                f"Sideload source missing: {src} (expected from the "
                f"operator-staged tarball — was scripts/download-"
                f"embedding-bits.sh run on a connected machine?)"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        actual = _hash_file(dest)
        if actual != expected_sha256:
            raise HashMismatch(filename, expected_sha256, actual)


def _count_manifest_files(manifest: dict[str, Any]) -> int:
    n = len(manifest.get("wheels", []))
    for model in manifest.get("models", []):
        n += len(model.get("files", []))
    return n


def _sum_manifest_bytes(manifest: dict[str, Any]) -> int:
    n = 0
    for w in manifest.get("wheels", []):
        n += int(w.get("size_bytes") or 0)
    for model in manifest.get("models", []):
        for f in model.get("files", []):
            n += int(f.get("size_bytes") or 0)
    return n


# ---------------------------------------------------------------------------
# Re-verify (no download)
# ---------------------------------------------------------------------------

def reverify(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
) -> InstallResult:
    """Re-hash every staged file against the current manifest.

    No downloads. Updates the install_state row on success/failure.
    Used by the admin [Re-verify] button to confirm the on-disk
    bytes still match what the installer wrote (catches bit-rot +
    operator-side tampering).
    """
    start = time.monotonic()
    try:
        raw_manifest = _load_raw_manifest(manifest_path)
        manifest = _resolve_manifest_arch(raw_manifest, label=manifest_path.name)
        _check_manifest_hashes_populated(manifest)
    except Exception as e:
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            duration_secs=time.monotonic() - start,
        )

    wheels_dir = target_dir / WHEELS_DIRNAME

    files_checked = 0
    try:
        for w in manifest.get("wheels", []):
            p = wheels_dir / w["filename"]
            if not p.exists():
                raise FileNotFoundError(
                    f"Missing staged wheel: {w['filename']}"
                )
            actual = _hash_file(p)
            if actual != w["sha256"]:
                raise HashMismatch(w["filename"], w["sha256"], actual)
            files_checked += 1
        for model in manifest.get("models", []):
            hf_dir = target_dir / HF_CACHE_DIRNAME / _model_hf_cache_dir(model)
            for f in model.get("files", []):
                p = hf_dir / f["name"]
                if not p.exists():
                    raise FileNotFoundError(
                        f"Missing staged model file: {f['name']}"
                    )
                actual = _hash_file(p)
                if actual != f["sha256"]:
                    raise HashMismatch(f["name"], f["sha256"], actual)
                files_checked += 1
        # N-524: the staged BYTES matching the manifest is not the same claim as
        # the INSTALLED SET matching it, and this function used to flip the row
        # to ``installed`` on the first claim alone — the "reverify never reads
        # manifest_sha256" half of the finding. A prefix holding the 2026-05-18
        # packages next to a freshly-staged 2026-09 wheel set would pass every
        # hash check above and be blessed as installed. Ask the same gate every
        # other consumer asks, and fail with a named class when it refuses.
        # Punch 569: EXACT match, not "may serve" — a stale_ok set is not this
        # image's set, however long it keeps serving.
        status = runtime_status(target_dir=target_dir, manifest_path=manifest_path)
        if not status.verified:
            raise RuntimeRecordError(
                f"the staged files match the manifest, but the INSTALLED set "
                f"does not: {status.reason}. Update the embedding runtime to "
                f"replace it, or remove it."
            )
        marker = read_installed_marker(target_dir) or {}
        if marker.get("schema") != INSTALLED_MARKER_SCHEMA:
            # Punch 569: a pre-569 marker carries no set version, so it could
            # never be stale_ok after the next non-security change. The tree was
            # just shown to be exactly this image's set; record it as such.
            write_installed_marker(
                target_dir=target_dir,
                manifest=manifest,
                manifest_sha256=_manifest_sha256(manifest_path),
                raw_manifest=raw_manifest,
            )
            invalidate_runtime_ready_cache()
        _update_state(
            conn,
            status="installed",
            set_installed_now=True,
            clear_error=True,
        )
        return InstallResult(
            status="installed",
            files_installed=files_checked,
            duration_secs=time.monotonic() - start,
        )
    except Exception as e:
        _update_state(
            conn,
            status="failed",
            last_error_class=type(e).__name__,
            last_error_msg=_scrub_error(str(e)),
        )
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            files_installed=files_checked,
            duration_secs=time.monotonic() - start,
        )


# ---------------------------------------------------------------------------
# Removal (N-526 / punch 541) — the ONE way the runtime install goes away
# ---------------------------------------------------------------------------

#: Statuses that mean an installer is working in the prefix right now. Removing
#: underneath a live install would race a running pip against an rmtree.
_IN_FLIGHT_STATUSES = ("downloading", "verifying", "installing")


#: A removal RENAMES the prefix to ``<name><infix><ns>`` beside it (atomic and
#: O(1) on one volume) and the tree is deleted afterwards, OFF the DB writer
#: thread (N-543 residual, db DB-539FC-4 / 539fc-db re-check (3)): an rmtree of
#: ~600 MB inside ``db_call`` held the single writer while the bounded queue
#: filled, after which ``submit_write`` sheds, so other users' ``@audit_emitter``
#: rows became gap-events. The tombstone is a SIBLING, never inside a prefix, so
#: the removal guard's layout check never reads one.
REMOVAL_TOMBSTONE_INFIX = ".removing-"


def removal_tombstones(target_dir: Path | None = None) -> list[Path]:
    """Every removal tombstone of ``target_dir`` (default: the runtime prefix)."""
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    parent = base.parent
    if not parent.is_dir():
        return []
    stem = base.name + REMOVAL_TOMBSTONE_INFIX
    return sorted(
        entry for entry in parent.iterdir()
        if entry.name.startswith(stem) and entry.is_dir() and not entry.is_symlink()
    )


def purge_removal_tombstones(target_dir: Path | None = None) -> list[str]:
    """Delete the removal tombstones of ``target_dir``; return the names removed.

    NEVER call this on the DB writer path (inside ``db_call``): that is the stall
    it exists to avoid, and ``tests/test_n543_deleter_before_witness_pin.py``
    fails if a ``db_call`` helper reaches it. Callers: the admin route (a
    ``to_thread`` task after the writer work returns), the CLI after
    :func:`remove_install`, and the installer's worker thread before it writes
    (so a tombstone a crash left behind is cleaned on the next install). A
    tombstone that survives (a held file) is logged, and the next call retries.
    """
    purged: list[str] = []
    for tomb in removal_tombstones(target_dir):
        # A name match is not an identity (devils-advocate, round 4): only a
        # tombstone holding nothing outside the runtime layout is deleted. Anything
        # else that happens to be named ``<prefix>.removing-*`` is left and logged.
        foreign = _foreign_entries(tomb)
        if foreign:
            log.warning(
                "embedding_bits: refusing to purge a removal tombstone that holds "
                "entries the installer never writes",
                extra={"_extra": {"tombstone": tomb.name, "foreign": foreign[:5]}},
            )
            continue
        shutil.rmtree(tomb, ignore_errors=True)
        if tomb.exists():
            log.warning(
                "embedding_bits: a removal tombstone could not be fully deleted; "
                "the next install or remove retries it",
                extra={"_extra": {"tombstone": tomb.name}},
            )
        else:
            purged.append(tomb.name)
    return purged


class RemoveInFlight(Exception):
    """Refused a removal because an install is in flight."""


class RemoveTargetRefused(Exception):
    """Refused a removal whose target is not positively a runtime prefix, or is
    or contains the database (N-549, punch 539 fold-check hipaa H539FC-9)."""


def _live_database_files(conn: sqlite3.Connection) -> list[Path]:
    """Every database file ``conn`` has open — the OBJECT, not the config value
    that is supposed to name it. Read from ``PRAGMA database_list`` positionally
    (``seq, name, file``): a keyed read of a SQLCipher row can raise (R44). An
    in-memory or temp database reports an empty name and is skipped. A failure
    here propagates, so the removal does not happen (fail closed)."""
    return [
        Path(row[2]) for row in conn.execute("PRAGMA database_list").fetchall()
        if row[2]
    ]


#: A wheel's ``*.data/data/`` files install relative to the prefix ROOT (pip's
#: data scheme is the prefix itself, so no install scheme names a directory for
#: them); ``share/`` is where they conventionally land. Listed once, here.
_WHEEL_DATA_TOPLEVEL = frozenset({"share"})


def runtime_prefix_layout() -> frozenset[str]:
    """Every top-level name a runtime prefix can hold, DERIVED rather than listed.

    * the installer's own writes: :data:`WHEELS_DIRNAME`,
      :data:`HF_CACHE_DIRNAME`, :data:`INSTALLED_MARKER_NAME`;
    * everything pip's ``--prefix`` run creates: the first path component of
      each directory the running interpreter's install schemes put under a
      prefix (purelib, platlib — ``lib64`` where ``platlibdir`` says so —
      include, scripts), across every non-user scheme, so the POSIX and Windows
      layouts are both covered (``lib``/``Lib``, ``bin``/``Scripts``,
      ``include``/``Include``);
    * :data:`_WHEEL_DATA_TOPLEVEL`.

    The N-549 guard refuses a marker-bearing target that holds anything else.
    """
    import sysconfig

    probe = Path(sys.prefix) / "_et_prefix_probe"
    names = {WHEELS_DIRNAME, HF_CACHE_DIRNAME, INSTALLED_MARKER_NAME}
    names |= _WHEEL_DATA_TOPLEVEL
    for scheme in sysconfig.get_scheme_names():
        if scheme.endswith("_user"):
            continue
        paths = sysconfig.get_paths(scheme=scheme, vars={
            "base": str(probe), "platbase": str(probe),
            "installed_base": str(probe), "installed_platbase": str(probe),
        })
        for value in paths.values():
            try:
                rel = Path(value).relative_to(probe)
            except ValueError:
                continue
            if rel.parts:
                names.add(rel.parts[0])
    return frozenset(names)


def _foreign_entries(resolved: Path) -> list[str]:
    """Top-level names in ``resolved`` outside :func:`runtime_prefix_layout`."""
    layout = runtime_prefix_layout()
    return sorted(entry.name for entry in resolved.iterdir() if entry.name not in layout)


def install_target_refusal(target_dir: Path) -> str:
    """Why the installer must NOT write into ``target_dir``, or "" when it may.

    Defence in depth for N-549 (devils-advocate, 539 fold-2 re-check): the
    installer writes :data:`INSTALLED_MARKER_NAME` into whatever prefix it is
    handed, and a marker is what the removal guard trusts. So the installer
    refuses a NON-default, non-empty target that holds anything outside
    :func:`runtime_prefix_layout`: it never marks a foreign directory (the
    backups, the certificates, the data volume). A target whose entries are all
    installer-layout names is admitted with or without a marker, so a retry after
    a failed download (``wheels/`` and ``hf-cache/`` but no marker yet) still
    works. The resolved :data:`DEFAULT_RUNTIME_DEPS` is always admitted.
    """
    resolved = target_dir.resolve()
    if resolved == Path(DEFAULT_RUNTIME_DEPS).resolve() or not resolved.exists():
        return ""
    if not resolved.is_dir():
        return f"the install target {target_dir} exists and is not a directory."
    foreign = _foreign_entries(resolved)
    if foreign:
        return (
            f"the install target {target_dir} already holds {len(foreign)} "
            f"entr{'y' if len(foreign) == 1 else 'ies'} the installer never writes "
            f"(for example {foreign[0]!r}); refusing to install into it."
        )
    return ""


def _refuse_unsafe_target(base: Path, conn: sqlite3.Connection) -> None:
    """The N-549 guard, db-sme's three-part shape (539fc-db §4b), checked before
    any delete and before any row write. Raises :class:`RemoveTargetRefused`.

    1. The target, resolved (``..`` and symlinks followed), must not be a live
       database file or any directory containing one.
    2. It must not be ``/``, ``/app`` or ``/app/data`` — the ancestors of
       :data:`DEFAULT_RUNTIME_DEPS`, derived rather than restated (R7b).
    3. It must be POSITIVELY a runtime prefix: the resolved
       :data:`DEFAULT_RUNTIME_DEPS` (admitted unconditionally, so a half-written
       install there can still be removed), or a directory holding a marker
       :func:`read_installed_marker` PARSES with a known schema AND nothing
       outside :func:`runtime_prefix_layout` (db DB-539F2-1: a marker FILE check
       admitted a backups directory holding an unparseable marker, a
       ``.db.enc`` and ``master_key.bin``). A deny-list alone loses the race, for the
       same reason a sentinel list does on ``build_sha``. The marker alone is not
       enough (hipaa 539 fold-2 re-check F1): the installer writes it into
       whatever prefix it is handed (``--target-dir``; until punch 547 also the
       ``EMBEDDING_BITS_RUNTIME_DEPS`` env var), so pointed at
       ``/app/data/backups`` a marker-only check would ``rmtree`` the
       encrypted backups, which the connection cannot see as database files.

    Needed because the target is not always the default: it can come from the
    CLI's typed ``--target-dir`` (the ``EMBEDDING_BITS_RUNTIME_DEPS`` env read was
    removed by punch 547), and ``rmtree(..., ignore_errors=True)`` deletes
    whatever it is handed.
    """
    # Arms 1 and 2 judge the RESOLVED object, so they run first: a symbolic link
    # to the database or the data volume is refused for THAT reason, the more
    # severe one. The link refusal still precedes every admission below.
    try:
        resolved = base.resolve()
    except (OSError, RuntimeError) as exc:  # a symlink loop raises here
        raise RemoveTargetRefused(
            f"refusing to remove {base}: its path cannot be resolved ({exc})."
        ) from exc
    for db_file in _live_database_files(conn):
        if _is_under(db_file.resolve(), resolved):
            raise RemoveTargetRefused(
                f"refusing to remove {base}: it is, or contains, the database file."
            )
    default = Path(DEFAULT_RUNTIME_DEPS)
    if resolved in {p.resolve() for p in default.parents}:
        raise RemoveTargetRefused(
            f"refusing to remove {base}: it is the data volume or one of its "
            f"parents."
        )
    if base.is_symlink():
        raise RemoveTargetRefused(
            f"refusing to remove {base}: it is a symbolic link. Renaming it would "
            f"move the link and leave the tree it points at on disk."
        )
    if resolved == default.resolve():
        return
    if read_installed_marker(resolved) is None:
        raise RemoveTargetRefused(
            f"refusing to remove {base}: it is not the runtime prefix "
            f"({DEFAULT_RUNTIME_DEPS}) and holds no readable {INSTALLED_MARKER_NAME} "
            f"of a known schema written by the installer."
        )
    foreign = _foreign_entries(resolved)
    if foreign:
        raise RemoveTargetRefused(
            f"refusing to remove {base}: it holds {INSTALLED_MARKER_NAME}, but "
            f"also {len(foreign)} top-level entr{'y' if len(foreign) == 1 else 'ies'} "
            f"the installer never writes (for example {foreign[0]!r}), so it is "
            f"not only a runtime prefix."
        )


def remove_install(
    *,
    conn: sqlite3.Connection,
    target_dir: Path | None = None,
) -> dict[str, Any]:
    """Delete the runtime prefix AND reset the install-state row. ONE step.

    THE ONE REMOVAL FUNNEL. Before it there was no supported way to remove the
    install at all: the tree is on a persistent volume that survives every image
    rebuild, and the row that describes it could only be corrected by a
    hand-written UPDATE against the SQLCipher DB — a live-DB write from outside
    the app, and (via the host bind mount) a root bypass of the container's own
    data safeguards. So "remove the stale packages" was not a thing the product
    could do, which is why 18 distributions from 2026-05-18 were still there.

    Both halves in one call, deliberately: a deleted tree with a row still
    saying ``installed`` reads as a broken install to every surface, and a reset
    row over a tree still on disk is the drift this release is closing. Callers
    (the CLI subcommand and the admin POST) add their own audit row through the
    audit-emitter SSOT — never a raw INSERT — and this function does no auditing
    itself, so it cannot fork the chain from two places.

    Refuses (raises :class:`RemoveTargetRefused`, N-549) BEFORE any delete and
    before any row write when the target is not positively a runtime prefix, or
    is or contains a live database file, or is ``/`` / ``/app`` / ``/app/data``:
    the target can come from the CLI's typed ``--target-dir`` (no longer from
    the environment, punch 547), and a wrong path must not turn this ``rmtree`` into
    deletion of the PHI store. Refuses (raises :class:`RemoveInFlight`) while an
    install is in flight.

    Returns a summary: ``removed`` (a tree was there and is now gone — measured
    AFTER the delete, never the pre-state), ``residual_tree`` (the delete was
    partial; files remain), ``sys_path_entries`` (entries dropped from the live
    ``sys.path``), ``restart_required`` (True when anything was already imported
    from the prefix — this function cannot un-import, so the operator is told).
    """
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    _refuse_unsafe_target(base, conn)
    state = get_install_status(conn)
    if update_in_progress():
        raise RemoveInFlight(
            "a runtime update is in flight; wait for it to finish before "
            "removing the runtime."
        )
    if str(state.get("status") or "") in _IN_FLIGHT_STATUSES:
        raise RemoveInFlight(
            f"an install is in flight (status={state.get('status')}); cancel it "
            f"and wait for it to settle before removing the runtime."
        )

    loaded_from_prefix = _modules_loaded_from(base)
    existed = base.exists()
    tombstone: Path | None = None
    if existed:
        # The whole prefix: lib/, wheels/, hf-cache/ and INSTALLED.json. Unlike
        # a refresh — which keeps the hash-verified model weights — removal means
        # the feature is being switched off, so the ~600 MB goes too. It is
        # RENAMED here (O(1), atomic on one volume) and deleted later, off the DB
        # writer, by purge_removal_tombstones (N-543). A failed rename raises:
        # nothing is moved and the row is not reset.
        tombstone = base.with_name(
            f"{base.name}{REMOVAL_TOMBSTONE_INFIX}{time.time_ns()}"
        )
        os.replace(base, tombstone)
    # ``existed`` is a PRE-state, so reporting it as "removed" would put a claim
    # in the audit row that the disk contradicts. Measure the POST-state.
    residual = base.exists()
    removed = existed and not residual
    dropped = remove_runtime_from_sys_path(base)
    invalidate_runtime_ready_cache()

    _update_state(
        conn,
        status="not_installed",
        clear_install_record=True,
        clear_error=True,
    )
    if residual:
        log.warning(
            "embedding_bits: the runtime prefix was only partly removed; "
            "files remain on the volume",
            extra={"_extra": {"sys_path_entries_dropped": len(dropped)}},
        )
    else:
        log.info(
            "embedding_bits: removed the runtime install",
            extra={"_extra": {
                "tree_existed": existed,
                "sys_path_entries_dropped": len(dropped),
                "restart_required": bool(loaded_from_prefix),
            }},
        )
    return {
        "removed": removed,
        "residual_tree": residual,
        "tombstone": tombstone.name if tombstone is not None else "",
        "sys_path_entries": dropped,
        "restart_required": bool(loaded_from_prefix),
        "loaded_modules": loaded_from_prefix,
    }


def _modules_loaded_from(prefix: Path) -> list[str]:
    """Top-level module names in ``sys.modules`` whose file lives under ``prefix``.

    Answers the question ``/proc/<pid>/maps`` cannot: that instrument lists
    loaded shared objects, so it is blind to a pure-Python import from the
    volume. A non-empty result means this process is already running code from
    the prefix and a restart is required to stop doing so.
    """
    try:
        prefix = prefix.resolve()
    except OSError:  # pragma: no cover — defensive
        return []
    out: set[str] = set()
    for name, mod in list(sys.modules.items()):
        if "." in name or mod is None:
            continue
        raw = getattr(mod, "__file__", None)
        if not raw:
            continue
        try:
            if _is_under(Path(raw).resolve(), prefix):
                out.add(name)
        except OSError:  # pragma: no cover — defensive
            continue
    return sorted(out)


# ---------------------------------------------------------------------------
# The atomic update (punch 569 D3) — the ONE way an installed runtime is replaced
#
# Stage the new set in a SIBLING prefix on the same volume (so a rename is
# atomic), verify it fully, then swap by two renames:
#
#     runtime-deps       -> runtime-deps.prev
#     runtime-deps.next  -> runtime-deps
#
# and ask the status funnel about the swapped prefix. Only an EXACT match
# deletes ``.prev``; anything else puts ``.prev`` back. Until the swap the old
# set keeps serving, so a failed download, a hash mismatch or a failed import
# probe changes nothing the app is using. Leftovers from a crash are resolved
# by :func:`recover_interrupted_update` at boot and before every update.
#
# Deletions here are RENAMES to the N-543 removal tombstone (O(1)); the bytes go
# later through :func:`purge_removal_tombstones`, off any DB writer.
# ---------------------------------------------------------------------------

STAGING_SUFFIX = ".next"
PREVIOUS_SUFFIX = ".prev"


def staging_prefix(base: Path | None = None) -> Path:
    """Where an update stages the new set: ``<prefix>.next``, a sibling."""
    b = base if base is not None else get_runtime_deps_path()
    return b.with_name(b.name + STAGING_SUFFIX)


def previous_prefix(base: Path | None = None) -> Path:
    """Where the old set waits during the swap: ``<prefix>.prev``."""
    b = base if base is not None else get_runtime_deps_path()
    return b.with_name(b.name + PREVIOUS_SUFFIX)


def _is_plain_dir(p: Path) -> bool:
    return p.is_dir() and not p.is_symlink()


def _retire(path: Path, base: Path) -> str:
    """Rename ``path`` to a removal tombstone of ``base``; return its name.
    Raises on failure — a caller that cannot retire must not carry on."""
    tomb = base.with_name(f"{base.name}{REMOVAL_TOMBSTONE_INFIX}{time.time_ns()}")
    os.replace(path, tomb)
    return tomb.name


def recover_interrupted_update(
    *, manifest_path: Path | None = None,
) -> list[str]:
    """Resolve what a crashed update left behind. Deterministic; renames only.

    * ``.prev`` present: the live prefix serves -> retire ``.prev`` (the swap
      finished); otherwise -> retire whatever is live and rename ``.prev`` back
      (the swap did not finish, or finished onto a set that does not serve).
    * ``.next`` present: it was never live -> retire it.

    A ``.prev`` / ``.next`` that is a symbolic link is left alone and logged:
    renaming a link moves the link, not the tree, and the purge never follows
    one. Returns the actions taken, as short path-free phrases.
    """
    live = get_runtime_deps_path()
    prev = previous_prefix(live)
    staging = staging_prefix(live)
    actions: list[str] = []
    for leftover in (prev, staging):
        if leftover.is_symlink():
            log.warning(
                "embedding_bits: an update leftover is a symbolic link; left alone",
                extra={"_extra": {"leftover": leftover.name}},
            )
    if _is_plain_dir(prev):
        status = runtime_status(manifest_path=manifest_path)
        if _is_plain_dir(live) and status.serving:
            actions.append(f"retired the previous set ({_retire(prev, live)})")
        else:
            if live.exists() and not live.is_symlink():
                actions.append(f"retired the unfinished live set ({_retire(live, live)})")
            os.replace(prev, live)
            actions.append("restored the previous set")
            invalidate_runtime_ready_cache()
    if _is_plain_dir(staging):
        actions.append(f"retired an unfinished staged set ({_retire(staging, live)})")
    if actions:
        log.warning(
            "embedding_bits: resolved an interrupted runtime update",
            extra={"_extra": {"actions": actions}},
        )
    return actions


def reconcile_interrupted_install_row(conn: sqlite3.Connection) -> str:
    """Boot: repair an install-state row a stopped process left behind.

    Panel B3 db F569-1(c) / DA F569-8. A just-started process has no installer
    worker, so an in-flight status (``downloading`` / ``verifying`` /
    ``installing``) is stale: left as it is, every later install, update and
    removal is refused as "already in flight" until someone edits the DB by
    hand. And a row naming ``<prefix>.next`` / ``<prefix>.prev`` names a tree
    that :func:`recover_interrupted_update` has just retired or renamed. Returns
    a short path-free phrase of what was repaired, or "" when nothing was.

    ASSUMES one app process per data volume (panel B3 DA fold-check R-b): a
    second worker booting against the same volume while the first installs
    would mark that live install ``failed``. the deploy host unit runs one process.
    """
    state = get_install_status(conn)
    status = str(state.get("status") or "")
    live = get_runtime_deps_path()
    named = str(state.get("runtime_deps_path") or "")
    leftover = {str(staging_prefix(live)), str(previous_prefix(live))}
    names_leftover = bool(named) and named in leftover
    in_flight = status in _IN_FLIGHT_STATUSES
    if not (in_flight or names_leftover):
        return ""
    kw: dict[str, Any] = {}
    done: list[str] = []
    if names_leftover:
        kw["runtime_deps_path"] = str(live)
        done.append("the install record named an update's staging prefix; it now names the live one")
    if in_flight:
        kw.update(
            status="failed", current_file=None,
            last_error_class="Interrupted",
            last_error_msg=(
                f"the app stopped while an install or update was {status}; "
                f"nothing is running now"
            ),
        )
        done.append(f"cleared an install record left {status} by a stopped process")
    _update_state(conn, **kw)
    return "; ".join(done)


def _seed_staging(live: Path, staging: Path) -> int:
    """Hard-link the live prefix's staged wheels and model files into the
    staging prefix, so an update downloads only what changed. Returns the count.

    Safe because the installer never writes a staged file IN PLACE: a file that
    fails its hash is unlinked and re-created (:func:`_stage_one`), a download
    lands by ``replace`` (:func:`_http_download`), and the prune unlinks
    (:func:`_prepare_prefix_for_install`) — each replaces the staging prefix's
    directory entry and leaves the live file's bytes alone. Every seeded file is
    re-hashed against the image's manifest by the install that follows. A copy
    is the fallback where a link is refused.
    """
    n = 0
    for sub in (WHEELS_DIRNAME, HF_CACHE_DIRNAME):
        src_root = live / sub
        if not _is_plain_dir(src_root):
            continue
        for src in sorted(src_root.rglob("*")):
            if src.is_symlink() or not src.is_file() or src.name.startswith(".partial-"):
                continue
            dst = staging / src.relative_to(live)
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)
            n += 1
    return n


@dataclass
class UpdateResult:
    """What :func:`update_runtime` did. ``status`` is ``updated`` or ``failed``;
    on ``failed`` the previous set is untouched and still in place."""

    status: Literal["updated", "failed"]
    error_class: str = ""
    error_msg: str = ""
    restart_required: bool = False
    loaded_modules: list[str] = field(default_factory=list)
    from_state: str = ""
    from_set_version: int | None = None
    to_set_version: int | None = None
    retired: list[str] = field(default_factory=list)


#: The exact words every surface uses when an update needs a restart (D4).
RESTART_MESSAGE = "restart the container to load the new runtime"

#: ``UpdateResult.error_class`` of an update that the AUTOMATIC caller asked to
#: defer (``defer_if_loaded``) and that found the runtime already loaded here.
DEFERRED_ERROR_CLASS = "DeferredRuntimeLoaded"

#: Held for the whole of :func:`update_runtime`. The row's in-flight status
#: is released by the install step BEFORE the swap, so the status alone would
#: let a removal or an install start mid-swap; every such caller also asks
#: :func:`update_in_progress`.
_update_lock = threading.Lock()


def update_in_progress() -> bool:
    return _update_lock.locked()


def update_runtime(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path | None = None,
    source_dir: Path | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    defer_if_loaded: bool = False,
) -> UpdateResult:
    """Stage, verify, swap, re-verify; roll back on any failure. Blocking.

    ``source_dir`` sideloads (air-gapped) instead of downloading; hash
    verification is identical either way. The caller holds the in-flight guard
    (the route flips the row to ``downloading`` under the DB lock first) and
    writes the audit rows; this function writes none, so the chain cannot fork
    from two places (PD-3).

    Reload (D4): if any package was already imported from the prefix, a Python
    process cannot unload it, so the swap sets :func:`restart_pending` and the
    result says :data:`RESTART_MESSAGE`; otherwise the lazy loader picks the
    new set up on next use.

    ``defer_if_loaded`` (operator ruling R1, 2026-10-25) is the AUTOMATIC caller's
    guard for a NON-security update: if this process has imported from the live
    prefix by the moment of the swap, nothing is swapped (the staged set is
    retired, the old set keeps serving) and the result is ``failed`` with
    :data:`DEFERRED_ERROR_CLASS`, so the restart-pending path is unreachable from
    the automatic caller for a non-security set. The caller pre-checks the same
    predicate; this closes the race between that check and the swap.
    """
    if not _update_lock.acquire(blocking=False):
        return UpdateResult(
            status="failed", error_class="UpdateInFlight",
            error_msg="an update is already running",
        )
    try:
        return _update_runtime_locked(
            conn=conn, manifest_path=manifest_path, source_dir=source_dir,
            progress_callback=progress_callback,
            defer_if_loaded=defer_if_loaded,
        )
    finally:
        _update_lock.release()


def _update_failed(
    result: UpdateResult,
    conn: sqlite3.Connection,
    live: Path,
    error_class: str,
    msg: str,
) -> UpdateResult:
    """Record a failed update on ``result`` and the row; the previous set is
    untouched. The row names the LIVE prefix, never the staging one."""
    result.status = "failed"
    result.error_class = error_class
    result.error_msg = _scrub_error(msg) or ""
    _update_state(
        conn,
        status="failed",
        runtime_deps_path=str(live),
        current_file=None,
        last_error_class=error_class,
        last_error_msg=msg,
    )
    return result


def _update_runtime_locked(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path | None,
    source_dir: Path | None,
    progress_callback: Callable[[dict], None] | None,
    defer_if_loaded: bool = False,
) -> UpdateResult:
    live = get_runtime_deps_path()
    staging = staging_prefix(live)
    prev = previous_prefix(live)
    mpath = manifest_path if manifest_path is not None else resolve_manifest_path()
    before = runtime_status(manifest_path=mpath)
    result = UpdateResult(
        status="failed",
        from_state=before.state,
        from_set_version=before.installed_set_version,
    )
    retired: list[str] = result.retired

    from functools import partial

    _fail = partial(_update_failed, result, conn, live)

    try:
        retired_names = recover_interrupted_update(manifest_path=mpath)
        retired.extend(retired_names)
        if staging.exists() or staging.is_symlink():
            return _fail(
                "UpdateStagingBusy",
                f"{staging.name} exists and could not be cleared; nothing changed.",
            )
        staging.mkdir(parents=True)
        if _is_plain_dir(live):
            _seed_staging(live, staging)
    except OSError as exc:
        return _fail("UpdateStagingFailed", f"could not prepare the staging prefix ({type(exc).__name__})")

    try:
        installed = _install_common(
            conn=conn,
            manifest_path=mpath,
            target_dir=staging,
            source_dir=source_dir,
            method="sideload" if source_dir is not None else "auto",
            progress_callback=progress_callback,
        )
    finally:
        # _install_common points HF_HOME at the staging cache; that path is gone
        # after the swap (or the retire). The live cache is the only right value
        # (punch 547: forced, never inherited).
        os.environ["HF_HOME"] = str(live / HF_CACHE_DIRNAME)
    if installed.status != "installed":
        if _is_plain_dir(staging):
            retired.append(_retire(staging, live))
        return _fail(
            installed.error_class or "UpdateInstallFailed",
            f"the new set did not install; the previous set is unchanged: "
            f"{installed.error_msg or installed.status}",
        )

    staged = runtime_status(target_dir=staging, manifest_path=mpath)
    if not staged.verified:
        retired.append(_retire(staging, live))
        return _fail(
            "StagedSetNotVerified",
            f"the staged set does not match this image's manifest: {staged.reason}",
        )

    loaded = _modules_loaded_from(live) if live.exists() else []
    if defer_if_loaded and loaded:
        retired.append(_retire(staging, live))
        return _fail(
            DEFERRED_ERROR_CLASS,
            "this process has already loaded the current runtime, so a swap now "
            "would pause embedding until a restart; nothing was swapped and the "
            "previous set keeps serving",
        )
    had_live = live.exists() or live.is_symlink()
    try:
        if had_live:
            os.replace(live, prev)
        try:
            os.replace(staging, live)
        except OSError:
            if had_live:
                os.replace(prev, live)
            raise
    except OSError as exc:
        if _is_plain_dir(staging):
            retired.append(_retire(staging, live))
        return _fail(
            "UpdateSwapFailed",
            f"the swap failed ({type(exc).__name__}); the previous set is in place",
        )

    invalidate_runtime_ready_cache()
    import importlib as _il
    _il.invalidate_caches()
    after = runtime_status(manifest_path=mpath)
    if not after.verified:
        # Roll back: the swapped prefix is not this image's set after all.
        if live.exists():
            retired.append(_retire(live, live))
        if had_live:
            os.replace(prev, live)
        invalidate_runtime_ready_cache()
        return _fail(
            "PostSwapVerifyFailed",
            f"the swapped set did not verify ({after.reason}); the previous set "
            f"was put back",
        )
    if had_live and prev.exists():
        retired.append(_retire(prev, live))
    if loaded:
        _mark_restart_pending()
    _update_state(
        conn,
        status="installed",
        runtime_deps_path=str(live),
        current_file=None,
        clear_error=True,
    )
    result.status = "updated"
    result.restart_required = bool(loaded)
    result.loaded_modules = loaded
    to_v = (read_installed_marker(live) or {}).get("set_version")
    result.to_set_version = to_v if isinstance(to_v, int) and not isinstance(to_v, bool) else None
    log.info(
        "embedding_bits: updated the runtime",
        extra={"_extra": {
            "from_state": result.from_state,
            "restart_required": result.restart_required,
            "retired": len(retired),
        }},
    )
    return result


# ---------------------------------------------------------------------------
# The update NOTICE (punch 569 D5/D6) — what every surface tells the admin
#
# The banner, the admin alert email, the daily health section and the card all
# say the same thing because they all read THIS (PD-5). Path-free and PHI-free:
# set versions, a security yes/no/unknown, advisory ids from the image's own
# manifest, and fixed sentences.
# ---------------------------------------------------------------------------

#: Where the [Update embedding runtime] button lives. A POST is not linkable,
#: so emails link to the page that carries it.
UPDATE_ACTION_PATH = "/config?tab=ai_backends#embedding-runtime-update"

#: Shown before the click when this process has already loaded the runtime.
UPDATE_PAUSE_NOTE = (
    "This app has already loaded the current runtime, so after the update "
    "embedding pauses until the container is restarted."
)


# ---------------------------------------------------------------------------
# Automatic update (operator decision 2026-10-25)
#
# The app replaces a stale or refused runtime itself (``web/embedding_update_
# runner.py`` is the ONE caller of :func:`update_runtime`; the boot-time first
# tick of its sweeper and the admin's click both go through it). This module
# only holds what the NOTICE needs to word itself truthfully: whether the
# auto-updater runs in this process, and the last failed attempt. Both are
# process-local mirrors, wired at boot (the lifespan sets the switch from
# ``config.embedding.auto_update`` and rehydrates the failure from its durable
# settings row), like :func:`restart_pending`.
# ---------------------------------------------------------------------------

_AUTO_UPDATE: bool | None = None
_auto_failure_lock = threading.Lock()
_auto_failure: dict[str, Any] | None = None


def configure_auto_update(enabled: bool | None) -> None:
    """Boot-wire the ``embedding.auto_update`` switch (``None`` = unset)."""
    global _AUTO_UPDATE
    _AUTO_UPDATE = None if enabled is None else bool(enabled)


def auto_update_enabled() -> bool:
    """Does this process update a stale runtime by itself?

    The config key's own default answers until the lifespan wires the
    configured value, so the default lives in ONE place
    (``EmbeddingConfig.auto_update``, R7b).
    """
    if _AUTO_UPDATE is not None:
        return _AUTO_UPDATE
    from email_triage.config import EmbeddingConfig

    return bool(EmbeddingConfig.auto_update)


def set_auto_update_failure(info: dict[str, Any] | None) -> None:
    """Mirror the last failed automatic attempt (``{"failures", "error_class"}``)
    for the notice; ``None`` clears it. Written by the runner on both edges."""
    global _auto_failure
    with _auto_failure_lock:
        _auto_failure = dict(info) if info else None


def auto_update_failure() -> dict[str, Any] | None:
    with _auto_failure_lock:
        return dict(_auto_failure) if _auto_failure else None


#: The deferral mirror (operator ruling R1, 2026-10-25). A NON-security ``stale_ok``
#: update is not applied while THIS process has already imported from the runtime
#: prefix: the swap would pause embedding until a human restarts the container,
#: which is operator intervention. The old set keeps serving and the update applies
#: at the next boot's first sweeper tick. The mirror lets every notice surface say
#: so; it is deliberately NOT rehydrated at boot (a fresh process has not loaded the
#: runtime, so it applies instead of waiting).
_auto_deferred: dict[str, Any] | None = None


def set_auto_update_deferred(info: dict[str, Any] | None) -> None:
    global _auto_deferred
    with _auto_failure_lock:
        _auto_deferred = dict(info) if info else None


def auto_update_deferred() -> dict[str, Any] | None:
    with _auto_failure_lock:
        return dict(_auto_deferred) if _auto_deferred else None


# --- Boot gate (panel T fold 2, DA SHOULD-A1; lead ruling: make the deferral converge) ---
#
# R1 defers a non-security ``stale_ok`` update when this process has already loaded the
# runtime. Left alone that races: the update tick starts ~20 s after boot while other
# sweepers (7-12 s) and the mail watchers can embed first, so on an active site the same
# deferral could recur at every boot. So at boot, when auto mode is on and the status is
# ``stale_ok``, the FIRST embedding load waits for the first auto-update decision (the
# first tick finishing, whatever it decides), and that tick runs without its warmup.
#
# Bounded: the load never waits longer than :data:`BOOT_UPDATE_GATE_CAP_SECS`. 900 s is
# 1.5x the 5-10 minutes the route docstring gives for the ~600 MB install: long enough that
# a normal update completes under the gate, short enough that a stuck or lease-starved
# sweeper cannot hold embedding off for long. Past the cap the old set serves (still
# verified) and a deferral is surfaced in-process (this module has no db handle); the
# funnel's deferral at the end of that download is the durable record and carries
# ``cause: boot-gate-timeout`` (panel T DA NOTE-A5).
#
# The wait is ASYNC (``embed_text`` polls) and never blocks the loop, because the tick that
# releases the gate runs on that same loop.
BOOT_UPDATE_GATE_CAP_SECS = 900.0
#: The in-process deferral mirror's target while the cap has ended the wait, and the
#: ``cause`` of the durable deferral that follows it.
BOOT_GATE_TIMEOUT = "boot-gate-timeout"

_boot_gate_lock = threading.Lock()
_boot_gate_armed_at: float | None = None


def arm_boot_update_gate() -> bool:
    """Arm the gate for this process: only when auto mode is on and the installed
    runtime is ``stale_ok`` (a refused set is never loaded; a current one needs no
    update). Called once by the lifespan. Returns whether it armed."""
    global _boot_gate_armed_at
    if not auto_update_enabled():
        return False
    try:
        armed = runtime_status().state == STATE_STALE_OK
    except Exception:  # noqa: BLE001 — a status read that raises arms nothing
        return False
    if not armed:
        return False
    with _boot_gate_lock:
        _boot_gate_armed_at = time.monotonic()
    return True


def boot_update_gate_pending() -> bool:
    with _boot_gate_lock:
        return _boot_gate_armed_at is not None


def release_boot_update_gate() -> None:
    """The first auto-update decision is made (or the process is stopping)."""
    global _boot_gate_armed_at
    with _boot_gate_lock:
        _boot_gate_armed_at = None


async def wait_for_boot_update_decision() -> bool:
    """Called before the first in-process load of the runtime. Returns immediately
    when the gate is not armed; otherwise waits (async, 0.25 s poll) until the first
    auto-update decision releases it. Returns ``True`` when the cap ended the wait
    (the old set then serves and a deferral is surfaced)."""
    while True:
        with _boot_gate_lock:
            armed_at = _boot_gate_armed_at
        if armed_at is None:
            return False
        if time.monotonic() - armed_at >= BOOT_UPDATE_GATE_CAP_SECS:
            release_boot_update_gate()
            set_auto_update_deferred({"target": BOOT_GATE_TIMEOUT, "count": 0})
            log.warning(
                "embedding runtime update did not decide within the boot gate cap; "
                "serving the installed runtime and recording a deferral",
                extra={"_extra": {"cap_secs": BOOT_UPDATE_GATE_CAP_SECS}},
            )
            return True
        await asyncio.sleep(0.25)


#: A deferral that has recurred this many boots, or has lasted this long, is escalated:
#: the daily health email flips to Attention and the admin is emailed (DA SHOULD-A1b).
DEFERRAL_ESCALATE_COUNT = 3
DEFERRAL_ESCALATE_DAYS = 7


def deferral_escalated(info: dict[str, Any] | None, *, now: float | None = None) -> bool:
    """Has this deferral recurred :data:`DEFERRAL_ESCALATE_COUNT` boots or lasted
    :data:`DEFERRAL_ESCALATE_DAYS` days? ``info`` is the durable ``deferred`` record
    (``count``, ``since``)."""
    if not info:
        return False
    count = info.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and count >= DEFERRAL_ESCALATE_COUNT:
        return True
    from email_triage._isotime import parse_iso_aware

    since = parse_iso_aware(info.get("since")) if info.get("since") else None
    if since is None:
        return False
    from datetime import datetime, timezone

    cur = datetime.fromtimestamp(now, timezone.utc) if now is not None else datetime.now(timezone.utc)
    return (cur - since).days >= DEFERRAL_ESCALATE_DAYS


#: A retired runtime kept as EVIDENCE of an integrity refusal is renamed from its
#: ``.removing-`` tombstone to this infix, so the routine tombstone purge (which matches
#: ``.removing-`` only) never deletes it. It stays on the data volume, beside the live
#: prefix, until an admin removes it (hipaa-sme NOTE-1).
EVIDENCE_INFIX = ".evidence-"


def keep_as_evidence(names: list[str], target_dir: Path | None = None) -> list[str]:
    """Rename the named removal tombstones of ``target_dir`` to evidence sets; return
    the new directory NAMES (path-free). A name that is not a plain tombstone
    directory is left alone."""
    base = target_dir if target_dir is not None else get_runtime_deps_path()
    kept: list[str] = []
    for name in names:
        if REMOVAL_TOMBSTONE_INFIX not in name:
            continue
        src = base.parent / name
        if not _is_plain_dir(src):
            continue
        dst = base.parent / name.replace(REMOVAL_TOMBSTONE_INFIX, EVIDENCE_INFIX, 1)
        try:
            os.replace(src, dst)
        except OSError:
            continue
        kept.append(dst.name)
    return kept


def wire_auto_update_from_site_config(path: str | Path | None = None) -> bool:
    """For a process that is NOT the app (the ``deploy.sh`` step-9b probe, a CLI):
    wire the switch from the SITE's config exactly as the running app reads it
    (``load_config`` with the same search order), so :func:`update_notice` words
    itself the way the app does. A config that cannot be loaded leaves the config
    key's own default and returns ``False``; never raises."""
    try:
        from email_triage.config import load_config

        configure_auto_update(load_config(path).embedding.auto_update)
        return True
    except Exception:  # noqa: BLE001 — informational callers must not fail on this
        return False


def deploy_notice_lines() -> list[str]:
    """The two machine lines ``scripts/deploy.sh`` step 9b reads from a fresh
    interpreter inside the new container: ``ET569:<headline or current>`` and
    ``ET569K:<kind or current>``. It wires the SITE's ``embedding.auto_update`` from
    the config first (:func:`wire_auto_update_from_site_config`, the same
    ``load_config`` search the running app uses), so a site with the switch off is
    told to click and a default site is told the app does it. In the product, not in
    the shell snippet, so it is testable without reading ``deploy.sh``."""
    wire_auto_update_from_site_config()
    n = update_notice()
    return [
        "ET569:" + (n["headline"] if n else "current"),
        "ET569K:" + (n["kind"] if n else "current"),
    ]


def _runtime_loaded_here() -> bool:
    """Has this process imported anything from the live prefix? Never raises."""
    try:
        return bool(_modules_loaded_from(get_runtime_deps_path()))
    except Exception:  # noqa: BLE001 — display hint only; the update's own
        return False      # scan still decides whether a restart is needed.


def _auto_update_notice(
    st: RuntimeStatus, *, versions: str,
) -> dict[str, Any]:
    """The notice while the app updates the runtime itself: no button, no click.

    ``kind`` is ``"auto"`` (the update is pending or running), ``"auto_failed"``
    (the last automatic attempt failed; the app retries by itself) or
    ``"auto_deferred"`` (a non-security update waits for the next restart). The sentence
    about what embedding does MEANWHILE is the same fail-closed fact the click
    notice states: a security change refuses the old set until the swap.
    """
    failure = auto_update_failure()
    deferred = auto_update_deferred() if st.state == STATE_STALE_OK else None
    tail = []
    if versions:
        tail.append(f"manifest {versions}")
    if st.security == SECURITY_FIX:
        tail.append("security fix")
    suffix = f" ({', '.join(tail)})" if tail else ""
    if st.state == STATE_STALE_OK:
        meanwhile = "The installed runtime keeps serving meanwhile."
    elif st.reason_token == "interpreter_mismatch":
        meanwhile = (
            "Embedding is switched off meanwhile: the installed runtime was built "
            "for a different Python version than this release runs, so it cannot "
            "load."
        )
    elif st.security == SECURITY_FIX:
        meanwhile = (
            "Embedding is switched off meanwhile: this release fixes a "
            "security problem in the embedding runtime, so the installed one "
            "is refused."
        )
    elif st.security == SECURITY_UNKNOWN:
        meanwhile = (
            "Embedding is switched off meanwhile: the installed runtime "
            "cannot show that this release's change is not a security fix, "
            "so it is refused."
        )
    else:
        meanwhile = (
            "Embedding is switched off meanwhile: the installed runtime "
            "could not be verified."
        )
    escalated = bool(deferred) and deferral_escalated(deferred)
    if deferred is not None:
        kind = "auto_deferred"
        headline = "Embedding runtime update waits for the next restart" + suffix
        consequence = (
            f"{meanwhile} This app has already loaded the installed runtime, and "
            "swapping it now would pause embedding until the container is "
            "restarted, so the update is applied by itself when the container "
            "next starts."
        )
        if BOOT_GATE_TIMEOUT in (deferred.get("cause"), deferred.get("target")):
            # Panel U DA S2: the durable cause must reach the operator, or the
            # once-per-start re-download on a slow link cannot be diagnosed.
            consequence += (
                " At the last start the download did not finish within the "
                f"{int(BOOT_UPDATE_GATE_CAP_SECS // 60)}-minute boot window (a slow "
                "link), so each start downloads it again."
            )
        if escalated:
            headline = "Embedding runtime update keeps being deferred" + suffix
            consequence += (
                " It has now been deferred "
                + (f"at {int(deferred.get('count') or 0)} starts" if (deferred.get('count') or 0) >= DEFERRAL_ESCALATE_COUNT
                   else f"for {DEFERRAL_ESCALATE_DAYS} days or more")
                + " running: restart the container when embedding can pause "
                "briefly, so the update is applied before anything loads the runtime."
            )
        failures, error_class = 0, ""
    elif failure is None:
        kind = "auto"
        headline = "Embedding runtime update in progress" + suffix
        consequence = (
            f"{meanwhile} The app installs this release's runtime by itself, "
            "so there is nothing to click."
        )
        failures, error_class = 0, ""
    else:
        kind = "auto_failed"
        headline = "Embedding runtime update failed, retrying" + suffix
        failures = int(failure.get("failures") or 0)
        error_class = str(failure.get("error_class") or "")
        consequence = (
            f"{meanwhile} The last automatic update failed"
            f" ({error_class or 'unknown error'}; {failures} "
            f"attempt{'s' if failures != 1 else ''} so far). The app tries "
            "again by itself; the failed attempt changed nothing."
        )
    return {
        "kind": kind,
        "headline": headline,
        "consequence": consequence,
        "pause_note": UPDATE_PAUSE_NOTE if _runtime_loaded_here() else "",
        "serving": st.serving,
        "security": st.security or SECURITY_UNKNOWN,
        "versions": versions,
        "advisories": list(st.advisories),
        "auto": True,
        "escalated": escalated,
        "failures": failures,
        "error_class": error_class,
        # STABLE across retries (no count, no time): the failure alert repeats on
        # its own cooldown, a changed reason is a new edge.
        "alert_reason": (
            f"{kind}:{st.state}:{st.reason_token}:{versions or 'unversioned'}"
        ),
    }


def update_notice(
    status: RuntimeStatus | None = None,
    *,
    restart: bool | None = None,
    auto: bool | None = None,
) -> dict[str, Any] | None:
    """The admin notice for the runtime's current state, or ``None``.

    ``kind`` is ``"update"`` (stale_ok or refused: show the button), or
    ``"restart"`` (an update finished under loaded packages: no button, say
    :data:`RESTART_MESSAGE`), or, while the app updates the runtime itself
    (``auto``, default :func:`auto_update_enabled`), ``"auto"`` / ``"auto_failed"``
    (no button: see :func:`_auto_update_notice`). ``alert_reason`` is STABLE
    across reads of the same state (no timestamps), because the admin alert fires
    again only when it changes: a stale_ok install that later meets a security
    release is a second email, a status re-read every minute is not.
    """
    restart = restart_pending() if restart is None else restart
    if restart:
        return {
            "kind": "restart",
            "headline": "Embedding runtime updated: restart required",
            "consequence": (
                f"The new embedding runtime is installed and verified. This "
                f"process had already loaded the old one, so embedding is "
                f"paused: {RESTART_MESSAGE}."
            ),
            "serving": False,
            "security": "",
            "versions": "",
            "advisories": [],
            "alert_reason": "restart_pending",
        }
    st = status if status is not None else runtime_status()
    if not st.update_required:
        return None
    versions = ""
    if st.installed_set_version is not None and st.image_set_version is not None:
        versions = f"v{st.installed_set_version} -> v{st.image_set_version}"
    auto_on = auto_update_enabled() if auto is None else auto
    # An INTEGRITY refusal is never healed by the app (hipaa-sme R3): even with
    # auto-update on it gets the click notice, worded for what it is.
    integrity_wait = bool(auto_on and st.integrity_refusal)
    if auto_on and not integrity_wait:
        return _auto_update_notice(st, versions=versions)
    tail = []
    if versions:
        tail.append(f"manifest {versions}")
    if st.security == SECURITY_FIX:
        tail.append("security fix")
    headline = "Embedding runtime update required" + (
        f" ({', '.join(tail)})" if tail else ""
    )
    if integrity_wait and st.reason_token == "manifest_unreadable":
        headline = "Embedding runtime check failed: the image's manifest could not be read"
        consequence = (
            "Embedding is switched off: this image's own manifest, the file every "
            "comparison starts from, could not be read (manifest_unreadable). The "
            "fault is in the image, not in the data volume, and the app cannot "
            "update the runtime from it by itself; redeploy a good image."
        )
    elif integrity_wait:
        headline = (
            "Embedding runtime refused: the installed files changed after they "
            f"were verified ({st.reason_token})"
        )
        consequence = (
            "Embedding is switched off. The installed runtime no longer matches "
            "the record made when it was verified, which may mean it was changed "
            "outside the app. The app does not replace it by itself, because "
            "that could destroy evidence of the change: check what changed (the "
            "runtime card on the AI Backends page names the packages, and the "
            "audit log records the detection), then update it to replace it with "
            "this release's runtime. The replaced files are kept for inspection."
        )
    elif st.state == STATE_STALE_OK:
        consequence = (
            "The installed runtime keeps serving until you update it: no "
            "change since it was installed is marked as a security fix."
        )
    elif st.security == SECURITY_FIX:
        consequence = (
            "Embedding is switched off: this release fixes a security problem "
            "in the embedding runtime, so the installed one is refused until "
            "you update it."
        )
    elif st.security == SECURITY_UNKNOWN:
        consequence = (
            "Embedding is switched off: the installed runtime cannot show that "
            "this release's change is not a security fix, so it is refused "
            "until you update it."
        )
    else:
        consequence = (
            "Embedding is switched off: the installed runtime could not be "
            "verified. Updating replaces it with this release's runtime."
        )
    return {
        "kind": "update",
        "headline": headline,
        "consequence": consequence,
        # Panel B3 DA F569-2: said BEFORE the click. A process that has already
        # imported the runtime cannot load the new one (D4), so the update
        # pauses embedding until a restart, even from a serving stale_ok.
        "pause_note": UPDATE_PAUSE_NOTE if _runtime_loaded_here() else "",
        "serving": st.serving,
        "security": st.security or SECURITY_UNKNOWN,
        "versions": versions,
        "advisories": list(st.advisories),
        # True only while the auto-updater is ON and the refusal is an integrity
        # one: the admin must act, and the alert is the urgent repeating one.
        "integrity_wait": integrity_wait,
        "integrity_token": st.reason_token if st.integrity_refusal else "",
        # What changed, bounded (package names and tokens, no path, no PHI): the
        # URGENT email prints it so the admin can judge before clicking (hipaa-sme
        # SHOULD-2); the install card shows the same reason.
        "integrity_reason": st.reason[:400] if integrity_wait else "",
        "alert_reason": (
            f"{st.state}:{st.reason_token}:{versions or 'unversioned'}"
        ),
    }


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "install_auto",
    "install_sideload",
    "get_install_status",
    "is_runtime_ready",
    "normalize_arch",
    "runtime_python_path",
    "runtime_site_packages_candidates",
    "runtime_imports_cleanly",
    "runtime_importable_probe",
    "add_runtime_to_sys_path",
    "remove_runtime_from_sys_path",
    "get_runtime_deps_path",
    "resolve_manifest_path",
    "request_cancel",
    "clear_cancel",
    "is_cancel_requested",
    "invalidate_runtime_ready_cache",
    "reverify",
    # N-524 install record / drift gate
    "canonical_dist_name",
    "scan_installed_distributions",
    "manifest_expected_versions",
    "environment_provided_versions",
    "installed_marker_path",
    "read_installed_marker",
    "write_installed_marker",
    "runtime_marker_status",
    "runtime_install_record",
    "INSTALLED_MARKER_NAME",
    "WHEELS_DIRNAME",
    "HF_CACHE_DIRNAME",
    "runtime_prefix_layout",
    "INSTALLED_MARKER_SCHEMA",
    "RuntimeRecordError",
    # Punch 569 set history + status funnel + restart flag
    "SET_CHANGES_KEY",
    "ManifestHistoryError",
    "SetChange",
    "manifest_set_digest",
    "manifest_models_digest",
    "reconcile_interrupted_install_row",
    "UPDATE_PAUSE_NOTE",
    "parse_set_changes",
    "dist_info_digests",
    "RuntimeStatus",
    "runtime_status",
    "runtime_status_memo",
    "STATE_NO_PREFIX",
    "STATE_OK",
    "STATE_STALE_OK",
    "STATE_REFUSED",
    "SERVING_STATES",
    "RuntimeRestartRequired",
    "restart_pending",
    "update_runtime",
    "update_in_progress",
    "recover_interrupted_update",
    "staging_prefix",
    "previous_prefix",
    "UpdateResult",
    "RESTART_MESSAGE",
    "DEFERRED_ERROR_CLASS",
    "SECURITY_FIX",
    "SECURITY_NONE",
    "SECURITY_UNKNOWN",
    "update_notice",
    "UPDATE_ACTION_PATH",
    # Automatic update (operator decision 2026-10-25)
    "configure_auto_update",
    "auto_update_enabled",
    "set_auto_update_failure",
    "auto_update_failure",
    "set_auto_update_deferred",
    "auto_update_deferred",
    "wire_auto_update_from_site_config",
    "deploy_notice_lines",
    "arm_boot_update_gate",
    "boot_update_gate_pending",
    "release_boot_update_gate",
    "wait_for_boot_update_decision",
    "BOOT_UPDATE_GATE_CAP_SECS",
    "BOOT_GATE_TIMEOUT",
    "DEFERRAL_ESCALATE_COUNT",
    "DEFERRAL_ESCALATE_DAYS",
    "deferral_escalated",
    "EVIDENCE_INFIX",
    "keep_as_evidence",
    "INTEGRITY_TOKENS",
    # N-526 removal funnel
    "remove_install",
    "removal_tombstones",
    "purge_removal_tombstones",
    "install_target_refusal",
    "REMOVAL_TOMBSTONE_INFIX",
    "RemoveInFlight",
    "RemoveTargetRefused",
    "InstallResult",
    "InstallCancelled",
    "HashMismatch",
    "PipInstallError",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_RUNTIME_DEPS",
]
