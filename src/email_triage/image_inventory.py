"""What the running image carries that no Python manifest declares (punch 734, 647, 848).

Three inventories for cve-arc, all served by ``GET /health/runtime-deps``:

* **OS packages (734).** The image's Debian packages from ``/var/lib/dpkg/status``:
  the AES in this image is Debian's libcrypto, linked dynamically and declared in
  no lock file, so an OpenSSL CVE pages nobody unless something lists it. Shape
  agreed with cve-arc 2026-10-15 (design_2026-10-15_os_packages_on_health_runtime_deps_for_cve_arc).
* **Vendored libraries (647).** pip copies 18 libraries into ``pip/_vendor``, and
  the stdlib's ``ensurepip/_bundled`` holds a whole pip wheel with its own copy.
  Neither has a ``*.dist-info``, so a CVE in a vendored ``urllib3`` is invisible
  to every distribution scan.
* **Bundled native libraries (848).** cryptography 50.0.1 statically linked
  OpenSSL 4.0.2 (CVE-2026-84782/84783), and the only record was the wheel's
  PEP 770 SBOM in ``cryptography-*.dist-info/sboms/``. Those components, and the
  libraries auditwheel or delvewheel graft into ``<name>.libs/`` or
  ``<package>/.libs/``, are listed under their carrier distribution. A separate key from ``vendored``, which cve-arc reads
  as PyPI: these rows are every ecosystem but PyPI (design_2026-11-04_bundled_runtime_deps_key_for_cve_arc).

IMPORTS NOTHING it inventories: every fact comes from a file read off disk, a
directory listing, or a wheel's zip index. A ``.libs`` library is read as BYTES
for its version and never loaded, ctypes-opened or executed. PATH-FREE: a
vendored carrier is named as ``<root label>/<path inside that root>`` (labels
``stdlib``, ``purelib``, ``platlib``, ``runtime``), a bundled carrier by its
distribution name, and an error carries the exception class and
``strerror`` only, never ``str(e)``, because an ``OSError`` string names the
absolute path. FAIL LOUD: an unreadable source is an explicit error field, never
an empty list or map that reads as "nothing installed".
"""
from __future__ import annotations

import csv
import json
import re
import stat
import struct
import sysconfig
import zipfile
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable

DPKG_STATUS = Path("/var/lib/dpkg/status")
OS_RELEASE = Path("/etc/os-release")

# dpkg install states, matched to cve-arc's own dpkg reader (design record):
# counted states are installed code; skipped states leave no code behind; any
# other state is listed as unstateable, which cve-arc reports as UNKNOWN.
_COUNTED_STATES = frozenset({"installed", "triggers-pending", "triggers-awaited"})
_SKIPPED_STATES = frozenset({"not-installed", "config-files"})
_SOURCE_RE = re.compile(r"(?P<name>\S+)(?:\s+\((?P<version>[^)\s]+)\))?")

# Carrier shapes the vendored reader understands: <root>/<pkg>/_vendor and
# <root>/<pkg>/_bundled/*.whl. A dir with one of the other names is reported in
# vendored_error as an unknown carrier, so it is seen rather than skipped.
VENDOR_DIR = "_vendor"
BUNDLED_DIR = "_bundled"
UNKNOWN_CARRIER_DIRS = ("vendored", "_vendored")
_PACKAGE_LINE = re.compile(r"^Package:", re.MULTILINE)
_LISTING_SKIP = frozenset({"__init__.py", "__pycache__", "vendor.txt", "bom.cdx.json"})


def _error_text(exc: BaseException) -> str:
    detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else ""
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


# ---------------------------------------------------------------------------
# OS packages (punch 734)
# ---------------------------------------------------------------------------

def _stanza_fields(stanza: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in stanza.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue  # a continuation line (Description, Conffiles) or junk
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def parse_dpkg_status(text: str) -> tuple[dict[str, dict[str, list[str]]], list[dict[str, str]]]:
    """``(os_packages, os_packages_unstateable)`` from a dpkg status file's text.

    Keyed by SOURCE package, since OSV's Debian advisories key on source. The
    version is what ``dpkg-query -W -f='${source:Version}'`` prints: the version
    in ``Source: name (ver)`` when present (so a binNMU binary ``5.2.37-2+b10``
    reports source ``5.2.37-2``), else the binary ``Version:``. Every version
    found is listed, never first-wins; cve-arc reports more than one as UNKNOWN.
    """
    found: dict[str, dict[str, set[str]]] = {}
    unstateable: list[dict[str, str]] = []
    for stanza in re.split(r"\n[ \t]*\n", text.replace("\r\n", "\n")):
        fields = _stanza_fields(stanza)
        package = fields.get("Package", "").split(":", 1)[0]
        if not package:
            continue
        status = fields.get("Status", "")
        words = status.split()
        state = words[-1] if words else ""
        if state in _SKIPPED_STATES:
            continue
        if state not in _COUNTED_STATES:
            unstateable.append({"package": package, "status": status})
            continue
        version = fields.get("Version", "")
        source = _SOURCE_RE.fullmatch(fields.get("Source", ""))
        name = source.group("name") if source else package
        src_version = (source.group("version") if source else None) or version
        entry = found.setdefault(name, {"versions": set(), "binaries": set()})
        entry["versions"].add(src_version)
        entry["binaries"].add(package)
    packages = {
        name: {"versions": sorted(e["versions"]), "binaries": sorted(e["binaries"])}
        for name, e in sorted(found.items())
    }
    return packages, sorted(unstateable, key=lambda r: r["package"])


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in ("ID", "VERSION_ID"):
            values[key.lower()] = value.strip().strip("\"'")
    return {"id": values.get("id", ""), "version_id": values.get("version_id", "")}


def os_package_inventory(
    *, status_path: Path = DPKG_STATUS, os_release_path: Path = OS_RELEASE,
) -> dict[str, Any]:
    """The four ``os_*`` keys of ``/health/runtime-deps``. Never raises.

    ``os_packages`` is ``{}`` only when the status file truly lists nothing
    installed; a missing or unreadable file gives ``os_packages: None`` and a
    non-null ``os_packages_error``.
    """
    errors: list[str] = []
    os_release: dict[str, str] | None = None
    packages: dict[str, Any] | None = None
    unstateable: list[dict[str, str]] | None = None
    try:
        os_release = parse_os_release(os_release_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 - reported, never raised
        errors.append(f"os-release unreadable ({_error_text(e)})")
    try:
        text = status_path.read_text(encoding="utf-8", errors="replace")
        if _PACKAGE_LINE.search(text):
            packages, unstateable = parse_dpkg_status(text)
        else:
            # Empty or not a dpkg status file: a real dpkg database keeps a stanza for
            # every package it ever held, so this is never "nothing installed".
            errors.append("dpkg status holds no Package: stanza")
    except Exception as e:  # noqa: BLE001 - reported, never raised
        errors.append(f"dpkg status unreadable ({_error_text(e)})")
    return {
        "os_release": os_release,
        "os_packages": packages,
        "os_packages_unstateable": unstateable,
        "os_packages_error": "; ".join(errors) or None,
    }


# ---------------------------------------------------------------------------
# Vendored libraries (punch 647)
# ---------------------------------------------------------------------------

def _inventory_row(carrier: str, name: str, version: Any, purl: Any, source: str) -> dict[str, Any]:
    return {
        "carrier": carrier,
        "name": name,
        "version": version if isinstance(version, str) and version else None,
        "purl": purl if isinstance(purl, str) and purl else None,
        "source": source,
    }


def _canonical_name(name: str) -> str:
    """The PEP 503 normalised name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _rows_from_bom(
    text: str, carrier: str, own: str | None, source: str = "bom.cdx.json",
) -> list[dict[str, Any]]:
    """The ONE CycloneDX ``components`` walker (PD-5): pip's vendored
    ``bom.cdx.json`` and a wheel's PEP 770 ``sboms/*.json`` both go through it.
    The document's own subject is skipped: the SBOM's ``metadata.component``,
    matched as the same component (``bom-ref``, else name + version + purl),
    never by name alone, and for the vendored path a component named ``own``
    (pip, with no version). A wheel's SBOM passes ``own=None``: lz4's wheel
    bundles the C library lz4, and a same-name skip would drop that row."""
    bom = json.loads(text)
    components = bom.get("components") if isinstance(bom, dict) else None
    if not isinstance(components, list):
        raise ValueError("SBOM has no components list")
    metadata = bom.get("metadata")
    subject = metadata.get("component") if isinstance(metadata, dict) else None
    own_name = _canonical_name(own) if own else None
    rows = []
    for comp in components:
        name = comp.get("name") if isinstance(comp, dict) else None
        if not isinstance(name, str) or not name or _canonical_name(name) == own_name:
            continue
        if isinstance(subject, dict) and _same_component(comp, subject):
            continue
        rows.append(_inventory_row(carrier, name, comp.get("version"), comp.get("purl"), source))
    return rows


def _same_component(comp: dict[str, Any], subject: dict[str, Any]) -> bool:
    """True when ``comp`` is the SBOM's own subject: the same ``bom-ref``, else
    the same canonical name and version, and the same purl when the subject
    names one. A same-name component at another version is a different thing."""
    ref = subject.get("bom-ref")
    if isinstance(ref, str) and ref:
        return comp.get("bom-ref") == ref
    name = subject.get("name")
    return (
        isinstance(name, str) and _canonical_name(comp["name"]) == _canonical_name(name)
        and comp.get("version") == subject.get("version")
        and (subject.get("purl") is None or comp.get("purl") == subject.get("purl"))
    )


def _rows_from_vendor_txt(text: str, carrier: str) -> list[dict[str, Any]]:
    rows = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue  # nested deps are indented; strip() keeps them as rows
        name, sep, version = line.partition("==")
        name = name.split("[", 1)[0].strip()
        rows.append(_inventory_row(carrier, name, version.strip() if sep else None, None, "vendor.txt"))
    return rows


def _name_versions(rows: list[dict[str, Any]]) -> set[str]:
    """``name==version`` with the name PEP 503-normalised, for comparing manifests."""
    return {f"{_canonical_name(r['name'])}=={r['version']}" for r in rows}


def _inventory_vendor_dir(
    carrier: str,
    own: str,
    read: Callable[[str], str | None],
    listing: Callable[[], list[str]],
    rows: list[dict[str, Any]],
    errors: list[dict[str, str]],
) -> None:
    """bom.cdx.json first, else vendor.txt, else the directory listing with
    ``version: None``. A manifest that exists but cannot be parsed is reported
    and the next source is tried, so one bad file never empties the carrier.

    When BOTH manifests parse, their ``{name, version}`` sets must agree (the
    carrier's own component excluded): a disagreement is reported in errors, so
    the inventory never depends silently on which file happened to be read."""
    parsed: dict[str, list[dict[str, Any]]] = {}
    for manifest, parse in (
        ("bom.cdx.json", lambda t: _rows_from_bom(t, carrier, own)),
        ("vendor.txt", lambda t: _rows_from_vendor_txt(t, carrier)),
    ):
        try:
            text = read(manifest)
            if text is not None:
                parsed[manifest] = parse(text)
        except Exception as e:  # noqa: BLE001 - reported, never raised
            errors.append({"carrier": f"{carrier}/{manifest}", "error": _error_text(e)})
    if len(parsed) == 2:
        bom, txt = (_name_versions(parsed[m]) for m in ("bom.cdx.json", "vendor.txt"))
        if bom != txt:
            errors.append({"carrier": carrier, "error": (
                "bom.cdx.json and vendor.txt disagree: only in bom "
                f"{sorted(bom - txt)}, only in vendor.txt {sorted(txt - bom)}")})
    listed = [
        name[:-3] if name.endswith(".py") else name for name in listing()
        if name not in _LISTING_SKIP and not name.endswith((".dist-info", ".pyi", ".typed"))
        and not name.upper().startswith(("README", "LICENSE"))
    ]
    chosen = next((m for m in ("bom.cdx.json", "vendor.txt") if m in parsed), None)
    if chosen is not None and (parsed[chosen] or not listed):
        rows.extend(parsed[chosen])
        return
    if chosen is not None:
        # A manifest naming nothing over a carrier that holds packages would be a
        # silent empty inventory (panel 647 MUST-1): report it, read the listing.
        errors.append({"carrier": carrier, "error": (
            f"{chosen} lists no package but the directory holds {len(listed)}; "
            "the listing was read instead")})
    rows.extend(_inventory_row(carrier, stem, None, None, "listing") for stem in listed)


def _exists_as(path: Path, kind: Callable[[int], bool]) -> bool:
    """``Path.is_dir`` / ``is_file`` swallow every OSError (python 3.14), so an
    unreadable entry would read as absent and the scan as clean. Only a missing
    entry is absent here; any other OSError raises for the caller to report."""
    try:
        return kind(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def _read_disk_file(path: Path, name: str) -> str | None:
    f = path / name
    return f.read_text(encoding="utf-8") if _exists_as(f, stat.S_ISREG) else None


def _list_disk_dir(path: Path, carrier: str, errors: list[dict[str, str]]) -> list[str]:
    try:
        return sorted(p.name for p in path.iterdir())
    except OSError as e:
        errors.append({"carrier": carrier, "error": _error_text(e)})
        return []


def _read_zip_member(
    zf: zipfile.ZipFile, names: set[str], prefix: str, name: str,
) -> str | None:
    return zf.read(prefix + name).decode("utf-8") if prefix + name in names else None


def _list_zip_dir(members: list[str], prefix: str) -> list[str]:
    return sorted({m[len(prefix):].split("/", 1)[0] for m in members
                   if m.startswith(prefix) and len(m) > len(prefix)})


def _inventory_disk_vendor_dir(
    carrier: str, own: str, path: Path,
    rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    _inventory_vendor_dir(
        carrier, own, partial(_read_disk_file, path),
        partial(_list_disk_dir, path, carrier, errors), rows, errors,
    )


def _inventory_wheel(
    carrier: str, whl: Path, rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    parts = whl.name[: -len(".whl")].split("-")
    if len(parts) >= 2:
        rows.append(_inventory_row(carrier, parts[0], parts[1],
                         f"pkg:pypi/{parts[0].lower()}@{parts[1]}", "wheel-filename"))
    else:
        errors.append({"carrier": carrier, "error": "wheel filename carries no version"})
    try:
        with zipfile.ZipFile(whl) as zf:
            members = zf.namelist()
            vendor_pkgs = sorted({
                PurePosixPath(m).parts[0] for m in members
                if len(PurePosixPath(m).parts) >= 3
                and PurePosixPath(m).parts[1] == VENDOR_DIR
                and not PurePosixPath(m).parts[0].endswith(".dist-info")
            })
            names = set(members)
            for pkg in vendor_pkgs:
                inner = f"{carrier}!{pkg}/{VENDOR_DIR}"
                prefix = f"{pkg}/{VENDOR_DIR}/"
                _inventory_vendor_dir(
                    inner, pkg, partial(_read_zip_member, zf, names, prefix),
                    partial(_list_zip_dir, members, prefix), rows, errors,
                )
    except Exception as e:  # noqa: BLE001 - reported, never raised
        errors.append({"carrier": carrier, "error": _error_text(e)})


def _scan_root(
    label: str, root: Path, rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    """Carriers at ``<root>/<pkg>/<carrier dir>``. An absent root is not an error
    (no runtime volume); an unreadable one is."""
    try:
        if not _exists_as(root, stat.S_ISDIR):
            return
        entries = sorted(root.iterdir())
    except OSError as e:
        errors.append({"carrier": label, "error": _error_text(e)})
        return
    for pkg in entries:
        if pkg.name.endswith(".dist-info") or pkg.name == "__pycache__":
            continue
        for child in (VENDOR_DIR, BUNDLED_DIR, *UNKNOWN_CARRIER_DIRS):
            path = pkg / child
            carrier = f"{label}/{pkg.name}/{child}"
            try:
                if not _exists_as(path, stat.S_ISDIR):
                    continue
            except OSError as e:
                errors.append({"carrier": carrier, "error": _error_text(e)})
                continue
            if child == VENDOR_DIR:
                _inventory_disk_vendor_dir(carrier, pkg.name, path, rows, errors)
            elif child == BUNDLED_DIR:
                try:
                    bundled = sorted(path.iterdir())
                except OSError as e:
                    errors.append({"carrier": carrier, "error": _error_text(e)})
                    continue
                for item in bundled:
                    if item.name.endswith(".whl"):
                        _inventory_wheel(f"{carrier}/{item.name}", item, rows, errors)
                    elif item.name not in _LISTING_SKIP:
                        errors.append({"carrier": f"{carrier}/{item.name}",
                                       "error": "unknown carrier shape"})
            else:
                errors.append({"carrier": carrier, "error": "unknown carrier shape"})


def image_roots() -> list[tuple[str, Path]]:
    paths = sysconfig.get_paths()
    roots = [("stdlib", Path(paths["stdlib"])), ("purelib", Path(paths["purelib"]))]
    if paths["platlib"] != paths["purelib"]:
        roots.append(("platlib", Path(paths["platlib"])))
    return roots


def scan_vendored(roots: list[tuple[str, Path]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for label, root in roots:
        _scan_root(label, root, rows, errors)
    return rows, errors


_IMAGE_MEMO: tuple[list[dict[str, Any]], list[dict[str, str]]] | None = None


def vendored_inventory(runtime_roots: list[Path]) -> dict[str, Any]:
    """The ``vendored`` / ``vendored_error`` keys of ``/health/runtime-deps``.

    The image part is read once per process (the image cannot change under a
    running container) and only memoised when it read cleanly; the runtime
    volume part is read on every call. Never raises: an unexpected failure gives
    ``vendored: None`` and names it in ``vendored_error``.
    """
    global _IMAGE_MEMO
    try:
        if _IMAGE_MEMO is None:
            scanned = scan_vendored(image_roots())
            if not scanned[1]:
                _IMAGE_MEMO = scanned
        else:
            scanned = _IMAGE_MEMO
        rows, errors = list(scanned[0]), list(scanned[1])
        more_rows, more_errors = scan_vendored(_runtime_labelled(runtime_roots))
        return {"vendored": rows + more_rows, "vendored_error": errors + more_errors}
    except Exception as e:  # noqa: BLE001 - reported, never raised
        return {"vendored": None, "vendored_error": [{"carrier": "*", "error": _error_text(e)}]}


def _runtime_labelled(runtime_roots: list[Path]) -> list[tuple[str, Path]]:
    return [(f"runtime{i}" if i else "runtime", r) for i, r in enumerate(runtime_roots)]


# ---------------------------------------------------------------------------
# Bundled native libraries (punch 848)
# ---------------------------------------------------------------------------

DIST_INFO_SUFFIX = ".dist-info"
SBOM_DIR = "sboms"
LIBS_SUFFIX = ".libs"
_PYPI_PURL = "pkg:pypi/"
# auditwheel renames a grafted library to <name>-<8 hex of its hash><rest>
# (libgomp-a34b3233.so.1.0.0); the hash is dropped so the name is the library's.
# A library grafted twice carries two (numpy 2.5.2 in the prod image:
# libgfortran-83c28eba-468e71e5.so.5.0.0); every trailing hash is dropped, or the
# name changes per build and a banner-table library loses its banner read.
_AUDITWHEEL_HASH = re.compile(r"(?P<name>.+?)(?:-[0-9a-f]{8})+(?=\.|$)")
_SONAME_ABI = re.compile(r"\.so\.(?P<abi>\d+(?:\.\d+)*)$")

# ONE reviewed table: library-name prefix -> the banner that library's own
# source compiles in. Never a generic "anything that looks like a version" scan:
# that emits false versions, and cve-arc range-matches binary_banner rows. A
# prefix matches only where the name does not go on with a name character, so
# "libz" is not "libzstd" and "libssl" is not NSS's "libssl3".
_OPENSSL_BANNER = re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)")
BANNERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("libssl", _OPENSSL_BANNER),
    ("libcrypto", _OPENSSL_BANNER),
    ("libpq", re.compile(rb"PostgreSQL (\d+(?:\.\d+)+)")),
    # zlib-ng in compat mode prints "deflate 1.3.1.zlib-ng": the version must end
    # at whitespace, or zlib-ng would be read as zlib 1.3.1 and range-matched.
    ("libz", re.compile(rb"(?:de|in)flate (\d+\.\d+(?:\.\d+)*)(?=\s)")),
)
# A .libs file can be tens of MB: it is streamed in chunks that overlap by more
# than the longest banner, and read no further than the cap.
BANNER_READ_CAP = 64 * 1024 * 1024
_BANNER_CHUNK = 1024 * 1024
_BANNER_OVERLAP = 256

_ELF_MAGIC = b"\x7fELF"
_PT_LOAD, _PT_DYNAMIC = 1, 2
_DT_NULL, _DT_STRTAB, _DT_SONAME = 0, 5, 14
_ELF_READ_LIMIT = 1024 * 1024  # bound on any one header or table read


def _bundled_row(row: dict[str, Any], carrier_version: str | None,
                 version_source: str | None) -> dict[str, Any]:
    """The one place a ``bundled`` row is built. Its ``carrier`` is the PEP 503
    name on every shape (``Pillow.libs`` is ``pillow``, ``scikit_learn`` is
    ``scikit-learn``, a no-owner stem too): cve-arc keys findings on it. A
    ``bundled_error`` carrier stays raw, since it names what is on disk."""
    return {
        "source": row["source"],
        "name": row["name"],
        "version": row["version"],
        "version_source": version_source,
        "purl": row["purl"],
        "carrier": _canonical_name(row["carrier"]),
        "carrier_version": carrier_version,
    }


def _dist_info_carrier(dirname: str) -> tuple[str, str | None]:
    """``(name, version)`` from ``<name>-<version>.dist-info``, split on the last ``-``."""
    stem = dirname[: -len(DIST_INFO_SUFFIX)]
    name, sep, version = stem.rpartition("-")
    return (name, version) if sep and name and version else (stem, None)


def _names_library(name: str, prefix: str) -> bool:
    # "-" continues a name too: libz-ng (zlib-ng) is not libz.
    return re.match(re.escape(prefix) + r"(?![A-Za-z0-9_-])", name) is not None


def _banner_versions(f: BinaryIO, pattern: re.Pattern[bytes]) -> tuple[set[str], bool]:
    """``(versions, over_cap)``: every distinct version ``pattern`` finds in the
    first ``BANNER_READ_CAP`` bytes. A match counts in the buffer where it STARTS
    before the carried tail; one starting in the tail is read whole from the next
    buffer, so a banner cut by a chunk edge is neither lost nor read short. Past
    the cap the last tail is not read, since its banner may be cut."""
    f.seek(0)
    found: set[str] = set()
    tail, read = b"", 0
    while read < BANNER_READ_CAP:
        chunk = f.read(min(_BANNER_CHUNK, BANNER_READ_CAP - read))
        if not chunk:
            break
        read += len(chunk)
        buf = tail + chunk
        cut = max(len(buf) - _BANNER_OVERLAP, 0)
        found.update(m.group(1).decode("ascii") for m in pattern.finditer(buf) if m.start() < cut)
        tail = buf[cut:]
    over_cap = read >= BANNER_READ_CAP and bool(f.read(1))
    if not over_cap:
        found.update(m.group(1).decode("ascii") for m in pattern.finditer(tail))
    return found, over_cap


def _elf_soname(f: BinaryIO) -> str | None:
    """The ``DT_SONAME`` of an ELF file, parsed from its bytes through the
    program headers (what the loader reads, so it survives stripped section
    headers). ``None`` for a file that is not ELF (a delvewheel DLL), has no
    dynamic segment, names no SONAME, or whose headers do not hold together.
    Every unpacked offset is unsigned and ``vaddr <= strtab`` guards the one
    subtraction, so no offset is negative; an offset the OS refuses raises
    OSError; the caller reports it per file. It raises rather than return
    ``None``, so a crafted file never reads as a normal file with no SONAME."""
    f.seek(0)
    head = f.read(64)
    if head[:4] != _ELF_MAGIC or len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2):
        return None
    end = "<" if head[5] == 1 else ">"
    try:
        if head[4] == 2:  # ELF64
            (phoff,) = struct.unpack_from(end + "Q", head, 32)
            phentsize, phnum = struct.unpack_from(end + "HH", head, 54)
            phdr, dyn, keep = struct.Struct(end + "IIQQQQQQ"), struct.Struct(end + "qQ"), (0, 2, 3, 5)
        else:  # ELF32
            (phoff,) = struct.unpack_from(end + "I", head, 28)
            phentsize, phnum = struct.unpack_from(end + "HH", head, 42)
            phdr, dyn, keep = struct.Struct(end + "8I"), struct.Struct(end + "iI"), (0, 1, 2, 4)
        if phentsize < phdr.size:
            return None
        f.seek(phoff)
        table = f.read(min(phentsize * phnum, _ELF_READ_LIMIT))
        # (p_type, p_offset, p_vaddr, p_filesz) per program header
        segments = [tuple(phdr.unpack_from(table, i * phentsize)[k] for k in keep)
                    for i in range(len(table) // phentsize)]
        dynamic = next((s for s in segments if s[0] == _PT_DYNAMIC), None)
        if dynamic is None:
            return None
        f.seek(dynamic[1])
        raw = f.read(min(dynamic[3], _ELF_READ_LIMIT))
        tags: dict[int, int] = {}
        for i in range(len(raw) // dyn.size):
            tag, value = dyn.unpack_from(raw, i * dyn.size)
            if tag == _DT_NULL:
                break
            tags.setdefault(tag, value)
        if _DT_SONAME not in tags or _DT_STRTAB not in tags:
            return None
        strtab = tags[_DT_STRTAB]  # a virtual address: map it through the PT_LOAD segments
        offset = next((off + strtab - vaddr for kind, off, vaddr, size in segments
                       if kind == _PT_LOAD and vaddr <= strtab < vaddr + size), None)
        if offset is None:
            return None
        f.seek(offset + tags[_DT_SONAME])
        return f.read(4096).split(b"\0", 1)[0].decode("ascii", "replace") or None
    except (struct.error, ValueError, OverflowError):
        return None


def _libs_file_version(path: Path, name: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    """``(version, version_source, problems)`` from a library's BYTES only: it is
    never loaded, ctypes-opened or executed (loading runs its constructors). A
    banner from the one reviewed table first; several distinct banners leave the
    version null and say so, never pick one. Else the ELF SONAME's ABI number,
    which cve-arc shows as a hint and never range-matches. Else nothing."""
    pattern = next((p for prefix, p in BANNERS if _names_library(name, prefix)), None)
    problems: list[str] = []
    with path.open("rb") as f:
        if pattern is not None:
            versions, over_cap = _banner_versions(f, pattern)
            if over_cap:
                problems.append(f"banner scan stopped at the {BANNER_READ_CAP}-byte read cap")
            if len(versions) > 1:
                problems.append(f"several version banners {sorted(versions)}; version left null")
                return None, None, tuple(problems)
            if versions:
                return versions.pop(), "binary_banner", tuple(problems)
        soname = _elf_soname(f)
    abi = _SONAME_ABI.search(soname) if soname else None
    if abi:
        return abi.group("abi"), "soname", tuple(problems)
    return None, None, tuple(problems)


# Per file, keyed by (size, mtime_ns, inode), so /health/runtime-deps does not
# re-read an unchanged runtime-volume library on every call; the inode catches a
# file replaced in place with the same size and mtime. A failed read is not kept.
_LIBS_CACHE: dict[str, tuple[tuple[int, int, int], tuple[str | None, str | None, tuple[str, ...]]]] = {}


def _cached_libs_version(path: Path, name: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    st = path.stat()
    key = (st.st_size, st.st_mtime_ns, st.st_ino)
    hit = _LIBS_CACHE.get(str(path))
    if hit is not None and hit[0] == key:
        return hit[1]
    result = _libs_file_version(path, name)
    _LIBS_CACHE[str(path)] = (key, result)
    return result


def _scan_sboms(
    carrier: str, carrier_version: str | None, sboms: Path,
    rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    """Every ``*.json`` in a dist-info's ``sboms/`` as CycloneDX; every component
    but PyPI ones is a row (no purl is not provably PyPI). One unreadable SBOM is
    an error and the others are still read."""
    for item in _list_disk_dir(sboms, f"{carrier}/{SBOM_DIR}", errors):
        where = f"{carrier}/{SBOM_DIR}/{item}"
        if not item.endswith(".json"):
            errors.append({"carrier": where, "error": "not a .json SBOM; not read"})
            continue
        try:
            found = _rows_from_bom(
                (sboms / item).read_text(encoding="utf-8"), carrier, None, "dist-info-sbom",
            )
        except Exception as e:  # noqa: BLE001 - reported, never raised
            errors.append({"carrier": where, "error": _error_text(e)})
            continue
        rows.extend(
            _bundled_row(r, carrier_version, "sbom" if r["version"] else None)
            for r in found if not (r["purl"] or "").lower().startswith(_PYPI_PURL)
        )


def _in_package_libs_owners(
    entries: list[Path], errors: list[dict[str, str]],
) -> dict[str, list[tuple[str, str | None]]]:
    """``{package: [(dist name, version), ...]}`` for every ``<package>/.libs/``
    a dist-info's RECORD lists. An older auditwheel, and delvewheel, put grafted
    libraries inside the package, whose import name is not the distribution's
    (``sklearn/.libs`` is scikit-learn's), so RECORD is what names the carrier."""
    owners: dict[str, list[tuple[str, str | None]]] = {}
    for entry in entries:
        if not entry.name.endswith(DIST_INFO_SUFFIX):
            continue
        dist = _dist_info_carrier(entry.name)
        try:
            # Uncached by decision (DA, 2026-11-04): every RECORD in a root that holds a
            # <package>/.libs is read; 173 RECORDs (3.80 MB) took 174 ms, in a worker thread.
            text = _read_disk_file(entry, "RECORD") or ""
        except Exception as e:  # noqa: BLE001 - reported, never raised
            errors.append({"carrier": f"{dist[0]}/RECORD", "error": _error_text(e)})
            continue
        parts = (PurePosixPath(row[0]).parts for row in csv.reader(text.splitlines()) if row)
        for package in sorted({p[0] for p in parts if len(p) > 2 and p[1] == LIBS_SUFFIX}):
            owners.setdefault(package, []).append(dist)
    return owners


def _scan_libs(
    name: str, where: str, libs: Path, owners: list[tuple[str, str | None]], no_owner: str,
    rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    """One row per file in a ``.libs`` dir, carried by its one owning dist-info.
    No owner, or several, leaves ``carrier_version`` null and says so."""
    carrier, carrier_version = owners[0] if len(owners) == 1 else (name, None)
    if not owners:
        errors.append({"carrier": name, "error": no_owner})
    elif len(owners) > 1:
        errors.append({"carrier": name, "error": (
            f"several dist-info name this carrier: {sorted(f'{n}-{v}' for n, v in owners)}")})
    for item in _list_disk_dir(libs, where, errors):
        path = libs / item
        hashed = _AUDITWHEEL_HASH.match(item)
        name = hashed.group("name") if hashed else item
        try:
            if not _exists_as(path, stat.S_ISREG):
                errors.append({"carrier": f"{where}/{item}", "error": "not a regular file"})
                continue
            version, version_source, problems = _cached_libs_version(path, name)
        except Exception as e:  # noqa: BLE001 - reported, never raised; the row stays
            version, version_source, problems = None, None, (_error_text(e),)
        rows.append(_bundled_row(
            _inventory_row(carrier, name, version, None, "auditwheel-libs"),
            carrier_version, version_source,
        ))
        errors.extend({"carrier": f"{where}/{item}", "error": p} for p in problems)


def _scan_bundled_root(
    label: str, root: Path, rows: list[dict[str, Any]], errors: list[dict[str, str]],
) -> None:
    """``<root>/*.dist-info/sboms/``, ``<root>/<name>.libs/`` (auditwheel, carried
    by the dist-info of the same PEP 503 name) and ``<root>/<package>/.libs/``
    (older auditwheel and delvewheel, carried by the dist-info whose RECORD lists
    it). An absent root is not an error (no runtime volume); an unreadable one is."""
    try:
        if not _exists_as(root, stat.S_ISDIR):
            return
        entries = sorted(root.iterdir())
    except OSError as e:
        errors.append({"carrier": label, "error": _error_text(e)})
        return
    dist_versions: dict[str, set[str]] = {}
    for entry in entries:
        if entry.name.endswith(DIST_INFO_SUFFIX):
            name, version = _dist_info_carrier(entry.name)
            if version:
                dist_versions.setdefault(_canonical_name(name), set()).add(version)
    in_package: dict[str, list[tuple[str, str | None]]] | None = None
    for entry in entries:
        if entry.name.endswith(DIST_INFO_SUFFIX):
            carrier, carrier_version = _dist_info_carrier(entry.name)
            sboms = entry / SBOM_DIR
            if _is_dir_or_report(sboms, f"{carrier}/{SBOM_DIR}", errors):
                if carrier_version is None:
                    errors.append({"carrier": carrier, "error": "dist-info name carries no version"})
                _scan_sboms(carrier, carrier_version, sboms, rows, errors)
        elif entry.name.endswith(LIBS_SUFFIX):
            if _is_dir_or_report(entry, entry.name, errors):
                name = entry.name[: -len(LIBS_SUFFIX)]
                owners = [(name, v) for v in sorted(dist_versions.get(_canonical_name(name), ()))]
                _scan_libs(name, entry.name, entry, owners, "no dist-info names this carrier",
                           rows, errors)
        elif entry.name != "__pycache__":
            where = f"{entry.name}/{LIBS_SUFFIX}"
            if _is_dir_or_report(entry / LIBS_SUFFIX, where, errors):
                if in_package is None:  # read every RECORD once, and only for this shape
                    in_package = _in_package_libs_owners(entries, errors)
                _scan_libs(entry.name, where, entry / LIBS_SUFFIX, in_package.get(entry.name, []),
                           "no dist-info RECORD lists this .libs dir", rows, errors)


def _is_dir_or_report(path: Path, carrier: str, errors: list[dict[str, str]]) -> bool:
    try:
        return _exists_as(path, stat.S_ISDIR)
    except OSError as e:
        errors.append({"carrier": carrier, "error": _error_text(e)})
        return False


def scan_bundled(roots: list[tuple[str, Path]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for label, root in roots:
        _scan_bundled_root(label, root, rows, errors)
    return rows, errors


_BUNDLED_IMAGE_MEMO: tuple[list[dict[str, Any]], list[dict[str, str]]] | None = None


def bundled_inventory(runtime_roots: list[Path]) -> dict[str, Any]:
    """The ``bundled`` / ``bundled_error`` keys of ``/health/runtime-deps``.

    Same contract as :func:`vendored_inventory`: the image part is read once per
    process and memoised only when it read cleanly, the runtime volume part on
    every call (its libraries through the per-file cache). Never raises: an
    unexpected failure gives ``bundled: None`` and names it in ``bundled_error``.
    """
    global _BUNDLED_IMAGE_MEMO
    try:
        if _BUNDLED_IMAGE_MEMO is None:
            scanned = scan_bundled(image_roots())
            if not scanned[1]:
                _BUNDLED_IMAGE_MEMO = scanned
        else:
            scanned = _BUNDLED_IMAGE_MEMO
        rows, errors = list(scanned[0]), list(scanned[1])
        more_rows, more_errors = scan_bundled(_runtime_labelled(runtime_roots))
        return {"bundled": rows + more_rows, "bundled_error": errors + more_errors}
    except Exception as e:  # noqa: BLE001 - reported, never raised
        return {"bundled": None, "bundled_error": [{"carrier": "*", "error": _error_text(e)}]}
