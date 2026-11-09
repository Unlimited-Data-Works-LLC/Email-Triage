"""Punch 734 (dpkg OS packages), 647 (vendored libraries) and 848 (bundled
native libraries) readers.

The dpkg cases follow the design record's required tests: every ``Source:``
form, the binNMU case, each install state and the missing-file error. The
vendored cases cover each carrier shape, each manifest fallback, the unreadable
tree both ways, and that nothing in the payload names a filesystem path. The
bundled cases run the shared cve-arc acceptance fixture (cryptography 50.0.1's
real SBOMs), each fail-loud path both ways, and the byte-only version read on a
synthetic ELF built in the test.
"""
from __future__ import annotations

import errno
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest

from email_triage import image_inventory as ii

STATUS = """\
Package: bash
Status: install ok installed
Version: 5.2.37-2+b10
Source: bash (5.2.37-2)
Description: GNU Bourne Again SHell
 a continuation line: Source: not-a-field (9.9)

Package: libssl3t64
Status: hold ok installed
Architecture: amd64
Version: 3.5.4-1~deb13u1
Source: openssl

Package: openssl
Status: install ok triggers-pending
Version: 3.5.4-1~deb13u1

Package: zlib1g:amd64
Status: install ok triggers-awaited
Version: 1:1.3.dfsg+really1.3.1-1+b1
Source: zlib (1:1.3.dfsg+really1.3.1-1)

Package: zlib-old
Status: install ok installed
Version: 1:1.2.13.dfsg-1
Source: zlib (1:1.2.13.dfsg-1)

Package: gone
Status: deinstall ok config-files
Version: 1.0

Package: never
Status: unknown ok not-installed

Package: broken
Status: install reinstreq half-installed
Version: 2.0

Package: halfway
Status: install ok unpacked
Version: 3.0
"""


def test_dpkg_status_is_source_keyed_with_source_versions():
    packages, unstateable = ii.parse_dpkg_status(STATUS)
    assert packages == {
        "bash": {"versions": ["5.2.37-2"], "binaries": ["bash"]},
        "openssl": {"versions": ["3.5.4-1~deb13u1"], "binaries": ["libssl3t64", "openssl"]},
        "zlib": {
            "versions": ["1:1.2.13.dfsg-1", "1:1.3.dfsg+really1.3.1-1"],
            "binaries": ["zlib-old", "zlib1g"],
        },
    }
    assert unstateable == [
        {"package": "broken", "status": "install reinstreq half-installed"},
        {"package": "halfway", "status": "install ok unpacked"},
    ]


def test_nothing_installed_is_an_empty_map_and_no_error(tmp_path):
    status = tmp_path / "status"
    status.write_text("Package: gone\nStatus: deinstall ok config-files\n")
    osr = tmp_path / "os-release"
    osr.write_text('ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian"\n')
    inv = ii.os_package_inventory(status_path=status, os_release_path=osr)
    assert inv == {
        "os_release": {"id": "debian", "version_id": "13"},
        "os_packages": {},
        "os_packages_unstateable": [],
        "os_packages_error": None,
    }


@pytest.mark.parametrize("text", ["", "not a dpkg database\n"], ids=["empty", "garbage"])
def test_an_empty_or_garbage_status_file_is_an_error_never_an_empty_map(tmp_path, text):
    status = tmp_path / "status"
    status.write_text(text)
    inv = ii.os_package_inventory(status_path=status, os_release_path=tmp_path / "none")
    assert inv["os_packages"] is None and inv["os_packages_unstateable"] is None
    assert "dpkg status holds no Package: stanza" in inv["os_packages_error"]


def test_a_missing_status_file_is_an_error_never_an_empty_map(tmp_path):
    inv = ii.os_package_inventory(
        status_path=tmp_path / "no-such-status", os_release_path=tmp_path / "no-os-release",
    )
    assert inv["os_packages"] is None and inv["os_packages_unstateable"] is None
    assert inv["os_release"] is None
    err = inv["os_packages_error"]
    assert err and "dpkg status unreadable" in err and "os-release unreadable" in err
    assert tmp_path.name not in err and "no-such-status" not in err


@pytest.mark.skipif(
    not (shutil.which("dpkg-query") and ii.DPKG_STATUS.is_file()),
    reason="needs a Debian-family host (the image check runs on the deploy host)",
)
def test_the_parse_matches_dpkg_query_on_this_host():
    """The design record's parity check: the parse equals dpkg-query's own
    ``${source:Package} ${source:Version}`` for every installed package."""
    out = subprocess.run(
        ["dpkg-query", "-W", "-f=${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"],
        capture_output=True, text=True, check=True,
    ).stdout
    expected: dict[str, set[str]] = {}
    for line in out.splitlines():
        name, version, abbrev = line.split("\t")
        # ${db:Status-Abbrev} char 2: i installed, t triggers-pending, W triggers-awaited.
        if abbrev[1:2] in ("i", "t", "W"):
            expected.setdefault(name, set()).add(version)
    packages, _ = ii.parse_dpkg_status(ii.DPKG_STATUS.read_text(encoding="utf-8"))
    assert {k: set(v["versions"]) for k, v in packages.items()} == expected


# ---------------------------------------------------------------------------
# Vendored libraries (647)
# ---------------------------------------------------------------------------

BOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {"bom-ref": "bom-ref:pip", "name": "pip", "type": "library"},
        {"name": "urllib3", "version": "1.26.20", "purl": "pkg:pypi/urllib3@1.26.20"},
        {"name": "setuptools", "version": "70.3.0", "purl": "pkg:pypi/setuptools@70.3.0"},
    ],
}
VENDOR_TXT = "CacheControl[filecache]==0.14.3\n  msgpack==1.1.1  # nested\nsix; python_version<'4'\n"


def _carrier(root: Path, pkg: str, **files: str) -> Path:
    d = root / pkg / "_vendor"
    d.mkdir(parents=True)
    (d / "__init__.py").write_text("")
    for name, text in files.items():
        (d / name.replace("_DOT_", ".")).write_text(text)
    return d


def _scan(root: Path):
    return ii.scan_vendored([("purelib", root)])


AGREEING_TXT = "urllib3==1.26.20\n  setuptools==70.3.0\n"


def test_bom_first_and_the_carriers_own_component_is_skipped(tmp_path):
    _carrier(tmp_path, "pip", bom_DOT_cdx_DOT_json=json.dumps(BOM), vendor_DOT_txt=AGREEING_TXT)
    rows, errors = _scan(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"], r["source"]) for r in rows] == [
        ("urllib3", "1.26.20", "bom.cdx.json"), ("setuptools", "70.3.0", "bom.cdx.json"),
    ]
    assert {r["carrier"] for r in rows} == {"purelib/pip/_vendor"}


def test_manifests_that_disagree_are_reported_never_silently_resolved(tmp_path):
    _carrier(tmp_path, "pip", bom_DOT_cdx_DOT_json=json.dumps(BOM),
             vendor_DOT_txt="urllib3==1.26.20\nsetuptools==70.2.0\n")
    rows, errors = _scan(tmp_path)
    assert [r["source"] for r in rows] == ["bom.cdx.json", "bom.cdx.json"]
    assert errors == [{"carrier": "purelib/pip/_vendor", "error": (
        "bom.cdx.json and vendor.txt disagree: only in bom ['setuptools==70.3.0'], "
        "only in vendor.txt ['setuptools==70.2.0']")}]


@pytest.mark.parametrize("files", [
    {"vendor_DOT_txt": "# nothing pinned\n"},
    {"bom_DOT_cdx_DOT_json": json.dumps({"components": []}), "vendor_DOT_txt": ""},
], ids=["lone-empty-vendor-txt", "both-empty"])
def test_a_manifest_naming_nothing_over_packages_is_reported(tmp_path, files):
    d = _carrier(tmp_path, "pip", **files)
    (d / "urllib3").mkdir()
    rows, errors = _scan(tmp_path)
    assert [(r["name"], r["source"]) for r in rows] == [("urllib3", "listing")]
    assert len(errors) == 1 and "lists no package but the directory holds 1" in errors[0]["error"]


def test_an_unreadable_carrier_dir_is_an_error_not_an_absence(tmp_path, monkeypatch):
    _carrier(tmp_path, "pip", vendor_DOT_txt=AGREEING_TXT)
    target, real_stat = tmp_path / "pip" / "_vendor", Path.stat

    def stat(self, *a, **k):
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", stat)
    rows, errors = _scan(tmp_path)
    assert rows == []
    assert errors == [{"carrier": "purelib/pip/_vendor", "error": "PermissionError: Permission denied"}]


def test_vendor_txt_when_there_is_no_bom(tmp_path):
    _carrier(tmp_path, "pkg", vendor_DOT_txt=VENDOR_TXT)
    rows, errors = _scan(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"]) for r in rows] == [
        ("CacheControl", "0.14.3"), ("msgpack", "1.1.1"), ("six", None),
    ]


def test_a_malformed_bom_is_reported_and_vendor_txt_still_read(tmp_path):
    _carrier(tmp_path, "pip", bom_DOT_cdx_DOT_json="{not json", vendor_DOT_txt=VENDOR_TXT)
    rows, errors = _scan(tmp_path)
    assert errors == [{"carrier": "purelib/pip/_vendor/bom.cdx.json", "error": "JSONDecodeError"}]
    assert [r["source"] for r in rows] == ["vendor.txt"] * 3


def test_a_manifestless_carrier_lists_names_with_no_version(tmp_path):
    d = _carrier(tmp_path, "thing")
    (d / "idna").mkdir()
    (d / "six.py").write_text("")
    (d / "README.rst").write_text("")
    rows, errors = _scan(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"], r["source"]) for r in rows] == [
        ("idna", None, "listing"), ("six", None, "listing"),
    ]


def test_a_bundled_wheel_reports_itself_and_its_own_vendor_dir(tmp_path):
    bundled = tmp_path / "ensurepip" / "_bundled"
    bundled.mkdir(parents=True)
    whl = bundled / "pip-26.2.2-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("pip/_vendor/bom.cdx.json", json.dumps(BOM))
        zf.writestr("pip/_vendor/vendor.txt", AGREEING_TXT)
        zf.writestr("pip-26.2.2.dist-info/licenses/src/pip/_vendor/idna/LICENSE", "")
    rows, errors = ii.scan_vendored([("stdlib", tmp_path)])
    assert errors == []
    carrier = "stdlib/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl"
    assert rows[0] == {"carrier": carrier, "name": "pip", "version": "26.2.2",
                       "purl": "pkg:pypi/pip@26.2.2", "source": "wheel-filename"}
    assert {(r["carrier"], r["name"]) for r in rows[1:]} == {
        (f"{carrier}!pip/_vendor", "urllib3"), (f"{carrier}!pip/_vendor", "setuptools"),
    }


def test_an_unknown_carrier_shape_is_an_error_not_a_silence(tmp_path):
    (tmp_path / "botocore" / "vendored").mkdir(parents=True)
    rows, errors = _scan(tmp_path)
    assert rows == []
    assert errors == [{"carrier": "purelib/botocore/vendored", "error": "unknown carrier shape"}]


def test_an_unreadable_root_is_an_error_both_ways(tmp_path, monkeypatch):
    _carrier(tmp_path, "pip", vendor_DOT_txt=VENDOR_TXT)
    assert _scan(tmp_path)[1] == []  # readable: no error

    real = Path.iterdir

    def refuse(self):
        if self == tmp_path:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "iterdir", refuse)
    rows, errors = _scan(tmp_path)
    assert rows == []
    assert errors == [{"carrier": "purelib", "error": "PermissionError: Permission denied"}]


def test_no_row_or_error_names_a_filesystem_path(tmp_path, monkeypatch):
    _carrier(tmp_path, "pip", bom_DOT_cdx_DOT_json="{not json", vendor_DOT_txt=VENDOR_TXT)
    (tmp_path / "x" / "vendored").mkdir(parents=True)
    monkeypatch.setattr(ii, "_IMAGE_MEMO", None)
    monkeypatch.setattr(ii, "image_roots", lambda: [("purelib", tmp_path)])
    raw = json.dumps(ii.vendored_inventory([tmp_path / "absent", tmp_path]))
    assert str(tmp_path) not in raw and tmp_path.name not in raw
    assert "site-packages" not in raw and os.sep * 2 not in raw


def test_the_image_part_is_read_once_and_the_runtime_part_every_call(tmp_path, monkeypatch):
    image, runtime = tmp_path / "image", tmp_path / "runtime"
    _carrier(image, "pip", vendor_DOT_txt="a==1\n")
    runtime.mkdir()
    monkeypatch.setattr(ii, "_IMAGE_MEMO", None)
    monkeypatch.setattr(ii, "image_roots", lambda: [("purelib", image)])
    first = ii.vendored_inventory([runtime])
    _carrier(runtime, "late", vendor_DOT_txt="b==2\n")
    (image / "pip" / "_vendor" / "vendor.txt").write_text("a==9\n")
    second = ii.vendored_inventory([runtime])
    assert [(r["name"], r["version"]) for r in first["vendored"]] == [("a", "1")]
    assert [(r["carrier"], r["name"], r["version"]) for r in second["vendored"]] == [
        ("purelib/pip/_vendor", "a", "1"), ("runtime/late/_vendor", "b", "2"),
    ]


# ---------------------------------------------------------------------------
# Carrier census (count-agnostic): the reader only looks at <root>/<pkg>/<dir>.
# Every carrier-named dir in THIS interpreter's roots must sit at that depth or
# inside a carrier already read, so a deeper one cannot go unreported.
# ---------------------------------------------------------------------------

_CARRIER_NAMES = {ii.VENDOR_DIR, ii.BUNDLED_DIR, *ii.UNKNOWN_CARRIER_DIRS}


def _not_imported_here(path: Path) -> bool:
    """A package root this process does not import from (CI run 41794835586: a
    base interpreter's site-packages inside stdlib, not on sys.path). One that IS
    on sys.path stays in the walk, so a root the reader misses is still caught."""
    on_path = {Path(p).resolve() for p in sys.path if p}
    return path.name in {"site-packages", "dist-packages"} and path.resolve() not in on_path


def _deep_carriers(root: Path, other_roots: tuple[Path, ...] = ()) -> list[str]:
    others = {r.resolve() for r in other_roots}
    deep = []
    for dirpath, dirnames, _files in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = [d for d in dirnames
                       if not d.endswith(".dist-info") and d != "__pycache__"
                       and Path(dirpath, d).resolve() not in others  # purelib sits in stdlib
                       and not _not_imported_here(Path(dirpath, d))]
        for d in list(dirnames):
            if d not in _CARRIER_NAMES:
                continue
            if len(rel.parts) != 1:
                deep.append((rel / d).as_posix())
            dirnames.remove(d)  # its contents belong to the carrier
    return deep


def test_every_carrier_in_this_interpreter_sits_where_the_reader_looks():
    paths = sysconfig.get_paths()
    roots = {label: Path(paths[label]) for label in ("stdlib", "purelib", "platlib")}
    deep = []
    for label, root in roots.items():
        if root.is_dir():
            others = tuple(r for r in roots.values() if r != root)
            deep += [f"{label}/{p}" for p in _deep_carriers(root, others)]
    assert not deep, (
        f"carrier dirs below <root>/<pkg>/ that image_inventory never reads: {deep}; "
        f"teach _scan_root that depth, then re-run the image census on the deploy host"
    )


def test_the_census_has_teeth(tmp_path):
    (tmp_path / "pkg" / "sub" / "_vendor").mkdir(parents=True)
    (tmp_path / "ok" / "_vendor" / "inner" / "_vendor").mkdir(parents=True)
    (tmp_path / "x-1.dist-info" / "licenses" / "_vendor").mkdir(parents=True)
    assert _deep_carriers(tmp_path) == ["pkg/sub/_vendor"]


def test_the_census_prunes_only_a_package_root_this_process_does_not_import(tmp_path, monkeypatch):
    root = tmp_path / "site-packages"
    (root / "pip" / "_vendor").mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [p for p in sys.path if p and Path(p).resolve() != root.resolve()])
    assert _deep_carriers(tmp_path) == []
    monkeypatch.setattr(sys, "path", [*sys.path, str(root)])
    assert _deep_carriers(tmp_path) == ["site-packages/pip/_vendor"]


def test_this_interpreters_pip_vendor_is_inventoried():
    pip_vendor = Path(sysconfig.get_paths()["purelib"]) / "pip" / "_vendor"
    if not pip_vendor.is_dir():
        pytest.skip("no pip in this interpreter's purelib")
    rows, errors = ii.scan_vendored(ii.image_roots())
    assert errors == [], errors
    mine = [r for r in rows if r["carrier"] == "purelib/pip/_vendor"]
    assert mine and all(r["name"] for r in mine)
    txt = pip_vendor / "vendor.txt"
    if txt.is_file():
        # Every requirement line in pip's own vendor.txt is one entry: none dropped, none doubled.
        lines = [ln for ln in txt.read_text(encoding="utf-8").splitlines()
                 if ln.split("#", 1)[0].strip()]
        assert len(ii._rows_from_vendor_txt(txt.read_text(encoding="utf-8"), "c")) == len(lines)
        assert len(mine) == len(lines), (len(mine), len(lines))


# ---------------------------------------------------------------------------
# Bundled native libraries (848)
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
# The shared acceptance fixture agreed with cve-arc: cryptography 50.0.1's
# two PEP 770 SBOMs, byte for byte as the wheel ships them in
# cryptography-50.0.1.dist-info/sboms/.
CRYPTOGRAPHY_SBOMS = {
    "sbom.json": FIXTURES / "cryptography-50.0.1-sbom.json",
    "cryptography-rust.cyclonedx.json": FIXTURES / "cryptography-50.0.1-cryptography-rust.cyclonedx.json",
}
OPENSSL_402_ROW = {
    "source": "dist-info-sbom",
    "name": "openssl",
    "version": "4.0.2",
    "version_source": "sbom",
    "purl": "pkg:generic/openssl@4.0.2?download_url=https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz",
    "carrier": "cryptography",
    "carrier_version": "50.0.1",
}


def _sboms(root: Path, dist: str, files: dict[str, str]) -> Path:
    d = root / f"{dist}.dist-info" / "sboms"
    d.mkdir(parents=True)
    for name, text in files.items():
        (d / name).write_text(text, encoding="utf-8")
    return d


def _libs(root: Path, carrier: str, files: dict[str, bytes]) -> Path:
    d = root / f"{carrier}.libs"
    d.mkdir(parents=True)
    for name, data in files.items():
        (d / name).write_bytes(data)
    return d


def _bundled(root: Path):
    return ii.scan_bundled([("purelib", root)])


def _elf(soname: str | None, payload: bytes = b"", bits: int = 64) -> bytes:
    """A minimal little-endian ELF shared object: one PT_LOAD over the whole file
    (so a virtual address is its file offset) and one PT_DYNAMIC whose DT_STRTAB
    and DT_SONAME name ``soname``. ``payload`` (a banner, padding) follows."""
    if bits == 64:
        hdr, ph, dyn, ehsize, phsize = "<HHIQQQIHHHHHH", "<IIQQQQQQ", "<qQ", 64, 56
    else:
        hdr, ph, dyn, ehsize, phsize = "<HHIIIIIHHHHHH", "<8I", "<iI", 52, 32
    dyn_off = ehsize + 2 * phsize
    dyn_size = 3 * struct.calcsize(dyn)
    tags = [(5, dyn_off + dyn_size), (14, 1) if soname else (0, 0), (0, 0)]
    body = (b"".join(struct.pack(dyn, t, v) for t, v in tags)
            + b"\0" + (soname.encode() + b"\0" if soname else b"") + payload)
    total = dyn_off + len(body)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1]) + bytes(9)
    header = ident + struct.pack(hdr, 3, 62, 1, 0, ehsize, 0, 0, ehsize, phsize, 2, 0, 0, 0)
    if bits == 64:
        phdrs = (struct.pack(ph, 1, 5, 0, 0, 0, total, total, 0x1000)
                 + struct.pack(ph, 2, 6, dyn_off, dyn_off, dyn_off, dyn_size, dyn_size, 8))
    else:
        phdrs = (struct.pack(ph, 1, 0, 0, 0, total, total, 5, 0x1000)
                 + struct.pack(ph, 2, dyn_off, dyn_off, dyn_off, dyn_size, dyn_size, 6, 4))
    return header + phdrs + body


def _libs_row(name, version, version_source, carrier="c", carrier_version="1.0"):
    return {"source": "auditwheel-libs", "name": name, "version": version,
            "version_source": version_source, "purl": None,
            "carrier": carrier, "carrier_version": carrier_version}


@pytest.fixture
def libs_root(tmp_path, monkeypatch):
    """A root holding c-1.0.dist-info, so a c.libs/ dir has its carrier version."""
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    (tmp_path / "c-1.0.dist-info").mkdir()
    return tmp_path


def test_the_shared_cryptography_fixture_emits_openssl_and_every_cargo_crate(tmp_path):
    d = tmp_path / "cryptography-50.0.1.dist-info" / "sboms"
    d.mkdir(parents=True)
    for name, src in CRYPTOGRAPHY_SBOMS.items():
        shutil.copyfile(src, d / name)
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert [r for r in rows if r["purl"].startswith("pkg:generic/")] == [OPENSSL_402_ROW]
    # The Rust SBOM: every crate is a row, and its own subject is not.
    rust = json.loads(CRYPTOGRAPHY_SBOMS["cryptography-rust.cyclonedx.json"].read_text(encoding="utf-8"))
    cargo = [r for r in rows if r["purl"].startswith("pkg:cargo/")]
    assert sorted((r["name"], r["version"], r["purl"]) for r in cargo) == sorted(
        (c["name"], c["version"], c["purl"]) for c in rust["components"])
    assert rust["metadata"]["component"]["name"] not in {r["name"] for r in rows}
    assert len(rows) == len(cargo) + 1
    # cargo openssl 0.10.81 is the Rust binding, never OpenSSL itself: its purl says so.
    assert sorted(r["purl"] for r in rows if r["name"] == "openssl") == [
        "pkg:cargo/openssl@0.10.81", OPENSSL_402_ROW["purl"]]
    assert {(r["carrier"], r["carrier_version"], r["version_source"]) for r in rows} == {
        ("cryptography", "50.0.1", "sbom")}


def test_the_cargo_openssl_crate_carries_a_cargo_purl(tmp_path):
    d = tmp_path / "cryptography-50.0.1.dist-info" / "sboms"
    d.mkdir(parents=True)
    shutil.copyfile(CRYPTOGRAPHY_SBOMS["cryptography-rust.cyclonedx.json"], d / "cryptography-rust.cyclonedx.json")
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert [r for r in rows if r["name"] == "openssl"] == [{
        **OPENSSL_402_ROW, "version": "0.10.81", "purl": "pkg:cargo/openssl@0.10.81",
    }]


def test_a_50_0_2_wheel_bundling_openssl_4_0_3_emits_4_0_3(tmp_path):
    text = CRYPTOGRAPHY_SBOMS["sbom.json"].read_text(encoding="utf-8").replace("4.0.2", "4.0.3")
    _sboms(tmp_path, "cryptography-50.0.2", {"sbom.json": text})
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"], r["carrier_version"]) for r in rows] == [
        ("openssl", "4.0.3", "50.0.2")]
    assert rows[0]["purl"].startswith("pkg:generic/openssl@4.0.3?")


def test_pypi_components_and_the_documents_own_subject_are_not_bundled(tmp_path):
    bom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "thing-rust", "version": "0.2.0"}},
        "components": [
            {"name": "thing-rust", "version": "0.2.0", "purl": "pkg:cargo/thing-rust@0.2.0"},
            {"name": "Thing", "version": "2.0", "purl": "pkg:cargo/thing@2.0"},
            {"name": "six", "version": "1.17.0", "purl": "pkg:PyPI/six@1.17.0"},
            {"name": "zlib", "version": "1.3.1"},
            {"name": "nover", "purl": "pkg:generic/nover"},
            {"version": "9"},
        ],
    }
    _sboms(tmp_path, "thing-2.0", {"thing.cdx.json": json.dumps(bom)})
    rows, errors = _bundled(tmp_path)
    assert errors == []
    # The cargo crate named like the carrier is kept: only pkg:pypi and the subject are skipped.
    assert rows == [
        {"source": "dist-info-sbom", "name": "Thing", "version": "2.0", "version_source": "sbom",
         "purl": "pkg:cargo/thing@2.0", "carrier": "thing", "carrier_version": "2.0"},
        {"source": "dist-info-sbom", "name": "zlib", "version": "1.3.1", "version_source": "sbom",
         "purl": None, "carrier": "thing", "carrier_version": "2.0"},
        {"source": "dist-info-sbom", "name": "nover", "version": None, "version_source": None,
         "purl": "pkg:generic/nover", "carrier": "thing", "carrier_version": "2.0"},
    ]


def test_a_component_named_like_its_carrier_is_still_bundled(tmp_path):
    # lz4's wheel bundles the C library lz4: a skip by the carrier's name would
    # drop that row with no error (panel 848, devils-advocate MUST-1).
    bom = {
        "metadata": {"component": {"name": "lz4", "version": "4.4.4", "purl": "pkg:pypi/lz4@4.4.4"}},
        "components": [
            {"name": "lz4", "version": "1.9.4", "purl": "pkg:generic/lz4@1.9.4"},
            {"name": "LZ4", "version": "1.9.4"},
            {"name": "xxhash", "version": "0.8.2", "purl": "pkg:generic/xxhash@0.8.2"},
        ],
    }
    _sboms(tmp_path, "lz4-4.4.4", {"bom.json": json.dumps(bom)})
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"], r["purl"], r["carrier"]) for r in rows] == [
        ("lz4", "1.9.4", "pkg:generic/lz4@1.9.4", "lz4"),
        ("LZ4", "1.9.4", None, "lz4"),
        ("xxhash", "0.8.2", "pkg:generic/xxhash@0.8.2", "lz4"),
    ]


def test_the_subject_is_matched_by_bom_ref_when_it_has_one(tmp_path):
    bom = {
        "metadata": {"component": {"bom-ref": "root", "name": "lz4"}},
        "components": [
            {"bom-ref": "root", "name": "lz4", "version": "4.4.4", "purl": "pkg:generic/lz4@4.4.4"},
            {"bom-ref": "c-lib", "name": "lz4", "version": "1.9.4", "purl": "pkg:generic/lz4@1.9.4"},
        ],
    }
    _sboms(tmp_path, "lz4-4.4.4", {"bom.json": json.dumps(bom)})
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert [(r["name"], r["version"]) for r in rows] == [("lz4", "1.9.4")]


def test_an_unreadable_sbom_is_an_error_and_the_others_are_still_read(tmp_path):
    good = {"components": [{"name": "zlib", "version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1"}]}
    _sboms(tmp_path, "thing-2.0", {
        "a.json": "{not json",
        "b.json": json.dumps(good),
        "c.json": json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}),
        "d.spdx": "SPDXVersion: SPDX-2.3\n",
    })
    rows, errors = _bundled(tmp_path)
    assert [(r["name"], r["version"]) for r in rows] == [("zlib", "1.3.1")]
    assert errors == [
        {"carrier": "thing/sboms/a.json", "error": "JSONDecodeError"},
        {"carrier": "thing/sboms/c.json", "error": "ValueError"},
        {"carrier": "thing/sboms/d.spdx", "error": "not a .json SBOM; not read"},
    ]


def test_an_unreadable_sboms_dir_is_an_error_both_ways(tmp_path, monkeypatch):
    d = _sboms(tmp_path, "thing-2.0", {"b.json": json.dumps({"components": []})})
    assert _bundled(tmp_path) == ([], [])
    real = Path.iterdir

    def refuse(self):
        if self == d:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "iterdir", refuse)
    assert _bundled(tmp_path) == ([], [{"carrier": "thing/sboms", "error": "PermissionError: Permission denied"}])


def test_libs_rows_strip_the_auditwheel_hash_and_take_the_carrier_version(tmp_path, monkeypatch):
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    (tmp_path / "pillow-11.0.0.dist-info").mkdir()
    _libs(tmp_path, "Pillow", {"libjpeg-1a2b3c4d.so.62.4.0": b"jpeg", "libopenblas64_p-r0-15028c96.3.21.so": b"",
                               "libgfortran-83c28eba-468e71e5.so.5.0.0": b"",  # grafted twice (numpy 2.5.2)
                               "LICENSE.txt": b"text"})
    rows, errors = _bundled(tmp_path)
    assert errors == []
    # The carrier is the PEP 503 name, not the dir stem: cve-arc keys findings on it.
    assert rows == [_libs_row(n, None, None, "pillow", "11.0.0")
                    for n in ("LICENSE.txt", "libgfortran", "libjpeg", "libopenblas64_p-r0")]


def test_a_twice_hashed_library_keeps_its_banner_read(libs_root):
    # With "-" continuing a library name, a name left as libssl-0a1b2c3d would miss the table.
    _libs(libs_root, "c", {"libssl-0a1b2c3d-1a2b3c4d.so.3": b"\0OpenSSL 3.0.13 30 Jan 2024\0"})
    assert _bundled(libs_root) == ([_libs_row("libssl", "3.0.13", "binary_banner")], [])


@pytest.mark.parametrize("dists, error", [
    ((), "no dist-info names this carrier"),
    (("c-1.0", "c-2.0"), "several dist-info name this carrier: ['c-1.0', 'c-2.0']"),
], ids=["none", "several"])
def test_a_libs_carrier_without_one_dist_info_is_reported_and_its_rows_kept(
    tmp_path, monkeypatch, dists, error,
):
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    for dist in dists:
        (tmp_path / f"{dist}.dist-info").mkdir()
    _libs(tmp_path, "c", {"libx-0a1b2c3d.so.1": b""})
    rows, errors = _bundled(tmp_path)
    assert rows == [_libs_row("libx", None, None, carrier_version=None)]
    assert errors == [{"carrier": "c", "error": error}]


def test_an_in_package_libs_dir_is_carried_by_the_dist_info_whose_record_lists_it(tmp_path, monkeypatch):
    # Older auditwheel and delvewheel: <package>/.libs/, where the import name is
    # not the distribution's (sklearn/.libs is scikit-learn's).
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    dist = tmp_path / "scikit_learn-1.8.0.dist-info"
    dist.mkdir()
    (dist / "RECORD").write_text(
        "sklearn/__init__.py,sha256=x,1\nsklearn/.libs/vcomp140.dll,sha256=y,2\n", encoding="utf-8")
    (tmp_path / "sklearn" / ".libs").mkdir(parents=True)
    (tmp_path / "sklearn" / ".libs" / "vcomp140.dll").write_bytes(b"MZ")
    (tmp_path / "six.py").write_text("")
    rows, errors = _bundled(tmp_path)
    assert errors == []
    assert rows == [_libs_row("vcomp140.dll", None, None, "scikit-learn", "1.8.0")]


def test_an_in_package_libs_dir_no_record_lists_is_reported_and_its_rows_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    (tmp_path / "other-1.0.dist-info").mkdir()
    (tmp_path / "other-1.0.dist-info" / "RECORD").write_text("other/x.py,,\n", encoding="utf-8")
    (tmp_path / "pkg" / ".libs").mkdir(parents=True)
    (tmp_path / "pkg" / ".libs" / "libq-0a1b2c3d.so.2").write_bytes(b"")
    rows, errors = _bundled(tmp_path)
    assert rows == [_libs_row("libq", None, None, "pkg", None)]
    assert errors == [{"carrier": "pkg", "error": "no dist-info RECORD lists this .libs dir"}]


@pytest.mark.parametrize("bits", [64, 32])
def test_a_soname_gives_the_abi_number_when_no_banner_names_the_library(libs_root, bits):
    _libs(libs_root, "c", {"libfoo-0a1b2c3d.so.3.1": _elf("libfoo-0a1b2c3d.so.3.1", bits=bits)})
    assert _bundled(libs_root) == ([_libs_row("libfoo", "3.1", "soname")], [])


def test_a_banner_wins_over_the_soname(libs_root):
    data = _elf("libssl.so.3", payload=b"\0OpenSSL 3.0.13 30 Jan 2024\0")
    _libs(libs_root, "c", {"libssl-0a1b2c3d.so.3": data})
    assert _bundled(libs_root) == ([_libs_row("libssl", "3.0.13", "binary_banner")], [])


def test_one_version_named_by_several_banners_is_one_version(libs_root):
    data = b"\0 deflate 1.3.1 Copyright 1995-2024 \0 inflate 1.3.1 Copyright 1995-2024 \0"
    _libs(libs_root, "c", {"libz-0a1b2c3d.so.1.3.1": data})
    assert _bundled(libs_root) == ([_libs_row("libz", "1.3.1", "binary_banner")], [])


def test_conflicting_banners_leave_the_version_null_and_say_so(libs_root):
    data = _elf("libcrypto.so.3", payload=b"\0OpenSSL 3.0.13 30 Jan 2024\0OpenSSL 1.1.1w 11 Sep 2023\0")
    _libs(libs_root, "c", {"libcrypto-0a1b2c3d.so.3": data})
    rows, errors = _bundled(libs_root)
    assert rows == [_libs_row("libcrypto", None, None)]
    assert errors == [{"carrier": "c.libs/libcrypto-0a1b2c3d.so.3",
                       "error": "several version banners ['1.1.1w', '3.0.13']; version left null"}]


def test_the_banner_table_matches_a_whole_library_name_only(libs_root):
    # libzstd is not libz, and NSS's libssl3 is not OpenSSL's libssl: no table entry, no banner read.
    _libs(libs_root, "c", {"libzstd-0a1b2c3d.so.1": b"\0deflate 1.3.1\0",
                           "libssl3.so": b"\0OpenSSL 3.0.13\0"})
    assert _bundled(libs_root) == ([_libs_row("libssl3.so", None, None), _libs_row("libzstd", None, None)], [])


def test_zlib_ng_is_never_read_as_zlib(libs_root):
    # zlib-ng in compat mode prints "deflate 1.3.1.zlib-ng" (pillow ships it), and
    # libz-ng is zlib-ng's own name: neither is a zlib version (panel 848, DA SHOULD-1).
    _libs(libs_root, "c", {"libz-0a1b2c3d.so.1": b"\0 deflate 1.3.1.zlib-ng Copyright 1995-2024 \0",
                           "libz-ng-0a1b2c3d.so.2": b"\0 deflate 2.2.2 Copyright 1995-2024 \0"})
    assert _bundled(libs_root) == ([_libs_row("libz", None, None), _libs_row("libz-ng", None, None)], [])


def test_no_elf_and_no_banner_leaves_both_null(libs_root):
    _libs(libs_root, "c", {"libssl-0a1b2c3d.so.3": b"MZ not an ELF file", "libbad-0a1b2c3d.so.1": b"\x7fELF\x02"})
    assert _bundled(libs_root) == ([_libs_row("libbad", None, None), _libs_row("libssl", None, None)], [])


@pytest.mark.parametrize("start", range(20, 72))
def test_a_banner_cut_by_a_chunk_edge_is_read_whole(monkeypatch, start):
    monkeypatch.setattr(ii, "_BANNER_CHUNK", 64)
    monkeypatch.setattr(ii, "_BANNER_OVERLAP", 32)
    data = b"\0" * start + b"OpenSSL 3.0.13 30 Jan 2024" + b"\0" * 150
    assert ii._banner_versions(io.BytesIO(data), ii._OPENSSL_BANNER) == ({"3.0.13"}, False)


def test_a_file_past_the_read_cap_is_reported_and_its_row_kept(libs_root, monkeypatch):
    monkeypatch.setattr(ii, "BANNER_READ_CAP", 512)
    monkeypatch.setattr(ii, "_BANNER_CHUNK", 64)
    monkeypatch.setattr(ii, "_BANNER_OVERLAP", 32)
    early = b"\0OpenSSL 3.0.13 30 Jan 2024\0" + b"\0" * 1000
    late = _elf("libssl.so.3", payload=b"\0" * 1000 + b"OpenSSL 3.0.13 30 Jan 2024\0")
    _libs(libs_root, "c", {"libcrypto-0a1b2c3d.so.3": early, "libssl-0a1b2c3d.so.3": late})
    rows, errors = _bundled(libs_root)
    assert rows == [_libs_row("libcrypto", "3.0.13", "binary_banner"), _libs_row("libssl", "3", "soname")]
    assert errors == [
        {"carrier": f"c.libs/{n}-0a1b2c3d.so.3", "error": "banner scan stopped at the 512-byte read cap"}
        for n in ("libcrypto", "libssl")
    ]


def test_an_unreadable_library_keeps_its_row_with_an_error(libs_root, monkeypatch):
    lib = _libs(libs_root, "c", {"libssl-0a1b2c3d.so.3": b""}) / "libssl-0a1b2c3d.so.3"
    real = Path.open

    def refuse(self, *a, **k):
        if self == lib:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "open", refuse)
    rows, errors = _bundled(libs_root)
    assert rows == [_libs_row("libssl", None, None)]
    assert errors == [{"carrier": "c.libs/libssl-0a1b2c3d.so.3", "error": "PermissionError: Permission denied"}]


class _RefusingSeek(io.BytesIO):
    """A file whose ``seek`` past 0 fails as Linux ``lseek`` does past the
    filesystem's maximum offset (EINVAL). BytesIO alone never reaches that path."""

    def seek(self, pos, whence=0):
        if pos:
            raise OSError(errno.EINVAL, "Invalid argument")
        return super().seek(pos, whence)


def test_an_elf_offset_the_os_refuses_keeps_the_row_with_one_error(libs_root, monkeypatch):
    # _elf_soname raises here rather than return None: a crafted file must not
    # read as a normal file with no SONAME.
    data = _elf("libfoo.so.1")
    lib = _libs(libs_root, "c", {"libfoo-0a1b2c3d.so.1": data}) / "libfoo-0a1b2c3d.so.1"
    real = Path.open

    def refusing(self, *a, **k):
        return _RefusingSeek(data) if self == lib else real(self, *a, **k)

    monkeypatch.setattr(Path, "open", refusing)
    rows, errors = _bundled(libs_root)
    assert rows == [_libs_row("libfoo", None, None)]
    assert errors == [{"carrier": "c.libs/libfoo-0a1b2c3d.so.1", "error": "OSError: Invalid argument"}]
    assert ii._LIBS_CACHE == {}  # a failed read is not kept


def test_an_unreadable_bundled_root_is_an_error_both_ways(tmp_path, monkeypatch):
    _sboms(tmp_path, "thing-2.0", {"b.json": json.dumps({"components": []})})
    assert _bundled(tmp_path) == ([], [])
    assert ii.scan_bundled([("purelib", tmp_path / "absent")]) == ([], [])
    real = Path.iterdir

    def refuse(self):
        if self == tmp_path:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "iterdir", refuse)
    assert _bundled(tmp_path) == ([], [{"carrier": "purelib", "error": "PermissionError: Permission denied"}])


def test_a_whole_scan_failure_is_null_bundled_never_an_empty_list(monkeypatch):
    monkeypatch.setattr(ii, "_BUNDLED_IMAGE_MEMO", None)

    def boom(_roots):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(ii, "scan_bundled", boom)
    assert ii.bundled_inventory([]) == {
        "bundled": None, "bundled_error": [{"carrier": "*", "error": "RuntimeError"}]}


def test_no_bundled_row_or_error_names_a_filesystem_path(tmp_path, monkeypatch):
    _sboms(tmp_path, "thing-2.0", {"a.json": "{not json", "d.spdx": ""})
    _libs(tmp_path, "orphan", {"libssl-0a1b2c3d.so.3": b"OpenSSL 3.0.13 x OpenSSL 1.0.2u y"})
    monkeypatch.setattr(ii, "_BUNDLED_IMAGE_MEMO", None)
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    monkeypatch.setattr(ii, "image_roots", lambda: [("purelib", tmp_path)])
    inv = ii.bundled_inventory([tmp_path / "absent", tmp_path])
    assert inv["bundled"] and len(inv["bundled_error"]) >= 4
    raw = json.dumps(inv)
    assert str(tmp_path) not in raw and tmp_path.name not in raw
    assert "site-packages" not in raw and os.sep * 2 not in raw


def test_the_bundled_image_part_is_read_once_and_the_runtime_part_every_call(tmp_path, monkeypatch):
    image, runtime = tmp_path / "image", tmp_path / "runtime"
    _sboms(image, "a-1", {"s.json": json.dumps({"components": [{"name": "x", "version": "1"}]})})
    runtime.mkdir()
    monkeypatch.setattr(ii, "_BUNDLED_IMAGE_MEMO", None)
    monkeypatch.setattr(ii, "image_roots", lambda: [("purelib", image)])
    first = ii.bundled_inventory([runtime])
    _sboms(runtime, "b-2", {"s.json": json.dumps({"components": [{"name": "y", "version": "2"}]})})
    (image / "a-1.dist-info" / "sboms" / "s.json").write_text(
        json.dumps({"components": [{"name": "x", "version": "9"}]}), encoding="utf-8")
    second = ii.bundled_inventory([runtime])
    assert [(r["name"], r["version"]) for r in first["bundled"]] == [("x", "1")]
    assert [(r["carrier"], r["name"], r["version"]) for r in second["bundled"]] == [
        ("a", "x", "1"), ("b", "y", "2"),
    ]


def test_an_image_scan_with_errors_is_not_memoised(tmp_path, monkeypatch):
    # The memo is set only on a clean scan, so the next call rescans (panel 848, db-sme SHOULD-1).
    image = tmp_path / "image"
    sbom = _sboms(image, "a-1", {"s.json": "{not json"}) / "s.json"
    monkeypatch.setattr(ii, "_BUNDLED_IMAGE_MEMO", None)
    monkeypatch.setattr(ii, "image_roots", lambda: [("purelib", image)])
    first = ii.bundled_inventory([])
    assert first["bundled"] == [] and len(first["bundled_error"]) == 1
    assert ii._BUNDLED_IMAGE_MEMO is None
    sbom.write_text(json.dumps({"components": [{"name": "x", "version": "1"}]}), encoding="utf-8")
    second = ii.bundled_inventory([])
    assert [(r["name"], r["version"]) for r in second["bundled"]] == [("x", "1")]
    assert second["bundled_error"] == []
    assert ii._BUNDLED_IMAGE_MEMO is not None  # the clean rescan is kept


def test_an_unchanged_runtime_library_is_not_read_again(tmp_path, monkeypatch):
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    monkeypatch.setattr(ii, "_BUNDLED_IMAGE_MEMO", ([], []))
    (tmp_path / "c-1.0.dist-info").mkdir()
    lib = _libs(tmp_path, "c", {"libssl-0a1b2c3d.so.3": b"OpenSSL 3.0.13 x"}) / "libssl-0a1b2c3d.so.3"
    reads = []
    real = ii._libs_file_version

    def counting(path, name):
        reads.append(name)
        return real(path, name)

    monkeypatch.setattr(ii, "_libs_file_version", counting)
    first = ii.bundled_inventory([tmp_path])
    second = ii.bundled_inventory([tmp_path])
    assert first == second and reads == ["libssl"]
    lib.write_bytes(b"OpenSSL 3.0.15 the patched copy")
    third = ii.bundled_inventory([tmp_path])
    assert reads == ["libssl", "libssl"]
    assert [r["version"] for r in third["bundled"]] == ["3.0.15"]


# ---------------------------------------------------------------------------
# Bundled census (count-agnostic), extending the carrier census above: every
# SBOM under a *.dist-info/sboms/ and every *.libs dir in THIS interpreter's
# roots, at any depth, must sit where the reader looks and be represented in
# ``bundled`` rows or ``bundled_error``.
# ---------------------------------------------------------------------------

def _sbom_files_and_libs_dirs(root: Path, other_roots: tuple[Path, ...] = ()) -> tuple[list[Path], list[Path]]:
    others = {r.resolve() for r in other_roots}
    sboms: list[Path] = []
    libs: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if here.name == ii.SBOM_DIR and here.parent.name.endswith(ii.DIST_INFO_SUFFIX):
            sboms += [here / f for f in filenames]
        dirnames[:] = [d for d in dirnames
                       if d != "__pycache__" and Path(dirpath, d).resolve() not in others
                       and not _not_imported_here(Path(dirpath, d))]
        libs += [here / d for d in dirnames if d.endswith(ii.LIBS_SUFFIX)]
    return sboms, libs


def _wanted_names(sbom: Path, carrier: str) -> set[str]:
    """The test's own oracle: the non-PyPI component names an SBOM holds,
    without the document's subject (the one-parser pin scopes src/ only)."""
    bom = json.loads(sbom.read_text(encoding="utf-8"))
    own = {ii._canonical_name(carrier),
           ii._canonical_name(((bom.get("metadata") or {}).get("component") or {}).get("name") or "")}
    return {c["name"] for c in bom["components"] if isinstance(c, dict) and isinstance(c.get("name"), str)
            and c["name"] and ii._canonical_name(c["name"]) not in own
            and not str(c.get("purl") or "").lower().startswith("pkg:pypi/")}


def _bundled_census(roots: dict[str, Path], rows, errors) -> list[str]:
    erred = {e["carrier"] for e in errors}
    missed = []
    for label, root in roots.items():
        others = tuple(r for r in roots.values() if r != root)
        sboms, libs = _sbom_files_and_libs_dirs(root, others)
        for sbom in sboms:
            rel = "/".join(sbom.relative_to(root).parts)
            carrier, _ = ii._dist_info_carrier(sbom.parent.parent.name)
            if rel.count("/") != 2:
                missed.append(f"{label}/{rel} (below <root>/<dist>.dist-info/sboms/)")
            elif f"{carrier}/sboms/{sbom.name}" not in erred:
                got = {r["name"] for r in rows
                       if r["carrier"] == ii._canonical_name(carrier) and r["source"] == "dist-info-sbom"}
                if not _wanted_names(sbom, carrier) <= got:
                    missed.append(f"{label}/{rel} (components missing from bundled)")
        for libs_dir in libs:
            parts = libs_dir.relative_to(root).parts
            rel = "/".join(parts)
            if len(parts) == 1 and libs_dir.name != ii.LIBS_SUFFIX:
                carriers = {libs_dir.name[: -len(ii.LIBS_SUFFIX)]}
            elif len(parts) == 2 and libs_dir.name == ii.LIBS_SUFFIX:
                carriers = {parts[0]} | _record_owners(root, f"{rel}/")
            else:
                missed.append(f"{label}/{rel} (below <root>/<name>.libs/ or <root>/<package>/.libs/)")
                continue
            carriers = {ii._canonical_name(c) for c in carriers}
            for f in sorted(libs_dir.iterdir()):
                if f"{rel}/{f.name}" in erred:
                    continue
                if not any(r["source"] == "auditwheel-libs" and r["carrier"] in carriers
                           and (f.name == r["name"] or f.name.startswith(r["name"] + "-")) for r in rows):
                    missed.append(f"{label}/{rel}/{f.name}")
    return missed


def _record_owners(root: Path, prefix: str) -> set[str]:
    """The test's own oracle: names of the dist-infos whose RECORD lists ``prefix``."""
    owners = set()
    for dist in root.iterdir():
        record = dist / "RECORD"
        if dist.name.endswith(ii.DIST_INFO_SUFFIX) and record.is_file():
            if any(line.lstrip('"').startswith(prefix)
                   for line in record.read_text(encoding="utf-8").splitlines()):
                owners.add(ii._dist_info_carrier(dist.name)[0])
    return owners


def test_every_sbom_and_libs_dir_in_this_interpreter_is_inventoried():
    paths = sysconfig.get_paths()
    roots = {label: Path(paths[label]) for label in ("stdlib", "purelib", "platlib")}
    rows, errors = ii.scan_bundled(ii.image_roots())
    missed = _bundled_census({k: v for k, v in roots.items() if v.is_dir()}, rows, errors)
    assert not missed, (
        f"SBOMs or .libs files that image_inventory never reports: {missed}; teach "
        f"_scan_bundled_root that shape, then re-run the image census on the deploy host"
    )


def test_the_bundled_census_has_teeth(tmp_path):
    _sboms(tmp_path / "pkg", "deep-1", {"s.json": json.dumps({"components": [{"name": "z"}]})})
    _libs(tmp_path / "pkg", "deep", {"libd.so": b""})
    _sboms(tmp_path, "top-1", {"s.json": json.dumps({"components": [
        {"name": "zlib"}, {"name": "six", "purl": "pkg:pypi/six@1"}]})})
    _libs(tmp_path, "top", {"libt-0a1b2c3d.so.1": b""})
    (tmp_path / "own" / ".libs").mkdir(parents=True)
    (tmp_path / "own" / ".libs" / "liba.so").write_bytes(b"")
    (tmp_path / "own_dist-3.dist-info").mkdir()
    (tmp_path / "own_dist-3.dist-info" / "RECORD").write_text("own/.libs/liba.so,,\n", encoding="utf-8")
    (tmp_path / "pkg" / "sub" / ".libs").mkdir(parents=True)
    rows, errors = _bundled(tmp_path)
    deep = [
        "purelib/pkg/deep-1.dist-info/sboms/s.json (below <root>/<dist>.dist-info/sboms/)",
        "purelib/pkg/deep.libs (below <root>/<name>.libs/ or <root>/<package>/.libs/)",
        "purelib/pkg/sub/.libs (below <root>/<name>.libs/ or <root>/<package>/.libs/)",
    ]
    assert sorted(_bundled_census({"purelib": tmp_path}, rows, errors)) == deep
    assert sorted(_bundled_census({"purelib": tmp_path}, [], [])) == sorted(deep + [
        "purelib/own/.libs/liba.so",
        "purelib/top-1.dist-info/sboms/s.json (components missing from bundled)",
        "purelib/top.libs/libt-0a1b2c3d.so.1",
    ])
