"""Punch 848: the bundled inventory's two structural invariants.

1. **ONE CycloneDX parser (PD-5).** pip's vendored ``bom.cdx.json`` (punch 647)
   and a wheel's PEP 770 ``*.dist-info/sboms/*.json`` (punch 848) are both
   CycloneDX, and both are read by ``image_inventory._rows_from_bom``. A second
   walker would drift from the first in the rules cve-arc depends on: which
   component is the document's own subject, how a missing version or purl is
   reported, and the FAIL LOUD error on a document with no components list.
   PROPERTY (count-agnostic, over every file under ``src/email_triage``): every
   string constant equal to ``"components"`` outside a docstring sits inside
   ``_rows_from_bom`` in ``image_inventory.py``. That covers
   ``bom["components"]``, ``bom.get("components")``, ``"components" in bom``
   and ``operator.itemgetter("components")`` alike.

2. **Bytes only, never loaded.** A ``.libs`` library's version is read from its
   bytes. Loading it (``ctypes.CDLL``, ``PQlibVersion``) runs its constructors:
   the exact hazard of a possibly-vulnerable copy. PROPERTY: ``image_inventory``
   imports no module that loads or executes code.

3. **Every ``bundled`` carrier is its PEP 503 name.** cve-arc keys a finding on
   ``carrier``, so ``Pillow`` from one shape and ``pillow`` from another would
   key one distribution twice, and a later rename would re-key every finding.
   PROPERTY (count-agnostic, over every row): ``carrier ==
   image_inventory._canonical_name(carrier)``, over this interpreter's scan and
   over a fixture tree that names every carrier shape non-canonically on disk.
   A ``bundled_error`` carrier stays raw: it names what is on disk.

SCOPE CAVEAT: a green run does not prove there is no second walker whose key is
built at runtime (``"comp" + "onents"``), read from config, or reached through a
CycloneDX library; it does not look outside ``src/email_triage`` (``scripts/``
does not serve the inventory); arm 2 checks imports, not an
``__import__("ctypes")`` call; and arm 3 sees only the shapes this interpreter
and the fixture tree hold.
"""
from __future__ import annotations

import ast
import shutil
from pathlib import Path

from email_triage import image_inventory as ii

from _pin_harness import (
    assert_pin_has_teeth,
    docstring_constant_ids,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
)

_KEY = "components"
_PARSER_HOME = ("image_inventory.py", "_rows_from_bom")
# os (os.system, os.exec*, os.posix_spawn), pty (pty.spawn) and zipimport load or
# run code too; the module reads bytes through pathlib and needs none of them.
_LOADERS = frozenset({
    "ctypes", "_ctypes", "cffi", "subprocess", "importlib", "runpy", "multiprocessing",
    "os", "pty", "zipimport",
})
_FIXTURES = Path(__file__).parent / "fixtures"


def _components_sites(tree: ast.AST) -> list[tuple[int, str]]:
    """``(lineno, enclosing function)`` of every code ``"components"`` constant."""
    docs = docstring_constant_ids(tree)
    return [
        (node.lineno, enclosing_fn(node)) for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == _KEY and id(node) not in docs
    ]


def _all_sites() -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, fn in _components_sites(tree):
            found.setdefault((relpath(path), fn), []).append(lineno)
    return found


def _loader_imports(tree: ast.AST) -> list[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.append(node.module)
    return sorted(n for n in names if n.split(".", 1)[0] in _LOADERS)


def _non_canonical(rows) -> list[str]:
    return sorted({r["carrier"] for r in rows if r["carrier"] != ii._canonical_name(r["carrier"])})


def _every_carrier_shape(root: Path) -> None:
    """One carrier per shape, each named on disk as it is NOT canonical."""
    sboms = root / "cryptography-50.0.1.dist-info" / "sboms"
    sboms.mkdir(parents=True)
    for name in ("sbom.json", "cryptography-rust.cyclonedx.json"):
        shutil.copyfile(_FIXTURES / f"cryptography-50.0.1-{name}", sboms / name)
    (root / "Foo_Bar-2.0.dist-info" / "sboms").mkdir(parents=True)
    (root / "Foo_Bar-2.0.dist-info" / "sboms" / "s.json").write_text(
        '{"components": [{"name": "zlib", "version": "1.3.1"}]}', encoding="utf-8")
    (root / "pillow-11.0.0.dist-info").mkdir()
    (root / "Pillow.libs").mkdir()  # <name>.libs: the dir stem
    (root / "Pillow.libs" / "libjpeg-1a2b3c4d.so.62").write_bytes(b"")
    (root / "scikit_learn-1.8.0.dist-info").mkdir()
    (root / "scikit_learn-1.8.0.dist-info" / "RECORD").write_text(
        "sklearn/.libs/vcomp140.dll,,\n", encoding="utf-8")
    (root / "sklearn" / ".libs").mkdir(parents=True)  # <package>/.libs: the RECORD owner
    (root / "sklearn" / ".libs" / "vcomp140.dll").write_bytes(b"MZ")
    (root / "Odd_Name.libs").mkdir()  # no dist-info: the stem is the fallback carrier
    (root / "Odd_Name.libs" / "libq.so").write_bytes(b"")
    (root / "Weird_Pkg" / ".libs").mkdir(parents=True)  # no RECORD: the package is the fallback
    (root / "Weird_Pkg" / ".libs" / "libw.so").write_bytes(b"")


def test_only_the_one_parser_reads_a_cyclonedx_components_list():
    strays = {site: lines for site, lines in _all_sites().items() if site != _PARSER_HOME}
    assert not strays, (
        "a CycloneDX `components` list is read outside "
        f"{_PARSER_HOME[0]}::{_PARSER_HOME[1]}: {strays}. Route the SBOM through "
        "_rows_from_bom (give it a `source`), never a second walker (PD-5)."
    )


def test_the_parser_home_still_reads_the_components_list():
    # Not stale: the home named above is a real site, so the pin is not vacuous.
    assert _PARSER_HOME in _all_sites(), (
        f"{_PARSER_HOME} no longer reads `components`: re-point this pin at the parser"
    )


def test_image_inventory_imports_nothing_that_loads_code():
    tree = next(parse_module(p) for p in iter_src_files() if relpath(p) == _PARSER_HOME[0])
    assert _loader_imports(tree) == [], (
        "image_inventory imports a module that loads or runs code; a .libs "
        "library is read as bytes and never loaded (punch 848 rule 7)"
    )


def test_every_bundled_carrier_in_this_interpreter_is_its_pep_503_name():
    rows, _ = ii.scan_bundled(ii.image_roots())
    assert _non_canonical(rows) == [], (
        "a bundled row's carrier is not its PEP 503 name; build every row "
        "through image_inventory._bundled_row (cve-arc keys findings on carrier)"
    )


def test_every_bundled_carrier_shape_emits_its_pep_503_name(tmp_path, monkeypatch):
    monkeypatch.setattr(ii, "_LIBS_CACHE", {})
    _every_carrier_shape(tmp_path)
    rows, errors = ii.scan_bundled([("purelib", tmp_path)])
    assert _non_canonical(rows) == []
    # Not vacuous: every shape gave rows, each under its canonical carrier.
    assert {(r["source"], r["carrier"]) for r in rows} == {
        ("dist-info-sbom", "cryptography"), ("dist-info-sbom", "foo-bar"),
        ("auditwheel-libs", "pillow"), ("auditwheel-libs", "scikit-learn"),
        ("auditwheel-libs", "odd-name"), ("auditwheel-libs", "weird-pkg"),
    }
    assert errors == [
        {"carrier": "Odd_Name", "error": "no dist-info names this carrier"},
        {"carrier": "Weird_Pkg", "error": "no dist-info RECORD lists this .libs dir"},
    ]


def test_pin_has_teeth():
    def strays(tree):
        return [s for s in _components_sites(tree) if s[1] != _PARSER_HOME[1]]

    assert_pin_has_teeth(
        strays,
        'def read(bom):\n    return bom.get("components")\n',
        'def _rows_from_bom(bom):\n    """Reads "components"."""\n    return bom["components"]\n',
    )
    assert_pin_has_teeth(
        strays, 'from operator import itemgetter\nget = itemgetter("components")\n',
    )
    assert_pin_has_teeth(
        _loader_imports, "import ctypes.util\n", "import struct\nfrom pathlib import Path\n",
    )
    assert_pin_has_teeth(_loader_imports, "from importlib import import_module\n")
    assert_pin_has_teeth(_loader_imports, "import os\n", "import stat\n")
    assert_pin_has_teeth(_loader_imports, "from os import system\n")
    assert _non_canonical([{"carrier": "Pillow"}, {"carrier": "scikit_learn"}, {"carrier": "pillow"}]) == [
        "Pillow", "scikit_learn"]
    assert _non_canonical([{"carrier": "scikit-learn"}, {"carrier": "odd-name"}]) == []
