"""Pin: every package a lock pins is reachable from a ``pyproject.toml`` root, or is on a reasoned allowlist (PD-1, PD-2, PD-5).

Why this exists. The installed-but-unused audit (2026-10-17) found alembic and mako in
the production image with no runtime consumer. pyproject then stopped requiring alembic
in the image's dependencies (it is dev-only), and the OLD ``requirements.lock``, still
pinning alembic and mako, passed every pin. N-542 reads pyproject -> lock (is each
requirement pinned, at a satisfying version). N-545 reads the lock's own shape. Neither
reads lock -> pyproject: nothing asked whether a pin is still wanted by anyone. A dropped
requirement left its pin, and everything that pin pulls in, in the image.

INVARIANT (count-agnostic, over every lock pin):
  O1  every entry in each ``requirements*.lock`` is reachable from a ROOT along the
      lock's ``# via`` edges (parent -> child), or is on ``_ALLOW`` with a reason.
      A root is a requirement in ``[project].dependencies`` or in an extra the lock
      was compiled with. A self-referencing extra (``email-triage[cache]``) is expanded.
  O2  the allowlist is not stale: each entry is pinned in its lock, would be an
      orphan without it, and carries a reason.
  O3  the image lock's header names exactly the extras scripts/regen-lock.sh compiles
      into it, so the extras O1 reads as roots are the script's, not a stale header's
      (the dev lock's header is the same check, punch 511 D2/D3). O3 also refuses a header
      carrying --no-annotate or --annotation-style=line, so a RED names its cause.
  O4  every requirement in [project].dependencies and in every extra EXCEPT the test-only
      ones (dev, e2e) is imported by some module under src/email_triage, or sits on
      _ALLOW_UNIMPORTED with a reason and the file:line of its runtime use. O1 asks
      whether a PIN is wanted; O4 asks whether a DECLARED requirement is used. At 2d279690
      alembic was a pyproject root, so O1 called alembic and mako reachable and stayed
      green on the defect that motivated this pin; O4 goes RED there. It also covers an
      extra no lock compiles (the gemini shape), which never enters _LOCKS.

ROOTS COME FROM pyproject, NEVER FROM THE LOCK. The lock's ``# via email-triage
(pyproject.toml)`` line is the lock's CLAIM that pyproject asks for a pin. A stale lock
still makes that claim for alembic. Reading roots from it would call every pin justified
and stay green on the exact defect this pin exists for. The edges come from the lock
(a transitive dependency appears nowhere else); the roots do not.

PROXY vs OBJECT. The ``# via`` edges are pip-compile's record of the resolve it ran. This
pin proves the lock agrees with the pyproject it sits beside. It does not prove that the
image installs nothing but the lock (hash-checking mode, N-545 P1, does) or that a pin
is used at runtime (O4 asks the narrower question of whether src imports each declared
requirement; an import is still not proof of use). The edges are trusted as pip-compile wrote them: a
hand-edited ``# via`` line can hide an orphan behind a real root (measured 2026-10-17:
relabelling mako's ``# via`` to a real root hid it), and only a regen
(scripts/regen-lock.sh) re-derives them.

All lock reading goes through scripts/lock_reader.py (PD-5): ``LockedSet.via`` holds the
edges, the same parser N-542 and N-545 use. The extras are read the way N-542 reads them
(the lock header, ``header_extras``) and anchored to scripts/regen-lock.sh by O3.
"""

from __future__ import annotations

import ast
import copy
import functools
import importlib.metadata as _md
import tomllib

import pytest
from packaging.requirements import Requirement

from _pin_harness import REPO_ROOT, load_repo_script, parse_source, walk_src
from test_punch511_ci_installs_are_hash_locked_pin import _regen_extras  # the one regen-script reader (PD-5)

#: THE lock parser (PD-5).
drift = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")

_PYPROJECT = REPO_ROOT / "pyproject.toml"
_REGEN = REPO_ROOT / "scripts" / "regen-lock.sh"
_IMAGE_LOCK = REPO_ROOT / "requirements.lock"
_DEV_LOCK = REPO_ROOT / "requirements-dev.lock"
#: Every lock at the repo root: requirements.lock (the image) and requirements-dev.lock (CI).
_LOCKS = sorted(REPO_ROOT.glob("requirements*.lock"))

#: (lock file name, canonical package) -> why the pin is installed with no pyproject path
#: to it. Empty on purpose: a pin nobody asks for belongs out of the lock, not on a list.
#: Entries are keyed by lock name AND package (a pin allowed in the dev lock must not be
#: allowed in the image's), and are stable under unrelated edits (no line numbers).
_ALLOW: dict[tuple[str, str], str] = {}

_HINT = (
    "A pin no pyproject root reaches is an installed-but-unused package. Remove its requirement "
    "from the right extra (or drop the dead pin by regenerating with scripts/regen-lock.sh on a "
    "Linux podman host), or, if it is installed on purpose, add it to _ALLOW with the reason."
)


def _expand(raws, optional: dict, own: str, seen: set[str]):
    """Canonical names of the requirements in ``raws``; a self-referencing extra
    (``email-triage[cache]``) is replaced by that extra's requirements."""
    for raw in raws:
        req = Requirement(raw)
        name = drift.canonical(req.name)
        if name != own:
            yield name
            continue
        for extra in sorted(e.lower() for e in req.extras):
            if extra not in seen:
                seen.add(extra)
                yield from _expand(optional.get(extra, []), optional, own, seen)


def _roots(pyproject: dict, lock_text: str) -> frozenset[str]:
    """The packages pyproject asks for: ``[project].dependencies`` plus the extras the lock
    was compiled with. Environment markers are ignored: reachability asks whether anything
    wants a pin, and a marker that is false here still wants it on its own platform."""
    project = pyproject["project"]
    optional = project.get("optional-dependencies", {})
    scoped = list(project.get("dependencies", []))
    seen: set[str] = set()
    for extra in sorted(drift.header_extras(lock_text)):
        seen.add(extra)
        scoped.extend(optional.get(extra, []))
    return frozenset(_expand(scoped, optional, drift.canonical(project["name"]), seen))


def _orphans(pyproject: dict, lock_text: str, allow=frozenset()) -> list[str]:
    """Pins in ``lock_text`` that no pyproject root (or ``allow`` entry) reaches along the
    lock's ``# via`` edges. A pin reachable only through another orphan, or only through a
    cycle of orphans, is an orphan too."""
    locked = drift.parse_lock(lock_text, None)
    every = set(locked.pins) | set(locked.unevaluated) | set(locked.not_applicable)
    assert every == set(locked.via), "parse_lock lost an entry's # via"
    children: dict[str, set[str]] = {}
    for child, parents in locked.via.items():
        for parent in parents:
            children.setdefault(parent, set()).add(child)
    reached: set[str] = set()
    frontier = [n for n in _roots(pyproject, lock_text) | set(allow) if n in every]
    while frontier:
        name = frontier.pop()
        if name not in reached:
            reached.add(name)
            frontier.extend(children.get(name, ()))
    return sorted(every - reached)


def _stale_allow(pyproject: dict, lock_text: str, allow: dict[str, str]) -> list[str]:
    """O2: allowlist entries that name no pin, that need no entry, or that give no reason."""
    pinned = set(drift.parse_lock(lock_text, None).via)
    needed = set(_orphans(pyproject, lock_text))
    out = []
    for name, reason in sorted(allow.items()):
        if name not in pinned:
            out.append(f"{name}: not pinned in the lock")
        elif name not in needed:
            out.append(f"{name}: already reachable from a pyproject root, drop the entry")
        if not reason.strip():
            out.append(f"{name}: no reason")
    return out


def _image_header_violations(lock_text: str, regen_text: str) -> list[str]:
    """O3."""
    want, got = _regen_extras(regen_text, ("EXTRAS",)), drift.header_extras(lock_text)
    out = []
    if want - got:
        out.append(f"the image lock never compiled extras {sorted(want - got)} that scripts/regen-lock.sh names")
    if got - want:
        out.append(f"the image lock compiled extras {sorted(got - want)} that scripts/regen-lock.sh does not name")
    flags = drift.header_command(lock_text).split()
    for flag in ("--no-annotate", "--annotation-style=line"):
        if flag in flags:
            out.append(f"the image lock header carries {flag}, which blinds or corrupts the # via edges O1 reads")
    return out


def _real_pyproject() -> dict:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))


def _allow_for(lock_name: str) -> dict[str, str]:
    return {pkg: why for (lock, pkg), why in _ALLOW.items() if lock == lock_name}


# --- the invariants on the real tree ----------------------------------------------


def test_every_repo_lock_is_in_scope() -> None:
    assert _IMAGE_LOCK in _LOCKS, "the lock glob missed requirements.lock; the scanner is blind"
    assert _DEV_LOCK in _LOCKS, "the lock glob missed requirements-dev.lock; the scanner is blind to the dev lock"


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_o1_every_lock_pin_is_reachable_from_a_pyproject_root(lock_path) -> None:
    text = lock_path.read_text(encoding="utf-8")
    assert _orphans(_real_pyproject(), text, _allow_for(lock_path.name)) == [], _HINT


@pytest.mark.parametrize("lock_path", _LOCKS, ids=lambda p: p.name)
def test_the_scanner_reads_real_roots_and_real_edges(lock_path) -> None:
    """Not vacuous: an empty edge map or an empty root set would reach nothing and flag
    every pin (RED), but a regression that made ``_orphans`` return early would stay green."""
    text = lock_path.read_text(encoding="utf-8")
    locked = drift.parse_lock(text, None)
    assert any(locked.via.values()), "no # via edge read from the lock; the edge reader is blind"
    assert _roots(_real_pyproject(), text) & set(locked.via), "no pyproject root is pinned in the lock; the root reader is blind"


def test_o2_the_allowlist_is_not_stale() -> None:
    assert {lock for lock, _ in _ALLOW} <= {p.name for p in _LOCKS}, "an _ALLOW entry names a lock that does not exist"
    pyproject = _real_pyproject()
    for lock_path in _LOCKS:
        stale = _stale_allow(pyproject, lock_path.read_text(encoding="utf-8"), _allow_for(lock_path.name))
        assert stale == [], (lock_path.name, stale)


def test_o3_the_image_lock_header_names_the_extras_the_regen_script_compiles() -> None:
    lock = _IMAGE_LOCK.read_text(encoding="utf-8")
    assert _image_header_violations(lock, _REGEN.read_text(encoding="utf-8")) == []


# --- teeth: each must-sentence above, planted and caught --------------------------

_NL = chr(10)
_H = chr(92)  # the continuation backslash pip-compile writes before each hash line
_SHA = "--hash=sha256:" + "a" * 64
_PROJECT = "email-triage (pyproject.toml)"
_BOTH_FORMATS = (True, False)  # hashed, plain


def _header(*extras: str) -> str:
    flags = " ".join(f"--extra={e}" for e in extras)
    return f"#{_NL}#    pip-compile {flags} --generate-hashes --output-file=requirements.lock pyproject.toml{_NL}#{_NL}"


def _entry(spec: str, *via: str, hashed: bool = True) -> str:
    """One lock entry as pip-compile writes it: the pin, its hash lines, its ``# via``."""
    out = f"{spec} {_H}{_NL}    {_SHA}{_NL}" if hashed else f"{spec}{_NL}"
    if len(via) == 1:
        return out + f"    # via {via[0]}{_NL}"
    return out + f"    # via{_NL}" + "".join(f"    #   {v}{_NL}" for v in sorted(via))


def _pyproject(deps: list[str], **extras: list[str]) -> dict:
    return {"project": {"name": "email-triage", "dependencies": deps, "optional-dependencies": extras}}


def _old_lock(hashed: bool) -> str:
    """The shape of the requirements.lock before alembic left the image (excerpt, 2d279690):
    alembic asked for by the project, mako only by alembic, alembic under sqlalchemy's and
    typing-extensions's edges as well."""
    e = lambda spec, *via: _entry(spec, *via, hashed=hashed)  # noqa: E731
    return _header("cache") + (
        e("alembic==1.19.1", _PROJECT)
        + e("jinja2==3.1.6", _PROJECT)
        + e("mako==1.4.3", "alembic")
        + e("markupsafe==3.0.3", _PROJECT, "jinja2", "mako")
        + e("sqlalchemy==2.0.52", "alembic", _PROJECT)
        + e("typing-extensions==4.16.0", "alembic", "sqlalchemy")
    )


#: pyproject AFTER alembic moved to the dev extra, which the image lock is not compiled with.
_PYPROJECT_NOW = _pyproject(["jinja2>=3.1", "markupsafe>=2.1", "sqlalchemy>=2.0"], dev=["alembic>=1.13"])


@pytest.mark.parametrize("hashed", _BOTH_FORMATS, ids=("hashed", "plain"))
def test_teeth_the_old_lock_with_the_current_pyproject_reports_alembic_and_mako(hashed) -> None:
    """The incident: pyproject no longer asks for alembic, the lock still pins it and
    still says (via email-triage) that pyproject does. Both orphans are reported; the
    pins other roots still reach (typing-extensions, via sqlalchemy) are not."""
    assert _orphans(_PYPROJECT_NOW, _old_lock(hashed)) == ["alembic", "mako"]
    # good variant: pyproject that still requires alembic in the image leaves no orphan
    still = _pyproject(["jinja2>=3.1", "markupsafe>=2.1", "sqlalchemy>=2.0", "alembic>=1.13"])
    assert _orphans(still, _old_lock(hashed)) == []


def test_teeth_roots_never_come_from_the_locks_own_via_claim() -> None:
    """alembic's ``# via email-triage (pyproject.toml)`` must not make alembic a root."""
    assert "alembic" not in _roots(_PYPROJECT_NOW, _old_lock(True))
    assert _roots(_PYPROJECT_NOW, _old_lock(True)) == {"jinja2", "markupsafe", "sqlalchemy"}


def test_teeth_the_old_pins_planted_in_the_real_image_lock_are_caught() -> None:
    """The same defect on the real tree's text: the current lock plus the two pins the
    audit removed. Nothing on disk is touched."""
    lock = _IMAGE_LOCK.read_text(encoding="utf-8")
    planted = lock + _entry("alembic==1.19.1", _PROJECT) + _entry("mako==1.4.3", "alembic")
    assert _orphans(_real_pyproject(), lock) == []
    assert _orphans(_real_pyproject(), planted) == ["alembic", "mako"]


def test_teeth_an_orphan_cycle_and_a_chain_off_an_orphan_are_caught() -> None:
    lock = _header() + (
        _entry("root==1", _PROJECT)
        + _entry("child==1", "root")
        + _entry("grandchild==1", "child")
        + _entry("cyc-a==1", "cyc-b")
        + _entry("cyc-b==1", "cyc-a")
        + _entry("tail==1", "cyc-a")
    )
    assert _orphans(_pyproject(["root"]), lock) == ["cyc-a", "cyc-b", "tail"]


def test_teeth_names_match_by_pep_503_normalization() -> None:
    lock = _header() + _entry("Ruamel.Yaml==1", _PROJECT) + _entry("Typing_Extensions==2", "ruamel-yaml")
    assert _orphans(_pyproject(["ruamel-yaml>=1"]), lock) == []
    assert _orphans(_pyproject(["other"]), lock) == ["ruamel-yaml", "typing-extensions"]


def test_teeth_only_the_extras_the_lock_was_compiled_with_are_roots() -> None:
    pyproject = _pyproject([], cache=["redis>=5"], dev=["pytest>=8"])
    lock_for = lambda *extras: _header(*extras) + _entry("redis==5", _PROJECT) + _entry("pytest==8", _PROJECT)  # noqa: E731
    assert _orphans(pyproject, lock_for("cache")) == ["pytest"]
    assert _orphans(pyproject, lock_for("cache", "dev")) == []
    assert _orphans(pyproject, lock_for()) == ["pytest", "redis"]


def test_teeth_a_self_referencing_extra_is_expanded() -> None:
    pyproject = _pyproject([], cache=["redis>=5"], everything=["email-triage[cache]"])
    lock = _header("everything") + _entry("redis==5", _PROJECT)
    assert _orphans(pyproject, lock) == []
    cyclic = _pyproject([], a=["email-triage[b]", "x"], b=["email-triage[a]", "y"])
    assert _roots(cyclic, _header("a")) == {"x", "y"}, "a cycle of self-referencing extras must terminate"


def test_teeth_the_via_reader_takes_packages_and_drops_requirement_sources() -> None:
    lock = _header("cache") + (
        _entry("one==1", _PROJECT)
        + _entry("two==1", "one")
        + _entry("three==1", "-c requirements.lock.pins", "one", "two", _PROJECT)
    )
    assert dict(drift.parse_lock(lock, None).via) == {
        "one": frozenset(),
        "two": frozenset({"one"}),
        "three": frozenset({"one", "two"}),
    }


def test_teeth_a_marker_gated_pin_is_read_and_reached() -> None:
    lock = _header() + _entry("colorama==0.4.6 ; sys_platform == \"win32\"", "click") + _entry("click==8", _PROJECT)
    assert _orphans(_pyproject(["click"]), lock) == []
    assert _orphans(_pyproject(["other"]), lock) == ["click", "colorama"]


def test_teeth_an_allowlisted_orphan_and_its_children_are_accepted() -> None:
    lock = _header() + _entry("root==1", _PROJECT) + _entry("kept==1", _PROJECT) + _entry("leaf==1", "kept")
    assert _orphans(_pyproject(["root"]), lock) == ["kept", "leaf"]
    assert _orphans(_pyproject(["root"]), lock, allow={"kept"}) == []


def test_teeth_a_stale_or_reasonless_allowlist_entry_is_caught() -> None:
    lock = _header() + _entry("root==1", _PROJECT) + _entry("kept==1", _PROJECT)
    pyproject = _pyproject(["root"])
    assert _stale_allow(pyproject, lock, {"kept": "installed for the sidecar"}) == []
    assert _stale_allow(pyproject, lock, {"gone": "was needed once"}) == ["gone: not pinned in the lock"]
    assert _stale_allow(pyproject, lock, {"root": "already asked for"}) == [
        "root: already reachable from a pyproject root, drop the entry"
    ]
    assert _stale_allow(pyproject, lock, {"kept": "  "}) == ["kept: no reason"]


def test_teeth_o3_a_header_that_disagrees_with_the_regen_script_is_caught() -> None:
    regen = 'EXTRAS="--extra=cache --extra=imap"' + _NL + 'DEV_EXTRAS="--extra=dev"' + _NL
    assert _image_header_violations(_header("cache", "imap"), regen) == []
    assert _image_header_violations(_header("cache"), regen) == [
        "the image lock never compiled extras ['imap'] that scripts/regen-lock.sh names"
    ]
    assert _image_header_violations(_header("cache", "imap", "dev"), regen) == [
        "the image lock compiled extras ['dev'] that scripts/regen-lock.sh does not name"
    ]


# --- O4: every declared requirement has an importer under src/ -----------------------

#: Extras that are test or CI tooling and never imported by src. `dev` and `e2e` are the extras
#: regen-lock.sh compiles into the dev lock only (DEV_EXTRAS, asserted below; e2e since punch 622);
#: `ci` is the CI tool set it compiles into requirements-ci-tools.lock only (punch 623; N-542
#: _EXCLUDED_EXTRAS gives the same reasons). Every other extra is checked.
_TEST_ONLY_EXTRAS = frozenset({"dev", "e2e", "ci"})

#: distribution -> top-level modules, for names where they differ and for dists a test env may
#: not have installed (importlib.metadata sees only installed ones). Any other dist falls back to
#: its installed modules, then to its name with - as _. A dist that cannot be mapped has no
#: importer, so O4 goes RED naming it; it never skips.
_MODULES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pyjwt": ("jwt",),
    "dnspython": ("dns",),
    "python-multipart": ("python_multipart", "multipart"),
    "sentence-transformers": ("sentence_transformers",),
}

#: canonical dist -> (path:line of its runtime use, a string that file must contain, why src never
#: imports it by name). Keyed by dist, not by section: a dist allowed here is allowed wherever it
#: is declared. An entry for a dist with no runtime use says so in its reason.
_ALLOW_UNIMPORTED: dict[str, tuple[str, str, str]] = {
    "python-multipart": (
        "src/email_triage/web/form_limits.py:64",
        "request.form()",
        "Starlette imports python_multipart itself when request.form() parses a form or multipart body",
    ),
    "certifi": (
        "src/email_triage/_http_client.py:43",
        "import httpx",
        "GHSA-6q48-6c7w-9gw2 floor on the CA bundle httpx and requests verify against (pyproject.toml); "
        "httpx and requests import certifi and src imports both",
    ),
    "pyasn1": (
        "src/email_triage/web/webauthn_auth.py:35",
        "webauthn",
        "CVE-2026-59885/59886 floor on webauthn's own dependency (pyproject.toml); webauthn imports pyasn1 and src imports webauthn",
    ),
    "torch": (
        "src/email_triage/embedding_bits/__init__.py:1392",
        "sentence_transformers",
        "the embedding runtime is installed at run time from a hash manifest; sentence-transformers imports torch",
    ),
}

_HINT_O4 = (
    "A declared requirement no module under src/email_triage imports is installed and unused (DECLARED-UNUSED). "
    "Remove it from pyproject.toml (and regenerate the locks on a Linux podman host), or, if it is loaded without "
    "an import, add it to _ALLOW_UNIMPORTED with the file:line of its runtime use."
)


def _imported_modules(trees) -> frozenset[str]:
    """Top-level module names the parsed modules in ``trees`` import: ``import x``, ``from x import y``
    (absolute) and a string literal passed to ``import_module`` / ``find_spec`` / ``__import__``."""
    found: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in ("import_module", "find_spec", "__import__"):
                    found.add(node.args[0].value.split(".")[0])
    return frozenset(found)


def _real_imports() -> frozenset[str]:
    """What src/email_triage imports, walked through the shared pin harness (a file it cannot parse is skipped by
    the harness, as for every structural pin)."""
    return _imported_modules(tree for _path, _rel, tree in walk_src())


@functools.cache
def _installed_modules() -> dict[str, frozenset[str]]:
    by_dist: dict[str, set[str]] = {}
    for module, dists in _md.packages_distributions().items():
        for dist in dists:
            by_dist.setdefault(drift.canonical(dist), set()).add(module)
    return {dist: frozenset(mods) for dist, mods in by_dist.items()}


def _modules_for(dist: str) -> frozenset[str]:
    return frozenset(_MODULES.get(dist, ())) | _installed_modules().get(dist, frozenset()) | {dist.replace("-", "_")}


def _checked_requirements(pyproject: dict) -> dict[str, set[str]]:
    """section -> canonical dist names, for ``[project].dependencies`` and every non-test extra."""
    project = pyproject["project"]
    own = drift.canonical(project["name"])
    sections = {"dependencies": project.get("dependencies", [])}
    for extra, reqs in project.get("optional-dependencies", {}).items():
        if extra.lower() not in _TEST_ONLY_EXTRAS:
            sections[f"extra {extra}"] = reqs
    return {s: {n for n in (drift.canonical(Requirement(r).name) for r in reqs) if n != own} for s, reqs in sections.items()}


def _unimported(pyproject: dict, imported, allow) -> list[str]:
    """``"section: dist"`` for each checked requirement with no importer and no ``allow`` entry."""
    return sorted(
        f"{section}: {dist}"
        for section, dists in _checked_requirements(pyproject).items()
        for dist in dists
        if dist not in allow and not (_modules_for(dist) & imported)
    )


def _stale_unimported_allow(pyproject: dict, imported, allow, root: Path = REPO_ROOT) -> list[str]:
    """O4 allowlist hygiene: an entry must name a declared requirement, still need the entry, give a
    reason, and cite a file that exists, contains the needle, and has that line."""
    declared = set().union(*_checked_requirements(pyproject).values())
    needed = {entry.split(": ", 1)[1] for entry in _unimported(pyproject, imported, {})}
    out = []
    for dist, (use, needle, why) in sorted(allow.items()):
        if dist not in declared:
            out.append(f"{dist}: not declared in a checked section")
        elif dist not in needed:
            out.append(f"{dist}: has an importer now, drop the entry")
        if not why.strip():
            out.append(f"{dist}: no reason")
        rel, _, line = use.rpartition(":")
        cited = root / rel
        if not cited.is_file():
            out.append(f"{dist}: cited file {rel} does not exist")
            continue
        body = cited.read_text(encoding="utf-8")
        if needle not in body:
            out.append(f"{dist}: {rel} no longer contains {needle!r}")
        if not line.isdigit() or not 1 <= int(line) <= len(body.splitlines()):
            out.append(f"{dist}: cited line {line!r} is outside {rel}")
    return out


def test_o4_every_declared_requirement_has_an_importer_or_a_reasoned_entry() -> None:
    assert _unimported(_real_pyproject(), _real_imports(), _ALLOW_UNIMPORTED) == [], _HINT_O4


def test_o4_the_allowlist_is_not_stale() -> None:
    stale = _stale_unimported_allow(_real_pyproject(), _real_imports(), _ALLOW_UNIMPORTED)
    assert stale == [], stale


def test_o4_the_test_only_extras_come_from_the_lock_ssot() -> None:
    assert "dev" in _regen_extras(_REGEN.read_text(encoding="utf-8"), ("DEV_EXTRAS",)), (
        "scripts/regen-lock.sh no longer compiles `dev` into the dev lock only; O4 would exempt the wrong extra"
    )
    declared = {e.lower() for e in _real_pyproject()["project"].get("optional-dependencies", {})}
    assert _TEST_ONLY_EXTRAS <= declared, "a test-only extra O4 exempts is no longer declared"
    assert _checked_requirements(_real_pyproject())["dependencies"], "O4 read no runtime requirement; the scanner is blind"


def test_o4_the_scanner_reads_real_imports() -> None:
    imported = _real_imports()
    assert {"fastapi", "yaml", "httpx"} <= imported, "the import scan found no known import; the scanner is blind"


# --- teeth: each must-sentence above, planted and caught ---------------------------


def test_o4_teeth_alembic_as_a_root_with_no_importer_is_red() -> None:
    """The 2d279690 shape: alembic in [project].dependencies. O1 was green on it; O4 names alembic."""
    imported = _real_imports()
    old = copy.deepcopy(_real_pyproject())
    old["project"]["dependencies"].append("alembic>=1.13")
    assert _unimported(_real_pyproject(), imported, _ALLOW_UNIMPORTED) == []
    assert _unimported(old, imported, _ALLOW_UNIMPORTED) == ["dependencies: alembic"]


def test_o4_teeth_an_extra_nobody_imports_is_red() -> None:
    """The gemini shape: an extra no lock compiles, so O1 never sees it."""
    gemini = copy.deepcopy(_real_pyproject())
    gemini["project"].setdefault("optional-dependencies", {})["gemini"] = ["google-generativeai>=0.8.0"]
    assert _unimported(gemini, _real_imports(), _ALLOW_UNIMPORTED) == ["extra gemini: google-generativeai"]


def test_o4_teeth_the_test_only_extras_are_not_checked() -> None:
    py = copy.deepcopy(_real_pyproject())
    py["project"]["optional-dependencies"]["dev"].append("some-test-tool>=1")
    py["project"]["optional-dependencies"]["e2e"].append("some-browser-tool>=1")
    assert _unimported(py, _real_imports(), _ALLOW_UNIMPORTED) == []


def test_o4_teeth_every_import_form_counts() -> None:
    tree = parse_source(
        "import plain_a\nimport b_pkg.sub as b\nfrom c_pkg.sub import x\nfrom . import rel_d\nfrom .rel_e import y\n"
        "importlib.import_module('d_pkg.x')\nimportlib.util.find_spec('e_pkg')\n__import__('f_pkg')\nopen('not_a_module')\n"
    )
    assert _imported_modules([tree]) == {"plain_a", "b_pkg", "c_pkg", "d_pkg", "e_pkg", "f_pkg"}


def test_o4_teeth_an_unmappable_dist_is_red_not_skipped() -> None:
    py = {"project": {"name": "x", "dependencies": ["no-such-dist-anywhere>=1"]}}
    assert _unimported(py, frozenset({"unrelated"}), {}) == ["dependencies: no-such-dist-anywhere"]
    assert _unimported(py, frozenset({"no_such_dist_anywhere"}), {}) == []


def test_o4_teeth_a_stale_allowlist_entry_is_caught(tmp_path) -> None:
    (tmp_path / "f.py").write_text("line one\nuses the thing\n", encoding="utf-8", newline="\n")
    py = {"project": {"name": "x", "dependencies": ["needed-dist>=1", "imported-dist>=1"]}}
    imported = frozenset({"imported_dist"})
    good = {"needed-dist": ("f.py:2", "uses the thing", "loaded without an import")}
    assert _stale_unimported_allow(py, imported, good, tmp_path) == []
    bad = {
        "imported-dist": ("f.py:2", "uses the thing", "has an importer"),
        "gone-dist": ("f.py:2", "uses the thing", "not declared"),
        "needed-dist": ("f.py:9", "absent needle", " "),
    }
    stale = _stale_unimported_allow(py, imported, {**bad, "needed-dist": bad["needed-dist"]}, tmp_path)
    assert any("imported-dist: has an importer now" in s for s in stale)
    assert any("gone-dist: not declared" in s for s in stale)
    assert any("needed-dist: no reason" in s for s in stale)
    assert any("no longer contains 'absent needle'" in s for s in stale)
    assert any("cited line '9' is outside" in s for s in stale)
    missing = {"needed-dist": ("nope.py:1", "x", "why")}
    assert _stale_unimported_allow(py, imported, missing, tmp_path) == ["needed-dist: cited file nope.py does not exist"]


def test_o3_teeth_a_header_flag_that_corrupts_the_edges_names_its_cause() -> None:
    lock = _IMAGE_LOCK.read_text(encoding="utf-8")
    regen = _REGEN.read_text(encoding="utf-8")
    assert _image_header_violations(lock, regen) == []
    for flag in ("--no-annotate", "--annotation-style=line"):
        planted = lock.replace("--generate-hashes", f"--generate-hashes {flag}", 1)
        assert planted != lock, "the plant did not land; the header has no --generate-hashes"
        assert [v for v in _image_header_violations(planted, regen) if flag in v], flag
