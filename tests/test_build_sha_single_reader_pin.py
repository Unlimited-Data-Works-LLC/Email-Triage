"""ONE baked-build-sha reader under ``src/email_triage/`` (punch 539 rebase, 2026-09-30).

hipaa ``H539-1`` / db ``N-539-X1(a)`` / da ``DA-C6`` (panel 4, 2026-09-29): punch
538 (``GET /health/build``) and punch 542 (``GET /health/runtime-deps``) were
built on separate branches and each shipped its own reader of the baked
``/app/VERSION`` file plus its own full-sha regex. They were converged into
``email_triage._build_sha`` when 539-542 was rebased onto the main that carried
538. Nothing FAILED if that convergence was forgotten, and nothing fails if a
third reader arrives tomorrow, so this pin makes the convergence a property.

Two readers of one fact is the mirrored-copy drift PD-5 forbids, and here the
fact is the one a dependency scanner acts on: ``/health/build`` and
``/health/runtime-deps`` disagreeing about ``build_sha`` is the failure cve-arc's
ancestry rule cannot tolerate.

Count-agnostic (PD-1): every assertion is a property over EVERY module the
shared harness walks, never a length. Docstrings are exempt, because prose must
be able to name what code may not repeat. The home module is matched by its
EXACT package-relative path (``_build_sha.py``), never by a suffix: a suffix
match exempted ``web/served_build_sha.py`` (R38, db DB-539FC-2).

WHAT IS SEEN (hardened at the punch 539 fold-check, db DB-539FC-2 / da
DA-FC539-3, each arm with a planted mutant in the teeth test):

* the ``/app/VERSION`` literal in any code string;
* a full-sha shape gate, by MEANING, not spelling: any string passed to
  ``re.compile`` / ``fullmatch`` / ``match`` / ``search`` that fully matches 40
  hex characters and not 39 (``[a-f0-9]{40}``, ``[0-9a-fA-F]{40}``, ``\\w{40}``
  all qualify), plus the literal ``[0-9a-f]{40}`` in any code string;
* a reference to ``BAKED_VERSION_PATH`` under ANY spelling that binds the name:
  the bare name, an import alias (``from … import BAKED_VERSION_PATH as P``, any
  module, relative imports included), and attribute access on ANY receiver
  (``_build_sha.BAKED_VERSION_PATH``, ``m.BAKED_VERSION_PATH``). The attribute
  arm is receiver-agnostic, which is strictly wider than resolving the receiver
  through ``_pin_harness.module_ssot_imports`` (that helper resolves absolute
  imports only);
* at EVERY scope: module level, a class body and a lambda count as a reader,
  not only a function body.

WHAT IS NOT: a path assembled from parts (``Path("/app") / "VERSION"``), a hex
gate built without a regex (``set(string.hexdigits)``), a regex held in a
variable and compiled elsewhere under a different spelling, and anything outside
``src/email_triage/`` — ``scripts/check_deps_drift.py``'s in-container probe
opens ``/app/VERSION`` for display-only the monitoring system text and is out of this pin's
scope by design (hipaa H539FC-1). The funnel and no-environment properties of the
readers themselves are pinned in ``tests/test_web/test_health_build_endpoint.py``.

The LAST test pins the route side (db DB-539FC-1): every ``"build_sha"`` value
``web/routers/health.py`` emits is ``_served_build_sha(...)``, directly or
through a local bound only to that call. "Bound" means ``Assign`` /
``AnnAssign`` in the same function; an ``AugAssign`` or walrus rebinding of
that local after the funnel call is not seen.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    docstring_constant_ids,
    innermost_fn_at_lineno,
    parse_module,
    parse_source,
    walk_src,
)

#: The one module allowed to hold the baked path, the regex and the file read,
#: as the harness's package-relative key (EXACT match, never a suffix).
HOME = "_build_sha.py"
BAKED_PATH_LITERAL = "/app/VERSION"
FULL_SHA_PATTERN = "[0-9a-f]{40}"
BAKED_PATH_NAME = "BAKED_VERSION_PATH"
_REGEX_CALLS = frozenset({"compile", "fullmatch", "match", "search"})
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def code_literal_sites(tree: ast.AST, needle: str) -> list[int]:
    """Line of every NON-docstring string constant in ``tree`` containing ``needle``."""
    docs = docstring_constant_ids(tree)
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and needle in node.value
        and id(node) not in docs
    )


def is_full_sha_gate(pattern: str) -> bool:
    """True when ``pattern`` accepts exactly a 40-char hex run and not 39 — the
    MEANING of a full-sha gate, whatever the character-class spelling."""
    try:
        return bool(
            re.fullmatch(pattern, "a" * 40)
            and re.fullmatch(pattern, "0" * 40)
            and not re.fullmatch(pattern, "a" * 39)
        )
    except re.error:
        return False


def full_sha_gate_sites(tree: ast.AST) -> list[int]:
    """Lines where a full-sha shape gate is written: a regex call whose string
    argument is one (:func:`is_full_sha_gate`), or the canonical literal."""
    lines = set(code_literal_sites(tree, FULL_SHA_PATTERN))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else (
            func.id if isinstance(func, ast.Name) else ""
        )
        if name not in _REGEX_CALLS:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if is_full_sha_gate(arg.value):
                lines.add(node.lineno)
    return sorted(lines)


def _baked_path_aliases(tree: ast.AST) -> set[str]:
    """Every local name an import binds to ``BAKED_VERSION_PATH`` (any module)."""
    names = {BAKED_PATH_NAME}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == BAKED_PATH_NAME:
                    names.add(alias.asname or alias.name)
    return names


def _scope_of(node: ast.AST) -> str:
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, _SCOPES):
            return getattr(cur, "name", "<lambda>")
        cur = getattr(cur, "_ph_parent", None)
    return "<module>"


def baked_path_readers(tree: ast.AST) -> set[str]:
    """Every scope in ``tree`` (function, lambda, class body or ``<module>``) that
    READS ``BAKED_VERSION_PATH`` under any binding spelling. A store (the one
    assignment in the home module) is not a read."""
    names = _baked_path_aliases(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        hit = (
            isinstance(node, ast.Name)
            and node.id in names
            and isinstance(node.ctx, ast.Load)
        ) or (
            isinstance(node, ast.Attribute)
            and node.attr == BAKED_PATH_NAME
            and isinstance(node.ctx, ast.Load)
        )
        if hit:
            found.add(_scope_of(node))
    return found


def _sites(detector) -> dict[str, object]:
    out: dict[str, object] = {}
    for _path, rel, tree in walk_src():
        hit = detector(tree)
        if hit:
            out[rel] = hit
    return out


def _is_home(rel: str) -> bool:
    return rel == HOME


def test_the_baked_path_literal_lives_only_in_the_home_module():
    sites = _sites(lambda t: code_literal_sites(t, BAKED_PATH_LITERAL))
    assert any(_is_home(r) for r in sites), (
        f"no {BAKED_PATH_LITERAL!r} code literal in {HOME} — the detector or the "
        f"home moved, so a clean result elsewhere would mean nothing"
    )
    strays = {r: s for r, s in sites.items() if not _is_home(r)}
    assert not strays, (
        f"{strays}: a second spelling of the baked build-identity path. Import "
        f"BAKED_VERSION_PATH / read_baked_version from email_triage._build_sha "
        f"instead (hipaa H539-1, PD-5)."
    )


def test_the_full_sha_gate_lives_only_in_the_home_module():
    sites = _sites(full_sha_gate_sites)
    assert any(_is_home(r) for r in sites), (
        f"no full-sha gate in {HOME} — the detector or the home moved, so a "
        f"clean result elsewhere would mean nothing"
    )
    strays = {r: s for r, s in sites.items() if not _is_home(r)}
    assert not strays, (
        f"{strays}: a second full-sha shape gate. Import FULL_SHA_RE from "
        f"email_triage._build_sha — two gates WILL disagree about what a build "
        f"sha looks like (db N-539-X1)."
    )


def test_exactly_one_scope_reads_the_baked_path():
    sites = _sites(baked_path_readers)
    readers = sorted(f"{r}:{fn}" for r, fns in sites.items() for fn in fns)
    assert readers == [f"{HOME}:read_baked_version"], (
        f"scopes reading {BAKED_PATH_NAME}: {readers}. Exactly ONE may: "
        f"{HOME}:read_baked_version, and every other build identifier derives "
        f"from it. A second opener is a second reader of the fact a scanner acts "
        f"on (da DA-C6)."
    )


def test_the_home_key_is_exact_not_a_suffix():
    """R38: ``web/served_build_sha.py`` and ``cve/legacy_build_sha.py`` end with
    the home's basename and must NOT be treated as the home."""
    assert _is_home("_build_sha.py")
    for impostor in ("web/served_build_sha.py", "cve/legacy_build_sha.py",
                     "web/_build_sha.py", "x_build_sha.py"):
        assert not _is_home(impostor), impostor


def test_the_detectors_have_teeth():
    """Each arm FLAGS a planted second reader and passes a clean module, before
    any of them is trusted to report a clean tree. The mutants are db-sme's
    (DB-539FC-2) and da's (DA-FC539-3) planted shapes."""
    clean = (
        'from email_triage._build_sha import baked_build_sha\n'
        'import re\n'
        'SHORT = re.compile(r"[0-9a-f]{7,12}")\n'
        'def f():\n'
        '    """Reads /app/VERSION and checks [0-9a-f]{40}, in prose only."""\n'
        '    return baked_build_sha()\n'
    )
    # the literal arm
    assert_pin_has_teeth(
        lambda t: code_literal_sites(t, BAKED_PATH_LITERAL),
        'def g():\n    return open("/app/VERSION").read()\n',
        clean,
    )
    # the full-sha arm: canonical spelling, then three other spellings
    for bad in (
        'import re\nX = re.compile(r"[0-9a-f]{40}")\n',
        'import re\nX = re.compile(r"[a-f0-9]{40}")\n',
        'import re\ndef ok(v):\n    return re.fullmatch("[0-9a-fA-F]{40}", v)\n',
        'from re import match\nY = match(r"\\w{40}", "x")\n',
    ):
        assert_pin_has_teeth(full_sha_gate_sites, bad, clean)
    # the reader arm: bare name in a default, an alias, an attribute on the
    # module, and a module-level read
    for bad in (
        'def h(p=BAKED_VERSION_PATH):\n    return p\n',
        'from email_triage._build_sha import BAKED_VERSION_PATH as _BVP\n'
        'def h():\n    return open(_BVP).read()\n',
        'import email_triage._build_sha as _bsmod\n'
        'def h():\n    return open(_bsmod.BAKED_VERSION_PATH).read()\n',
        'from email_triage import _build_sha\n'
        'X = open(_build_sha.BAKED_VERSION_PATH).read()\n',
        'from .._build_sha import BAKED_VERSION_PATH as P\n'
        'READ = lambda: open(P).read()\n',
    ):
        assert_pin_has_teeth(baked_path_readers, bad, clean)
    # a store is not a read: the home's own assignment must not count
    assert baked_path_readers(parse_source('BAKED_VERSION_PATH = "/x"\n')) == set()
    # the docstring exemption is real, not accidental
    assert code_literal_sites(parse_source(clean), BAKED_PATH_LITERAL) == []


# ---------------------------------------------------------------------------
# The route side (db DB-539FC-1): one served value, through one funnel
# ---------------------------------------------------------------------------

HEALTH = "web/routers/health.py"
FUNNEL = "_served_build_sha"


def _is_funnel_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == FUNNEL
    )


def _bound_only_to_funnel(name: str, scope: ast.AST) -> bool:
    """True when every assignment to ``name`` inside ``scope`` is a funnel call."""
    values = [
        n.value for n in ast.walk(scope)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
    ] + [
        n.value for n in ast.walk(scope)
        if isinstance(n, ast.AnnAssign)
        and isinstance(n.target, ast.Name) and n.target.id == name
        and n.value is not None
    ]
    return bool(values) and all(_is_funnel_call(v) for v in values)


def build_sha_values(tree: ast.AST) -> list[ast.AST]:
    """Every expression emitted under the ``build_sha`` key: a dict-literal
    value, a ``dict(build_sha=…)`` keyword, or a ``x["build_sha"] = …`` store."""
    out: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "build_sha":
                    out.append(v)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "dict":
            out.extend(kw.value for kw in node.keywords if kw.arg == "build_sha")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) \
                        and t.slice.value == "build_sha":
                    out.append(node.value)
    return out


def unfunneled_build_sha_values(tree: ast.AST) -> list[int]:
    """Lines of ``build_sha`` values that are neither the funnel call nor a local
    bound only to it."""
    bad: list[int] = []
    for v in build_sha_values(tree):
        if _is_funnel_call(v):
            continue
        scope = innermost_fn_at_lineno(tree, v.lineno) or tree
        if isinstance(v, ast.Name) and _bound_only_to_funnel(v.id, scope):
            continue
        bad.append(getattr(v, "lineno", 0))
    return bad


def test_every_served_build_sha_goes_through_the_funnel():
    tree = parse_module(SRC_ROOT / HEALTH)
    assert tree is not None
    values = build_sha_values(tree)
    assert len(values) >= 2, (
        f"found {len(values)} build_sha value(s) in {HEALTH}; both build-identity "
        f"routes emit one, so the detector or the routes moved"
    )
    bad = unfunneled_build_sha_values(tree)
    assert not bad, (
        f"{HEALTH} lines {bad}: a build_sha value that is not {FUNNEL}(...). "
        f"Both routes must serve app.state.build_sha through the ONE shape-gated "
        f"funnel, or they can disagree (db DB-539FC-1)."
    )


def test_the_funnel_detector_has_teeth():
    """db's two mutants of ``health.py:1779`` both went green before this arm."""
    good = (
        'def a(request):\n'
        '    build_sha = _served_build_sha(request)\n'
        '    return {"build_sha": build_sha, "version": "x"}\n'
        'def b(request):\n'
        '    return {"build_sha": _served_build_sha(request)}\n'
    )
    for bad in (
        'def b(request):\n    return {"build_sha": baked_build_sha()}\n',
        'def b(request):\n    return {"build_sha": read_baked_version()[:40]}\n',
        'def b(request):\n    s = read_baked_version()\n    return {"build_sha": s}\n',
        'def b(request):\n    return dict(build_sha=request.app.state.build_sha)\n',
        'def b(request):\n    out = {}\n    out["build_sha"] = "x"\n    return out\n',
    ):
        assert_pin_has_teeth(unfunneled_build_sha_values, bad, good)
