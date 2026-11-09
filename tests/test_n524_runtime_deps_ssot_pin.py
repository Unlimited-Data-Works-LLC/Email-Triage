"""Structural pins for the embedding runtime-deps drift fix (N-524 / N-525 / N-526).

WHAT WENT WRONG, so the invariants below read as consequences rather than taste.

The embedding feature pip-installs ~18 distributions into ``/app/data/runtime-deps``,
a HOST BIND MOUNT that survives every image rebuild. Three defects composed:

1. **Nothing compared the installed set with the manifest.** ``manifest_sha256``
   was written to the install-state row and only ever DISPLAYED; ``reverify``
   never read it. So an install made against a 2026-05 manifest stayed on the
   volume and stayed loadable after the image moved on — measured by cve-arc on
   2026-09-29 as 18 distributions with 104 OSV records, one CRITICAL
   (CVE-2025-32434), invisible to every scanner because no repository manifest
   describes a post-build install.
2. **``add_runtime_to_sys_path`` used ``sys.path.insert(0, …)``**, so the volume
   sat ahead of the image AND the stdlib, permanently (nothing ever removed the
   entry). And it was reached from a *page render*: opening the admin
   AI-backends tab called ``is_runtime_ready()`` → ``add_runtime_to_sys_path()``,
   with no check of whether the embedding feature was even configured.
3. **There was no way to remove the install.** The tree outlives every rebuild
   and the row describing it could only be corrected by hand-written SQL against
   the SQLCipher DB — a live-DB write from outside the app.

Each pin below is count-agnostic (it walks EVERY site via the shared harness,
never ``len(X)==N``) and carries a teeth arm that plants the bad shape and
asserts it is flagged, plus a good variant asserted NOT flagged where an
exemption exists (R38).

SCOPE CAVEAT — what a green run here does NOT prove:
  * Nothing about behaviour. The behavioural halves (a stale marker leaves
    sys.path untouched; the admin render touches nothing; the route's auth tier
    and closed key set) live in
    ``tests/test_web/test_n527_runtime_deps_route_pin.py`` and
    ``tests/test_embedding_bits/test_runtime_ready_check.py``.
  * The deletion pin follows a prefix value only through assignments and
    parameters WITHIN one function. A prefix smuggled through a dict, an
    instance attribute, or a cross-module call is not followed.
  * Nothing about the CONTAINER. Whether the real pip skips the three
    image-provided names, and whether a real install produces exactly one
    dist-info per name, can only be measured on a running container.
  * The ``sys.path`` arm matches ``sys.path.insert`` (and that literal inside a
    string). It does NOT match ``sys.path[:0] = [...]``, ``sys.path = [p] +
    sys.path``, or a site-dir injected by some other mechanism. The real
    function's POSITION is asserted behaviourally by
    ``tests/test_embedding_bits/test_runtime_ready_check.py::
    test_add_runtime_to_sys_path_appends_never_shadows_the_image``; this arm is
    the drift net for NEW sites, not a proof about the existing one.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    PHI_KEY_NEEDLES,
    assert_pin_has_teeth,
    enclosing_fn,
    iter_src_files,
    iter_string_literals,
    parse_module,
    parse_source,
    phi_shaped_keys,
    relpath,
    returned_dict_keys,
)

# ---------------------------------------------------------------------------
# Pin 1 — no `sys.path.insert` anywhere in the package (N-525)
#
# Keyed on the SHAPE of the mutation, not on the one function that did it: the
# harm is "volume code positioned ahead of the image", and any future site that
# inserts rather than appends re-creates it. The exemption list is EMPTY and
# repo-relative (R38) — there is currently no legitimate insert in src/.
# ---------------------------------------------------------------------------


def _is_sys_path_insert(node: ast.AST) -> bool:
    """``sys.path.insert(...)`` — the front-of-path mutation."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "insert"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "path"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "sys"
    )


def _sys_path_insert_sites(tree: ast.AST) -> list[tuple[str, int]]:
    return [
        (enclosing_fn(node), getattr(node, "lineno", 0))
        for node in ast.walk(tree)
        if _is_sys_path_insert(node)
    ]


def _sys_path_insert_in_strings(tree: ast.AST) -> list[str]:
    """The same shape hiding inside a STRING literal.

    Not paranoia: ``embedding_bits.runtime_imports_cleanly`` builds a probe
    script as a string and runs it with ``python -c``, and that string carried
    ``sys.path.insert(0, sp)``. An AST walk cannot see it, so a pin that only
    walks calls reports green over a live front-of-path insert in a subprocess.

    ``iter_string_literals`` yields reconstructed STRING VALUES (it stitches
    f-strings and ``+`` concatenations back together), not nodes — so there is
    no line number to report, and the needle is matched against the stitched
    value, which is what makes a split literal detectable.
    """
    return [
        text for text in iter_string_literals(tree)
        if "sys.path.insert" in text
    ]


def test_no_sys_path_insert_in_src():
    violations: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for fn, lineno in _sys_path_insert_sites(tree):
            violations.append(f"{rel}:{lineno} in {fn}() — sys.path.insert")
        for text in _sys_path_insert_in_strings(tree):
            violations.append(
                f"{rel} — 'sys.path.insert' inside a string literal (an "
                f"embedded script the AST cannot see): {text[:120]!r}"
            )
    assert not violations, (
        "sys.path must be APPENDED, never inserted at the front (N-525). An "
        "insert puts the runtime-deps volume ahead of the image and the stdlib, "
        "so any name the volume also carries is served from the volume — and "
        "nothing ever removes the entry. Sites:\n  "
        + "\n  ".join(violations)
    )


def test_no_sys_path_insert_pin_has_teeth():
    assert_pin_has_teeth(
        lambda tree: _sys_path_insert_sites(tree),
        bad_source=(
            "import sys\n"
            "def add_runtime_to_sys_path():\n"
            "    for p in runtime_python_path():\n"
            "        sys.path.insert(0, p)\n"
        ),
        good_source=(
            "import sys\n"
            "def add_runtime_to_sys_path():\n"
            "    for p in runtime_python_path():\n"
            "        sys.path.append(p)\n"
        ),
    )


def test_string_literal_arm_has_teeth():
    """The string arm needs its OWN teeth — it is a separate detector, and the
    call-shape teeth above say nothing about it."""
    bad = parse_source("probe = \"if sp:\\n    sys.path.insert(0, sp)\\n\"\n")
    good = parse_source("probe = \"if sp:\\n    sys.path.append(sp)\\n\"\n")
    assert _sys_path_insert_in_strings(bad), "string arm missed a planted insert"
    assert not _sys_path_insert_in_strings(good), "string arm flagged an append"


# ---------------------------------------------------------------------------
# Pin 2 — every deletion of the runtime prefix goes through the removal funnel
#         (N-526 / punch 541)
#
# TWO classes, deliberately distinguished, because collapsing them would make
# the pin either vacuous or wrong:
#   * a ROOT deletion (``rmtree(target_dir)``) is the removal operation, and it
#     must pair with the install-state reset — so it belongs ONLY to
#     ``remove_install``, which does both in one step.
#   * a CHILD deletion (``rmtree(target_dir / "lib")``) is the refresh
#     pre-step, and it must NOT reset the row. One named home for that too.
# A staged-FILE unlink (``dest.unlink()``) is neither and is out of scope: it
# deletes one downloaded wheel, not a tree.
# ---------------------------------------------------------------------------

_TREE_DELETERS = frozenset({"rmtree", "removedirs", "rmdir"})
_PREFIX_PARAM_NAMES = frozenset({"target_dir", "runtime_deps_path", "prefix"})
_PREFIX_ORIGIN_CALLS = frozenset({"get_runtime_deps_path"})

#: enclosing-function names permitted to delete, per class. Keyed on the
#: FUNCTION (line-stable, R38), never on a line number.
_ROOT_DELETE_FUNNEL = frozenset({"remove_install"})
_CHILD_DELETE_FUNNEL = frozenset({"remove_install", "_prepare_prefix_for_install"})


def _callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
    return ""


def _leftmost_name(node: ast.AST) -> str:
    """The base Name of a path expression: ``a / "b" / "c"`` → ``a``."""
    cur = node
    for _ in range(12):  # bounded walk; path expressions are shallow
        if isinstance(cur, ast.Name):
            return cur.id
        if isinstance(cur, ast.BinOp):
            cur = cur.left
        elif isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        else:
            return ""
    return ""


def _prefix_bound_names(fn: ast.AST) -> tuple[set[str], set[str]]:
    """``(root_names, child_names)`` — names inside ``fn`` holding the prefix
    itself, and names holding a path DERIVED from it.

    Seeded from parameter names and from assignments whose value is a prefix
    origin call, then closed to a fixpoint so
    ``base = target_dir if target_dir is not None else get_runtime_deps_path()``
    propagates. This is the interprocedural-within-a-function half (PD-2): a pin
    keyed on the literal ``get_runtime_deps_path()`` expression would be blind
    to every site that went through a local first — which is all of them.

    The root/child SPLIT is load-bearing and was added after this pin flagged
    the real refresh pruner as a root deletion: ``tree = target_dir / name`` then
    ``rmtree(tree)`` deletes a CHILD, and a classifier that looked only at the
    deletion's own argument shape (``ast.Name`` ⇒ root) called it a root. Reading
    the shape at the deletion site is reading the wrong thing; the class is a
    property of the VALUE, so it has to be carried with the binding.
    """
    root: set[str] = set()
    child: set[str] = set()
    args = getattr(fn, "args", None)
    if args is not None:
        for arg in (
            list(getattr(args, "posonlyargs", []))
            + list(args.args)
            + list(args.kwonlyargs)
        ):
            if arg.arg in _PREFIX_PARAM_NAMES:
                root.add(arg.arg)
    for _ in range(4):  # fixpoint; assignment chains here are 1-2 deep
        grew = False
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            candidates: list[ast.AST] = (
                [value.body, value.orelse]
                if isinstance(value, ast.IfExp)
                else [value]
            )
            kind = ""
            for c in candidates:
                base = _leftmost_name(c)
                is_prefix_expr = (
                    _callee_name(c) in _PREFIX_ORIGIN_CALLS
                    or base in root
                    or base in child
                )
                if not is_prefix_expr:
                    continue
                # A bare Name / a bare origin CALL re-binds the prefix itself;
                # anything built on top of one (``p / "lib"``, ``p.parent``) is a
                # child. Strongest classification wins across an IfExp's arms:
                # a value that is the prefix on either arm is treated as root.
                if (
                    isinstance(c, ast.Name)
                    or _callee_name(c) in _PREFIX_ORIGIN_CALLS
                ):
                    if base in child and not isinstance(c, ast.Name):
                        kind = kind or "child"
                    else:
                        kind = "root"
                else:
                    kind = kind or "child"
            if not kind:
                continue
            targets = (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                bucket = root if kind == "root" else child
                if target.id not in bucket:
                    bucket.add(target.id)
                    grew = True
        if not grew:
            break
    return root, child


def _prefix_delete_sites(tree: ast.AST) -> list[tuple[str, str, int]]:
    """``(kind, enclosing_fn, lineno)`` for every prefix tree-deletion.

    ``kind`` is ``"root"`` (the prefix itself) or ``"child"`` (a subtree of it).
    """
    out: list[tuple[str, str, int]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        root, child = _prefix_bound_names(fn)
        if not root and not child:
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if _callee_name(node) not in _TREE_DELETERS:
                continue
            target: ast.AST | None = None
            if node.args:
                target = node.args[0]
            elif isinstance(node.func, ast.Attribute):
                # ``some_path.rmdir()`` — the receiver IS the target.
                target = node.func.value
            if target is None:
                continue
            base = _leftmost_name(target)
            if base not in root and base not in child:
                continue
            is_root = isinstance(target, ast.Name) and base in root
            out.append(
                ("root" if is_root else "child", fn.name, getattr(node, "lineno", 0))
            )
    return out


def test_every_runtime_prefix_deletion_goes_through_the_funnel():
    violations: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for kind, fn, lineno in _prefix_delete_sites(tree):
            allowed = (
                _ROOT_DELETE_FUNNEL if kind == "root" else _CHILD_DELETE_FUNNEL
            )
            if fn not in allowed:
                violations.append(
                    f"{rel}:{lineno} in {fn}() deletes the runtime prefix "
                    f"({kind}); allowed only in {sorted(allowed)}"
                )
    assert not violations, (
        "Deleting the runtime-deps prefix must go through the ONE removal "
        "funnel, embedding_bits.remove_install, which also resets the "
        "install-state row (N-526). A tree deleted without the reset leaves a "
        "row claiming 'installed' over nothing — and a row reset without the "
        "deletion leaves the stale packages exactly where they were, which is "
        "the drift this release closes. Sites:\n  " + "\n  ".join(violations)
    )


def test_prefix_deletion_pin_has_teeth():
    """Teeth on BOTH classes, and on the exemption.

    A single-armed version of this pin would be the trap: if it flagged any
    rmtree of a prefix-derived path, the refresh pre-step would be a permanent
    violation and someone would allow-list the funnel itself, leaving the pin
    green over anything.
    """
    def _detect(tree):
        return [
            (kind, fn, lineno)
            for kind, fn, lineno in _prefix_delete_sites(tree)
            if fn not in (
                _ROOT_DELETE_FUNNEL if kind == "root" else _CHILD_DELETE_FUNNEL
            )
        ]

    # ROOT deletion outside the funnel — the defect.
    assert_pin_has_teeth(
        _detect,
        bad_source=(
            "import shutil\n"
            "def cleanup(target_dir):\n"
            "    shutil.rmtree(target_dir)\n"
        ),
        good_source=(
            "import shutil\n"
            "def remove_install(conn, target_dir=None):\n"
            "    base = target_dir if target_dir else get_runtime_deps_path()\n"
            "    shutil.rmtree(base)\n"
        ),
    )
    # CHILD deletion outside BOTH funnels — also a defect.
    assert_pin_has_teeth(
        _detect,
        bad_source=(
            "import shutil\n"
            "def refresh(target_dir):\n"
            "    shutil.rmtree(target_dir / 'lib')\n"
        ),
        good_source=(
            "import shutil\n"
            "def _prepare_prefix_for_install(target_dir, manifest):\n"
            "    shutil.rmtree(target_dir / 'lib')\n"
        ),
    )
    # A staged-FILE unlink is out of scope and must NOT be flagged — otherwise
    # the installer's ordinary re-stage path becomes a false positive that
    # pressures someone into widening the allow-list.
    file_unlink = parse_source(
        "def _stage_one(target_dir, name):\n"
        "    dest = target_dir / 'wheels' / name\n"
        "    dest.unlink(missing_ok=True)\n"
    )
    assert not _detect(file_unlink), (
        "the pin must not flag a single-file unlink; only tree deletions"
    )


# ---------------------------------------------------------------------------
# Pin 3 — /health/runtime-deps declares a CLOSED key set, and is not the
#         detail body wearing a new name (N-527 / punch 542)
# ---------------------------------------------------------------------------

#: The route's contract, as promised to cve-arc in HANDOVER.md
#: (RESPONSE 2026-09-29 16:05). Restated here so the pin fails if the module's
#: own constant is widened — a pin that merely re-read the constant would agree
#: with any drift.
_PROMISED_KEYS = frozenset({
    "build_sha",
    "python",
    "runtime_deps_present",
    "distributions",
    "image_manifest_sha256",
    "installed_manifest_sha256",
    "runtime_on_sys_path",
    # Punch 552 / N-555, argued for: the drift gate's own bool from the SAME
    # record as the keys above, so it adds no host fact. A monitor reads it
    # instead of re-deriving "verified" from the two shas. The reason text stays
    # out: ``set_mismatch`` detail names packages and versions.
    "runtime_verified",
    # Punch 734, argued for: shape agreed with cve-arc 2026-10-15 11:46
    # (design_2026-10-15_os_packages_on_health_runtime_deps_for_cve_arc). The
    # image's Debian packages, source-keyed: OpenSSL is Debian's libcrypto and
    # appears in no lock file, so without these keys its CVEs page nobody. It is
    # the same kind of fact as ``distributions`` (installed name + version), under
    # the same gate; an unreadable status file is ``os_packages_error``.
    "os_release",
    "os_packages",
    "os_packages_unstateable",
    "os_packages_error",
    # Punch 647, argued for: libraries copied INSIDE installed packages
    # (pip/_vendor, the stdlib's ensurepip wheel) have no dist-info, so no other
    # key can show them. Rows name a carrier relative to a root label, never a path.
    "vendored",
    "vendored_error",
    # Punch 848, argued for: shape agreed with cve-arc 2026-11-04
    # (design_2026-11-04_bundled_runtime_deps_key_for_cve_arc). What a wheel
    # bundles beyond Python (cryptography's static OpenSSL), from its PEP 770
    # SBOMs and auditwheel .libs; no other key can show it, and ``vendored`` is
    # read as PyPI. Carriers are distribution names, never paths.
    "bundled",
    "bundled_error",
})


def test_route_key_set_constant_matches_the_promise():
    from email_triage.web.routers.health import _RUNTIME_DEPS_KEYS

    assert set(_RUNTIME_DEPS_KEYS) == set(_PROMISED_KEYS), (
        "the key set of GET /health/runtime-deps is a CLOSED contract published "
        "to cve-arc. A version list is a targeting map, so the payload is safe "
        "because the set is enumerated — any new key must be argued for here, "
        "not arrive by drift.\n"
        f"  added:   {sorted(set(_RUNTIME_DEPS_KEYS) - set(_PROMISED_KEYS))}\n"
        f"  missing: {sorted(set(_PROMISED_KEYS) - set(_RUNTIME_DEPS_KEYS))}"
    )


def _route_fn(name: str) -> ast.AST:
    path = None
    for candidate in iter_src_files("web/routers"):
        if candidate.name == "health.py":
            path = candidate
            break
    assert path is not None, "web/routers/health.py not found"
    tree = parse_module(path)
    assert tree is not None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    raise AssertionError(f"{name} not found in web/routers/health.py")


def _referenced_names(fn: ast.AST) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.add(node.attr)
    return out


def test_route_is_not_the_detail_body_and_gates_on_admin():
    """Structural, because these three facts ARE the safety argument.

    A 2026-06-13 review rejected "a token alone on the published port" unlocking
    /health/detail. This route stays clear of that artifact by never computing
    the detail body, never honouring the loopback ops token, and requiring the
    admin role. Intent is not enough — assert it.
    """
    fn = _route_fn("health_runtime_deps")
    names = _referenced_names(fn)
    assert "_compute_health_detail" not in names, (
        "/health/runtime-deps must never compute the detail body — that body is "
        "the object the 2026-06-13 review protected (its `status` alone is a "
        "one-bit oracle over sixteen OR-terms)."
    )
    assert "_ops_token_authorized" not in names, (
        "the loopback ops-token bypass must NOT reach this route: it is the "
        "container-CLI path and has no business widening a route built for "
        "remote callers."
    )
    assert "is_admin" in names, (
        "a package-version inventory is a targeting map; the lowest role that "
        "answers the question is admin."
    )


def test_detail_body_absence_arm_has_teeth():
    """Prove the detector can FAIL — a name-set check that always passes is the
    classic vacuous pin."""
    bad = parse_source(
        "async def health_runtime_deps(request):\n"
        "    body, degraded = await _compute_health_detail(request)\n"
        "    return body\n"
    )
    for node in ast.walk(bad):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert "_compute_health_detail" in _referenced_names(node)
            assert "is_admin" not in _referenced_names(node)
            break
    else:  # pragma: no cover
        raise AssertionError("planted function not parsed")


# ---------------------------------------------------------------------------
# Pin 4 — the record payload is PHI-FREE, structurally (container health-endpoint
#         standard, "Compliance obligations")
#
# The standard's rule: "a machine-checked test asserting the detail/deps payloads
# contain no owner-name / email / subject / message-content key — so a non-session
# reader can never SILENTLY become a PHI surface as fields are added later." The
# word doing the work is *silently*: the risk is not that someone adds PHI on
# purpose, it is that a field added for a good reason turns an inventory route
# into a PHI surface and nothing says so.
#
# WHY THE NEEDLE CHECK APPLIES TO THE CONTRACT KEYS AND **NOT** TO THE PACKAGE
# NAMES. Two different kinds live in this payload (PD-5's precondition: name the
# KIND a predicate is canonical for):
#   * the top-level keys are the API contract — authored here, so a
#     PHI-shaped name among them is a real defect;
#   * the keys INSIDE ``distributions`` are PEP-503 package names read off disk,
#     and real PyPI packages are called ``email-validator``, ``user-agents``,
#     ``names``. A needle search over those would flag a legitimate dependency,
#     somebody would allow-list it, and the pin would end up weaker than if it
#     had never been written.
# So the nested map is asserted by SHAPE (canonical name -> list of version
# strings) instead, which is the property that actually forecloses a PHI field
# there: a PHI value cannot arrive as a version string in a package-name map.
# ---------------------------------------------------------------------------

def test_the_record_payload_is_structurally_phi_free():
    fn = _route_fn("health_runtime_deps")
    emitted = returned_dict_keys(fn)
    assert emitted, (
        "the route must return a dict LITERAL so its key set is readable at the "
        "source; a dict built by mutation cannot be pinned structurally"
    )
    assert set(emitted) == set(_PROMISED_KEYS), (
        f"the route emits {sorted(set(emitted))}, the closed contract is "
        f"{sorted(_PROMISED_KEYS)}"
    )
    offenders = phi_shaped_keys(emitted)
    assert not offenders, (
        "a PHI / user-identity-shaped key reached the runtime-deps payload: "
        + ", ".join(offenders)
        + ". This route is read by an external scanner over an api-key; it is "
        "an inventory surface and must never become a PHI surface as fields "
        "are added."
    )


def test_phi_free_pin_has_teeth():
    """Plant the failure the standard is about: a field added for a plausible
    reason that happens to name a person."""
    bad = parse_source(
        "async def health_runtime_deps(request):\n"
        "    return {\n"
        "        'build_sha': sha,\n"
        "        'distributions': dists,\n"
        "        'requested_by_email': user['email'],\n"
        "    }\n"
    )
    for node in ast.walk(bad):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            planted = returned_dict_keys(node)
            assert "requested_by_email" in planted
            assert phi_shaped_keys(planted), "the needle set missed a PHI key"
            break
    else:  # pragma: no cover
        raise AssertionError("planted function not parsed")

    # ...and the GOOD shape is not flagged, including a package-name map whose
    # entries legitimately contain a needle substring.
    good = parse_source(
        "async def health_runtime_deps(request):\n"
        "    return {\n"
        "        'build_sha': sha,\n"
        "        'distributions': {'email-validator': ['2.2.0']},\n"
        "    }\n"
    )
    for node in ast.walk(good):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert not phi_shaped_keys(returned_dict_keys(node)), (
                "a real PyPI package name containing 'email' must NOT be "
                "flagged — that false positive is how this pin would get "
                "allow-listed into uselessness"
            )
            break
    else:  # pragma: no cover
        raise AssertionError("planted function not parsed")


# ---------------------------------------------------------------------------
# Pin 5 — versions come from importlib.metadata / dist-info, never `pip freeze`
#         (container health-endpoint standard, "GET /health/deps")
#
# The standard's reason is a comparator argument, not style: `pip freeze` emits
# ``-e`` / ``@ file://`` / bare-path forms that no consumer can parse reliably,
# so a record built from it is unusable to the scanner it exists for. Keeping the
# rule mechanical means the next person to reach for a subprocess here trips it.
# ---------------------------------------------------------------------------

def _record_reader_fns(tree: ast.AST) -> list[ast.AST]:
    wanted = {"scan_installed_distributions", "environment_provided_versions"}
    return [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in wanted
    ]


def test_the_installed_set_is_read_from_metadata_not_pip():
    path = None
    for candidate in iter_src_files("embedding_bits"):
        if candidate.name == "__init__.py":
            path = candidate
            break
    assert path is not None, "embedding_bits/__init__.py not found"
    tree = parse_module(path)
    assert tree is not None
    readers = _record_reader_fns(tree)
    assert len(readers) == 2, (
        "expected both record readers; found "
        f"{[getattr(r, 'name', '?') for r in readers]}"
    )
    for fn in readers:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee = _callee_name(node)
                assert callee not in ("run", "check_output", "Popen", "getoutput"), (
                    f"{fn.name} shells out ({callee}); the installed set must "
                    f"come from importlib.metadata / dist-info on disk. "
                    f"`pip freeze` emits -e / @ file:// / path forms no "
                    f"comparator can parse, which defeats the whole point of "
                    f"the record."
                )
        for text in iter_string_literals(fn):
            assert "freeze" not in text, (
                f"{fn.name} mentions 'freeze'; read metadata, not pip output"
            )


def test_names_are_pep503_canonicalized_at_the_source():
    """Consumers must never re-derive the canonical form (the standard's rule).

    Asserted on the real helper rather than on a regex in a docstring: the
    property is that the ONE function every key passes through collapses
    ``[-_.]+`` to ``-`` and lowercases.
    """
    from email_triage.embedding_bits import canonical_dist_name

    for raw, want in (
        ("scikit_learn", "scikit-learn"),
        ("SciKit.Learn", "scikit-learn"),
        ("scikit-learn", "scikit-learn"),
        ("huggingface_hub", "huggingface-hub"),
        ("torch", "torch"),
        ("  Pillow  ", "pillow"),
        ("a__b..c--d", "a-b-c-d"),
    ):
        assert canonical_dist_name(raw) == want, raw


# ---------------------------------------------------------------------------
# Pin 7 - the manifest env override is gone from src, as a STRING
# (punch 539 fold-check: hipaa H539FC-8 / R7, db DB-539FC-7, da DA-FC539-1/2)
# ---------------------------------------------------------------------------

#: The variable used to WIN over the image manifest in two copies of the resolver
#: (the domain module and the CLI), and that resolver is the default reference
#: for the N-524 drift gate and the scanner-facing ``image_manifest_sha256``.
#: Assembled here so this file does not itself carry the literal it forbids.
_GUTTED_MANIFEST_VAR = "EMBEDDING_BITS_" + "MANIFEST"

#: The env registry (punch 547), whose ``RETIRED`` map must NAME the variable to
#: refuse a process that still carries it (PD-8: a leftover drop-in fails closed
#: instead of being silently ignored).
ENV_REGISTRY_MODULE = "_env_registry.py"


def _retired_key_line(text: str) -> int | None:
    """Line of the variable as a key of the ``RETIRED`` dict literal, or None."""
    for node in ast.walk(parse_source(text)):
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        else:
            continue
        if not (any(isinstance(t, ast.Name) and t.id == "RETIRED" for t in targets)
                and isinstance(node.value, ast.Dict)):
            continue
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and key.value == _GUTTED_MANIFEST_VAR:
                return key.lineno
    return None


def gutted_manifest_var_lines(text: str, *, registry: bool = False) -> list[int]:
    """Line of every occurrence of the gutted variable name in ``text`` — code,
    docstring or comment alike: the name must appear nowhere under src/.

    One exception, in the env registry only (``registry=True``): the
    variable as a key of the ``RETIRED`` dict literal, alone on its line. Any
    other occurrence there still counts: its value string, a comment on the
    key's line, another dict, a docstring."""
    admitted = _retired_key_line(text) if registry else None
    return [
        i for i, line in enumerate(text.splitlines(), 1)
        if _GUTTED_MANIFEST_VAR in line
        and not (i == admitted and line.count(_GUTTED_MANIFEST_VAR) == 1)
    ]


def test_the_manifest_env_var_appears_nowhere_under_src():
    """Count-agnostic over every src module (PD-1). Not a code-string scan: a
    docstring naming the variable is how the next reader re-learns it exists.
    The one admitted site is the refusal key in the env registry (see
    :func:`gutted_manifest_var_lines`)."""
    found = {}
    for path in iter_src_files():
        hits = gutted_manifest_var_lines(
            path.read_text(encoding="utf-8"),
            registry=relpath(path) == ENV_REGISTRY_MODULE,
        )
        if hits:
            found[relpath(path)] = hits
    assert not found, (
        f"{found}: the manifest env override is named in src. The manifest is "
        f"the baked image fact DEFAULT_MANIFEST_PATH, resolved only by "
        f"embedding_bits.resolve_manifest_path(); a caller with another manifest "
        f"passes manifest_path= (the CLI's typed --manifest)."
    )


def test_the_manifest_env_var_detector_has_teeth():
    var = _GUTTED_MANIFEST_VAR
    for bad in (
        f'import os\nX = os.environ.get("{var}", "")\n',
        f'def f():\n    """{var} used to win here."""\n',
        f'# reads {var}\n',
    ):
        assert gutted_manifest_var_lines(bad), bad
    assert not gutted_manifest_var_lines(
        'import os\nX = os.environ.get("EMBEDDING_BITS_RUNTIME_DEPS", "")\n'
    ), "the runtime-deps variable is punch 547's, not this pin's"
    # The registry exception admits the RETIRED key and nothing beside it.
    key_only = f'RETIRED: dict[str, str] = {{\n    "{var}":\n        "nothing",\n}}\n'
    assert not gutted_manifest_var_lines(key_only, registry=True)
    assert gutted_manifest_var_lines(key_only), "the exception is registry-only"
    for bad in (
        f'RETIRED: dict[str, str] = {{\n    "{var}":  # {var} won here\n        "x",\n}}\n',
        f'RETIRED = {{\n    "{var}":\n        "{var} used to win",\n}}\n',
        f'OTHER: dict[str, str] = {{\n    "{var}":\n        "x",\n}}\n',
        f'"""{var} used to win."""\nRETIRED = {{\n    "{var}":\n        "x",\n}}\n',
    ):
        assert gutted_manifest_var_lines(bad, registry=True), bad


def test_the_manifest_env_var_is_refused_at_start():
    """The other half of the registry exception: the name it admits must be
    a refusal key, so a process that still sets it exits instead of running."""
    from email_triage._env_registry import RETIRED

    assert _GUTTED_MANIFEST_VAR in RETIRED


# ---------------------------------------------------------------------------
# Pin 8 - the removal guard's layout set cannot drift from the installer's writes
# (N-549, punch 539 fold-check round 3, hipaa 539 fold-2 re-check F1)
# ---------------------------------------------------------------------------

EMBEDDING_BITS_MODULE = "embedding_bits/__init__.py"


def prefix_literal_joins(tree: ast.AST) -> list[tuple[int, str]]:
    """``<name> / "<literal>"`` joins: the shape of an installer write of a new
    top-level entry into a prefix. ``(line, literal)`` for each."""
    return [
        (node.lineno, node.right.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
        and isinstance(node.left, ast.Name)
        and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
    ]


def test_every_prefix_join_in_the_installer_is_in_the_removal_layout():
    """The guard refuses a marked target holding anything outside
    ``runtime_prefix_layout()``. If the installer starts writing a new top-level
    entry, the guard would refuse every non-default prefix it produced, or worse,
    the layout set would be widened by hand. This pin makes the installer's
    literal joins a subset of the derived set, so a new entry must go through a
    constant the set is built from."""
    from email_triage.embedding_bits import runtime_prefix_layout

    tree = parse_module(SRC_ROOT / EMBEDDING_BITS_MODULE)
    assert tree is not None
    joins = prefix_literal_joins(tree)
    assert joins, "no literal prefix joins found; the detector or the module moved"
    layout = runtime_prefix_layout()
    stray = [(ln, lit) for ln, lit in joins if lit not in layout]
    assert not stray, (
        f"{EMBEDDING_BITS_MODULE}: prefix joins outside the removal layout: {stray}. "
        f"Name the entry with a module constant and add it to runtime_prefix_layout()."
    )


def test_the_prefix_join_detector_has_teeth():
    from email_triage.embedding_bits import runtime_prefix_layout

    layout = runtime_prefix_layout()

    def stray(src: str):
        return [lit for _ln, lit in prefix_literal_joins(parse_source(src)) if lit not in layout]

    assert stray('p = target_dir / "backups"\n') == ["backups"]
    assert stray('p = target_dir / WHEELS_DIRNAME\nq = base / "lib"\n') == []
