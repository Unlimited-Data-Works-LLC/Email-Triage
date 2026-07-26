"""run17  — reverse SSOT-registry bijection.

The §3 SSOT registry in ``internal documentation`` records, per
harmonized class, the SSOT + the test that enforces it (``✅ pinned``). That
registry can DRIFT from the tests: a test renamed or deleted while its §3 row
keeps claiming ``✅ pinned`` is a silent coverage LIE — the row asserts an
enforcement that no longer exists. This pin closes the reverse direction:

  every enforcement test NAMED in the playbook §3 registry MUST EXIST.

A registry row names its enforcing test two ways, and we check BOTH:

  * **path reference** — ``tests/test_foo_pin.py`` (or ``tests/sub/test_x.py``,
    optionally ``…py::test_method``). This is the PRIMARY, unambiguous anchor:
    every such path must resolve to a real file.
  * **bare identifier** — an inline-code ``test_*pin*`` token (e.g.
    ``test_envbool_ssot_pin_a9``) with no path. A file with that stem must exist.

The path-reference arm is the one that matters: the enforcement column writes
its security-control pins as PATHS (``tests/test_no_unguarded_secret_write.py``,
``tests/test_privacy_invariants_log_scrub.py``, ``tests/test_audit_safe_write.py``,
…) — many of which do NOT contain the substring ``pin``. The original version of
this pin keyed ONLY on ``"pin"``-substring identifiers and so silently EXCLUDED
those path-named secret-write / PHI-scrub / audit-chain rows from the bijection
(devil's-advocate catch, run17 ) — proving "no drift" over only the ``*pin*``
subset, the exact coverage-lie this pin claims to close. Anchoring on the
path references closes that hole.

The FORWARD direction (every test file is registered in §3) is intentionally NOT
checked — many structural pins (teeth helpers, behavioural guards, the meta-pins
themselves) are legitimately not §3-registry SSOTs, so a forward bijection would
false-flag. The census  ask is the reverse: a registry row can't name a
vanished test. Layered-defense (the "census the censusers" reverse arm
companion to the pin-harness adoption meta-pin).
"""

from __future__ import annotations

import re

from _pin_harness import REPO_ROOT, iter_files, relpath

_PLAYBOOK = REPO_ROOT / "docs" / "ssot-and-divergence-playbook.md"
_TESTS = REPO_ROOT / "tests"

# Path references named in the registry that legitimately have no file (e.g. a
# planned-but-deferred pin), each with a reason. Empty today.
_PATH_ALLOW: frozenset[str] = frozenset()
# Bare ``test_*pin*`` identifiers named in the registry that legitimately have no
# ``test_*.py`` file (e.g. a pin folded into another module), each with a reason.
_NAME_ALLOW: frozenset[str] = frozenset()


def _registry_path_refs() -> set[str]:
    """Every ``tests/…\\.py`` path reference in the §3 registry (PRIMARY anchor).

    Strips an optional ``::test_method`` suffix — only the file must exist. This
    is the unambiguous arm: a path that names a missing file is real drift,
    independent of whether the filename happens to contain ``pin``."""
    text = _PLAYBOOK.read_text(encoding="utf-8")
    refs = re.findall(r"\btests/[A-Za-z0-9_/]+\.py(?:::[A-Za-z0-9_]+)?", text)
    return {r.split("::", 1)[0] for r in refs}


def _registry_named_pins() -> set[str]:
    """Every bare ``test_*pin*`` identifier named in the §3 registry (SECONDARY).

    Matches the FULL identifier (``\\b…\\b``) so a suffixed name
    (``test_envbool_ssot_pin_a9`` / ``test_secret_read_collapse_pin_a5``) is not
    truncated at the first ``_pin``. Keeps only tokens containing ``pin`` — bare
    non-``pin`` identifiers are too ambiguous (method names vs file stems) to
    check as file stems; those enforcement tests are caught instead via their
    PATH reference (the primary arm above)."""
    text = _PLAYBOOK.read_text(encoding="utf-8")
    return {t for t in re.findall(r"\btest_[a-z0-9_]+\b", text) if "pin" in t}


def _existing_test_stems() -> set[str]:
    # Route the tests-tree walk through the shared harness walker (R5b) instead
    # of a raw ``_TESTS.rglob`` — ``iter_files`` is the generic walker for a
    # non-src tree (skips ``__pycache__``, sorted). The substring→AST adoption
    # meta-pin (run18) flags a raw rglob here even though this file imports the
    # harness for ``REPO_ROOT``, so the walk itself must route through it.
    return {p.stem for p in iter_files(_TESTS, "test_*.py")}


def _existing_rel_paths() -> set[str]:
    # ALL tests/*.py — a registry path ref may legitimately name a NON-``test_``
    # file (e.g. ``tests/_pin_harness.py``, the shared harness); the question is
    # only "does the referenced path exist", so walk every ``.py`` under tests/
    # via the harness ``iter_files`` (not a raw rglob — see _existing_test_stems).
    return {relpath(p, REPO_ROOT) for p in iter_files(_TESTS, "*.py")}


def test_every_registry_path_ref_exists():
    """PRIMARY: every ``tests/…\\.py`` named in the §3 registry resolves to a
    real file — including the path-named security-control rows (secret-write,
    PHI-scrub, audit-chain) the ``pin``-substring filter would miss."""
    refs = _registry_path_refs()
    missing = sorted(refs - _existing_rel_paths() - _PATH_ALLOW)
    assert not missing, (
        "The §3 SSOT registry names enforcement test PATH(s) with NO file (a "
        f"renamed/deleted/mis-typed pin left a stale ✅-pinned row — a coverage lie): {missing}. "
        "Fix/rename the registry path, restore the test, or add it to _PATH_ALLOW with a reason."
    )


def test_every_registry_named_pin_exists():
    """SECONDARY: every bare inline ``test_*pin*`` identifier has a file stem."""
    named = _registry_named_pins()
    missing = sorted(named - _existing_test_stems() - _NAME_ALLOW)
    assert not missing, (
        "The §3 SSOT registry names pin identifier(s) with NO test file "
        f"(a renamed/deleted pin left a stale ✅-pinned row): {missing}. "
        "Fix/rename the registry row, restore the pin, or add it to _NAME_ALLOW with a reason."
    )


def test_bijection_has_teeth():
    # non-vacuous: the parser actually finds path-refs AND named pins in the live
    # registry (a mis-wired regex that returned {} would pass both checks above).
    refs = _registry_path_refs()
    assert len(refs) >= 30, f"too few §3 path refs parsed ({len(refs)}) — parser mis-wired"
    named = _registry_named_pins()
    assert named, "no test_*_pin names parsed from the §3 registry — parser mis-wired"
    # and a planted absent path / name is reported missing by the same set logic.
    planted_path = {"tests/test_definitely_absent_pin.py"}
    assert sorted(planted_path - _existing_rel_paths() - _PATH_ALLOW) == [
        "tests/test_definitely_absent_pin.py"
    ]
    planted_name = {"test_definitely_absent_pin"}
    assert sorted(planted_name - _existing_test_stems() - _NAME_ALLOW) == [
        "test_definitely_absent_pin"
    ]


# ---------------------------------------------------------------------------
# ARM 3 (R20 #4 pinned-verify meta — N-180): every named STRUCTURAL enforcer in
# the §3 registry MUST import a `_pin_harness` walker, else be on an allow-list
# with a stated reason. Non-structural (behavioral / unit / integration) tests
# are legitimately allow-listed — they exercise runtime behavior, not code
# structure. Catches a "named pin" that self-declares behavioral yet is claimed
# as structural drift catch in §3, and a pin that hand-rolls an AST walker
# bypassing the harness (PD#6: pins obey the SSOT rule too).
# ---------------------------------------------------------------------------

# Registered structural pins that legitimately do NOT need `_pin_harness`
# (behavioral test rather than AST walk / model-level rather than seam-level /
# routes through a sibling harness). Each entry needs a stated reason.
_HARNESS_IMPORT_ALLOW: frozenset[str] = frozenset({
    # N-206 R22 (2026-07-02): rot-guard test_harness_import_allow_is_not_stale
    # removed 5 stale entries from this list:
    # - test_flash_error_surface_scaffold: GHOST (file no longer exists)
    # - test_error_html_escape_pin_a8: GHOST (file exists but no longer named in §3 registry)
    # - test_migrations_applied_body_immutable: GHOST (same — dropped from registry)
    # - test_redirect_qs_ssot_pin: MIGRATED (now imports _pin_harness)
    # - test_ssot_registry_coverage_pin: MIGRATED (now imports _pin_harness)
    "test_outer_key_bare_sender_pin",      # cache-key behavioral: exercises make_outer_cache_key runtime, not code shape
    # N-264 R27 (2026-07-03): the ARM 3 selector widened from `pin`-name-
    # substring to path-based resolution (`_named_pin_files`), so 7
    # legitimately non-structural files now surface. Add each with a
    # reason.
    "_pin_harness",  # THE harness itself — trivially cannot self-import.
    "test_access_audit",  # behavioral: exercises hipaa_access_events emission at runtime, not code shape.
    "test_n175_digest_preview_redact_pii_net",  # behavioral: render-view smoke, asserts scrubbed HTML output, not source AST.
    "test_log_chain",  # behavioral: verifies HMAC chain integrity by writing rows + reading them back.
    "test_digest_candidates_render_smoke",  # behavioral: renders digest candidates page, asserts non-PHI output.
    "test_audit_safe_write",  # behavioral: safe_audit_write runtime behavior on chain-write failures.
    "test_retry_drainer",  # behavioral: drains the retry queue, asserts outcome, not code shape.
    "test_discover_folder_phi_render",  # behavioral: folder-discover PHI-render check via HTTP response body.
})

_HARNESS_IMPORT_RE = re.compile(r"^\s*(?:from\s+(?:tests\.)?_pin_harness|import\s+_pin_harness)\b", re.M)


def _named_pin_files() -> dict[str, "REPO_ROOT / str"]:
    """Every registry-referenced test FILE (from the tests/ tree), for
    arm-3 harness-import inspection.

    N-264 R27 widening: the pre-widening version used
    ``_registry_named_pins()`` which filtered on ``"pin" in stem`` —
    it missed 8 registry-referenced HIPAA-load-bearing enforcers with
    non-``pin`` names (``test_no_unguarded_secret_write``,
    ``test_n175_digest_preview_redact_pii_net``,
    ``test_n73_recipient_digest_hipaa_audit``, ``test_n133_...``,
    ``test_credential_inputs_hardened``, ``test_audit_safe_write``,
    ``test_digest_candidates_render_smoke``,
    ``test_retry_drainer``). Census R27 flagged this as the ARM 3+4
    selector gap — the exact drift-prevention hole R23 was written
    to plug.

    Widened to use ``_registry_path_refs()`` (the PATH-based anchor)
    which catches PATHS the registry names regardless of whether the
    stem contains ``pin``. Also keeps the historical ``_registry_
    named_pins()`` union so registry-named-only-by-identifier stems
    stay covered."""
    result: dict = {}
    # Primary: registry PATH refs (catches non-`pin`-named files).
    for ref in _registry_path_refs():
        # ref is like `tests/test_no_unguarded_secret_write.py`.
        p = REPO_ROOT / ref
        if not p.exists():
            continue
        stem = p.stem
        result[stem] = p
    # Secondary: registry-named `pin`-stems (backwards-compat).
    for stem in _registry_named_pins():
        if stem in result:
            continue
        for p in iter_files(_TESTS, f"{stem}.py"):
            result[stem] = p
            break
    return result


def test_every_registry_named_pin_imports_harness_or_is_allowed():
    """ARM 3 (R20 #4 / N-180): every registry-named STRUCTURAL pin routes its
    AST walk / file iteration through the shared ``_pin_harness`` — else it
    forks the harness (PD#6, `pins-obey-the-SSOT-rule` from the style guide)
    or self-declares behavioral without saying so (§3 coverage lie).
    Allow-list carries a reason per row."""
    files = _named_pin_files()
    forkers: list[str] = []
    for stem, path in files.items():
        if stem in _HARNESS_IMPORT_ALLOW:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not _HARNESS_IMPORT_RE.search(text):
            forkers.append(f"{stem} ({relpath(path, REPO_ROOT)})")
    assert not forkers, (
        "The §3 SSOT registry names structural pin(s) that DON'T import "
        "`_pin_harness` — either they fork the harness (PD#6 violation) or "
        "self-declare behavioral without acknowledging it. Route the AST walk "
        "through `_pin_harness` (iter_files/parse_module/enclosing_fn), OR add "
        "the stem to `_HARNESS_IMPORT_ALLOW` with a stated reason. "
        f"Forking pins: {forkers}"
    )


def test_harness_import_allow_is_not_stale():
    """N-206 R22 (2026-07-02): PD#7 rot-guard for `_HARNESS_IMPORT_ALLOW`
    — sibling stale-guards (`test_covered_elsewhere_entries_exist` for
    `_COVERED_ELSEWHERE` in `test_db_write_coverage_pin.py`) exist but
    `_HARNESS_IMPORT_ALLOW` did NOT (census run22 R22_4).

    Two ways an entry goes stale:
    (a) The named pin no longer exists as a registered `test_*pin*`
        stem — the exemption points at a ghost.
    (b) The named pin file NOW imports `_pin_harness` (e.g., after a
        refactor migrated it to the shared harness) — the exemption is
        dead weight and lulls reviewers into thinking the harness
        adoption is incomplete.

    Both cases silently exempt a FUTURE pin from harness adoption if
    a new pin lands under the same stem or the stale entry's neighbours
    grow the same shape."""
    files = _named_pin_files()
    ghosts: list[str] = []
    already_migrated: list[str] = []
    for stem in _HARNESS_IMPORT_ALLOW:
        path = files.get(stem)
        if path is None:
            ghosts.append(stem)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if _HARNESS_IMPORT_RE.search(text):
            already_migrated.append(f"{stem} ({path.name})")
    problems = []
    if ghosts:
        problems.append(
            "Ghost entries (registry no longer names these pins — "
            "renamed/deleted?): " + ", ".join(sorted(ghosts))
        )
    if already_migrated:
        problems.append(
            "Migrated entries (these pins NOW import `_pin_harness` — "
            "remove from `_HARNESS_IMPORT_ALLOW`, the exemption is dead): "
            + ", ".join(sorted(already_migrated))
        )
    assert not problems, (
        "N-206 R22: `_HARNESS_IMPORT_ALLOW` has stale entries. Rot-guard "
        "keeps the allowlist honest (PD#7 — the pins themselves obey the "
        "SSOT rule; the exemption list is part of the pin's contract).\n\n"
        + "\n".join(problems)
    )


# ---------------------------------------------------------------------------
# ARM 4 (N-237 R23, 2026-07-02): pinned-verify teeth-adoption meta-arm.
# Census R23 flagged 6 of 63 registry-referenced pins as either
# "substring-proxy" (V2), "no-teeth" (V3, incl. HIPAA-load-bearing
# test_no_unguarded_secret_write / test_n175_digest_preview_redact_pii_net
# / test_n73_recipient_digest_hipaa_audit), "mislabeled behavioural" (V4),
# or "meta-existence-only" (V5). No meta-pin enforces that every named
# pin has TEETH.
#
# ARM 4 asserts: every registry-named pin has AT LEAST ONE non-trivial
# `assert` statement. "Non-trivial" = an assert against something other
# than a bare `True`, `1`, or a literal expression the parser can prove
# is always truthy. This is a floor, not a ceiling; pins can + should
# still call `_pin_harness.assert_pin_has_teeth` for the deeper teeth
# contract (that check lives per-pin, not here).
# ---------------------------------------------------------------------------

def _has_nontrivial_assert(source: str) -> bool:
    """True if `source` contains any `assert <non-trivially-True-expr>`."""
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Assert):
            continue
        test = node.test
        # Trivial always-true: `assert True` / `assert 1` / `assert "s"`
        if isinstance(test, _ast.Constant) and test.value:
            continue
        # Anything else counts as non-trivial (a comparison, a call, a
        # Name, a set membership, etc.).
        return True
    return False


def test_every_registry_named_pin_has_teeth():
    """ARM 4 (N-237 R23): every registry-referenced pin file must contain
    at least one non-trivial `assert`. A "meta-existence" pin (its whole
    body is a docstring + `assert True`) fires."""
    toothless: list[str] = []
    for stem, path in _named_pin_files().items():
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _has_nontrivial_assert(source):
            toothless.append(stem)
    assert not toothless, (
        "N-237 R23 ARM 4: registry-referenced pin(s) contain no non-trivial "
        "`assert` — they're `assert True` / body-less / docstring-only. Each "
        "pin must exercise a real property; a meta-existence pin gives "
        "false coverage. Suspect files:\n"
        + "\n".join(toothless)
    )


# ARM 4 upgrade (N-367 R31, 2026-07-05): teeth-probe upgrade per Census
# run22 §2 (pinned-verify row) + the backlog N-349b + TASK . The prior
# ARM 4 check (`_has_nontrivial_assert`) is a floor — it catches pins
# whose body is `assert True` but does NOT catch pins that lack any of
# the STANDARD teeth-signalling shapes. Census recommendation: for
# every registry-named pin, AST-locate at least one of:
#
#   1. A `def` named `_has_teeth`, `_pin_has_teeth`, or matching
#      `test_*teeth*`.
#   2. A call to `_pin_harness.assert_pin_has_teeth`.
#   3. An import of `_pin_harness` (a proxy for the "pin routes through
#      the shared harness" contract — most teeth utilities live there).
#
# This is a signal-check + still allows pins with genuinely inline
# teeth. Allow-list `_ARM4_TEETH_PROBE_ALLOW` keyed by pin stem carries
# an explicit exemption for pins whose teeth genuinely live outside
# these shapes (e.g. a pure structural-property check that has no
# discrete teeth function).


_TEETH_FN_NAME_PATTERNS = ("_has_teeth", "_pin_has_teeth", "teeth")


def _has_teeth_probe_signal(source: str) -> bool:
    """N-367: True if the pin source carries ONE of the teeth-signalling
    shapes: a teeth-named fn, an `assert_pin_has_teeth` call, or an
    import of `_pin_harness`."""
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            name = node.name.lower()
            if any(p in name for p in _TEETH_FN_NAME_PATTERNS):
                return True
        elif isinstance(node, _ast.Call):
            # `_pin_harness.assert_pin_has_teeth(...)` call.
            fn = node.func
            if isinstance(fn, _ast.Attribute) and fn.attr == "assert_pin_has_teeth":
                return True
            if isinstance(fn, _ast.Name) and fn.id == "assert_pin_has_teeth":
                return True
        elif isinstance(node, _ast.ImportFrom):
            if node.module == "_pin_harness":
                return True
        elif isinstance(node, _ast.Import):
            for alias in node.names:
                if alias.name == "_pin_harness":
                    return True
    return False


# N-367 R31 baseline: pin stems exempted from the teeth-probe signal
# check. Each entry is a pin whose teeth genuinely live outside the
# standard shapes (e.g. structural property check purely via ast +
# assertions, no discrete teeth fn). Migration IOU: shrink monotonically
# as pins adopt the standard teeth shapes.
_ARM4_TEETH_PROBE_ALLOW: frozenset[str] = frozenset({
    # Baseline at N-367 landing (2026-07-05). Each pin below has
    # genuinely-inline teeth (assertion + property check) but does NOT
    # use the standard `_pin_harness` routing / teeth-fn / assert_pin_
    # has_teeth call. Migration IOU: shrink monotonically as pins adopt
    # the standard teeth-signal shapes.
    "test_access_audit",
    "test_audit_safe_write",
    "test_digest_candidates_render_smoke",
    "test_discover_folder_phi_render",
    "test_log_chain",
    "test_n175_digest_preview_redact_pii_net",
    "test_outer_key_bare_sender_pin",
    "test_retry_drainer",
})


def test_every_registry_named_pin_has_teeth_probe_signal():
    """ARM 4 upgrade (N-367 R31 per Census run22 §2): every registry-
    named pin MUST carry at least one teeth-signalling shape (teeth-
    named fn, `_pin_harness.assert_pin_has_teeth` call, or `_pin_
    harness` import). Prevents drift back to `assert True` bodies + no
    _pin_harness routing. Pins with genuinely-inline teeth outside
    these shapes exempt via `_ARM4_TEETH_PROBE_ALLOW`."""
    no_probe: list[str] = []
    baseline_hits: set[str] = set()
    for stem, path in _named_pin_files().items():
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _has_teeth_probe_signal(source):
            continue
        if stem in _ARM4_TEETH_PROBE_ALLOW:
            baseline_hits.add(stem)
        else:
            no_probe.append(stem)
    if no_probe:
        preview = "\n  ".join(sorted(no_probe)[:10])
        raise AssertionError(
            "N-367 ARM 4 upgrade: registry-named pin(s) carry no teeth-"
            "signal shape (no `_has_teeth`/`_pin_has_teeth`/`test_*teeth*` "
            "fn, no `_pin_harness.assert_pin_has_teeth` call, no `_pin_"
            "harness` import). Either add a teeth-signalling shape OR add "
            "the stem to `_ARM4_TEETH_PROBE_ALLOW` with explanatory rationale."
            f"\n\nSuspect files (first 10):\n  {preview}"
        )
    stale = _ARM4_TEETH_PROBE_ALLOW - baseline_hits
    if stale:
        raise AssertionError(
            "N-367 ARM 4 ratchet-shrink: allow-list entries with teeth-probe "
            "signal NOW present — remove them from "
            f"`_ARM4_TEETH_PROBE_ALLOW`.\n\nStale entries:\n  "
            + "\n  ".join(sorted(stale))
        )
