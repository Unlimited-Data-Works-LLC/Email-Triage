"""Meta-pin: enumerate load-bearing structural pins that must not be silently deleted.

Complements :mod:`test_pin_harness_adoption` (which catches ADDITION-side drift
— a NEW count-agnostic pin must adopt the shared harness) with the missing
DELETION-side check: a critical pin whose disappearance would silently degrade
a defense-in-depth layer.

Origin: devils-advocate SB-2 fold from the N-432 SME panel (2026-07-19). The
pre-existing :mod:`feedback_meta_pins_gate_new_pin_pushes` policy guarded pin
ADDITION but not DELETION — a bare ``git rm tests/test_n432_*.py`` passes CI
today, dropping the walresetbug defense-in-depth silently. This registry is
the counterpart: an allow-list of pins whose deletion is a defect by itself.

Curation policy
===============

The ``_REQUIRED_PINS`` set below is CURATED, not exhaustive. Every entry is a
pin whose deletion would be an unrecoverable regression:

* The pin enforces a HIPAA-class invariant (audit-chain funnel, secret-write
  never-clobber, encryption-aware opener, walresetbug P0/P1/P1 defense).
* OR the pin is the sole enforcer of a Prime Directive from the project
  style guide (§3 SSOT registry).
* OR the pin is a meta-pin itself (harness adoption, or this registry).

Adding a new entry: verify the pin has no redundant coverage elsewhere, cite
the finding-ID / drawer, put it in the list.

Removing an entry: means the pin has been consolidated INTO another pin
(name the successor in a comment) — a pure ``git rm`` without a comment
naming the successor is an audit-trail regression by itself.
"""

from __future__ import annotations

import pathlib

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent

# Relative paths (POSIX-style) under tests/ — subdir entries carry their prefix
# so a pin under tests/test_web/ isn't collapsed into a same-basename ambiguity.
_REQUIRED_PINS: frozenset[str] = frozenset({
    # ─── N-432 SQLite walresetbug defense-in-depth (2026-07-19 SME panel) ───
    # P0 (PRAGMA wal_autocheckpoint=0 + serialized checkpoint funnel + @db_write).
    "test_n432_sqlite_walreset_p0_pin.py",
    # P1 (SQLite < 3.51.3 floor sensor with structured WARN payload).
    "test_n432_boot_assert_sqlite_floor_pin.py",
    # P1 (interprocedural raw-sqlite3.connect sweep; opener SSOT reach).
    "test_n432_raw_sqlite_connect_pin.py",
    # P0-companion (supervisor wire + runtime pragma-reaches-opener assertion).
    "test_n432_walreset_wiring_pin.py",
    # NTH-3 fold (runtime guard against migration primitives on running app).
    "test_n432_migration_live_app_guard_pin.py",
    # Punch 636: the shutdown checkpoint is the last DB op and every
    # connection singleton closes before it (no -wal left at a clean stop).
    "test_636_shutdown_last_close_pin.py",
    # Punch 636: every bounded shutdown wait, from its named constant, fits
    # inside the container StopTimeout with a margin.
    "test_636_shutdown_envelope_pin.py",

    # ─── audit-chain HMAC integrity (§164.312(b) / Prime Directive #3) ───
    # The audit-event emitter SSOT — never a raw INSERT (forks the HMAC chain).
    "test_audit_chain_insert_ssot_pin.py",

    # ─── encrypt-at-rest opener SSOT (Prime Directive ) ───
    # Every dedicated/backup/migration connection inherits the encryption key
    # via the encryption-aware opener; a raw sqlite3.connect() bypasses it.
    "test_encryption_aware_sqlite_open_ssot_pin.py",

    # ─── secret-write never-clobber (incident_2026-06-08_oauth_save_clobber,
    #     Prime Directive ) ───
    # A blank form field PRESERVES the stored secret — never infer write-intent
    # from field presence. Enforced via the `_secret_write` SSOT funnel.
    "test_no_unguarded_secret_write.py",

    # ─── async-DB safety funnel ───
    # A DB write from an async context MUST route through `db_call` (writer
    # thread); lifespan startup is the sole `async-db-ok` exemption.
    "test_web/test_async_db_safety.py",

    # ─── no silently-skipped control arm (CVE-2026-59951 mcp removal, 2026-10-16) ───
    # Every importorskip names a distribution the dev lock installs, so the arm
    # RUNS in CI; the sole enforcer (the N-433 jsonschema arm would have become a
    # quiet CI skip when jsonschema left the lock with mcp).
    "test_importorskip_names_a_dev_lock_distribution_pin.py",

    # ─── no orphan lock pin (installed-but-unused audit, 2026-10-17) ───
    # Every package a lock pins is reachable from a pyproject root along the lock's
    # `# via` edges; roots come from pyproject, never from the lock's own claim. The sole
    # enforcer: N-542 (pyproject -> lock) and N-545 (the lock's shape) both stayed green
    # while the old lock pinned alembic and mako that pyproject no longer asked for.
    "test_lock_pins_are_reachable_from_pyproject_pin.py",
    # Punch 639: every deploy container that mounts the PHI data or config dir runs at
    # the live container's pinned MCS level (fed by the one quadlet harvest), and no
    # such mount relabels with :z/:Z. The sole enforcer of cross-container isolation
    # of the PHI dirs on the deploy path.
    "tooling/test_639_mcs_level_pin.py",

    # ─── the shared harness's own reach (census-r2 class B, sme-da SHOULD-1) ───
    # Teeth for the hop helpers every call-graph pin leans on: unknown-receiver edges, the
    # bounded re-export chain, and the unresolved-hop report. The sole enforcer of that reach.
    "test_pin_harness_reach_teeth.py",

    # ─── meta-pins (self-protection layer, Prime Directive #7 "census the
    #     censusers") ───
    # The harness-adoption meta-pin — catches ADDITION drift.
    "test_pin_harness_adoption.py",
    # This registry itself — catches DELETION drift.
    "test_pin_registry.py",
})

# Required pins that scripts/publish-strip-paths.txt strips individually (their subject does
# not ship). Required in the dev tree; skipped only where tests/tooling/ is absent (the mirror).
_DEV_ONLY_STRIPPED_PINS = frozenset({
    "test_636_shutdown_envelope_pin.py",
})


def test_all_required_pins_present():
    """Every entry in ``_REQUIRED_PINS`` must exist as a real file under tests/.

    A ``git rm`` of a required pin trips this test even if the deleter forgot
    to update ``_REQUIRED_PINS`` — the deletion is caught before merge. If the
    deletion was intentional (pin consolidation), the deleter must remove the
    entry AND name the successor in a comment in the diff, which is visible on
    review.
    """
    # tests/tooling/ (operator-tooling pins) is stripped from the public mirror as a whole
    # package (scripts/publish-strip-paths.txt `tests/tooling/*`). Its entries are required
    # wherever the package exists; only a tree with NO tests/tooling/__init__.py (the
    # mirror) skips them. Deleting one tooling pin in the dev tree still trips this test.
    # Same skip for the few required pins stripped ONE BY ONE because their subject
    # (deploy/, publish/deploy/) does not ship; they stay in tests/ because they also
    # import the product. 2026-11-09: the v0.2.0 public Release run failed on this.
    tooling_present = (_TESTS_ROOT / "tooling" / "__init__.py").is_file()
    missing = [
        rel for rel in sorted(_REQUIRED_PINS)
        if not (_TESTS_ROOT / rel).is_file()
        and (tooling_present
             or not (rel.startswith("tooling/") or rel in _DEV_ONLY_STRIPPED_PINS))
    ]
    assert not missing, (
        "SB-2 required-pin registry: these pins are listed in _REQUIRED_PINS "
        "but do NOT exist under tests/. If the deletion was intentional (pin "
        "consolidation), REMOVE the entry from _REQUIRED_PINS and name the "
        "successor pin in a same-diff comment. If unintentional, restore the "
        "file — its deletion would silently degrade a defense-in-depth layer."
        "\n\nMissing:\n  " + "\n  ".join(missing)
    )


def test_required_list_entries_look_like_pins():
    """Every required entry must be a Python test-file relative path matching
    the pin naming convention — a typo (e.g. dropping the trailing ``.py`` or
    swapping ``_pin`` for ``_pn``) surfaces here with a specific message
    rather than as a generic "missing" from :func:`test_all_required_pins_present`.
    """
    for rel in _REQUIRED_PINS:
        name = rel.rsplit("/", 1)[-1]  # last path segment = basename
        assert name.startswith("test_") and name.endswith(".py"), (
            f"required-pin entry {rel!r} isn't a `test_*.py` basename"
        )
        # Accept _pin.py, _pin_registry, _pin_harness_adoption, _ssot_pin.py,
        # _ratchet_pin.py, "safety" tests (async_db_safety), or explicit
        # invariant tests (test_no_unguarded_secret_write — the never-clobber
        # funnel — is a canonical protection test, not a *_pin.py by name).
        toklike = ("pin", "registry", "adoption", "safety", "no_unguarded")
        assert any(t in name for t in toklike), (
            f"required-pin entry {rel!r} doesn't match a pin naming convention "
            f"(expected one of: {toklike})"
        )


import ast as _ast
import re as _re

_DEF_TEST_RE = _re.compile(r"^\s*def\s+test_[A-Za-z0-9_]+\s*\(", _re.MULTILINE)


def _file_has_module_level_skip(source: str) -> bool:
    """True if the file has a MODULE-LEVEL call to ``pytest.skip(...,
    allow_module_level=True)`` (an AST check — a regex would false-match
    the pattern's own definition string inside this very file)."""
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False
    for node in tree.body:  # module-level statements ONLY
        if not isinstance(node, _ast.Expr):
            continue
        call = node.value
        if not isinstance(call, _ast.Call):
            continue
        f = call.func
        # Match `pytest.skip(...)` — Attribute on Name "pytest".
        if not (
            isinstance(f, _ast.Attribute)
            and f.attr == "skip"
            and isinstance(f.value, _ast.Name)
            and f.value.id == "pytest"
        ):
            continue
        for kw in call.keywords:
            if kw.arg == "allow_module_level" and isinstance(
                kw.value, _ast.Constant,
            ) and kw.value.value is True:
                return True
    return False


def test_required_pins_have_teeth_not_neutered():
    """DA-SF-2 (batched NTH-panel 2026-07-19): a required pin file that
    exists but has been NEUTERED (zero-byte, ``pass``-only, or top-level
    ``pytest.skip(allow_module_level=True)``) silently defeats the pin
    while keeping the registry green.

    Verify each entry:
      1. is at least 300 bytes (a real pin has docstring + imports + one
         test function + assertion — well above 300 bytes; catch-all for
         zero-byte or single-line files).
      2. contains at least one ``def test_...(`` function definition.
      3. does NOT contain a module-level ``pytest.skip(...,
         allow_module_level=True)`` — which would cause pytest to skip
         the entire module and turn every pin inside into a no-op.
    """
    _MIN_BYTES = 300
    offenders: list[str] = []
    for rel in sorted(_REQUIRED_PINS):
        path = _TESTS_ROOT / rel
        if not path.is_file():
            continue  # test_all_required_pins_present reports this shape
        size = path.stat().st_size
        if size < _MIN_BYTES:
            offenders.append(f"{rel}: {size} bytes < {_MIN_BYTES} minimum")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _file_has_module_level_skip(text):
            offenders.append(
                f"{rel}: has module-level `pytest.skip(..., "
                "allow_module_level=True)` — pin is silently skipped"
            )
            continue
        if not _DEF_TEST_RE.search(text):
            offenders.append(
                f"{rel}: no `def test_...(` function defined — file exists "
                "but pytest collects zero tests"
            )
    assert not offenders, (
        "DA-SF-2 pin-registry teeth: required pins exist as files but appear "
        "NEUTERED (zero-teeth). A `git rm` was avoided but a `pass`-only "
        "rewrite or a top-level skip achieves the same silent degradation.\n\n"
        + "\n".join(offenders)
    )


def test_meta_pin_has_teeth():
    """The teeth: if ``_REQUIRED_PINS`` were emptied, both tests above would
    vacuously pass. A floor assertion prevents a future maintainer neutering
    the registry by silently shrinking the list.

    The floor is deliberately lower than the current member-count so
    legitimate consolidation (e.g. two N-432 pins fold into one over time)
    stays possible — but a mass-clear ("just this one commit — CI green")
    trips it.
    """
    # Current member-count at landing: 10. Floor set to 5 — allows a genuine
    # ~50% consolidation before requiring a documented rethink of the layer.
    _FLOOR = 5
    assert len(_REQUIRED_PINS) >= _FLOOR, (
        "SB-2 pin-registry: `_REQUIRED_PINS` has been shrunk below the "
        f"{_FLOOR}-pin floor. Consolidation is fine, but a set this small "
        "suggests the SSOT-defense layer is being dismantled — investigate "
        "before merge."
    )
