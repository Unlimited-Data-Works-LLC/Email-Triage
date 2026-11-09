"""Punch 538 / cve-arc  — the build READS ``source-built.pins``, and keeps reading it.

``source-built.pins`` declares the components this image builds from upstream
source. cve-arc silences advisories on its word, gated on the running container
descending from the commit that added it. That rule has one blind spot, and it
is the reason this file exists: **a build-time assert cannot detect its own
removal.** A later commit that stops reading the declaration — reverts to a PyPI
wheel, re-introduces an ``ENV`` pin, drops a clone — while leaving the file in
place still satisfies the descendant rule, and cve-arc keeps silencing for a
component that is no longer built the way the file says. Nothing in CI builds
the image on main (``release.yml`` fires on ``v*`` tags; ``arm64-build-check.yml``
is path-filtered), so the build's own asserts never run there either.

A pin that runs in the ordinary suite is what closes it.

Every check below is count-agnostic — a PROPERTY over every site, derived from
the declaration itself, never ``len(X) == N`` (PD#1). Adding a fourth component
adds a clone and a declared row, and (a) re-derives; it does not need editing.

The parser is IMPORTED, never re-implemented (PD#5): ``scripts/source_built.py``
is the funnel the Containerfile also runs, so a grammar the pin accepts and the
build rejects cannot exist.

Each detector is a pure function of the text, so the teeth tests plant a
mutated Containerfile and prove the check goes RED — a pin whose teeth arm was
never exercised is indistinguishable from a pin that cannot fail.
"""

from __future__ import annotations

import re
import tomllib

import pytest

from _pin_harness import (
    CONTAINERFILE,
    REPO_ROOT,
    dockerfile_code,
    dockerfile_stages,
    load_repo_script,
)

#: THE one parser (PD#5) — the same module the Containerfile runs. The pin must
#: not grow a second copy of the grammar, or a row the build rejects could be
#: green here.
sb = load_repo_script("scripts/source_built.py", "_et_source_built")

PINS_PATH = REPO_ROOT / sb.PINS_FILENAME
COMPONENTS = sb.load(PINS_PATH)

_CF_TEXT = CONTAINERFILE.read_text(encoding="utf-8")
_CF_CODE = dockerfile_code(_CF_TEXT)

#: Every declared string that must never be spelled out in Containerfile code.
#: Derived from the declaration, so a component added tomorrow is covered.
#: Deliberately EXACT strings: the retained walresetbug guard asserts a
#: ``'4.20.'`` PREFIX, which is a floor with its own reason to exist and is not
#: a copy of the declared ``4.20.0``.
DECLARED_VALUES = sorted(
    {c.sha for c in COMPONENTS}
    | {c.version for c in COMPONENTS}
    | {c.tag for c in COMPONENTS}
)

_CLONE_RE = re.compile(
    r"git\s+clone\s+(?:--\S+\s+)*https://github\.com/"
    r"([A-Za-z0-9._-]+/[A-Za-z0-9._-]+?)(?:\.git)?(?=[\s;'\"]|$)"
)
_HEX40_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])")
_ARG_ENV_RE = re.compile(r"^\s*(?:ARG|ENV)\s+(.*)$", re.M)
_DEFAULT_SUBST_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):[-=?+]([^}]*)\}")


# ---------------------------------------------------------------------------
# (a) clone-site bijection
# ---------------------------------------------------------------------------


def clone_repos(cf_code: str) -> set[str]:
    """Every ``owner/repo`` the Containerfile ``git clone``s."""
    return set(_CLONE_RE.findall(cf_code))


def declared_clone_repos(components) -> set[str]:
    """Every declared repository that needs a clone of its own — i.e. every
    non-embedded component's. An EMBEDDED component (``sqlite``, which is the
    SQLCipher amalgamation under the identity CVEs are filed against) rides on
    another row's checkout and must NOT add a clone."""
    return {c.repo for c in components if not c.embedded}


def test_clone_sites_are_exactly_the_declared_repositories():
    """The set of clones EQUALS the set of declared non-embedded repositories.

    Both directions matter and they fail differently. A clone with no
    declaration is a source-built component invisible to every scanner — the
    original  defect, re-opened. A declaration with no clone is worse: the
    file asserts a version nothing in this build produces, and cve-arc silences
    advisories against it."""
    cloned = clone_repos(_CF_CODE)
    declared = declared_clone_repos(COMPONENTS)
    assert cloned == declared, (
        f"Containerfile clones {sorted(cloned)}; source-built.pins declares "
        f"{sorted(declared)} as needing a clone.\n"
        f"  only cloned:   {sorted(cloned - declared)} (source-built and "
        f"undeclared — invisible to cve-arc, which is the whole #87 defect)\n"
        f"  only declared: {sorted(declared - cloned)} (declared but not built "
        f"here — the file would assert a version this build does not produce)"
    )


def test_clone_bijection_has_teeth():
    """Both directions go RED on a planted break."""
    dropped = _CF_CODE.replace(
        "git clone https://github.com/coleifer/sqlcipher3.git sqlcipher3-src", "true"
    )
    assert dropped != _CF_CODE, "teeth fixture is stale — the clone line moved"
    assert clone_repos(dropped) != declared_clone_repos(COMPONENTS)

    added = _CF_CODE + "\nRUN git clone https://github.com/attacker/evil.git evil-src\n"
    assert clone_repos(added) != declared_clone_repos(COMPONENTS)

    extra = list(COMPONENTS) + [
        sb.Component("c", "openssl", "3.0.0", "openssl/openssl", "0" * 40, "3.0.0", 99)
    ]
    assert declared_clone_repos(extra) != clone_repos(_CF_CODE)


# ---------------------------------------------------------------------------
# (b) no second copy of a declared value
# ---------------------------------------------------------------------------


def second_copies(cf_code: str, declared: list[str]) -> list[str]:
    """Every place Containerfile CODE carries a declared value itself.

    The invariant is the broad one — **no literal copy of a declared value
    anywhere in code** — not a list of the three shapes that happened to exist
    in this file's history. Keying on `ARG`/`ENV` alone would have let
    ``RUN pip install sqlcipher3==0.6.2`` through, which is a second copy of a
    declared version in the place it does the most damage.

    Reported per shape, because the shapes fail differently:

      * ANY declared sha, version or tag as a literal on a code line. ``ARG``
        and ``ENV`` are named separately because ``ARG`` is the worse of the
        two: ``--build-arg`` then overrides the pin from OUTSIDE the
        repository, which is precisely the objection cve-arc raised to parsing
        the Containerfile at all.
      * a bare 40-hex literal even if it matches nothing declared — an
        undeclared sha in a build is a pin with no declaration behind it.
      * a ``${VAR:-default}`` substitution on any ``SB_*`` variable. That one
        is not about the literal: it re-introduces a silent fallback where
        ``set -u`` currently makes a component dropped from the declaration a
        fatal error, so it converts a fail-closed build into a fail-open one.

    Comparison is by EXACT declared string, which is what keeps the retained
    walresetbug guard's ``startswith('4.20.')`` out of scope by construction:
    ``4.20.`` is not ``4.20.0``, and folding that floor into this check would
    delete a control with its own reason to exist.
    """
    found: list[str] = []
    for m in _HEX40_RE.finditer(cf_code):
        found.append(f"40-hex literal {m.group(0)!r}")
    arg_env_spans = [(m.start(), m.end(), m.group(1)) for m in _ARG_ENV_RE.finditer(cf_code)]
    for value in declared:
        if _HEX40_RE.fullmatch(value):
            continue  # already reported by the 40-hex arm, whatever its shape
        for m in re.finditer(re.escape(value), cf_code):
            where = next(
                (f"ARG/ENV {body.strip()!r}" for s, e, body in arg_env_spans
                 if s <= m.start() < e),
                "code line " + cf_code[:m.start()].count("\n").__str__(),
            )
            found.append(f"literal copy of declared value {value!r} in {where}")
    for m in _DEFAULT_SUBST_RE.finditer(cf_code):
        var, default = m.group(1), m.group(2)
        if var.startswith("SB_"):
            found.append(f"default-substitution on {var} defeats set -u: {m.group(0)!r}")
        elif any(value in default for value in declared):
            found.append(f"default-substitution carries a declared value: {m.group(0)!r}")
    return found


def test_no_second_copy_of_any_declared_value_in_containerfile_code():
    """There is ONE source for each sha, version and tag: the declaration.

    Comments are excluded — the history of this build is worth writing down,
    and prose that names a sha cannot make a build use it."""
    offenders = second_copies(_CF_CODE, DECLARED_VALUES)
    assert not offenders, (
        "Containerfile code carries its own copy of a declared value. The "
        "build must read source-built.pins and nothing else, or the file can "
        "say one thing while the build does another — and cve-arc silences "
        "advisories on the file's word:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    "planted",
    [
        "ENV SQLCIPHER_SHA=355d4db92d3404e71faa8088d071a71d767807f4",
        "ARG SQLCIPHER3_VERSION=0.6.5",
        'RUN echo "355d4db92d3404e71faa8088d071a71d767807f4"',
        'RUN git checkout "${SB_SQLCIPHER_SHA:-355d4db92d3404e71faa8088d071a71d767807f4}"',
        'RUN git checkout "${SB_SQLCIPHER_SHA:-}"',
        "ENV SQLCIPHER_TAG=v4.20.0",
        # A declared version as a literal OUTSIDE any ARG/ENV — the shape an
        # ARG/ENV-keyed check would miss, in the place it does most damage.
        "RUN pip install sqlcipher3==0.6.5",
        "RUN git checkout v4.20.0",
        'RUN test "$v" = "3.54.1"',
    ],
)
def test_second_copy_detector_has_teeth(planted):
    """Each forbidden shape, planted into the real file, goes RED."""
    assert second_copies(_CF_CODE + "\n" + planted + "\n", DECLARED_VALUES), (
        f"the second-copy detector missed {planted!r}"
    )


def test_second_copy_detector_does_not_flag_a_comment_or_the_retained_floor():
    """False-positive arm. A comment naming the old ENV pin is fine, and so is
    the retained ``startswith('4.20.')`` walresetbug guard: a PREFIX floor is
    not a copy of the declared ``4.20.0``, and folding the two would delete a
    control that has its own reason to exist."""
    commented = (
        _CF_TEXT
        + "\n# historical: ENV SQLCIPHER_SHA=355d4db92d3404e71faa8088d071a71d767807f4\n"
    )
    assert not second_copies(dockerfile_code(commented), DECLARED_VALUES)
    floor = _CF_CODE + "\nRUN python -c \"assert v.startswith('4.20.')\"\n"
    assert not second_copies(floor, DECLARED_VALUES)


# ---------------------------------------------------------------------------
# (c) COPY before use, per stage
# ---------------------------------------------------------------------------

_READ_TOKENS = ("source-built.pins", "source_built.py")


def copy_before_use_offenders(cf_text: str) -> list[str]:
    """Per BUILD STAGE: every file the stage READS must be COPYed earlier in
    THAT stage.

    Per stage, because each ``FROM`` starts a fresh filesystem: the builder
    having the declaration says nothing about the runtime image, and the
    runtime verify is the run cve-arc's proof actually rests on. A missing COPY
    is not a silent skip — the RUN fails — but it fails at BUILD time, on the
    deploy host, in the middle of a release, which is the expensive place to
    learn it."""
    offenders: list[str] = []
    for stage, instructions in dockerfile_stages(cf_text):
        copied: dict[str, int] = {}
        for idx, (lineno, instr) in enumerate(instructions):
            verb = instr.split(None, 1)[0].upper() if instr.split() else ""
            is_copy = verb == "COPY" and "--from=" not in instr
            for token in _READ_TOKENS:
                if token not in instr:
                    continue
                if is_copy:
                    copied.setdefault(token, idx)
                elif verb == "RUN" and token not in copied:
                    offenders.append(
                        f"stage {stage!r} line {lineno}: reads {token} with no "
                        f"earlier COPY of it in this stage"
                    )
    return offenders


def test_the_declaration_and_its_parser_are_copied_before_every_stage_reads_them():
    offenders = copy_before_use_offenders(_CF_TEXT)
    assert not offenders, "COPY-before-use broken:\n  " + "\n  ".join(offenders)


def test_both_stages_that_verify_actually_copy_both_files():
    """The declaration AND the parser, in EVERY stage that runs ``verify``.

    Count-agnostic: the stage set is discovered from the file. The builder
    proves ``/install``; the runtime stage proves the image that ships. Losing
    the second one is the failure mode db-sme named — a builder-only check is
    green while a later COPY path diverges."""
    verifying = [
        stage
        for stage, instructions in dockerfile_stages(_CF_TEXT)
        if any(
            instr.split(None, 1)[0].upper() == "RUN" and "source_built.py verify" in instr
            for _, instr in instructions
        )
    ]
    assert len(verifying) >= 2, (
        f"only {verifying} run `source_built.py verify`. The builder check "
        f"proves /install; only the RUNTIME stage proves the image that ships."
    )
    for stage, instructions in dockerfile_stages(_CF_TEXT):
        if stage not in verifying:
            continue
        for token in _READ_TOKENS:
            assert any(
                instr.split(None, 1)[0].upper() == "COPY"
                and "--from=" not in instr
                and token in instr
                for _, instr in instructions
            ), f"stage {stage!r} verifies but never COPYs {token}"


def test_copy_before_use_detector_has_teeth():
    """Moving the runtime COPY below the RUN that reads it goes RED."""
    copy_line = "COPY source-built.pins /app/source-built.pins"
    assert copy_line in _CF_TEXT, "teeth fixture is stale — the runtime COPY moved"
    moved = _CF_TEXT.replace(copy_line + "\n", "", 1).replace(
        "COPY scripts/embedding-bits-manifest.json",
        copy_line + "\nCOPY scripts/embedding-bits-manifest.json",
        1,
    )
    assert copy_before_use_offenders(moved), (
        "the ordering detector did not notice a COPY moved below its reader"
    )
    deleted = _CF_TEXT.replace(copy_line + "\n", "", 1)
    assert copy_before_use_offenders(deleted)


# ---------------------------------------------------------------------------
# (d) / (e) the other install surfaces agree with the declaration
# ---------------------------------------------------------------------------


def _pypi_components():
    return [c for c in COMPONENTS if c.kind == "pypi"]


def encryption_extra_pins(pyproject_text: str) -> list[str]:
    """The requirement strings in pyproject's ``encryption`` extra."""
    data = tomllib.loads(pyproject_text)
    return [s.strip() for s in data["project"]["optional-dependencies"]["encryption"]]


def extra_disagreements(pyproject_text: str, components) -> list[str]:
    """Declared ``pypi`` rows whose version the ``encryption`` extra does not
    pin. Pure over the text so a teeth arm can plant a bumped extra."""
    pins = encryption_extra_pins(pyproject_text)
    return [
        f"{c.name}=={c.version} (extra has {pins})"
        for c in components
        if c.kind == "pypi" and f"{c.name}=={c.version}" not in pins
    ]


#: THE lock parser (PD#5), shipped (scripts/lock_reader.py). The split
#: this file used to do yielded a bogus ``--hash`` name on a hashed lock.
drift = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")


def lock_names(lock_text: str) -> set[str]:
    """Every distribution the lock names (PEP 503 canonical), marker or not."""
    locked = drift.parse_lock(lock_text, None)
    return set(locked.pins) | set(locked.unevaluated) | set(locked.not_applicable)


def lock_overlap(lock_text: str, components) -> list[str]:
    """Names that are BOTH source-built and lock-pinned. ``sqlcipher3-binary``
    is named explicitly: it is a DIFFERENT distribution carrying the same
    import, so a name-equality check alone would miss it."""
    forbidden = {drift.canonical(c.name) for c in components if c.kind == "pypi"}
    forbidden.add("sqlcipher3-binary")
    return sorted(lock_names(lock_text) & forbidden)


def test_pyproject_encryption_extra_matches_the_declared_pypi_version():
    """``[encryption]``'s pin and the declaration are the same number.

    They are two different mechanisms — the extra is what a pip-installed
    (non-container) deployment resolves, the declaration is what the image
    builds — and a scanner reads the extra. If they drift, one of them is
    lying about the encryption boundary and there is no way to tell which."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    bad = extra_disagreements(text, COMPONENTS)
    assert not bad, (
        "pyproject's [encryption] extra and source-built.pins disagree. The "
        "extra a pip install resolves and the version the image builds must be "
        "the same number:\n  " + "\n  ".join(bad)
    )


def test_pyproject_agreement_has_teeth():
    """Bump the extra and leave the declaration alone — the real detector, over
    real pyproject text, must go RED. (Asserting a hand-built mismatch instead
    would test the assertion, not the check.)"""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = _pypi_components()[0]
    bumped = text.replace(
        f'"{declared.name}=={declared.version}"',
        f'"{declared.name}=={declared.version}9"', 1,
    )
    assert bumped != text, "teeth fixture is stale — the extra's pin moved"
    assert extra_disagreements(bumped, COMPONENTS)
    assert not extra_disagreements(text, COMPONENTS)


def test_no_declared_pypi_distribution_is_also_in_the_lockfile():
    """A declared ``pypi`` name must NOT appear in ``requirements.lock``.

    The lock install runs BEFORE the source build and shares its ``--prefix``,
    so a lock line would fetch the published wheel first — which is what the
    source build exists to avoid (that wheel vendors SQLCipher 4.12.0 /
    SQLite 3.51.1). Today the runtime asserts would catch the result and break
    the build; the risk this pin covers is the AMBIGUOUS two-install state, a
    wheel's residue left beside the source install, which the declaration would
    then describe incorrectly. ``sqlcipher3-binary`` is named explicitly: it is
    a DIFFERENT distribution name carrying the same import, so a name-equality
    check alone would miss it."""
    lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")
    overlap = lock_overlap(lock, COMPONENTS)
    assert not overlap, (
        f"{overlap} is both source-built (declared in source-built.pins) and "
        f"pinned in requirements.lock. The lock install runs first into the "
        f"same --prefix, so pip would fetch the published wheel the source "
        f"build exists to avoid."
    )


@pytest.mark.parametrize(
    "planted",
    [
        "sqlcipher3==0.6.2",
        "sqlcipher3-binary==0.5.4",
        "SQLCipher3 == 0.6.2",           # case + spacing
        "sqlcipher3[extra]==0.6.2",      # an extras marker
        # the --generate-hashes shape (punch 549): continuation + hash line
        "sqlcipher3==0.6.2 " + chr(92) + "\n    --hash=sha256:" + "a" * 64,
        'sqlcipher3==0.6.2 ; sys_platform == "linux" ' + chr(92) + "\n    --hash=sha256:" + "b" * 64,
    ],
)
def test_lockfile_check_has_teeth(planted):
    """Plant the line in REAL lock text and run the REAL parser over it.

    The previous version of this built a name set by hand and intersected it,
    which never exercised ``lock_names`` at all — it asserted that set
    intersection works. A lock-line spelling the parser mis-splits would have
    read green."""
    lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")
    assert not lock_overlap(lock, COMPONENTS), "baseline lock already overlaps"
    assert lock_overlap(lock + planted + "\n", COMPONENTS), (
        f"the lock check did not catch a planted {planted!r}"
    )


def test_lockfile_check_ignores_a_comment_and_an_unrelated_name():
    """False-positive arm: a commented-out line is not an install, and a
    different distribution is not ours."""
    lock = (REPO_ROOT / "requirements.lock").read_text(encoding="utf-8")
    assert not lock_overlap(lock + "# sqlcipher3==0.6.2\n", COMPONENTS)
    assert not lock_overlap(lock + "sqlalchemy==2.0.0\n", COMPONENTS)


# ---------------------------------------------------------------------------
# (f) the grammar itself
# ---------------------------------------------------------------------------


def test_the_shipped_declaration_parses():
    assert COMPONENTS, "source-built.pins declares nothing"
    assert any(c.kind == "pypi" for c in COMPONENTS)
    assert any(c.kind == "c" for c in COMPONENTS)


_GOOD = (
    "pypi  sqlcipher3  0.6.2   coleifer/sqlcipher3  "
    "14fc2632676b20011e0bba64fdda49763a2dd2ec  0.6.2\n"
    "c     sqlcipher   4.17.0  sqlcipher/sqlcipher  "
    "810db22f575ee7cf94ea96a3e91622b5fcece3dc  v4.17.0\n"
    "c     sqlite      3.53.3  sqlcipher/sqlcipher  "
    "810db22f575ee7cf94ea96a3e91622b5fcece3dc  v4.17.0\n"
)


def test_the_teeth_fixture_itself_parses():
    """Prove the mutation base is VALID before asserting mutations are not —
    a fixture that fails for its own reasons would make every rejection arm
    below pass without measuring anything."""
    assert len(sb.parse_text(_GOOD)) == 3


@pytest.mark.parametrize(
    "label,text",
    [
        ("empty file", "# only a comment\n"),
        ("five columns", "c sqlcipher 4.17.0 sqlcipher/sqlcipher " + "8" * 40 + "\n"),
        (
            "trailing comment is a seventh column",
            _GOOD.replace("v4.17.0\n", "v4.17.0  # the tag\n", 1),
        ),
        ("unknown kind", _GOOD.replace("pypi ", "rust ", 1)),
        ("short sha", _GOOD.replace("810db22f575ee7cf94ea96a3e91622b5fcece3dc", "810db22f")),
        (
            "uppercase sha",
            _GOOD.replace(
                "14fc2632676b20011e0bba64fdda49763a2dd2ec",
                "14FC2632676B20011E0BBA64FDDA49763A2DD2EC",
            ),
        ),
        ("duplicate name", _GOOD + _GOOD.splitlines()[1] + "\n"),
        (
            "embedded row with no matching repo@sha",
            "pypi  sqlcipher3  0.6.2  coleifer/sqlcipher3  " + "1" * 40 + "  0.6.2\n"
            "c     sqlite      3.53.3 sqlcipher/sqlcipher  " + "8" * 40 + "  v4.17.0\n",
        ),
        (
            "one repository, two shas",
            _GOOD.replace(
                "810db22f575ee7cf94ea96a3e91622b5fcece3dc  v4.17.0\n"
                "c     sqlite      3.53.3  sqlcipher/sqlcipher  "
                "810db22f575ee7cf94ea96a3e91622b5fcece3dc",
                "810db22f575ee7cf94ea96a3e91622b5fcece3dc  v4.17.0\n"
                "c     sqlite      3.53.3  sqlcipher/sqlcipher  " + "7" * 40,
            ),
        ),
        ("version with a leading v", _GOOD.replace(" 4.17.0 ", " v4.17.0 ", 1)),
        ("repository without an owner", _GOOD.replace("sqlcipher/sqlcipher", "sqlcipher", 1)),
        (
            # db-sme N-538-D1 (panel 4, 2026-09-29). `_SHELL_UNSAFE_RE` folds
            # `-`, `_` and `.` all to `_`, and `_NAME_RE` admits all three, so
            # two LEGAL distinct names can share one `SB_*` stem. `shell` then
            # emits both sets of assignments and the sourcing shell keeps the
            # LAST — the earlier component's values vanish with rc=0. The
            # duplicate guard above is keyed on the declared NAME and cannot
            # see this; neither can the emission pin, which asserts that every
            # variable the Containerfile uses IS emitted and is satisfied by a
            # colliding pair. The grammar rule has to be enforced where the
            # grammar is.
            "two declared names that collapse to one SB_* shell stem",
            "pypi  my-lib  1.0  o/my-lib  " + "1" * 40 + "  1.0\n"
            "pypi  my_lib  2.0  o/my_lib  " + "2" * 40 + "  2.0\n",
        ),
    ],
)
def test_the_parser_rejects_every_malformed_shape(label, text):
    """Fail-closed on the grammar. A parser that shrugs at a malformed row
    hands the build an unset variable, and a lenient reader downstream could
    still act on the row this one ignored."""
    with pytest.raises(sb.DeclarationError):
        sb.parse_text(text)


def test_the_cli_exits_non_zero_on_a_malformed_file(tmp_path, capsys):
    """The BUILD calls the CLI, not the function. Exit code is the contract."""
    bad = tmp_path / "source-built.pins"
    bad.write_text("c sqlcipher 4.17.0 sqlcipher/sqlcipher deadbeef v4.17.0\n",
                   encoding="utf-8")
    assert sb.main(["parse", str(bad)]) != 0
    assert sb.main(["shell", str(bad)]) != 0
    good = tmp_path / "good.pins"
    good.write_text(_GOOD, encoding="utf-8")
    assert sb.main(["parse", str(good)]) == 0


def test_shell_output_names_every_component_and_carries_no_default():
    """``shell`` emits one assignment per field per component, single-quoted,
    with no ``export`` and no ``:-`` default — a dropped component must become
    an unbound-variable error under ``set -u``, not an empty string."""
    lines = sb.shell_assignments(COMPONENTS)
    for comp in COMPONENTS:
        for field, value in (("SHA", comp.sha), ("TAG", comp.tag),
                             ("VERSION", comp.version)):
            assert f"{comp.shell_prefix}_{field}='{value}'" in lines
    assert not any("export" in ln or ":-" in ln for ln in lines)


def test_every_shell_variable_the_containerfile_uses_is_emitted():
    """Interprocedural arm (PD#2): the pin is keyed on the CONSUMER, not the
    producer. A ``${SB_SQLITE_TAG}`` in the build that ``shell`` never emits is
    an unbound variable at build time — and a variable the build stopped using
    is dead weight the declaration still claims to drive."""
    used = set(re.findall(r"\$\{(SB_[A-Z0-9_]+)\}", _CF_CODE))
    emitted = {ln.split("=", 1)[0] for ln in sb.shell_assignments(COMPONENTS)}
    assert used, "the Containerfile references no SB_* variable — it stopped reading the declaration"
    missing = sorted(used - emitted)
    assert not missing, (
        f"the Containerfile uses {missing}, which `source_built.py shell` does "
        f"not emit. Under `set -u` that is a fatal unbound variable at build time."
    )


def test_the_build_reads_the_declaration_through_the_shared_parser():
    """The anti-removal arm, stated directly: the Containerfile must invoke
    ``source_built.py``. Every other check here is about HOW it reads the
    declaration; this one is about WHETHER. A revert that keeps the file but
    stops reading it still passes cve-arc's descendant rule."""
    assert "source_built.py shell" in _CF_CODE, (
        "the build no longer sources `source_built.py shell` — its SHAs would "
        "be coming from somewhere else"
    )
    assert "source_built.py verify" in _CF_CODE, (
        "the build no longer runs `source_built.py verify` — nothing would "
        "prove the installed versions equal the declared ones"
    )


def test_each_clone_still_asserts_its_sha_and_its_tag():
    """Per declared clone, count-agnostic: a ``rev-parse HEAD`` equality and a
    tag peel.

    The tag arm is not redundant with the sha arm. A sha pin binds the
    CHECKOUT; it does not prove the checkout is the RELEASE. coleifer's
    ``setup.py`` carries ``VERSION = '0.6.2'`` from the moment the bump lands,
    so a pre-release commit reports the release version to
    ``importlib.metadata`` — and every advisory the release fixed is then
    silenced against code that lacks the fixes. ``rev-parse <tag>^{commit}``
    rather than ``tag --points-at`` because ``v4.17.0`` is an ANNOTATED tag
    (object f9788efa, not the commit) and because ``--points-at`` depends on
    clone tag auto-follow."""
    for comp in COMPONENTS:
        if comp.embedded:
            continue
        assert f'rev-parse HEAD)" = "${{{comp.shell_prefix}_SHA}}"' in _CF_CODE, (
            f"no `rev-parse HEAD == {comp.shell_prefix}_SHA` assert for {comp.name}"
        )
        assert f'refs/tags/${{{comp.shell_prefix}_TAG}}^{{commit}}' in _CF_CODE, (
            f"no tag-peel assert for {comp.name}: the sha pin binds the commit, "
            f"not the release, and the version string comes from the release"
        )


# ---------------------------------------------------------------------------
# (g) the cipher-LINE checks outside the declaration agree with it
# ---------------------------------------------------------------------------
# Punch 631. Two major.minor checks live outside source-built.pins on purpose:
# each is a line check with its own reason to exist, not a copy of the declared
# version (see DECLARED_VALUES above). They are the runtime smoke's
# ``startswith('<major>.<minor>.')`` in the Containerfile, which is fatal at
# build, and ``SQLCIPHER_EXPECTED_MAJOR_MINOR`` in db/_engine.py, which /health
# reports as ``expected_line``. Raising ``c sqlcipher`` without them breaks the
# image build at the smoke, or leaves /health saying at_expected_line=False on
# the very build it describes. This pin keeps that bump to one change.

_ENGINE_PATH = REPO_ROOT / "src" / "email_triage" / "db" / "_engine.py"
_SMOKE_LINE_RE = re.compile(
    r"str\(r\['cipher_version'\]\)\.startswith\('(\d+)\.(\d+)\.'\)"
)
_ENGINE_LINE_RE = re.compile(
    r"^SQLCIPHER_EXPECTED_MAJOR_MINOR\b[^=\n]*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)",
    re.MULTILINE,
)


def cipher_line_disagreements(cf_code: str, engine_src: str, components) -> list[str]:
    """Every place a cipher major.minor line check disagrees with the declared
    ``sqlcipher`` version. A check that cannot be FOUND is a disagreement too:
    a renamed constant or a reworded smoke must not turn this pin vacuous."""
    declared = [c for c in components if c.name == "sqlcipher"]
    if not declared:
        return ["no 'sqlcipher' component is declared, so no line can be checked"]
    want = tuple(int(p) for p in declared[0].version.split(".")[:2])
    out: list[str] = []
    for label, pattern, text in (
        ("Containerfile runtime smoke startswith", _SMOKE_LINE_RE, cf_code),
        ("db/_engine.py SQLCIPHER_EXPECTED_MAJOR_MINOR", _ENGINE_LINE_RE, engine_src),
    ):
        found = [tuple(int(g) for g in m.groups()) for m in pattern.finditer(text)]
        if not found:
            out.append(f"{label}: not found")
        out += [
            f"{label}: {a}.{b}, but source-built.pins declares sqlcipher "
            f"{declared[0].version}"
            for (a, b) in found
            if (a, b) != want
        ]
    return out


def test_cipher_line_checks_agree_with_the_declaration():
    engine_src = _ENGINE_PATH.read_text(encoding="utf-8")
    bad = cipher_line_disagreements(_CF_CODE, engine_src, COMPONENTS)
    assert not bad, (
        "a cipher-line check disagrees with source-built.pins; a SQLCipher bump "
        "must move it in the same change:\n  " + "\n  ".join(bad)
    )


@pytest.mark.parametrize("target", ["smoke", "engine", "smoke-removed", "engine-removed"])
def test_cipher_line_agreement_has_teeth(target):
    engine_src = _ENGINE_PATH.read_text(encoding="utf-8")
    cf_code = _CF_CODE
    declared = next(c for c in COMPONENTS if c.name == "sqlcipher")
    major, minor = (int(p) for p in declared.version.split(".")[:2])
    off = f"{major}.{minor + 1}"
    if target == "smoke":
        cf_code = _SMOKE_LINE_RE.sub(f"str(r['cipher_version']).startswith('{off}.')", cf_code)
    elif target == "smoke-removed":
        cf_code = _SMOKE_LINE_RE.sub("True", cf_code)
    elif target == "engine":
        engine_src = _ENGINE_LINE_RE.sub(
            f"SQLCIPHER_EXPECTED_MAJOR_MINOR: tuple[int, int] = ({major}, {minor + 1})", engine_src
        )
    else:
        engine_src = _ENGINE_LINE_RE.sub("SQLCIPHER_RENAMED = (0, 0)", engine_src)
    assert cipher_line_disagreements(cf_code, engine_src, COMPONENTS), target
