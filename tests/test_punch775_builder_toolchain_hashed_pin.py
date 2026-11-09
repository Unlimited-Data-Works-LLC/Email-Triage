"""Punch 775: every ``pip install`` in the shipped ``Containerfile`` is hashed, or installs the local tree.

The builder stage compiles the encryption-at-rest binding (sqlcipher3) with ``--no-build-isolation``, so
its build backend is whatever the stage installed first. Until 775 that was ``pip install setuptools wheel``:
unpinned, unhashed. ``source_built.py verify`` binds the source and amalgamation sha, never the toolchain.

THE PROPERTY (count-agnostic: it walks every ``pip install`` in every stage, never ``len(...) == N``):

* An install is HASHED when it carries ``--require-hashes``; every ``-r`` file it reads must then give every
  requirement a ``--hash=sha256:`` (so pip would refuse an unhashed line anyway, and this pin names the file).
* An install is LOCAL when it passes ``--no-deps`` and every target is a path in the build context (``.``,
  ``.[extra]``, ``-e .``): no index fetch is possible for the package itself, and ``--no-deps`` leaves nothing
  for pip to fetch behind it.
* Anything else (a bare name, a ``-r`` file without ``--require-hashes``, a local path WITHOUT ``--no-deps``)
  is a violation.

Scope: ``Containerfile`` (the shipped image). ``Containerfile.test`` is a test image and is not covered here.
"""
from __future__ import annotations

import re
import shlex

import pytest

from _pin_harness import REPO_ROOT, dockerfile_instructions, dockerfile_shell_text, dockerfile_stages

CONTAINERFILE = REPO_ROOT / "Containerfile"

_PIP_INSTALL = re.compile(r"(?:^|[\s;&|(])(?:python3?\s+-m\s+)?pip3?\s+install\b([^;&|\n]*)")
# options that consume the NEXT token as their value
_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "--prefix", "--target", "-t", "--root", "--no-binary",
    "--only-binary", "--timeout", "--retries", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--platform", "--python-version", "--implementation", "--abi", "--progress-bar", "--trusted-host", "--cache-dir",
}
_LOCAL_TARGET = re.compile(r"^(?:\.|\./.*|/.*)(?:\[[^\]]*\])?$")


def _installs(text: str) -> list[tuple[int, list[str]]]:
    """``(Containerfile line, argv after "pip install")`` for every pip install in every RUN."""
    out: list[tuple[int, list[str]]] = []
    for lineno, instr in dockerfile_instructions(text):
        if not instr.lstrip().upper().startswith("RUN"):
            continue
        shell = dockerfile_shell_text(instr)
        for m in _PIP_INSTALL.finditer(shell):
            try:
                out.append((lineno, shlex.split(m.group(1))))
            except ValueError:
                out.append((lineno, m.group(1).split()))
    return out


def _parse(argv: list[str]) -> tuple[set[str], list[str], list[str]]:
    """``(flags, requirement files, positional targets)``; ``-e X`` counts X as a target."""
    flags: set[str] = set()
    req_files: list[str] = []
    targets: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in {"-r", "--requirement"} and i + 1 < len(argv):
            req_files.append(argv[i + 1])
            flags.add("-r")
            i += 2
        elif tok.startswith("--requirement="):
            req_files.append(tok.split("=", 1)[1])
            flags.add("-r")
            i += 1
        elif tok == "-e" or tok == "--editable":
            if i + 1 < len(argv):
                targets.append(argv[i + 1])
            i += 2
        elif tok in _VALUE_FLAGS:
            flags.add(tok)
            i += 2
        elif tok.startswith("-"):
            flags.add(tok.split("=", 1)[0])
            i += 1
        else:
            targets.append(tok)
            i += 1
    return flags, req_files, targets


def unhashed_installs(text: str) -> list[str]:
    """Every pip install in ``text`` that is neither hashed nor a ``--no-deps`` local-tree install."""
    bad: list[str] = []
    for lineno, argv in _installs(text):
        flags, req_files, targets = _parse(argv)
        if "--require-hashes" in flags:
            continue
        if "--no-deps" in flags and not req_files and targets and all(_LOCAL_TARGET.match(t) for t in targets):
            continue
        bad.append(f"line {lineno}: pip install {' '.join(argv)}")
    return bad


def hashes_missing_in(req_text: str) -> list[str]:
    """Requirement lines of a pip requirements file that carry no ``--hash=sha256:``."""
    joined = re.sub(r"\\\r?\n", " ", req_text)
    bad = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if not re.search(r"--hash=sha256:[0-9a-f]{64}", line):
            bad.append(line.split()[0])
    return bad


def test_every_pip_install_in_the_containerfile_is_hashed_or_local():
    text = CONTAINERFILE.read_text(encoding="utf-8")
    assert _installs(text), "the walk found no pip install in the Containerfile; the pin is blind"
    bad = unhashed_installs(text)
    assert not bad, (
        "unhashed pip install(s) in the shipped Containerfile (punch 775). Add --require-hashes with a "
        "hash-pinned requirements file, or install the local tree with --no-deps:\n  " + "\n  ".join(bad)
    )


def test_every_required_file_is_a_repo_file_and_fully_hashed():
    text = CONTAINERFILE.read_text(encoding="utf-8")
    seen = 0
    for lineno, argv in _installs(text):
        flags, req_files, _targets = _parse(argv)
        for rf in req_files:
            seen += 1
            name = rf.rsplit("/", 1)[-1]  # a Containerfile path is POSIX; no separator to normalise
            path = REPO_ROOT / name
            assert path.is_file(), f"line {lineno}: -r {rf} names {name}, which is not a repo-root file"
            assert "--require-hashes" in flags, f"line {lineno}: -r {rf} without --require-hashes"
            missing = hashes_missing_in(path.read_text(encoding="utf-8"))
            assert not missing, f"{name} has requirement(s) with no sha256 hash: {missing}"
    assert seen, "no `-r <file>` install found; the file arm of the pin is blind"


def test_the_build_toolchain_is_installed_from_the_hashed_file_before_the_sqlcipher3_build():
    """In the builder stage the toolchain RUN comes before the RUN that builds sqlcipher3."""
    stages = dict(dockerfile_stages(CONTAINERFILE.read_text(encoding="utf-8")))
    builder = stages["builder"]
    tool = [i for i, (_l, ins) in enumerate(builder) if "requirements-build.txt" in ins and ins.lstrip().upper().startswith("RUN")]
    build = [i for i, (_l, ins) in enumerate(builder) if "--no-build-isolation" in ins and ins.lstrip().upper().startswith("RUN")]
    copy = [i for i, (_l, ins) in enumerate(builder) if ins.lstrip().upper().startswith("COPY") and "requirements-build.txt" in ins]
    assert tool and build and copy, (tool, build, copy)
    assert copy[0] < tool[0], "requirements-build.txt must be COPYed before the RUN that installs from it"
    assert tool[0] <= build[0], "the toolchain must be installed in or before the RUN that builds sqlcipher3"
    assert not re.search(r"pip\s+install[^;&|]*\b(setuptools|wheel)\b(?![^;&|]*requirements)", builder[build[0]][1]), (
        "the sqlcipher3 build RUN installs setuptools/wheel by bare name again"
    )


# --- teeth: the detector is proved on planted shapes --------------------------------------------------

_BAD = [
    "RUN pip install --no-cache-dir setuptools wheel",
    "RUN pip install --no-cache-dir --no-build-isolation .",              # local path without --no-deps
    "RUN pip install --no-deps somepackage",                              # --no-deps but a named package
    "RUN pip install -r requirements.lock",                               # -r without --require-hashes
    "RUN set -eux; cd /x; python -m pip install --upgrade pip; echo ok",  # -m pip form, bare option install
]
_GOOD = [
    "RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock",
    "RUN pip install --no-cache-dir --no-deps --prefix=/install \\\n    \".[keyfile,imap,office365]\"",
    "RUN pip install --no-cache-dir --no-deps -e .",
    "RUN set -eux; pip install --require-hashes --only-binary :all: --no-deps -r /build/requirements-build.txt; echo ok",
]


@pytest.mark.parametrize("snippet", _BAD)
def test_the_detector_flags_a_planted_unhashed_install(snippet):
    assert unhashed_installs(snippet), snippet


@pytest.mark.parametrize("snippet", _GOOD)
def test_the_detector_passes_a_planted_hashed_or_local_install(snippet):
    assert not unhashed_installs(snippet), snippet


def test_the_hash_reader_flags_an_unhashed_requirement_line():
    assert hashes_missing_in("good==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\nbad==2.0\n") == ["bad==2.0"]
    assert hashes_missing_in("# c\n--only-binary :all:\n") == []
