"""Punch 658 pin: once the image installs the hash-pinned pip, no later step reinstalls pip unhashed.

WHY. N-621 pins the image's pip by hash (requirements-pip.txt, installed with
``--require-hashes``). Nothing stopped a later RUN from ``pip install -U pip`` or a requirement set
that pulls pip in, which would replace the verified pip with an unverified one while the hash pin
still reads green. Panel J (2026-10-21).

PROPERTY (count-agnostic, PD-1): in every build stage that installs requirements-pip.txt, and in
every stage built ``FROM`` such a stage, every later ``pip install`` either carries
``--require-hashes``, or carries ``--no-deps`` and names only requirements this pin can judge (no
``pip`` requirement; a ``-r``/``-c`` file, a wheel, an archive or a URL is unjudgeable and fails
closed); no later step runs ``ensurepip``/``get-pip`` or installs a distro ``python3-pip``.
Parsed with the harness Dockerfile helpers (``dockerfile_instructions``, ``dockerfile_shell_text``).
Panel N db-sme (2026-10-22) supplied the child-stage, option-form and unjudgeable-requirement cases.
"""
from __future__ import annotations

import re
import shlex

import pytest

from tests._pin_harness import REPO_ROOT, dockerfile_instructions, dockerfile_shell_text

CONTAINERFILE = REPO_ROOT / "Containerfile"
_PIP_PIN = "requirements-pip.txt"
# pip, pip3, pip3.12, python -m pip, python3.12 -m pip; global options (with or without a value,
# e.g. `--index-url https://x/simple`) may sit before `install` (panel N DA).
_INSTALL = re.compile(r"\bpip[0-9.]*\b[^;&|]*?\binstall\b"
                      r"|\bpython[0-9.]*\s+-m\s+pip\b[^;&|]*?\binstall\b")
# A build-context or cross-stage copy over the interpreter tree replaces the hashed pip too.
_OVER_INTERPRETER = re.compile(r"^/usr/local(?:/|$)|site-packages|dist-packages")
_PIP_REQ = re.compile(r"^pip(?:[<>=!~;\[ ].*)?$", re.I)
_UNJUDGEABLE = re.compile(r"\.(?:whl|tar\.gz|tgz|zip)$|://|^git\+", re.I)
_REQ_FILE_OPTS = {"-r", "--requirement", "-c", "--constraint"}
_BOOTSTRAP = re.compile(r"\bensurepip\b|\bget-pip(?:\.py)?\b")
_DISTRO_PIP = re.compile(r"\b(?:apt-get|apt|apk|dnf|yum|microdnf)\b[^;&|]*\b(?:install|add)\b[^;&|]*\bpy(?:thon)?3?-pip\b")


def _segments(shell: str) -> list[str]:
    return [s for s in re.split(r"&&|\|\||;|\|", shell) if s.strip()]


def _from_stage(instr: str) -> tuple[str, str]:
    """(base, name) of a FROM instruction; flags such as --platform are skipped."""
    args = [a for a in instr.split()[1:] if not a.startswith("--")]
    base = args[0] if args else ""
    name = args[2] if len(args) >= 3 and args[1].upper() == "AS" else base
    return base, name


def _install_problems(seg: str, words: list[str]) -> list[str]:
    if "--require-hashes" in words:
        return []
    out: list[str] = []
    if "--no-deps" not in words:
        out.append(f"pip install without --no-deps or --require-hashes: {seg.strip()[:90]}")
    if any(w in _REQ_FILE_OPTS or w.startswith(("--requirement=", "--constraint="))
           or (w[:2] in ("-r", "-c") and not w.startswith("--")) for w in words):
        out.append(f"requirement file under --no-deps is unjudgeable: {seg.strip()[:90]}")
    reqs = [w for w in words if not w.startswith("-")]
    if any(_PIP_REQ.match(w) for w in reqs):
        out.append(f"reinstalls pip unhashed: {seg.strip()[:90]}")
    if any(_UNJUDGEABLE.search(w) for w in reqs):
        out.append(f"wheel/archive/URL requirement is unjudgeable: {seg.strip()[:90]}")
    return out


def later_pip_problems(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    pinned_stages: set[str] = set()
    stage, pinned_at = "", None
    for line, instr in dockerfile_instructions(text):
        head = instr.split(None, 1)[0].upper() if instr.strip() else ""
        if head == "FROM":
            base, stage = _from_stage(instr)
            # BuildKit matches stage names case-insensitively (panel N DA).
            base, stage = base.lower(), stage.lower()
            pinned_at = line if base in pinned_stages else None
            if pinned_at is not None:
                pinned_stages.add(stage)
            continue
        if head in ("COPY", "ADD") and pinned_at is not None:
            dest = instr.split()[-1].strip('"[],')
            if _OVER_INTERPRETER.search(dest):
                out.append((line, f"{head} over the interpreter tree after the pip hash pin: {dest}"))
            continue
        if head != "RUN":
            continue
        shell = dockerfile_shell_text(instr)
        if pinned_at is None:
            if not (_PIP_PIN in shell and "--require-hashes" in shell):
                continue
            # The pin RUN itself is judged too: a chained `&& pip install -U pip` after the
            # pinned install is the likeliest way this defect gets written (panel N DA MUST).
            pinned_at = line
            pinned_stages.add(stage)
        if _BOOTSTRAP.search(shell):
            out.append((line, "runs ensurepip/get-pip after the pip hash pin"))
        if _DISTRO_PIP.search(shell):
            out.append((line, "installs a distro python3-pip after the pip hash pin"))
        for seg in _segments(shell):
            m = _INSTALL.search(seg)
            if not m:
                continue
            try:
                words = shlex.split(seg[m.end():])
            except ValueError:
                words = seg[m.end():].split()
            out.extend((line, why) for why in _install_problems(seg, words))
    return out


def test_no_unhashed_pip_reinstall_after_the_pin():
    text = CONTAINERFILE.read_text(encoding="utf-8")
    pinned = [ln for ln, i in dockerfile_instructions(text)
              if i.strip().upper().startswith("RUN") and _PIP_PIN in dockerfile_shell_text(i)]
    assert pinned, f"no RUN installs {_PIP_PIN}: the pin judges nothing"
    problems = later_pip_problems(text)
    assert not problems, "\n".join(f"Containerfile:{ln}: {why}" for ln, why in problems)


_BASE = ("FROM python:3.12-slim AS rt\n"
         "RUN python -m pip install --require-hashes -r /tmp/requirements-pip.txt\n")


@pytest.mark.parametrize("tail", [
    "RUN pip install -U pip\n",
    "RUN pip install --no-deps pip==24.0\n",
    "RUN pip install requests\n",
    "RUN python -m ensurepip --upgrade\n",
    "RUN true && pip3 install --upgrade pip setuptools\n",
    "RUN pip -q install -U pip\n",
    "RUN pip --disable-pip-version-check install -U pip\n",
    "RUN pip3.12 install -U pip\n",
    "RUN pip install --no-deps pip-24.0-py3-none-any.whl\n",
    "RUN pip install --no-deps -r /tmp/extra.txt\n",
    "RUN pip install --no-deps git+https://github.com/pypa/pip\n",
    "RUN apt-get update && apt-get install -y python3-pip\n",
    # A child stage inherits the pinned pip; BuildKit stage names are case-insensitive.
    "FROM rt AS final\nRUN pip install -U pip\n",
    "FROM RT AS final\nRUN pip install -U pip\n",
    # Panel N DA: the pin RUN itself, a valued global option, attached -r, a copy over the tree.
    "RUN python -m pip install --require-hashes -r /tmp/r2.txt && pip install -U pip\n",
    "RUN pip --index-url https://x/simple install -U pip\n",
    "RUN pip install --no-deps -r/tmp/x.txt\n",
    "COPY --from=builder /install /usr/local\n",
])
def test_teeth_flags(tail):
    assert later_pip_problems(_BASE + tail), tail


@pytest.mark.parametrize("text", [
    _BASE + "RUN pip install --no-cache-dir --no-deps -e .\n",
    _BASE + "RUN pip install --require-hashes -r other.txt\n",
    _BASE + "COPY src/ /app/src/\n",
    # The real pin RUN shape: a chained cleanup is not an install.
    "FROM python:3.12-slim AS rt\nRUN python -m pip install --require-hashes -r /tmp/requirements-pip.txt "
    "&& rm /tmp/requirements-pip.txt\n",
    # Before the pin, or in an unrelated stage, the pin does not judge.
    "FROM x AS b\nRUN pip install -U pip\n" + _BASE,
    _BASE + "FROM python:3.12-slim AS other\nRUN pip install -U pip\n",
])
def test_teeth_passes(text):
    assert later_pip_problems(text) == [], text
