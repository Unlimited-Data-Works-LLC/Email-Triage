"""Structural pin (2026-07-22) — every ``pywin32`` entry in
``requirements.lock`` MUST carry the ``sys_platform == "win32"`` environment
marker, AND the maintainer note explaining why the marker exists MUST remain
present in the comment block.

Story: 2026-07-21 a ``pip-compile`` regen stripped the manual
``; sys_platform == "win32"`` marker from the pywin32 lock line. mcp==1.28.1
DOES declare the marker upstream (``pywin32>=310; sys_platform == "win32"
and python_version < "3.14"``), but pip-compile did NOT propagate it. Without
the marker, Linux container installs try to install pywin32 (a Windows-only
wheel) and fail at install time. The regression was caught by CI only because
the committed lock still carried the marker; a subsequent commit that
happened to include the stripped lock would break every Linux CI run.

The manual re-add is a maintainer commitment — a human must notice the strip
after each ``pip-compile`` regen. This pin is the deterministic backstop:
count-agnostic, structural, fires on the strip regardless of how many
pywin32 entries exist or whether they're moved around.

WHAT IT PINS:

  1. Every line in ``requirements.lock`` matching ``^pywin32==`` MUST end
     with ``; sys_platform == "win32"`` (or an equivalent
     ``sys_platform=='win32'`` — quote style-tolerant, whitespace-tolerant).

  2. The immediately-following comment block MUST retain a mention of
     ``pip-compile`` so the maintainer note (why the marker was manually
     added, what regenerates strip it, what to do on next regen) doesn't
     drift away silently.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = REPO_ROOT / "requirements.lock"

# Match ``^pywin32==<version>`` at the start of a line (lock format).
_PYWIN32_RE = re.compile(r"^pywin32==\S+")

# Marker shape tolerance — either quote style, optional space around ==.
_MARKER_RE = re.compile(
    r";\s*sys_platform\s*==\s*[\"']win32[\"']"
)


def _iter_lock_lines() -> list[str]:
    assert LOCKFILE.exists(), f"requirements.lock missing at {LOCKFILE}"
    return LOCKFILE.read_text(encoding="utf-8").splitlines()


def _pywin32_line_indices(lines: list[str]) -> list[int]:
    return [i for i, line in enumerate(lines) if _PYWIN32_RE.match(line)]


def _following_comment_block(lines: list[str], start_idx: int) -> str:
    """Return the concatenated comment lines immediately following
    ``lines[start_idx]`` up to the first non-comment / non-blank line.
    The lock file format is:

        pywin32==312 ; sys_platform == "win32"
            # via mcp
            # Manual environment marker — ...
            # ...
    """
    out: list[str] = []
    for j in range(start_idx + 1, len(lines)):
        stripped = lines[j].lstrip()
        if stripped.startswith("#"):
            out.append(stripped[1:].strip())
        elif stripped == "":
            break
        else:
            break
    return "\n".join(out)


def test_pywin32_lockfile_lines_carry_win32_marker():
    """Rule 1 — every ``^pywin32==`` line in requirements.lock ends with
    the ``; sys_platform == "win32"`` environment marker."""
    lines = _iter_lock_lines()
    indices = _pywin32_line_indices(lines)
    assert indices, (
        "requirements.lock has no `pywin32==` entry. If pywin32 was "
        "removed intentionally, delete this pin file too. Otherwise, "
        "the lockfile regen likely lost the pywin32 dep — investigate "
        "before deleting either."
    )
    missing: list[str] = []
    for i in indices:
        if not _MARKER_RE.search(lines[i]):
            missing.append(f"line {i + 1}: {lines[i]!r}")
    assert not missing, (
        "requirements.lock: pywin32 entry(ies) missing the "
        "`; sys_platform == \"win32\"` marker. pip-compile does NOT "
        "propagate mcp's upstream marker reliably — the marker must be "
        "manually restored after every regen or Linux container installs "
        "will fail (pywin32 is a Windows-only wheel). Missing on:\n  "
        + "\n  ".join(missing)
    )


def test_pywin32_maintainer_note_retains_pip_compile_phrase():
    """Rule 2 — the comment block following each ``^pywin32==`` line must
    retain a mention of ``pip-compile`` so the manual-marker rationale
    doesn't drift out."""
    lines = _iter_lock_lines()
    indices = _pywin32_line_indices(lines)
    drifted: list[str] = []
    for i in indices:
        comment = _following_comment_block(lines, i).lower()
        if "pip-compile" not in comment:
            drifted.append(
                f"line {i + 1} block below: {comment[:200]!r}"
            )
    assert not drifted, (
        "requirements.lock: pywin32 maintainer-note drift — the comment "
        "block following the pywin32 entry must retain the `pip-compile` "
        "mention so a future maintainer understands WHY the marker is "
        "manually restored (and knows to re-restore on every regen). "
        "Comment block(s) with drift:\n  " + "\n  ".join(drifted)
    )
