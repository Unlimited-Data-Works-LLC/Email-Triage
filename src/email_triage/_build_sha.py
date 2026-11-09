"""The BAKED build sha — read from the image's ``/app/VERSION`` file and nothing else.

WHY THIS IS NOT ``app.state.version``
=====================================
``web/app.py:_resolve_version()`` answers a different question: "give the
operator *some* build identifier". It is human-facing, so a short sha or a
release tag is a wanted answer there, and in a dev checkout it falls back to a
``.git`` walk. A machine comparator needs the stricter answer this module gives:
the full commit the IMAGE was built from, or nothing. Until 2026-09-29
``_resolve_version()`` also preferred the ``EMAIL_TRIAGE_VERSION`` / ``GIT_SHA``
env vars; the operator directed that override removed outright (punch 538 /
N-523, punch 547's first entry), so neither reader consults the environment. An
env var is set by whoever starts the container, so a monitor comparing it
against the repository's HEAD would be comparing against an operator-supplied
string rather than against what was built.

``/app/VERSION`` is written into the image by the build itself (``COPY COMMIT
/app/VERSION``, from ``git rev-parse HEAD`` in the build context), so it cannot
be overridden at run time without rebuilding. That is the property a drift
comparator needs, and it is the only source this module reads.

ABSENT BEATS WRONG
==================
:func:`baked_build_sha` returns ``""`` — never a placeholder, never a partial —
unless the file holds a full 40-hex commit sha. A short sha, a release tag, an
unsubstituted ``$Format:%H$`` literal, a ``dev``/``unknown`` sentinel and a
missing file all read as "no answer", which a comparator must treat as UNKNOWN
and must not score as drift. A plausible-but-wrong value can never equal HEAD,
so it would render as permanent false drift: a security fix that looks eternally
un-deployed on a HIPAA-class service.

ONE READER (converged at the punch-539 rebase, 2026-09-30)
==========================================================
Punch 538 (``GET /health/build``) and punch 542 (``GET /health/runtime-deps``)
were built on separate branches, each with its own reader of the baked file.
Two readers of one fact is the mirrored-copy drift PD-5 forbids, so when 539-542
was rebased onto the main that carried 538 they converged HERE (hipaa
``H539-1``, db ``N-539-X1``, da ``DA-C6``, panel 4 2026-09-29):

* :func:`read_baked_version` is the ONLY function that opens
  :data:`BAKED_VERSION_PATH`, and it applies the one placeholder predicate
  (:func:`is_placeholder_build_value`). Both build identifiers derive from it.
* :func:`baked_build_sha` shape-gates that value to a full commit sha. It is the
  machine-read answer; ``create_app`` stores it once as ``app.state.build_sha``
  and BOTH routes serve that one stored value, so they cannot disagree.
* ``web/app.py:_resolve_version()`` (the human-facing ``/health`` ``version``)
  takes the same baked value and falls back to a ``.git`` walk in a dev
  checkout. It is deliberately NOT shape-gated: a short sha or a release tag is
  a wanted answer there.

Pinned by ``tests/test_build_sha_single_reader_pin.py`` (one opener of the baked
path, one ``/app/VERSION`` code literal and one 40-hex regex under
``src/email_triage/``) and by the env/funnel pins in
``tests/test_web/test_health_build_endpoint.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Where the container build stamps the commit it was built from
#: (``Containerfile``: ``COPY COMMIT /app/VERSION``).
BAKED_VERSION_PATH = "/app/VERSION"

#: A full git commit sha and nothing else. The SHAPE assertion, not a sentinel
#: deny-list: enumerating sentinels loses the race by construction, because the
#: next new non-sha value is unguarded again.
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")

#: The two sentinels a non-container build writes into the baked file, and the
#: prefix of an ``export-subst`` placeholder ``git archive`` never substituted.
PLACEHOLDER_BAKED_VALUES = frozenset({"dev", "unknown"})
EXPORT_SUBST_PREFIX = "$Format"


def is_placeholder_build_value(value: str) -> bool:
    """True when a baked build identifier carries no answer at all.

    ONE predicate for every reader of the baked file. It used to be inlined in
    two resolvers, character-for-character the same three-part test, which is
    the R5 shape that drifts: a sentinel added to one and missed in the other
    lets the human-facing ``version`` and the machine-read ``build_sha``
    disagree about which image is running with nothing saying so. (hipaa
    ``H538-5``, da ``DA-A2``, panel 4 2026-09-29.)

    **No environment.** Neither this predicate nor any reader that calls it
    reads an environment variable (operator directive 2026-09-29, punch 547's
    first entry).
    """
    return (
        not value
        or value in PLACEHOLDER_BAKED_VALUES
        or value.startswith(EXPORT_SUBST_PREFIX)
    )


def read_baked_version(path: str | Path | None = None) -> str:
    """The stripped contents of the baked file, or ``""`` for no answer.

    The ONLY function that opens :data:`BAKED_VERSION_PATH`. ``path`` exists so
    a test can point at a fixture file; production callers pass nothing.
    A missing or unreadable file (``OSError``), a file that is not UTF-8
    (``UnicodeDecodeError``) and a placeholder value all read as ``""``, so no
    caller ever sees a sentinel. This is the raw build identifier: callers that
    need a commit sha use :func:`baked_build_sha`, which shape-gates it.

    Uses the builtin ``open`` (not ``Path.read_text``) so the ``/health``
    version tests can steer it by patching ``builtins.open``.
    """
    target = BAKED_VERSION_PATH if path is None else path
    try:
        with open(target, encoding="utf-8") as f:
            raw = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return "" if is_placeholder_build_value(raw) else raw


def baked_build_sha(path: str | Path | None = None) -> str:
    """The commit sha baked into the image, or ``""`` when there is no answer.

    Reads ONLY the file at ``path`` (default :data:`BAKED_VERSION_PATH`). No
    environment variable is consulted, by design — see the module docstring.
    ``path`` is a parameter so a test can point at a fixture file; production
    callers pass nothing.

    Fail-closed in the "absent beats wrong" direction: any read error, and any
    content that is not a full 40-hex sha, yields ``""``.
    """
    raw = read_baked_version(path)
    return raw if FULL_SHA_RE.fullmatch(raw) else ""
