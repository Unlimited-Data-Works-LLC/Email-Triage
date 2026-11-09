"""The ONE reader of a CI step's requirement file cut from a repo lock (class AJ, fold G3).

A workflow step that installs only the entry the SME gate itself imports (fold F2:
``awk ... requirements-ci-tools.lock > "$RUNNER_TEMP/packaging.req"``) hands pip a file that is not
in the repo. Two pins judge the install lines of a step and both must read that cut back to the
lock it came from: ``test_punch511_ci_installs_are_hash_locked_pin.py`` and
``test_punch512_613_dependency_manifests_on_sme_net_pin.py``. It lives here, not in either pin,
because a pin must not import a pin (PD-6): the second one's scoping would then ride on the
first one's file.
"""

from __future__ import annotations

import re

_DERIVED_REQ_CUT = re.compile(
    r"(?P<src>(?<![\w./-])requirements[\w.-]*\.lock)\s*>\s*[\"']?(?P<out>\$\{?RUNNER_TEMP\}?/[\w.-]+)[\"']?\s*$")


def derived_requirement_sources(run: str) -> dict[str, str]:
    """``$RUNNER_TEMP/x.req`` -> the one repo-root lock a step cuts it from.

    A step that installs ONLY the entry the SME gate itself imports (class AJ, fold F2:
    ``awk ... requirements-ci-tools.lock > "$RUNNER_TEMP/packaging.req"``) hands pip a file that
    is not in the repo. This is the one place that reads such a cut back to its source lock, so
    every install pin judges the lock and not the temp name. Only a line that ends in a redirect
    of a ``requirements*.lock`` into a ``$RUNNER_TEMP`` file counts; a temp file nothing cut from a
    lock stays unknown, and the pins then fail it closed."""
    out: dict[str, str] = {}
    for line in run.replace(chr(92) + chr(10), " ").splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = _DERIVED_REQ_CUT.search(line)
        if m:
            out[m.group("out")] = m.group("src")
    return out
