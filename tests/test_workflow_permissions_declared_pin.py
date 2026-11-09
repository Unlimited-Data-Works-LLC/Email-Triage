"""Every workflow must declare its own `permissions:` block.

A workflow with no `permissions:` block inherits whatever the REPOSITORY-WIDE
default happens to be. That default is a single setting an admin can flip in the
UI, and `ci-green-ref.yml` needs it raised to write in order to publish its
marker branch (`GITHUB_TOKEN` currently gets
`403 {"message":"Resource not accessible by integration"}` on create-a-reference
because the repo default is read-only).

The moment that setting is raised, every undeclared workflow silently gains
write access to the repository contents — including the test, e2e, and gate
workflows that execute repo code and have no business writing anything. That is
a privilege escalation nobody reviews, arriving as a side effect of an unrelated
change.

This pin makes the escalation impossible rather than unlikely: it is
count-agnostic (it walks every workflow file, so a NEW workflow is covered the
day it lands) and it does not care what the repo default is. Each workflow
states its own needs; the repo default becomes a ceiling rather than a grant.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"

# Top-level `permissions:` — column 0, not the job-level one nested under a job.
_TOP_LEVEL_PERMISSIONS = re.compile(r"^permissions:\s*$", re.MULTILINE)


def _workflows() -> list[Path]:
    files = sorted(p for p in _WORKFLOW_DIR.glob("*.yml"))
    assert files, f"no workflows found under {_WORKFLOW_DIR}"
    return files


def test_every_workflow_declares_permissions():
    missing = [
        p.name
        for p in _workflows()
        if not _TOP_LEVEL_PERMISSIONS.search(p.read_text(encoding="utf-8"))
    ]
    assert not missing, (
        "these workflows would inherit the repository-wide default token "
        "permissions, so raising that default silently grants them write "
        f"access: {', '.join(missing)}. Add a top-level `permissions:` block "
        "declaring what each one actually needs (usually `contents: read`)."
    )


def test_only_the_marker_workflow_asks_for_contents_write():
    """Write access is a reviewable exception, not a default.

    If a second workflow legitimately needs to write, adding it here is a
    deliberate edit that shows up in review — which is the point.
    """
    allowed = {
        # Publishes the `ci-green` marker branch — the whole point of it.
        "ci-green-ref.yml",
        # Release: creates the GitHub Release (alongside packages/id-token/
        # attestations write for GHCR push and SLSA-3 provenance).
        "release.yml",
        # Operator-attest: updates the GitHub Release body with the operator
        # attestation note (`gh release view/edit`).
        "operator-attest.yml",
    }
    writers = {
        p.name
        for p in _workflows()
        if re.search(r"^\s+contents:\s*write\s*(#.*)?$", p.read_text(encoding="utf-8"), re.MULTILINE)
    }
    assert writers <= allowed, (
        f"unexpected workflow(s) requesting contents: write: {sorted(writers - allowed)}"
    )
