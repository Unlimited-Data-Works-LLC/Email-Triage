"""N-326-C5 R31 — trust-root SSOT pin (byte-equality + golden-hash + rglob).

Three-legged coverage:

  1. `.github/op-approve/allowed_signers` MUST match the checked-in
     `tests/goldens/allowed_signers.sha256` — SME-panel DA fold #3.
     Runs on CI + operator machine.  A malicious PR that swaps the
     trust-root file must also swap the golden hash file (two files,
     one CODEOWNERS-covered directory) — CODEOWNERS + this pin form
     the joint gate.

  2. `~/.the AI assistant/allowed_signers` (session-local, operator machine
     only) MUST be byte-equal to the repo copy.  Skipped on CI.
     Original DA fold R2.

  3. ANY additional `allowed_signers` file discovered under the repo
     via `rglob` MUST be byte-equal to the canonical repo copy —
     SME-panel db-sme fold #1.  Catches a future third mirror
     (e.g., someone adds `deploy/op-approve/allowed_signers` for a
     container bake).  Three-forks-with-drift is worse than one.

Rotation procedure (see `internal documentation`):

  1. New FIDO2-sk key on a fresh (or same) YubiKey.
  2. Update `~/.the AI assistant/allowed_signers` on the operator's machine.
  3. Update `.github/op-approve/allowed_signers` AND regenerate
     `tests/goldens/allowed_signers.sha256`.
  4. Any additional mirrors (rglob-discovered) update in the same
     commit.
  5. Commit with the panel-authored `SME-Reviewed: GO` trailer.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_TRUST_ROOT = _REPO_ROOT / ".github" / "op-approve" / "allowed_signers"
_GOLDEN_HASH_PATH = _REPO_ROOT / "tests" / "goldens" / "allowed_signers.sha256"

_HOME = Path(os.environ.get("USERPROFILE") or os.path.expanduser("~"))
_SESSION_TRUST_ROOT = _HOME / ".the AI assistant" / "allowed_signers"


def test_repo_trust_root_exists_and_nonempty():
    """Checked-in trust root must exist + be non-empty + carry the FIDO2-sk marker."""
    assert _REPO_TRUST_ROOT.exists(), (
        f"Repo trust root missing at {_REPO_TRUST_ROOT}.  CI-side verify "
        "cannot run without it — sme-gate.yml would fail-CLOSED on every "
        "OP-SKIP commit."
    )
    data = _REPO_TRUST_ROOT.read_bytes()
    assert data, "Repo trust root is empty."
    assert b"op-approval@bob" in data, (
        "Repo trust root missing identity `op-approval@bob`."
    )
    assert b"sk-ssh-ed25519@openssh.com" in data, (
        "Repo trust root missing FIDO2-sk ed25519 algorithm marker."
    )


def test_repo_trust_root_matches_golden_hash():
    """SME-panel DA fold #3: CI-leg trust-root byte-integrity via golden hash.

    Runs on CI where `~/.the AI assistant/allowed_signers` is absent.  An attacker's PR
    that swaps `.github/op-approve/allowed_signers` to a forger-controlled
    pubkey MUST also swap `tests/goldens/allowed_signers.sha256` — CODEOWNERS
    on `.github/op-approve/**` + this pin + CODEOWNERS on `tests/goldens/**`
    form the joint gate (operator to add both to CODEOWNERS post-land).

    THIRD LEG — `.gitattributes text eol=lf` on BOTH files (see
    `.gitattributes` for the LF pin + comment).  Without it, a well-meaning
    rotator on a Windows checkout would compute the golden against CRLF
    bytes, ship the wrong hash, and CI (Linux, LF) would fail with a false-
    positive DRIFT.  DA-panel fix-forward on `1e720601` — same drift class
    as the pre-existing `scripts/embedding-bits-manifest.json` precedent.
    """
    assert _GOLDEN_HASH_PATH.exists(), (
        f"Golden hash missing at {_GOLDEN_HASH_PATH} — regenerate via "
        "`sha256sum .github/op-approve/allowed_signers | awk '{print $1}' > "
        "tests/goldens/allowed_signers.sha256`."
    )
    golden = _GOLDEN_HASH_PATH.read_text(encoding="utf-8").strip()
    actual = hashlib.sha256(_REPO_TRUST_ROOT.read_bytes()).hexdigest()
    assert golden == actual, (
        "DRIFT: repo trust root hash does not match golden.\n"
        f"  golden: {golden}\n"
        f"  actual: {actual}\n"
        "If this is a legitimate rotation, regenerate the golden file in the "
        "SAME commit as the trust-root update (see rotation procedure in "
        "internal documentation)."
    )


def test_session_and_repo_trust_roots_byte_equal():
    """Operator-machine-only: session-local == repo copy (byte-equal)."""
    if not _SESSION_TRUST_ROOT.exists():
        pytest.skip(
            f"Session-local trust root absent at {_SESSION_TRUST_ROOT} — "
            "operator-workstation-only test.  CI uses the checked-in copy "
            "via the golden-hash pin above."
        )
    repo_bytes = _REPO_TRUST_ROOT.read_bytes()
    session_bytes = _SESSION_TRUST_ROOT.read_bytes()
    assert repo_bytes == session_bytes, (
        "DRIFT: repo trust root and session-local trust root are NOT "
        "byte-equal.  Rotate BOTH in the same commit (see rotation "
        "procedure in internal documentation)."
    )


def test_no_undeclared_allowed_signers_mirror_drifts():
    """SME-panel db-sme fold #1: any additional in-repo `allowed_signers`
    mirror MUST be byte-equal to the canonical `.github/op-approve/` copy.

    Catches a future third mirror (e.g., `deploy/op-approve/allowed_signers`,
    `packaging/allowed_signers`).  Prime Directive #5 — collapse duplicated
    predicate lists into one SSOT; this pin enforces it structurally.
    """
    canonical = _REPO_TRUST_ROOT.read_bytes()
    drifted: list[str] = []
    for candidate in _REPO_ROOT.rglob("allowed_signers"):
        # Skip the canonical location itself, the goldens dir hash file, and
        # anything under __pycache__ / node_modules / .git.
        parts_lower = [p.lower() for p in candidate.parts]
        if any(x in parts_lower for x in ("__pycache__", "node_modules", ".git")):
            continue
        if candidate.resolve() == _REPO_TRUST_ROOT.resolve():
            continue
        if candidate.read_bytes() != canonical:
            drifted.append(str(candidate.relative_to(_REPO_ROOT)))
    assert not drifted, (
        "DRIFT: additional in-repo `allowed_signers` mirror(s) do not match "
        "the canonical `.github/op-approve/allowed_signers`:\n  "
        + "\n  ".join(drifted)
        + "\n\nCollapse to the SSOT or regenerate the mirror in the same "
        "commit as the canonical."
    )
