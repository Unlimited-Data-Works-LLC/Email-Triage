"""N-326-C5 R31 — CODEOWNERS coverage nag-pin for the trust root.

SME-panel DA fold #8. Post-land operator action per
`internal documentation` — CODEOWNERS entry covering
`.github/op-approve/**` (the trust-root pubkey mirror + `pending/`
artifact dir) AND `tests/goldens/**` (the golden-hash file for the
byte-integrity pin) so a PR-based swap requires an operator-side
review that the model cannot bypass. Without CODEOWNERS, direct-push
to `feat/v0.2.0` would sidestep the operator-only review requirement.

Landed 2026-07-09 (`.github/CODEOWNERS` — this repo). The nag-pin's
xfail markers were REMOVED in the SAME commit as the CODEOWNERS file
per the "flip to XPASS on land + remove xfail marker" note in the
original C5 landing docstring. The two tests now enforce the CODEOWNERS
coupling as a positive invariant — any PR that deletes the coverage
lines will red the pin.
"""
from __future__ import annotations

from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]

_CODEOWNERS_CANDIDATES = (
    _REPO_ROOT / "CODEOWNERS",
    _REPO_ROOT / ".github" / "CODEOWNERS",
    _REPO_ROOT / "docs" / "CODEOWNERS",
)


def _read_codeowners() -> str | None:
    for p in _CODEOWNERS_CANDIDATES:
        if p.exists():
            return p.read_text(encoding="utf-8")
    return None


def test_codeowners_covers_trust_root_directory():
    body = _read_codeowners()
    assert body is not None, (
        "No CODEOWNERS file at any of: "
        + ", ".join(str(p) for p in _CODEOWNERS_CANDIDATES)
    )
    # Any line that names `.github/op-approve/` — permissive on wildcard shape.
    assert any(
        ".github/op-approve/" in line and not line.lstrip().startswith("#")
        for line in body.splitlines()
    ), (
        "CODEOWNERS present but does not cover `.github/op-approve/**` — the "
        "trust-root directory needs an operator-review gate. Add a line "
        "like `.github/op-approve/** @C-Doe`."
    )


def test_codeowners_covers_goldens_directory():
    body = _read_codeowners()
    assert body is not None
    assert any(
        "tests/goldens/" in line and not line.lstrip().startswith("#")
        for line in body.splitlines()
    ), (
        "CODEOWNERS present but does not cover `tests/goldens/**` — the "
        "golden-hash file needs an operator-review gate coupled to the "
        "trust-root file."
    )
