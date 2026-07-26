"""N-326-C5 R31 — server-side OP-SKIP forgery-rejection red test.

Trust-repair #333b close.  Asserts the CI-side gate REJECTS every shape
of forged `SME-Reviewed: OPERATOR-APPROVED-SKIP` trailer that the model
could produce.  A model can write any string to a commit body; it
CANNOT produce a `ssh-keygen -Y verify`-valid signature against the
operator's YubiKey.

Each test builds a synthetic commit message + calls
``_op_approval_server.verify_op_skip_trailer`` directly.  If any
returns True, the gate is broken.

Sibling of the healthy path — the operator's actual-signed OP-SKIP
verify is tested via manual integration + a smoke test at the client
`emit_op_approval_trailer.py` script.  This file focuses on
adversarial rejection.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "hooks"))
from _op_approval_server import verify_op_skip_trailer  # noqa: E402


_FAKE_SHA = "0" * 40
_FAKE_PATHS = ["src/email_triage/example.py"]
_FAKE_TREE = "a" * 40  # not the actual tree — verify rejects since git rev-parse fails


def _msg_body(*, verb: str = "sme-skip", tree: str = _FAKE_TREE,
              paths: str = "src/email_triage/example.py",
              issued: int = 1783000000, expiry: int = 1793000000,
              nonce: str = "0" * 32, target: str = "N-333b",
              omit: str | None = None) -> bytes:
    fields = [
        ("verb", verb), ("target", target), ("tree", tree),
        ("paths", paths), ("issued", str(issued)),
        ("expiry", str(expiry)), ("nonce", nonce),
    ]
    lines = [f"{k}={v}" for k, v in fields if k != omit]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _make_msg_with_trailer(trailer_line: str) -> str:
    return (
        "feat(example): example commit that touches a risk surface\n"
        "\n"
        "Body of the commit — some rationale.\n"
        "\n"
        f"SME-Reviewed: OPERATOR-APPROVED-SKIP (rationale, 2026-07-08)\n"
        f"{trailer_line}\n"
    )


def _trailer_from(msg_body: bytes, sig: bytes = b"any-sig-bytes") -> str:
    blob = msg_body + b"\x00" + sig
    return "SME-Approval-Proof: " + base64.b64encode(blob).decode()


def test_op_skip_without_proof_trailer_is_rejected():
    msg = (
        "feat(example): commit\n\nBody\n\n"
        "SME-Reviewed: OPERATOR-APPROVED-SKIP (I said so)\n"
    )
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok, "Server-side gate accepted OP-SKIP without a proof trailer."
    assert "SME-Approval-Proof" in reason


def test_op_skip_with_garbage_base64_proof_is_rejected():
    msg = _make_msg_with_trailer("SME-Approval-Proof: not-base64-!!!")
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "base64" in reason.lower() or "SME-Approval-Proof" in reason


def test_op_skip_with_random_base64_bytes_is_rejected():
    blob = b"random data no separator"
    trailer = "SME-Approval-Proof: " + base64.b64encode(blob).decode()
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "NUL" in reason or "separator" in reason.lower()


def test_op_skip_with_wellformed_msg_but_forged_sig_is_rejected():
    """Well-formed message + fabricated signature bytes MUST fail verify.

    The forged sig is 64 random bytes.  Either ssh-keygen rejects the
    sig envelope, or tree/paths mismatch fires first — any is fail-CLOSED.
    """
    trailer = _trailer_from(_msg_body(), sig=b"X" * 64)
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok, (
        "Server-side gate accepted a forged signature — this is the exact "
        "forgery vector #333b existed to close."
    )
    assert (
        "ssh-keygen" in reason.lower()
        or "signature" in reason.lower()
        or "paths mismatch" in reason.lower()
        or "tree" in reason.lower()
    )


def test_op_skip_paths_mismatch_is_rejected():
    trailer = _trailer_from(_msg_body(paths="some/OTHER/path.py"))
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "paths" in reason.lower() or "tree" in reason.lower()


def test_op_skip_tree_mismatch_is_rejected():
    """N-326-C5 SME-panel DA fold #1: reject when signed tree ≠ commit tree.

    Kills the content-substitution replay class where the model waits for a
    legit signed trailer on paths P, then within TTL writes malicious content
    to the same P and pastes the same trailer verbatim.  `_FAKE_SHA` cannot
    be `git rev-parse`d in the test repo — verifier fails at the tree step.
    """
    trailer = _trailer_from(_msg_body(tree="b" * 40))
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "tree" in reason.lower() or "rev-parse" in reason.lower()


def test_op_skip_expired_proof_is_rejected():
    trailer = _trailer_from(_msg_body(issued=1000000000, expiry=1000000001))
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "expired" in reason.lower() or "tree" in reason.lower()


def test_op_skip_wrong_verb_is_rejected():
    trailer = _trailer_from(_msg_body(verb="push-public"))
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "verb" in reason.lower()


def test_op_skip_missing_required_field_is_rejected():
    """Missing any of {verb, target, tree, paths, issued, expiry, nonce} → reject."""
    trailer = _trailer_from(_msg_body(omit="paths"))
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert (
        "missing" in reason.lower()
        or "paths" in reason.lower()
        or "field-set" in reason.lower()
        or "mismatch" in reason.lower()
    )


def test_op_skip_field_order_mismatch_is_rejected():
    """N-326-C5 SME-panel DA fold #5: canonical field-order is part of the SSOT.

    A trailer whose canonical message reorders fields (e.g., `paths=` before
    `tree=`) MUST be rejected — the SSOT parse asserts exact field-order match.
    Prevents silent drift between signer and verifier canonicalization.
    """
    msg_bytes = (
        b"verb=sme-skip\n"
        b"target=N-333b\n"
        b"paths=src/email_triage/example.py\n"  # WRONG ORDER: paths before tree
        b"tree=" + (_FAKE_TREE.encode()) + b"\n"
        b"issued=1783000000\n"
        b"expiry=1793000000\n"
        b"nonce=" + (b"0" * 32) + b"\n"
    )
    trailer = _trailer_from(msg_bytes)
    msg = _make_msg_with_trailer(trailer)
    ok, reason = verify_op_skip_trailer(msg, _FAKE_SHA, _FAKE_PATHS)
    assert not ok
    assert "field-set" in reason.lower() or "mismatch" in reason.lower() or "order" in reason.lower()
