""" / N-15 seam 1 — FREEZE the two live audit-chain canonical byte forms.

This test is the *refactor guard* for the audit-chain class-fix. The
class-fix generalizes the duplicated HMAC dispatch shared by ``log_entries``
and ``audit_gap_events`` into one ``_apply_chain_hmac`` helper (PD#5/#6). The
single sharpest risk flagged by all three SME/DA reviewers (wf_7af575de-5d8):

    the two LIVE chains use DIFFERENT canonical byte forms today —
      * ``_canonical_log_row``  = pipe-join,    NO NFC normalization
      * ``_canonical_gap_row``  = newline-join, WITH NFC normalization
    a naive unified canonicalizer silently re-canonicalizes 6-year-retained
    history, every old ``row_hash`` fails recompute, and the fail-closed
    verifier dies in prod — the exact shape of the 2026-05-31 incident.

So the generalize refactor MUST extract ONLY the keyed-HMAC dispatch and leave
both canonical byte forms byte-identical. These golden vectors (computed from
the pre-refactor implementation at HEAD c2d31d3) lock that invariant: if a
future change alters either canonical byte form OR the keyed-hash dispatch,
this test fails BEFORE the change can break a deployed chain's verification.

The inputs deliberately carry a DECOMPOSED é (``"e" + U+0301``) so the vectors
also *document* the NFC difference: the log form keeps it decomposed
(``...cafe\xcc\x81...``), the gap form composes it to NFC (``...caf\xc3\xa9...``).
"""
from __future__ import annotations

import hashlib
import hmac
import unicodedata as _ud

from email_triage.db import audit as A

# 'cafe' + COMBINING ACUTE ACCENT (U+0301), i.e. a DECOMPOSED é. NFC would
# fold this to the single precomposed code point U+00E9.
_DECOMP = "café"

# Deterministic 32-byte HMAC subkey installed at version 0 for the digest
# vectors. NOT a real key — a fixed constant so the golden digests are stable.
_TEST_KEY = bytes(range(32))

# Self-guard: if a future editor runs an NFC pass over this file it would fold
# ``_DECOMP`` to the precomposed U+00E9 (len 4), silently changing the test
# INPUT and producing a confusing "impl drifted" failure. Catch that here with
# a clear message: the decomposed form is NFD-stable and 5 code points long.
assert len(_DECOMP) == 5 and _ud.normalize("NFD", _DECOMP) == _DECOMP, (
    "_DECOMP must stay DECOMPOSED ('cafe' + U+0301, 5 code points); a file "
    "NFC-normalization pass corrupted it to the precomposed form."
)

# --- Golden CANONICAL byte forms (the freeze) ------------------------------
# log_entries: pipe-join, NO NFC -> the combining mark survives as e + cc 81.
_LOG_CANON = b'PREV|2026-01-01T00:00:00Z|INFO|lg|cafe\xcc\x81|{"k": 1}'
# audit_gap_events: newline-join, WITH NFC -> e + U+0301 composes to c3 a9.
_GAP_CANON = b"PREV\n2026-01-01T00:00:00Z\nrecord_x\ncaf\xc3\xa9\ndeadbeef\nValueError\nboom"

# --- Golden keyed-HMAC digests (guards the dispatch refactor end-to-end) ----
_LOG_HMAC = "b234860a533185a93e046694252c3a0a559190d71f62bf80f104029a0144b204"
_GAP_HMAC = "6d992b3db8c9e6edb8569cc6490e67ac7538991f42477b88d77e36bc2dc3da01"


def test_log_canonical_byte_form_is_frozen_pipe_join_no_nfc():
    """``_canonical_log_row`` is pipe-joined and does NOT NFC-normalize.

    Locks the byte form so the generalize refactor cannot silently re-hash
    the log_entries chain. The decomposed combining mark surviving proves
    no NFC pass was added.
    """
    out = A._canonical_log_row(
        "PREV", "2026-01-01T00:00:00Z", "INFO", "lg", _DECOMP, '{"k": 1}'
    )
    assert out == _LOG_CANON
    assert b"e\xcc\x81" in out, "log canonical must keep the DECOMPOSED mark (no NFC)"
    assert b"|" in out and b"\n" not in out, "log canonical is pipe-joined"


def test_gap_canonical_byte_form_is_frozen_newline_join_with_nfc():
    """``_canonical_gap_row`` is newline-joined and DOES NFC-normalize.

    Locks the byte form so the generalize refactor cannot silently re-hash
    the audit_gap_events chain. The decomposed mark composing to U+00E9
    proves the NFC pass is intact.
    """
    out = A._canonical_gap_row(
        "PREV", "2026-01-01T00:00:00Z", "record_x", _DECOMP,
        "deadbeef", "ValueError", "boom",
    )
    assert out == _GAP_CANON
    assert b"caf\xc3\xa9" in out, "gap canonical must COMPOSE to NFC (U+00E9)"
    assert b"e\xcc\x81" not in out, "gap canonical must not leave a decomposed mark"


def test_two_live_chains_use_DIFFERENT_byte_forms():
    """The whole reason the refactor must NOT unify canonical forms.

    Same logical é, two different stored byte sequences. A unified
    canonicalizer would converge these and break one chain's history.
    """
    log_c = A._canonical_log_row(
        "P", "T", "L", "g", _DECOMP, "{}"
    )
    gap_c = A._canonical_gap_row("P", "T", "h", _DECOMP, "x", "E", "m")
    # The é is decomposed in the log form, composed in the gap form.
    assert b"e\xcc\x81" in log_c
    assert b"\xc3\xa9" in gap_c
    assert b"\xc3\xa9" not in log_c
    assert b"e\xcc\x81" not in gap_c


def test_log_keyed_hmac_digest_is_frozen():
    """``compute_log_row_hash`` HMAC output is locked under a fixed key.

    Guards the dispatch refactor: if the generalized ``_apply_chain_hmac``
    changes the keyed-hash computation (key lookup, primitive, version
    handling) for the log chain, the digest drifts and this fails.
    """
    A._set_hmac_key_for_test(_TEST_KEY, version=0)
    try:
        digest = A.compute_log_row_hash(
            "PREV", "2026-01-01T00:00:00Z", "INFO", "lg", _DECOMP, '{"k": 1}',
            hash_alg="hmac-sha256-v1", master_key_version=0,
        )
    finally:
        A._clear_hmac_keys_for_test()
    assert digest == _LOG_HMAC
    # Independent cross-check against the frozen canonical bytes.
    assert digest == hmac.new(_TEST_KEY, _LOG_CANON, hashlib.sha256).hexdigest()


def test_gap_keyed_hmac_digest_is_frozen():
    """``compute_gap_row_hash`` HMAC output is locked under a fixed key."""
    A._set_hmac_key_for_test(_TEST_KEY, version=0)
    try:
        digest = A.compute_gap_row_hash(
            "PREV", "2026-01-01T00:00:00Z", "record_x", _DECOMP,
            "deadbeef", "ValueError", "boom",
            hash_alg="hmac-sha256-v1", master_key_version=0,
        )
    finally:
        A._clear_hmac_keys_for_test()
    assert digest == _GAP_HMAC
    assert digest == hmac.new(_TEST_KEY, _GAP_CANON, hashlib.sha256).hexdigest()


# --- N-507 option A: hmac-sha256-v2 (punch ) -----------------------------
# v2 prefixes ``"<hash_alg>\n<master_key_version>\n"`` to the SAME frozen
# canonical bytes, so the stored labels are inside the keyed hash. The canonical
# forms above are untouched; only the dispatch gained a branch. The v1 vectors
# above must stay byte-identical: v1 rows in retained history verify forever.
_V2_BOUND = b"hmac-sha256-v2\n0\n"
_LOG_HMAC_V2 = "0007dc5eb14ea2db6d59bce974eb9ecb6d512359018247cb18e7a4c0f569be95"
_GAP_HMAC_V2 = "e8fc77a53e479e4f4037274868dc0eb5d10c6fe59595579f468339071a024564"


def test_log_keyed_hmac_v2_digest_is_frozen():
    A._set_hmac_key_for_test(_TEST_KEY, version=0)
    try:
        digest = A.compute_log_row_hash(
            "PREV", "2026-01-01T00:00:00Z", "INFO", "lg", _DECOMP, '{"k": 1}',
            hash_alg="hmac-sha256-v2", master_key_version=0,
        )
    finally:
        A._clear_hmac_keys_for_test()
    assert digest == _LOG_HMAC_V2
    assert digest == hmac.new(
        _TEST_KEY, _V2_BOUND + _LOG_CANON, hashlib.sha256,
    ).hexdigest()
    assert digest != _LOG_HMAC  # a v2 row relabelled v1 cannot verify


def test_gap_keyed_hmac_v2_digest_is_frozen():
    A._set_hmac_key_for_test(_TEST_KEY, version=0)
    try:
        digest = A.compute_gap_row_hash(
            "PREV", "2026-01-01T00:00:00Z", "record_x", _DECOMP,
            "deadbeef", "ValueError", "boom",
            hash_alg="hmac-sha256-v2", master_key_version=0,
        )
    finally:
        A._clear_hmac_keys_for_test()
    assert digest == _GAP_HMAC_V2
    assert digest == hmac.new(
        _TEST_KEY, _V2_BOUND + _GAP_CANON, hashlib.sha256,
    ).hexdigest()
    assert digest != _GAP_HMAC
