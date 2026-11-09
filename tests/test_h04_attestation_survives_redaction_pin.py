"""Panel 547 hipaa F1 — the H-04 Transmission Security attestation row survives
HIPAA-mode redaction, key by key.

The row exists to put the declared §164.312(e) posture on the HMAC-chained
``log_entries`` record (§164.316(b)(2)). Under HIPAA mode both log legs apply the
fail-closed allow-list ``redact_persisted_extra`` (the console leg since punch
547). A kwarg of that call that is not allow-listed is stored as ``[redacted]``,
which silently erases the evidence the row was written for. Until punch 547 all
six of its kwargs were being erased in ``log_entries``; HIPAA-mode rows written
before this change carry ``[redacted]`` values and cannot be recovered.

Count-agnostic: the kwargs are DERIVED from every ``log.<level>("H-04-flag...")``
call in ``web/transmission_security.py``, never listed here, so a key added to
that call later fails this pin until it is allow-listed (or deliberately
omitted from the row).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, assert_pin_has_teeth, parse_module
from email_triage.triage_logging import redact_persisted_extra

_LEVELS = {"debug", "info", "warning", "error", "critical"}


def _h04_kwargs(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _LEVELS and node.args
                and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).startswith("H-04-flag")):
            out += [k.arg for k in node.keywords if k.arg]
    return out


def _erased(tree: ast.AST) -> list[str]:
    keys = _h04_kwargs(tree)
    kept = redact_persisted_extra({k: "v" for k in keys}, hipaa=True)
    return [k for k in keys if kept.get(k) != "v"]


def test_every_h04_attestation_kwarg_survives_hipaa_redaction():
    tree = parse_module(SRC_ROOT / "web" / "transmission_security.py")
    assert tree is not None
    keys = _h04_kwargs(tree)
    assert len(keys) >= 6, f"the H-04 attestation call was not found: {keys}"
    assert _erased(tree) == [], (
        "H-04 attestation kwargs that HIPAA-mode redaction erases — add them to "
        "triage_logging._PERSIST_SAFE_KEYS (they are config, not content)"
    )


def test_pin_has_teeth():
    assert_pin_has_teeth(
        _erased,
        'log.info("H-04-flag: x", tls_enabled=True, free_text_reason="r")\n',
        'log.info("H-04-flag: x", tls_enabled=True)\n',
    )
