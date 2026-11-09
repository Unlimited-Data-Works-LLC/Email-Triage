"""N-74 per-account HIPAA reason-redaction in engine/store.py.

Fix verified: engine/store._cls_to_json now accepts an `account_hipaa`
parameter and gates redaction on EITHER is_hipaa_mode() OR account_hipaa
(fail-closed — most-restrictive wins). The redact_reason SSOT makes this
a single code path.

The previous gate checked only is_hipaa_mode() (install-wide), so a
per-account-HIPAA mailbox on a non-HIPAA install wrote cleartext PHI to
flows.classification_json.

Behavioural contracts:
  * Per-account HIPAA ON + global mode OFF → reason="" (redacted).
  * Per-account HIPAA OFF + global mode OFF → reason preserved.
  * Per-account HIPAA OFF + global mode ON → reason="" (redacted).
  * Per-account HIPAA ON + global mode ON → reason="" (redacted).

Structural (count-agnostic) pin:
  * Every call to _cls_to_json in engine/store.py routes through the
    redact_reason SSOT (no raw ``cls.reason`` bypass).
  * The redact_reason helper exists at module scope in engine/store.py.
"""

from __future__ import annotations

import ast
import json
import sqlite3

import pytest

from _pin_harness import SRC_ROOT as SRC, parse_module  # census run13 #4 + N-350 R31
STORE_PY = SRC / "engine" / "store.py"


# ---------------------------------------------------------------------------
# Structural pin
# ---------------------------------------------------------------------------

def test_redact_reason_ssot_exists():
    """redact_reason must be defined at module scope in engine/store.py."""
    tree = parse_module(STORE_PY); assert tree is not None  # N-350 R31
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "redact_reason" in names, (
        "redact_reason SSOT vanished from engine/store.py — "
        "the per-account HIPAA redaction gate has no single authority"
    )


def test_cls_to_json_uses_redact_reason():
    """_cls_to_json must call redact_reason (the SSOT) — not the old
    inline is_hipaa_mode() pattern."""
    tree = parse_module(STORE_PY); assert tree is not None  # N-350 R31
    # Find the _cls_to_json function
    fn_node = None
    for n in ast.walk(tree):
        if (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "_cls_to_json"
        ):
            fn_node = n
            break
    assert fn_node is not None, "_cls_to_json not found in engine/store.py"

    names_used: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            names_used.add(n.id)
        elif isinstance(n, ast.Attribute):
            names_used.add(n.attr)
    assert "redact_reason" in names_used, (
        "_cls_to_json does not call redact_reason — the per-account HIPAA "
        "redaction gate is not wired through the SSOT"
    )


def test_capture_baseline_passes_account_hipaa():
    """_capture_baseline must pass account_hipaa= to _cls_to_json."""
    text = STORE_PY.read_text(encoding="utf-8")
    # The kwarg must appear in the source — check textually as a quick guard.
    assert "account_hipaa=account_hipaa" in text, (
        "_capture_baseline does not pass account_hipaa= to _cls_to_json — "
        "the per-account HIPAA flag never reaches the redaction gate"
    )


def test_cls_reason_only_appears_as_redact_reason_arg():
    """In _cls_to_json, cls.reason must only appear as an argument to
    redact_reason — NOT as a direct value in the output dict.

    The check: the json.dumps dict literal must NOT have 'reason': cls.reason
    as a key-value pair; it must use the local variable returned by
    redact_reason (or some name other than the raw cls.reason attribute).
    Concretely: redact_reason(cls.reason, account_hipaa=...) is correct usage;
    'reason': cls.reason in the final dict would be a bypass.
    """
    tree = parse_module(STORE_PY); assert tree is not None  # N-350 R31
    fn_node = None
    for n in ast.walk(tree):
        if (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "_cls_to_json"
        ):
            fn_node = n
            break
    assert fn_node is not None

    # Look for json.dumps({..., "reason": cls.reason, ...}) — the dict passed
    # to json.dumps should NOT have cls.reason as a direct value.
    for call in ast.walk(fn_node):
        if not isinstance(call, ast.Call):
            continue
        # Match json.dumps(...)
        func = call.func
        if not (
            (isinstance(func, ast.Attribute) and func.attr == "dumps")
            or (isinstance(func, ast.Name) and func.id == "dumps")
        ):
            continue
        if not call.args:
            continue
        dict_arg = call.args[0]
        if not isinstance(dict_arg, ast.Dict):
            continue
        # Inspect key-value pairs in the dict
        for key, val in zip(dict_arg.keys, dict_arg.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "reason"
                and isinstance(val, ast.Attribute)
                and val.attr == "reason"
                and isinstance(val.value, ast.Name)
                and val.value.id == "cls"
            ):
                pytest.fail(
                    f"_cls_to_json passes cls.reason directly as the 'reason' "
                    f"value in json.dumps dict at line {call.lineno} — must "
                    "route through redact_reason(cls.reason, account_hipaa=...)"
                )


# ---------------------------------------------------------------------------
# Behavioural tests — _cls_to_json / redact_reason
# ---------------------------------------------------------------------------

from email_triage.engine.models import Classification


def _make_cls(reason: str = "patient MRN 12345") -> Classification:
    return Classification(
        category="medical",
        confidence=0.9,
        reason=reason,
        source="llm",
    )


def test_account_hipaa_on_global_off_redacts():
    """Per-account HIPAA ON + global mode OFF → reason=""."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False  # global OFF
        from email_triage.engine.store import _cls_to_json
        cls = _make_cls("patient MRN 12345")
        result = json.loads(_cls_to_json(cls, account_hipaa=True))
        assert result["reason"] == "", (
            f"Per-account HIPAA ON should redact reason, got: {result['reason']!r}"
        )
    finally:
        _tl._hipaa_mode = orig


def test_account_hipaa_off_global_off_preserves():
    """Per-account HIPAA OFF + global mode OFF → reason preserved."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False
        from email_triage.engine.store import _cls_to_json
        cls = _make_cls("the subject line was about work")
        result = json.loads(_cls_to_json(cls, account_hipaa=False))
        assert result["reason"] == "the subject line was about work", (
            f"Non-HIPAA should preserve reason, got: {result['reason']!r}"
        )
    finally:
        _tl._hipaa_mode = orig


def test_account_hipaa_off_global_on_redacts():
    """Per-account HIPAA OFF + global mode ON → reason="" (global wins)."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = True  # global ON
        from email_triage.engine.store import _cls_to_json
        cls = _make_cls("patient chart #9876")
        result = json.loads(_cls_to_json(cls, account_hipaa=False))
        assert result["reason"] == "", (
            f"Global HIPAA ON should redact reason even with account_hipaa=False, "
            f"got: {result['reason']!r}"
        )
    finally:
        _tl._hipaa_mode = orig


def test_both_on_redacts():
    """Both flags ON → reason=""."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = True
        from email_triage.engine.store import _cls_to_json
        cls = _make_cls("PHI content here")
        result = json.loads(_cls_to_json(cls, account_hipaa=True))
        assert result["reason"] == ""
    finally:
        _tl._hipaa_mode = orig


def test_none_classification_returns_none():
    """_cls_to_json(None) returns None (no regression from adding account_hipaa)."""
    from email_triage.engine.store import _cls_to_json
    assert _cls_to_json(None) is None
    assert _cls_to_json(None, account_hipaa=True) is None


def test_state_bag_account_hipaa_flows_through_capture_baseline():
    """A FlowState with state_bag['account_hipaa']=True causes _capture_baseline
    to produce a redacted classification_json."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False  # global OFF — per-account must carry it
        from email_triage.engine.models import FlowState, FlowStatus
        from email_triage.engine.store import _capture_baseline

        cls = _make_cls("PHI free-text reason")
        flow = FlowState(
            flow_id="test-flow-id",
            message_id="msg-1",
            provider="imap",
            status=FlowStatus.CLASSIFIED,
            classification=cls,
            state_bag={"account_hipaa": True},
        )
        baseline = _capture_baseline(flow)
        parsed = json.loads(baseline["classification_json"])
        assert parsed["reason"] == "", (
            f"state_bag['account_hipaa']=True should redact reason, got: "
            f"{parsed['reason']!r}"
        )
    finally:
        _tl._hipaa_mode = orig


def test_state_bag_no_account_hipaa_preserves_reason():
    """A FlowState without state_bag['account_hipaa'] preserves reason
    when global mode is off."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False
        from email_triage.engine.models import FlowState, FlowStatus
        from email_triage.engine.store import _capture_baseline

        cls = _make_cls("sender matched work rule")
        flow = FlowState(
            flow_id="test-flow-id-2",
            message_id="msg-2",
            provider="imap",
            status=FlowStatus.CLASSIFIED,
            classification=cls,
            state_bag={},
        )
        baseline = _capture_baseline(flow)
        parsed = json.loads(baseline["classification_json"])
        assert parsed["reason"] == "sender matched work rule", (
            f"No HIPAA flags → reason should be preserved, got: {parsed['reason']!r}"
        )
    finally:
        _tl._hipaa_mode = orig
