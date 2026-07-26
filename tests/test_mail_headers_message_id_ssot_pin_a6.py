"""A6 (divergence census 2026-06-09) — RFC Message-ID extraction SSOT pin.

Providers emit the RFC-5322 header in inconsistent casing: Gmail
``Message-ID``, IMAP-parsed ``Message-Id``, some lowercase ``message-id``.
The census found 4 hand-rolled extractors each checking a DIFFERENT subset
of casings — most consequentially ``SentMailIndex`` (checked only
``Message-ID``/``message-id``, missing ``Message-Id``, with no provider-id
fallback → an IMAP-cased sent message resolved to "" → dedup skipped → a
duplicate row on every re-scan).

The single casing authority is ``mail_headers.get_rfc_message_id`` (header
level) / ``get_message_rfc_id`` (message level, with provider fallback).

This **count-agnostic** pin asserts the STRUCTURAL invariant: no module
under ``src/email_triage`` extracts the Message-ID header by hand — i.e.
no ``<x>.get("Message-Id"...)`` / ``<x>["message-id"]`` read of the header
literal anywhere except the SSOT module itself. New code that re-rolls a
casing subset fails here regardless of how many sites exist.
"""

from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

# The one module allowed to name the header literal (it IS the authority).
_ALLOWED = {"mail_headers.py"}


def _is_message_id_literal(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.strip().lower() == "message-id"
    )


def _calls_get_rfc_message_id(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "get_rfc_message_id")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "get_rfc_message_id")
        )
    )


def _refs_provider_message_id(node: ast.AST) -> bool:
    # ``x.message_id`` attribute or a bare ``message_id`` name.
    if isinstance(node, ast.Attribute) and node.attr == "message_id":
        return True
    return isinstance(node, ast.Name) and node.id == "message_id"


def _is_manual_message_level_shape(node: ast.AST) -> bool:
    """True for the hand-rolled message-level shape
    ``get_rfc_message_id(...) or <x>.message_id`` — the exact pattern
    ``mail_headers.get_message_rfc_id`` now owns. Intentional header-ONLY
    sites (``get_rfc_message_id(headers)`` with NO ``or message_id`` — the
    / durable idempotency keys) are NOT this shape and pass."""
    if not (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or)):
        return False
    has_call = any(_calls_get_rfc_message_id(v) for v in node.values)
    has_provider_id = any(_refs_provider_message_id(v) for v in node.values)
    return has_call and has_provider_id


def _find_violations() -> list[str]:
    violations: list[str] = []
    for path in iter_src_files():
        if path.name in _ALLOWED:
            continue
        tree = parse_module(path)
        if tree is None:  # pragma: no cover
            continue
        rel = relpath(path)
        for node in ast.walk(tree):
            # x.get("Message-Id" [, default])
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and _is_message_id_literal(node.args[0])
            ):
                violations.append(f"{rel}:{node.lineno} (.get of Message-ID header)")
            # x["Message-Id"]  (subscript READ of the header literal)
            elif (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Load)
                and _is_message_id_literal(node.slice)
            ):
                violations.append(f"{rel}:{node.lineno} (subscript read of Message-ID header)")
            # get_rfc_message_id(...) or <x>.message_id  (manual msg-level shape)
            elif _is_manual_message_level_shape(node):
                violations.append(
                    f"{rel}:{node.lineno} (manual `get_rfc_message_id(...) or "
                    f"x.message_id` — use get_message_rfc_id(message))"
                )
    return violations


def test_no_hand_rolled_message_id_header_extraction():
    """Every Message-ID header read must go through the
    ``mail_headers`` SSOT (``get_rfc_message_id`` / ``get_message_rfc_id``).

    A hit means a site re-rolled the casing subset — the exact A6
    divergence that lets one provider's casing slip through and break
    dedup. Replace the inline read with the SSOT call.
    """
    violations = _find_violations()
    assert violations == [], (
        "Hand-rolled Message-ID header extraction (A6 divergence) at:\n  "
        + "\n  ".join(violations)
        + "\nUse mail_headers.get_message_rfc_id(message) (message level) or "
        "get_rfc_message_id(headers) (header level) — the single casing "
        "authority."
    )


def test_pin_has_teeth(tmp_path):
    """A planted hand-rolled extraction MUST be detected."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "def f(h):\n    return h.get('Message-Id') or h['message-id']\n",
        encoding="utf-8",
    )
    tree = parse_module(planted); assert tree is not None
    hits = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and _is_message_id_literal(node.args[0])
        ):
            hits.append(node.lineno)
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and _is_message_id_literal(node.slice)
        ):
            hits.append(node.lineno)
    assert len(hits) >= 2, "pin matcher failed to flag a planted extraction"


def test_pin_flags_manual_message_level_shape():
    """The widened pin catches the SSOT's own call-shape
    ``get_rfc_message_id(...) or x.message_id`` (SME DA-#3); but a
    deliberate header-ONLY ``get_rfc_message_id(headers)`` (the durable
    idempotency keys) is NOT flagged."""
    flagged = ast.parse(
        "def f(m):\n    return get_rfc_message_id(m.headers) or m.message_id\n"
    )
    assert any(
        _is_manual_message_level_shape(n) for n in ast.walk(flagged)
    ), "widened pin missed the manual message-level shape"

    header_only = ast.parse(
        "def f(m):\n    return get_rfc_message_id(getattr(m, 'headers', {}) or {})\n"
    )
    assert not any(
        _is_manual_message_level_shape(n) for n in ast.walk(header_only)
    ), "header-only idempotency-key shape must NOT be flagged"


def test_message_level_ssot_casing_and_fallback():
    """The SSOT resolves every header casing + the provider-id fallback."""
    from email_triage.mail_headers import get_message_rfc_id, get_rfc_message_id

    # Header-level authority covers all three casings.
    assert get_rfc_message_id({"Message-ID": "<a@x>"}) == "<a@x>"
    assert get_rfc_message_id({"Message-Id": "<b@x>"}) == "<b@x>"   # IMAP casing
    assert get_rfc_message_id({"message-id": "<c@x>"}) == "<c@x>"

    class _Msg:
        def __init__(self, headers, message_id=None, rfc822_message_id=None):
            self.headers = headers
            self.message_id = message_id
            self.rfc822_message_id = rfc822_message_id

    # The IMAP-cased header is now resolved (was the SentMailIndex miss).
    assert get_message_rfc_id(_Msg({"Message-Id": "<imap@x>"})) == "<imap@x>"
    # No header -> provider-native fallback (kills the header-less double-count).
    assert get_message_rfc_id(_Msg({}, message_id="prov-123")) == "prov-123"
    # rfc822_message_id attr beats the provider id.
    assert get_message_rfc_id(
        _Msg({}, message_id="prov-1", rfc822_message_id="<rfc@x>")
    ) == "<rfc@x>"
    # Dict-shaped message (topic-backscan hit path).
    assert get_message_rfc_id({"headers": {"message-id": "<d@x>"}}) == "<d@x>"
    assert get_message_rfc_id({"message_id": "prov-9"}) == "prov-9"
    # Nothing present -> "".
    assert get_message_rfc_id(_Msg({})) == ""
