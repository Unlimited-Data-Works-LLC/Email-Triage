"""N-272b R28 structural pin — modern-API EmailMessage() hardened headers SSOT.

Companion to `test_n272_mime_envelope_builder_pin.py`. N-272 covered the
LEGACY ``MIMEMultipart("alternative")`` API via
`web/_mime_builder.build_alternative_message`; N-272b covers the MODERN
``email.message.EmailMessage()`` API used by daily_health digest,
update-failed alert, regulatory-clock escalation, and the single-recipient
SMTP helper.

WHY

``web/smtp_send.send_smtp_message`` is pure transport (calls
``server.send_message``; smtplib does NOT auto-add ``Date`` or ``Message-Id``).
Every ``EmailMessage()`` construct on a send path previously omitted these,
degrading MUA threading + inbox-provider dedup. N-272b lands the SSOT
`web.smtp_send.stamp_default_message_headers` + adopts at all 4 sites.

WHAT IT PINS (count-agnostic, interprocedural)

Every ``EmailMessage()`` / ``MIMEEmailMessage()`` construct under
``src/email_triage/**/*.py``, in the enclosing function scope, must be
accompanied by a call to ``stamp_default_message_headers(msg)``. Allow-list
covers the SSOT itself + the Gmail RAW builder (Gmail send endpoint sets
``Date`` + ``Message-Id`` server-side, so caller MUST NOT preset them).
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    enclosing_qualified_name,
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    relpath,
)


# Allow-list keyed on (relpath, enclosing qualified fn) — the Gmail RAW
# builder is legitimately exempt: it produces a base64-URL payload for
# the Gmail Drafts/Send endpoint; the Gmail send endpoint sets Date +
# Message-Id server-side (client-set values would be discarded / cause
# dedup surprises).
_ALLOWLIST: frozenset[tuple[str, str]] = frozenset({
    ("providers/gmail_api.py", "GmailApiProvider._build_raw_message"),
})


def _stdlib_emailmessage_names(tree: ast.AST) -> set[str]:
    """Names bound in this module that resolve to ``email.message.EmailMessage``
    (stdlib). Follows aliases: ``from email.message import EmailMessage as X``
    binds the stdlib class to ``X``. A same-file re-import from the domain
    ``email_triage.engine.models`` OVERRIDES the stdlib binding (last-writer
    wins in Python) — remove those names so a domain ``EmailMessage`` ctor
    doesn't false-positive."""
    stdlib_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "email.message":
            for alias in node.names:
                if alias.name == "EmailMessage":
                    stdlib_names.add(alias.asname or alias.name)
    # A later same-name domain import shadows the stdlib binding.
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("email_triage."):
            for alias in node.names:
                if alias.name == "EmailMessage":
                    bound = alias.asname or alias.name
                    stdlib_names.discard(bound)
    return stdlib_names


def _is_stamp_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name):
        return f.id == "stamp_default_message_headers"
    if isinstance(f, ast.Attribute):
        return f.attr == "stamp_default_message_headers"
    return False


def _ctor_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _is_emailmessage_ctor(node: ast.AST, stdlib_names: set[str]) -> bool:
    """Only STDLIB EmailMessage ctors — filters out the domain
    ``email_triage.engine.models.EmailMessage`` (a Pydantic/dataclass with
    ``message_id=``/``provider=`` kwargs, not a MIME envelope)."""
    return _ctor_name(node) in stdlib_names


def test_emailmessage_construct_requires_stamp_ssot():
    """N-272b R28 — every ``EmailMessage()`` construct in a src/ send path
    must be accompanied by a call to
    ``web.smtp_send.stamp_default_message_headers`` in the same enclosing
    function. NEW hand-rolls fire — route through the SSOT."""
    offenders: list[tuple[str, str, int]] = []
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        stdlib_names = _stdlib_emailmessage_names(tree)
        if not stdlib_names:
            continue
        for node in ast.walk(tree):
            if not _is_emailmessage_ctor(node, stdlib_names):
                continue
            enclosing = innermost_fn_at_lineno(tree, node.lineno)
            if enclosing is None:
                # Module-scope ctor — no local function body to stamp in
                # (distinct concern the SSOT doesn't cover).
                continue
            fn_qname = enclosing_qualified_name(node)
            if (rel, fn_qname) in _ALLOWLIST:
                continue
            has_stamp = any(
                _is_stamp_call(n) for n in ast.walk(enclosing)
            )
            if not has_stamp:
                offenders.append((rel, fn_qname, node.lineno))
    assert not offenders, (
        "N-272b R28: EmailMessage()/MIMEEmailMessage() constructs on a "
        "send path MUST call `stamp_default_message_headers(msg)` in the "
        "same enclosing function (owns Date + Message-Id — smtplib does "
        "not auto-add either).\n\n"
        + "\n".join(f"{p}:{ln}  ({fn})" for p, fn, ln in offenders)
    )


def test_stamp_default_message_headers_ssot_shape():
    """Anti-vacuity: the SSOT stamps a UTC Date + an RFC-2822 Message-Id."""
    from email.message import EmailMessage

    from email_triage.web.smtp_send import stamp_default_message_headers

    msg = EmailMessage()
    stamp_default_message_headers(msg)
    date_hdr = msg.get("Date")
    assert date_hdr and str(date_hdr).endswith(("GMT", "+0000")), (
        f"expected UTC Date (GMT or +0000), got {date_hdr!r}"
    )
    msgid = msg.get("Message-Id")
    assert msgid and msgid.startswith("<") and msgid.endswith(">"), (
        f"expected RFC-2822 Message-Id, got {msgid!r}"
    )
