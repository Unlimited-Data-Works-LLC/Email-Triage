"""N-42 — exception text is PHI-scrubbed before it reaches a persisted log field.

An exception string routinely echoes a recipient/sender ADDRESS or a MAILBOX
PATH (a Maildir folder can be named after a patient). Unredacted, it flowed into
the HMAC-chained ``log_entries`` table where it cannot be expunged without
breaking the §164.312(b) chain. The fix: a single ``redact_exc`` value-scrubber
that ``fmt_exc`` routes through (covering every ``error=fmt_exc(e)`` site) and
that the structured-logging formatters apply to the ``exc_info`` exception (the
separate leak leg used when a call passes ``exc_info=True``).
"""
from __future__ import annotations

import ast
import json
import logging
import sys
from pathlib import Path

import email_triage.triage_logging as tlog
from email_triage._errfmt import fmt_exc, redact_exc
from email_triage.triage_logging import _JsonFormatter, _TextFormatter

from tests._pin_harness import parse_module


# ---------------------------------------------------------------------------
# Behavioural — the scrubber itself
# ---------------------------------------------------------------------------

def test_redact_exc_strips_email_addresses():
    out = redact_exc(ValueError("SMTP refused rcpt jane.doe@hosp.org for delivery"))
    assert "jane.doe@hosp.org" not in out
    assert "@hosp.org" not in out
    assert "[redacted-addr]" in out
    assert "SMTP refused" in out  # non-PHI context preserved


def test_redact_exc_strips_filesystem_and_mailbox_paths():
    out = redact_exc("[Errno 2] No such file: '/var/mail/.INBOX.Smith-Labs/cur/1.eml'")
    assert "Smith-Labs" not in out
    assert "[redacted-path]" in out
    assert "[Errno 2]" in out


def test_redact_exc_leaves_clean_text_untouched():
    assert redact_exc(ValueError("invalid config value for retries")) == (
        "invalid config value for retries"
    )


def test_redact_exc_empty_exception_falls_back_to_repr_no_phi():
    # repr() of a bare exception is the class name + () — never PHI.
    assert redact_exc(ValueError()) == "ValueError()"


def test_fmt_exc_routes_through_redact_exc():
    # The 295 error=fmt_exc(e) sites inherit the scrub for free.
    assert "@hosp.org" not in fmt_exc(RuntimeError("connect failed for bob@hosp.org"))
    assert "[redacted-addr]" in fmt_exc(RuntimeError("connect failed for bob@hosp.org"))


# ---------------------------------------------------------------------------
# Integration — a real LogRecord through each formatter (the exc_info leg)
# ---------------------------------------------------------------------------

def _record_with_exc(exc: Exception) -> logging.LogRecord:
    try:
        raise exc
    except Exception:
        return logging.LogRecord(
            "t", logging.ERROR, "f.py", 1, "operation failed", None, sys.exc_info()
        )


def test_json_formatter_scrubs_exc_info_address():
    rec = _record_with_exc(ValueError("rcpt jane@hosp.org refused"))
    out = json.loads(_JsonFormatter().format(rec))
    assert "@hosp.org" not in out["error"]
    assert "[redacted-addr]" in out["error"]
    # error_type stays the class name (not PHI).
    assert out["error_type"] == "ValueError"


def test_text_formatter_scrubs_exc_info_path():
    rec = _record_with_exc(
        OSError("open '/srv/mail/.INBOX.Doe/cur/9.eml' failed")
    )
    out = _TextFormatter().format(rec)
    assert ".INBOX.Doe" not in out
    assert "[redacted-path]" in out


# ---------------------------------------------------------------------------
# Count-agnostic structural pin — no raw exc_info render in the formatters
# ---------------------------------------------------------------------------

def _renders_exc_info_text(node: ast.AST) -> bool:
    """An AST node that turns ``*.exc_info[..]`` into TEXT — the leak shape:
    ``str(record.exc_info[1])`` or an f-string ``{record.exc_info[1]}``. A
    ``redact_exc(...)`` wrap, a ``type(...)`` read, and an ``is not None`` guard
    are NOT this shape (their child is the Call/Compare, not the bare subscript)."""
    def _is_exc_sub(n: ast.AST) -> bool:
        return (
            isinstance(n, ast.Subscript)
            and isinstance(n.value, ast.Attribute)
            and n.value.attr == "exc_info"
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and node.args
        and _is_exc_sub(node.args[0])
    ):
        return True
    if isinstance(node, ast.FormattedValue) and _is_exc_sub(node.value):
        return True
    return False


def test_no_raw_exc_info_render_in_logging_module():
    """Count-agnostic N-42 pin: ANYWHERE in triage_logging that renders an
    ``exc_info`` exception to TEXT must route through ``redact_exc`` — never a
    raw ``str(record.exc_info[1])`` or an f-string ``{record.exc_info[1]}``.
    Covers the formatters AND the SQLite/log_entries persist handler; a new
    render leg inherits the requirement (a property over the module, not
    ``len == N``). This pin caught the persist-handler leak the formatter-only
    fix missed."""
    tree = parse_module(Path(tlog.__file__))
    assert tree is not None, "expected parseable source at Path(tlog.__file__)"
    leaks = sorted(
        node.lineno for node in ast.walk(tree) if _renders_exc_info_text(node)
    )
    assert not leaks, (
        f"raw exc_info text render (not via redact_exc) at lines {leaks} in "
        f"triage_logging.py — N-42 PHI leak into the HMAC-chained log_entries"
    )


# ---------------------------------------------------------------------------
# db-sme MUST-FIX coverage: edge case, URL carve-out, the count-agnostic sink
# ---------------------------------------------------------------------------

def test_redact_exc_survives_exception_whose_str_raises():
    """fmt_exc is on 353 sites and promises "the operator always sees
    something" — an exception whose __str__ itself raises must NOT propagate out
    of redact_exc/fmt_exc (db-sme edge case)."""
    class Boom(Exception):
        def __str__(self):
            raise RuntimeError("str boom")

    out = redact_exc(Boom())
    assert isinstance(out, str) and out  # non-empty string, no exception escaped
    assert "Boom" in out  # class name still surfaced
    # fmt_exc (the 353-site funnel) must be safe too — it passes the exception.
    assert isinstance(fmt_exc(Boom()), str) and fmt_exc(Boom())


def test_redact_exc_keeps_urls_but_redacts_absolute_paths():
    """db-sme over-redaction fix: a URL path (OAuth/API endpoint — no PHI) stays
    intact for debuggability; a leading-slash absolute/mailbox path is still
    redacted."""
    url = "token refresh POST to https://login.microsoftonline.com/abc/oauth2/v2.0/token failed"
    out = redact_exc(url)
    assert "login.microsoftonline.com/abc/oauth2/v2.0/token" in out  # URL preserved
    assert "[redacted-path]" not in out
    # absolute mailbox path still redacted
    out2 = redact_exc("open '/var/mail/.INBOX.Doe/cur/9.eml' failed")
    assert ".INBOX.Doe" not in out2 and "[redacted-path]" in out2


def test_sqlite_handler_extra_hoist_scrubs_every_value():
    """Count-agnostic SINK pin (db-sme M1): the SQLiteLogHandler hoists every
    _extra value into the persisted, HMAC-chained log_entries via str(). A bare
    ``extra[..] = str(..)`` is the leak — it MUST be ``redact_exc(str(..))`` so a
    str(exc)/mailbox-path put into _extra ANYWHERE is scrubbed at this one point
    (covers the ~239 render sites without chasing each). ``error_type`` (the
    class-name read) is not a str() render and is exempt."""
    tree = parse_module(Path(tlog.__file__))
    assert tree is not None, "expected parseable source at Path(tlog.__file__)"
    bad: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].value, ast.Name)
            and node.targets[0].value.id == "extra"
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "str"  # a bare str(...) render into the sink
        ):
            bad.append(node.lineno)
    assert not bad, (
        f"persisted `extra[..] = str(..)` not scrubbed via redact_exc at lines "
        f"{bad} — N-42 sink leak into log_entries.extra_json"
    )
