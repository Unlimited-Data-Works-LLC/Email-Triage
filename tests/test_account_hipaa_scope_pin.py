"""N-77 class-fix pin: account_hipaa_effective SSOT + bare-is_hipaa_mode ban.

Two goals:
1. STRUCTURAL (count-agnostic): ban a BARE ``is_hipaa_mode()`` call in the
   per-account PHI-decision layers (``engine/``, ``cache/``, ``actions/``,
   and the specific web PHI-gate sites) OUTSIDE an explicit allow-list.
   A new PHI-decision site that reaches for the global flag instead of the
   per-account SSOT trips CI immediately.

2. TRUTH-TABLE unit pin: ``account_hipaa_effective`` correctly applies
   most-restrictive-wins over all three axes (system flag, account flag,
   message.hipaa stamp).

3. TEETH: the SSOT function itself must be importable and callable.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple

import pytest

from _pin_harness import (
    SRC_ROOT,
    annotate_parents,
    enclosing_fn,
    iter_src_files,
    parse_module,
    relpath,
)

# SRC_ROOT (= src/email_triage) is the canonical package root, computed once in
# the shared harness. Aliased to SRC here because this file references ``SRC``
# in many places (``SRC / "actions" / ...`` etc.) — the value and base are
# identical, so the alias preserves every existing reference verbatim.
SRC = SRC_ROOT


def _rel_key(py_path: Path) -> str:
    """Allow-list / scan key: SRC_ROOT-relative, forward-slash, NO ``.py``
    suffix (``web/routers/ui/admin``). The harness ``relpath`` yields the same
    base WITH the suffix (``web/routers/ui/admin.py``); the allow-list has
    always keyed on the suffix-stripped form, so strip it here to preserve the
    exact key semantics."""
    return relpath(py_path).removesuffix(".py")

# ---------------------------------------------------------------------------
# 1. SSOT existence + teeth
# ---------------------------------------------------------------------------

def test_account_hipaa_effective_importable():
    """The SSOT function must be importable from triage_logging."""
    from email_triage.triage_logging import account_hipaa_effective  # noqa: F401
    assert callable(account_hipaa_effective)


# ---------------------------------------------------------------------------
# 2. Truth-table unit pin
# ---------------------------------------------------------------------------

class _FakeAccount:
    """Minimal account-like object with a .hipaa attribute."""
    def __init__(self, hipaa: bool):
        self.hipaa = hipaa


class _FakeMessage:
    """Minimal message-like object with a .hipaa attribute."""
    def __init__(self, hipaa: bool):
        self.hipaa = hipaa


def _call(
    *,
    global_on: bool,
    acct_hipaa: bool | None,
    msg_hipaa: bool | None,
) -> bool:
    import email_triage.triage_logging as _tl
    from email_triage.triage_logging import account_hipaa_effective
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = global_on
        account = _FakeAccount(acct_hipaa) if acct_hipaa is not None else None
        message = _FakeMessage(msg_hipaa) if msg_hipaa is not None else None
        return account_hipaa_effective(account=account, message=message)
    finally:
        _tl._hipaa_mode = orig


# Global-on: always True regardless of per-account/message
def test_global_on_no_account_no_message():
    assert _call(global_on=True, acct_hipaa=None, msg_hipaa=None) is True

def test_global_on_acct_off_msg_off():
    assert _call(global_on=True, acct_hipaa=False, msg_hipaa=False) is True

# Per-account-on + global-off → True (the core class-fix bug)
def test_global_off_acct_on_no_message():
    assert _call(global_on=False, acct_hipaa=True, msg_hipaa=None) is True

# Message-stamp-on + global-off + acct-off → True
def test_global_off_acct_off_msg_on():
    assert _call(global_on=False, acct_hipaa=False, msg_hipaa=True) is True

# Both off → False
def test_all_off():
    assert _call(global_on=False, acct_hipaa=False, msg_hipaa=False) is False

# No account, no message, global off → False (safe default; not fail-closed,
# but this only occurs when the caller genuinely has no account context)
def test_no_context_global_off():
    assert _call(global_on=False, acct_hipaa=None, msg_hipaa=None) is False

# dict account (sqlite3.Row-like mapping)
def test_dict_account():
    import email_triage.triage_logging as _tl
    from email_triage.triage_logging import account_hipaa_effective
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False
        assert account_hipaa_effective(account={"hipaa": 1}) is True
        assert account_hipaa_effective(account={"hipaa": 0}) is False
    finally:
        _tl._hipaa_mode = orig

# message.hipaa beats missing account
def test_message_stamp_with_no_account():
    assert _call(global_on=False, acct_hipaa=None, msg_hipaa=True) is True


# ---------------------------------------------------------------------------
# 3. Structural pin — bare is_hipaa_mode() ban in per-account PHI layers
# ---------------------------------------------------------------------------

# Category-A allow-list: these sites correctly use the install-wide flag
# for non-PHI-decision purposes (boot enforcement, admin display, session TTL,
# MFA policy, system health). The dict maps (relative path, lineno-key) →
# justification. Lineno is a comment/approx — the AST walker checks by
# enclosing function name, not line number, to avoid brittleness.
#
# Format: "file_stem:function_name" → justification string.
# A site is allowed iff its enclosing function (or module-level scope)
# appears here. Module-level scope = sentinel "__module__".
# Every key below was VERIFIED against HEAD on 2026-06-10 by enumerating the
# real call sites with an alias-aware AST walk (NOT hand-guessed function
# names — an earlier draft of this list fabricated names like ``accounts_new``
# / ``otp_verify_post`` that do not exist, which were dead because the file
# was not even scanned). Each entry's enclosing function is the actual one
# the walker reports.
#
# SCOPE BOUNDARY: this pin covers the per-account PHI-DECISION layers only
# (BANNED_MODULES). Install-wide POLICY modules — web/auth (session TTL),
# web/mfa (MFA), secrets / db/_engine (boot enforcement),
# web/transmission_security (TLS), cli (offline validator), web/app (startup
# breadcrumb), web/daily_health (health reporting) — are deliberately OUT of
# scope: their ``is_hipaa_mode()`` use is correctly install-scoped and they
# make no per-account PHI decision. Do not add them here without also adding
# the module to BANNED_MODULES (an allow-list entry for an unscanned module
# is dead and misleads — that was the original defect).
ALLOW_LIST: dict[str, str] = {
    # engine/store.py — N-74 SSOT: redact_reason takes an account_hipaa param;
    # the bare is_hipaa_mode() is belt-and-suspenders (system flag still
    # forces redaction). N-74 done + separately pinned.
    "engine/store:redact_reason": "N-74 SSOT: uses account_hipaa param; is_hipaa_mode() is belt-and-suspenders",
    # web/background_sweepers.py — HIPAA-boundary drift detector inner tick;
    # compares the install-wide flag to the last boundary-event row.
    "web/background_sweepers:_tick": "drift detector inner tick: compares install-wide is_hipaa_mode() to last boundary event",
    # --- web/routers/ui: install-wide DISPLAY / POLICY / INHERITANCE sites ---
    # Each either shows the system flag to an admin, applies an install-wide
    # policy, sets the initial per-account inheritance at create time, or does
    # an install-wide first-pass WITH an explicit per-account follow in the
    # SAME function (each verified by reading the body 2026-06-10).
    "web/routers/ui/_shared:_render": "template context: hipaa_mode flag for admin UI display",
    "web/routers/ui/_shared:_inject_baa_banner_ctx": "BAA banner: install-wide first-pass + per-account 'WHERE hipaa=1' fallback in same fn",
    "web/routers/ui/_shared:_compliance_page_snapshot": "compliance page: reports system_on; per-account rows via is_account_hipaa",
    "web/routers/ui/_shared:_writing_tab_context": "style-learning gate: system first-pass + per-account is_account_hipaa loop follow in same fn",
    "web/routers/ui/accounts:accounts_create": "account-create: inherits system HIPAA; no per-account flag exists yet",
    "web/routers/ui/accounts:accounts_edit_form": "template context: hipaa_mode for admin UI display",
    "web/routers/ui/users:login_verify": "install-wide MFA/session policy at login",
    "web/routers/ui/wizard:wizard_step1_submit": "account-create: inherits system HIPAA when no per-account override",
    "web/routers/ui/wizard:wizard_step5_submit": "completion success message: informs user of system HIPAA state",
    "web/routers/ui/admin:admin_security_save": "HIPAA flip: captures PRE-toggle system state (aliased import) to emit the boundary event",
}

# Modules+paths within src/email_triage that are subject to the ban.
# These are the per-account PHI-decision layers.
BANNED_MODULES = [
    "actions",
    "engine",
    "cache",
    "web/digest",
    "web/topic_digest_sender",
    "web/watch_runner",
    "web/poll_ingestion",
    "web/ingestion_push",
    "web/watcher",
    "web/background_sweepers",
    "web/routers/agent_api",
    # web/routers/ui carries real per-account PHI-decision sites (the
    # recipient/topic digest send/test/preview handlers in accounts.py route
    # through account_hipaa_effective). The install-wide DISPLAY/POLICY sites
    # in the same tree are individually allow-listed above.
    "web/routers/ui",
    # baa_expiry.py — auto_disable_expired_for_hipaa_accounts routes its
    # per-account BAA gate through account_hipaa_effective; in scope so a
    # regression re-introducing a bare is_hipaa_mode() there is caught.
    "baa_expiry",
]


class _Violation(NamedTuple):
    file: str
    lineno: int
    fn_name: str


def _collect_violations() -> list[_Violation]:
    """AST-walk banned modules for bare is_hipaa_mode() calls not in ALLOW_LIST."""
    violations: list[_Violation] = []

    def _walk_module(rel: str, tree: ast.Module, src_path: Path) -> None:
        # Enclosing-function resolution comes from the shared harness
        # (annotate_parents was applied by parse_module; enclosing_fn walks
        # the ._ph_parent chain). enclosing_fn returns "<module>" at module
        # scope; the allow-list key uses the "__module__" sentinel, so map it.

        # Collect every LOCAL name bound to is_hipaa_mode, INCLUDING aliases
        # (``from ... import is_hipaa_mode as _x``). Without this an aliased
        # import silently evades the ban — a one-line bypass. PD#6: a pin
        # keyed on the literal name only is blind by construction. (admin.py
        # really does ``import is_hipaa_mode as _was_hipaa``.)
        # RESIDUAL (known, no live site): this still would not catch a
        # ``getattr(tl, "is_hipaa_mode")()`` or a non-import rebind
        # (``f = is_hipaa_mode; f()``). Those are the remaining one-line
        # bypasses; the SME panel (DA) flagged them as theoretical. If one ever
        # appears, extend the alias set to follow simple Name = Name assigns.
        aliases: set[str] = {"is_hipaa_mode"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "is_hipaa_mode":
                        aliases.add(a.asname or a.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Match is_hipaa_mode() — bare name, an import-alias of it, or the
            # attribute form (``mod.is_hipaa_mode()``).
            func = node.func
            is_bare = (
                isinstance(func, ast.Name) and func.id in aliases
            ) or (
                isinstance(func, ast.Attribute) and func.attr == "is_hipaa_mode"
            )
            if not is_bare:
                continue

            enc = enclosing_fn(node)
            fn = None if enc == "<module>" else enc
            fn_key = f"{rel}:{fn or '__module__'}"
            if fn_key in ALLOW_LIST:
                continue
            violations.append(_Violation(
                file=relpath(src_path, SRC.parent),
                lineno=node.lineno,
                fn_name=fn or "<module>",
            ))

    for module_rel in BANNED_MODULES:
        module_path = SRC / module_rel
        if module_path.is_dir():
            # iter_src_files walks the subtree, skips __pycache__, sorted.
            paths = list(iter_src_files(module_rel))
        elif module_path.with_suffix(".py").exists():
            paths = [module_path.with_suffix(".py")]
        else:
            paths = []

        for py_path in paths:
            tree = parse_module(py_path)  # None on syntax/decode error → skip
            if tree is None:
                continue
            # Relative path key like "actions/notify" or "web/digest".
            rel_key = _rel_key(py_path)
            _walk_module(rel_key, tree, py_path)

    return violations


def test_aliased_is_hipaa_mode_not_invisible(monkeypatch):
    """An aliased import must NOT evade the ban (PD#6 teeth).

    ``admin.py:admin_security_save`` really does
    ``from ... import is_hipaa_mode as _was_hipaa`` and calls ``_was_hipaa()``.
    A name-only matcher would never see it. Prove the alias-aware walker does:
    with that site's allow-list entry removed, it MUST be flagged. If this
    test ever passes with the entry present but FAILS to flag when removed,
    the detector has regressed to name-only matching and the ban is bypassable
    by a one-line alias.
    """
    import sys
    M = sys.modules[__name__]
    pruned = dict(M.ALLOW_LIST)
    removed = pruned.pop("web/routers/ui/admin:admin_security_save", None)
    assert removed is not None, (
        "expected web/routers/ui/admin:admin_security_save in ALLOW_LIST — "
        "the aliased-import test anchor is gone"
    )
    monkeypatch.setattr(M, "ALLOW_LIST", pruned)
    violations = M._collect_violations()
    assert any(v.fn_name == "admin_security_save" for v in violations), (
        "alias-aware detector failed to catch the aliased is_hipaa_mode() "
        "call in admin.py — the ban is evadable by a one-line `import as`"
    )


def test_no_bare_is_hipaa_mode_in_phi_layers():
    """No bare is_hipaa_mode() call in per-account PHI layers outside ALLOW_LIST.

    Any new PHI-decision site that reaches for the global flag instead of
    account_hipaa_effective will be caught here.

    If a new site is LEGITIMATELY install-wide, add it to ALLOW_LIST with
    a justification before committing.
    """
    violations = _collect_violations()
    if violations:
        lines = [
            f"\n  {v.file}:{v.lineno} (in {v.fn_name!r})"
            for v in violations
        ]
        pytest.fail(
            f"Bare is_hipaa_mode() found in per-account PHI layer(s) — "
            f"use account_hipaa_effective(account=..., message=...) instead, "
            f"or add to ALLOW_LIST with justification:{chr(10).join(lines)}"
        )


# ---------------------------------------------------------------------------
# 4. SSOT is not duplicated — account_hipaa_effective must be the single
#    "all three axes" implementation (provider_labels.resolve_label_hipaa
#    must delegate to it, not re-implement independently).
# ---------------------------------------------------------------------------

def test_resolve_label_hipaa_delegates_to_ssot():
    """resolve_label_hipaa must call account_hipaa_effective (not re-implement)."""
    pl_path = SRC / "actions" / "provider_labels.py"
    tree = parse_module(pl_path); assert tree is not None  # N-350 R31 harness SSOT

    fn_node = None
    for n in ast.walk(tree):
        if (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "resolve_label_hipaa"
        ):
            fn_node = n
            break
    assert fn_node is not None, "resolve_label_hipaa not found in provider_labels.py"

    names: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            names.add(n.attr)
    assert "account_hipaa_effective" in names, (
        "resolve_label_hipaa no longer delegates to account_hipaa_effective — "
        "this creates a second independent axis-combination implementation"
    )


# ---------------------------------------------------------------------------
# 5. Behavioural: per-account HIPAA subject with global OFF gets HIPAA
#    treatment in notify.py and escalate.py
# ---------------------------------------------------------------------------

def test_notify_action_hipaa_with_global_off():
    """NotifyAction._build_payload uses per-account HIPAA (global off)."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False  # global OFF
        from email_triage.actions.notify import NotifyAction
        from email_triage.engine.models import EmailMessage
        from datetime import datetime, timezone

        # Message stamped as per-account HIPAA
        msg = EmailMessage(
            message_id="test-msg-1",
            sender="patient@example.com",
            recipients=["doc@clinic.com"],
            subject="My health record request",
            body_text="Dear doctor, ...",
            date=datetime.now(timezone.utc),
            provider="imap",
            hipaa=True,  # per-account stamp
        )

        action = NotifyAction()
        from email_triage.engine.models import Classification, FlowState, FlowStatus
        classification = Classification(
            category="medical", confidence=0.9, reason="PHI reason", source="llm",
        )
        flow = FlowState(
            flow_id="f1", message_id="test-msg-1", provider="imap",
            status=FlowStatus.CLASSIFIED,
        )
        payload = action._build_notification(flow=flow, message=msg, classification=classification)
        # HIPAA payload: sender + subject are redacted (not present)
        assert "sender" not in payload, "sender leaked in per-account HIPAA notify payload"
        assert "subject" not in payload, "subject leaked in per-account HIPAA notify payload"
        # Must have the safe fields
        assert "category" in payload
        assert "flow_id" in payload
    finally:
        _tl._hipaa_mode = orig


def test_notify_action_non_hipaa_with_global_off():
    """NotifyAction._build_payload does NOT redact when both flags are off."""
    import email_triage.triage_logging as _tl
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False
        from email_triage.actions.notify import NotifyAction
        from email_triage.engine.models import EmailMessage, Classification, FlowState, FlowStatus
        from datetime import datetime, timezone

        msg = EmailMessage(
            message_id="test-msg-2",
            sender="sender@example.com",
            recipients=["user@example.com"],
            subject="Work meeting follow-up",
            body_text="Hi, following up on ...",
            date=datetime.now(timezone.utc),
            provider="imap",
            hipaa=False,  # no HIPAA
        )
        action = NotifyAction()
        classification = Classification(
            category="work", confidence=0.8, reason="work", source="llm",
        )
        flow = FlowState(
            flow_id="f2", message_id="test-msg-2", provider="imap",
            status=FlowStatus.CLASSIFIED,
        )
        payload = action._build_notification(flow=flow, message=msg, classification=classification)
        # Standard (non-HIPAA) payload: sender + subject are present
        assert "sender" in payload, "sender missing from non-HIPAA notify payload"
        assert "subject" in payload, "subject missing from non-HIPAA notify payload"
    finally:
        _tl._hipaa_mode = orig


# ---------------------------------------------------------------------------
# 6. Watcher PHI-redaction OUTCOME (N-77 headline fix + its sibling).
#    The structural pin only checks WHICH function the gate calls, NOT the
#    redaction outcome — so a regression that flips the gate could pass the
#    pin and every model/auth test (the N-74 'mock-the-seam' trap). These
#    drive a REAL EmailMessage through the actual helpers the watcher writes
#    its log line + status dict from, and assert the PHI is gone.
# ---------------------------------------------------------------------------

def _phi_message():
    from email_triage.engine.models import EmailMessage
    from datetime import datetime, timezone
    return EmailMessage(
        message_id="w-msg-1",
        sender="patient@example.com",
        recipients=["doc@clinic.com"],
        subject="lab results for review",
        body_text="...",
        date=datetime.now(timezone.utc),
        provider="imap",
        hipaa=True,
    )


def test_watcher_log_phi_omits_fields_for_hipaa_account():
    """_watch_log_phi OMITS sender/subject/reason for an effective-HIPAA
    account (§164.312(b)): the log record carries no PHI."""
    from email_triage.web.watcher import _watch_log_phi
    msg = _phi_message()
    fields = _watch_log_phi(msg, "PHI reason text", account_hipaa=True)
    assert fields == {}, f"PHI leaked into watcher log fields: {fields}"


def test_watcher_log_phi_includes_fields_for_non_hipaa_account():
    """_watch_log_phi includes sender/subject/reason for a non-HIPAA account."""
    from email_triage.web.watcher import _watch_log_phi
    msg = _phi_message()
    fields = _watch_log_phi(msg, "ordinary reason", account_hipaa=False)
    assert fields["sender"] == "patient@example.com"
    assert fields["subject"].startswith("lab results")
    assert fields["reason"] == "ordinary reason"


def test_watcher_status_phi_redacts_for_hipaa_account():
    """_watch_status_phi sentinel-redacts sender/subject for an
    effective-HIPAA account so the admin watch-status partial shows no PHI
    (§164.502(b)/§164.312(a)(1) — the must-fix sibling of the log gate)."""
    from email_triage.web.watcher import _watch_status_phi
    from email_triage.triage_logging import REDACTED
    msg = _phi_message()
    sender, subject = _watch_status_phi(msg, account_hipaa=True)
    assert sender == REDACTED and subject == REDACTED
    assert "patient@example.com" not in sender
    assert "lab results" not in subject
    # Non-HIPAA → raw values present
    sender2, subject2 = _watch_status_phi(msg, account_hipaa=False)
    assert sender2 == "patient@example.com"
    assert subject2 == "lab results for review"


def test_watcher_wires_both_phi_sinks_through_the_helpers():
    """Structural: _watch_account must route BOTH PHI sinks (the status
    last_message dict AND the triaged-message log line) through the redaction
    helpers. If a future edit inlines a raw message.sender/subject at either
    sink again, this fails (keeps the two siblings from drifting apart)."""
    import ast
    tree = parse_module(SRC / "web" / "watcher.py")
    assert tree is not None, "expected parseable source at SRC / 'web' / 'watcher.py'"
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == "_watch_account"),
        None,
    )
    assert fn is not None, "_watch_account not found"
    called = {
        n.func.id for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    # N-283 R29: `_watch_status_phi` was folded into `record_message_result`
    # (N-256b/N-213b) — the SSOT now does the redacted substitution when
    # `account_hipaa=True`. Either path (the legacy `_watch_status_phi` helper
    # OR the SSOT) satisfies the PHI-render gate; direct raw dict-write to
    # `last_message` still fails the pin.
    assert ("_watch_status_phi" in called or "record_message_result" in called), (
        "_watch_account no longer routes last_message through _watch_status_phi "
        "OR record_message_result — the admin-UI PHI-render gate "
        "(N-77 sibling / N-256b/N-213b successor) may have regressed"
    )
    assert "_watch_log_phi" in called, (
        "_watch_account no longer routes the triaged-message log line through "
        "_watch_log_phi — the §164.312(b) PHI-log gate may have regressed"
    )


def test_action_log_extras_redacts_for_hipaa_via_system_axis():
    """build_action_log_extras gates on account_hipaa_effective (system axis
    restored), so a HIPAA install redacts even if message.hipaa is unstamped
    (DA peer-site fix — was a bare getattr(message,'hipaa') fail-open)."""
    import email_triage.triage_logging as _tl
    from email_triage.actions.base import build_action_log_extras
    from email_triage.engine.models import (
        EmailMessage, Classification, FlowState, FlowStatus,
    )
    from datetime import datetime, timezone

    class _Prov:
        name = "imap"

    msg = EmailMessage(
        message_id="a-msg-1", sender="patient@example.com",
        recipients=["doc@clinic.com"], subject="appointment",
        body_text="...", date=datetime.now(timezone.utc),
        provider="imap", hipaa=False,  # UNSTAMPED — the fail-open trigger
    )
    classification = Classification(
        category="medical", confidence=0.9, reason="r", source="llm",
    )
    flow = FlowState(
        flow_id="af1", message_id="a-msg-1", provider="imap",
        status=FlowStatus.CLASSIFIED,
    )
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = True  # system HIPAA ON, message stamp OFF
        extras = build_action_log_extras(flow, msg, classification, _Prov())
        assert "sender" not in extras, "sender leaked despite system HIPAA on"
        assert "subject" not in extras, "subject leaked despite system HIPAA on"
    finally:
        _tl._hipaa_mode = orig


# ---------------------------------------------------------------------------
# N-81 structural pin — raw acct["hipaa"] / .get("hipaa") used as a
# PHI-decision BRANCH CONDITION outside the SSOT definitions.
#
# The existing N-77 pin bans bare is_hipaa_mode() calls in the per-account
# PHI layers.  It does NOT catch a different shape: code that reads the raw
# per-account column (acct.get("hipaa") / acct["hipaa"]) directly to make a
# PHI-decision (redact, audit, gate, egress) WITHOUT folding the system flag.
# On a system-HIPAA install where acct["hipaa"]=0, those gates are False →
# the system flag is silently dropped.  The N-77 pin never scanned jobs/.
#
# This pin targets:
#   a) The raw-column read used AS A BRANCH CONDITION (ast.If / ast.IfExp /
#      boolean-op test, or ``return not bool(...)`` gate) in PHI-decision
#      code, including jobs/.
#   b) NOT: display-only template-context assignments, DB row construction,
#      the SSOT internals (triage_logging.py), or the HIPAA-flag WRITE path.
#
# Allow-list entries are derived from a ground-truth AST walk of HEAD and
# each carries a one-line justification.  Do NOT add a site here without
# verifying it is genuinely display-only or a WRITE-path — that would
# hollow out the pin.
# ---------------------------------------------------------------------------

# Modules subject to the N-81 raw-column branch ban.
_N81_BANNED_MODULES = [
    # Same per-account PHI-decision scope as the N-77 pin.
    "actions",
    "engine",
    "cache",
    "web/digest",
    "web/topic_digest_sender",
    "web/watch_runner",
    "web/poll_ingestion",
    "web/ingestion_push",
    "web/watcher",
    "web/background_sweepers",
    "web/routers/agent_api",
    "web/routers/ui",
    "baa_expiry",
    # N-81 addition: jobs/ was never scanned by the N-77 pin.
    "jobs",
]

# Allow-list: file_stem:function_name → justification.
# A site is allowed iff its enclosing function (or module scope) appears here.
# ONLY genuinely-display / WRITE-path / SSOT-internal sites belong here.
# Every entry was verified against HEAD on 2026-06-11 by reading the body.
_N81_ALLOW_LIST: dict[str, str] = {
    # profile.py — _hit_from_verdict: builds an EPHEMERAL context dict that
    # carries ``"hipaa": bool(account.get("hipaa"))`` for template display.
    # This is a DICT ASSIGNMENT (RHS of a key→value), not a branch condition;
    # the rendered value is a display flag shown to the operator in the topic-
    # digest preview UI. No PHI redaction or audit decision hangs off it.
    "web/routers/ui/profile:_hit_from_verdict": (
        "display-only dict key for template context; not a branch condition"
    ),
    # profile.py — _style_data_export_db_work: the inline dict that carries
    # ``"hipaa": bool(acct.get("hipaa"))`` is a JSON export field, NOT a
    # branch condition; the export REDACTION gate above it is already routed
    # through is_account_hipaa (N-81 fix).
    "web/routers/ui/profile:_style_data_export_db_work": (
        "export payload dict field — display/metadata, not a branch condition"
    ),
    # profile.py — _topic_digest_cards_snapshot / _topic_editor_snapshot /
    # _err_ctx: all three compute ``protected = any(... .get('hipaa') ...)``.
    # This sets a UI badge flag (padlock icon on the card/editor) — display-
    # only, no PHI redaction or audit row hangs off it.  The badge being
    # wrong (missing on system-HIPAA install) is a UX issue, not a HIPAA-
    # data-loss issue — flagged for lead review (see N-81 report).
    "web/routers/ui/profile:_topic_digest_cards_snapshot": (
        "protected badge display flag — padlock UI indicator, not audit/redact gate"
    ),
    "web/routers/ui/profile:_topic_editor_snapshot": (
        "protected badge display flag — padlock UI indicator, not audit/redact gate"
    ),
    "web/routers/ui/profile:_err_ctx": (
        "protected badge display flag — padlock UI indicator, not audit/redact gate"
    ),
    # accounts.py — _hipaa_flag_db_work: ``was_hipaa = bool(acct.get('hipaa'))``
    # captures PRE-save state to detect a 0→1 flip for auto-off of AI-learns
    # toggle.  This is a WRITE-path helper for the HIPAA flag itself, not a
    # PHI-read gate.  The flip detection (``if desired and not was_hipaa``) is
    # bookkeeping on the flag write, not a PHI-data-access decision.
    "web/routers/ui/accounts:_hipaa_flag_db_work": (
        "pre-save HIPAA state capture for flip detection on flag WRITE path, not PHI-read gate"
    ),
    # admin.py — _security_save_hipaa_db_work: the ``if pre_hipaa != new_runtime['hipaa']``
    # comparison checks whether the SYSTEM-LEVEL hipaa flag flipped (pre_hipaa is
    # is_hipaa_mode(), new_runtime['hipaa'] is the new config value).  This is an
    # install-wide flag-flip detector on the admin security page — not a per-account
    # PHI-read gate.  The 'hipaa' key here lives in a system config dict, not an
    # email_accounts row.  The scanner cannot distinguish config dicts from account
    # dicts by variable name, so this entry silences the false positive.
    "web/routers/ui/admin:_security_save_hipaa_db_work": (
        "system HIPAA flag flip detection in admin security page — config dict, not per-account PHI gate"
    ),
}


class _N81Violation(ast.NodeVisitor):
    """Collect raw-column hipaa branch conditions via AST walk.

    Detects:
      * ``if ... acct.get("hipaa") ...``  (ast.If / ast.IfExp test)
      * ``if ... acct["hipaa"] ...``
      * ``return not bool(account.get("hipaa"))``  (ast.Return)
      * ``any(... .get("hipaa") ...)`` used as a boolean expression
        nested inside an ast.If/ast.Return/assignment that feeds a branch

    Conservative: we flag any node that BOTH:
      (a) has a raw []/get() access on the literal key "hipaa", AND
      (b) appears inside an ast.If.test, ast.IfExp.test, ast.Return value,
          or is the direct condition of a boolean-op (ast.BoolOp) whose
          parent is an ast.If.test.

    We specifically do NOT flag:
      - Dict-literal values (``{"hipaa": ...}`` key→value assignments)
      - Attribute reads (``acct.hipaa``), which belong to ORM / dataclass
        access and are a separate surface
      - Non-branch boolean contexts (e.g. a bare ``bool(acct.get("hipaa"))``
        assigned to a variable with no branch)

    This is intentionally conservative (may miss creative shapes) while
    never flagging false positives on the allow-listed patterns.  The SME
    review layer catches what the static walk misses.
    """

    def __init__(self, rel: str, src_path: Path):
        self.violations: list[_Violation] = []
        self._rel = rel
        self._src_path = src_path

    def _tag_parents(self, node: ast.AST, fn: str | None = None) -> None:
        """Annotate ._ph_parent on the tree so :func:`enclosing_fn` resolves the
        enclosing function of any If/Return node. Delegates to the shared
        harness; the ``fn`` arg is retained for the existing call signature
        (``_tag_parents(tree, None)``) but is unused — enclosing_fn walks the
        parent chain rather than a precomputed map. Equivalence with the old
        precompute-map approach was verified for If/Return nodes (the only
        nodes this visitor keys on), incl. nested + module scope."""
        annotate_parents(node)

    def _enclosing(self, node: ast.AST) -> str | None:
        """Enclosing function name, or None at module scope (the allow-list key
        uses the '__module__' sentinel for module scope, mapped at the call)."""
        enc = enclosing_fn(node)
        return None if enc == "<module>" else enc

    @staticmethod
    def _is_raw_hipaa_read(node: ast.AST) -> bool:
        """True when node is acct.get("hipaa") / acct["hipaa"] / account.get("hipaa") etc."""
        # Shape A: acct.get("hipaa") or account.get("hipaa") → ast.Call
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and len(node.args) >= 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "hipaa"
            ):
                return True
        # Shape B: acct["hipaa"] / account["hipaa"] → ast.Subscript
        if isinstance(node, ast.Subscript):
            slice_node = node.slice
            # Python 3.9+ slice is the value directly
            val = slice_node
            if isinstance(val, ast.Index):  # Python < 3.9
                val = val.value  # type: ignore[attr-defined]
            if isinstance(val, ast.Constant) and val.value == "hipaa":
                return True
        return False

    @staticmethod
    def _contains_raw_hipaa(node: ast.AST) -> bool:
        """True when any descendant of node is a raw hipaa read."""
        return any(
            _N81Violation._is_raw_hipaa_read(n)
            for n in ast.walk(node)
        )

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        """Flag raw hipaa reads in If.test."""
        if self._contains_raw_hipaa(node.test):
            fn = self._enclosing(node)
            fn_key = f"{self._rel}:{fn or '__module__'}"
            if fn_key not in _N81_ALLOW_LIST:
                self.violations.append(_Violation(
                    file=relpath(self._src_path, SRC.parent),
                    lineno=node.lineno,
                    fn_name=fn or "<module>",
                ))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        """Flag ``return not bool(account.get('hipaa'))`` shapes."""
        if node.value is not None and self._contains_raw_hipaa(node.value):
            # Only flag if the return value looks like a boolean gate
            # (not bool or bool wrapped), i.e. the return is a boolean
            # expression over the hipaa column.
            v = node.value
            is_bool_gate = False
            if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not):
                is_bool_gate = True
            elif isinstance(v, ast.Call):
                if isinstance(v.func, ast.Name) and v.func.id == "bool":
                    is_bool_gate = True
            if is_bool_gate:
                fn = self._enclosing(node)
                fn_key = f"{self._rel}:{fn or '__module__'}"
                if fn_key not in _N81_ALLOW_LIST:
                    self.violations.append(_Violation(
                        file=relpath(self._src_path, SRC.parent),
                        lineno=node.lineno,
                        fn_name=fn or "<module>",
                    ))
        self.generic_visit(node)


def _collect_n81_violations() -> list[_Violation]:
    """Walk banned modules for raw-column hipaa branch conditions."""
    all_violations: list[_Violation] = []

    for module_rel in _N81_BANNED_MODULES:
        module_path = SRC / module_rel
        if module_path.is_dir():
            # iter_src_files walks the subtree, skips __pycache__, sorted.
            paths = list(iter_src_files(module_rel))
        elif module_path.with_suffix(".py").exists():
            paths = [module_path.with_suffix(".py")]
        else:
            paths = []

        for py_path in paths:
            # Skip triage_logging.py — the SSOT itself reads the raw column
            # inside is_account_hipaa / account_hipaa_effective by design.
            if py_path.name == "triage_logging.py":
                continue
            tree = parse_module(py_path)  # None on syntax/decode error → skip
            if tree is None:
                continue
            rel_key = _rel_key(py_path)
            visitor = _N81Violation(rel_key, py_path)
            visitor._tag_parents(tree, None)
            visitor.visit(tree)
            all_violations.extend(visitor.violations)

    return all_violations


def test_no_raw_hipaa_column_phi_decision_gate():
    """No raw acct.get('hipaa') / acct['hipaa'] branch used as a PHI-decision
    gate in per-account PHI layers (incl. jobs/) outside the SSOT definitions.

    N-81 class fix: a raw-column read drops the system flag (_hipaa_mode).
    On a system-HIPAA install where acct['hipaa']=0, such a gate is False
    and the system-HIPAA treatment is silently skipped.

    Any new site that reads the raw column to gate PHI handling (redact /
    audit / egress / feature access) MUST route through is_account_hipaa()
    instead, or be added to _N81_ALLOW_LIST with a justification.

    KNOWN RESIDUAL (PD#6, documented like the N-77 getattr/rebind residual):
    the visitor inspects the raw read INSIDE an ``If.test`` / ``IfExp`` / a
    boolean ``Return`` only. A var-aliased read then branched on
    (``h = acct.get("hipaa"); if h: redact()`` or ``h = bool(acct["hipaa"]);
    if h and x:``) is NOT caught — the assignment is not a branch condition and
    the later ``if h:`` reads a plain Name. No such site exists today; a future
    tightening would track ``Name = <raw hipaa read>`` assignments and treat a
    branch on that Name as a violation. The in-branch + return-gate shapes are
    where every real divergence in this class has appeared.
    """
    violations = _collect_n81_violations()
    if violations:
        lines = [
            f"\n  {v.file}:{v.lineno} (in {v.fn_name!r})"
            for v in violations
        ]
        pytest.fail(
            "Raw acct[hipaa]/.get('hipaa') used as PHI-decision branch — "
            "route through is_account_hipaa(acct) to fold the system flag, "
            "or add to _N81_ALLOW_LIST with justification:"
            + "".join(lines)
        )


def test_n81_pin_covers_jobs_dir():
    """The N-81 scanner must include the jobs/ directory.

    The N-77 pin never scanned jobs/, which is how embedding_reindex.py:248
    (the N-81 reliability site) survived undetected. This test ensures jobs/
    is in the scanned scope so a regression is caught immediately.
    """
    assert any(
        m.startswith("jobs") for m in _N81_BANNED_MODULES
    ), "jobs/ must be in _N81_BANNED_MODULES — the N-77 pin missed it"
    # Also verify the directory actually exists and is scanned.
    jobs_path = SRC / "jobs"
    assert jobs_path.is_dir(), f"jobs/ dir not found at {jobs_path}"
    # Route the jobs/ walk through the shared harness walker (R5b) — a raw
    # ``jobs_path.rglob("*.py")`` here is a SOURCE-tree walk, and the
    # substring→AST adoption meta-pin (run18) flags it even though this file
    # already imports the harness for ``iter_src_files``/``SRC_ROOT``.
    py_files = list(iter_src_files(subdir="jobs"))
    assert len(py_files) > 0, "jobs/ dir has no .py files — something is wrong"


# ---------------------------------------------------------------------------
# N-81 behavioural test — the headline HIPAA fix (profile.py:3174 gate)
#
# Before N-81: the gate was ``acct.get('hipaa')`` (raw column). On a
# system-HIPAA install with acct['hipaa']=0 that evaluates False → the
# record_access_event call is skipped → the non-owner PHI touch is not
# logged to the access_log table.
#
# After N-81: the gate is is_account_hipaa(acct).  With _hipaa_mode=True
# and acct['hipaa']=0, is_account_hipaa returns True → the call fires.
#
# We test the gate condition in isolation (not the full HTTP handler) to
# avoid the full session/DB setup cost. We drive the real is_account_hipaa
# helper — NOT a mock — so the test pins the actual SSOT behaviour.
# ---------------------------------------------------------------------------

def test_n81_system_hipaa_acct_col_zero_fires_access_gate():
    """is_account_hipaa returns True when system flag is on AND acct['hipaa']=0.

    This is the exact scenario that profile.py:3174 was wrong about.
    Before N-81 the inline gate used acct.get('hipaa') which returned 0
    (falsy) and skipped the audit write.  After N-81 the gate uses
    is_account_hipaa which correctly folds the system flag.
    """
    import email_triage.triage_logging as _tl
    from email_triage.triage_logging import is_account_hipaa
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = True  # system HIPAA ON
        acct = {"id": 1, "user_id": 10, "hipaa": 0}  # per-account flag OFF
        actor_user_id = 99  # non-owner

        # The old gate: acct.get("hipaa") → 0 (falsy) → gate is False
        old_gate = bool(acct.get("hipaa"))
        assert old_gate is False, "old gate (raw column) is False — the bug"

        # The new gate: is_account_hipaa(acct) → True (system flag wins)
        new_gate = (actor_user_id != acct["user_id"] and is_account_hipaa(acct))
        assert new_gate is True, (
            "new gate must be True: system-HIPAA + non-owner "
            "→ access-event MUST be emitted"
        )
    finally:
        _tl._hipaa_mode = orig


def test_n81_no_system_hipaa_acct_col_zero_no_fire():
    """Without the system flag AND acct['hipaa']=0, the gate is correctly False.

    Sanity check: the fix does not emit an access row on a non-HIPAA install
    for a non-HIPAA account (no false positives).
    """
    import email_triage.triage_logging as _tl
    from email_triage.triage_logging import is_account_hipaa
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False  # system HIPAA OFF
        acct = {"id": 1, "user_id": 10, "hipaa": 0}  # per-account flag OFF
        actor_user_id = 99  # non-owner

        new_gate = (actor_user_id != acct["user_id"] and is_account_hipaa(acct))
        assert new_gate is False, (
            "gate must be False: no system flag + no per-account flag → not HIPAA"
        )
    finally:
        _tl._hipaa_mode = orig


def test_n81_per_account_hipaa_on_system_off_fires():
    """Per-account hipaa=1 still fires the gate even with system flag off.

    Regression check: the fix must not accidentally break the base case
    where the per-account column IS set (non-HIPAA install, one HIPAA acct).
    """
    import email_triage.triage_logging as _tl
    from email_triage.triage_logging import is_account_hipaa
    orig = _tl._hipaa_mode
    try:
        _tl._hipaa_mode = False  # system HIPAA OFF
        acct = {"id": 1, "user_id": 10, "hipaa": 1}  # per-account ON
        actor_user_id = 99  # non-owner

        new_gate = (actor_user_id != acct["user_id"] and is_account_hipaa(acct))
        assert new_gate is True, (
            "per-account hipaa=1 must fire the gate regardless of system flag"
        )
    finally:
        _tl._hipaa_mode = orig


def test_n81_pin_has_teeth():
    """The N-81 raw-column visitor MUST flag a synthetic raw acct.get('hipaa')
    PHI-decision gate (and the acct['hipaa'] subscript + return-not-bool shapes)
    and MUST NOT flag the SSOT call — proves the structural ban isn't vacuous
    (a ban that catches nothing is theatre; the DA flags teeth-less pins).
    """
    _fake = SRC / "actions" / "_n81_teeth_fake.py"  # never written; path-only

    def _run(code: str):
        tree = ast.parse(code)
        v = _N81Violation("actions/_n81_teeth_fake", _fake)
        v._tag_parents(tree, None)
        v.visit(tree)
        return v.violations

    # POSITIVE — raw .get('hipaa') in an If.test must be flagged
    assert _run(
        "def f(acct):\n"
        "    if acct.get('hipaa'):\n"
        "        redact()\n"
    ), "N-81 pin failed to flag a raw acct.get('hipaa') If gate — NO TEETH"

    # POSITIVE — acct['hipaa'] subscript in an If.test must be flagged
    assert _run(
        "def f(acct):\n"
        "    if acct['hipaa'] and other:\n"
        "        redact()\n"
    ), "N-81 pin failed to flag a raw acct['hipaa'] subscript gate"

    # POSITIVE — return not bool(account.get('hipaa')) gate must be flagged
    assert _run(
        "def g(account):\n"
        "    return not bool(account.get('hipaa'))\n"
    ), "N-81 pin failed to flag a return-not-bool(account['hipaa']) gate"

    # NEGATIVE — routing through the SSOT must NOT be flagged
    assert not _run(
        "def f(acct):\n"
        "    if is_account_hipaa(acct):\n"
        "        redact()\n"
    ), "N-81 pin FALSE-flagged the SSOT call is_account_hipaa(acct)"

    # NEGATIVE — a display-only dict literal value is NOT a branch gate
    assert not _run(
        "def f(acct):\n"
        "    ctx = {'hipaa': bool(acct.get('hipaa'))}\n"
        "    return ctx\n"
    ), "N-81 pin FALSE-flagged a display-only dict-literal hipaa value"
