"""Punch 595: a login code never reaches a persisted log sink.

Before the fix, with no SMTP host configured, ``POST /login/email`` ran
``log.warning("No SMTP configured — logging OTP (dev mode) code=%s" % code)``.
The code was formatted into the message BEFORE the call, so neither the
``code`` kwarg redaction (``code`` is a SECRET_TOKEN_KEYS key) nor the HIPAA
positional-arg gate could see it, and ``SQLiteLogHandler`` wrote it in clear
into ``log_entries`` (HMAC-chained, 6-year retention). No dev flag, no HIPAA
guard: HIPAA mode issued and persisted codes the same way (H-05 refuses OTP
only at /login/verify, and only for a user who already has a passkey or
recovery code; a bootstrap user completes OTP login in HIPAA mode).

Now: no SMTP host -> refused before a code is minted, unless
``smtp.dev_console_otp`` is set on a non-HIPAA process, which prints the code to
stderr only. The behavioural tests drive the real handler and the real logger
tree into a real ``SQLiteLogHandler`` on the test DB.
"""
from __future__ import annotations

import ast
import logging
from types import SimpleNamespace

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    iter_src_files,
    parse_module,
    relpath,
)
from email_triage import triage_logging
from email_triage.triage_logging import SQLiteLogHandler, get_logger

CODE = "735194"


@pytest.fixture
def persisted_log(db):
    """A real SQLiteLogHandler on the test DB, attached where production
    attaches it (the ``email_triage`` root logger). Yields a reader that
    returns every ``(message, extra_json)`` row written."""
    root = logging.getLogger("email_triage")
    handler = SQLiteLogHandler(db, flush_interval=1, shares_app_connection=True)
    prior_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    try:
        yield lambda: [tuple(r) for r in db.execute(
            "SELECT message, extra_json FROM log_entries").fetchall()]
    finally:
        root.removeHandler(handler)
        root.setLevel(prior_level)


@pytest.fixture
def fixed_code(monkeypatch):
    from email_triage.web.routers.ui import users as users_mod
    monkeypatch.setattr(users_mod, "generate_otp", lambda: CODE)
    return CODE


def _rows_with_code(rows):
    return [r for r in rows if CODE in (r[0] or "") or CODE in (r[1] or "")]


def _otp_rows(db, email):
    return db.execute("SELECT COUNT(*) FROM otp_codes WHERE email = ?",
                      (email,)).fetchone()[0]


def test_the_sink_rig_can_see_a_row(persisted_log):
    """The rig can PASS and FAIL: a record from the auth logger lands in
    log_entries, so an absent code below is absence, not a dead sink."""
    get_logger("web.auth").warning("sink probe 595")
    assert any("sink probe 595" in (m or "") for m, _ in persisted_log())


def test_dev_console_code_reaches_stderr_and_never_log_entries(
    client, db, admin_user, persisted_log, fixed_code, capsys,
):
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200
    assert "6-digit code" in resp.text
    assert CODE in capsys.readouterr().err
    assert _rows_with_code(persisted_log()) == []
    assert _otp_rows(db, admin_user["email"]) == 1


def test_no_smtp_and_no_flag_is_refused_with_no_code_anywhere(
    client, db, admin_user, persisted_log, fixed_code, capsys,
):
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200
    assert "Sign-in codes can" in resp.text and "Traceback" not in resp.text
    assert CODE not in capsys.readouterr().err
    assert _rows_with_code(persisted_log()) == []
    assert _otp_rows(db, admin_user["email"]) == 0
    # The operator-facing reason is on the record (without any code).
    assert any("no SMTP host is configured" in (m or "") for m, _ in persisted_log())


def test_hipaa_mode_refuses_the_dev_flag_at_request_time(
    client, db, admin_user, persisted_log, fixed_code, capsys, monkeypatch,
):
    """HIPAA can be switched on at runtime, after a config with the flag
    loaded: the request-time check refuses it."""
    monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200
    assert "Sign-in codes can" in resp.text
    assert CODE not in capsys.readouterr().err
    assert _rows_with_code(persisted_log()) == []
    assert _otp_rows(db, admin_user["email"]) == 0


def test_dev_console_refuses_a_user_with_a_hipaa_account(
    client, db, admin_user, persisted_log, fixed_code, capsys,
):
    """HIPAA risk 4 (operator ruling 2026-11-07): install-wide HIPAA mode OFF,
    console flag ON, but the user owns a HIPAA-flagged mailbox. No code is
    minted or printed; the user gets the no-delivery refusal."""
    from email_triage.web.db import create_email_account
    create_email_account(
        db, admin_user["id"], "Study mailbox", "imap", {"host": "x.invalid"},
        hipaa=True,
    )
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200
    assert "Sign-in codes can" in resp.text
    assert "6-digit code" not in resp.text
    assert CODE not in capsys.readouterr().err
    assert _rows_with_code(persisted_log()) == []
    assert _otp_rows(db, admin_user["email"]) == 0
    # hipaa-sme r14 S3: the refusal leaves a login-failure audit row.
    assert _console_refusal_rows(db, admin_user["email"]) == 1


def _console_refusal_rows(db, email):
    return db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type='login_otp_request' "
        "AND outcome='failure' AND detail='console_otp_refused' AND email=?",
        (email,),
    ).fetchone()[0]


def test_dev_console_refuses_a_non_admin_user(
    client, db, regular_user, fixed_code, capsys,
):
    """Operator ruling 2026-11-07: console OTP is admin-only ("users would
    never have a need"), even with no HIPAA-flagged account in reach."""
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": regular_user["email"]})
    assert resp.status_code == 200
    assert "Sign-in codes can" in resp.text
    assert CODE not in capsys.readouterr().err
    assert _otp_rows(db, regular_user["email"]) == 0
    assert _console_refusal_rows(db, regular_user["email"]) == 1


def test_dev_console_refuses_an_admin_who_is_a_hipaa_delegate(
    client, db, admin_user, regular_user, fixed_code, capsys,
):
    """db-sme r14 SHOULD 5: reach counts delegate access, not just ownership."""
    from email_triage.db.accounts import add_account_delegate
    from email_triage.web.db import create_email_account
    aid = create_email_account(
        db, regular_user["id"], "Their study mailbox", "imap",
        {"host": "x.invalid"}, hipaa=True,
    )
    assert add_account_delegate(db, aid, admin_user["id"], regular_user["id"])
    db.commit()
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert "Sign-in codes can" in resp.text
    assert CODE not in capsys.readouterr().err
    assert _otp_rows(db, admin_user["email"]) == 0


def test_hipaa_user_with_a_hardware_key_still_reaches_the_picker(
    client, db, admin_user, fixed_code, capsys, monkeypatch,
):
    """DA r14 SHOULD 1: the risk-4 refusal sits BELOW the  hardware-key
    picker (which mints no code), so a HIPAA user with a security key on a
    console-delivery install is not locked out at the email step."""
    import email_triage.web.db_auth_helpers as h
    from email_triage.web.db import create_email_account
    create_email_account(
        db, admin_user["id"], "Study mailbox", "imap", {"host": "x.invalid"},
        hipaa=True,
    )
    monkeypatch.setattr(h, "user_has_active_hardware_key", lambda *_a, **_k: True)
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200
    assert "Sign-in codes can" not in resp.text
    assert CODE not in capsys.readouterr().err
    assert _otp_rows(db, admin_user["email"]) == 0
    # ...and the OTP fallback from the picker is still refused for that user.
    resp = client.post("/login/email?otp_fallback=1", data={"email": admin_user["email"]})
    assert "Sign-in codes can" in resp.text
    assert CODE not in capsys.readouterr().err
    assert _otp_rows(db, admin_user["email"]) == 0


def test_dev_console_still_serves_a_user_with_only_non_hipaa_accounts(
    client, db, admin_user, fixed_code, capsys,
):
    from email_triage.web.db import create_email_account
    create_email_account(
        db, admin_user["id"], "Plain mailbox", "imap", {"host": "x.invalid"},
        hipaa=False,
    )
    client.app.state.config.smtp.dev_console_otp = True
    resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200 and "6-digit code" in resp.text
    assert CODE in capsys.readouterr().err


def test_the_refusal_page_is_identical_for_known_and_unknown_emails(client, admin_user):
    import re
    known = client.post("/login/email", data={"email": admin_user["email"]})
    unknown = client.post("/login/email", data={"email": "nobody@example.test"})
    for r in (known, unknown):
        assert r.status_code == 200
        assert "Sign-in codes can" in r.text
        assert "No account found" not in r.text and "6-digit code" not in r.text
    # Same page modulo per-request tokens (CSRF / nonces).
    strip = lambda t: re.sub(r'(value|content|nonce)="[^"]*"', "", t)  # noqa: E731
    assert strip(known.text) == strip(unknown.text)


def test_smtp_path_is_unchanged(client, db, admin_user, persisted_log, fixed_code, monkeypatch):
    from unittest.mock import patch
    cfg = client.app.state.config.smtp
    cfg.host, cfg.port, cfg.from_addr = "smtp.example.com", 587, "no-reply@example.com"
    monkeypatch.setattr("email_triage.secrets.read_secret", lambda *a, **k: "pw")
    from email_triage.web.routers.ui import users as users_mod
    with patch.object(users_mod, "send_otp_email") as send:
        resp = client.post("/login/email", data={"email": admin_user["email"]})
    assert resp.status_code == 200 and "6-digit code" in resp.text
    assert send.call_args.kwargs["code"] == CODE
    assert _rows_with_code(persisted_log()) == []


@pytest.mark.parametrize("host,flag,hipaa,expected", [
    ("smtp.example.com", False, False, "smtp"),
    ("smtp.example.com", True, True, "smtp"),
    ("", True, False, "console"),
    ("", True, True, "refuse"),
    ("", False, False, "refuse"),
])
def test_delivery_decision(monkeypatch, host, flag, hipaa, expected):
    from email_triage.web.routers.ui.users import _otp_delivery
    monkeypatch.setattr(triage_logging, "_hipaa_mode", hipaa)
    cfg = SimpleNamespace(smtp=SimpleNamespace(host=host, dev_console_otp=flag))
    assert _otp_delivery(cfg) == expected


def test_a_config_without_the_attribute_is_refused(monkeypatch):
    from email_triage.web.routers.ui.users import _otp_delivery
    monkeypatch.setattr(triage_logging, "_hipaa_mode", False)
    assert _otp_delivery(SimpleNamespace(smtp=SimpleNamespace(host=""))) == "refuse"


def test_config_load_refuses_the_flag_in_hipaa_mode(tmp_path):
    from email_triage.config import ConfigError, load_config
    p = tmp_path / "c.yaml"
    p.write_text("logging:\n  hipaa: true\nsmtp:\n  dev_console_otp: true\n",
                 encoding="utf-8")
    with pytest.raises(ConfigError, match="dev_console_otp"):
        load_config(str(p))


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("yes", True), ("false", False), ('"false"', False),
    ("garbage", "refused"), ("", "refused"),
])
def test_config_flag_parse_is_fail_closed(tmp_path, raw, expected):
    """Parsed by the punch-598 strict funnel: an unrecognised or null value is
    refused at load (never silently True)."""
    from email_triage.config import ConfigError, load_config
    p = tmp_path / "c.yaml"
    p.write_text(f"smtp:\n  dev_console_otp: {raw}\n", encoding="utf-8")
    if expected == "refused":
        with pytest.raises(ConfigError):
            load_config(str(p))
    else:
        assert load_config(str(p)).smtp.dev_console_otp is expected


@pytest.mark.parametrize("flag", [True, False])
def test_admin_config_save_round_trips_the_flag(tmp_path, monkeypatch, flag):
    """load(save(x)) == x for the new key: an admin save must not drop it."""
    from email_triage.config import TriageConfig, load_config
    from email_triage.web.routers.ui._shared import _write_config_yaml
    monkeypatch.chdir(tmp_path)
    (tmp_path / "email-triage.yaml").write_text("{}\n", encoding="utf-8")
    cfg = TriageConfig()
    cfg.smtp.dev_console_otp = flag
    _write_config_yaml(cfg)
    assert load_config(str(tmp_path / "email-triage.yaml")).smtp.dev_console_otp is flag


# --- structural pin ---------------------------------------------------------
#
# INVARIANT (count-agnostic): in every src module that touches an OTP /
# recovery-code primitive (discovered by scan, not listed), no log-method call
# references an OTP-named value anywhere in its arguments: not formatted into
# the message (``%``, f-string, ``+``, ``.format``), not as a printf argument,
# not as a keyword value. A code has no business in any log record: every
# ``email_triage.*`` record reaches the HMAC-chained log_entries.
#
# SCOPE CAVEAT: "OTP-named" is by identifier: a name containing the
# underscore-token otp / code / codes / plaintext(s). A code carried under an
# unrelated name (``x = code; log.info(f"{x}")``) is not followed, and a module
# that handles a code without touching a primitive is outside the scope. The
# behavioural tests above are the backstop for the one known path.

_OTP_PRIMITIVES = frozenset({
    "generate_otp", "store_otp", "verify_otp", "send_otp_email",
    "issue_recovery_codes", "consume_recovery_code", "_print_dev_console_otp",
})
_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
})
_NEEDLE_TOKENS = frozenset({"otp", "code", "codes", "plaintext", "plaintexts"})
#: Identifiers that contain a needle token but are never a login code (belt
#: against false positives; the token scan is the primary net).
_NOT_A_CODE = frozenset({
    "status_code", "error_code", "exit_code", "returncode", "http_code", "rcode",
})


def _ident(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _touches_otp(tree: ast.AST) -> bool:
    for n in ast.walk(tree):
        name = (_ident(n) if not isinstance(n, ast.alias) else n.name.split(".")[-1])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = n.name
        if name in _OTP_PRIMITIVES:
            return True
    return False


def _is_needle(name: str) -> bool:
    return name not in _NOT_A_CODE and bool(set(name.lower().split("_")) & _NEEDLE_TOKENS)


def _otp_log_violations(tree: ast.AST, rel: str) -> list[str]:
    out: list[str] = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in _LOG_METHODS):
            continue
        for part in [*call.args, *(k.value for k in call.keywords)]:
            for n in ast.walk(part):
                name = _ident(n)
                if name and _is_needle(name):
                    out.append(f"{rel}:{call.lineno}: log call references {name!r}")
    return out


def test_no_log_call_in_an_otp_module_references_a_code():
    violations: list[str] = []
    scoped: list[str] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None or not _touches_otp(tree):
            continue
        rel = relpath(path)
        scoped.append(rel)
        violations += _otp_log_violations(tree, rel)
    # The scope discovery must find the OTP handler modules it exists for.
    assert {"web/routers/ui/users.py", "web/auth.py", "web/mfa.py"} <= set(scoped), scoped
    assert violations == [], "\n".join(violations)


def test_no_secret_named_value_is_interpolated_into_a_message_anywhere_in_src():
    """db-sme / hipaa-sme retro (punch 595): the sink persists
    ``record.getMessage()`` raw in BOTH modes, and only ``extra`` is scrubbed
    (``code`` IS a SECRET_TOKEN_KEYS key -- that strip is why the old author
    inlined it). So across ALL of src, no raise or log message may interpolate
    a value named in SECRET_TOKEN_KEYS by f-string, ``%``, ``+`` or ``.format``,
    nor pass one as a printf argument (the N-338 positional gate redacts only in
    HIPAA mode). Same funnel as the widened N-475 PHI pin, other name set.
    Measured: HEAD has exactly one hit (web/routers/ui/users.py:297 ``code``);
    this tree has none."""
    from _pin_harness import message_interpolation_offenders, walk_src
    from email_triage._secret_scrub import SECRET_TOKEN_KEYS
    hits, scanned = [], 0
    for _p, rel, tree in walk_src():
        scanned += 1
        hits += [f"{rel}:{ln} {kind} interpolates {names}" for ln, kind, names
                 in message_interpolation_offenders(tree, SECRET_TOKEN_KEYS, printf_args=True)]
    assert scanned > 100
    assert hits == [], "\n".join(hits)


def test_secret_message_pin_has_teeth():
    from _pin_harness import message_interpolation_offenders
    from email_triage._secret_scrub import SECRET_TOKEN_KEYS
    det = lambda t: message_interpolation_offenders(  # noqa: E731
        t, SECRET_TOKEN_KEYS, printf_args=True)
    for bad in (
        'log.warning("No SMTP configured code=%s" % code)',  # the 595 site
        'log.info(f"token {access_token}")',
        'log.error("pw " + password)',
        'log.info("key {}".format(cfg.api_key))',
        'log.warning("code %s", code)',                      # printf arg
        'raise RuntimeError("secret=%s" % secret)',
    ):
        assert_pin_has_teeth(det, bad_source=bad)
    for good in (
        'log.info("http %s" % status_code)',
        'log.warning("refused", code=code)',   # kwarg: stripped by the token filter
        'log.info("static text")',
    ):
        assert not det(ast.parse(good)), good


def test_otp_log_pin_has_teeth():
    detector = lambda t: _otp_log_violations(t, "web/routers/ui/users.py")  # noqa: E731
    # The exact defect this row fixed.
    assert_pin_has_teeth(
        detector,
        bad_source='log.warning("No SMTP configured code=%s" % code, email=email)\n',
        good_source='log.warning("OTP login refused: no SMTP host", email=email)\n',
    )
    for bad in (
        'log.info(f"otp {otp_code}")\n',
        'log.error("code %s", code)\n',
        'log.warning("x", value=plaintexts[0])\n',
        'logger.debug("sent " + login_code)\n',
        'log.info("x {}".format(recovery_codes))\n',
    ):
        assert_pin_has_teeth(detector, bad_source=bad)
    # An HTTP status code is not a login code.
    assert not detector(ast.parse('log.info("http", status_code=resp.status_code)\n'))
