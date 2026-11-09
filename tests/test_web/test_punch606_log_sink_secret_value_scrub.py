"""Punch 606 (X1): the ``log_entries`` sink strips secret VALUES, not just keys.

Before the fix the HMAC-chained sink stripped secrets by KEY only:
``redact_persisted_extra`` placeholdered a ``SECRET_TOKEN_KEYS`` key, but a
secret riding INSIDE an allow-listed value (``error="... access_token=ya29..."``)
or inlined into the message text (02352e1ab's ``code=<otp>``) persisted
verbatim in both logging modes, into a table that cannot be expunged without
breaking the chain (6-year retention).

Now one funnel, ``triage_logging.scrub_persisted_log_text``, runs over the
message and every string extra value at BOTH chain writers
(``SQLiteLogHandler.emit`` and ``db/audit.insert_log_entry``) BEFORE the hash
preimage, so the stored row and the hashed row are the same scrubbed text and
``verify_log_chain`` still passes (PD-12).

SCOPE CAVEAT (what a green run does NOT prove): the scrub is the token-SHAPE
strip of ``_secret_scrub`` (``key=value`` / ``key='value'`` / ``"key": "value"``
for each SECRET_TOKEN_KEYS key). A secret with no key name next to it, or in
a ``key: value`` (colon, unquoted) shape, is not detected. The console and
file handlers (stderr/journald) are a separate leg and are not covered here.
"""
from __future__ import annotations

import ast
import json
import logging

import pytest

from _pin_harness import assert_pin_has_teeth, walk_src
from email_triage import triage_logging
from email_triage.triage_logging import SQLiteLogHandler, get_logger

SECRET = "ya29.SECRETVALUE606"
OTP = "482913"


@pytest.fixture
def persisted_log(db):
    """A real SQLiteLogHandler on the test DB, on the ``email_triage`` root
    logger where production attaches it. Yields a reader of every row."""
    root = logging.getLogger("email_triage")
    handler = SQLiteLogHandler(db, flush_interval=1, shares_app_connection=True)
    prior_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    try:
        yield lambda: [dict(r) for r in db.execute(
            "SELECT id, ts, level, logger, message, extra_json, prev_hash, "
            "row_hash, hash_alg, master_key_version FROM log_entries ORDER BY id").fetchall()]
    finally:
        root.removeHandler(handler)
        root.setLevel(prior_level)


@pytest.fixture(params=[False, True], ids=["standard", "hipaa"])
def hipaa(request, monkeypatch):
    monkeypatch.setattr(triage_logging, "_hipaa_mode", request.param)
    return request.param


def _row(rows, needle):
    hits = [r for r in rows if needle in (r["message"] or "")]
    assert hits, f"no persisted row carries {needle!r}: the rig did not see the emit"
    return hits[-1]


def test_secret_value_in_an_allow_listed_extra_never_persists(persisted_log, hipaa):
    get_logger("web.triage_runner").error(
        "Triage error for message 606a",
        error=f"token refresh failed: access_token={SECRET}",
    )
    row = _row(persisted_log(), "606a")
    assert SECRET not in row["extra_json"]
    # ``error`` is in _PERSIST_SAFE_KEYS, so its value survives in both
    # modes: the diagnostic stays, only the token is gone.
    assert json.loads(row["extra_json"])["error"] == (
        "token refresh failed: access_token=[REDACTED]")


def test_secret_inlined_into_the_message_never_persists(persisted_log, hipaa):
    get_logger("web.auth").warning(f"606b logging OTP (dev mode) code={OTP}")
    row = _row(persisted_log(), "606b")
    assert OTP not in row["message"]
    assert row["message"] == "606b logging OTP (dev mode) code=[REDACTED]"


def test_raw_stdlib_logger_message_args_are_scrubbed(persisted_log, hipaa):
    logging.getLogger("email_triage.test606").warning("606c password=%s", "hunter2-606")
    row = _row(persisted_log(), "606c")
    assert "hunter2-606" not in row["message"]


def test_hash_covers_the_scrubbed_row_and_the_chain_verifies(persisted_log, db, hipaa):
    from email_triage.web.db import compute_log_row_hash, verify_log_chain

    log = get_logger("web.triage_runner")
    log.error(f"606d code={OTP}", error=f"access_token={SECRET}")
    log.info("606d plain follow-up row")
    row = _row(persisted_log(), "606d code")
    assert OTP not in row["message"] and SECRET not in row["extra_json"]
    recomputed = compute_log_row_hash(
        row["prev_hash"], row["ts"], row["level"], row["logger"],
        row["message"], row["extra_json"],
        hash_alg=row["hash_alg"], master_key_version=row["master_key_version"],
    )
    assert recomputed == row["row_hash"], "hash preimage != stored (scrub after hash)"
    assert verify_log_chain(db)["first_break_id"] is None


def test_insert_log_entry_routes_message_and_extras_through_the_funnel(db):
    from email_triage.db.audit import insert_log_entry

    insert_log_entry(db, "2026-10-10T00:00:00+00:00", "INFO", "email_triage.t606",
                     f"606e code={OTP}", extra={"error": f"access_token={SECRET}", "n": 3})
    db.commit()
    row = db.execute("SELECT message, extra_json FROM log_entries "
                     "WHERE logger = 'email_triage.t606'").fetchone()
    assert OTP not in row["message"] and SECRET not in row["extra_json"]
    assert json.loads(row["extra_json"])["n"] == 3   # non-str values untouched


def test_both_chain_writers_scrub_and_the_chain_verifies(persisted_log, db):
    """Lead condition (PD-12): a secret-bearing row through BOTH writers, in
    one chain, then the verifier recomputes over the stored text."""
    from email_triage.db.audit import insert_log_entry
    from email_triage.web.db import verify_log_chain

    get_logger("web.x").error(f"606g emit code={OTP}", error=f"access_token={SECRET}")
    insert_log_entry(db, "2026-10-10T00:00:01+00:00", "INFO", "email_triage.t606g",
                     f"606g insert code={OTP}", extra={"error": f"access_token={SECRET}"})
    db.commit()
    # (No emit after the insert: the handler caches its own tail, by design
    # the only in-process writer; insert_log_entry reads the DB tail.)
    rows = [r for r in persisted_log() if "606g" in (r["message"] or "")]
    assert len(rows) == 2
    for r in rows:
        assert OTP not in r["message"] and SECRET not in r["extra_json"]
    assert verify_log_chain(db)["first_break_id"] is None


@pytest.mark.parametrize("text", [
    "Gmail push returned status code=503",
    "exit code=2 from podman",
    "HTTP status_code=500",
    "error code=AADSTS50076 from Azure",
    "line one\nline two keeps its newline",
    "x" * 900,                                       # no truncation on the chain
])
def test_diagnostic_text_persists_unchanged(persisted_log, text):
    logging.getLogger("email_triage.test606diag").warning("%s", text)
    rows = [r for r in persisted_log() if r["logger"] == "email_triage.test606diag"]
    assert rows[-1]["message"] == text


def test_an_already_scrubbed_value_is_not_rewritten(persisted_log):
    from email_triage._errfmt import scrub_error_for_persist

    pre = scrub_error_for_persist(f"refresh failed access_token={SECRET} code='{OTP}'")
    get_logger("web.x").error("606f", error=pre)
    row = _row(persisted_log(), "606f")
    assert json.loads(row["extra_json"])["error"] == pre
    assert "]]" not in row["extra_json"]


@pytest.mark.parametrize("fmt_name", ["_JsonFormatter", "_TextFormatter"])
def test_console_formatters_use_the_same_funnel(fmt_name, hipaa):
    """stderr/journald is retained too: both formatters scrub the message, every
    extra value and the exc_info text through the same funnel."""
    fmt = getattr(triage_logging, fmt_name)()
    captured = []

    class _Cap(logging.Handler):
        def emit(self, record):
            captured.append(fmt.format(record))

    lg = logging.getLogger("email_triage.test606fmt")
    h = _Cap()
    lg.addHandler(h)
    try:
        get_logger("test606fmt").error(
            f"606h code={OTP}", error=f"access_token={SECRET}",
            exc_info=RuntimeError(f"refresh_token={SECRET}x"))
    finally:
        lg.removeHandler(h)
    assert captured, "the capture handler saw no record"
    assert OTP not in captured[-1] and SECRET not in captured[-1]


# ---------------------------------------------------------------------------
# The SSOT shapes (_secret_scrub): before/after table in the report.
# ---------------------------------------------------------------------------

_SHAPE_TABLE = [
    (f"(dev mode) code={OTP}", "(dev mode) code=[REDACTED]"),
    (f"access_token={SECRET}", "access_token=[REDACTED]"),
    ("Gmail push returned status code=503", "Gmail push returned status code=503"),
    ("exit code=2 from podman", "exit code=2 from podman"),
    ("http code=404 from upstream", "http code=404 from upstream"),
    ("error code=AADSTS50076 from Azure", "error code=AADSTS50076 from Azure"),
    ("return code=-15", "return code=-15"),
    ("HTTP status_code=500", "HTTP status_code=500"),
    (f"{{'code': '{OTP}'}}", "{'code': '[REDACTED]'}"),
    (f"code='{OTP}'", "code='[REDACTED]'"),
    # Panel B3 hipaa-sme F2: the diagnostic exemption keys on the VALUE's shape
    # too. A 6-digit value after `status` is a plausible OTP, so it is redacted
    # (this arm expected it kept before the fold); a 3-digit status is kept.
    (f"status code='{OTP}' then code={OTP}", "status code='[REDACTED]' then code=[REDACTED]"),
    ("status code='503' then done", "status code='503' then done"),
    (f"OTP error code={OTP}", "OTP error code=[REDACTED]"),
    (f"Error code={OTP}", "Error code=[REDACTED]"),
    ("login failed, error code=4/0AX4XfWh-abc", "login failed, error code=[REDACTED]"),
    ("Authorization=Bearer ya29.abc def", "Authorization=[REDACTED] def"),
    ("password='hunter2", "password=[REDACTED]"),
]


@pytest.mark.parametrize("text, expected", _SHAPE_TABLE)
def test_secret_token_shapes(text, expected):
    from email_triage._secret_scrub import redact_secret_tokens
    assert redact_secret_tokens(text) == expected


#: Property: scrub(scrub(x)) == scrub(x) over the WHOLE shape table, plus
#: already-redacted inputs.
@pytest.mark.parametrize("text", [t for t, _ in _SHAPE_TABLE] + [
    f"access_token={SECRET} tail", "code=[REDACTED]",
    "access_token=[REDACTED] tail", "{'password': '[REDACTED]'}",
    "Authorization=Bearer ya29.abc", f"password=\"{OTP}\"",
])
def test_scrub_is_idempotent(text):
    from email_triage._secret_scrub import redact_secret_tokens, scrub_secrets_from_text
    once = redact_secret_tokens(text)
    assert redact_secret_tokens(once) == once
    s1 = scrub_secrets_from_text(text)
    assert scrub_secrets_from_text(s1) == s1


def test_persist_scrub_keeps_its_collapse_and_cap():
    """``scrub_secrets_from_text`` (the DB error-column funnel) still collapses
    whitespace and caps at SECRET_SCRUB_MAX_LEN; only the log sink skips those."""
    from email_triage._secret_scrub import SECRET_SCRUB_MAX_LEN, scrub_secrets_from_text
    assert scrub_secrets_from_text("a\nb  c") == "a b c"
    assert len(scrub_secrets_from_text("y" * 2000)) == SECRET_SCRUB_MAX_LEN
    assert scrub_secrets_from_text("") is None


# ---------------------------------------------------------------------------
# Structural pin: every chain writer routes message + extras through the funnel.
# ---------------------------------------------------------------------------

_FUNNEL = "scrub_persisted_log_text"
_EXTRA_FUNNEL = "redact_persisted_extra"


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _writes_log_entries(fn: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Constant) and isinstance(n.value, str)
        and "INTO log_entries" in n.value
        for n in ast.walk(fn)
    )


def _funnel_bound_names(fn: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(fn):
        if (isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                and _callee(n.value) == _FUNNEL):
            out |= {t.id for t in n.targets if isinstance(t, ast.Name)}
    return out


def _chain_writer_violations(tree: ast.AST) -> list[str]:
    bad: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _writes_log_entries(fn):
            continue
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        hash_calls = [c for c in calls if _callee(c) == "compute_log_row_hash"]
        if not hash_calls:
            continue   # an unchained sentinel/gap row: fixed text, no preimage
        name = fn.name
        if not any(_callee(c) == _EXTRA_FUNNEL for c in calls):
            bad.append(f"{name}: extras not routed through {_EXTRA_FUNNEL}")
        bound = _funnel_bound_names(fn)
        for c in hash_calls:
            msg = c.args[4] if len(c.args) > 4 else next(
                (k.value for k in c.keywords if k.arg == "message"), None)
            if not (isinstance(msg, ast.Name) and msg.id in bound):
                bad.append(f"{name}: hashed message is not the {_FUNNEL} result")
        for c in calls:
            if _callee(c) == "getMessage":
                parent = getattr(c, "_ph_parent", None)
                if not (isinstance(parent, ast.Call) and _callee(parent) == _FUNNEL):
                    bad.append(f"{name}: raw getMessage() outside {_FUNNEL}")
        for n in ast.walk(fn):
            if isinstance(n, ast.Attribute) and n.attr == "msg" and isinstance(n.ctx, ast.Load):
                bad.append(f"{name}: raw record.msg read")
    return bad


def test_every_chain_writer_routes_through_the_funnel():
    writers, bad = [], []
    for _path, rel, tree in walk_src():
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and _writes_log_entries(fn):
                if any(isinstance(c, ast.Call) and _callee(c) == "compute_log_row_hash"
                       for c in ast.walk(fn)):
                    writers.append(f"{rel}:{fn.name}")
        bad += [f"{rel}: {v}" for v in _chain_writer_violations(tree)]
    # Prove the input is in the set the pin acts on.
    assert "triage_logging.py:emit" in writers
    assert "db/audit.py:insert_log_entry" in writers
    assert bad == []


def test_redact_persisted_extra_value_scrubs_through_the_funnel():
    import inspect
    tree = ast.parse(inspect.getsource(triage_logging.redact_persisted_extra))
    assert any(isinstance(n, ast.Call) and _callee(n) == _FUNNEL for n in ast.walk(tree))


def test_chain_writer_pin_has_teeth():
    bad = (
        "def emit(self, record):\n"
        "    extra_json = json.dumps(redact_persisted_extra(extra, hipaa=h))\n"
        "    row_hash = compute_log_row_hash(p, ts, lvl, name, record.getMessage(), extra_json)\n"
        "    conn.execute('INSERT INTO log_entries (message) VALUES (?)', (record.getMessage(),))\n"
    )
    good = (
        "def emit(self, record):\n"
        "    message = scrub_persisted_log_text(record.getMessage())\n"
        "    extra_json = json.dumps(redact_persisted_extra(extra, hipaa=h))\n"
        "    row_hash = compute_log_row_hash(p, ts, lvl, name, message, extra_json)\n"
        "    conn.execute('INSERT INTO log_entries (message) VALUES (?)', (message,))\n"
    )
    no_extra_funnel = good.replace("redact_persisted_extra(extra, hipaa=h)", "extra")
    assert_pin_has_teeth(_chain_writer_violations, bad, good)
    assert_pin_has_teeth(_chain_writer_violations, no_extra_funnel)

def test_container_extras_are_scrubbed_at_every_depth():
    """Panel B3 hipaa-sme (N-338 ruling): a dict/list extra was passed through whole,
    so a token inside it reached extra_json unscrubbed."""
    out = triage_logging.redact_persisted_extra(
        {"resp": {"access_token": "ya29.SECRETSECRET", "note": "code=482913 sent",
                  "items": ["ok", {"refresh_token": "1//abc"}]}},
        hipaa=False,
    )
    flat = repr(out)
    assert "ya29.SECRETSECRET" not in flat and "1//abc" not in flat, out
    assert "482913" not in flat, out
    assert out["resp"]["items"][0] == "ok", out


def test_container_past_the_depth_cap_is_replaced_whole():
    deep = cur = {}
    for _ in range(12):
        cur["n"] = {}
        cur = cur["n"]
    cur["access_token"] = "ya29.DEEPSECRET"
    out = triage_logging.scrub_persisted_log_text(deep)
    assert "ya29.DEEPSECRET" not in repr(out)
