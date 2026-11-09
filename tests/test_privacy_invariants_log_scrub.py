"""Privacy log-scrub invariants (M-9).

Pins:

1. ``triage_logging.TriageLogger._TOKEN_KEYS`` is a superset of the
   canonical token-shape key set. New keys are fine (more redaction);
   removals fail the test.
2. ``triage_logging.TriageLogger._PHI_KEYS`` is a superset of the
   canonical PHI-shape key set. Same monotonic-superset rule.
3. A draft-reply round-trip with a deterministic embedding backend
   leaves NO embedding payload, NO body excerpt, and NO token-shape
   value in any log record captured at the SQLite-style sink.

Sibling: ``tests/test_log_no_token_leak.py`` (Gmail / O365 OAuth
refresh paths, sentinel-based capture). The M-9 module focuses on
the M-series style-learning ladder specifically.

See ``internal documentation`` for the full operator contract.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from email_triage.triage_logging import TriageLogger


# ---------------------------------------------------------------------------
# Canonical key sets -- what _TOKEN_KEYS / _PHI_KEYS MUST contain
# ---------------------------------------------------------------------------

# Token-shape keys: values are NEVER legitimate log payloads.
# Stripped in BOTH standard and HIPAA modes by ``TriageLogger._sanitise``.
# Pinned subset: the live module set must contain at least these names.
# Adding a new key to the live set is fine -- the test only fails when
# a key is REMOVED.
_CANONICAL_TOKEN_KEYS: frozenset[str] = frozenset({
    "authorization", "access_token", "refresh_token", "id_token",
    "code", "auth_code", "client_secret", "bearer_token",
    "api_key", "password", "smtp_password", "imap_password",
    "session_token",
})

# PHI-shape keys: values may be PHI; stripped in HIPAA mode only.
_CANONICAL_PHI_KEYS: frozenset[str] = frozenset({
    "sender", "senders", "recipients", "subject", "body",
    "body_text", "body_html", "links", "attachment", "attachments",
    "reason", "classification_reason", "headers",
    # census run17 #1 — LLM-over-PHI output keys (pinned as required).
    "raw", "prompt", "completion", "llm_response",
})


# ---------------------------------------------------------------------------
# Sentinels for the round-trip test
# ---------------------------------------------------------------------------

# Body content sentinel -- if it appears in any log payload the test
# fails. Carries no real PII; visually obvious.
_BODY_SENTINEL = "DRAFT_REPLY_BODY_SENTINEL_42_must_not_log"
_INCOMING_BODY_SENTINEL = "INCOMING_BODY_SENTINEL_88_must_not_log"

# Token-shape sentinel -- a 64-char synthetic value that
# substring-matches reliably and is NOT JWT-shaped (so it doesn't
# trip the static-source guard in ``test_security_token_logging.py``).
_TOKEN_SENTINEL = "FAKETOKEN_M9_" + "x" * 48

# Embedding-shape sentinel -- a fixed float vector. If the float
# string ever lands in a log payload, that's the embedding leaking.
_EMBED_VECTOR = [9.99, 8.88, 7.77, 6.66]


# ---------------------------------------------------------------------------
# Invariant 1 + 2: monotonic-superset on _TOKEN_KEYS / _PHI_KEYS
# ---------------------------------------------------------------------------

class TestScrubKeyMonotonicity:
    """The canonical sets are PINNED: future commits may add more keys
    to the live module but may NOT remove keys without operator
    sign-off. The test fails on removal, not on addition."""

    def test_token_keys_superset_of_canonical(self):
        live = set(TriageLogger._TOKEN_KEYS)
        missing = _CANONICAL_TOKEN_KEYS - live
        assert not missing, (
            f"TriageLogger._TOKEN_KEYS dropped these names: {missing}. "
            f"Removing a token-shape key relaxes the privacy posture; "
            f"add the key back or get operator sign-off + update the "
            f"canonical set in tests/test_privacy_invariants_log_scrub.py."
        )

    def test_phi_keys_superset_of_canonical(self):
        live = set(TriageLogger._PHI_KEYS)
        missing = _CANONICAL_PHI_KEYS - live
        assert not missing, (
            f"TriageLogger._PHI_KEYS dropped these names: {missing}. "
            f"Same rule as token keys -- add it back or update the "
            f"canonical set with operator sign-off."
        )

    def test_token_keys_is_frozenset(self):
        """Pin the type so a future commit cannot turn the set mutable
        and pop entries at runtime."""
        assert isinstance(TriageLogger._TOKEN_KEYS, frozenset)

    def test_phi_keys_is_frozenset(self):
        assert isinstance(TriageLogger._PHI_KEYS, frozenset)


# ---------------------------------------------------------------------------
# Invariant 3: draft-reply round-trip leaves no leakage
# ---------------------------------------------------------------------------

class _SQLiteRecorder(logging.Handler):
    """Stand-in for ``SQLiteLogHandler`` that records the exact payload
    the real handler would persist. Mirrors the in-memory capture
    pattern used in ``tests/test_log_no_token_leak.py`` so the test
    does not require a real SQLite connection.

    Mirrors ``_STANDARD_LOG_KEYS`` from ``triage_logging.py``; if that
    set drifts the recorder produces FALSE NEGATIVES (missed extras),
    not false positives -- the bias is conservative.
    """

    _STANDARD_LOG_KEYS = frozenset({
        "name", "msg", "args", "created", "relativeCreated", "exc_info",
        "exc_text", "stack_info", "lineno", "funcName", "pathname",
        "filename", "module", "thread", "threadName", "process",
        "processName", "levelname", "levelno", "message", "msecs",
        "taskName",
    })

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.entries: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        extra: dict = {}
        for key in list(vars(record)):
            if key not in self._STANDARD_LOG_KEYS:
                extra[key] = str(getattr(record, key))
        if record.exc_info and record.exc_info[1] is not None:
            extra["error"] = str(record.exc_info[1])
            extra["error_type"] = type(record.exc_info[1]).__name__
        self.entries.append({
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "extra": extra,
        })


@pytest.fixture
def sqlite_recorder():
    """Attach a SQLite-style recorder to the email_triage logger tree."""
    rec = _SQLiteRecorder()
    root = logging.getLogger("email_triage")
    prior_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(rec)
    try:
        yield rec
    finally:
        root.removeHandler(rec)
        root.setLevel(prior_level)


def _scan_recorder_for_offenders(
    recorder: _SQLiteRecorder,
) -> list[str]:
    """Walk every captured record's message + extras for any sentinel."""
    offenders: list[str] = []
    needles: tuple[str, ...] = (
        _BODY_SENTINEL, _INCOMING_BODY_SENTINEL, _TOKEN_SENTINEL,
    )
    embed_needles = tuple(str(v) for v in _EMBED_VECTOR)
    for e in recorder.entries:
        haystack = e["message"] + " " + repr(e["extra"])
        for needle in needles:
            if needle in haystack:
                offenders.append(
                    f"{e['logger']}:{e['level']}: sentinel "
                    f"{needle!r} leaked: {haystack!r}"
                )
        for needle in embed_needles:
            # Match the float string literal; if it shows up there's
            # an embedding-vector leak.
            if needle in haystack:
                offenders.append(
                    f"{e['logger']}:{e['level']}: embedding-vector "
                    f"value {needle!r} leaked: {haystack!r}"
                )
    return offenders


class _SentinelEmbeddingBackend:
    """Cooperative embedding backend that carries the sentinel vector.

    The vector is the M-9 leakage canary: if it ever lands in a log
    record, the round-trip test will fail loudly and point at the
    code path that did the logging.
    """

    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        return list(_EMBED_VECTOR)


def _make_db() -> sqlite3.Connection:
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(
    conn: sqlite3.Connection, user_id: int,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Operator A Mailbox", "imap", "{}", 0, now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


@pytest.mark.asyncio
async def test_draft_reply_round_trip_no_payload_leaked(
    sqlite_recorder,
):
    """Run the full M-5 ``build_prompt_messages`` path with all four
    layers active and assert NO embedding payload, NO body excerpt,
    and NO token-shape value lands in the captured log entries.

    The sentinel strategy:
      * The incoming message body carries ``_INCOMING_BODY_SENTINEL``
      * The seeded sent_mail_index row carries ``_BODY_SENTINEL`` in
        the body_excerpt column
      * The embedding backend returns a fixed vector
        (``_EMBED_VECTOR``) -- if any of the floats ends up in a
        log record, that's a leak
      * A faux token sentinel lives in extras dicts the helper might
        carelessly emit -- token sanitise should drop those keys

    A green test means: through the full retrieval + prompt-build
    path, the SQLite log sink captured no PHI / token / vector
    payloads.
    """
    import json
    import struct

    from email_triage.actions.draft_reply import build_prompt_messages
    from email_triage.engine.models import Classification, EmailMessage
    from email_triage.web.db import (
        set_rag_sent_index_enabled,
        set_style_learning_master_enabled,
    )

    conn = _make_db()
    user_id = _seed_user(conn)
    acct_id = _seed_account(conn, user_id)

    # All four layers ON.
    set_style_learning_master_enabled(conn, True)
    set_rag_sent_index_enabled(conn, acct_id, enabled=True)

    # Seed the sent-mail index so M-4 retrieval has something to
    # return. The body_excerpt carries the sentinel; the
    # embedding_vec is the cooperating backend's vector packed.
    vec_bytes = struct.pack(
        f"<{len(_EMBED_VECTOR)}f", *_EMBED_VECTOR,
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO sent_mail_index ("
        "account_id, message_id, rfc_message_id, sent_at, "
        "to_addresses, subject, body_excerpt, embedding_vec, "
        "embedding_model, indexed_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            acct_id, "u1", "<m1@example.com>", now,
            json.dumps(["other@example.com"]),
            "Re: anything",
            _BODY_SENTINEL,
            vec_bytes,
            "test-embedder-v0",
            now,
        ),
    )
    conn.commit()

    backend = _SentinelEmbeddingBackend()
    app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=backend,
        embedding_model="test-embedder-v0",
        sqlite_vec_available=False,
    ))
    account = {
        "id": acct_id,
        "hipaa": False,
        "config": {"style_learning_enabled": True},
    }

    incoming = EmailMessage(
        message_id="m-incoming",
        provider="imap",
        sender="other@example.com",
        recipients=["user@example.com"],
        subject="Quick question",
        body_text=_INCOMING_BODY_SENTINEL,
        date=datetime(2026, 5, 8, tzinfo=timezone.utc),
    )
    classification = Classification(
        category="to-respond",
        confidence=0.91,
        reason="Direct reply requested.",
    )

    messages = await build_prompt_messages(
        db=conn, app=app, account=account, user_id=user_id,
        message=incoming, classification=classification,
    )

    # Sanity: the prompt builder DID surface the sentinel body excerpt
    # in the assistant turn (so the test isn't trivially green
    # because the M-4 layer silently broke).
    flat = "\n".join(m["content"] for m in messages)
    assert _BODY_SENTINEL in flat, (
        "Sanity check: M-4 retrieval should have surfaced the seeded "
        "body excerpt into the prompt; if not, the round-trip didn't "
        "exercise the codepath we're guarding against"
    )

    # Now the actual privacy assertion: NONE of the sentinels ended
    # up in any log record.
    offenders = _scan_recorder_for_offenders(sqlite_recorder)
    assert not offenders, (
        "Privacy regression: draft-reply round-trip leaked a payload "
        "into the log sink:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Direct sanitiser tests -- canonical pin via the sanitise method
# ---------------------------------------------------------------------------

class TestSanitiseCanonical:
    """Per-key drop behaviour -- ensure every canonical key listed
    above actually gets dropped by the live ``_sanitise`` method.
    Belt-and-braces on top of the superset check above."""

    def test_every_canonical_token_key_drops_in_standard_mode(self):
        from email_triage import triage_logging
        wrapper = TriageLogger(logging.getLogger("email_triage.test"))
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = False
        try:
            extras = {k: _TOKEN_SENTINEL for k in _CANONICAL_TOKEN_KEYS}
            extras["safe_field"] = 42
            out = wrapper._sanitise(extras)
        finally:
            triage_logging._hipaa_mode = prior
        for k in _CANONICAL_TOKEN_KEYS:
            assert k not in out, (
                f"Canonical token key {k!r} survived _sanitise in "
                f"standard mode -- the live _TOKEN_KEYS is missing "
                f"this entry"
            )
        # The non-token field passes through untouched.
        assert out.get("safe_field") == 42
        # No sentinel survived.
        assert _TOKEN_SENTINEL not in repr(out)

    def test_every_canonical_phi_key_drops_in_hipaa_mode(self):
        from email_triage import triage_logging
        wrapper = TriageLogger(logging.getLogger("email_triage.test"))
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = True
        try:
            extras = {k: "PHI_VALUE_SENTINEL" for k in _CANONICAL_PHI_KEYS}
            extras["safe_field"] = 42
            extras["account_id"] = 7  # in _PERSIST_SAFE_KEYS
            extras["raw_head_scrubbed"] = "PHI_VALUE_SENTINEL"  # the 547 gap
            out = wrapper._sanitise(extras)
        finally:
            triage_logging._hipaa_mode = prior
        for k in _CANONICAL_PHI_KEYS:
            assert k not in out, (
                f"Canonical PHI key {k!r} survived _sanitise in HIPAA "
                f"mode -- the live _PHI_KEYS is missing this entry"
            )
        # Punch 547 (PD-8): the console leg applies the SAME fail-closed
        # allow-list as the persisted sink — an un-allowlisted key keeps its
        # NAME and loses its value, so a new PHI-bearing key name (the
        # ``raw_head_scrubbed`` that slipped the denylist) cannot leak.
        assert out.get("safe_field") == "[redacted]"
        assert out.get("raw_head_scrubbed") == "[redacted]"
        assert out.get("account_id") == 7
        assert "PHI_VALUE_SENTINEL" not in repr(out)


# ---------------------------------------------------------------------------
# run17 #1 — persisted-log redaction SSOT (sink ALLOWLIST, fail-closed)
# ---------------------------------------------------------------------------
# The field-strip used to live ONLY on the TriageLogger path (``_sanitise``);
# a raw ``logging.getLogger`` bypassed it and free-text PHI rode into the
# un-expungeable HMAC ``log_entries`` table (census run17 #1). The fix relocates
# a FAIL-CLOSED ALLOWLIST (``triage_logging.redact_persisted_extra``) into the
# persisted-log sinks, applied BEFORE the hash preimage (so hash == store). The
# 3-SME panel (hipaa-sme + db-sme + devils-advocate, 2026-06-27) hard-gated on
# ALLOWLIST-not-denylist: the ``raw`` key was absent from the ``_PHI_KEYS``
# denylist, which is exactly how it leaked — a denylist on a write-once table is
# fail-OPEN by construction.

class TestPersistedExtraRedaction:
    """``redact_persisted_extra`` — the sink ALLOWLIST chokepoint."""

    def test_hipaa_mode_redacts_non_allowlisted_keys(self):
        from email_triage.triage_logging import (
            redact_persisted_extra, _REDACTED_PLACEHOLDER,
        )
        out = redact_persisted_extra(
            {"raw": "PATIENT LAB RESULT PHI", "subject": "Dx diabetes",
             "flow_id": "f1", "account_id": 7},
            hipaa=True,
        )
        # non-allowlisted PHI-shaped keys → placeholder (value gone)...
        assert out["raw"] == _REDACTED_PLACEHOLDER
        assert out["subject"] == _REDACTED_PLACEHOLDER
        # ...allowlisted operator/plumbing keys keep their value.
        assert out["flow_id"] == "f1"
        assert out["account_id"] == 7
        # No PHI substring survives anywhere in the persisted dict.
        assert "PATIENT LAB RESULT PHI" not in repr(out)
        assert "diabetes" not in repr(out)

    def test_raw_llm_key_is_redacted_at_sink(self):
        """The exact run17 #1 leak: ``extra={"raw": <llm-over-PHI>}`` reaching
        the HMAC sink. ``raw`` is NOT in the operator allowlist."""
        from email_triage.triage_logging import (
            redact_persisted_extra, _REDACTED_PLACEHOLDER, _PERSIST_SAFE_KEYS,
        )
        assert "raw" not in _PERSIST_SAFE_KEYS
        out = redact_persisted_extra({"raw": "verbatim model output"}, hipaa=True)
        assert out["raw"] == _REDACTED_PLACEHOLDER

    def test_tokens_redacted_in_both_modes(self):
        from email_triage.triage_logging import (
            redact_persisted_extra, _REDACTED_PLACEHOLDER, TriageLogger,
        )
        tok = next(iter(TriageLogger._TOKEN_KEYS))
        for hipaa in (True, False):
            out = redact_persisted_extra({tok: "SECRETVALUE"}, hipaa=hipaa)
            assert out[tok] == _REDACTED_PLACEHOLDER, hipaa
            assert "SECRETVALUE" not in repr(out)

    def test_non_hipaa_keeps_operator_extras(self):
        """A non-HIPAA install has no PHI to protect → rich logging stays
        (only token-shaped keys are stripped)."""
        from email_triage.triage_logging import redact_persisted_extra
        out = redact_persisted_extra(
            {"raw": "x", "custom_diag": "y", "flow_id": "f1"}, hipaa=False,
        )
        assert out == {"raw": "x", "custom_diag": "y", "flow_id": "f1"}

    def test_placeholder_preserves_key_name(self):
        """Redacted keys keep their NAME so the /logs viewer shows the field
        existed (value-strip, not key-drop) — hipaa-sme adjustment."""
        from email_triage.triage_logging import redact_persisted_extra
        out = redact_persisted_extra({"subject": "PHI"}, hipaa=True)
        assert "subject" in out  # key preserved, value redacted

    def test_operator_context_survives_allowlist(self):
        """/logs render-survival (style rule 17 + dynamic-over-hardcoding): the
        keys the template ACTUALLY reads — its ``priority_keys`` pill list AND
        the named ``e.extra.<key>`` styling reads — must NOT be redacted by the
        HIPAA persist-allowlist, else the operator-facing /logs view silently
        loses fields. DERIVED FROM logs.html so the allowlist can't fall behind
        the view. (devils-advocate caught the prior hand-picked set as a
        false-green: it passed while run_id/elapsed_secs/error_class/
        provider_type all redacted.)"""
        import re
        from pathlib import Path

        import email_triage
        from email_triage.triage_logging import (
            redact_persisted_extra, _REDACTED_PLACEHOLDER,
        )

        tmpl = (
            Path(email_triage.__file__).parent
            / "web" / "templates" / "logs.html"
        ).read_text(encoding="utf-8")

        # The pill list: ``{% set priority_keys = priority_keys or [ '...' ] %}``
        m = re.search(r"priority_keys\s+or\s*\[(.*?)\]", tmpl, re.DOTALL)
        assert m, "could not find the priority_keys default list in logs.html"
        pill_keys = set(
            re.findall(r"['\"]([a-zA-Z_]\w*)['\"]", m.group(1))
        )
        # Named ``e.extra.<key>`` styling reads (error_class / provider_type /
        # error / account_id) — exclude method calls like ``.items()``/``.get()``.
        # ``(?![\w(])`` rejects BOTH a trailing word-char (so greedy backtracking
        # can't yield ``item`` out of ``items()``) and a method call ``(`` (so
        # ``.items()``/``.get()`` are excluded) — only true attribute reads.
        extra_reads = set(re.findall(r"e\.extra\.([a-zA-Z_]\w*)(?![\w(])", tmpl))
        required = pill_keys | extra_reads
        assert required, "derived no template keys — the logs.html regex drifted"

        redacted = sorted(
            k for k in required
            if redact_persisted_extra({k: "operatorvalue"}, hipaa=True)[k]
            == _REDACTED_PLACEHOLDER
        )
        assert not redacted, (
            "/logs renders these keys but the HIPAA persist-allowlist redacts "
            f"them (operator-context loss): {redacted}. Add each (after "
            "confirming non-PHI) to triage_logging._PERSIST_SAFE_KEYS."
        )


def test_log_entries_insert_only_in_sanctioned_sinks():
    """Inverse-INSERT structural pin (db-sme deliverable): a row may enter the
    HMAC ``log_entries`` table ONLY via the two sinks that call
    ``redact_persisted_extra`` first — ``SQLiteLogHandler.emit`` (triage_logging)
    and ``insert_log_entry`` (db/audit). A NEW ``INSERT INTO log_entries``
    anywhere else would bypass the fail-closed redaction. Count-agnostic."""
    import re

    from _pin_harness import iter_src_files, relpath

    _ALLOW = {"triage_logging.py", "db/audit.py"}
    pat = re.compile(r"INSERT\s+INTO\s+log_entries", re.IGNORECASE)
    offenders = sorted(
        relpath(p)
        for p in iter_src_files()
        if pat.search(p.read_text(encoding="utf-8")) and relpath(p) not in _ALLOW
    )
    assert not offenders, (
        "INSERT INTO log_entries outside the two redaction-applying sinks "
        "(would bypass redact_persisted_extra → PHI into the HMAC chain): "
        f"{offenders}"
    )


def test_inverse_insert_pin_has_teeth():
    """The sanctioned sinks MUST actually contain the INSERT the pin allows —
    else the allow-list is stale (PD#7) and the pin is vacuous."""
    import re

    from _pin_harness import iter_src_files, relpath

    pat = re.compile(r"INSERT\s+INTO\s+log_entries", re.IGNORECASE)
    sinks = {
        relpath(p)
        for p in iter_src_files()
        if pat.search(p.read_text(encoding="utf-8"))
    }
    assert sinks == {"triage_logging.py", "db/audit.py"}, sinks
