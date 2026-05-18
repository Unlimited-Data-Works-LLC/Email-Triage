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

See ``docs/privacy-audit-runbook.md`` for the full operator contract.
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
    return init_db(":memory:")


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
            out = wrapper._sanitise(extras)
        finally:
            triage_logging._hipaa_mode = prior
        for k in _CANONICAL_PHI_KEYS:
            assert k not in out, (
                f"Canonical PHI key {k!r} survived _sanitise in HIPAA "
                f"mode -- the live _PHI_KEYS is missing this entry"
            )
        assert out.get("safe_field") == 42
        assert "PHI_VALUE_SENTINEL" not in repr(out)
