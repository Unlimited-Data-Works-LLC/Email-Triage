"""SQLiteLogHandler token-leak guard for OAuth refresh paths (#111).

Sibling to ``tests/test_security_token_logging.py`` — that module
covers the static-grep guard + standard-mode caplog inspection.
This module focuses on the SQLite log sink specifically:
``triage_logging.SQLiteLogHandler.emit`` writes every log
record's structured extras into a hash-chained ``log_entries``
table. Token leakage there would survive rotation and could not
be expunged without breaking the chain (HIPAA §164.312(b) audit
controls + §164.312(e)(1) transmission security).

Approach:

1. Monkey-patch ``SQLiteLogHandler.emit`` to record every record
   it would write — keep the real handler off the test (no DB
   round-trip needed) so the assertions inspect the in-memory
   capture instead of querying SQLite.
2. Force a Gmail OAuth refresh round through the provider, with
   ``httpx`` mocked at the AsyncClient layer so the token
   endpoint round trip stays in-process.
3. Repeat for Office365 (MSAL-backed) — patch the MSAL app
   methods so the silent flow returns a sentinel token without
   network calls.
4. Assert NO token-shaped value lands in any record's message,
   ``_extra`` dict, or any standard-attr field that the SQLite
   handler would dump to ``extra_json``.

Sentinel values: deliberately NOT JWT-shaped (eyJ...) and NOT
high-entropy random strings — those would trip
``test_security_token_logging.test_no_raw_jwt_in_source``. We
embed sentinels as 64-char ``x``-runs prefixed with a known
marker so the assertion can substring-search reliably.
"""

from __future__ import annotations

import logging
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stub MSAL so the Office365Provider import + construction stay in-process
# ---------------------------------------------------------------------------

_mock_msal = MagicMock()
_mock_msal.SerializableTokenCache = MagicMock
_mock_msal.PublicClientApplication = MagicMock
_mock_msal.ConfidentialClientApplication = MagicMock


@pytest.fixture
def _msal_stub():
    """Inject a stub msal module + flip HAS_MSAL=True so the
    Office365Provider constructor doesn't ImportError. Mirrors
    the autouse fixture used by tests/test_providers/test_office365.py
    but scoped per-test (only the O365 tests in this file ask
    for it)."""
    with patch.dict(sys.modules, {"msal": _mock_msal}):
        import email_triage.providers.office365 as o365_mod
        prior = o365_mod.HAS_MSAL
        o365_mod.HAS_MSAL = True
        try:
            yield
        finally:
            o365_mod.HAS_MSAL = prior


# ---------------------------------------------------------------------------
# Sentinels — synthesized, never real. Length 16+ and prefixed with a
# distinctive marker so substring search has zero ambiguity.
# ---------------------------------------------------------------------------

# 64 chars of "x" prefixed by a marker — visually obvious in any
# log line; not real-shape so the static JWT-source guard ignores it.
_FAKE_ACCESS_TOKEN = "FAKEACCESS_" + "x" * 64
_FAKE_REFRESH_TOKEN = "FAKEREFRESH_" + "y" * 64
_FAKE_CLIENT_SECRET = "FAKESECRET_" + "z" * 32
_FAKE_AUTH_CODE = "FAKECODE_" + "q" * 32
_FAKE_ID_TOKEN = "FAKEIDTOKEN_" + "w" * 64

_ALL_SENTINELS = (
    _FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN,
    _FAKE_CLIENT_SECRET, _FAKE_AUTH_CODE, _FAKE_ID_TOKEN,
)


# ---------------------------------------------------------------------------
# SQLiteLogHandler.emit recorder — captures records WITHOUT a DB hop.
# ---------------------------------------------------------------------------


class _SQLiteRecorder(logging.Handler):
    """Stand-in for SQLiteLogHandler that records exactly the
    payload the real handler would persist. Avoids needing a
    SQLite connection; keeps the test purely in-memory.

    Mirrors ``SQLiteLogHandler.emit``'s extra-collection logic so
    the captured payloads match what would land in
    ``log_entries.extra_json``."""

    # Mirror of triage_logging._STANDARD_LOG_KEYS — kept in sync
    # by hand because importing the private set into a test
    # couples too tightly. If the real set drifts, this test will
    # produce false negatives (missing extras), not false
    # positives, so the bias is safe.
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


def _scan_recorder_for_sentinels(recorder: _SQLiteRecorder) -> list[str]:
    """Return offender entries — empty list = clean."""
    offenders: list[str] = []
    for e in recorder.entries:
        haystack = e["message"] + " " + repr(e["extra"])
        for needle in _ALL_SENTINELS:
            if needle in haystack:
                offenders.append(
                    f"{e['logger']}:{e['level']}: "
                    f"{e['message']!r} extras={e['extra']!r}"
                )
    return offenders


@pytest.fixture
def sqlite_recorder():
    """Attach a stand-in SQLite handler to the email_triage logger
    tree, yield the capture object, detach on teardown."""
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


# ---------------------------------------------------------------------------
# Gmail — provider._refresh_access_token + exchange_code_for_tokens
# ---------------------------------------------------------------------------


class _FakeHttpResponse200:
    status_code = 200

    def __init__(self, payload: dict):
        self._payload = payload
        self.text = ""

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def post(self, *args, **kwargs):
        return self._response


@pytest.mark.asyncio
async def test_gmail_refresh_access_token_no_token_in_sqlite_log(
    sqlite_recorder,
):
    """Force a successful Gmail refresh round; assert the SQLite
    recorder captured zero records containing the access /
    refresh token, the client_secret, or any sentinel."""
    from email_triage.providers.gmail_api import GmailApiProvider

    fake_resp = _FakeHttpResponse200({
        "access_token": _FAKE_ACCESS_TOKEN,
        "expires_in": 3600,
    })

    with patch(
        "email_triage.providers.gmail_api.httpx.AsyncClient",
        return_value=_FakeAsyncClient(fake_resp),
    ):
        provider = GmailApiProvider(
            client_id="cid",
            client_secret=_FAKE_CLIENT_SECRET,
            refresh_token=_FAKE_REFRESH_TOKEN,
        )
        token = await provider._refresh_access_token()

    assert token == _FAKE_ACCESS_TOKEN
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "Gmail refresh leaked a token into the SQLite log sink:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_gmail_refresh_access_token_4xx_no_token_in_sqlite_log(
    sqlite_recorder,
):
    """Same guarantee on the 4xx error path. The provider raises
    GmailAuthError(status, body, OAUTH_TOKEN_URL); the body field
    is preserved on the exception, but no log call should expose
    the sent refresh_token / client_secret to the sink."""
    from email_triage.providers.gmail_api import (
        GmailApiProvider, GmailAuthError,
    )

    class _FakeResp4xx:
        status_code = 400
        text = '{"error":"invalid_grant"}'

        def json(self):
            return {
                "error": "invalid_grant",
                "error_description": "Token has been expired or revoked.",
            }

    with patch(
        "email_triage.providers.gmail_api.httpx.AsyncClient",
        return_value=_FakeAsyncClient(_FakeResp4xx()),
    ):
        provider = GmailApiProvider(
            client_id="cid",
            client_secret=_FAKE_CLIENT_SECRET,
            refresh_token=_FAKE_REFRESH_TOKEN,
        )
        with pytest.raises(GmailAuthError):
            await provider._refresh_access_token()

    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "Gmail refresh 4xx path leaked a token into the SQLite log sink:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_gmail_exchange_code_for_tokens_no_secret_in_sqlite_log(
    sqlite_recorder,
):
    """exchange_code_for_tokens (initial OAuth code-grant path)
    must not leak the auth code, the refresh token Google
    returned, or the client_secret we sent."""
    from email_triage.providers.gmail_api import exchange_code_for_tokens

    fake_resp = _FakeHttpResponse200({
        "access_token": _FAKE_ACCESS_TOKEN,
        "refresh_token": _FAKE_REFRESH_TOKEN,
        "id_token": _FAKE_ID_TOKEN,
        "expires_in": 3600,
        "token_type": "Bearer",
    })

    with patch(
        "email_triage.providers.gmail_api.httpx.AsyncClient",
        return_value=_FakeAsyncClient(fake_resp),
    ):
        result = await exchange_code_for_tokens(
            client_id="cid",
            client_secret=_FAKE_CLIENT_SECRET,
            code=_FAKE_AUTH_CODE,
            redirect_uri="https://example.com/cb",
        )

    assert result["refresh_token"] == _FAKE_REFRESH_TOKEN
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "exchange_code_for_tokens leaked a secret into the SQLite log sink:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Office365 — MSAL silent flow + client-credentials flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_o365_acquire_token_silent_no_token_in_sqlite_log(
    sqlite_recorder, _msal_stub,
):
    """MSAL silent acquisition (cached refresh token) must not
    surface the access_token in any log record. We patch
    msal.PublicClientApplication's get_accounts +
    acquire_token_silent so the path stays in-process."""
    from email_triage.providers.office365 import Office365Provider

    class _FakeMsalApp:
        def get_accounts(self):
            return [{"username": "u@example.com"}]

        def acquire_token_silent(self, scopes, account):
            return {
                "access_token": _FAKE_ACCESS_TOKEN,
                "expires_in": 3600,
                "id_token": _FAKE_ID_TOKEN,
            }

        def acquire_token_for_client(self, scopes):  # pragma: no cover
            raise AssertionError("silent flow should win first")

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret=_FAKE_CLIENT_SECRET,
        token_cache_path="/tmp/msal_test_unused.json",
    )
    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            token = await provider.acquire_token()

    assert token == _FAKE_ACCESS_TOKEN
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 silent flow leaked a token into the SQLite log sink:\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_o365_acquire_token_client_credentials_no_token_in_sqlite_log(
    sqlite_recorder, _msal_stub,
):
    """MSAL client-credentials path (daemon mode). Same guarantee:
    no access_token / client_secret surfaces in any log
    record."""
    from email_triage.providers.office365 import Office365Provider

    class _FakeMsalApp:
        def get_accounts(self):
            return []  # no cached account → fall through to client-creds

        def acquire_token_for_client(self, scopes):
            return {
                "access_token": _FAKE_ACCESS_TOKEN,
                "expires_in": 3600,
            }

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret=_FAKE_CLIENT_SECRET,
        token_cache_path="/tmp/msal_test_unused.json",
    )
    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            token = await provider.acquire_token()

    assert token == _FAKE_ACCESS_TOKEN
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 client-credentials flow leaked a token into the SQLite log sink:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Direct verification: TriageLogger._sanitise drops _TOKEN_KEYS in BOTH modes
# ---------------------------------------------------------------------------


def test_token_keys_stripped_in_standard_mode():
    """_TOKEN_KEYS scrub fires regardless of HIPAA mode — token-
    shaped values are never legitimate log payloads. Future log
    calls that pass these keys directly land at the sink with the
    key dropped (defense in depth on top of the per-call-site
    redaction the providers already practise)."""
    from email_triage import triage_logging
    from email_triage.triage_logging import TriageLogger

    # Force standard mode for this assertion.
    prior = triage_logging._hipaa_mode
    triage_logging._hipaa_mode = False
    try:
        wrapper = TriageLogger(logging.getLogger("email_triage.test"))
        out = wrapper._sanitise({
            "access_token": _FAKE_ACCESS_TOKEN,
            "refresh_token": _FAKE_REFRESH_TOKEN,
            "id_token": _FAKE_ID_TOKEN,
            "authorization": "Bearer " + _FAKE_ACCESS_TOKEN,
            "code": _FAKE_AUTH_CODE,
            "client_secret": _FAKE_CLIENT_SECRET,
            "password": "hunter2",
            # Non-token field — should pass through untouched.
            "account_id": 42,
        })
    finally:
        triage_logging._hipaa_mode = prior

    # Token keys gone.
    for k in (
        "access_token", "refresh_token", "id_token",
        "authorization", "code", "client_secret", "password",
    ):
        assert k not in out, f"{k} survived _sanitise in standard mode"
    # Non-token field survived.
    assert out.get("account_id") == 42
    # No sentinel value anywhere.
    assert _FAKE_ACCESS_TOKEN not in repr(out)
    assert _FAKE_REFRESH_TOKEN not in repr(out)
    assert _FAKE_CLIENT_SECRET not in repr(out)


def test_token_keys_stripped_in_hipaa_mode():
    """Same scrub holds under HIPAA mode (additive: PHI keys ALSO
    drop). Verifies the two filters compose correctly."""
    from email_triage import triage_logging
    from email_triage.triage_logging import TriageLogger

    prior = triage_logging._hipaa_mode
    triage_logging._hipaa_mode = True
    try:
        wrapper = TriageLogger(logging.getLogger("email_triage.test"))
        out = wrapper._sanitise({
            "access_token": _FAKE_ACCESS_TOKEN,
            "subject": "patient-X-results",  # PHI key
            "account_id": 42,                # safe key
        })
    finally:
        triage_logging._hipaa_mode = prior

    assert "access_token" not in out
    assert "subject" not in out
    assert out.get("account_id") == 42
