"""Privacy-invariant test pin — OAuth refresh paths never log plaintext tokens (#168).

Audit-driven response to the 2026-05-14 weekly HIPAA / NERC-CIP audit
recommendation #4 ("OAuth token refresh logging — audit that no
plaintext tokens land in logs during refresh flows (provider-level
check)"). Code-side scrub (#86 + #111) lives in
``triage_logging.TriageLogger._TOKEN_KEYS`` + each provider's refresh
implementation; this module fills the audit-gap by pinning the
invariant at runtime across the paths the sibling
``tests/test_log_no_token_leak.py`` did not yet cover.

Existing coverage (do NOT duplicate):

* ``test_log_no_token_leak.py``
    - Gmail ``_refresh_access_token`` (200 success path)
    - Gmail ``_refresh_access_token`` (400 error path)
    - Gmail ``exchange_code_for_tokens``
    - O365 ``acquire_token`` silent flow (cached refresh)
    - O365 ``acquire_token`` client-credentials flow
    - ``TriageLogger._sanitise`` drops _TOKEN_KEYS in BOTH modes
* ``test_security_token_logging.py``
    - Static grep for log-emit lines that interpolate a token name
    - Raw JWT shape in source
    - caplog-level capture for exchange_code + Gmail _refresh
    - OAuth state-token round-trip
* ``test_privacy_invariants_log_scrub.py``
    - Canonical-set monotonic-superset on _TOKEN_KEYS / _PHI_KEYS
    - Per-key drop behaviour in both modes

Gaps this module fills (#168):

1. **O365 error path on token acquisition.** When
   ``acquire_token_for_client`` returns a dict WITHOUT
   ``access_token`` but WITH ``error_description`` that hypothetically
   carries a token-shaped value (a misbehaving identity-provider
   response), the ``RuntimeError`` message must not surface the value
   to any log sink.
2. **O365 device-code flow.** ``acquire_token`` invokes
   ``logger.info("Device code auth required", extra={...})`` with
   ``device_message`` / ``user_code`` / ``verification_uri`` fields.
   Even if the upstream flow dict picked up an extra token-shaped key
   the provider's extras list intentionally limits the fields it
   forwards — verify by injecting one that the provider's contract
   would silently drop.
3. **End-to-end ``oauth_request`` 401-retry-refresh.** Both Gmail
   and O365 use the shared ``providers/_oauth_http.oauth_request``
   helper for every API call. When the server returns 401, the
   helper logs ``"OAuth token rejected; refreshing"`` with
   ``extra={"path": path}`` and invokes the provider's
   ``refresh_token`` callback. The integration test forces this
   exact path and asserts neither the stale nor the rotated token
   shows up in any captured log record.
4. **GmailAuthError string serialization.** The exception's text
   becomes part of ``caplog`` records' ``exc_text``/``exc_info`` and
   the SQLite log sink's ``error`` field. If the upstream token
   endpoint returned a malformed 4xx body (a dict missing ``error``
   but carrying token-shaped values), ``GmailApiError.__init__``'s
   ``msg = str(body)`` fallback could surface the dict verbatim. The
   provider currently catches this via ``resp.status_code >= 400``
   before parsing — pin the contract.

The sentinel-string strategy mirrors the sibling module: 64-char
``x``-runs prefixed with a distinctive marker, NOT JWT-shaped, so
the static source-grep guard in ``test_security_token_logging`` does
not flag the test fixtures.
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
    Office365Provider constructor doesn't ImportError. Mirrors the
    fixture in ``tests/test_log_no_token_leak.py``; replicated here
    to keep the two files import-independent (one can land or be
    deleted without breaking the other)."""
    with patch.dict(sys.modules, {"msal": _mock_msal}):
        import email_triage.providers.office365 as o365_mod
        prior = o365_mod.HAS_MSAL
        o365_mod.HAS_MSAL = True
        try:
            yield
        finally:
            o365_mod.HAS_MSAL = prior


# ---------------------------------------------------------------------------
# Sentinels — synthesized, NOT JWT-shaped + NOT high-entropy random.
# 64-char x/y/z runs prefixed with a marker so substring search has
# zero ambiguity and the static-source JWT guard in
# ``test_security_token_logging.test_no_raw_jwt_in_source`` does not
# false-positive these test fixtures.
# ---------------------------------------------------------------------------

_FAKE_ACCESS_TOKEN = "OAUTH168_ACCESS_" + "x" * 64
_FAKE_REFRESH_TOKEN = "OAUTH168_REFRESH_" + "y" * 64
_FAKE_REFRESH_TOKEN_ROTATED = "OAUTH168_ROTATED_" + "r" * 64
_FAKE_CLIENT_SECRET = "OAUTH168_SECRET_" + "z" * 32
_FAKE_ID_TOKEN = "OAUTH168_IDTOKEN_" + "w" * 64

_ALL_SENTINELS: tuple[str, ...] = (
    _FAKE_ACCESS_TOKEN,
    _FAKE_REFRESH_TOKEN,
    _FAKE_REFRESH_TOKEN_ROTATED,
    _FAKE_CLIENT_SECRET,
    _FAKE_ID_TOKEN,
)


# ---------------------------------------------------------------------------
# Recorder + fixture — copy-pasted shape from
# ``test_log_no_token_leak.py`` so this file can be read standalone.
# The recorder mirrors the real ``SQLiteLogHandler.emit`` extra-collection
# logic so captured payloads match what would land in
# ``log_entries.extra_json`` at runtime.
# ---------------------------------------------------------------------------


class _SQLiteRecorder(logging.Handler):
    """Stand-in for SQLiteLogHandler that records the exact payload
    the real handler would persist. Avoids a DB round trip; keeps the
    test purely in-memory."""

    # Mirror of triage_logging._STANDARD_LOG_KEYS — kept in sync by
    # hand (same comment as the sibling). If drift produces false
    # negatives the bias is conservative.
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
        # The real SQLite handler also stringifies any exc_info on the
        # record. Mirror that so an exception's __str__ would surface
        # here if it leaked a token-shaped value.
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
# Gap 1 — O365 acquire_token client-credentials error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_o365_acquire_token_client_credentials_error_path_no_leak(
    sqlite_recorder, _msal_stub,
):
    """Client-credentials flow returns a dict WITHOUT ``access_token``
    but WITH ``error_description``. The provider raises
    ``RuntimeError(f"Failed to acquire token: {error}")``. The
    exception's text must not carry a token-shaped value — even if
    the identity provider erroneously included one in the description
    string. The provider's exception text becomes part of any
    upstream caller's exception log; the SQLite-style recorder
    captures it via the ``error`` field of the synthesized record.
    """
    from email_triage.providers.office365 import Office365Provider

    # Hypothetical malformed MSAL/AAD response: error_description
    # carries the refresh token verbatim. AAD shouldn't do this, but
    # the contract is "the scrub holds regardless of upstream
    # weirdness" — that's the whole point of defence-in-depth.
    malformed = {
        "error": "invalid_client",
        "error_description": (
            f"AADSTS70011: token validation failed for "
            f"refresh_token={_FAKE_REFRESH_TOKEN} (this should never "
            f"come back from AAD but assume it might)"
        ),
    }

    class _FakeMsalApp:
        def get_accounts(self):
            return []  # no cached account → fall through to client-creds

        def acquire_token_for_client(self, scopes):
            return malformed

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret=_FAKE_CLIENT_SECRET,
        token_cache_path="/tmp/msal_test_unused_168_clientcred_err.json",
    )

    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            with pytest.raises(RuntimeError) as excinfo:
                await provider.acquire_token()

    # Sanity: the exception WAS raised (so the code path executed),
    # and the RuntimeError text DOES surface the error_description
    # content (per current provider code — error_description is the
    # operator-facing diagnostic; we are NOT asserting the message
    # is fully scrubbed of upstream weirdness, only that no log
    # record carries the sentinel).
    assert "invalid_client" in str(excinfo.value) or (
        "AADSTS70011" in str(excinfo.value)
    )

    # The actual invariant: the LOG sink captured no sentinel.
    # If a future commit adds ``logger.error("auth failed", exc_info=e)``
    # to this path, the recorder would capture the str(RuntimeError)
    # via its ``error`` field and fail this test — which is exactly
    # the regression we want to catch.
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 client-credentials error path leaked a token sentinel "
        "into the SQLite log sink:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_o365_acquire_token_silent_returns_none_then_error_path_no_leak(
    sqlite_recorder, _msal_stub,
):
    """Silent flow returns ``None`` (no cached account) AND
    client-credentials returns a non-token result. Exercises the
    second fallthrough path in ``acquire_token``."""
    from email_triage.providers.office365 import Office365Provider

    class _FakeMsalApp:
        def get_accounts(self):
            return [{"username": "u@example.com"}]

        def acquire_token_silent(self, scopes, account):
            # MSAL contract: ``None`` is allowed when refresh fails
            # quietly. The provider then falls through to
            # client-creds.
            return None

        def acquire_token_for_client(self, scopes):
            return {
                "error": "invalid_grant",
                "error_description": (
                    f"refresh_token={_FAKE_REFRESH_TOKEN} expired or "
                    f"revoked"
                ),
            }

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret=_FAKE_CLIENT_SECRET,
        token_cache_path="/tmp/msal_test_unused_168_silent_fallthrough.json",
    )

    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            with pytest.raises(RuntimeError):
                await provider.acquire_token()

    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 silent→client-creds fallthrough leaked a token sentinel "
        "into the SQLite log sink:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Gap 2 — O365 device-code flow log scrub
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_o365_device_code_flow_log_no_token_leak(
    sqlite_recorder, _msal_stub, capsys,
):
    """Device-code flow path: provider logs
    ``logger.info("Device code auth required", extra={...})`` with
    a small allowlist of fields. The test pins that the
    forwarded extras (``device_message`` / ``user_code`` /
    ``verification_uri``) cannot carry a token-shaped value even if
    the upstream MSAL flow dict picked one up — the provider's code
    only forwards the three named keys, but a future refactor that
    forwards ``flow`` whole or adds a new key could leak.

    To make the test sensitive to that regression, the fake MSAL
    flow dict DOES include a sentinel token-shaped value under both
    ``access_token`` and a hypothetical future ``id_token`` field.
    A clean test means the provider did not forward those into the
    log row.
    """
    from email_triage.providers.office365 import Office365Provider

    class _FakeMsalApp:
        def get_accounts(self):
            return []  # no cached account, no client_secret either
                       # so we fall to device-code

        def initiate_device_flow(self, scopes):
            return {
                "user_code": "ABCD-EFGH",
                "device_code": "device-XYZ",
                "verification_uri": "https://microsoft.com/devicelogin",
                "message": (
                    "To sign in, use a web browser to open "
                    "https://microsoft.com/devicelogin and enter "
                    "the code ABCD-EFGH"
                ),
                "expires_in": 900,
                "interval": 5,
                # Hypothetical token-shaped fields the provider's
                # forwarder must NOT carry through to the log row.
                # Real AAD device-flow init doesn't return these, but
                # the test is the canary for a future refactor that
                # forwards the dict whole.
                "access_token": _FAKE_ACCESS_TOKEN,
                "id_token": _FAKE_ID_TOKEN,
            }

        def acquire_token_by_device_flow(self, flow):
            # Simulate successful device-code completion.
            return {
                "access_token": _FAKE_ACCESS_TOKEN,
                "expires_in": 3600,
                "id_token": _FAKE_ID_TOKEN,
            }

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret="",  # empty → public client → device-code path
        token_cache_path="/tmp/msal_test_unused_168_devcode.json",
    )

    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            token = await provider.acquire_token()
    # Discard the operator-facing console print; doesn't go through
    # the logger but ``capsys`` captures it to keep the test output
    # clean.
    capsys.readouterr()

    assert token == _FAKE_ACCESS_TOKEN

    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 device-code flow leaked a token sentinel into the "
        "SQLite log sink:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_o365_device_code_flow_init_error_no_leak(
    sqlite_recorder, _msal_stub,
):
    """Device-code init returns a malformed flow (no ``user_code``)
    with ``error_description`` carrying a sentinel. The provider
    raises before logging — pin that no leak occurred."""
    from email_triage.providers.office365 import Office365Provider

    class _FakeMsalApp:
        def get_accounts(self):
            return []

        def initiate_device_flow(self, scopes):
            return {
                "error": "invalid_request",
                "error_description": (
                    f"client_secret={_FAKE_CLIENT_SECRET} cannot be "
                    f"used with public client device flow"
                ),
            }

    provider = Office365Provider(
        tenant_id="tid",
        client_id="cid",
        client_secret="",
        token_cache_path="/tmp/msal_test_unused_168_devinit_err.json",
    )

    with patch.object(provider, "_get_app", return_value=_FakeMsalApp()):
        with patch.object(provider, "_save_cache"):
            with pytest.raises(RuntimeError):
                await provider.acquire_token()

    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "O365 device-code init error path leaked a sentinel:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Gap 3 — end-to-end ``oauth_request`` 401-retry-refresh path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_request_401_refresh_retry_no_token_leak(
    sqlite_recorder,
):
    """Drive the shared ``oauth_request`` helper through its
    401-refresh-retry loop and assert neither the initial token nor
    the rotated token surfaces in any log record.

    Sequence:
        1. First request: 401, stale ``initial_token`` attached.
        2. Helper logs ``"OAuth token rejected; refreshing"`` and
           invokes the refresh callback.
        3. Refresh callback returns the rotated token sentinel.
        4. Second request: 200, rotated token attached.
    """
    from unittest.mock import AsyncMock, MagicMock

    from email_triage.providers._oauth_http import oauth_request

    # Fake httpx-style responses.
    def _make_resp(status, body=None):
        resp = MagicMock()
        resp.status_code = status
        if body is None:
            resp.content = b""
            resp.json.return_value = {}
            resp.text = ""
        else:
            import json as _json
            resp.content = _json.dumps(body).encode()
            resp.json.return_value = body
            resp.text = _json.dumps(body)
        return resp

    responses = iter([
        _make_resp(401, {"error": "auth"}),
        _make_resp(200, {"id": "msg-42", "subject": "ok"}),
    ])
    captured_headers: list[dict] = []

    async def fake_request(method, path, **kwargs):
        captured_headers.append(dict(kwargs.get("headers", {})))
        return next(responses)

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock(return_value=_FAKE_REFRESH_TOKEN_ROTATED)

    class _Err(Exception):
        def __init__(self, status, body, path):
            super().__init__(f"{status} {body} {path}")

    body = await oauth_request(
        client=client,
        method="GET",
        path="/me/messages/msg-42",
        initial_token=_FAKE_ACCESS_TOKEN,
        refresh_token=refresh,
        error_factory=_Err,
    )

    # Sanity: the helper did the retry-with-new-token round.
    assert body == {"id": "msg-42", "subject": "ok"}
    refresh.assert_awaited_once()
    assert len(captured_headers) == 2
    assert captured_headers[0]["Authorization"] == f"Bearer {_FAKE_ACCESS_TOKEN}"
    assert captured_headers[1]["Authorization"] == f"Bearer {_FAKE_REFRESH_TOKEN_ROTATED}"

    # Invariant: no token sentinel reached the log sink. The
    # helper's ``logger.debug("OAuth token rejected; refreshing",
    # extra={"path": path})`` line is the only emission on this
    # path; it must carry only ``path`` and never the bearer value.
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "oauth_request 401-retry-refresh leaked a token sentinel "
        "into the SQLite log sink:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_oauth_request_double_401_failure_no_token_leak(
    sqlite_recorder,
):
    """Both attempts hit 401 — helper's 4xx branch raises
    ``error_factory(status, body, path)`` where ``body`` is the
    parsed response JSON (or text). The 4xx body is server-supplied,
    NOT helper-supplied, so it carries no token from the local
    process. Pin that the raised exception's text + any captured
    log records carry zero token-shape sentinels even when the
    upstream-server 4xx body would (hypothetically) include one.

    Note: the helper's ``raise error_factory(401, "Auth failed
    after refresh", path)`` fallback at the bottom of the function
    is dead code today — the 4xx branch fires first on any second
    401. Test exercises the live branch.
    """
    from unittest.mock import AsyncMock, MagicMock

    from email_triage.providers._oauth_http import oauth_request

    def _make_resp(status, body=None):
        resp = MagicMock()
        resp.status_code = status
        if body is None:
            resp.content = b""
            resp.json.return_value = {}
            resp.text = ""
        else:
            import json as _json
            resp.content = _json.dumps(body).encode()
            resp.json.return_value = body
            resp.text = _json.dumps(body)
        return resp

    # Hypothetical: an upstream 401 body that erroneously includes
    # a token-shape field. Helper passes ``body`` to ``error_factory``
    # verbatim — the contract is that the error class scrubs / does
    # not log it. We don't assert provider-class scrubbing here; we
    # only assert the helper itself does not surface the body to a
    # log record on this path.
    leak_body = {
        "error": "invalid_grant",
        "access_token": _FAKE_ACCESS_TOKEN,
    }
    responses = iter([_make_resp(401, leak_body), _make_resp(401, leak_body)])

    async def fake_request(method, path, **kwargs):
        return next(responses)

    client = MagicMock()
    client.request = AsyncMock(side_effect=fake_request)

    refresh = AsyncMock(return_value=_FAKE_REFRESH_TOKEN_ROTATED)

    captured_err = {}

    class _Err(Exception):
        def __init__(self, status, body, path):
            captured_err["status"] = status
            captured_err["body"] = body
            captured_err["path"] = path
            super().__init__(f"{status} {body} {path}")

    with pytest.raises(_Err):
        await oauth_request(
            client=client,
            method="GET",
            path="/me/messages",
            initial_token=_FAKE_ACCESS_TOKEN,
            refresh_token=refresh,
            error_factory=_Err,
        )

    # The helper passed the upstream body through unmodified. That
    # is by design — provider-class error formatters are responsible
    # for any scrubbing of body content. The pin here is on the
    # HELPER side: it must not have logged the body itself.
    assert captured_err["status"] == 401

    # Invariant: the helper did NOT log a token-shape sentinel,
    # even though the upstream body carried one. The only log call
    # on the 401 path is the "OAuth token rejected; refreshing"
    # debug line with ``extra={"path": path}`` — that line must
    # never carry the body.
    offenders = _scan_recorder_for_sentinels(sqlite_recorder)
    assert not offenders, (
        "oauth_request double-401 failure leaked a token sentinel "
        "via a helper log call:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Gap 4 — GmailAuthError string serialization with token-shaped body
# ---------------------------------------------------------------------------


def test_gmail_auth_error_str_with_dict_body_no_token_leak():
    """``GmailApiError.__init__`` falls back to ``str(body)`` when
    the body dict has no ``error`` key. Pin that the resulting
    exception's str() does NOT carry token-shaped values straight
    through.

    This is the contract the provider code relies on: the upstream
    token endpoint should NEVER return a 4xx with a body shaped like
    ``{"access_token": "..."}`` — but the test pin catches a future
    refactor that accidentally raises ``GmailAuthError(400, payload)``
    where ``payload`` is the success-shape token dict.

    HARDENED 2026-05-15 — ``GmailApiError.__init__`` now scrubs
    token-shape keys (per ``TriageLogger._TOKEN_KEYS``) from the
    body dict BEFORE stringifying. The xfail marker that previously
    documented this latent leak surface has been removed; the
    positive pin below is now the standing contract.
    """
    from email_triage.providers.gmail_api import GmailAuthError

    weird_body = {
        # No ``error`` key — falls through to the dict-stringification
        # branch in ``GmailApiError.__init__``. The defensive scrub
        # drops the token-shape keys before stringification.
        "access_token": _FAKE_ACCESS_TOKEN,
        "refresh_token": _FAKE_REFRESH_TOKEN,
        "expires_in": 3600,
    }
    exc = GmailAuthError(400, weird_body, "https://oauth2.googleapis.com/token")

    rendered = str(exc)
    for sentinel in _ALL_SENTINELS:
        assert sentinel not in rendered, (
            f"GmailAuthError text leaked sentinel {sentinel!r}: "
            f"{rendered!r}"
        )
    # And the surviving non-token field is still useful for
    # operators reading the exception message.
    assert "expires_in" in rendered, (
        "Scrub should drop token-shape keys but keep non-secret "
        "operational fields. ``expires_in`` was dropped, suggesting "
        "the scrub is over-aggressive."
    )


def test_gmail_auth_error_normal_4xx_body_no_token_leak():
    """The normal Google 4xx body (``{"error": "invalid_grant",
    "error_description": "..."}``) renders cleanly: ``msg`` comes
    from ``body["error"]["message"]`` when ``error`` is a dict, or
    from ``body["error_description"]`` when ``error`` is a flat
    string. Neither path surfaces token-shape fields. Pin the
    happy-path contract for completeness — a regression here would
    indicate someone replaced the explicit lookup with a generic
    ``str(body)``."""
    from email_triage.providers.gmail_api import GmailAuthError

    # Shape 1: flat-string error + error_description (device-flow shape).
    exc = GmailAuthError(
        400,
        {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        },
        "https://oauth2.googleapis.com/token",
    )
    rendered = str(exc)
    assert "expired or revoked" in rendered
    for sentinel in _ALL_SENTINELS:
        assert sentinel not in rendered

    # Shape 2: nested ``error`` dict (Google API shape).
    exc2 = GmailAuthError(
        403,
        {
            "error": {
                "code": 403,
                "message": "insufficient authentication scopes",
                "status": "PERMISSION_DENIED",
            }
        },
        "https://gmail.googleapis.com/...",
    )
    rendered2 = str(exc2)
    assert "insufficient authentication scopes" in rendered2
    for sentinel in _ALL_SENTINELS:
        assert sentinel not in rendered2


# ---------------------------------------------------------------------------
# Regression — defensive scrub covers every _TOKEN_KEYS field for
# BOTH ``GmailApiError`` and ``GmailAuthError`` (sibling class — same
# ``__init__``, but pin explicitly so a future override on either
# subclass cannot drop the scrub).
# ---------------------------------------------------------------------------


def test_gmail_api_error_scrub_covers_all_token_keys():
    """For every key in ``TriageLogger._TOKEN_KEYS``, constructing
    ``GmailApiError`` with a body dict that has NO ``error`` key and
    carries that token-shape value must NOT leak the value through
    ``str(exc)``. Sweeps the whole frozenset so adding a new token-key
    name later (e.g. a new provider's secret field) inherits the same
    defence without a separate test pin.

    Hardening added 2026-05-15 — sibling to
    ``test_gmail_auth_error_str_with_dict_body_no_token_leak`` but
    runs against the BASE class and across every token-key name.
    """
    from email_triage.providers.gmail_api import GmailApiError
    from email_triage.triage_logging import TriageLogger

    sentinel_value = "OAUTH168_KEYSCAN_" + "k" * 64
    for key in TriageLogger._TOKEN_KEYS:
        body = {key: sentinel_value}  # no ``error`` key — str(body) fallback
        exc = GmailApiError(400, body, "https://example/")
        rendered = str(exc)
        assert sentinel_value not in rendered, (
            f"GmailApiError leaked the value of token-shape key "
            f"{key!r}: rendered={rendered!r}"
        )


def test_gmail_auth_error_scrub_inherits_from_base():
    """``GmailAuthError`` is a subclass with no ``__init__`` override;
    pin that the parent-class scrub still fires when the subclass is
    constructed directly. Defends against a future override that
    forgets to call ``super().__init__`` or rolls its own message
    construction.
    """
    from email_triage.providers.gmail_api import GmailApiError, GmailAuthError

    # Same shape as the base test, but built via the subclass.
    body = {
        "access_token": _FAKE_ACCESS_TOKEN,
        "id_token": _FAKE_ID_TOKEN,
        "refresh_token": _FAKE_REFRESH_TOKEN,
    }
    exc = GmailAuthError(400, body, "https://oauth2.googleapis.com/token")
    assert isinstance(exc, GmailApiError), (
        "GmailAuthError must remain a GmailApiError subclass; "
        "the parent-class scrub depends on this inheritance."
    )
    rendered = str(exc)
    for sentinel in (_FAKE_ACCESS_TOKEN, _FAKE_ID_TOKEN, _FAKE_REFRESH_TOKEN):
        assert sentinel not in rendered, (
            f"GmailAuthError leaked sentinel {sentinel!r}: {rendered!r}"
        )


def test_gmail_api_error_scrub_preserves_non_secret_fields():
    """The scrub MUST be narrow: only ``_TOKEN_KEYS`` get dropped.
    Operational metadata fields (``expires_in``, ``token_type``,
    ``scope``, etc.) and any unknown non-secret field must survive
    so the rendered exception is still useful for operators.
    """
    from email_triage.providers.gmail_api import GmailApiError

    body = {
        "access_token": _FAKE_ACCESS_TOKEN,  # scrubbed
        "expires_in": 3600,                  # kept
        "token_type": "Bearer",              # kept
        "scope": "gmail.modify gmail.labels",  # kept
        "issued_at": "2026-05-15T12:34:56Z",  # kept (unknown field)
    }
    exc = GmailApiError(400, body, "https://example/")
    rendered = str(exc)

    # Token sentinel gone.
    assert _FAKE_ACCESS_TOKEN not in rendered
    # Operational fields preserved.
    assert "expires_in" in rendered
    assert "Bearer" in rendered
    assert "gmail.modify" in rendered
    assert "issued_at" in rendered


def test_gmail_api_error_non_dict_body_unchanged():
    """If ``body`` is not a dict, the constructor falls back to plain
    ``str(body)`` — no scrub semantics apply (there are no key names
    to filter on). Pin the contract so a future refactor doesn't
    accidentally string-replace tokens out of unstructured upstream
    bodies (which would mask real upstream errors with sentinel
    substrings).
    """
    from email_triage.providers.gmail_api import GmailApiError

    exc = GmailApiError(500, "Internal Server Error: backend timeout", "https://x/")
    rendered = str(exc)
    assert "Internal Server Error" in rendered
    assert "backend timeout" in rendered

    # And bytes / lists / None still stringify without exploding.
    exc2 = GmailApiError(502, ["a", "b"], "https://x/")
    assert "['a', 'b']" in str(exc2)


# ---------------------------------------------------------------------------
# Backstop — _TOKEN_KEYS frozenset audit against the field names the
# providers actually emit. Sibling
# ``test_privacy_invariants_log_scrub.test_token_keys_superset_of_canonical``
# pins the monotonic-superset rule; here we anchor that pin to the
# REAL Gmail + Microsoft token-response payload shapes so a future
# refactor that grows a new emit-side field name (e.g. Microsoft's
# ``ext_expires_in`` if MS ever decides the value is sensitive) gets
# considered for the strip set at the same time.
# ---------------------------------------------------------------------------


# Token-response fields the providers actually receive:
#   Google ``token`` endpoint: ``access_token``, ``refresh_token``,
#     ``id_token``, ``expires_in``, ``token_type``, ``scope``.
#   Microsoft Graph token endpoint: ``access_token``, ``refresh_token``,
#     ``id_token``, ``expires_in``, ``ext_expires_in``, ``token_type``,
#     ``scope``.
# Sensitive subset = the *_token fields. Time / type / scope are
# operational metadata and do NOT need to be in _TOKEN_KEYS — they
# are not secrets. The pin below names ONLY the secret-shape fields
# both providers emit.
_PROVIDER_EMITTED_TOKEN_FIELDS: frozenset[str] = frozenset({
    "access_token",
    "refresh_token",
    "id_token",
})


def test_token_keys_covers_every_provider_emitted_secret_field():
    """Every secret-shape field name the providers' token endpoints
    actually emit MUST be in ``_TOKEN_KEYS``. The canonical
    monotonic-superset test in the sibling
    ``test_privacy_invariants_log_scrub`` pins a hand-curated set;
    this test anchors that set to the provider response shapes so
    the canonical set is not allowed to drift away from reality."""
    from email_triage.triage_logging import TriageLogger

    missing = _PROVIDER_EMITTED_TOKEN_FIELDS - set(TriageLogger._TOKEN_KEYS)
    assert not missing, (
        f"_TOKEN_KEYS is missing provider-emitted secret-shape "
        f"fields: {sorted(missing)}. Add them to "
        f"src/email_triage/triage_logging.py: _TOKEN_KEYS, and "
        f"update the canonical set in "
        f"tests/test_privacy_invariants_log_scrub.py."
    )


def test_token_keys_includes_authorization_header_name():
    """The ``Authorization`` header value is a bearer token; if a
    log call ever passes ``extra={"authorization": headers.get(...)}``
    the scrub layer must catch it. Pin separately because the field
    is not in the token-response shape but is the canonical leak
    surface (auth header on every API request)."""
    from email_triage.triage_logging import TriageLogger

    assert "authorization" in TriageLogger._TOKEN_KEYS
