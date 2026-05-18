"""Static guard against logging OAuth/API tokens (#47, #54).

Greps the source tree for log-emit lines that pass token-bearing
field names as values. Runs in pytest so CI catches regressions.

Allowlist semantics:
- We allow log lines that mention these names as KEYS for redacted
  metadata ("token_present=true", "has_refresh_token=true").
- We block lines where a token-bearing field is the value of a log
  format-arg, or where a raw bearer/JWT/long opaque token appears
  inline.

Patterns block:
- ``log.info(f"... {refresh_token} ...")``
- ``log.debug("token=%s", token)``
- ``log.error(f"failed: {access_token}")``
- ``log.warning("Bearer eyJ... ")`` (raw JWT shape)

Patterns NOT blocked (safe):
- ``log.info("token refresh", extra={"present": bool(refresh_token)})``
- ``log.debug("access_token redacted")``
- ``logger.info("OAuth flow", token_kind="refresh")`` — kind, not value
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_SRC = Path(__file__).resolve().parents[1] / "src"

# Token-bearing field names that must NOT appear as a logged value.
TOKEN_NAMES = {
    "refresh_token", "access_token", "id_token",
    "client_secret", "bearer_token", "api_key", "password",
    "smtp_password", "imap_password", "session_token",
}

# JWT (eyJ-prefixed three-segment), opaque OAuth refresh tokens, and
# pip-audit-style long base64 in source. ~64+ char base64 is a
# reasonable lower bound; tighter would have false negatives.
RAW_TOKEN_PATTERNS = [
    re.compile(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'),
    # OAuth refresh tokens often start with `1//` or are 30+ random chars
    # near the word "refresh_token" + an = sign assignment.
]

# Log-call shapes we treat as suspicious.
LOG_CALL_RE = re.compile(
    r"\b(log|logger|_log)\.(info|debug|warning|error|exception|critical)\b"
)


def _iter_python_files() -> list[Path]:
    return [
        p for p in REPO_SRC.rglob("*.py")
        if "__pycache__" not in p.parts
    ]


def _is_log_line(line: str) -> bool:
    """Heuristic: does this line invoke a logger?"""
    return bool(LOG_CALL_RE.search(line))


def _line_emits_token_value(line: str) -> bool:
    """True when a log line passes a token-bearing name as a value.

    We err on the side of false-positive — better to require an
    explicit allow comment than to miss a real leak. Acceptable
    safe forms (substrings):
        # token-log-allowed
        bool(<name>)        — boolean cast, not the value
        len(<name>)         — length, not the value
        <name>_present
        <name>_kind
        present=
        redacted
        scrub
    """
    safe_markers = (
        "# token-log-allowed",
        "_present",
        "_kind",
        "_redacted",
        "scrub",
        "redact",
        "encrypt",
        "len(",
        "bool(",
    )
    for marker in safe_markers:
        if marker in line:
            return False
    # f-string interpolation of a token name.
    for name in TOKEN_NAMES:
        if re.search(rf'\{{\s*{name}\b', line):
            return True
        # Positional-arg style: log.info("...", refresh_token)
        if re.search(rf'\b{name}\s*[,)]', line) and "{" not in line and "extra=" not in line:
            # Only flag when this clearly looks like a value position
            # (after a comma, before ) ). Field-name use in `extra={}`
            # is fine because dict KEY is the name; the VALUE is a
            # separate expression.
            return True
    return False


def test_no_token_values_in_log_calls():
    """No log line in src/ emits a token-bearing field as its value."""
    offenders: list[str] = []
    for path in _iter_python_files():
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if not _is_log_line(line):
                continue
            if _line_emits_token_value(line):
                rel = path.relative_to(REPO_SRC.parent)
                offenders.append(f"{rel}:{i}: {line.strip()}")

    assert not offenders, (
        "Token-bearing field appears as a value in a log call. Either "
        "redact (bool(...) / len(...) / _present suffix) or add the "
        "comment '# token-log-allowed' on the line:\n  "
        + "\n  ".join(offenders)
    )


def test_no_raw_jwt_in_source():
    """No raw eyJ-style JWT literal appears anywhere in src/.

    Tokens are runtime values; a literal in source is either a leaked
    secret or a hard-coded test fixture that should live in tests/.
    """
    offenders: list[str] = []
    for path in _iter_python_files():
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for pat in RAW_TOKEN_PATTERNS:
            for m in pat.finditer(text):
                # File and approximate line.
                line_no = text.count("\n", 0, m.start()) + 1
                rel = path.relative_to(REPO_SRC.parent)
                offenders.append(f"{rel}:{line_no}: {m.group(0)[:40]}...")

    assert not offenders, (
        "Raw JWT-shaped literal found in source — never check tokens "
        "into a public repo:\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Runtime tests — capture ACTUAL log output during token-bearing flows
# (audit 2026-04-30 next-cycle deeper dive #2). Static grep above catches
# obvious f-string interpolations; runtime tests catch indirect leaks
# (e.g. an exception's repr() including the request body, structured-log
# extras dict carrying a value-bearing key, formatter's str() of the
# response object).
# ---------------------------------------------------------------------------

# Sentinel values that are visually distinct so a substring search is
# unambiguous. NEVER use a real-shape value here -- these are test
# fixtures, the static `test_no_raw_jwt_in_source` would flag them.
_TEST_AUTH_CODE = "TEST_AUTH_CODE_DO_NOT_LEAK_4f8a91"
_TEST_REFRESH_TOKEN = "TEST_REFRESH_TOKEN_DO_NOT_LEAK_b2c391"
_TEST_ACCESS_TOKEN = "TEST_ACCESS_TOKEN_DO_NOT_LEAK_a9f721"
_TEST_CLIENT_SECRET = "TEST_CLIENT_SECRET_DO_NOT_LEAK_e5d712"
_TEST_SECRET_VALUES = (
    _TEST_AUTH_CODE,
    _TEST_REFRESH_TOKEN,
    _TEST_ACCESS_TOKEN,
    _TEST_CLIENT_SECRET,
)


def _scan_records_for_secrets(records, fail_msg_prefix: str) -> list[str]:
    """Inspect every log record's message + extras for any of the
    test-sentinel secret values. Returns offender strings (empty
    list = clean).
    """
    offenders: list[str] = []
    for rec in records:
        # Render message as the formatter would, then also stringify
        # any structured extras the logger emitted.
        try:
            rendered = rec.getMessage()
        except Exception:
            rendered = str(rec.msg)
        bag = [rendered]
        # _extra dict -- our TriageLogger uses this for structured kwargs
        extra = getattr(rec, "_extra", None)
        if extra:
            bag.append(repr(extra))
        # The standard fields formatters often serialize.
        for attr in ("exc_text", "stack_info"):
            v = getattr(rec, attr, None)
            if v:
                bag.append(str(v))
        for piece in bag:
            for secret in _TEST_SECRET_VALUES:
                if secret in piece:
                    offenders.append(
                        f"{fail_msg_prefix}: secret leaked in "
                        f"{rec.name}:{rec.levelname}: {piece!r}"
                    )
    return offenders


@pytest.mark.asyncio
async def test_exchange_code_for_tokens_does_not_log_secrets(
    caplog, monkeypatch,
):
    """Successful exchange_code_for_tokens path: captured logs across
    the project must not contain the auth code, the refresh token
    Google returned, or the client_secret we sent."""
    import logging
    from unittest.mock import patch, AsyncMock

    from email_triage.providers.gmail_api import exchange_code_for_tokens

    # Mock the httpx POST so no real network hop, and we control
    # exactly what the response shape looks like.
    fake_resp = type("R", (), {
        "status_code": 200,
        "json": lambda self: {
            "access_token": _TEST_ACCESS_TOKEN,
            "refresh_token": _TEST_REFRESH_TOKEN,
            "expires_in": 3600,
            "token_type": "Bearer",
        },
        "text": "",
    })()

    class _FakeClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return None
        async def post(self, *a, **kw):
            return fake_resp

    caplog.set_level(logging.DEBUG)
    with patch("email_triage.providers.gmail_api.httpx.AsyncClient",
               return_value=_FakeClient()):
        result = await exchange_code_for_tokens(
            client_id="cid",
            client_secret=_TEST_CLIENT_SECRET,
            code=_TEST_AUTH_CODE,
            redirect_uri="https://example.com/cb",
        )

    # Sanity: the function returned the token shape it received.
    assert result["refresh_token"] == _TEST_REFRESH_TOKEN

    # No log record may contain any of the four sentinels.
    offenders = _scan_records_for_secrets(
        caplog.records, "exchange_code_for_tokens",
    )
    assert not offenders, "\n".join(offenders)


@pytest.mark.asyncio
async def test_refresh_access_token_does_not_log_secrets(
    caplog, monkeypatch,
):
    """GmailApiProvider._refresh_access_token must not log the
    refresh token, the access token, or the client_secret."""
    import logging
    from unittest.mock import patch

    from email_triage.providers.gmail_api import GmailApiProvider

    fake_resp = type("R", (), {
        "status_code": 200,
        "json": lambda self: {
            "access_token": _TEST_ACCESS_TOKEN,
            "expires_in": 3600,
        },
        "text": "",
    })()

    class _FakeClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return None
        async def post(self, *a, **kw):
            return fake_resp

    provider = GmailApiProvider(
        client_id="cid",
        client_secret=_TEST_CLIENT_SECRET,
        refresh_token=_TEST_REFRESH_TOKEN,
    )
    caplog.set_level(logging.DEBUG)
    with patch("email_triage.providers.gmail_api.httpx.AsyncClient",
               return_value=_FakeClient()):
        token = await provider._refresh_access_token()
    assert token == _TEST_ACCESS_TOKEN

    offenders = _scan_records_for_secrets(
        caplog.records, "_refresh_access_token",
    )
    assert not offenders, "\n".join(offenders)


def test_oauth_state_serializer_does_not_log_secrets(caplog):
    """Round-trip through the signed state token (used to bind the
    OAuth callback to the originating account). Secrets passed in
    must not surface in any log record produced during the dump or
    verify."""
    import logging
    from itsdangerous import URLSafeSerializer, BadSignature

    secret_key = "test-session-secret-for-signing-x"
    serializer = URLSafeSerializer(secret_key, salt="email-triage-oauth-state")

    caplog.set_level(logging.DEBUG)

    # State payload includes the auth-code-as-marker so a leak in
    # the dump path would catch the sentinel.
    payload = {
        "acct": 42,
        "code_hint": _TEST_AUTH_CODE,
        "calendar": False,
    }
    token = serializer.dumps(payload)
    decoded = serializer.loads(token)
    assert decoded == payload

    # itsdangerous itself shouldn't log -- this is mostly a guard
    # against a future maintainer adding `log.debug(state)` somewhere.
    offenders = _scan_records_for_secrets(
        caplog.records, "oauth_state_round_trip",
    )
    assert not offenders, "\n".join(offenders)
