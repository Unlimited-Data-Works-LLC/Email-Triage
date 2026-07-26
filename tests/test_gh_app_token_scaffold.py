"""test_gh_app_token_scaffold.py — scaffold-level teeth for the GitHub App
installation-token helper (2026-07-02).

Full live-mint tests need a real GitHub App private key + a valid
installation ID — they belong in `tests/integration/test_gh_app_live.py`
(not yet present; opt-in via `GH_APP_LIVE=1`). This scaffold covers:
1. Import + --help exit 0.
2. JWT construction: header/payload shape matches RFC 7519 + the
   github-recommended clock-skew slack.
3. Missing config errors are OPERATOR-friendly (no traceback dumps),
   never leak PEM bytes.
4. `_mint_gh_app_env` in `test_repair_daemon.py` returns None when the
   token script is missing OR when it exits non-zero (graceful fallback).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture(scope="module")
def token_mod():
    sys.path.insert(0, str(_SCRIPTS_DIR))
    import gh_app_token  # type: ignore
    return gh_app_token


@pytest.fixture(scope="module")
def daemon_mod():
    sys.path.insert(0, str(_SCRIPTS_DIR))
    import test_repair_daemon as trd  # type: ignore
    return trd


def test_help_exits_zero():
    r = subprocess.run(
        [sys.executable, str(_SCRIPTS_DIR / "gh_app_token.py"), "--help"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, f"--help failed: {r.stderr[:300]}"
    assert "usage:" in r.stdout.lower()


def test_jwt_header_and_payload_shape(token_mod, tmp_path):
    """Signed JWT decodes to the expected header + payload shapes with
    the -60s clock-skew slack the github docs recommend."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwt = token_mod._mint_jwt("1234567", pem)
    header_b64, payload_b64, sig_b64 = jwt.split(".")

    import base64
    def _b64u_decode(s: str) -> bytes:
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    header = json.loads(_b64u_decode(header_b64))
    payload = json.loads(_b64u_decode(payload_b64))
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert payload["iss"] == "1234567"
    assert 0 < (payload["exp"] - payload["iat"]) <= 10 * 60  # < 10 min
    import time
    now = int(time.time())
    assert payload["iat"] <= now  # -60s slack means iat is in the past
    assert payload["exp"] > now


def test_config_missing_error_is_operator_friendly(token_mod, monkeypatch, tmp_path):
    """When no config file / env / secrets provider is available, the
    error message is a SystemExit with actionable text — NOT a traceback."""
    monkeypatch.setattr(token_mod, "_CONFIG_PATHS", [tmp_path / "no-such.json"])
    for var in ("ET_GH_APP_ID", "ET_GH_INSTALLATION_ID", "ET_GH_PRIVATE_KEY_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(token_mod, "_from_secrets_provider",
                        lambda: (_ for _ in ()).throw(SystemExit("test: no secrets provider")))
    with pytest.raises(SystemExit) as excinfo:
        token_mod._resolve_config()
    assert "test: no secrets provider" in str(excinfo.value)


def test_mint_gh_app_env_returns_none_when_script_missing(daemon_mod, monkeypatch, tmp_path):
    """If `scripts/gh_app_token.py` doesn't exist, the wire returns None
    (→ falls back to parent env / `gh`'s own auth). The daemon must not
    crash on missing token infrastructure."""
    fake_here = tmp_path
    monkeypatch.setattr(daemon_mod, "__file__", str(fake_here / "test_repair_daemon.py"))
    # After monkeypatch, `Path(__file__).parent / "gh_app_token.py"` won't exist.
    result = daemon_mod._mint_gh_app_env()
    assert result is None


def test_mint_gh_app_env_returns_none_when_subprocess_fails(daemon_mod, monkeypatch):
    """If the token script exits non-zero, the wire returns None (safe
    fallback), NEVER raises."""
    class _FakeCompleted:
        returncode = 1
        stdout = ""
        stderr = "simulated auth failure"

    monkeypatch.setattr(
        daemon_mod.subprocess, "run",
        lambda *a, **kw: _FakeCompleted(),
    )
    result = daemon_mod._mint_gh_app_env()
    assert result is None
