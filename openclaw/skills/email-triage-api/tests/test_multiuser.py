"""Tests for the multi-user token model (--as <alias> + users.json).

The skill is intentionally stdlib-only and has no pytest fixtures of
its own; these tests drive the CLI directly via subprocess so they
exercise exactly what OpenClaw or a human operator would run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = SKILL_ROOT / "scripts" / "email-triage-api.py"


def _run(args: list[str], *, env: dict | None = None, cwd: Path | None = None):
    """Invoke the skill script with isolated HOME so users.json lookup
    lands in our tmp dir, not the operator's actual install.

    We point the script at a throwaway ``skill_dir`` by copying the
    script into a subdir of tmp and running from there (script lives at
    ``<root>/scripts/..``; users.json lives at ``<root>/users.json``).
    """
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        env={**os.environ, **(env or {})},
        cwd=cwd or SKILL_ROOT,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.fixture
def fresh_skill(tmp_path, monkeypatch):
    """Copy the script into a tmp skill dir so the users.json sibling
    file is isolated per-test."""
    import shutil
    dst = tmp_path / "email-triage-api"
    (dst / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, dst / "scripts" / SCRIPT.name)
    monkeypatch.chdir(dst)
    return dst


def _invoke(skill_dir: Path, args: list[str], env: dict | None = None):
    """Run the isolated script copy."""
    script = skill_dir / "scripts" / SCRIPT.name
    # Scrub EMAIL_TRIAGE_* from the inherited env so tests control resolution.
    clean = {k: v for k, v in os.environ.items() if not k.startswith("EMAIL_TRIAGE_")}
    return subprocess.run(
        [sys.executable, str(script), *args],
        env={**clean, **(env or {})},
        cwd=skill_dir,
        capture_output=True, text=True, timeout=15,
    )


class TestRegisterMe:
    def test_registers_new_alias(self, fresh_skill):
        r = _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_aliceXYZ"])
        assert r.returncode == 0, r.stderr
        users = json.loads((fresh_skill / "users.json").read_text())
        assert users == {"alice": "et_aliceXYZ"}

    def test_overwrites_existing_alias(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_old"])
        r = _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_new"])
        assert r.returncode == 0, r.stderr
        users = json.loads((fresh_skill / "users.json").read_text())
        assert users == {"alice": "et_new"}

    def test_file_is_0600(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_tok"])
        if os.name == "nt":
            pytest.skip("POSIX perms not meaningful on Windows")
        mode = (fresh_skill / "users.json").stat().st_mode & 0o777
        assert mode == 0o600

    def test_warns_on_non_et_prefix(self, fresh_skill):
        r = _invoke(fresh_skill, ["register-me", "--as", "x", "--token", "not-a-token"])
        assert r.returncode == 0  # warning, not failure
        assert "warning" in r.stderr.lower()


class TestListAliases:
    def test_empty(self, fresh_skill):
        r = _invoke(fresh_skill, ["list-aliases"])
        assert r.returncode == 0
        assert "No aliases" in r.stdout

    def test_shows_aliases_but_not_tokens(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_aliceSECRET"])
        _invoke(fresh_skill, ["register-me", "--as", "bob", "--token", "et_bobSECRET"])
        r = _invoke(fresh_skill, ["list-aliases"])
        assert r.returncode == 0
        assert "alice" in r.stdout
        assert "bob" in r.stdout
        # The secret part of each token must NOT appear.
        assert "aliceSECRET" not in r.stdout
        assert "bobSECRET" not in r.stdout


class TestForgetMe:
    def test_removes_alias(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_tok"])
        r = _invoke(fresh_skill, ["forget-me", "--as", "alice"])
        assert r.returncode == 0
        users = json.loads((fresh_skill / "users.json").read_text())
        assert users == {}

    def test_missing_alias_is_noop(self, fresh_skill):
        r = _invoke(fresh_skill, ["forget-me", "--as", "ghost"])
        assert r.returncode == 0
        assert "No alias" in r.stdout


class TestTokenResolution:
    def test_unknown_alias_exits_4_not_silent_fallback(self, fresh_skill):
        """--as <alias> that isn't in users.json must FAIL, not silently
        fall back to the default/env. Silent fallback would act as the
        wrong user."""
        _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_alice"])
        r = _invoke(
            fresh_skill,
            ["--as", "nobody", "--url", "http://x", "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN": "et_envfallback"},
        )
        assert r.returncode == 4
        assert "no token registered for alias 'nobody'" in r.stderr

    def test_default_wins_over_env(self, fresh_skill):
        """When no --as is given and users.json has a 'default' entry,
        that beats EMAIL_TRIAGE_TOKEN. Server will reject unreachable URL,
        but we can tell by the Authorization header which path the
        resolution took — easier to check the exit code for connect
        failure (exit 1) + lack of 'missing token' output."""
        _invoke(fresh_skill, ["register-me", "--as", "default", "--token", "et_def"])
        r = _invoke(
            fresh_skill,
            ["--url", "http://127.0.0.1:1", "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN": "et_env"},
        )
        # Resolution picked *some* token — we hit the network and failed.
        # If resolution had failed, exit would be 4 not 1.
        assert r.returncode == 1
        assert "network failure" in r.stderr

    def test_env_fallback_used_when_no_users_json(self, fresh_skill):
        r = _invoke(
            fresh_skill,
            ["--url", "http://127.0.0.1:1", "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN": "et_env"},
        )
        assert r.returncode == 1  # connect failure, not missing-config


class TestLocalCommandsSkipRequirement:
    """register-me / forget-me / list-aliases must work without URL or
    token configured anywhere. They're pure local-file operations."""

    def test_register_without_url_or_token_envvars(self, fresh_skill):
        r = _invoke(fresh_skill, ["register-me", "--as", "alice", "--token", "et_a"])
        assert r.returncode == 0

    def test_list_without_url_or_token_envvars(self, fresh_skill):
        r = _invoke(fresh_skill, ["list-aliases"])
        assert r.returncode == 0


# ---------------------------------------------------------------------------
#  — secret-backend resolution (credential helper + per-alias SecretRef env).
# The skill prefers a real secret store over the plaintext users.json; a
# configured helper is FAIL-CLOSED (never silently falls back to plaintext).
# ---------------------------------------------------------------------------

UNREACHABLE = "http://127.0.0.1:1"

# Helper that prints `et_<ET_ALIAS>` (or et_fromcmd when no alias is passed).
_HELPER_ECHO_ALIAS = (
    "import os\n"
    "a = os.environ.get('ET_ALIAS', '')\n"
    "print('et_' + (a or 'fromcmd'))\n"
)
_HELPER_FAIL = "import sys\nsys.exit(7)\n"          # always errors
_HELPER_EMPTY = "pass\n"                             # prints nothing, exit 0
# Store helper: writes 'ET_ALIAS:<stdin>' to the file named by ET_STORE_OUT.
_HELPER_STORE = (
    "import os, sys\n"
    "out = os.environ['ET_STORE_OUT']\n"
    "data = sys.stdin.read()\n"
    "open(out, 'w', encoding='utf-8').write("
    "os.environ.get('ET_ALIAS', '') + ':' + data)\n"
)


def _write_helper(dir_: Path, name: str, body: str) -> str:
    """Write a tiny python helper script; return a quoted shell command
    string usable as EMAIL_TRIAGE_TOKEN_CMD / _SET_CMD on win + posix."""
    p = dir_ / name
    p.write_text(body, encoding="utf-8")
    return f'"{sys.executable}" "{p}"'


class TestSecretBackendResolution:
    def test_cmd_helper_resolves_token(self, fresh_skill):
        cmd = _write_helper(fresh_skill.parent, "h_echo.py", _HELPER_ECHO_ALIAS)
        r = _invoke(
            fresh_skill, ["--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        # Resolution succeeded → reached the network (exit 1), not exit 4.
        assert r.returncode == 1, r.stderr
        assert "network failure" in r.stderr

    def test_cmd_helper_receives_alias(self, fresh_skill):
        cmd = _write_helper(fresh_skill.parent, "h_echo.py", _HELPER_ECHO_ALIAS)
        r = _invoke(
            fresh_skill,
            ["--as", "bob", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 1, r.stderr
        assert "network failure" in r.stderr

    def test_cmd_helper_fail_closed_ignores_plaintext(self, fresh_skill):
        """The KEY security property: a configured helper that FAILS must
        NOT fall through to a (possibly revoked) plaintext token."""
        _invoke(fresh_skill, ["register-me", "--as", "bob", "--token", "et_plain"])
        cmd = _write_helper(fresh_skill.parent, "h_fail.py", _HELPER_FAIL)
        r = _invoke(
            fresh_skill,
            ["--as", "bob", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 4, r.stderr
        assert "exited 7" in r.stderr
        # Proof we never reached / used the plaintext store:
        assert "plaintext users.json" not in r.stderr

    def test_cmd_helper_empty_output_fail_closed(self, fresh_skill):
        cmd = _write_helper(fresh_skill.parent, "h_empty.py", _HELPER_EMPTY)
        r = _invoke(
            fresh_skill,
            ["--as", "bob", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 4, r.stderr
        assert "no token" in r.stderr

    def test_per_alias_env_resolves(self, fresh_skill):
        r = _invoke(
            fresh_skill,
            ["--as", "bob", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CRAIG": "et_craigenv"},
        )
        assert r.returncode == 1, r.stderr
        assert "network failure" in r.stderr

    def test_per_alias_env_beats_plaintext(self, fresh_skill):
        """Secure per-alias env wins over users.json → no plaintext warning."""
        _invoke(fresh_skill, ["register-me", "--as", "bob", "--token", "et_plain"])
        r = _invoke(
            fresh_skill,
            ["--as", "bob", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CRAIG": "et_craigenv"},
        )
        assert r.returncode == 1, r.stderr
        assert "plaintext users.json" not in r.stderr

    def test_plaintext_warning_emitted(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "default", "--token", "et_def"])
        r = _invoke(fresh_skill, ["--url", UNREACHABLE, "accounts-list"])
        assert r.returncode == 1
        assert "plaintext users.json" in r.stderr

    def test_plaintext_warning_suppressed(self, fresh_skill):
        _invoke(fresh_skill, ["register-me", "--as", "default", "--token", "et_def"])
        r = _invoke(
            fresh_skill, ["--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_SUPPRESS_PLAINTEXT_WARNING": "1"},
        )
        assert r.returncode == 1
        assert "plaintext users.json" not in r.stderr

    def test_invalid_alias_rejected_before_helper(self, fresh_skill):
        """An alias with shell metacharacters is rejected (exit 1) BEFORE it
        can be interpolated into the helper command — even with a failing
        helper configured (which would otherwise exit 4)."""
        cmd = _write_helper(fresh_skill.parent, "h_fail.py", _HELPER_FAIL)
        r = _invoke(
            fresh_skill,
            ["--as", "bob;rm -rf x", "--url", UNREACHABLE, "accounts-list"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 1, r.stderr
        assert "invalid" in r.stderr

    def test_local_command_skips_failing_helper(self, fresh_skill):
        """list-aliases is a local op — a configured (even failing) helper
        must NOT be invoked, so it can't fail-closed the local command."""
        cmd = _write_helper(fresh_skill.parent, "h_fail.py", _HELPER_FAIL)
        r = _invoke(
            fresh_skill, ["list-aliases"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 0, r.stderr
        assert "credential helper" in r.stderr or "credential helper" in r.stdout


class TestRegisterMeBackend:
    def test_refuses_plaintext_when_read_helper_configured(self, fresh_skill):
        cmd = _write_helper(fresh_skill.parent, "h_echo.py", _HELPER_ECHO_ALIAS)
        r = _invoke(
            fresh_skill, ["register-me", "--as", "bob", "--token", "et_x"],
            env={"EMAIL_TRIAGE_TOKEN_CMD": cmd},
        )
        assert r.returncode == 1, r.stderr
        assert not (fresh_skill / "users.json").exists()
        assert "EMAIL_TRIAGE_TOKEN_SET_CMD" in r.stderr

    def test_set_cmd_stores_via_backend(self, fresh_skill):
        out = fresh_skill.parent / "stored.txt"
        cmd = _write_helper(fresh_skill.parent, "h_store.py", _HELPER_STORE)
        r = _invoke(
            fresh_skill, ["register-me", "--as", "bob", "--token", "et_secret"],
            env={
                "EMAIL_TRIAGE_TOKEN_SET_CMD": cmd,
                "ET_STORE_OUT": str(out),
            },
        )
        assert r.returncode == 0, r.stderr
        # No plaintext file — the token went to the backend instead.
        assert not (fresh_skill / "users.json").exists()
        stored = out.read_text(encoding="utf-8")
        assert stored.startswith("bob:")
        assert "et_secret" in stored

    def test_legacy_plaintext_note_when_no_backend(self, fresh_skill):
        r = _invoke(fresh_skill, ["register-me", "--as", "bob", "--token", "et_x"])
        assert r.returncode == 0, r.stderr
        assert (fresh_skill / "users.json").exists()
        assert "PLAINTEXT" in r.stderr
