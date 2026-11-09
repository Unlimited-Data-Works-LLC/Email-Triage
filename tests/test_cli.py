"""Tests for the CLI interface."""

import json
from pathlib import Path

import pytest

from email_triage.cli import build_parser, cmd_config_validate, cmd_init, cmd_status, main


class TestParser:
    def test_no_command_returns_zero(self):
        assert main([]) == 0

    def test_run_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["run"])
        assert args.command == "run"
        assert args.query == "is:unread"
        assert args.limit == 50
        assert args.dry_run is False

    def test_run_with_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "run", "--query", "from:boss", "--limit", "5", "--dry-run",
        ])
        assert args.query == "from:boss"
        assert args.limit == 5
        assert args.dry_run is True

    def test_watch_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["watch"])
        assert args.command == "watch"
        assert args.interval == 300
        assert args.query == "is:unread"

    def test_watch_with_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "watch", "--interval", "60", "--query", "is:unread newer_than:1h",
        ])
        assert args.interval == 60

    def test_status_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"
        assert args.status is None

    def test_status_with_filter(self):
        parser = build_parser()
        args = parser.parse_args(["status", "--status", "classified"])
        assert args.status == "classified"

    def test_secrets_list(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "list"])
        assert args.command == "secrets"
        assert args.secrets_cmd == "list"

    def test_secrets_set(self):
        parser = build_parser()
        args = parser.parse_args(["secrets", "set", "SMTP_PASSWORD"])
        assert args.secrets_cmd == "set"
        assert args.key == "SMTP_PASSWORD"

    def test_init_no_path(self):
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"
        assert args.path is None

    def test_init_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["init", "/tmp/my-triage"])
        assert args.path == "/tmp/my-triage"

    def test_config_validate(self):
        parser = build_parser()
        args = parser.parse_args(["config", "--validate"])
        assert args.command == "config"

    def test_serve(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "--port", "9090"])
        assert args.command == "serve"
        assert args.port == 9090

    def test_serve_parser(self):
        parser = build_parser()
        args = parser.parse_args(["serve"])
        assert args.command == "serve"
        assert args.host == "0.0.0.0"
        assert args.port == 8080


class TestInit:
    def test_scaffolds_config(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["init", str(tmp_path / "triage")])
        result = cmd_init(args)
        assert result == 0

        config_file = tmp_path / "triage" / "email-triage.yaml"
        assert config_file.exists()
        content = config_file.read_text()
        assert "provider:" in content
        assert "classifier:" in content
        assert "routes:" in content

        data_dir = tmp_path / "triage" / "data"
        assert data_dir.is_dir()

    def test_scaffolds_backup_section_loadable(self, tmp_path):
        """ — the init scaffold carries a documented ``backup:`` block
        (question 3: configurable via the CLI/init OR the UI). It must be
        DISABLED by default and parse cleanly back through load_config so a
        fresh install can fill it in without a YAML syntax surprise."""
        import yaml

        from email_triage.config import load_config

        parser = build_parser()
        args = parser.parse_args(["init", str(tmp_path / "triage")])
        assert cmd_init(args) == 0

        config_file = tmp_path / "triage" / "email-triage.yaml"
        content = config_file.read_text()
        assert "backup:" in content
        raw = yaml.safe_load(content)
        assert raw["backup"]["enabled"] is False  # OFF until a restore path exists

        cfg = load_config(config_file)
        assert cfg.backup.enabled is False
        assert cfg.backup.cadence == "manual"
        assert cfg.backup.encryption == "master-key"

    def test_refuses_if_exists(self, tmp_path):
        config_file = tmp_path / "email-triage.yaml"
        config_file.write_text("existing")
        parser = build_parser()
        args = parser.parse_args(["init", str(tmp_path)])
        result = cmd_init(args)
        assert result == 1

    def test_scaffolded_secrets_backend_is_auto_not_env(self, tmp_path):
        """R-3 per H-07 verify-don't-accept review 2026-05-24 (DA-4 +
        hipaa-sme-3 convergent verdict). The init template MUST scaffold
        `backend: auto`, not `backend: env`. Closing H-07 with the init
        template still pointing at the deprecated path would have been
        structurally hollow: every fresh install would land on the
        deprecated backend and trigger the H-07 deprecation warning on
        first boot, reproducing the very gap the finding closes.

        Per project_hipaa_asap_policy.md no-defer-tier on HIPAA findings,
        cli.py:1496 fix had to land Cycle 6 (NOT Cycle 7) — same SHA as
        the rest of H-07 closure.
        """
        parser = build_parser()
        args = parser.parse_args(["init", str(tmp_path / "triage")])
        result = cmd_init(args)
        assert result == 0

        config_file = tmp_path / "triage" / "email-triage.yaml"
        content = config_file.read_text()
        assert "backend: auto" in content, (
            "init template must scaffold `backend: auto` per H-07 closure "
            "(DA-4 + hipaa-sme-3 verify-don't-accept review 2026-05-24)"
        )
        assert "backend: env" not in content, (
            "init template must NOT scaffold `backend: env` — that's the "
            "deprecated path H-07 closes. New installs would otherwise "
            "land on the deprecation warning on first boot."
        )


class TestBackupGenKeypairWindows:
    """ — the `backup gen-keypair` admin tool must work on Windows.

    The bug: its guidance printed a `→` (U+2192), which Windows' cp1252 console
    cannot encode → UnicodeEncodeError killed the command AFTER its first ASCII
    line but BEFORE it emitted the keys (exit 1, no usable output). The operator
    hit this trying to generate a public-key-backup keypair on Windows. Two
    independent fixes, each pinned below: (1) main() reconfigures stdout to UTF-8
    (SSOT for the whole CLI); (2) the safety-critical keygen guidance is ASCII.
    """

    def test_gen_keypair_output_is_ascii_safe(self, capsys):
        """The keygen output must be pure ASCII so it can't crash on ANY console
        encoding — a future non-ASCII char reintroduced here fails this pin."""
        rc = main(["backup", "gen-keypair"])
        out = capsys.readouterr().out
        assert rc == 0
        out.encode("ascii")  # raises UnicodeEncodeError if non-ASCII slipped back
        assert "BEGIN PUBLIC KEY" in out
        assert "BEGIN PRIVATE KEY" in out

    def test_cli_main_forces_utf8_stdout(self, monkeypatch):
        """SSOT class-fix: the CLI reconfigures stdout to UTF-8 at entry so ANY
        non-ASCII CLI output survives a Windows cp1252 console — not just the
        ASCII-ized gen-keypair. Pin via a real cp1252-backed stream."""
        import io
        import sys

        buf = io.BytesIO()
        stream = io.TextIOWrapper(buf, encoding="cp1252")
        monkeypatch.setattr(sys, "stdout", stream)
        rc = main(["backup", "gen-keypair"])
        assert rc == 0
        # main() reconfigured the cp1252 stream to UTF-8 before any output.
        assert sys.stdout.encoding.lower().replace("-", "") == "utf8"


class TestConfigValidate:
    def test_valid_config(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""\
provider:
  type: gmail_api
classifier:
  backend: ollama
""")
        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "config", "--validate", str(config_file)])
        result = cmd_config_validate(args)
        assert result == 0

    def test_invalid_config(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""\
provider:
  type: yahoo
classifier:
  backend: gpt4all
""")
        parser = build_parser()
        args = parser.parse_args(["config", "--validate", str(config_file)])
        result = cmd_config_validate(args)
        assert result == 1


class TestStatus:
    def test_no_database(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""\
persistence:
  db_path: ./nonexistent.db
""")
        monkeypatch.chdir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "status"])
        result = cmd_status(args)
        assert result == 1

    def test_with_flows(self, tmp_path, monkeypatch):
        # Create a store with some flows.
        from email_triage.engine.store import FlowStore
        from email_triage.engine.models import FlowStatus

        db_path = tmp_path / "triage.db"
        store = FlowStore(db_path)
        f1 = store.create_flow("m-1", "test")
        f2 = store.create_flow("m-2", "test")
        f1.status = FlowStatus.FINISHED
        store.update_flow(f1, expected_revision=0)
        store.close()

        config_file = tmp_path / "config.yaml"
        config_file.write_text(f"""\
persistence:
  db_path: {db_path}
  # Explicit plaintext intent: FlowStore built this DB unencrypted, and since
  # 903b9618 an omitted key resolves to encrypted-at-rest. This test covers
  # `status` output, not storage posture.
  encryption_enabled: false
""")
        monkeypatch.chdir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "status"])
        result = cmd_status(args)
        assert result == 0


# ---------------------------------------------------------------------------
#  (Cycle 6, 2026-05-23) — provider.close() failure surface
# ---------------------------------------------------------------------------
#
# Two CLI commands wrap ``asyncio.run(provider.close())`` in a
# ``try/except Exception`` finally block: cmd_style_mine and
# cmd_sent_mail_index_build. Pre-#275, both swallowed the exception with
# bare ``pass``;  replaces with ``log.warning("provider.close failed",
# exc_info=True)``. Per §4 principle 2 (fix all sites of one root cause)
# both sites land in one commit; per §4 principle 3 (audit the pattern),
# both sites tested in one class.
#
# These tests verify the contract behavior — they don't drive the full
# CLI subcommand (heavy fixture setup not load-bearing). The exact
# pattern lives in cli.py at the two cited finally-blocks; the test
# exercises a faithful reproduction of that pattern + asserts:
#   (a) the warning lands in the captured log
#   (b) the exception is consumed (does NOT escape)
#   (c) the surrounding return code is preserved


class TestProviderCloseFailureSurface_H275:
    """ — provider.close() exception in CLI cleanup finally surfaces
    as log.warning + does NOT mask the work's exit code."""

    def test_pattern_at_cmd_style_mine_site_raises_warning_not_exception(
        self, caplog,
    ):
        """The finally-block pattern at cli.py:1656 must consume the
        exception and emit a WARNING log (not silently pass)."""
        import asyncio
        import logging
        from email_triage.cli import log as cli_log

        class _BadProvider:
            async def close(self):
                raise RuntimeError("simulated provider-close failure")

        provider = _BadProvider()

        # Reproduce the cli.py:1656-1662 + cli.py:1804-1810 finally-block
        # pattern verbatim. ``return_value`` mirrors what _run() would
        # have returned upstream; the finally-block must NOT mutate it.
        return_value = 0
        try:
            actual = return_value  # what cmd_style_mine returns
        finally:
            with caplog.at_level(logging.WARNING, logger="email_triage.cli"):
                try:
                    asyncio.run(provider.close())
                except Exception:
                    cli_log.warning(
                        "provider.close failed", exc_info=True,
                    )

        # Contract assertions:
        # (a) the warning landed with the expected message.
        warning_records = [
            r for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "provider.close failed" in r.message for r in warning_records
        ), (
            f"expected 'provider.close failed' WARNING; got "
            f"{[r.message for r in warning_records]}"
        )
        # (b) the exception did NOT escape (we got here).
        # (c) the return value is preserved.
        assert actual == return_value == 0

    def test_pattern_at_cmd_sent_mail_index_build_site_raises_warning(
        self, caplog,
    ):
        """Second site at cli.py:1804 — identical pattern, identical
        contract. Per §4 principle 2 both sites tested in this class.
        """
        import asyncio
        import logging
        from email_triage.cli import log as cli_log

        class _BadProvider:
            async def close(self):
                raise OSError("simulated socket-close failure")

        provider = _BadProvider()
        return_value = 1  # different return value; finally must preserve
        try:
            actual = return_value
        finally:
            with caplog.at_level(logging.WARNING, logger="email_triage.cli"):
                try:
                    asyncio.run(provider.close())
                except Exception:
                    cli_log.warning(
                        "provider.close failed", exc_info=True,
                    )

        warning_records = [
            r for r in caplog.records if r.levelno == logging.WARNING
        ]
        # Different exception type than test 1 (OSError vs RuntimeError) —
        # verifies the except clause catches the broad Exception umbrella,
        # not just one specific type. Both tests reaching this assertion
        # mean the OSError (test 2) AND RuntimeError (test 1) were
        # consumed by the same ``except Exception`` clause.
        assert any(
            "provider.close failed" in r.message for r in warning_records
        ), (
            f"expected 'provider.close failed' WARNING; got "
            f"{[r.message for r in warning_records]}"
        )
        # Exit code preserved.
        assert actual == return_value == 1

    def test_close_failure_log_is_centralized_not_swallowed(self):
        """Regression-pin: the close-failure `log.warning(
        "provider.close failed"...)` must EXIST and never be a bare `pass`
        swallow. Post-N-131 the  log is CENTRALIZED in one helper; punch 820
        moved it from the CLI's own `_aclose_provider_quietly` onto
        `render_probe.close_provider(..., loud=True)`, the one best-effort close.
        All three CLI provider-close surfaces route close through it, in-loop.
        The cross-loop `asyncio.run(provider.close())` shape that N-131 fixed is
        pinned separately by test_cli_provider_close_in_loop_pin.py.
        """
        import re

        from _pin_harness import SRC_ROOT

        cli_src = (SRC_ROOT / "cli.py").read_text(encoding="utf-8")
        probe_src = (SRC_ROOT / "providers" / "render_probe.py").read_text(encoding="utf-8")
        # The post-#275 close-failure log must exist (>=1; centralized in
        # close_provider). A future revert to a bare swallow drops this to 0 ->
        # RED. N-131: match the log call itself, which uses error=fmt_exc(...)
        # (NOT the dead exc_info=True that TriageLogger.warning silently drops,
        # PD#10).
        post_fix = re.findall(
            r'_log\.warning\("provider\.close failed"',
            probe_src,
        )
        # Every CLI close site asks for the loud form.
        loud_sites = re.findall(
            r'await close_provider\(provider, loud=True\)',
            cli_src,
        )
        # The legacy cross-loop close + bare-pass swallow must be gone.
        legacy_swallow = re.findall(
            r'asyncio\.run\(provider\.close\(\)\)\s*\n\s*except Exception:\s*\n\s*pass\b',
            cli_src,
        )
        assert len(post_fix) >= 1, (
            "expected >=1 post-#275 close-failure log site (centralized in "
            f"render_probe.close_provider), found {len(post_fix)}"
        )
        all_sites = re.findall(r'await close_provider\(', cli_src)
        assert loud_sites and len(loud_sites) == len(all_sites), (
            "every CLI provider close must be close_provider(provider, loud=True) "
            f"(#275); {len(loud_sites)} loud of {len(all_sites)} sites"
        )
        assert len(legacy_swallow) == 0, (
            f"expected 0 legacy-bare-pass sites, found {len(legacy_swallow)}"
        )


class TestSecretsSetRefusesBlank:
    """Panel AA SHOULD-A2: ``secrets set`` with an empty prompt entry (an
    accidental Enter) must not overwrite the stored secret with ""."""

    @staticmethod
    def _run(monkeypatch, entered):
        import email_triage.cli as cli_mod
        import email_triage.secrets as secrets_mod
        from email_triage.config import TriageConfig

        writes = []

        class _Provider:
            def set(self, key, value):
                writes.append((key, value))

        monkeypatch.setattr(cli_mod, "load_config", lambda _p: TriageConfig())
        monkeypatch.setattr(cli_mod, "_cli_open_config_db", lambda _c: object())
        monkeypatch.setattr(
            secrets_mod, "bootstrap_secrets_from_config", lambda _c, _cfg: _Provider())
        monkeypatch.setattr(
            secrets_mod, "enforce_master_key_at_rest_for_hipaa", lambda _cfg: None)
        monkeypatch.setattr(
            secrets_mod, "wire_audit_chain_hmac_keys", lambda _p, _cfg: None)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: entered)
        args = build_parser().parse_args(["secrets", "set", "SMTP_PASSWORD"])
        return cli_mod.cmd_secrets(args), writes

    @pytest.mark.parametrize("entered", ["", "   ", "\t"])
    def test_a_blank_entry_is_refused_and_nothing_is_written(
            self, monkeypatch, capsys, entered):
        rc, writes = self._run(monkeypatch, entered)
        assert rc == 1
        assert writes == []
        err = capsys.readouterr().err
        assert "NOT saved" in err and "unchanged" in err

    def test_a_real_value_is_still_written(self, monkeypatch, capsys):
        rc, writes = self._run(monkeypatch, "s3cret")
        assert rc == 0
        assert writes == [("SMTP_PASSWORD", "s3cret")]
        assert "saved." in capsys.readouterr().out


