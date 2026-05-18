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

    def test_refuses_if_exists(self, tmp_path):
        config_file = tmp_path / "email-triage.yaml"
        config_file.write_text("existing")
        parser = build_parser()
        args = parser.parse_args(["init", str(tmp_path)])
        result = cmd_init(args)
        assert result == 1


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
""")
        monkeypatch.chdir(tmp_path)
        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "status"])
        result = cmd_status(args)
        assert result == 0


