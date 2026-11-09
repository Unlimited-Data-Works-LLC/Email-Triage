"""The ``deploy.sh`` step-9b probe (operator ruling 2026-10-25) reads the SITE's
``embedding.auto_update`` before it asks ``update_notice()``.

Before the fix the probe ran in a fresh ``python -`` where the switch was unset, so
it printed the DEFAULT (automatic) wording even for a site whose config says
``auto_update: false``, and told every site to click. The probe is now one call,
``embedding_bits.deploy_notice_lines()``, which is what this file tests against a real
stale prefix and a real config file. That ``deploy.sh`` calls it, and that only the
click kind is told to click, is pinned in ``tests/test_n569_manifest_set_history_pin.py``
(``deploy.sh`` does not ship, so no shipped test may read it).
"""

from __future__ import annotations

import sys

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", None)  # the fresh-interpreter state
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(eb, "_auto_deferred", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


def _lines() -> dict[str, str]:
    return dict(line.split(":", 1) for line in eb.deploy_notice_lines())


def _site(tmp_path, monkeypatch, auto_update):
    monkeypatch.chdir(tmp_path)
    body = "persistence:\n  encryption_enabled: false\n"
    if auto_update is not None:
        body += f"embedding:\n  auto_update: {str(auto_update).lower()}\n"
    (tmp_path / "email-triage.yaml").write_text(body, encoding="utf-8")


def test_a_site_with_auto_update_off_is_told_to_click(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path / "rt", monkeypatch, steps=(False,))
    _site(tmp_path, monkeypatch, False)
    out = _lines()
    assert out["ET569K"] == "update"
    assert out["ET569"].startswith("Embedding runtime update required")


def test_a_default_site_is_told_the_app_does_it(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path / "rt", monkeypatch, steps=(False,))
    _site(tmp_path, monkeypatch, None)
    out = _lines()
    assert out["ET569K"] == "auto"
    assert out["ET569"].startswith("Embedding runtime update in progress")


def test_a_current_runtime_prints_current(tmp_path, monkeypatch):
    make_verified_prefix(tmp_path / "rt", monkeypatch)
    _site(tmp_path, monkeypatch, False)
    out = _lines()
    assert out["ET569"] == "current" and out["ET569K"] == "current"


def test_an_integrity_refusal_is_a_click_kind_even_on_an_auto_site(tmp_path, monkeypatch):
    """The app never heals an integrity refusal, so a deploy that leaves one is told
    to click, not that the app does it."""
    prefix, site, _m = make_versioned_prefix(tmp_path / "rt", monkeypatch, steps=(True,))
    planted = site / "planted_pkg-6.6.6.dist-info"
    planted.mkdir()
    (planted / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: planted-pkg\nVersion: 6.6.6\n", encoding="utf-8",
    )
    _site(tmp_path, monkeypatch, True)
    out = _lines()
    assert out["ET569K"] == "update"
    assert out["ET569"].startswith("Embedding runtime refused")


def test_an_unreadable_config_leaves_the_default_and_never_raises(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path / "rt", monkeypatch, steps=(False,))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "email-triage.yaml").write_text("embedding: [not, a, mapping\n", encoding="utf-8")
    assert eb.wire_auto_update_from_site_config() is False
    assert _lines()["ET569K"] == "auto"  # the config key's own default
