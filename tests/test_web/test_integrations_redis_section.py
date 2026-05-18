"""Tests for the /admin/integrations Classification cache section (#151).

Covers the GET render (form fields present) + the POST save handler
(persists URL + TTL onto ``config.redis_cache`` and round-trips through
YAML when a file exists). The save handler also swaps the install-level
singleton in place — we assert that side effect via
``get_install_classification_cache``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from email_triage.cache.classification import (
    get_install_classification_cache,
    set_install_classification_cache,
)
from email_triage.config import RedisCacheConfig
from email_triage.web.auth import SESSION_COOKIE_NAME


@pytest.fixture(autouse=True)
def _reset_install_singleton():
    set_install_classification_cache(None)
    yield
    set_install_classification_cache(None)


@pytest.fixture
def yaml_in_tmpdir(tmp_path, monkeypatch):
    """Run each test inside a tmp working dir with an empty config file.

    The save handler invokes ``_write_config_yaml`` which searches for
    ``./email-triage.yaml`` etc. — without a file present the YAML write
    raises FileNotFoundError. Touch one in the test's cwd so the write
    actually exercises round-trip.
    """
    target = tmp_path / "email-triage.yaml"
    target.write_text("classifier:\n  backend: ollama\n")
    monkeypatch.chdir(tmp_path)
    return target


class TestRedisCacheSectionRender:
    def test_section_present(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        client.raise_server_exceptions = True
        resp = client.get("/admin/integrations")
        assert resp.status_code == 200
        body = resp.text
        # Section heading + form fields are present.
        assert "Classification cache" in body
        assert 'name="redis_cache_url"' in body
        assert 'name="redis_cache_ttl_secs"' in body
        # Counter line surfaces (zeros on a fresh process).
        assert "hits" in body
        assert "misses" in body
        # The privacy-boundary copy is present (on-LAN warning).
        assert "On-LAN only" in body
        # The HIPAA defence-in-depth note is present.
        assert "HIPAA-flagged" in body


class TestRedisCacheSave:
    def test_save_persists_url_and_ttl(
        self, client, admin_cookies, yaml_in_tmpdir,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/save",
            data={
                "redis_cache_url": "redis://example.lan:6379/2",
                "redis_cache_ttl_secs": "86400",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        # In-memory config mutated.
        cfg = client.app.state.config
        assert cfg.redis_cache.url == "redis://example.lan:6379/2"
        assert cfg.redis_cache.ttl_secs == 86400
        # Install singleton swapped.
        cache = get_install_classification_cache()
        assert cache is not None
        assert cache.enabled is True
        # YAML round-trip preserved.
        text = yaml_in_tmpdir.read_text()
        assert "redis_cache" in text
        assert "redis://example.lan:6379/2" in text
        assert "86400" in text

    def test_save_empty_url_disables_cache(
        self, client, admin_cookies, yaml_in_tmpdir,
    ):
        # Seed an enabled cache first.
        client.app.state.config.redis_cache = RedisCacheConfig(
            url="redis://example.lan:6379/2", ttl_secs=86400,
        )
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/save",
            data={
                "redis_cache_url": "",
                "redis_cache_ttl_secs": "86400",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        # Cache disabled.
        cfg = client.app.state.config
        assert cfg.redis_cache.url == ""
        # Install singleton dropped (build_cache_from_config returns
        # None when URL is empty).
        assert get_install_classification_cache() is None

    def test_save_invalid_ttl_falls_back_to_default(
        self, client, admin_cookies, yaml_in_tmpdir,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/save",
            data={
                "redis_cache_url": "redis://example.lan:6379/2",
                "redis_cache_ttl_secs": "not-a-number",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        # Falls back to default (30 days).
        cfg = client.app.state.config
        assert cfg.redis_cache.ttl_secs == 30 * 24 * 3600

    def test_save_clamps_ttl_to_floor(
        self, client, admin_cookies, yaml_in_tmpdir,
    ):
        """Sub-floor TTL snaps to ``MIN_TTL_SECS`` (3600 s = 1 hour).

        Spec range [3600, 7_776_000]. The old 60-s floor was tightened
        on 2026-05-12 — anything shorter than an hour is pointless given
        typical poll cadences, and Redis itself rejects ex=0.
        """
        from email_triage.cache.classification import MIN_TTL_SECS
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/save",
            data={
                "redis_cache_url": "redis://example.lan:6379/2",
                "redis_cache_ttl_secs": "5",  # below the 3600 s floor
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        cfg = client.app.state.config
        assert cfg.redis_cache.ttl_secs == MIN_TTL_SECS

    def test_save_clamps_ttl_to_ceiling(
        self, client, admin_cookies, yaml_in_tmpdir,
    ):
        """Above-ceiling TTL snaps to ``MAX_TTL_SECS`` (90 days)."""
        from email_triage.cache.classification import MAX_TTL_SECS
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/save",
            data={
                "redis_cache_url": "redis://example.lan:6379/2",
                "redis_cache_ttl_secs": str(10 ** 10),  # 317 years
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        cfg = client.app.state.config
        assert cfg.redis_cache.ttl_secs == MAX_TTL_SECS


class TestRedisCacheFlush:
    """The Flush button on /admin/integrations drops every classification
    cache key. Auth-gated; CSRF-required."""

    def test_flush_unconfigured_cache_redirects_with_error(
        self, client, admin_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.post(
            "/admin/integrations/cache/flush",
            follow_redirects=False,
        )
        assert resp.status_code == 303
        loc = resp.headers.get("location", "")
        # The flush_err querystring carries the "not configured" copy.
        assert "/admin/integrations" in loc
        assert "flush_err=" in loc

    def test_flush_anonymous_blocked(self, client):
        resp = client.post(
            "/admin/integrations/cache/flush",
            follow_redirects=False,
        )
        # Login redirect or 401/403; MUST NOT be the success redirect.
        assert resp.status_code in (302, 303, 401, 403)
        loc = resp.headers.get("location", "")
        assert "flushed=" not in loc


class TestRedisCacheAuth:
    def test_anonymous_cannot_save_redis_cache(self, client, yaml_in_tmpdir):
        resp = client.post(
            "/admin/integrations/save",
            data={"redis_cache_url": "redis://attacker.lan:6379/0"},
            follow_redirects=False,
        )
        # Redirect to login OR 403; never 303 to ?saved=1.
        assert resp.status_code in (302, 303, 401, 403)
        # If a redirect, it must NOT be the success one.
        loc = resp.headers.get("location", "")
        assert "saved=1" not in loc
