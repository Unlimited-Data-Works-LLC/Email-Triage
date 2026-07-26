"""Unit tests for the HTTP-01 ACME challenge solver.

Covers Http01Publisher in both modes:
- standalone: bound stdlib HTTPServer, in-memory token store, self-check via loopback GET
- webroot:    file drop under webroot_path

Contract asserted:
- 200 body == key_authorization for registered token; 404 otherwise
- Non-GET verbs → 405
- delete_token idempotent
- publish requires non-empty (token, key_auth)
- webroot: file written atomically (tmp + rename)
- webroot self-check returns True (external validation is LE's job)
- standalone stop() releases the socket so a fresh publisher can rebind
- Custom mode unsupported → ValueError
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from email_triage.config import Http01Config
from email_triage.web.acme_http01 import Http01Publisher


def _pick_free_port() -> int:
    """Grab a free ephemeral port so parallel test workers don't collide."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def standalone_cfg():
    return Http01Config(
        mode="standalone",
        bind_host="127.0.0.1",
        bind_port=_pick_free_port(),
        self_check_timeout_secs=3,
    )


@pytest.fixture
def webroot_cfg(tmp_path):
    return Http01Config(
        mode="webroot",
        webroot_path=str(tmp_path / "acme-challenge"),
        self_check_timeout_secs=3,
    )


class TestStandaloneMode:
    def test_publish_then_fetch_returns_key_auth(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            pub.publish_token("abc123", "abc123.keyauth-body")
            url = (
                f"http://127.0.0.1:{standalone_cfg.bind_port}"
                f"/.well-known/acme-challenge/abc123"
            )
            with urllib.request.urlopen(url, timeout=2) as resp:
                assert resp.status == 200
                assert resp.read().decode("utf-8") == "abc123.keyauth-body"
        finally:
            pub.stop()

    def test_unknown_token_returns_404(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            url = (
                f"http://127.0.0.1:{standalone_cfg.bind_port}"
                f"/.well-known/acme-challenge/notregistered"
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(url, timeout=2)
            assert exc_info.value.code == 404
        finally:
            pub.stop()

    def test_non_challenge_path_returns_404(self, standalone_cfg):
        """Hard-refuse everything except the challenge prefix. Guards against
        an operator plugging the standalone listener into a wider path (say,
        via a reverse proxy misconfig) and it silently serving other files."""
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            url = f"http://127.0.0.1:{standalone_cfg.bind_port}/health"
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(url, timeout=2)
            assert exc_info.value.code == 404
        finally:
            pub.stop()

    def test_non_get_verb_returns_405(self, standalone_cfg):
        """The ACME HTTP-01 protocol is GET-only per RFC 8555 §8.3. Any
        other verb must fail-closed with 405 — belt-and-suspenders on
        the same principle as the path check."""
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            url = f"http://127.0.0.1:{standalone_cfg.bind_port}/"
            req = urllib.request.Request(url, method="POST", data=b"body")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=2)
            assert exc_info.value.code == 405
        finally:
            pub.stop()

    def test_delete_token_removes_from_store(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            pub.publish_token("t1", "kv1")
            url = (
                f"http://127.0.0.1:{standalone_cfg.bind_port}"
                f"/.well-known/acme-challenge/t1"
            )
            with urllib.request.urlopen(url, timeout=2) as resp:
                assert resp.status == 200
            pub.delete_token("t1")
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(url, timeout=2)
            assert exc_info.value.code == 404
        finally:
            pub.stop()

    def test_delete_token_missing_is_no_op(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            pub.delete_token("never-registered")
        finally:
            pub.stop()

    def test_poll_local_hits_bound_socket(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            pub.publish_token("tok", "expected-body")
            assert pub.poll_local("tok", "expected-body") is True
        finally:
            pub.stop()

    def test_poll_local_false_on_wrong_body(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        try:
            pub.publish_token("tok", "actual-body")
            assert pub.poll_local(
                "tok", "different-body", timeout_secs=2,
            ) is False
        finally:
            pub.stop()

    def test_stop_releases_socket_for_rebind(self, standalone_cfg):
        """A rapid renewer retry must be able to re-open the same port
        after stop(). If stop() left the socket in TIME_WAIT without
        SO_REUSEADDR, the next start() would fail — the retry loop uses
        the same publisher instance, but a bail-and-retry-with-fresh-
        publisher path (test scaffolding, or a future re-init) needs a
        clean release."""
        p1 = Http01Publisher(standalone_cfg)
        p1.start()
        p1.stop()
        p2 = Http01Publisher(standalone_cfg)
        p2.start()
        p2.stop()

    def test_start_twice_is_no_op(self, standalone_cfg):
        """Idempotent start — a retry-loop call shape that re-invokes
        start() must not double-bind."""
        pub = Http01Publisher(standalone_cfg)
        pub.start()
        pub.start()  # must not raise
        pub.stop()

    def test_stop_without_start_is_no_op(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        pub.stop()

    def test_publish_requires_token_and_key_auth(self, standalone_cfg):
        pub = Http01Publisher(standalone_cfg)
        with pytest.raises(ValueError):
            pub.publish_token("", "kv")
        with pytest.raises(ValueError):
            pub.publish_token("tok", "")


class TestWebrootMode:
    def test_publish_writes_file(self, webroot_cfg):
        pub = Http01Publisher(webroot_cfg)
        pub.start()  # no-op in webroot mode
        try:
            pub.publish_token("tok", "keyauth-body")
            path = Path(webroot_cfg.webroot_path) / "tok"
            assert path.exists()
            assert path.read_text(encoding="utf-8") == "keyauth-body"
        finally:
            pub.stop()

    def test_publish_creates_webroot_dir_if_missing(self, webroot_cfg):
        # tmp_path/acme-challenge does not exist until publish creates it.
        assert not Path(webroot_cfg.webroot_path).exists()
        pub = Http01Publisher(webroot_cfg)
        pub.publish_token("tok", "kv")
        assert Path(webroot_cfg.webroot_path).exists()
        assert (Path(webroot_cfg.webroot_path) / "tok").is_file()

    def test_publish_writes_atomically_via_tmp_rename(self, webroot_cfg):
        """Guarantee that a webserver can't observe a partial-write:
        the file exists with full content once it appears at the final
        name (implemented via tmp + rename)."""
        pub = Http01Publisher(webroot_cfg)
        pub.publish_token("tok", "expected-content")
        final = Path(webroot_cfg.webroot_path) / "tok"
        tmp = Path(webroot_cfg.webroot_path) / ".tok.tmp"
        assert final.exists()
        assert final.read_text(encoding="utf-8") == "expected-content"
        # tmp is renamed to final; final tmp path should not be lingering.
        assert not tmp.exists()

    def test_delete_token_removes_file(self, webroot_cfg):
        pub = Http01Publisher(webroot_cfg)
        pub.publish_token("tok", "kv")
        final = Path(webroot_cfg.webroot_path) / "tok"
        assert final.exists()
        pub.delete_token("tok")
        assert not final.exists()

    def test_delete_token_missing_file_is_no_op(self, webroot_cfg):
        pub = Http01Publisher(webroot_cfg)
        # Directory may not even exist; delete must not raise.
        pub.delete_token("never-registered")

    def test_poll_local_skips_check_in_webroot_mode(self, webroot_cfg):
        """Webroot mode has no built-in listener to self-check against;
        the caller relies on LE's external validation to surface any
        proxy misconfig. poll_local returns True so the outer renewer
        proceeds to the answer_challenge step."""
        pub = Http01Publisher(webroot_cfg)
        pub.publish_token("tok", "kv")
        assert pub.poll_local("tok", "kv") is True


class TestModeValidation:
    def test_publish_unknown_mode_raises(self):
        cfg = Http01Config(mode="sidecar", webroot_path="/tmp/x")
        pub = Http01Publisher(cfg)
        with pytest.raises(ValueError, match="unknown mode"):
            pub.publish_token("tok", "kv")

    def test_start_no_op_in_webroot_mode(self, webroot_cfg):
        """Webroot mode never binds a socket; start() returns cleanly."""
        pub = Http01Publisher(webroot_cfg)
        pub.start()
        pub.stop()
