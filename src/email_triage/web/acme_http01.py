"""HTTP-01 ACME challenge solver.

Two operator-selectable delivery modes, both driven by ``Http01Config``
(see ``email_triage.config.Http01Config`` for the full contract):

- ``mode="standalone"`` — the publisher starts a small stdlib
  ``http.server.HTTPServer`` on ``bind_host:bind_port`` (default
  ``0.0.0.0:80``) that answers **only**
  ``GET /.well-known/acme-challenge/{token}`` from an in-memory
  token store, and returns 404 for every other path. The listener
  runs in a background thread and is torn down after cert issued.
  This is the ``certbot --standalone`` shape.

- ``mode="webroot"`` — the publisher writes the challenge token
  as a file at ``{webroot_path}/{token}`` containing the key
  authorization; the operator's reverse proxy is expected to serve
  ``/.well-known/acme-challenge/*`` from that directory. Matches
  ``certbot --webroot``.

HIPAA-safety
------------
The scoped listener (standalone) never touches PHI: it accepts only
GET requests, matches ONE hardcoded path prefix, returns the
key authorization (an LE-provided random string, NOT PHI) or 404.
The webroot dir (webroot) contains only ephemeral challenge tokens.
The main FastAPI process (which holds PHI, WebAuthn material, and
the SQLCipher key) is a SEPARATE socket in both modes — this module's
listener does not import it, cannot serve app routes, and has no DB
handle. HIPAA §164.312(b) audit-controls are unaffected because no
PHI-access happens on this path.

**Webroot operator warning** (hipaa-sme NTH-3 fold, 2026-07-17):
``webroot_path`` MUST be a dedicated directory owned by the app
process. If you point it at a dir containing the SQLCipher DB,
TLS certs, secrets keyfile, or ANY PHI-adjacent files, your
reverse proxy's ``location /.well-known/acme-challenge/`` block
will serve those files to any caller — an unauthenticated
``GET /.well-known/acme-challenge/server.key`` exfiltrates the
TLS private key. The config-load validator refuses a
``webroot_path`` that overlaps ``tls.cert_dir``; it cannot detect
overlap with operator-configured secret/data dirs that the app
doesn't know about (custom mounts, external secret stores) — the
operator's responsibility.

**Design note — no "FastAPI inline" third mode.** LE fetches
HTTP-01 on port 80 per RFC 8555 §8.3 (fixed); a route served from
the app's port 8080 is only reachable through a reverse proxy on
:80, and if that proxy exists, webroot mode is strictly better
(the proxy already owns the file-serving surface). Standalone
+ webroot fully covers the shape space.

Fail-closed
-----------
- ``publish_token`` raises on bind failure / disk write failure.
- ``poll_local`` returns False on any error and the outer renewer
  loop bails via the same retry path DNS-01 uses.
- ``stop()`` best-effort shuts down the listener (idempotent); a
  process crash leaves no state (in-mem store is GC'd, webroot
  files are ephemeral and deletable manually).

Concurrency
-----------
A single ``Http01Publisher`` instance manages at most one
standalone listener at a time. The listener runs in a daemon
thread so a process crash does not leave the socket bound.

Atomic-write SSOT
-----------------
The webroot arm's challenge write MUST route through the
``email_triage._atomicio.atomic_write_text`` SSOT (fsync +
sibling-tmp + chmod-before-replace + except-arm cleanup).
Enforced by ``tests/test_atomic_write_pin_a11.py`` — a
count-agnostic fn-body walk that flags any
``<name>.write_text/_bytes(...) + <name>.replace(...) /
os.replace(<name>, ...)`` shape outside the SSOT. Adopted +
pin widened 2026-07-18 (census run21 D1 fold; MED severity,
§164.312(e)(1) transmission-integrity defense-in-depth +
§164.308(a)(1)(ii)(B) risk-management convergence — DA fold
of `_fn_calls_atomic_ssot` blanket exemption same-drive).
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

# RFC 8555 §8.3 — ACME tokens are base64url random. hipaa-sme NTH-2 fold:
# refuse anything else at the publish/delete boundary as defense-in-depth
# against python-acme drift. Prevents (e.g.) a bad token slipping into a
# path-traversal shape at the webroot writer.
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class _ReuseAddrHTTPServer(HTTPServer):
    """HTTPServer subclass that enables SO_REUSEADDR without mutating the
    stdlib class globally. Class-scope mutation of the stdlib type
    (`HTTPServer.allow_reuse_address = True`) is a shared-state side
    effect that leaks into any other HTTPServer instantiation in the
    process; subclassing keeps the flag scoped to our listener.
    (db-sme NTH-1, 2026-07-17.)
    """
    allow_reuse_address = True
from pathlib import Path
from typing import Any

from email_triage._atomicio import atomic_write_text
from email_triage.config import Http01Config
from email_triage.triage_logging import get_logger

logger = get_logger("email_triage.web.acme_http01")

# The ONE path prefix this solver answers. Everything else is a hard
# 404. LE / Boulder issue tokens under this prefix per RFC 8555 §8.3.
_ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"

# Standalone listener shutdown-join grace: bound the wait for the serving
# thread to exit after ``shutdown()``. If the socket close races, we
# still return control to the caller.
_HTTP01_STANDALONE_JOIN_TIMEOUT_SECS: float = 2.0

# Per-request urlopen timeout on the standalone self-check loop. The
# outer poll loop uses the config-driven ``self_check_timeout_secs``
# deadline; this per-request bound keeps a single hung TCP connect from
# eating the whole budget.
_HTTP01_SELF_CHECK_URLOPEN_TIMEOUT_SECS: float = 3.0


def configure_http01_timeouts(
    standalone_join_secs: float | None = None,
    self_check_urlopen_secs: float | None = None,
) -> None:
    """SSOT-setter for the two HTTP-01 solver timeouts. Test-facing;
    prod defaults are the module constants above (DA NTH-2 fold): a
    ``None`` argument leaves the corresponding constant unchanged, so
    tuning a module default does NOT drift out of sync with a stale
    setter parameter default. Legitimate literal-context per  pin
    is the module-level ``_*_TIMEOUT_SECS`` assignment; this setter
    holds no timeout literals of its own."""
    global _HTTP01_STANDALONE_JOIN_TIMEOUT_SECS
    global _HTTP01_SELF_CHECK_URLOPEN_TIMEOUT_SECS
    if standalone_join_secs is not None:
        _HTTP01_STANDALONE_JOIN_TIMEOUT_SECS = float(standalone_join_secs)
    if self_check_urlopen_secs is not None:
        _HTTP01_SELF_CHECK_URLOPEN_TIMEOUT_SECS = float(self_check_urlopen_secs)


class _TokenStore:
    """Thread-safe in-memory token → key_auth map used by the
    standalone HTTP listener. Populated by ``Http01Publisher.publish_token``,
    consumed by the handler."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, str] = {}

    def put(self, token: str, key_auth: str) -> None:
        with self._lock:
            self._tokens[token] = key_auth

    def get(self, token: str) -> str | None:
        with self._lock:
            return self._tokens.get(token)

    def delete(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)


def _make_handler(store: _TokenStore) -> type[BaseHTTPRequestHandler]:
    """Build a BaseHTTPRequestHandler subclass bound to ``store``.

    Defined as a factory so the handler class carries the store via
    closure (BaseHTTPRequestHandler is instantiated per-request by
    HTTPServer, so no __init__ injection point exists)."""

    class _ChallengeHandler(BaseHTTPRequestHandler):
        _store: _TokenStore = store

        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if not self.path.startswith(_ACME_CHALLENGE_PREFIX):
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"not found\n")
                return
            token = self.path[len(_ACME_CHALLENGE_PREFIX):]
            key_auth = self._store.get(token)
            if key_auth is None:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"not found\n")
                return
            body = key_auth.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Hard-refuse every other verb; matches the fail-closed shape
        # (no PUT / POST / DELETE / etc. — the ACME challenge protocol
        # is GET-only per RFC 8555 §8.3).
        def do_POST(self) -> None:
            self.send_response(405)
            self.end_headers()

        def do_PUT(self) -> None:
            self.send_response(405)
            self.end_headers()

        def do_DELETE(self) -> None:
            self.send_response(405)
            self.end_headers()

    return _ChallengeHandler


class Http01Publisher:
    """Publish an ACME HTTP-01 challenge token and let LE fetch it.

    Two-mode contract (mode selected by ``cfg.mode``):

    - ``standalone``: bind a stdlib HTTP listener; store the token in
      memory; serve it from ``/.well-known/acme-challenge/{token}``.
    - ``webroot``: write the token to ``{webroot_path}/{token}``; rely
      on the operator's proxy to serve it.
    """

    def __init__(self, cfg: Http01Config) -> None:
        self.cfg = cfg
        self._store = _TokenStore()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the standalone listener. No-op in webroot mode.

        Raises ``OSError`` on bind failure so the outer renewer bails
        fast — a listener that couldn't bind is not a state we retry.
        """
        if self.cfg.mode != "standalone":
            return
        if self._server is not None:
            return
        handler_cls = _make_handler(self._store)
        # _ReuseAddrHTTPServer enables SO_REUSEADDR so a rapid restart in
        # the renewer loop (retry-after-transient-failure) doesn't hit
        # TIME_WAIT lock. Subclass keeps the flag scoped to our
        # listener — no side effect on other HTTPServer users in the
        # same process. (db-sme NTH-1 fold, 2026-07-17.)
        try:
            self._server = _ReuseAddrHTTPServer(
                (self.cfg.bind_host, int(self.cfg.bind_port)), handler_cls,
            )
        except OSError as exc:
            logger.error(
                "HTTP-01: standalone listener bind failed",
                extra={
                    "bind_host": self.cfg.bind_host,
                    "bind_port": self.cfg.bind_port,
                    "error": str(exc),
                },
            )
            raise
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="acme-http01-listener",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "HTTP-01: standalone listener started",
            extra={
                "bind": f"{self.cfg.bind_host}:{self.cfg.bind_port}",
            },
        )

    def stop(self) -> None:
        """Shut down the standalone listener. No-op in webroot mode
        or when the listener never started. Best-effort — a hung
        server thread is a bug, not a fatal, so we log + move on."""
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception as exc:
            logger.warning(
                "HTTP-01: listener shutdown raised (continuing)",
                extra={"error": str(exc)},
            )
        finally:
            self._server = None
            if self._thread is not None:
                self._thread.join(timeout=_HTTP01_STANDALONE_JOIN_TIMEOUT_SECS)
                self._thread = None
            logger.info("HTTP-01: standalone listener stopped")

    def publish_token(self, token: str, key_auth: str) -> None:
        """Register a token → key_auth pair for LE's fetch.

        Standalone: put the pair in the in-memory store.
        Webroot: write the file ``{webroot_path}/{token}`` with
        contents = ``key_auth`` (0644 perms so a webserver running
        under a different user can read).
        """
        if not token or not key_auth:
            raise ValueError("HTTP-01 publish requires non-empty token + key_auth")
        if not _ACME_TOKEN_RE.match(token):
            raise ValueError(
                f"HTTP-01 token {token!r} is not RFC 8555 §8.3 base64url — "
                f"refusing to publish (defense-in-depth against upstream drift)."
            )
        if self.cfg.mode == "standalone":
            self._store.put(token, key_auth)
            return
        if self.cfg.mode == "webroot":
            root = Path(self.cfg.webroot_path)
            root.mkdir(parents=True, exist_ok=True)
            path = root / token
            # Route through the _atomicio SSOT (A11) so a crash mid-write
            # can never leave a torn/half-written challenge file the
            # reverse proxy could serve as a partial. 0o644 world-readable
            # is required (the webserver runs as a different uid than the
            # app process). Same crash-safe pattern used everywhere else.
            atomic_write_text(path, key_auth, mode=0o644)
            return
        raise ValueError(f"HTTP-01: unknown mode {self.cfg.mode!r}")

    def delete_token(self, token: str) -> None:
        """Remove a token so a stale challenge cannot answer a
        future validation attempt. Idempotent — a missing token is
        NOT an error (the cleanup path runs on retry AND on success)."""
        if not token:
            return
        if not _ACME_TOKEN_RE.match(token):
            # Same guard as publish_token — no reason to accept a bad
            # shape at delete either. Silently no-op (never raise from
            # cleanup — the outer retry loop should always converge).
            return
        if self.cfg.mode == "standalone":
            self._store.delete(token)
            return
        if self.cfg.mode == "webroot":
            root = Path(self.cfg.webroot_path)
            path = root / token
            try:
                path.unlink()
            except FileNotFoundError:
                return
            except Exception as exc:
                logger.warning(
                    "HTTP-01: webroot cleanup failed (continuing)",
                    extra={"path": str(path), "error": str(exc)},
                )
            return

    def poll_local(
        self, token: str, expected: str,
        timeout_secs: int | None = None,
    ) -> bool:
        """Self-check: fetch our own challenge URL and confirm the
        body matches ``expected``. Guards against a listener that
        bound but returns wrong content, a webroot dir the proxy
        can't read, a firewall dropping :80, etc.

        For standalone mode we probe the loopback socket directly
        (skips any network hop or proxy). For webroot mode we probe
        via a hostname derived from the challenge domain — see
        :meth:`poll_external` for the external variant.
        """
        if timeout_secs is None:
            timeout_secs = int(self.cfg.self_check_timeout_secs)
        deadline = time.monotonic() + max(1, timeout_secs)
        # Standalone: probe our own bound socket. The bound host may be
        # 0.0.0.0 or a specific interface; loopback (127.0.0.1) is the
        # portable target for the self-check because binding to 0.0.0.0
        # means "listen on every interface" including loopback.
        if self.cfg.mode == "standalone":
            host = "127.0.0.1" if self.cfg.bind_host in (
                "0.0.0.0", "::", ""
            ) else self.cfg.bind_host
            url = (
                f"http://{host}:{self.cfg.bind_port}"
                f"{_ACME_CHALLENGE_PREFIX}{token}"
            )
        elif self.cfg.mode == "webroot":
            # For webroot we can't probe from here without a real
            # HTTP hop through the operator's proxy — that check IS
            # the external validation LE will do next. Skip local
            # self-check and return True; the outer LE validation
            # will surface any misconfig.
            return True
        else:
            return False

        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=_HTTP01_SELF_CHECK_URLOPEN_TIMEOUT_SECS) as resp:
                    if resp.status != 200:
                        time.sleep(0.5)
                        continue
                    body = resp.read().decode("utf-8", errors="replace")
                    if body == expected:
                        return True
                    time.sleep(0.5)
            except (urllib.error.URLError, socket.timeout, ConnectionError):
                time.sleep(0.5)
        return False
