"""A local stand-in for the Ollama HTTP API, for keep_alive behaviour tests.

Serves ``127.0.0.1`` on an ephemeral port from a daemon thread, records every
request, and returns a configurable ``/api/ps`` so a test can put the daemon in
any residency state (Forever pin, finite TTL, model not loaded, probe failure)
without touching a real inference host.

``/api/show`` returns ``show_parameters`` as its ``parameters`` field, an
OBJECT by default. The real daemon returns a multi-line string; the
PowerShell client's discovery reads ``$show.parameters.num_ctx``, which
throws under StrictMode on a string. That is a separate, pre-existing defect;
the object default keeps these tests about keep_alive only.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A Forever pin as Ollama reports it: now + MaxInt64 ns lands ~292 years out,
# with Go's RFC3339Nano (up to 9 fractional digits). Two spellings, because
# PowerShell's JSON reader turns only the second into a [datetime].
FOREVER_EXPIRES_NANO = "2318-02-01T12:00:00.123456789-05:00"
FOREVER_EXPIRES_SHORT = "2318-02-01T12:00:00.5-05:00"
FINITE_EXPIRES = "2026-10-11T12:10:00.5-04:00"

# /api/ps behaviours a test can select.
PS_OK = "ok"            # 200 + {"models": stub.ps_models}
PS_HTTP_500 = "500"     # non-200
PS_GARBAGE = "garbage"  # 200 + a body that is not JSON
PS_DROP = "drop"        # close the socket with no response (network error)

# Panel B3 db-sme F3: the clients honour proxy variables (urllib's urlopen, and
# .NET's HttpClient under pwsh), so on a runner with http_proxy set and no
# no_proxy entry for 127.0.0.1 the stub's traffic would go to the proxy and the
# test would read RED for the environment, not the code.
PROXY_ENV = ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")


def isolate_from_proxies(monkeypatch) -> None:
    """Clear every proxy variable and exempt the loopback stub, for this test
    and every child process it starts (they inherit ``os.environ``)."""
    for name in PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


class OllamaStub:
    """Start with :meth:`start`, stop with :meth:`close`; ``url`` is the API root."""

    def __init__(self) -> None:
        self.ps_mode = PS_OK
        self.ps_models: list[dict] = []
        self.show_parameters: object = {"num_ctx": 4096}
        self.requests: list[tuple[str, str, object]] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def set_loaded(self, model: str, expires_at: str) -> None:
        """Make ``/api/ps`` report exactly one loaded model."""
        self.ps_models = [{"name": model, "model": model, "expires_at": expires_at}]

    @property
    def url(self) -> str:
        assert self._server is not None, "stub not started"
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def chat_bodies(self) -> list[dict]:
        with self._lock:
            return [b for (m, p, b) in self.requests if m == "POST" and p == "/api/chat"]

    def ps_hits(self) -> int:
        with self._lock:
            return sum(1 for (m, p, _b) in self.requests if m == "GET" and p == "/api/ps")

    def _record(self, method: str, path: str, body: object) -> None:
        with self._lock:
            self.requests.append((method, path, body))

    def start(self) -> "OllamaStub":
        stub = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # keep test output clean
                pass

            def _send_json(self, status: int, payload: object) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                stub._record("GET", self.path, None)
                if self.path == "/api/version":
                    self._send_json(200, {"version": "0.0.0-stub"})
                elif self.path == "/api/tags":
                    self._send_json(200, {"models": list(stub.ps_models)})
                elif self.path == "/api/ps":
                    if stub.ps_mode == PS_DROP:
                        self.close_connection = True
                        return
                    if stub.ps_mode == PS_HTTP_500:
                        self._send_json(500, {"error": "stub failure"})
                        return
                    if stub.ps_mode == PS_GARBAGE:
                        data = b"<html>not json</html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    self._send_json(200, {"models": list(stub.ps_models)})
                else:
                    self._send_json(404, {"error": "not found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else None
                except ValueError:
                    body = raw.decode("utf-8", "replace")
                stub._record("POST", self.path, body)
                if self.path == "/api/chat":
                    self._send_json(200, {
                        "message": {"role": "assistant", "content": "ok"},
                        "done": True,
                    })
                elif self.path == "/api/show":
                    self._send_json(200, {"parameters": stub.show_parameters})
                else:
                    self._send_json(404, {"error": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
