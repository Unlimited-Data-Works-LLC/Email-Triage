# Tests: the network rule

No test reaches a host outside this machine. Two layers enforce it.

## 1. The run-time guard: `tests/_network_guard.py`

`tests/conftest.py` installs it from `pytest_configure`, process-wide. It covers collection,
session fixtures, the TestClient portal thread, `to_thread` workers, and a task that outlives
its test.

It refuses these, at once:

| Seam | Refused | Error |
|---|---|---|
| `socket.socket.connect` / `connect_ex` (smtplib, imaplib, http.client, urllib, sync httpx, ssl) | a non-loopback address | `OutboundConnectRefused` (a `ConnectionRefusedError`) |
| asyncio `sock_connect`, selector AND proactor loops (aioimaplib, async httpx, anyio) | a non-loopback address | `OutboundConnectRefused` |
| `socket.socket.sendto` (unconnected UDP, e.g. a hand-rolled DNS query) | a non-loopback address | `OutboundConnectRefused` |
| `socket.getaddrinfo`, `gethostbyname`, `gethostbyname_ex` | a name that is not `localhost` and not an IP literal | `OutboundLookupRefused` (a `socket.gaierror`) |
| `socket.gethostbyaddr` (and so `getfqdn`), `getnameinfo` without `NI_NUMERICHOST` | a reverse lookup of anything but loopback, IP literal included | `OutboundLookupRefused` |

It allows loopback (127.0.0.0/8, ::1, `localhost`), the unspecified address, `AF_UNIX` and
`socket.socketpair`. A loopback server you start in the test is the way to test a real socket.

A refusal names the test and the target:

```
outbound network refused in tests: tests/test_web/test_x.py::test_y -> imap.vendor.com:993
(socket.getaddrinfo). A test must not reach a non-loopback host: stub the client or provider,
or serve it on 127.0.0.1 (tests/_network_guard.py).
```

Code under test usually turns the refusal into its own failure path (a provider error, a
fallback page), so a test that passed before can still pass. The refusal arrives at once,
where a real attempt could hang until a timeout.

Opt-out, for a manual live-integration test only:

```python
@pytest.mark.allow_outbound_network(reason="manual integration test: talks to the live X "
                                           "named by $ENV_VAR, and skips when that is unset")
```

The reason is required (`tests/test_network_guard_pin.py`). Ask before adding one. The live host
comes from an env var, never a literal, and the test skips when the env var is unset.
`-p no:network-guard` turns the guard off, and `tests/test_network_guard.py` then goes red.

A raw assignment that removes the guard from a seam (`socket.getaddrinfo = ...`, not
`monkeypatch`) fails that test at teardown (`GuardRemoved`), and the guard is put back.

The guard does not cover subprocesses, a C extension that resolves or opens its own sockets,
`socket.sendmsg`, or the proactor loop's datagram sends.

## 2. The source pin: `tests/test_test_hosts_cannot_leave_pin.py`

A host literal in a connect-target position must not be able to leave the machine, even with
the guard off. Connect-target positions:

- a `host` / `*_host` / `hostname` / `server` / `url` / `endpoint` / `*_url` key, keyword or
  assignment;
- the first argument of an IMAP, SMTP or socket connector;
- a URL passed to an HTTP verb.

| Use | Do not use |
|---|---|
| `imap.example.invalid`, any name under `.invalid`, `.test` or `.example` | a real vendor host (`imap.gmail.com`, `api.openai.com`, ...) |
| `127.0.0.1`, `localhost` | `example.com` / `.net` / `.org`: reserved, but they resolve in public DNS |
| a 192.0.2.x / 198.51.100.x / 203.0.113.x documentation address | `.lan`, `.local`, `.internal`, `.ts.net` names |
| `testserver` (the TestClient's in-process host) | a single-label name such as `x` (the resolver appends the search domain and asks) |

Email addresses are not connect targets; the pin does not read them.

A test whose subject IS a product's exact host, such as the privacy allowlist or the
update check's default endpoint, gets an `ALLOW` entry in the pin, keyed by
`(repo-relative path, host)`, with its reason.
