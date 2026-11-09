"""hipaa-sme panel S NOTE (2026-10-25), binding for AUTOUPD: the automatic trigger
decides "stale" from LOCAL data alone.

It compares the INSTALLED set only with the manifest shipped in the running image
(``embedding_bits.resolve_manifest_path()``). It never asks PyPI, PyTorch or Hugging
Face what is newer (the project bans update checks), and it downloads only the exact
files and hashes that manifest names, inside ``update_runtime``, after staleness is
already decided.

These tests fail if any request leaves the process BEFORE that decision: every
network door (``socket.getaddrinfo`` / ``socket.connect`` to a non-loopback host, and
the installer's own ``_http_download`` / ``_fetch_with_retry`` / ``_run_pip_install``
seams) is recorded and refused, then the trigger runs for each way a tick can end.
The structural twin is ``tests/test_autoupd_single_funnel_pin.py::
test_the_runner_imports_no_network_client``.

SCOPE CAVEAT: the guard sees Python-level sockets and the three installer seams, not
a subprocess or a C extension that opens its own socket; the structural twin bounds
the first, and the trigger path starts no subprocess before ``update_runtime``.
"""

from __future__ import annotations

import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import embedding_update_runner as ru
from email_triage.web.db import set_setting

_LOOPBACK = (None, "", "localhost", "127.0.0.1", "::1")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


@pytest.fixture
def network(monkeypatch):
    """Record and refuse every outbound door. The returned list is the evidence."""
    calls: list[tuple] = []
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect

    def getaddrinfo(host, *a, **k):
        if host not in _LOOPBACK:
            calls.append(("getaddrinfo", host))
            raise OSError("blocked by the no-update-check test")
        return real_getaddrinfo(host, *a, **k)

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOOPBACK:
            calls.append(("connect", host))
            raise OSError("blocked by the no-update-check test")
        return real_connect(self, address)

    def seam(name):
        def blocked(*a, **k):
            calls.append((name,))
            raise OSError("blocked by the no-update-check test")
        return blocked

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    for name in ("_http_download", "_fetch_with_retry", "_run_pip_install"):
        monkeypatch.setattr(eb, name, seam(name))
    return calls


@pytest.fixture
def fake_app(db):
    return SimpleNamespace(state=SimpleNamespace(db=db))


@pytest.fixture
def events(monkeypatch):
    """Ordered log of every read of a manifest file, as ``("manifest", Path)``;
    the update stand-in appends ``"update_runtime"`` when the funnel is entered."""
    log: list = []
    real = eb._load_raw_manifest

    def spy(path):
        log.append(("manifest", Path(path)))
        return real(path)

    monkeypatch.setattr(eb, "_load_raw_manifest", spy)
    return log


class _Update:
    """``update_runtime`` stand-in: records the world at the moment the funnel is
    entered (the point after which downloads are allowed), then finishes."""

    def __init__(self, network, events):
        self.network, self.events = network, events
        self.calls = 0
        self.network_at_entry: list[tuple] | None = None
        self.manifest_path = None

    def __call__(self, **kw):
        self.calls += 1
        self.events.append("update_runtime")
        self.network_at_entry = list(self.network)
        self.manifest_path = kw.get("manifest_path")
        eb._update_state(kw["conn"], status="installed", current_file=None, clear_error=True)
        return eb.UpdateResult(status="updated", from_set_version=1, to_set_version=2)


def test_the_guard_has_teeth(network):
    """The refusal is real: a lookup, a connect and the installer seams are all
    recorded (a guard that records nothing would make every test below vacuous)."""
    # `.invalid` names (tests/test_test_hosts_cannot_leave_pin.py): the guard records the call
    # whatever the host, and the assert below fails if any seam went unrecorded.
    with pytest.raises(OSError):
        socket.getaddrinfo("pypi.invalid", 443)
    with pytest.raises(OSError):
        socket.socket().connect(("download.pytorch.invalid", 443))
    with pytest.raises(OSError):
        eb._http_download("https://huggingface.invalid/x", Path("x"))
    with pytest.raises(OSError):
        eb._run_pip_install()
    assert [c[0] for c in network] == [
        "getaddrinfo", "connect", "_http_download", "_run_pip_install",
    ]


@pytest.mark.parametrize("case", ["current", "absent"])
async def test_a_current_or_absent_runtime_makes_no_request(
    db, fake_app, network, events, tmp_path, monkeypatch, case,
):
    if case == "current":
        make_verified_prefix(tmp_path, monkeypatch)
    else:
        monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "none"))
        eb.invalidate_runtime_ready_cache()
    update = _Update(network, events)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "current"
    assert network == [] and update.calls == 0


async def test_the_switch_off_makes_no_request(db, fake_app, network, events, tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    update = _Update(network, events)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "disabled"
    assert network == [] and update.calls == 0 and events == []


async def test_a_tick_held_back_by_the_backoff_makes_no_request(
    db, fake_app, network, events, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    ru.record_auto_failure(db, error_class="X", target=ru.target_of(eb.runtime_status()))
    update = _Update(network, events)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "backoff"
    assert network == [] and update.calls == 0


@pytest.mark.parametrize("security", [False, True])
async def test_staleness_is_decided_from_the_shipped_manifest_before_any_request(
    db, fake_app, network, events, tmp_path, monkeypatch, security,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(security,))
    shipped = eb.resolve_manifest_path()
    events.clear()  # the fixture's own reads are not the trigger's
    update = _Update(network, events)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert update.calls == 1
    entered = events.index("update_runtime")
    before = events[:entered]
    # Staleness was decided by reading the manifest the image ships, and only that
    # one, before the update funnel was entered ...
    assert before and all(kind == "manifest" for kind, _p in before), before
    assert {p for _kind, p in before} == {shipped}
    # ... no request had left the process by then ...
    assert update.network_at_entry == []
    # ... and the funnel was handed that same shipped manifest: the exact files and
    # hashes it names are all it may download.
    assert update.manifest_path == shipped
    assert network == []


async def test_an_elapsed_backoff_retries_without_any_lookup(
    db, fake_app, network, events, tmp_path, monkeypatch,
):
    """The retry gate is local state (a settings row and the clock): a failure
    whose backoff has elapsed retries without asking any index anything."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    state = ru.record_auto_failure(db, error_class="X", target=ru.target_of(eb.runtime_status()))
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    set_setting(db, ru.AUTO_STATE_KEY, {**state, "last_failure_at": old})
    update = _Update(network, events)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert update.network_at_entry == [] and network == []
