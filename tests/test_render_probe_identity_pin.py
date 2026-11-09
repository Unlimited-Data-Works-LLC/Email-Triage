"""Pin (punches 692, 693): what a ``render_probe`` call site must tell the SSOT.

692: the bound log line names the account by its typed ``account_id`` (an ``int``, never the
account name or address), so a bound that fires for one mailbox is attributable. The SSOT cannot
know the id (a provider carries none), so EVERY ``render_probe(...)`` call in src passes
``account_id=``.

693: a probe the USER started and is waiting on (the discover scan) gets the provider's own 10 s
budget (``USER_SCAN_PROBE_TIMEOUT_S``), not the 3 s page-render bound that is right for a page
render. "User-started" is a semantic class no AST can derive, so that half is a targeted pin on
the one handler, plus the behaviour below.
"""

from __future__ import annotations

import ast
import asyncio

import pytest

from _pin_harness import (
    assert_pin_has_teeth, iter_src_files, parse_module, parse_source, relpath,
)

SSOT_HOME = "providers/render_probe.py"
SCAN_FILE = "web/routers/ui/triage_classify.py"
SCAN_FN = "discover_run"


def _render_probe_calls(tree: ast.AST) -> list[ast.Call]:
    return [c for c in ast.walk(tree) if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name) and c.func.id == "render_probe"]


def calls_without_account_id(tree: ast.AST) -> list[int]:
    """Lines of ``render_probe(...)`` calls that pass no ``account_id=`` keyword."""
    return [c.lineno for c in _render_probe_calls(tree)
            if not any(k.arg == "account_id" for k in c.keywords)]


def test_every_render_probe_call_passes_the_account_id():
    offenders, sites = [], 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        sites += len(_render_probe_calls(tree))
        offenders += [f"{relpath(path)}:{line}" for line in calls_without_account_id(tree)]
    assert sites, "no render_probe call found: the detector is blind, not the tree clean"
    assert not offenders, (
        "A render_probe call passes no `account_id=`: its bound log line cannot say which "
        "account stalled (punch 692):\n  " + "\n  ".join(offenders))


def test_account_id_pin_has_teeth():
    assert_pin_has_teeth(
        calls_without_account_id,
        bad_source="async def h(p):\n    return await render_probe(p)\n",
        good_source="async def h(p, i):\n    return await render_probe(p, account_id=i)\n",
    )


def _scan_probe_calls() -> list[ast.Call]:
    path = next(p for p in iter_src_files("web/routers/ui") if relpath(p) == SCAN_FILE)
    tree = parse_module(path)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == SCAN_FN)
    return _render_probe_calls(fn)


def test_the_user_started_scan_uses_the_provider_budget():
    calls = _scan_probe_calls()
    assert calls, f"{SCAN_FN} no longer probes through render_probe"
    for call in calls:
        bound = [k.value for k in call.keywords if k.arg == "timeout_s"]
        assert bound and isinstance(bound[0], ast.Name) \
            and bound[0].id == "USER_SCAN_PROBE_TIMEOUT_S", (
            f"{SCAN_FILE}:{call.lineno} {SCAN_FN} probes under the 3 s page-render bound; a "
            "scan the user started gets `timeout_s=USER_SCAN_PROBE_TIMEOUT_S` (punch 693)")


class _Slow:
    _host, _port = "imap.invalid", 993

    async def list_folders(self):
        await asyncio.sleep(0.2)
        return ["INBOX", "Sent"]


def _fast_render_bound(monkeypatch, render_s=0.05, scan_s=2.0):
    import email_triage.providers.render_probe as home
    monkeypatch.setattr(home, "RENDER_PROBE_TIMEOUT_S", render_s)
    monkeypatch.setattr(home, "USER_SCAN_PROBE_TIMEOUT_S", scan_s)
    return home


def test_a_slow_server_trips_the_render_bound_but_not_the_scan_budget(monkeypatch):
    home = _fast_render_bound(monkeypatch)

    async def run():
        with pytest.raises(home.RenderProbeTimeout):
            await home.render_probe(_Slow(), account_id=7)
        return await home.render_probe(_Slow(), account_id=7,
                                       timeout_s=home.USER_SCAN_PROBE_TIMEOUT_S)

    assert asyncio.run(run()) == ["INBOX", "Sent"]


def test_the_scan_budget_is_the_providers_ten_seconds_not_the_render_bound():
    from email_triage.providers.render_probe import (
        RENDER_PROBE_TIMEOUT_S, USER_SCAN_PROBE_TIMEOUT_S,
    )
    assert USER_SCAN_PROBE_TIMEOUT_S == 10.0 and USER_SCAN_PROBE_TIMEOUT_S > RENDER_PROBE_TIMEOUT_S


def _bound_log(monkeypatch, account_id):
    """Drive one bound and return the structured fields of the single INFO line it logs."""
    home = _fast_render_bound(monkeypatch)
    seen: list[dict] = []
    monkeypatch.setattr(
        home._log, "info",
        lambda msg, **kw: seen.append({"msg": msg, **kw}))

    async def run():
        with pytest.raises(home.RenderProbeTimeout):
            await home.render_probe(_Slow(), account_id=account_id)

    asyncio.run(run())
    return seen


def test_the_bound_log_line_carries_the_typed_account_id(monkeypatch):
    (line,) = _bound_log(monkeypatch, 42)
    assert line["msg"] == "render probe bound" and line["account_id"] == 42
    assert line["host"] == "imap.invalid"


@pytest.mark.parametrize("not_an_id", ["alice@example.invalid", "Dr Smith Clinic", True, 4.5, None])
def test_only_a_typed_int_ever_reaches_the_account_id_field(monkeypatch, not_an_id):
    (line,) = _bound_log(monkeypatch, not_an_id)
    assert line["account_id"] is None
    assert "alice" not in repr(line) and "Smith" not in repr(line)
