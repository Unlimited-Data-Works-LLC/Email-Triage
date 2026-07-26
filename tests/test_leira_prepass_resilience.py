"""Unit tests for the leira_prepass resilience shim (18b48ec9).

Covers:
- Cooldown enforcement: an active cooldown sidecar makes call_leira short-circuit
  with LeiraUnavailable BEFORE any HTTP attempt.
- Stale cooldown auto-clears (past-timestamp file is ignored).
- ollama_alive() pre-flight fail sets a cooldown + raises LeiraUnavailable.
- _set_cooldown writes a future-timestamp file readable by _in_cooldown.

Kept out of scope: exponential-backoff retry timing (would need to inject a mock
HTTP layer + a timer; leira_prepass's HTTP call is direct urllib for simplicity).
The e2e canary in verify_leira_prepass_vs_run19 covers the happy path.
"""
from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def leira_prepass(tmp_path, monkeypatch):
    """Fresh import of leira_prepass with a scoped TEMP so the cooldown +
    rotation sidecars live under tmp_path and don't collide with the real ones."""
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", str(SCRIPTS_DIR))
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    if "leira_prepass" in sys.modules:
        del sys.modules["leira_prepass"]
    mod = importlib.import_module("leira_prepass")
    # Punch  (2026-07-17): explicit rotation sidecar cleanup so
    # cross-test state doesn't leak via the shared file.
    if mod._ROTATION_SIDECAR.exists():
        mod._ROTATION_SIDECAR.unlink()
    return mod


def test_cooldown_future_blocks_call(leira_prepass, tmp_path):
    """A cooldown-until timestamp in the future => LeiraUnavailable, no HTTP."""
    leira_prepass._COOLDOWN_PATH.write_text(str(time.time() + 60))
    with pytest.raises(leira_prepass.LeiraUnavailable) as exc:
        leira_prepass.call_leira("hi")
    assert "cooldown" in str(exc.value).lower()
    # Include the exact clear command so an operator can act on the error line.
    assert str(leira_prepass._COOLDOWN_PATH) in str(exc.value)


def test_cooldown_past_ignored(leira_prepass, tmp_path):
    """A stale (past) cooldown timestamp is treated as no-cooldown."""
    leira_prepass._COOLDOWN_PATH.write_text(str(time.time() - 60))
    in_cd, remaining = leira_prepass._in_cooldown()
    assert not in_cd
    assert remaining == 0.0


def test_cooldown_malformed_file_ignored(leira_prepass):
    """A garbage cooldown file is treated as no-cooldown (fail-open)."""
    leira_prepass._COOLDOWN_PATH.write_text("not-a-number")
    in_cd, _ = leira_prepass._in_cooldown()
    assert not in_cd


def test_set_cooldown_creates_readable_file(leira_prepass):
    """_set_cooldown writes a future timestamp _in_cooldown can read back."""
    leira_prepass._set_cooldown("test-reason", duration_s=120)
    in_cd, remaining = leira_prepass._in_cooldown()
    assert in_cd
    assert 118 <= remaining <= 122  # allow ~2s slack for wall-clock jitter


def test_dead_leira_url_bails_via_pre_flight(leira_prepass, tmp_path, monkeypatch):
    """Pointing the active host at a bad URL causes ollama_alive() to fail =>
    cooldown set + LeiraUnavailable raised WITHOUT going through the retry
    loop's HTTP (which would otherwise hang for MAX_RETRIES * timeout_s).

    Drive-B (2026-07-17) note: call_leira now sources the request URL from
    ``_ACTIVE_HOST['url']`` (was module ``LEIRA_URL``). Both are set from
    ``_resolve_active_host()`` at import so they are equal by construction;
    the test now patches ``_ACTIVE_HOST`` directly to match the runtime
    routing path.
    """
    bad = "http://not-a-real-host.invalid:11434/api/chat"
    dead_host = {**leira_prepass._ACTIVE_HOST, "url": bad}
    monkeypatch.setattr(leira_prepass, "_ACTIVE_HOST", dead_host)
    monkeypatch.setattr(leira_prepass, "LEIRA_URL", bad)  # keep in sync for callers reading it
    with pytest.raises(leira_prepass.LeiraUnavailable) as exc:
        leira_prepass.call_leira("hi")
    assert "unreachable" in str(exc.value).lower() or "in cooldown" in str(exc.value).lower()
    # Drive-D (2026-07-17): pre-flight failure now arms the PER-HOST cooldown
    # (not the global). The active host is the one benched.
    assert leira_prepass._cooldown_path_for(leira_prepass._ACTIVE_HOST["name"]).exists()


def test_leira_unavailable_is_ollamacallerror_subclass(leira_prepass):
    """Existing consumers that except OllamaCallError keep fail-opening cleanly
    (verify_prepass returns UNCERTAIN; log_triage returns _prepass_error dict).
    LeiraUnavailable must not break that contract."""
    assert issubclass(leira_prepass.LeiraUnavailable, leira_prepass.OllamaCallError)


# ---------------------------------------------------------------------------
# Multi-host tests (design_leira_multihost_full, 2026-07-17). Mirror the Pester
# scaffold T8-T13 in tests/leira_ps_consumers_scaffold.Tests.ps1.
# ---------------------------------------------------------------------------

def _reimport_with_env(tmp_path, monkeypatch, **env):
    """Re-import leira_prepass with a scoped env so module-scope resolution
    (`_ACTIVE_HOST`, `LEIRA_URL`) re-runs against the requested env."""
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", str(SCRIPTS_DIR))
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    for name in ("OLLAMA_HOST", "OLLAMA_URL", "LEIRA_URL", "LEIRA_OLLAMA_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if "leira_prepass" in sys.modules:
        del sys.modules["leira_prepass"]
    return importlib.import_module("leira_prepass")


def test_multihost_default_host_resolves_to_leira(tmp_path, monkeypatch):
    """No env set → resolves to config default_host ('llm-host')."""
    mod = _reimport_with_env(tmp_path, monkeypatch)
    assert mod.active_host_name() == "llm-host"


def test_multihost_explicit_ollama_host_leira(tmp_path, monkeypatch):
    """OLLAMA_HOST=llm-host → explicit routing to hosts.llm-host (no error)."""
    mod = _reimport_with_env(tmp_path, monkeypatch, OLLAMA_HOST="llm-host")
    assert mod.active_host_name() == "llm-host"


def test_multihost_unknown_ollama_host_raises_config_error(tmp_path, monkeypatch):
    """Multi-host trap: OLLAMA_HOST=the ML host (or any name absent from hosts map)
    MUST raise LeiraConfigError, NOT silently return the default host. This is
    the entire point of the multi-host tightening."""
    for name in ("OLLAMA_HOST", "OLLAMA_URL", "LEIRA_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "the ML host")
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", str(SCRIPTS_DIR))
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    if "leira_prepass" in sys.modules:
        del sys.modules["leira_prepass"]
    with pytest.raises(Exception) as exc_info:
        importlib.import_module("leira_prepass")
    exc_type_name = exc_info.value.__class__.__name__
    assert exc_type_name == "LeiraConfigError", (
        f"expected LeiraConfigError on OLLAMA_HOST=the ML host; got {exc_type_name}"
    )
    msg = str(exc_info.value)
    assert "the ML host" in msg
    assert "known:" in msg and "llm-host" in msg


def test_multihost_leira_config_error_not_subclass_of_ollama_call_error(tmp_path, monkeypatch):
    """LeiraConfigError is startup-time misconfig; it MUST NOT subclass
    OllamaCallError (call-time) so consumers catching OllamaCallError don't
    accidentally swallow a misconfig they cannot recover from at runtime."""
    mod = _reimport_with_env(tmp_path, monkeypatch)
    assert issubclass(mod.LeiraConfigError, RuntimeError)
    assert not issubclass(mod.LeiraConfigError, mod.OllamaCallError)


def test_multihost_active_host_name_matches_resolved(tmp_path, monkeypatch):
    """active_host_name() returns the resolved host name (accessor contract).
    Consumers record it in audit output for reproducibility."""
    mod = _reimport_with_env(tmp_path, monkeypatch, OLLAMA_HOST="llm-host")
    assert mod.active_host_name() == "llm-host"
    assert mod._ACTIVE_HOST["name"] == "llm-host"


def test_multihost_leira_url_env_bypasses_hosts_map(tmp_path, monkeypatch):
    """LEIRA_URL env → raw chat URL (drawer §Knob-precedence rule 1). Bypasses
    the `hosts` map entirely. Name recorded as `<env-url>` sentinel — PS parity
    with `Get-LeiraActiveHost` when `$rawUrlEnv` wins. Pester T11."""
    mod = _reimport_with_env(
        tmp_path, monkeypatch, LEIRA_URL="http://ad-hoc:11434/api/chat"
    )
    assert mod.active_host_name() == "<env-url>"
    assert mod.LEIRA_URL == "http://ad-hoc:11434/api/chat"


def test_multihost_ollama_url_env_bypasses_hosts_map(tmp_path, monkeypatch):
    """OLLAMA_URL env → raw chat URL (drawer §Knob-precedence rule 2, alias of
    rule 1). Pester T12."""
    mod = _reimport_with_env(
        tmp_path, monkeypatch, OLLAMA_URL="http://ad-hoc-2:11434/api/chat"
    )
    assert mod.active_host_name() == "<env-url>"
    assert mod.LEIRA_URL == "http://ad-hoc-2:11434/api/chat"


def test_multihost_raw_url_wins_over_ollama_host_typo(tmp_path, monkeypatch):
    """DA Drive MF (2026-07-17): OLLAMA_HOST=<unknown> + LEIRA_URL=<url> MUST
    resolve to the raw URL, NOT raise LeiraConfigError. The drawer's rule 1
    (raw URL) beats rule 3 (typo trap). Pre-fix Python raised at import;
    post-fix mirrors the PS twin."""
    mod = _reimport_with_env(
        tmp_path,
        monkeypatch,
        OLLAMA_HOST="the ML host",
        LEIRA_URL="http://ad-hoc-3:11434/api/chat",
    )
    assert mod.active_host_name() == "<env-url>"
    assert mod.LEIRA_URL == "http://ad-hoc-3:11434/api/chat"


# ---------------------------------------------------------------------------
# Drive-B — per-call host override (call_leira host=<name>). 2026-07-17.
# Twin of Invoke-LeiraCall -HostName in scripts/leira_prepass.psm1.
# ---------------------------------------------------------------------------


def test_call_leira_unknown_host_raises_config_error(leira_prepass):
    """call_leira(host='the ML host') with no such host in the map raises
    LeiraConfigError BEFORE any HTTP attempt — typo trap symmetric with the
    env-driven OLLAMA_HOST rule 3."""
    with pytest.raises(leira_prepass.LeiraConfigError) as exc:
        leira_prepass.call_leira("hi", host="the ML host")
    msg = str(exc.value)
    assert "the ML host" in msg
    assert "known:" in msg and "llm-host" in msg


def test_resolve_host_by_name_known_returns_leira_entry(leira_prepass):
    """_resolve_host_by_name('llm-host') returns the hosts.llm-host entry
    (pure lookup — no env precedence, no cache)."""
    host = leira_prepass._resolve_host_by_name("llm-host")
    assert host["name"] == "llm-host"
    assert host["url"].endswith("/api/chat")
    # Model comes from hosts.llm-host.model, not env.
    assert host["model"]


def test_resolve_host_by_name_unknown_raises(leira_prepass):
    """_resolve_host_by_name('the ML host') raises LeiraConfigError with the
    diagnostic message (names offending host + known list)."""
    with pytest.raises(leira_prepass.LeiraConfigError) as exc:
        leira_prepass._resolve_host_by_name("the ML host")
    assert "the ML host" in str(exc.value)
    assert "known:" in str(exc.value)


# ---------------------------------------------------------------------------
# Drive-G — per-consumer host affinity (2026-07-17). Twin of PS
# _ResolveConsumerHost + Invoke-LeiraCall -Consumer.
# ---------------------------------------------------------------------------


def test_consumer_no_section_returns_none(leira_prepass):
    """Unknown consumer name -> None (LEGAL; consumers may opt in)."""
    assert leira_prepass._resolve_consumer_host("nonexistent_consumer") is None


def test_consumer_section_without_host_returns_none(leira_prepass):
    """Consumer section exists but has no `host` field -> None."""
    # census_prepass is a real section with no host field.
    assert leira_prepass._resolve_consumer_host("census_prepass") is None


def test_consumer_with_host_returns_that_host(leira_prepass, monkeypatch):
    """`_CFG[consumer].host` = 'llm-host' -> returns 'llm-host'."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {
            **leira_prepass._CFG,
            "my_consumer": {"host": "llm-host", "context_usage_ratio": 0.4},
        },
    )
    assert leira_prepass._resolve_consumer_host("my_consumer") == "llm-host"


def test_consumer_affinity_routes_call_leira(leira_prepass, monkeypatch):
    """call_leira(consumer='verify_prepass') routes to verify_prepass.host."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {
            **leira_prepass._CFG,
            "verify_prepass": {"host": "llm-host", "per_file_context_ratio": 0.10},
        },
    )

    seen_hosts: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        seen_hosts.append(host)
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    leira_prepass.call_leira("hi", consumer="verify_prepass")
    assert seen_hosts == ["llm-host"]


def test_consumer_explicit_host_wins_over_consumer(leira_prepass, monkeypatch):
    """host='pinned' beats consumer='X' — explicit user intent wins."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {
            **leira_prepass._CFG,
            "verify_prepass": {"host": "consumer_pinned"},
        },
    )

    seen_hosts: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        seen_hosts.append(host)
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    leira_prepass.call_leira("hi", host="explicit", consumer="verify_prepass")
    assert seen_hosts == ["explicit"]


def test_consumer_wins_over_strategy(leira_prepass, monkeypatch):
    """consumer affinity resolves BEFORE strategy rotation."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {
            **leira_prepass._CFG,
            "hosts": _hosts_with_weights(a=1, b=1),
            "verify_prepass": {"host": "consumer_pinned"},
        },
    )
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)

    seen_hosts: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        seen_hosts.append(host)
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    leira_prepass.call_leira(
        "hi", consumer="verify_prepass", strategy="round_robin"
    )
    assert seen_hosts == ["consumer_pinned"], (
        f"consumer must win over strategy; got {seen_hosts}"
    )


# ---------------------------------------------------------------------------
# Drive-F — round-robin / weighted rotation (2026-07-17). Twin of PS
# _NextHostByStrategy / _BuildRotationPool. Rotation counter is process-scope.
# ---------------------------------------------------------------------------


def _hosts_with_weights(**weight_by_name) -> dict:
    """Build a hosts.<name> map suitable for _CFG monkey-patching."""
    return {
        name: {
            "url": f"http://{name}:11434/api/chat",
            "model": "qwen3.6:35b",
            "weight": w,
        }
        for name, w in weight_by_name.items()
    }


def test_strategy_primary_returns_empty_rotation_pool(leira_prepass):
    """Default strategy ('primary') = no rotation pool = no host picked."""
    pool = leira_prepass._build_rotation_pool("primary")
    assert pool == []
    assert leira_prepass._next_host_by_strategy("primary") is None


def test_strategy_round_robin_pool_is_sorted_host_names(leira_prepass, monkeypatch):
    """round_robin pool = each configured host once, sorted."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(a=1, b=1, c=1)},
    )
    assert leira_prepass._build_rotation_pool("round_robin") == ["a", "b", "c"]


def test_strategy_weighted_pool_repeats_by_weight(leira_prepass, monkeypatch):
    """weighted pool = each host repeated `weight` times."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(alpha=3, beta=1)},
    )
    pool = leira_prepass._build_rotation_pool("weighted")
    assert pool.count("alpha") == 3
    assert pool.count("beta") == 1
    assert len(pool) == 4


def test_strategy_round_robin_advances_counter(leira_prepass, monkeypatch):
    """Successive calls return successive pool entries."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(a=1, b=1, c=1)},
    )
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)
    for h in ("a", "b", "c"):
        p = leira_prepass._cooldown_path_for(h)
        if p.exists():
            p.unlink()
    if leira_prepass._COOLDOWN_PATH.exists():
        leira_prepass._COOLDOWN_PATH.unlink()
    seq = [leira_prepass._next_host_by_strategy("round_robin") for _ in range(6)]
    assert seq == ["a", "b", "c", "a", "b", "c"], f"got {seq}"


def test_strategy_skips_cooldown_host(leira_prepass, monkeypatch):
    """A cooldown'd host is skipped in the rotation."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(a=1, b=1, c=1)},
    )
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)
    for h in ("a", "b", "c"):
        p = leira_prepass._cooldown_path_for(h)
        if p.exists():
            p.unlink()
    if leira_prepass._COOLDOWN_PATH.exists():
        leira_prepass._COOLDOWN_PATH.unlink()
    leira_prepass._set_cooldown_for("b", "test", duration_s=120)
    picks = [leira_prepass._next_host_by_strategy("round_robin") for _ in range(4)]
    assert "b" not in picks, f"b should be skipped; picks={picks}"


def test_strategy_call_leira_picks_before_dispatch(leira_prepass, monkeypatch):
    """call_leira sets host= to the strategy-picked host before dispatch;
    _call_leira_once sees the resolved host name."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(x=1, y=1)},
    )
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)

    seen_hosts: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        seen_hosts.append(host)
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    for h in ("x", "y"):
        p = leira_prepass._cooldown_path_for(h)
        if p.exists():
            p.unlink()
    leira_prepass.call_leira("hi", strategy="round_robin")
    leira_prepass.call_leira("hi", strategy="round_robin")
    assert seen_hosts == ["x", "y"]


def test_config_schema_valid_config_loads(leira_prepass):
    """Punch  (2026-07-17): the shipped `scripts/leira_config.json` MUST
    satisfy `scripts/leira_config.schema.json` — a broken shipped config
    would fail this pin at import."""
    # The very fact leira_prepass imported means the check passed at import.
    # Sanity: re-run explicit validation to catch any post-fixture drift.
    leira_prepass._validate_config_schema(leira_prepass._CFG)


def test_config_schema_unknown_strategy_raises(leira_prepass):
    """A `strategy` value outside the enum raises LeiraConfigError with the
    JSON path to the offending field."""
    with pytest.raises(leira_prepass.LeiraConfigError) as exc:
        leira_prepass._validate_config_schema(
            {"strategy": "roundrobin"},  # typo — missing underscore
        )
    msg = str(exc.value)
    assert "strategy" in msg


def test_config_schema_wrong_weight_type_raises(leira_prepass):
    """`hosts.<name>.weight` must be an integer; a string coerces silently
    downstream (returned as-is by JSON load). Pin catches at load."""
    with pytest.raises(leira_prepass.LeiraConfigError) as exc:
        leira_prepass._validate_config_schema(
            {"hosts": {"llm-host": {"weight": "3"}}},  # string, not int
        )
    assert "weight" in str(exc.value)


def test_config_schema_missing_file_fail_open(leira_prepass, monkeypatch):
    """A missing schema file falls through to load-succeeds — validation
    infra gap must never break config loading."""
    monkeypatch.setattr(
        leira_prepass,
        "_CONFIG_SCHEMA_PATH",
        leira_prepass._CONFIG_SCHEMA_PATH.parent / "missing_schema.json",
    )
    # Should not raise.
    leira_prepass._validate_config_schema({"strategy": "roundrobin"})


def test_rotation_counter_syncs_via_shared_sidecar(leira_prepass, monkeypatch):
    """Punch  (2026-07-17): the rotation counter is persisted to a
    shared sidecar so mixed Py+PS callers see a synchronized cursor.
    A pre-existing sidecar value overrides the module-scope int."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(a=1, b=1, c=1)},
    )
    # Clear both the sidecar + cooldowns for a/b/c so the test is isolated.
    for h in ("a", "b", "c"):
        p = leira_prepass._cooldown_path_for(h)
        if p.exists():
            p.unlink()
    if leira_prepass._ROTATION_SIDECAR.exists():
        leira_prepass._ROTATION_SIDECAR.unlink()
    # Simulate a PS twin having advanced the counter to 4 already.
    leira_prepass._ROTATION_SIDECAR.write_text("4")
    # Python should PICK UP from index 4 -> 4 % 3 = 1 -> 'b'.
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)
    picked = leira_prepass._next_host_by_strategy("round_robin")
    assert picked == "b", f"expected sidecar to sync counter to 4 (%3 = 1 -> 'b'); got {picked}"
    # Sidecar should now hold 5 (post-advance).
    persisted = int(leira_prepass._ROTATION_SIDECAR.read_text().strip())
    assert persisted == 5, f"sidecar should hold 5 after one pick; got {persisted}"


def test_rotation_sidecar_fail_open_on_malformed(leira_prepass, monkeypatch):
    """A garbage sidecar value must fail-open (fall back to module counter),
    not crash the wrapper."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(a=1, b=1)},
    )
    for h in ("a", "b"):
        p = leira_prepass._cooldown_path_for(h)
        if p.exists():
            p.unlink()
    leira_prepass._ROTATION_SIDECAR.write_text("not-a-number")
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)
    picked = leira_prepass._next_host_by_strategy("round_robin")
    # Should fall back to module counter (0) -> 'a'.
    assert picked == "a"


def test_strategy_explicit_host_wins_over_strategy(leira_prepass, monkeypatch):
    """host='pinned' MUST override strategy — user intent wins over rotation."""
    monkeypatch.setattr(
        leira_prepass, "_CFG",
        {**leira_prepass._CFG, "hosts": _hosts_with_weights(pinned=1, other=1)},
    )
    monkeypatch.setattr(leira_prepass, "_ROTATION_COUNTER", 0)

    seen_hosts: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        seen_hosts.append(host)
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    leira_prepass.call_leira("hi", host="pinned", strategy="round_robin")
    assert seen_hosts == ["pinned"]


# ---------------------------------------------------------------------------
# Drive-E — cross-host failover (2026-07-17). call_leira orchestrator
# delegates to _call_leira_once; catches LeiraUnavailable + tries the next
# host in the chain. LeiraConfigError (typo trap) bubbles immediately.
# ---------------------------------------------------------------------------


def test_failover_none_configured_single_call(leira_prepass, monkeypatch):
    """No failover_hosts + no config knob = pre-Drive-E behavior: exactly
    one call to _call_leira_once, no orchestration overhead."""
    calls: list[str | None] = []

    def _fake_once(prompt, schema=None, **kwargs):
        calls.append(kwargs.get("host"))
        return {"ok": True}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    monkeypatch.setattr(leira_prepass, "_CFG", {**leira_prepass._CFG, "failover_hosts": []})
    result = leira_prepass.call_leira("hi", schema={"required": []})
    assert result == {"ok": True}
    assert len(calls) == 1


def test_failover_primary_fails_second_succeeds(leira_prepass, monkeypatch):
    """Primary raises LeiraUnavailable → orchestrator falls to next in chain;
    result grows _leira_meta.failover_chain naming the traversal."""
    calls: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        calls.append(host)
        if host in (None, "llm-host"):
            raise leira_prepass.LeiraUnavailable(f"host={host} benched")
        return {"content": "ok"}

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    result = leira_prepass.call_leira(
        "hi",
        schema={"required": []},
        failover_hosts=["beshaba"],
    )
    assert result["content"] == "ok"
    assert result["_leira_meta"]["failover_chain"] == ["llm-host", "beshaba"]
    assert calls == ["llm-host", "beshaba"]


def test_failover_leira_config_error_bubbles_immediately(leira_prepass, monkeypatch):
    """A LeiraConfigError (typo trap) MUST NOT trigger failover — the
    misconfig applies to the config, not the host. Bubble on first raise."""
    calls: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        calls.append(host)
        raise leira_prepass.LeiraConfigError(f"unknown host {host}")

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    with pytest.raises(leira_prepass.LeiraConfigError):
        leira_prepass.call_leira("hi", failover_hosts=["one", "two"])
    assert len(calls) == 1, f"config-error must NOT chain — got calls={calls!r}"


def test_failover_all_hosts_exhausted_raises_unavailable(leira_prepass, monkeypatch):
    """Every host in the chain raises → orchestrator raises LeiraUnavailable
    with the traversal + last error surfaced."""
    calls: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        calls.append(host)
        raise leira_prepass.LeiraUnavailable(f"host={host} dead")

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    with pytest.raises(leira_prepass.LeiraUnavailable) as exc:
        leira_prepass.call_leira("hi", failover_hosts=["a", "b"])
    msg = str(exc.value)
    assert "exhausted" in msg
    assert calls == ["llm-host", "a", "b"]


def test_failover_chain_dedups_primary_from_failover_list(leira_prepass, monkeypatch):
    """If failover_hosts contains the primary, it's deduped — the chain is
    [primary, *others_not_including_primary]."""
    calls: list[str | None] = []

    def _fake_once(prompt, schema=None, *, host=None, **kwargs):
        calls.append(host)
        raise leira_prepass.LeiraUnavailable(f"host={host}")

    monkeypatch.setattr(leira_prepass, "_call_leira_once", _fake_once)
    with pytest.raises(leira_prepass.LeiraUnavailable):
        leira_prepass.call_leira("hi", failover_hosts=["llm-host", "b"])
    assert calls == ["llm-host", "b"], f"primary should be deduped from failover list; got {calls}"


# ---------------------------------------------------------------------------
# Drive-D — per-host cooldown (2026-07-17). Twin of PS _CooldownRemainingFor /
# _SetCooldownFor / _CooldownPathFor. Legacy global sidecar retained for
# backward-compat "all benched" reads.
# ---------------------------------------------------------------------------


def test_per_host_cooldown_scopes_to_named_host(leira_prepass):
    """Arming a per-host cooldown for `the ML host` MUST NOT bench `llm-host` —
    the entire point of Drive-D. Pre-Drive-D, both hosts shared one
    sidecar; benching one benched all."""
    # Clear both paths first (test isolation).
    for p in (
        leira_prepass._cooldown_path_for("the ML host"),
        leira_prepass._cooldown_path_for("llm-host"),
        leira_prepass._COOLDOWN_PATH,
    ):
        if p.exists():
            p.unlink()
    leira_prepass._set_cooldown_for("the ML host", "test-scope", duration_s=120)
    savras_in, savras_rem = leira_prepass._in_cooldown_for("the ML host")
    leira_in, _ = leira_prepass._in_cooldown_for("llm-host")
    assert savras_in and 100 <= savras_rem <= 130
    assert not leira_in, "llm-host must remain callable while the ML host is benched"


def test_global_cooldown_blocks_all_hosts_backward_compat(leira_prepass):
    """Writing directly to the LEGACY global sidecar benches EVERY host —
    the "all benched" backward-compat contract. A pre-Drive-D consumer
    that writes `_COOLDOWN_PATH` keeps working."""
    for p in (
        leira_prepass._cooldown_path_for("the ML host"),
        leira_prepass._cooldown_path_for("llm-host"),
    ):
        if p.exists():
            p.unlink()
    leira_prepass._COOLDOWN_PATH.write_text(str(time.time() + 60))
    for host in ("llm-host", "the ML host", "any-name"):
        in_cd, _ = leira_prepass._in_cooldown_for(host)
        assert in_cd, f"global cooldown must block host={host} (backward-compat)"


def test_per_host_cooldown_path_is_distinct_per_host(leira_prepass):
    """The sidecar filename embeds the (sanitized) host name so no two hosts
    share a path. Otherwise per-host semantics collapse."""
    p1 = leira_prepass._cooldown_path_for("llm-host")
    p2 = leira_prepass._cooldown_path_for("the ML host")
    assert p1 != p2
    assert "llm-host" in p1.name
    assert "the ML host" in p2.name


def test_per_host_cooldown_path_sanitizes_unsafe_chars(leira_prepass):
    """Path traversal and OS-illegal chars in host names must not escape the
    filename. `<env-url>` (raw-URL bypass sentinel) becomes `_env-url_`;
    dots + slashes become underscores."""
    p_env = leira_prepass._cooldown_path_for("<env-url>")
    assert "<" not in p_env.name and ">" not in p_env.name
    p_bad = leira_prepass._cooldown_path_for("../evil/host")
    assert ".." not in p_bad.name
    assert "/" not in p_bad.name and "\\" not in p_bad.name


def test_call_leira_per_host_cooldown_uses_resolved_host(leira_prepass, monkeypatch):
    """call_leira(host='llm-host') arms the PER-HOST cooldown on failure — NOT
    the global. Sibling hosts remain unblocked after this call."""
    # Bail via mocked ollama_alive so retry-loop-arm site fires.
    def _fake_alive(timeout_s=4, *, base_url=None):
        return False

    monkeypatch.setattr(leira_prepass, "ollama_alive", _fake_alive)
    # Clear before.
    for p in (
        leira_prepass._cooldown_path_for("llm-host"),
        leira_prepass._COOLDOWN_PATH,
    ):
        if p.exists():
            p.unlink()
    with pytest.raises(leira_prepass.LeiraUnavailable):
        leira_prepass.call_leira("hi", host="llm-host")
    # Per-host sidecar SHOULD exist for llm-host.
    assert leira_prepass._cooldown_path_for("llm-host").exists()
    # Global sidecar SHOULD NOT (pre-Drive-D would have written this).
    assert not leira_prepass._COOLDOWN_PATH.exists(), (
        "Drive-D: retry-exhaust must arm per-host, not global"
    )


# ---------------------------------------------------------------------------
# Drive-C — health-check alternates (leira_healthcheck). 2026-07-17.
# Twin of Get-LeiraHealthcheck in scripts/leira_prepass.psm1.
# Informational only — no cooldown side-effect, no auto-routing.
# ---------------------------------------------------------------------------


def test_leira_healthcheck_returns_list_of_dicts_with_expected_shape(leira_prepass):
    """leira_healthcheck() returns a list of dicts; every dict carries the
    documented keys (name/url/reachable/latency_ms/model_count/error).
    Structural pin — Prime Directive #1, count-agnostic across whatever the
    config's `hosts` map holds today or in future."""
    results = leira_prepass.leira_healthcheck(timeout_s=1)
    assert isinstance(results, list)
    required_keys = {"name", "url", "reachable", "latency_ms", "model_count", "error"}
    for r in results:
        assert isinstance(r, dict), f"result not a dict: {r!r}"
        missing = required_keys - r.keys()
        assert not missing, f"result missing keys {missing}: {r!r}"
        assert isinstance(r["reachable"], bool)
        assert isinstance(r["latency_ms"], int)


def test_leira_healthcheck_covers_every_configured_host(leira_prepass):
    """Count-agnostic pin: leira_healthcheck() emits exactly one result per
    configured `hosts.<name>` entry (no host silently skipped). Fails if a
    new host is added to the config but leira_healthcheck loses coverage."""
    hosts_map = leira_prepass._CFG.get("hosts") or {}
    results = leira_prepass.leira_healthcheck(timeout_s=1)
    seen_names = {r["name"] for r in results}
    assert seen_names == set(hosts_map.keys()), (
        f"healthcheck skipped or extra host: results={seen_names}, "
        f"config={set(hosts_map.keys())}"
    )


def test_leira_healthcheck_is_sorted_by_name(leira_prepass):
    """Deterministic ordering — sorted by host name. Consumers relying on
    row order (dashboard render, diff, cross-language cross-check) get
    stability."""
    results = leira_prepass.leira_healthcheck(timeout_s=1)
    names = [r["name"] for r in results]
    assert names == sorted(names), f"healthcheck order not sorted: {names}"


def test_leira_healthcheck_no_cooldown_side_effect(leira_prepass, tmp_path, monkeypatch):
    """Explicitly pin the drawer §Non-goals contract: healthcheck is
    INFORMATIONAL — a failed probe does NOT arm the persistent cooldown
    sidecar. Otherwise a dashboard render could disable subsequent calls."""
    # Ensure no cooldown at start.
    if leira_prepass._COOLDOWN_PATH.exists():
        leira_prepass._COOLDOWN_PATH.unlink()
    _ = leira_prepass.leira_healthcheck(timeout_s=1)
    # After a healthcheck that (likely) failed against a bad URL, cooldown
    # sidecar MUST NOT exist — that would piggyback on the call path's
    # cooldown state and confuse downstream call_leira().
    assert not leira_prepass._COOLDOWN_PATH.exists(), (
        "leira_healthcheck() must not arm the persistent cooldown sidecar"
    )


def test_call_leira_host_arg_routes_pre_flight_to_that_host(leira_prepass, monkeypatch):
    """The per-call -host route must pre-flight the RESOLVED host's URL, not
    the module cached one. Assert ollama_alive() is invoked with the resolved
    host's api_base — a routing bug would blow past this."""
    seen_base_urls: list[str | None] = []

    def _fake_alive(timeout_s: int = 4, *, base_url: str | None = None) -> bool:
        seen_base_urls.append(base_url)
        # Return False so the call bails via LeiraUnavailable — we're pinning
        # the routing (base_url arg), not the retry loop.
        return False

    monkeypatch.setattr(leira_prepass, "ollama_alive", _fake_alive)
    with pytest.raises(leira_prepass.LeiraUnavailable):
        leira_prepass.call_leira("hi", host="llm-host")

    assert seen_base_urls, "ollama_alive was not called — pre-flight is missing"
    assert seen_base_urls[0] is not None, (
        "call_leira(host=...) MUST pass base_url to ollama_alive; got None"
    )
    assert "/api/" not in seen_base_urls[0].rsplit("/", 1)[-1], (
        f"base_url should be the /api-root, got {seen_base_urls[0]!r}"
    )
    # DA Batch-1 NTH#4 fold: pin equality with the RESOLVED host's base URL,
    # not just non-None + shape. Otherwise a bug that mis-routed to any stub
    # URL matching the shape could slide past.
    expected_base = leira_prepass._resolve_host_by_name("llm-host")["url"].rsplit("/api/", 1)[0]
    assert seen_base_urls[0] == expected_base, (
        f"pre-flight base_url != hosts.llm-host's base URL — expected "
        f"{expected_base!r}, got {seen_base_urls[0]!r}"
    )
