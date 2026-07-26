#!/usr/bin/env python3
"""leira_prepass.py — shared Ollama-on-llm-host client wrapper for the offload stack.

Pattern: llm-host (qwen3.6:35b on llm-host's Ollama) does the WIDE/cheap/mechanical pass;
the AI assistant keeps judgment + gated commits. This module is the ONE place that talks to the
Ollama API + enforces the schema contract. Consumers (census pre-pass, verify-don't-accept
pre-filter, draft helpers, log triage) import `call_leira(...)`.

Contract:
- Input:  a task_prompt (str) + a JSON schema for the expected output.
- Output: a validated dict conforming to the schema, or raises OllamaCallError.
- Model:  qwen3.6:35b (llm-host's confirmed primary — see mempalace llm-host KG).
- Auth:   none (Ollama default on the LAN). Fail-closed on connect error.

llm-host output is a PROBE, never a verdict on security/HIPAA/root-cause. Consumers must
treat every returned finding as needing the AI assistant / SME review before it lands in a commit.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Layer-2 UTF-8 self-defense (Windows cp1252 stdout) — the wrapper's stdout is JSON so
# a stray → in a prompt echo would crash. See reference_windows_utf8_encoding_fix.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Dynamic config: JSON file next to this script + env overrides (env wins).
# Feedback_dynamic_over_hardcoding — the model / URL / thresholds can shift; deriving
# them at runtime avoids drift. See scripts/leira_config.json for the source values.
_CONFIG_PATH = Path(__file__).parent / "leira_config.json"
_CONFIG_SCHEMA_PATH = Path(__file__).parent / "leira_config.schema.json"


# ---------------------------------------------------------------------------
# 2026-07-02: multi-host abstraction. The config supports a `hosts.<name>` map
# + a `default_host` field. `OLLAMA_HOST` env picks which host entry to use
# for this invocation; falls back to `default_host`; falls back to "llm-host".
# Legacy top-level `url` / `model` in the config is honored for backward
# compat when the resolved host entry is absent or missing fields.
# Legacy `LEIRA_URL` / `LEIRA_MODEL` / etc env vars still honored (deprecated).
# ---------------------------------------------------------------------------

class LeiraConfigError(RuntimeError):
    """Startup-time config error — an OLLAMA_HOST env explicitly names a host
    not present in ``scripts/leira_config.json``:``hosts``. Distinct from
    ``OllamaCallError`` (call-time) so callers can differentiate a
    misconfiguration (fix env / config) from a call failure (retry / cooldown).
    Raised only when the env var is EXPLICITLY set to an unknown name; an
    implicit fallback via ``default_host`` still legacy-tolerates a missing
    entry via top-level ``url``/``model`` for backward compat with pre-2026-
    07-02 configs (mempalace design_leira_multihost_full).

    Punch  (2026-07-17): ALSO raised at load time by :func:`_load_config`
    when the config file fails JSON-Schema validation against
    ``scripts/leira_config.schema.json``. Catches the silent-coerce drift
    class (typo in ``strategy``, wrong type on ``hosts.<name>.weight``, etc.)
    before the caller sees a mysterious silent fallback."""


def _validate_config_schema(cfg: dict) -> None:
    """Validate the config dict against ``scripts/leira_config.schema.json``.

    Punch  (2026-07-17). Fail-loud on shape drift via LeiraConfigError.
    Fail-open if the schema file is missing OR the ``jsonschema`` package
    isn't importable (never break loading on a validation-infrastructure gap).
    """
    if not _CONFIG_SCHEMA_PATH.exists():
        return
    try:
        import jsonschema  # optional dependency
    except Exception:
        return
    try:
        schema = json.loads(_CONFIG_SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return
    try:
        jsonschema.validate(instance=cfg, schema=schema)
    except jsonschema.ValidationError as e:
        # Compact the path for the operator: hosts -> llm-host -> weight
        path = ".".join(str(p) for p in e.absolute_path) or "<root>"
        raise LeiraConfigError(
            f"scripts/leira_config.json failed schema validation at "
            f"path={path!r}: {e.message}. Fix: correct the config against "
            f"scripts/leira_config.schema.json."
        ) from e


def _load_config() -> dict:
    """Load leira_config.json; return empty dict on any failure (defaults will apply).

    Punch  (2026-07-17): after a successful load, validate against
    ``scripts/leira_config.schema.json`` — a schema mismatch raises
    :class:`LeiraConfigError` (fail-loud on drift, distinct from an
    absent/malformed file which stays fail-open with defaults)."""
    try:
        cfg = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    _validate_config_schema(cfg)
    return cfg


_CFG = _load_config()


def _resolve_active_host() -> dict:
    """Return the resolved host entry per the precedence in mempalace drawer
    ``design_leira_multihost_full`` §Knob-precedence — PS twin parity with
    ``_ResolveActiveHost`` in ``scripts/leira_prepass.psm1``:

    1. ``LEIRA_URL`` env → raw chat URL, bypasses ``hosts`` map. Name recorded
       as ``<env-url>`` sentinel (consumers grep this to detect raw-URL
       routing in audit output).
    2. ``OLLAMA_URL`` env → same as ``LEIRA_URL``, alias.
    3. ``OLLAMA_HOST`` env → picks ``hosts.<name>``. If explicitly set to a
       name absent from a non-empty ``hosts`` map, raises
       :class:`LeiraConfigError` (typo trap).
    4. ``config.default_host`` → picks ``hosts.<default_host>``.
    5. Implicit legacy fallback to top-level ``config.url`` when the resolved
       entry is missing a field (backward compat with pre-2026-07-02 configs;
       applied only when env not explicit).
    6. Last-resort literal ``http://llm-host:11434/api/chat``.
    """
    # Rule 1 + 2: raw-URL env short-circuits the hosts map entirely (PS parity —
    # psm1 `_ResolveActiveHost` L126-131). Name sentinel matches PS so cross-
    # twin audit rows for the same env emit the same string (drawer §active_
    # host_name — audit reproducibility contract).
    raw_url = os.environ.get("LEIRA_URL") or os.environ.get("OLLAMA_URL")
    if raw_url:
        return {
            "name": "<env-url>",
            "url": raw_url,
            "model": _CFG.get("model") or "qwen3.6:35b",
            "context_tokens_fallback": _CFG.get("context_tokens_fallback") or 8192,
        }

    env_host = os.environ.get("OLLAMA_HOST")
    host_name = env_host or _CFG.get("default_host") or "llm-host"
    hosts_map = _CFG.get("hosts", {})
    if not isinstance(hosts_map, dict):
        hosts_map = {}
    entry = hosts_map.get(host_name)
    if env_host and entry is None and hosts_map:
        known = ", ".join(sorted(hosts_map.keys())) or "<none>"
        raise LeiraConfigError(
            f"OLLAMA_HOST={env_host!r} but no such host in "
            f"scripts/leira_config.json:hosts (known: [{known}]). "
            f"Fix: either add hosts.{env_host} to the config, unset "
            f"OLLAMA_HOST to use default_host={_CFG.get('default_host', 'llm-host')!r}, "
            f"or set OLLAMA_URL / LEIRA_URL for a one-off raw-URL override."
        )
    if entry is None:
        entry = {}
    # Merge legacy top-level fields as fallback so a config that hasn't been
    # upgraded to the hosts-map still works (implicit-fallback path only).
    resolved = {
        "name": host_name,
        "url": entry.get("url") or _CFG.get("url") or "http://llm-host:11434/api/chat",
        "model": entry.get("model") or _CFG.get("model") or "qwen3.6:35b",
        "context_tokens_fallback": (
            entry.get("context_tokens_fallback")
            or _CFG.get("context_tokens_fallback")
            or 8192
        ),
    }
    return resolved


_ACTIVE_HOST = _resolve_active_host()


def _resolve_host_by_name(name: str) -> dict:
    """Resolve a specific host entry BY NAME (per-call host override path).

    Twin of the PS ``_ResolveHostByName``. Same class-of-error as
    :func:`_resolve_active_host` rule 3 — an unknown name raises
    :class:`LeiraConfigError` (typo trap symmetric with the env-driven path).
    Distinct from `_resolve_active_host` because the LATTER caches +
    honors ENV precedence; this one is a pure lookup + never caches.
    Used by :func:`call_leira` when the caller passes ``host=<name>`` to
    route a single call to a specific configured host (drawer §Non-goals
    item 4 landing, Drive-B 2026-07-17).
    """
    hosts_map = _CFG.get("hosts", {})
    if not isinstance(hosts_map, dict):
        hosts_map = {}
    entry = hosts_map.get(name)
    if entry is None:
        known = ", ".join(sorted(hosts_map.keys())) or "<none>"
        raise LeiraConfigError(
            f"call_leira(host={name!r}) but no such host in "
            f"scripts/leira_config.json:hosts (known: [{known}]). "
            f"Fix: add hosts.{name} to the config, or omit host= to use "
            f"the module-resolved active host "
            f"({_ACTIVE_HOST.get('name', 'unknown')!r})."
        )
    resolved = {
        "name": name,
        "url": entry.get("url") or _CFG.get("url") or "http://llm-host:11434/api/chat",
        "model": entry.get("model") or _CFG.get("model") or "qwen3.6:35b",
        "context_tokens_fallback": (
            entry.get("context_tokens_fallback")
            or _CFG.get("context_tokens_fallback")
            or 8192
        ),
    }
    return resolved

# Backward-compat name: `LEIRA_URL` still exported as the module-level URL for
# any legacy caller that reads it directly. Now sourced from the resolved
# active host (so the raw-URL env short-circuit at `_resolve_active_host`
# rule 1/2 is honored — the pre-2026-07-17 shape read env AGAIN here, which
# double-applied the env but also masked the drawer's precedence contract).
# New callers should use `_active_host_url()` / `_resolve_active_host()`.
LEIRA_URL = _ACTIVE_HOST["url"]
DEFAULT_TIMEOUT_S = int(
    os.environ.get("OLLAMA_TIMEOUT_S")
    or os.environ.get("LEIRA_TIMEOUT_S")
    or _CFG.get("timeout_s")
    or 300
)
_DEFAULT_TEMPERATURE = float(
    os.environ.get("OLLAMA_TEMPERATURE")
    or os.environ.get("LEIRA_TEMPERATURE")
    or _CFG.get("temperature")
    or 0.1
)


def _resolve_default_think() -> bool | None:
    """Resolve the module-level default for Ollama /api/chat `think` field.

    Precedence: `OLLAMA_THINK` env → `LEIRA_THINK` env → `_CFG.get("think")` →
    None. The tri-state `None` default means "do not send the `think` field at
    all" — the emitted JSON body is byte-identical to the pre-`think`-support
    behaviour for every existing caller. `1/true/yes/on` (case-insensitive) is
    truthy; everything else is falsy; an explicit `None` from `_CFG` stays None.
    """
    for src in (os.environ.get("OLLAMA_THINK"), os.environ.get("LEIRA_THINK")):
        if src is None or src == "":
            continue
        return src.strip().lower() in ("1", "true", "yes", "on")
    cfg_val = _CFG.get("think")
    if cfg_val is None:
        return None
    if isinstance(cfg_val, bool):
        return cfg_val
    return str(cfg_val).strip().lower() in ("1", "true", "yes", "on")


_DEFAULT_THINK: bool | None = _resolve_default_think()


def _resolve_default_keep_alive() -> int | str | None:
    """Resolve the module-level default for Ollama /api/chat `keep_alive`.

    Precedence: `OLLAMA_KEEP_ALIVE` env → `LEIRA_KEEP_ALIVE` env →
    `_CFG.get("keep_alive")` → ``-1`` (integer, forever). Per BINDING
    ``feedback_always_set_ollama_keep_alive_explicitly``: every direct
    `/api/chat` call MUST set ``keep_alive``. Absence lets Ollama apply
    its per-call default of ``"5m"``, which silently overrides any
    operator TTL pin and evicts warm models between calls (measured:
    scope-DA 13.2 s cold-load stall traced to this on qwen3.6:35b).

    Ollama's ``keep_alive`` field accepts either an INTEGER (seconds,
    with ``-1`` meaning "keep forever" and ``0`` meaning "unload
    immediately") OR a duration STRING like ``"30m"`` / ``"1h"``. A
    string ``"-1"`` is REJECTED with HTTP 400 ``time: missing unit in
    duration "-1"`` because Ollama parses string values as Go
    ``time.Duration`` (which requires a unit suffix). The integer form
    is the canonical way to say "forever."

    The SSOT default is the integer ``-1`` — the wrapper owns the
    model-lifetime contract; consumers wanting bounded TTL pass an
    explicit ``keep_alive="30m"`` (str) or ``keep_alive=1800`` (int).
    An env override that parses cleanly as an integer is passed as
    int; anything else is treated as a duration string. An explicit
    config ``None`` stays None — same tri-state as ``think`` — for
    callers that want zero-diff wire behavior.
    """
    for src in (os.environ.get("OLLAMA_KEEP_ALIVE"), os.environ.get("LEIRA_KEEP_ALIVE")):
        if src is None or src == "":
            continue
        s = src.strip()
        try:
            return int(s)
        except ValueError:
            return s
    if "keep_alive" not in _CFG:
        return -1
    cfg_val = _CFG.get("keep_alive")
    if cfg_val is None:
        return None
    if isinstance(cfg_val, int):
        return cfg_val
    s = str(cfg_val).strip()
    try:
        return int(s)
    except ValueError:
        return s


_DEFAULT_KEEP_ALIVE: int | str | None = _resolve_default_keep_alive()


def _api_base() -> str:
    """Derive the Ollama root URL from LEIRA_URL (strip /api/chat)."""
    return LEIRA_URL.rsplit("/api/", 1)[0]


def active_host_name() -> str:
    """Public accessor: which host entry is the wrapper currently talking to?
    Useful for consumers that want to record the source in their output for
    audit / reproducibility."""
    return _ACTIVE_HOST["name"]


def _discover_model() -> str:
    """Learn the primary chat model DYNAMICALLY from llm-host at runtime.

    Strategy: /api/ps first (models currently loaded in RAM — the authoritative "what's
    actually serving right now"); if empty, /api/tags (all installed models). Filter out
    embedding models; prefer the largest by parameter count / size. LEIRA_MODEL env
    override wins if set (for ops override or CI pinning). Fail-open to the last-known
    default if the API is unreachable — the actual call will error clearly later.
    """
    override = os.environ.get("LEIRA_MODEL")
    if override:
        return override

    def _pick_best(models: list[dict]) -> str | None:
        # models = [{"name": "qwen3.6:35b", "size": ...}, ...] from /api/tags or /api/ps
        chat = [m for m in models if "embedding" not in m.get("name", "").lower()]
        if not chat:
            return None
        # Prefer largest by 'size' if present (bytes on disk / in-RAM), else name-sort as fallback
        chat_with_size = [m for m in chat if isinstance(m.get("size"), (int, float))]
        if chat_with_size:
            return max(chat_with_size, key=lambda m: m["size"])["name"]
        return sorted(m["name"] for m in chat)[-1]  # lexicographic — later versions sort higher

    base = _api_base()
    for endpoint in ("/api/ps", "/api/tags"):
        try:
            with urllib.request.urlopen(urllib.request.Request(base + endpoint), timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        models = payload.get("models") or []
        picked = _pick_best(models)
        if picked:
            return picked

    # Everything failed — return a config-file value or a last-resort literal so the actual
    # call still has a name to send. It'll error explicitly if that name isn't installed.
    return _CFG.get("model") or "qwen3.6:35b"


DEFAULT_MODEL = _discover_model()


def _discover_context_tokens(model: str) -> int:
    """Learn the model's LOADED context window DYNAMICALLY (the runtime num_ctx that
    Ollama is actually serving), not the architectural maximum.

    Ollama exposes TWO context numbers and they differ:
    - /api/ps `context_length` per running model = the RUNTIME context (operator's
      num_ctx choice via Modelfile / OLLAMA_CONTEXT env). This is what actually gets
      used per request.
    - /api/show model_info.<arch>.context_length = the ARCHITECTURAL max (native
      pretraining ceiling). Often much larger than what's loaded (e.g. 262144 vs 98304
      on llm-host per pattern_ollama_vram_pressure_kv_quantization).

    We MUST use the runtime value or we'll over-fill prompts. the monitoring system/canary pattern:
    a mismatch between architectural max and runtime is normal (operator chooses),
    but the RUNTIME value is what serves the request.
    """
    override = os.environ.get("LEIRA_CONTEXT_TOKENS")
    if override:
        try:
            return int(override)
        except ValueError:
            pass

    # PRIMARY: /api/ps (the LOADED runtime context — what actually gets served).
    try:
        with urllib.request.urlopen(urllib.request.Request(_api_base() + "/api/ps"), timeout=5) as resp:
            ps = json.loads(resp.read().decode("utf-8"))
        for m in ps.get("models") or []:
            if m.get("name") == model or m.get("model") == model:
                ctx = m.get("context_length")
                if isinstance(ctx, int) and ctx > 0:
                    return ctx
        # Model not in /api/ps -> not loaded. Fall through; the first call will load it.
    except Exception:
        pass

    # FALLBACK: /api/show -> num_ctx from parameters (Modelfile-declared runtime context).
    try:
        req = urllib.request.Request(
            _api_base() + "/api/show",
            data=json.dumps({"model": model}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            info = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return int(_CFG.get("context_tokens_fallback", 8192))

    params = info.get("parameters", "") or ""
    if isinstance(params, str):
        for line in params.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "num_ctx":
                try:
                    return int(parts[1])
                except ValueError:
                    pass

    # LAST RESORT: architectural context_length (may over-report the actual loaded limit,
    # but strictly better than a hardcoded assumption).
    model_info = info.get("model_info") or {}
    for key, val in model_info.items():
        if key.endswith(".context_length") and isinstance(val, int):
            return val

    return int(_CFG.get("context_tokens_fallback", 8192))


DEFAULT_CONTEXT_TOKENS = _discover_context_tokens(DEFAULT_MODEL)


def get_consumer_config(section: str) -> dict:
    """Consumers call this to fetch their config section from leira_config.json.
    Example: get_consumer_config('census_prepass') -> {'context_usage_ratio': 0.4, ...}"""
    return _CFG.get(section) or {}


def context_bytes(ratio: float, *, chars_per_token: int = 4) -> int:
    """Derive an input byte budget from the DISCOVERED model context. `ratio` is the
    fraction of the model's context window to spend on this input (e.g. 0.3 = 30%).
    chars_per_token ~= 4 for qwen family. Consumers use this to size input caps so a
    bigger-context model automatically gets bigger caps (no hardcoded '98K')."""
    return int(DEFAULT_CONTEXT_TOKENS * ratio * chars_per_token)


class OllamaCallError(RuntimeError):
    """Any failure talking to llm-host / parsing/validating the response."""


class LeiraUnavailable(OllamaCallError):
    """Distinct-subclass signal that llm-host is down / rate-limited / in cooldown.
    Consumers can decide whether to fail-open (return UNCERTAIN, skip) or hard-error."""


# ---------------------------------------------------------------------------
# Resilience: ollama_alive() pre-flight, exponential backoff, persistent cooldown.
# Pattern adopted from OpenClaw's intelligence-miner
# (session_2026-05-22_intelligence_miner_repair) + pattern_rate_limit_bailout
# in the F2b-subnet project. Same shape: pre-flight probe, retry w/ backoff,
# on repeated fail write a cooldown-until timestamp to a sidecar so subsequent
# runs no-op cleanly instead of shredding the workload.
# ---------------------------------------------------------------------------

_COOLDOWN_PATH = Path(os.environ.get("TEMP", "/tmp")) / "leira_cooldown.until"
_COOLDOWN_ON_FAIL_S = int(os.environ.get("LEIRA_COOLDOWN_S") or _CFG.get("cooldown_on_fail_s", 300))
_MAX_RETRIES = int(os.environ.get("LEIRA_MAX_RETRIES") or _CFG.get("max_retries", 3))
_BASE_BACKOFF_S = float(os.environ.get("LEIRA_BASE_BACKOFF_S") or _CFG.get("base_backoff_s", 1.0))

# Consecutive-fail counter at module scope (per-process); a fresh Python invocation
# always starts from 0 — the PERSISTENT signal is the cooldown file below.
_consecutive_fails = 0


def _in_cooldown() -> tuple[bool, float]:
    """Return (in_cooldown, seconds_until_lapse) for the GLOBAL cooldown
    sidecar. Retained for backward-compat: pre-Drive-D consumers wrote to
    ``_COOLDOWN_PATH`` directly. Reads the sidecar; treats a malformed /
    stale file as no-cooldown (fail-open).

    Drive-D (2026-07-17): new code path is :func:`_in_cooldown_for` (per-host).
    The global path is treated as an "all hosts benched" signal for
    backward-compat during transition."""
    try:
        until = float(_COOLDOWN_PATH.read_text().strip())
        remaining = until - time.time()
        return (remaining > 0, max(0.0, remaining))
    except Exception:
        return (False, 0.0)


def _set_cooldown(reason: str, duration_s: int = None) -> None:
    """Write the GLOBAL cooldown sidecar. Retained for backward-compat.

    Drive-D (2026-07-17): new code arms per-host via :func:`_set_cooldown_for`.
    Direct callers of ``_set_cooldown()`` bench every host; keep for tests
    that pre-Drive-D exercised the global path directly."""
    dur = int(duration_s if duration_s is not None else _COOLDOWN_ON_FAIL_S)
    until = time.time() + dur
    try:
        _COOLDOWN_PATH.write_text(str(until))
        print(f"leira_prepass: cooldown until {time.strftime('%H:%M:%S', time.localtime(until))} — {reason}",
              file=sys.stderr)
    except Exception:
        pass  # cooldown is a hint; failure to write it is not fatal


def _sanitize_host_for_path(name: str) -> str:
    """Return a filesystem-safe token for use in a per-host cooldown filename.

    Drive-D (2026-07-17). Preserves alphanumeric + hyphen + underscore; any
    other byte becomes underscore. Prevents path traversal (``../``) and
    OS-illegal chars (``:``, ``/``, ``\\``). ``<env-url>`` from the raw-URL
    bypass becomes ``_env-url_`` — a stable dedicated bucket, never colliding
    with a real host name (angle brackets never appear in a real name).

    db-sme Batch-2 NTH#4 fold: an empty/whitespace-only name would sanitize
    to ``''`` giving a filename ``leira_cooldown..until`` (double-dot). Not
    exploitable (host names are never empty in current code) but a defensive
    gap — coerce to ``_unnamed_`` when sanitize collapses to empty."""
    sanitized = "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in name)
    return sanitized or "_unnamed_"


def _cooldown_path_for(host_name: str) -> Path:
    """Per-host cooldown sidecar path: ``$TEMP/leira_cooldown.<host>.until``.

    Drive-D (2026-07-17). Twin of PS ``_CooldownPathFor``. Distinct filename
    per host so benching ``hosts.the ML host`` doesn't bench ``hosts.llm-host`` —
    the fine-grained shape the drawer's §Non-goals item 2 required for
    Drive-E failover as a prerequisite."""
    safe = _sanitize_host_for_path(host_name)
    return Path(os.environ.get("TEMP", "/tmp")) / f"leira_cooldown.{safe}.until"


def _in_cooldown_for(host_name: str) -> tuple[bool, float]:
    """Return ``(in_cooldown, seconds_until_lapse)`` for the given host.

    Drive-D (2026-07-17). Backward-compat OR: reads both the per-host
    sidecar AND the GLOBAL sidecar (``_COOLDOWN_PATH``). Either being in
    the future counts — the global path is treated as "all hosts benched"
    (pre-Drive-D semantics). The returned ``seconds_until_lapse`` is the
    LONGER of the two.
    """
    max_remaining = 0.0
    in_cd = False
    for path in (_cooldown_path_for(host_name), _COOLDOWN_PATH):
        try:
            until = float(path.read_text().strip())
            remaining = until - time.time()
            if remaining > 0:
                in_cd = True
                if remaining > max_remaining:
                    max_remaining = remaining
            else:
                # db-sme Batch-2 NTH#3 fold: unlink expired sidecar (mirror
                # of the legacy _CooldownRemaining cleanup). Per-host sidecars
                # otherwise accumulate one file per host name ever benched.
                try:
                    path.unlink()
                except Exception:
                    pass
        except Exception:
            continue
    return (in_cd, max_remaining)


def _set_cooldown_for(host_name: str, reason: str, duration_s: int | None = None) -> None:
    """Arm the per-host cooldown sidecar. Drive-D (2026-07-17).

    Only benches ``host_name`` — other hosts remain callable. Prints a
    stderr line naming the benched host so an operator grepping the log
    can see WHICH host tripped which cooldown."""
    dur = int(duration_s if duration_s is not None else _COOLDOWN_ON_FAIL_S)
    until = time.time() + dur
    try:
        _cooldown_path_for(host_name).write_text(str(until))
        print(
            f"leira_prepass: host={host_name} cooldown until "
            f"{time.strftime('%H:%M:%S', time.localtime(until))} — {reason}",
            file=sys.stderr,
        )
    except Exception:
        pass  # cooldown is a hint; failure to write it is not fatal


def ollama_alive(timeout_s: int = 4, *, base_url: str | None = None) -> bool:
    """Pre-flight probe: ``/api/version``. Returns True iff Ollama is reachable.

    ``base_url`` (Drive-B addition, 2026-07-17): when set, probes THAT root
    instead of the module-resolved ``_api_base()``. Used by
    :func:`call_leira` when the caller passes ``host=<name>`` to route a
    single call to a specific configured host; the pre-flight then targets
    THAT host, not the cached module active host.
    """
    root = base_url if base_url is not None else _api_base()
    try:
        with urllib.request.urlopen(urllib.request.Request(root + "/api/version"),
                                    timeout=timeout_s) as resp:
            return resp.status == 200
    except Exception:
        return False


def _call_leira_once(
    task_prompt: str,
    schema: dict | None = None,
    *,
    model: str | None = None,
    system: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    think: bool | None = None,
    keep_alive: str | None = None,
    host: str | None = None,
) -> dict | str:
    """Single-shot llm-host call — one host, no failover.

    Drive-E (2026-07-17) refactor: the pre-existing ``call_leira`` body was
    renamed here; the public ``call_leira`` now orchestrates failover across
    a chain of hosts, delegating to this helper for each individual attempt.

    Resilience (adopted from OpenClaw's intelligence-miner +
    F2b-subnet's pattern_rate_limit_bailout): checks the per-host cooldown
    (Drive-D) first, then pre-flights ``ollama_alive()`` on the resolved
    host, then retries with exponential backoff on transient failures.
    Exhausted retries arm the per-host cooldown + raise ``LeiraUnavailable``
    so subsequent invocations no-op cleanly instead of shredding a batch
    through cascading timeouts. The public ``call_leira`` catches that
    ``LeiraUnavailable`` and tries the next failover host.
    """
    global _consecutive_fails

    # Drive-B (2026-07-17) — per-call host override. When set, resolve the
    # named host at CALL time (via _resolve_host_by_name) + use its URL for
    # both pre-flight + POST. Unknown name raises LeiraConfigError — typo-trap
    # symmetric with the env-driven rule 3 in _resolve_active_host. Consumers
    # get the resolved host echoed back in _leira_meta.active_host for audit.
    # (Resolve BEFORE cooldown check so the check keys on the RESOLVED host —
    # Drive-D per-host cooldown means a benched siblings does not block us.)
    if host is not None:
        _call_host = _resolve_host_by_name(host)
    else:
        _call_host = _ACTIVE_HOST
    _call_url = _call_host["url"]
    _call_base = _call_url.rsplit("/api/", 1)[0]
    _effective_model = model if model is not None else (_call_host.get("model") or DEFAULT_MODEL)

    # Drive-D (2026-07-17) — persistent per-host cooldown check. Reads the
    # per-host sidecar OR the legacy GLOBAL sidecar (backward-compat "all
    # benched" signal). Skips until whichever is furthest-in-the-future lapses.
    in_cd, remaining = _in_cooldown_for(_call_host["name"])
    if in_cd:
        raise LeiraUnavailable(
            f"llm-host host={_call_host['name']} in cooldown for {remaining:.0f}s "
            f"more (touch/rm {_cooldown_path_for(_call_host['name'])} to clear "
            f"the per-host sidecar; {_COOLDOWN_PATH} clears the legacy global)"
        )

    # Pre-flight the RESOLVED host's base URL, not the module-cached one.
    # A per-call override to a dead ad-hoc host would otherwise pre-flight
    # the module host + succeed, then blow up in the retry loop.
    if not ollama_alive(base_url=_call_base):
        _set_cooldown_for(
            _call_host["name"],
            f"ollama_alive pre-flight failed for host={_call_host['name']}",
        )
        raise LeiraUnavailable(f"llm-host unreachable at {_call_base}")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": task_prompt})

    body = {
        "model": _effective_model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": _DEFAULT_TEMPERATURE},  # deterministic-leaning; configurable
    }
    if schema is not None:
        body["format"] = schema

    # `think` is a TOP-LEVEL field on Ollama /api/chat (sibling of stream /
    # format / options — NOT nested in options; prior in-options placement
    # was a proven no-op). Guarded by `is not None` so the default None case
    # sends no field at all and the wire payload matches pre-`think` behaviour
    # for every existing caller.
    _effective_think = think if think is not None else _DEFAULT_THINK
    if _effective_think is not None:
        body["think"] = _effective_think

    # `keep_alive` is a TOP-LEVEL field on Ollama /api/chat controlling how
    # long the model stays warm after the call. Per BINDING
    # `feedback_always_set_ollama_keep_alive_explicitly`, every direct call
    # MUST set it — absence lets Ollama apply its per-call "5m" default,
    # silently overriding operator TTL pins and evicting warm models between
    # calls. The SSOT default (`_DEFAULT_KEEP_ALIVE`) is int `-1` (forever)
    # so the wrapper OWNS the model-lifetime contract; explicit callers may
    # pass a bounded duration string like "30m" OR an int seconds count.
    # NOTE: string "-1" is REJECTED by Ollama (HTTP 400, missing time unit) —
    # the "forever" sentinel is int-only; see `_resolve_default_keep_alive`
    # docstring for the wire-shape rules. Tri-state None matches `think`:
    # an explicit config None sends no field, byte-for-byte compat with
    # pre-`keep_alive` behavior for callers that opt back out.
    _effective_keep_alive = keep_alive if keep_alive is not None else _DEFAULT_KEEP_ALIVE
    if _effective_keep_alive is not None:
        body["keep_alive"] = _effective_keep_alive

    req = urllib.request.Request(
        _call_url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    last_err: Exception | None = None
    payload = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            _consecutive_fails = 0  # success clears the streak
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            last_err = e
            _consecutive_fails += 1
            if attempt < _MAX_RETRIES:
                delay = _BASE_BACKOFF_S * (2 ** (attempt - 1))
                print(f"leira_prepass: attempt {attempt}/{_MAX_RETRIES} failed ({e}); backoff {delay:.1f}s",
                      file=sys.stderr)
                time.sleep(delay)
            continue
    if payload is None:
        # All retries exhausted — arm the PER-HOST cooldown (Drive-D) so
        # subsequent runs targeting THIS host no-op cleanly, while calls
        # to other hosts remain unblocked. Backward-compat: consumers still
        # blocking on the global sidecar keep working via _in_cooldown_for's
        # OR-read.
        _set_cooldown_for(
            _call_host["name"],
            f"{_MAX_RETRIES} consecutive failures ({last_err})",
        )
        raise LeiraUnavailable(
            f"llm-host host={_call_host['name']} call failed {_MAX_RETRIES}× "
            f"(last: {last_err}); per-host cooldown engaged"
        )

    content = payload.get("message", {}).get("content", "")
    elapsed = time.monotonic() - started

    if schema is None:
        return content

    try:
        obj = json.loads(content)
    except json.JSONDecodeError as e:
        raise OllamaCallError(
            f"llm-host content wasn't valid JSON (elapsed {elapsed:.1f}s): {e}\nRaw: {content[:400]}"
        ) from e

    # Minimal schema validation: check required top-level keys are present. Deep validation
    # is the consumer's job (each has its own domain checks); we just ensure the model
    # produced the top-level shape.
    for key in schema.get("required", []):
        if key not in obj:
            raise OllamaCallError(f"llm-host response missing required key '{key}': keys={list(obj)}")

    obj["_leira_meta"] = {
        "model": _effective_model,
        "active_host": _call_host["name"],
        "elapsed_s": round(elapsed, 2),
        "eval_tokens": payload.get("eval_count"),
        "prompt_tokens": payload.get("prompt_eval_count"),
    }
    return obj


# Rotation counter (Drive-F). Process-scope Python int (arbitrary precision,
# no overflow). Punch  (2026-07-17): the counter is persisted to a shared
# sidecar `$TEMP/leira_rotation.next` so mixed Python+PS callers see a
# SYNCHRONIZED cursor rather than per-language drift. Fail-open on sidecar
# read/write errors (module counter is the fallback).
_ROTATION_COUNTER = 0
_ROTATION_SIDECAR = Path(os.environ.get("TEMP", "/tmp")) / "leira_rotation.next"
_VALID_STRATEGIES = ("primary", "round_robin", "weighted")


def _load_rotation_counter() -> int | None:
    """Read the shared rotation sidecar. Returns the persisted int or None
    when the file is absent / malformed / unreadable (fail-open)."""
    try:
        return int(_ROTATION_SIDECAR.read_text().strip())
    except Exception:
        return None


def _persist_rotation_counter(value: int) -> None:
    """Write the current counter to the shared sidecar. Fail-silent on IO
    error — the counter is a hint; the module fallback keeps working."""
    try:
        _ROTATION_SIDECAR.write_text(str(int(value)))
    except Exception:
        pass
_BAD_STRATEGY_SEEN: set[str] = set()


def _warn_once_bad_strategy(value: object) -> None:
    """Emit a one-shot stderr warning per unknown strategy value seen this
    process. hipaa-sme Batch-3 NTH-1 fold — invalid strategy strings coerce
    to 'primary' silently, hiding the root cause when an operator's
    rotation config isn't rotating."""
    key = repr(value)
    if key in _BAD_STRATEGY_SEEN:
        return
    _BAD_STRATEGY_SEEN.add(key)
    print(
        f"leira_prepass: unknown strategy {value!r}, defaulting to 'primary' "
        f"(valid: {_VALID_STRATEGIES})",
        file=sys.stderr,
    )


def _build_rotation_pool(strategy: str) -> list[str]:
    """Return the ordered rotation pool for a strategy. Drive-F (2026-07-17).

    ``round_robin`` yields each configured host name once (sorted for
    deterministic ordering across processes). ``weighted`` yields each
    host ``entry.weight`` times (default 1). ``primary`` (default) returns
    an empty list — no rotation happens, module-resolved active host is used.
    """
    hosts_map = _CFG.get("hosts") or {}
    if not isinstance(hosts_map, dict):
        hosts_map = {}
    names = sorted(hosts_map.keys())
    if strategy == "round_robin":
        return names
    if strategy == "weighted":
        pool: list[str] = []
        for name in names:
            entry = hosts_map[name] or {}
            weight = entry.get("weight") if isinstance(entry, dict) else None
            try:
                w = max(1, int(weight) if weight is not None else 1)
            except (TypeError, ValueError):
                w = 1
            pool.extend([name] * w)
        return pool
    return []  # 'primary' or unrecognized -> no rotation


def _resolve_consumer_host(consumer: str) -> str | None:
    """Return the affinity host name for ``consumer`` if configured.

    Drive-G (2026-07-17). Reads ``_CFG[consumer].host``. Returns None when
    the section is absent, is not a dict, or has no ``host`` field. Absent
    consumer sections are LEGAL (consumers may opt in without a host); an
    UNKNOWN host name is caught by ``_resolve_host_by_name`` downstream and
    surfaced as ``LeiraConfigError``.
    """
    section = _CFG.get(consumer)
    if not isinstance(section, dict):
        return None
    host = section.get("host")
    if not isinstance(host, str) or not host.strip():
        return None
    return host


def _next_host_by_strategy(strategy: str) -> str | None:
    """Advance the module rotation counter modulo the pool; skip cooldown'd.

    Drive-F (2026-07-17). ``primary`` returns None (caller falls back to
    default resolution). Empty pool returns None. When every candidate is
    cooldown'd, returns pool[0] anyway so the failover chain / orchestrator
    can decide (the ensuing call will re-check cooldown + raise cleanly).
    """
    global _ROTATION_COUNTER
    pool = _build_rotation_pool(strategy)
    if not pool:
        return None
    # Punch : load persisted counter (cross-language sync) so a mixed
    # Py+PS caller sees a SHARED cursor. Fail-open on read errors.
    persisted = _load_rotation_counter()
    if persisted is not None:
        _ROTATION_COUNTER = persisted
    n = len(pool)
    for _ in range(n):
        idx = _ROTATION_COUNTER % n
        _ROTATION_COUNTER += 1
        _persist_rotation_counter(_ROTATION_COUNTER)
        candidate = pool[idx]
        in_cd, _ = _in_cooldown_for(candidate)
        if not in_cd:
            return candidate
    return pool[0]


def call_leira(
    task_prompt: str,
    schema: dict | None = None,
    *,
    model: str | None = None,
    system: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    think: bool | None = None,
    keep_alive: str | None = None,
    host: str | None = None,
    failover_hosts: list[str] | None = None,
    strategy: str | None = None,
    consumer: str | None = None,
) -> dict | str:
    """Call llm-host with optional cross-host failover (Drive-E, 2026-07-17).

    When ``failover_hosts`` (or ``config.failover_hosts``) is set, this
    orchestrator builds an ordered chain: [primary, *failover_hosts] with
    duplicates removed, then delegates to :func:`_call_leira_once` for each.
    A :class:`LeiraUnavailable` from one host causes the orchestrator to try
    the next; a :class:`LeiraConfigError` (misconfig / typo trap) bubbles
    immediately — those cannot be recovered by trying another host.

    Args:
        host: pin the PRIMARY host for this call (Drive-B). When None, the
            module-resolved active host is used. Wins over ``consumer`` and
            ``strategy`` — explicit user intent trumps rotation.
        failover_hosts: ordered list of host names to try if the primary
            fails. When None, sources from ``config.failover_hosts`` (empty
            list means "no failover" = pre-Drive-E behaviour).
        strategy: rotation strategy for primary-host selection (Drive-F).
            One of ``'primary'`` (default; pre-Drive-F behaviour), ``'round_robin'``
            (each configured host in turn), or ``'weighted'`` (each host
            repeated ``hosts.<name>.weight`` times, default 1). Per-call value
            wins over ``config.strategy``. Only fires when ``host`` and
            ``consumer`` do not already pin one. Rotation counter is
            process-scope — see the module docstring for cross-twin drift.
        consumer: name of a consumer section (e.g. ``'census_prepass'``,
            ``'verify_prepass'``) — Drive-G per-consumer host affinity. When
            the section carries a ``host`` field, that value becomes the
            primary. Wins over ``strategy`` but loses to explicit ``host=``.
            A consumer-pinned host still respects cooldown; pair with
            ``failover_hosts`` for resilience.

    Returns:
        Same shape as :func:`_call_leira_once`. When failover triggered
        (a non-primary host served), the returned dict (schema mode) grows
        ``_leira_meta.failover_chain`` listing the hosts tried in order —
        the last entry is the one that served.

    Raises:
        LeiraConfigError: primary or any failover host name is unknown.
        LeiraUnavailable: every host in the chain failed.
    """
    # Drive-G (2026-07-17): per-consumer host affinity. When ``consumer`` is
    # named and its config section carries a ``host`` field, treat it as the
    # primary UNLESS the caller pinned host= (explicit intent wins). This
    # runs BEFORE strategy resolution so a consumer-pinned host is not
    # overwritten by round-robin/weighted rotation.
    if host is None and consumer is not None:
        _consumer_host = _resolve_consumer_host(consumer)
        if _consumer_host is not None:
            host = _consumer_host

    # Drive-F (2026-07-17): strategy resolution — round-robin / weighted
    # rotate the PRIMARY host across the configured `hosts` map. Per-call
    # strategy= kwarg wins; falls back to config.strategy; defaults to
    # 'primary' (pre-Drive-F behavior). Only fires when the caller has
    # NOT pinned a specific host= (which the user's per-call intent must
    # win over any rotation).
    _strategy = strategy if strategy is not None else (_CFG.get("strategy") or "primary")
    if _strategy not in _VALID_STRATEGIES:
        # hipaa-sme Batch-3 NTH-1 fold: an invalid strategy string silently
        # coerces to 'primary' — surface once/process on stderr so operators
        # can see WHY a config-driven rotation isn't rotating.
        _warn_once_bad_strategy(_strategy)
        _strategy = "primary"
    if host is None and _strategy in ("round_robin", "weighted"):
        _picked = _next_host_by_strategy(_strategy)
        if _picked is not None:
            host = _picked

    # DA Batch-2 NTH#4 fold: coerce non-list config values to [] so a typo
    # like `"failover_hosts": "the ML host"` (single-string) does NOT char-iterate
    # into ['s', 'a', 'v', ...]. Per-call kwarg is typed by the caller.
    _failover_cfg = failover_hosts if failover_hosts is not None else (
        _CFG.get("failover_hosts") or []
    )
    if not isinstance(_failover_cfg, list):
        _failover_cfg = []
    if not _failover_cfg:
        # No failover configured — behave as pre-Drive-E: one host, one try.
        return _call_leira_once(
            task_prompt, schema,
            model=model, system=system, timeout_s=timeout_s,
            think=think, keep_alive=keep_alive, host=host,
        )
    # db-sme Batch-2 NTH#2 fold: legacy global cooldown active → skip the
    # whole chain (every host is benched by the global OR-read semantic).
    # Surfacing "global cooldown active" is more honest than "N hosts exhausted".
    in_cd_global, remaining = _in_cooldown()
    if in_cd_global:
        raise LeiraUnavailable(
            f"llm-host legacy global cooldown active ({remaining:.0f}s remaining); "
            f"touch/rm {_COOLDOWN_PATH} to clear (failover_hosts={_failover_cfg})"
        )
    # db-sme Batch-2 NTH#1 fold: raw-URL sentinel (`<env-url>`) is not a
    # config host name — passing it to _call_leira_once as host=... would
    # raise LeiraConfigError (not in hosts map). When the module active host
    # is the sentinel, route the FIRST attempt WITHOUT host= so it uses the
    # cached _ACTIVE_HOST directly; failovers still resolve normally.
    _primary_active = host if host is not None else _ACTIVE_HOST["name"]
    _use_sentinel_route = (
        host is None and _primary_active == "<env-url>"
    )
    chain: list[str] = [_primary_active]
    for h in _failover_cfg:
        if h not in chain:
            chain.append(h)
    last_err: Exception | None = None
    for i, h in enumerate(chain):
        try:
            result = _call_leira_once(
                task_prompt, schema,
                model=model, system=system, timeout_s=timeout_s,
                think=think, keep_alive=keep_alive, host=h,
            )
            if isinstance(result, dict) and i > 0:
                # Failover fired — record the actual chain traversed for
                # audit reproducibility (drawer §Non-goals item 1 shape).
                result.setdefault("_leira_meta", {})["failover_chain"] = chain[: i + 1]
            return result
        except LeiraUnavailable as e:
            last_err = e
            continue
    raise LeiraUnavailable(
        f"llm-host all {len(chain)} hosts exhausted (chain={chain}); "
        f"last error: {last_err}"
    )


def leira_healthcheck(*, timeout_s: int = 4) -> list[dict]:
    """Probe ``/api/tags`` on EVERY host in ``scripts/leira_config.json:hosts``.

    Drive-C landing (2026-07-17). Consumers call this for a status-dashboard
    view of which alternates are reachable and how loaded they are; strictly
    informational — does NOT trip the cooldown sidecar, does NOT auto-route.
    Failover / preferred-alternate selection landed in Drive-E (2026-07-17);
    healthcheck itself remains informational and does not auto-route.

    Returns a list of dicts sorted by host name for deterministic ordering:

        [
            {
                "name": <str>, "url": <chat url>, "reachable": <bool>,
                "latency_ms": <int>, "model_count": <int|None>,
                "error": <str|None>  # truncated to 200 chars when set
            },
            ...
        ]

    Twin of PS ``Get-LeiraHealthcheck``. Both hit the SAME endpoint (``/api/tags``)
    so cross-language cross-check is a simple equality on ``name`` +
    ``reachable``.
    """
    hosts_map = _CFG.get("hosts", {})
    if not isinstance(hosts_map, dict):
        hosts_map = {}
    results: list[dict] = []
    for name in sorted(hosts_map):
        entry = hosts_map[name] or {}
        chat_url = entry.get("url") or _CFG.get("url") or "http://llm-host:11434/api/chat"
        base = chat_url.rsplit("/api/", 1)[0]
        tags_url = base + "/api/tags"
        started = time.monotonic()
        try:
            with urllib.request.urlopen(
                urllib.request.Request(tags_url), timeout=timeout_s
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            latency_ms = int((time.monotonic() - started) * 1000)
            models = data.get("models") or []
            results.append({
                "name": name,
                "url": chat_url,
                "reachable": True,
                "latency_ms": latency_ms,
                "model_count": len(models),
                "error": None,
            })
        except Exception as e:
            latency_ms = int((time.monotonic() - started) * 1000)
            results.append({
                "name": name,
                "url": chat_url,
                "reachable": False,
                "latency_ms": latency_ms,
                "model_count": None,
                "error": str(e)[:200],
            })
    return results


def probe_leira() -> tuple[bool, str]:
    """Quick reachability probe: returns (ok, message). URL derived from LEIRA_URL."""
    tags_url = LEIRA_URL.rsplit("/api/", 1)[0] + "/api/tags"
    try:
        with urllib.request.urlopen(urllib.request.Request(tags_url), timeout=5) as resp:
            models = [m["name"] for m in json.loads(resp.read()).get("models", [])]
        if DEFAULT_MODEL in models:
            return True, f"llm-host reachable at {tags_url}; {DEFAULT_MODEL} present ({len(models)} models)"
        return False, f"llm-host reachable but {DEFAULT_MODEL} missing; found: {models}"
    except Exception as e:
        return False, f"llm-host unreachable at {tags_url}: {e}"


if __name__ == "__main__":
    # CLI: probe reachability (no args) OR pipe a prompt on stdin (--prompt).
    if len(sys.argv) == 1:
        ok, msg = probe_leira()
        print(msg)
        sys.exit(0 if ok else 2)
    if sys.argv[1] == "--prompt":
        prompt = sys.stdin.read()
        try:
            out = call_leira(prompt)
        except OllamaCallError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        print(out)
