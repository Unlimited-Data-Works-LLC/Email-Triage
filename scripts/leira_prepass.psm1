#Requires -Version 7.0
<#
.SYNOPSIS
  leira_prepass.psm1 — PowerShell 7 port of scripts/leira_prepass.py.
  ONE call surface (Invoke-LeiraCall) for any PS Consumer of the llm-host offload stack.

.DESCRIPTION
  Enforces the 5 non-negotiable pillars from mempalace drawer `pattern_leira_offload_stack`:
    P1 NO HARDCODING       - model / context / timeouts / limits come from config or /api/show
    P2 DYNAMIC discovery   - /api/show once per process, cached module-scope
    P3 CONGESTION backoff  - exponential retry + persistent cooldown SIDECAR (Python-shared)
    P4 STRUCTURED output   - optional -Schema hashtable, wired as Ollama /api/chat 'format' field
    P5 HIPAA at CALLSITE   - this module does NOT gate; the invoking pipeline does

  Shares state with the Python wrapper so cross-language consumers never fight:
    - Reads the SAME scripts/leira_config.json (repo-root/scripts/)
    - Reads/writes the SAME cooldown sentinel: $env:TEMP\leira_cooldown.until
    - Honors the SAME env overrides: LEIRA_MAX_RETRIES / LEIRA_BASE_BACKOFF_S /
      LEIRA_COOLDOWN_S / LEIRA_OLLAMA_BASE_URL

  Consumer contract (mirrors the Python one):
    Import-Module ./scripts/leira_prepass.psm1 -Force
    $cfg = Get-LeiraConsumerConfig -Name 'my_consumer'
    $bytes = if ($cfg.max_input_bytes_override) { [int]$cfg.max_input_bytes_override } `
             else { Get-LeiraContextBytes -Ratio ($cfg.context_usage_ratio ?? 0.40) }
    try {
      $out = Invoke-LeiraCall -TaskPrompt $prompt -Schema $schema
    } catch [LeiraUnavailable] {
      # degrade gracefully — return {leira_error, empty payload}, exit 0
    }

.NOTES
  pwsh 7 ONLY (feedback_use_pwsh7_not_ps51). Uses ternary (?:), null-coalescing (??),
  class-based custom exceptions, and Invoke-RestMethod's -TimeoutSec.

  Multi-host support landed 2026-07-17 (session-following the pwsh7 twin drive per
  operator approval "OK, it's tooling. Approved."):
    - `OLLAMA_HOST` env picks `hosts.<name>` from the JSON config (Python parity
      with `_resolve_active_host` L62-101). An EXPLICIT `OLLAMA_HOST` that names a
      host absent from the map raises `LeiraConfigError` — a typo silently routing
      back to the default host was the multi-host trap `design_leira_multihost_full`
      closes.
    - `Get-LeiraActiveHost` public accessor (twin of Python `active_host_name` L141)
      returns the resolved host name so PS consumers can record it in audit output.
    - `LEIRA_URL` / `OLLAMA_URL` env overrides (Python parity L93-97) wire the raw
      `/api/chat` URL — bypass path for callers that need to hit an ad-hoc host
      not in the map. `LEIRA_OLLAMA_BASE_URL` still honored for BC.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Custom exception types ------------------------------------------------
# Match Python parity (leira_prepass.py ~L278-284):
#   OllamaCallError  = base for all call-time failures the consumer can recover from
#   LeiraUnavailable = subclass — cheap fast-fail during cooldown or reachability.
# The subclass relationship is a CONTRACT: consumers catch [OllamaCallError] to sweep
# BOTH branches; a bare `System.Exception` parent (previous shape) leaked past that catch.
# Order matters — OllamaCallError MUST be defined before LeiraUnavailable.
class OllamaCallError : System.Exception {
    OllamaCallError([string]$Msg) : base($Msg) {}
}
class LeiraUnavailable : OllamaCallError {
    LeiraUnavailable([string]$Msg) : base($Msg) {}
}
# Startup-time config error — distinct from OllamaCallError so callers can
# differentiate a misconfiguration (fix env / config) from a call failure
# (retry / cooldown). Raised only when OLLAMA_HOST is EXPLICITLY set to a
# name absent from the `hosts` map; Python parity with LeiraConfigError.
class LeiraConfigError : System.Exception {
    LeiraConfigError([string]$Msg) : base($Msg) {}
}

# ---- Paths, module-scope cache ---------------------------------------------
# $PSScriptRoot points at scripts/ (module lives there). Config sits beside it.
$Script:ConfigPath   = Join-Path $PSScriptRoot 'leira_config.json'
$Script:CooldownPath = Join-Path $env:TEMP 'leira_cooldown.until'   # SHARED with Python
$Script:Discovered   = $null     # cached { Model, ContextTokens, KeepAlive, BaseUrl }
$Script:CachedConfig = $null
$Script:ActiveHost   = $null     # cached { Name, Url } — resolved once per process

# ---- Config loader (SSOT: scripts/leira_config.json) -----------------------
function Get-LeiraConfig {
    [CmdletBinding()] param()
    if ($Script:CachedConfig) { return $Script:CachedConfig }
    if (-not (Test-Path $Script:ConfigPath)) {
        throw [OllamaCallError]::new("leira_config.json not found at $($Script:ConfigPath)")
    }
    $Script:CachedConfig = Get-Content -Raw $Script:ConfigPath | ConvertFrom-Json -AsHashtable
    return $Script:CachedConfig
}

function Get-LeiraConsumerConfig {
    [CmdletBinding()] param([Parameter(Mandatory)] [string]$Name)
    # Python parity (leira_prepass.py `get_consumer_config` ~L264-267): consumer
    # sections sit at the TOP LEVEL of leira_config.json (census_prepass, draft,
    # verify_prepass, defer_sweep, push_ci_shepherd, ...). There is NO `consumers`
    # wrapper — a nested lookup silently returns {} for every consumer, which then
    # falls through to hardcoded defaults + defeats config tuning.
    $cfg = Get-LeiraConfig
    return ($cfg[$Name] ?? @{})
}

# ---- Env-override helpers --------------------------------------------------
function _EnvOr {
    param([string]$EnvName, $Default)
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if ($null -ne $v -and $v -ne '') { return $v }
    return $Default
}

function _ResolveActiveHost {
    # Python parity (leira_prepass.py `_resolve_active_host` L62-101, tightened
    # 2026-07-17). Precedence:
    #   1. LEIRA_URL / OLLAMA_URL env — raw chat URL, bypasses the `hosts` map
    #      (name recorded as '<env-url>' for audit).
    #   2. OLLAMA_HOST env — picks `hosts.<name>`. If EXPLICIT + name absent from
    #      the map, raise LeiraConfigError (typo trap; the design record decision).
    #   3. `$cfg.default_host` → `hosts.<default_host>.url`.
    #   4. Implicit fallback to legacy top-level `$cfg.url` (backward compat with
    #      pre-multi-host configs, applied only when env not explicit).
    #   5. Last-resort literal http://llm-host:11434/api/chat.
    # Cached module-scope so multiple callers see the same resolved host.
    if ($Script:ActiveHost) { return $Script:ActiveHost }

    $rawUrlEnv = _EnvOr 'LEIRA_URL'   $null
    if (-not $rawUrlEnv) { $rawUrlEnv = _EnvOr 'OLLAMA_URL' $null }
    if ($rawUrlEnv) {
        $Script:ActiveHost = @{ Name = '<env-url>'; Url = $rawUrlEnv }
        return $Script:ActiveHost
    }

    $cfg         = Get-LeiraConfig
    $envHost     = _EnvOr 'OLLAMA_HOST' $null
    $hostName    = $envHost ?? ($cfg['default_host'] ?? 'llm-host')
    $hostsMap    = $cfg['hosts'] ?? @{}
    $hostEntry   = $hostsMap[$hostName]

    if ($envHost -and (-not $hostEntry) -and $hostsMap.Count -gt 0) {
        $known = ($hostsMap.Keys | Sort-Object) -join ', '
        if (-not $known) { $known = '<none>' }
        throw [LeiraConfigError]::new(
            "OLLAMA_HOST='$envHost' but no such host in " +
            "scripts/leira_config.json:hosts (known: [$known]). Fix: either " +
            "add hosts.$envHost to the config, unset OLLAMA_HOST to use " +
            "default_host='$($cfg['default_host'])', or set OLLAMA_URL / " +
            "LEIRA_URL for a one-off raw-URL override."
        )
    }
    if (-not $hostEntry) { $hostEntry = @{} }
    $configUrl = $hostEntry['url'] ?? $cfg['url'] ?? 'http://llm-host:11434/api/chat'
    $Script:ActiveHost = @{ Name = $hostName; Url = $configUrl }
    return $Script:ActiveHost
}

function _ResolveHostByName {
    # Twin of Python `_resolve_host_by_name` (leira_prepass.py Drive-B, 2026-07-17).
    # Pure lookup — no env precedence, no cache. Unknown name raises LeiraConfigError
    # (typo trap symmetric with _ResolveActiveHost rule 3). Used by Invoke-LeiraCall
    # when -Host <name> is passed to route a single call to a specific configured host.
    param([Parameter(Mandatory)] [string]$Name)
    $cfg      = Get-LeiraConfig
    $hostsMap = $cfg['hosts'] ?? @{}
    $entry    = $hostsMap[$Name]
    if (-not $entry) {
        $known = ($hostsMap.Keys | Sort-Object) -join ', '
        if (-not $known) { $known = '<none>' }
        throw [LeiraConfigError]::new(
            "Invoke-LeiraCall -Host '$Name' but no such host in " +
            "scripts/leira_config.json:hosts (known: [$known]). Fix: add " +
            "hosts.$Name to the config, or omit -Host to use the " +
            "module-resolved active host ('$((_ResolveActiveHost).Name)')."
        )
    }
    return @{
        Name  = $Name
        Url   = $entry['url'] ?? $cfg['url'] ?? 'http://llm-host:11434/api/chat'
        Model = $entry['model'] ?? $cfg['model'] ?? 'qwen3.6:35b'
        ContextTokensFallback = $entry['context_tokens_fallback'] ?? $cfg['context_tokens_fallback'] ?? 8192
    }
}

function Get-LeiraActiveHost {
    <#
    .SYNOPSIS
      Return the currently-resolved active host name — PS twin of Python
      `active_host_name()` (leira_prepass.py L141). Public accessor so PS
      consumers can record which Ollama host served the response in their
      audit output (source-of-truth for `hosts.<name>` selection).
    .OUTPUTS
      [string] the resolved host name. '<env-url>' when LEIRA_URL / OLLAMA_URL
      was used to bypass the `hosts` map with a raw chat URL.
    .NOTES
      Throws `LeiraConfigError` if `OLLAMA_HOST` names a host absent from
      `scripts/leira_config.json:hosts` (typo trap — see the design record
      mempalace drawer `design_leira_multihost_full` for the precedence
      contract). This is distinct from `OllamaCallError` — consumers using
      `catch [OllamaCallError]` for fail-open MUST add a separate
      `catch [LeiraConfigError]` clause to surface misconfig to the operator.
    #>
    [CmdletBinding()] param()
    return (_ResolveActiveHost).Name
}

function _GetBaseUrl {
    # LEGACY entry-point retained for internal callers (_Discover, Test-LeiraReachable,
    # Invoke-LeiraCall). Composes _ResolveActiveHost with LEIRA_OLLAMA_BASE_URL BC
    # override + tail-strip so callers get the API root (append /api/ps, /api/show,
    # /api/tags, /api/chat).
    $active    = _ResolveActiveHost
    $configUrl = $active.Url
    $url       = _EnvOr 'LEIRA_OLLAMA_BASE_URL' $configUrl
    # Strip trailing `/api/<endpoint>` so callers get the ROOT and can build endpoints.
    return ($url -replace '/api/[^/]+/?$', '')
}

# ---- P2 — Dynamic discovery (/api/show, cached per process) ----------------
$Script:DiscoverCallCount = 0
function _Discover {
    # Test-scope spy: T20 asserts $Script:DiscoverCallCount == 0 after an
    # Invoke-LeiraCall -HostName path, pinning that per-call HostName skips
    # module discovery (Batch-1 db-sme fold; MF-1 pre-fix bug).
    $Script:DiscoverCallCount++
    if ($Script:Discovered) { return $Script:Discovered }
    $cfg     = Get-LeiraConfig
    $baseUrl = _GetBaseUrl
    $hint    = $cfg['model']                                        # config's preferred model (hint)
    $fallbk  = [int]($cfg['context_tokens_fallback'] ?? 8192)

    # If no hint, ask /api/ps for currently-loaded models and pick first.
    $modelName = $hint
    try {
        if (-not $modelName) {
            $ps = Invoke-RestMethod -Method Get -Uri "$baseUrl/api/ps" -TimeoutSec 8
            if ($ps.models -and $ps.models.Count -gt 0) { $modelName = $ps.models[0].name }
        }
    } catch { }   # fall through — will error at /api/show below if truly unreachable

    if (-not $modelName) {
        # llm-host unreachable at discovery. Fall back to config hint OR raise.
        throw [LeiraUnavailable]::new("Cannot discover a llm-host model (no /api/ps hit, no config 'model' hint)")
    }

    try {
        $show = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/show" `
                    -ContentType 'application/json' `
                    -Body (@{ name = $modelName } | ConvertTo-Json) -TimeoutSec 8
    } catch {
        # /api/show failed — intentionally undersized fallback so a truncated payload
        # surfaces the discovery failure loudly (matches Python behavior).
        $Script:Discovered = @{ Model = $modelName; ContextTokens = $fallbk; KeepAlive = '5m'; BaseUrl = $baseUrl }
        return $Script:Discovered
    }

    $ctxTokens = 0
    if ($show.parameters -and $show.parameters.num_ctx) { $ctxTokens = [int]$show.parameters.num_ctx }
    elseif ($show.model_info) {
        # arch key varies; scan for any *.context_length
        foreach ($k in $show.model_info.PSObject.Properties.Name) {
            if ($k -like '*.context_length') { $ctxTokens = [int]$show.model_info.$k; break }
        }
    }
    if ($ctxTokens -le 0) { $ctxTokens = $fallbk }

    $keepAlive = if ($show.parameters -and $show.parameters.keep_alive) { $show.parameters.keep_alive } else { '5m' }

    $Script:Discovered = @{ Model = $modelName; ContextTokens = $ctxTokens; KeepAlive = $keepAlive; BaseUrl = $baseUrl }
    return $Script:Discovered
}

# ---- P1 — Byte budget derived from live context, not literal ---------------
function Get-LeiraContextBytes {
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [double]$Ratio,
        [int]$CharsPerToken = 4
    )
    if ($Ratio -le 0 -or $Ratio -gt 1) {
        throw [System.ArgumentException]::new("Ratio must be in (0, 1]; got $Ratio")
    }
    $d = _Discover
    return [int]($d.ContextTokens * $Ratio * $CharsPerToken)
}

# ---- P3 — Cooldown sentinel (SHARED with Python) ---------------------------
function _CooldownRemaining {
    # LEGACY: reads the GLOBAL sidecar only. Retained for backward-compat;
    # new code paths call _CooldownRemainingFor to key on host name.
    if (-not (Test-Path $Script:CooldownPath)) { return 0 }
    try {
        $until = [double](Get-Content -Raw $Script:CooldownPath).Trim()
        $now   = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $rem   = [int]($until - $now)
        if ($rem -le 0) {
            Remove-Item $Script:CooldownPath -ErrorAction SilentlyContinue
            return 0
        }
        return $rem
    } catch { return 0 }
}

function _SetCooldown {
    # LEGACY: writes the GLOBAL sidecar only. Retained for backward-compat;
    # new code paths call _SetCooldownFor to key on host name.
    param([int]$Seconds)
    $until = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $Seconds
    Set-Content -Path $Script:CooldownPath -Value ([string]$until) -Encoding utf8
}

function _SanitizeHostForPath {
    # Twin of Python _sanitize_host_for_path — preserves alphanumeric +
    # hyphen + underscore; other bytes become underscore. Prevents path
    # traversal + OS-illegal chars (colon on Windows, slash, backslash).
    # db-sme Batch-2 NTH#4 fold: empty sanitize -> '_unnamed_' so an
    # empty name never yields 'leira_cooldown..until' (double-dot).
    param([Parameter(Mandatory)] [string]$Name)
    $sanitized = -join ($Name.ToCharArray() | ForEach-Object {
        if ($_ -match '[A-Za-z0-9_-]') { $_ } else { '_' }
    })
    if ([string]::IsNullOrEmpty($sanitized)) { return '_unnamed_' }
    return $sanitized
}

function _CooldownPathFor {
    # Drive-D (2026-07-17). Per-host sidecar path: $env:TEMP/leira_cooldown.<host>.until.
    # Distinct per host so benching hosts.the ML host does NOT bench hosts.llm-host.
    # Twin of Python _cooldown_path_for.
    param([Parameter(Mandatory)] [string]$HostName)
    $safe = _SanitizeHostForPath -Name $HostName
    return (Join-Path $env:TEMP "leira_cooldown.$safe.until")
}

function _CooldownRemainingFor {
    # Drive-D (2026-07-17). Backward-compat OR: reads BOTH the per-host
    # sidecar AND the legacy GLOBAL sidecar; either being in the future
    # counts. Returns the LONGER remaining. Twin of Python _in_cooldown_for.
    param([Parameter(Mandatory)] [string]$HostName)
    $perHostPath = _CooldownPathFor -HostName $HostName
    $maxRem = 0
    $now    = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($p in @($perHostPath, $Script:CooldownPath)) {
        if (-not (Test-Path $p)) { continue }
        try {
            $until = [double](Get-Content -Raw $p).Trim()
            $rem = [int]($until - $now)
            if ($rem -gt 0) {
                if ($rem -gt $maxRem) { $maxRem = $rem }
            }
            else {
                # db-sme Batch-2 NTH#3 fold: unlink expired sidecar (mirror
                # of the legacy _CooldownRemaining cleanup). Per-host sidecars
                # otherwise accumulate one file per host name ever benched.
                Remove-Item $p -ErrorAction SilentlyContinue
            }
        } catch { }
    }
    return $maxRem
}

function _SetCooldownFor {
    # Drive-D (2026-07-17). Arm the per-host cooldown — benches ONE host,
    # leaves the others callable. Twin of Python _set_cooldown_for.
    param(
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [int]$Seconds
    )
    $until = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $Seconds
    $path  = _CooldownPathFor -HostName $HostName
    Set-Content -Path $path -Value ([string]$until) -Encoding utf8
}

# ---- P3 + P4 — the ONE call surface ---------------------------------------
function _InvokeLeiraCallOnce {
    <#
    .SYNOPSIS
      Single-shot llm-host call — one host, no failover. Twin of Python
      _call_leira_once. The public Invoke-LeiraCall orchestrates failover
      across hosts by catching LeiraUnavailable from this helper and trying
      the next host in the failover chain (Drive-E, 2026-07-17).
    .PARAMETER TaskPrompt
      The full prompt string.
    .PARAMETER Schema
      Optional hashtable = JSON schema. When set, Ollama enforces server-side (P4).
    .PARAMETER System
      Optional system message.
    .OUTPUTS
      When -Schema is set: PSCustomObject/hashtable parsed from JSON.
      When -Schema is not set: [string] raw content.
    .NOTES
      Throws [LeiraUnavailable] if cooldown is active or llm-host is unreachable.
      Throws [OllamaCallError] on non-recoverable call failure after retries.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string]$TaskPrompt,
        [hashtable]$Schema,
        [string]$System,
        # Drive-B (2026-07-17): per-call host override. When set, this call
        # resolves the named host via _ResolveHostByName + uses THAT host's
        # url/model for THIS invocation only — bypasses the module-cached
        # $Script:ActiveHost. Unknown name raises LeiraConfigError (typo trap
        # symmetric with the OLLAMA_HOST env-driven path). Twin of Python
        # `call_leira(host=<name>)`. `-HostName` (not `-Host`) avoids clash
        # with the PowerShell automatic `$Host` variable.
        [string]$HostName
    )

    # Drive-D per-host cooldown gate — resolved AFTER _ResolveHostByName below
    # (Drive-B fold sequence: typo trap first, then cooldown check on the
    # RESOLVED host). Kept as a placeholder; the actual check runs post-
    # resolution to key on the correct host name.

    $cfg          = Get-LeiraConfig
    $maxRetries   = [int](_EnvOr 'LEIRA_MAX_RETRIES'   ($cfg['max_retries']   ?? 3))
    $baseBackoff  = [double](_EnvOr 'LEIRA_BASE_BACKOFF_S' ($cfg['base_backoff_s'] ?? 1.0))
    # Config-key parity with leira_config.json + leira_prepass.py:
    #   cooldown_on_fail_s (JSON L19, py L297) — NOT `cooldown_s`
    #   timeout_s          (JSON L15, py L102) — NOT `call_timeout_s`
    # The previous names silently fell through to hardcoded defaults; config tuning
    # was inert. Env-var names (LEIRA_COOLDOWN_S / LEIRA_CALL_TIMEOUT_S) are kept
    # as-declared in this module's docstring.
    $cooldownOnFail = [int](_EnvOr 'LEIRA_COOLDOWN_S' ($cfg['cooldown_on_fail_s'] ?? 300))
    $callTimeout  = [int](_EnvOr 'LEIRA_CALL_TIMEOUT_S' ($cfg['timeout_s'] ?? 180))

    # Drive-B (Batch-1 SME fold, 2026-07-17): per-call host resolution +
    # discovery gating. Two MFs from db-sme forced the restructure below:
    #   MF-1: `_Discover` was called unconditionally + reads the MODULE
    #         active host — an unreachable module host blocked a valid
    #         `-HostName` escape hatch with `LeiraUnavailable`, killing
    #         the exact failover Drive-B was supposed to enable.
    #   MF-2: `num_ctx` sourced from `$d.ContextTokens` (module discovery)
    #         on the `-HostName` path — wrong context window when the
    #         per-call host serves a different model.
    # Fold: skip `_Discover` on `-HostName` path; use the per-call host's
    # ContextTokensFallback + KeepAlive-less body (defaults are fine for
    # the ad-hoc use case). Python twin parity: `call_leira(host=...)`
    # never calls the discovery helpers.
    $keepAlive = '5m'
    if ($HostName) {
        $callHost              = _ResolveHostByName -Name $HostName
        $callChatUrl           = $callHost.Url
        $effectiveModel        = $callHost.Model
        $effectiveContextTokens = [int]$callHost.ContextTokensFallback
    } else {
        $d = _Discover     # may throw LeiraUnavailable — only when NOT overriding
        $callHost              = _ResolveActiveHost
        $callChatUrl           = "$($d.BaseUrl)/api/chat"
        $effectiveModel        = $d.Model
        $effectiveContextTokens = [int]$d.ContextTokens
        $keepAlive             = $d.KeepAlive
    }

    # Drive-D (2026-07-17): per-host cooldown check keyed on the RESOLVED
    # host. Reads the per-host sidecar OR the legacy GLOBAL sidecar (backward-
    # compat "all benched" signal). A sibling host in cooldown does NOT block
    # us — the entire point of per-host scoping. Twin of Python
    # _in_cooldown_for at call_leira (Drive-D fold).
    $perHostCooldown = _CooldownRemainingFor -HostName $callHost.Name
    if ($perHostCooldown -gt 0) {
        throw [LeiraUnavailable]::new(
            "llm-host host=$($callHost.Name) in cooldown for ${perHostCooldown}s more " +
            "(per-host sidecar: $(_CooldownPathFor -HostName $callHost.Name); " +
            "legacy global: $($Script:CooldownPath))"
        )
    }

    $messages = @()
    if ($System) { $messages += @{ role = 'system'; content = $System } }
    $messages += @{ role = 'user'; content = $TaskPrompt }

    $body = @{
        model    = $effectiveModel
        messages = $messages
        stream   = $false
        options  = @{ num_ctx = $effectiveContextTokens }
    }
    if ($Schema) { $body.format = $Schema }

    $lastErr = $null
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $resp = Invoke-RestMethod -Method Post -Uri $callChatUrl `
                        -ContentType 'application/json' `
                        -Body ($body | ConvertTo-Json -Depth 12 -Compress) `
                        -TimeoutSec $callTimeout
            $content = $resp.message.content
            if ($Schema) {
                try {
                    $parsed = ($content | ConvertFrom-Json -AsHashtable)
                    # Python parity — inject _leira_meta with active_host for
                    # audit reproducibility (drawer §active_host_name).
                    $parsed['_leira_meta'] = @{
                        model       = $effectiveModel
                        active_host = $callHost.Name
                    }
                    return $parsed
                }
                catch {
                    # schema-shape violation on the model's side. Treat as retryable once.
                    $lastErr = "schema parse failure: $($_.Exception.Message)"
                    Start-Sleep -Seconds ([int]($baseBackoff * [Math]::Pow(2, $attempt - 1)))
                    continue
                }
            }
            return $content
        } catch {
            $lastErr = $_.Exception.Message
            if ($attempt -lt $maxRetries) {
                $delay = [int]($baseBackoff * [Math]::Pow(2, $attempt - 1))
                Start-Sleep -Seconds $delay
                continue
            }
            # Drive-D (2026-07-17): exhausted retries — arm the PER-HOST
            # cooldown so subsequent calls targeting THIS host no-op cleanly
            # while sibling hosts remain callable. Python parity:
            # _set_cooldown_for(_call_host['name'], ...).
            _SetCooldownFor -HostName $callHost.Name -Seconds $cooldownOnFail
            throw [LeiraUnavailable]::new("llm-host host=$($callHost.Name) call failed after $maxRetries attempts: $lastErr; per-host cooldown engaged")
        }
    }
}

$Script:RotationCounter = 0
$Script:RotationSidecarPath = Join-Path $env:TEMP 'leira_rotation.next'
$Script:ValidStrategies = @('primary', 'round_robin', 'weighted')

function _LoadRotationCounter {
    # Punch  (2026-07-17) — twin of Python _load_rotation_counter.
    # Returns the persisted int or $null on absent / malformed / unreadable.
    if (-not (Test-Path $Script:RotationSidecarPath)) { return $null }
    try {
        return [int](Get-Content -Raw $Script:RotationSidecarPath).Trim()
    } catch { return $null }
}

function _PersistRotationCounter {
    # Twin of Python _persist_rotation_counter. Fail-silent on IO error.
    param([Parameter(Mandatory)] [int]$Value)
    try {
        Set-Content -Path $Script:RotationSidecarPath -Value ([string]$Value) -Encoding utf8
    } catch { }
}
$Script:BadStrategySeen = @{}

function _WarnOnceBadStrategy {
    # hipaa-sme Batch-3 NTH-1 fold — twin of Python _warn_once_bad_strategy.
    # One-shot Write-Warning per unknown strategy value seen this process.
    param([string]$Value)
    if ($Script:BadStrategySeen.ContainsKey($Value)) { return }
    $Script:BadStrategySeen[$Value] = $true
    $valid = ($Script:ValidStrategies -join ', ')
    Write-Warning "leira_prepass: unknown strategy '$Value', defaulting to 'primary' (valid: $valid)"
}

function _BuildRotationPool {
    # Drive-F (2026-07-17) — twin of Python _build_rotation_pool.
    # 'round_robin' yields each host name once (sorted). 'weighted' yields
    # each host `entry.weight` times (default 1). 'primary' returns empty.
    param([Parameter(Mandatory)] [string]$Strategy)
    $cfg      = Get-LeiraConfig
    $hostsMap = $cfg['hosts'] ?? @{}
    $names    = @($hostsMap.Keys | Sort-Object)
    if ($Strategy -eq 'round_robin') { return $names }
    if ($Strategy -eq 'weighted') {
        $pool = @()
        foreach ($n in $names) {
            $entry = $hostsMap[$n] ?? @{}
            $w = 1
            try {
                $rawWeight = $entry['weight']
                if ($null -ne $rawWeight) { $w = [Math]::Max(1, [int]$rawWeight) }
            } catch { $w = 1 }
            for ($i = 0; $i -lt $w; $i++) { $pool += $n }
        }
        return $pool
    }
    return @()
}

function _ResolveConsumerHost {
    # Drive-G (2026-07-17). Twin of Python _resolve_consumer_host. Returns
    # the affinity host name for the named consumer if configured; otherwise
    # $null. Absent consumer sections are LEGAL; unknown host names are
    # caught by _ResolveHostByName downstream and surface as LeiraConfigError.
    # db-sme Batch-3 NTH-2 fold: type-guard the host field. PowerShell
    # implicit-stringifies non-string values (int, array), and a stringified
    # 'System.Object[]' would then bubble to LeiraConfigError — diverging
    # from the Python twin's silent None-fallthrough. Both are fail-closed
    # but the surface differed; the guard makes them symmetric.
    param([Parameter(Mandatory)] [string]$Consumer)
    $cfg = Get-LeiraConfig
    $section = $cfg[$Consumer]
    if (-not $section -or -not ($section -is [hashtable])) { return $null }
    $h = $section['host']
    if (-not ($h -is [string])) { return $null }
    if ([string]::IsNullOrWhiteSpace($h)) { return $null }
    return $h
}

function _NextHostByStrategy {
    # Drive-F (2026-07-17) — twin of Python _next_host_by_strategy.
    # Returns $null for 'primary' or empty pool; otherwise advances
    # $Script:RotationCounter modulo pool size, skipping cooldown'd hosts.
    # When every candidate is benched, returns pool[0] anyway so the caller
    # can propagate a clean LeiraUnavailable rather than looping forever.
    # db-sme Batch-3 NTH-1 fold: guard against Int32 overflow — PS `++` at
    # Int32.MaxValue silently wraps to MinValue giving a NEGATIVE index into
    # the pool (which PS legally treats as a from-end index — order flip).
    # Reset to 0 when nearing the ceiling. Python twin uses arbitrary-
    # precision int so this is a PS-only guard.
    param([Parameter(Mandatory)] [string]$Strategy)
    $pool = _BuildRotationPool -Strategy $Strategy
    if (-not $pool -or $pool.Count -eq 0) { return $null }
    if ($Script:RotationCounter -ge ([int]::MaxValue - 1000)) {
        $Script:RotationCounter = 0
    }
    # Punch : load persisted counter (cross-language sync) so a mixed
    # Py+PS caller sees a SHARED cursor. Fail-open on read errors.
    $persisted = _LoadRotationCounter
    if ($null -ne $persisted) { $Script:RotationCounter = $persisted }
    $n = $pool.Count
    for ($i = 0; $i -lt $n; $i++) {
        $idx = $Script:RotationCounter % $n
        $Script:RotationCounter++
        _PersistRotationCounter -Value $Script:RotationCounter
        $candidate = $pool[$idx]
        if ((_CooldownRemainingFor -HostName $candidate) -eq 0) { return $candidate }
    }
    return $pool[0]
}

function Invoke-LeiraCall {
    <#
    .SYNOPSIS
      Call llm-host with optional cross-host failover (Drive-E, 2026-07-17).
    .DESCRIPTION
      Twin of Python `call_leira`. When -FailoverHosts (or
      `config.failover_hosts`) is set, iterates a chain
      [primary, ...failoverHosts] with duplicates removed and calls
      _InvokeLeiraCallOnce for each. A LeiraUnavailable from one host causes
      the orchestrator to try the next; a LeiraConfigError (typo trap)
      bubbles immediately.
    .PARAMETER TaskPrompt
      The full prompt string.
    .PARAMETER Schema
      Optional hashtable = JSON schema. When set, Ollama enforces server-side (P4).
    .PARAMETER System
      Optional system message.
    .PARAMETER HostName
      Pin the PRIMARY host for this call (Drive-B). Unknown name raises
      LeiraConfigError. When empty, the module-resolved active host is used.
    .PARAMETER FailoverHosts
      Ordered list of host names to try if the primary fails. When empty,
      sources from `config.failover_hosts` (empty list means "no failover"
      = pre-Drive-E behaviour).
    .PARAMETER Strategy
      Rotation strategy for primary-host selection (Drive-F, 2026-07-17).
      One of 'primary' (default; pre-Drive-F behaviour), 'round_robin' (each
      configured host in turn), or 'weighted' (each host repeated
      hosts.<name>.weight times, default 1). Per-call value wins over
      config.strategy. Only fires when -HostName + -Consumer do not already
      pin one. Rotation counter is process-scope; twin counters
      (Python + PS) are independent by design — see design_leira_multihost_full
      drawer for cross-twin drift semantics.
    .PARAMETER Consumer
      Name of a consumer section (e.g. 'census_prepass', 'verify_prepass') —
      Drive-G per-consumer host affinity. When the section carries a `host`
      field, that value becomes the primary. Wins over -Strategy but loses
      to explicit -HostName. A consumer-pinned host still respects cooldown;
      pair with -FailoverHosts for resilience.
    .OUTPUTS
      Same shape as _InvokeLeiraCallOnce. When failover triggered (a
      non-primary host served), the returned hashtable (schema mode) grows
      _leira_meta.failover_chain listing the hosts tried in order.
    .NOTES
      Throws [LeiraConfigError] if any name in the chain is unknown.
      Throws [LeiraUnavailable] if every host in the chain fails.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)] [string]$TaskPrompt,
        [hashtable]$Schema,
        [string]$System,
        [string]$HostName,
        [string[]]$FailoverHosts,
        # Drive-F (2026-07-17): rotation strategy for primary host selection.
        # 'primary' (default) uses the module-resolved active host. 'round_robin'
        # rotates across all configured hosts. 'weighted' rotates by
        # hosts.<name>.weight (default 1). Only fires when -HostName is not
        # pinned. Per-call value wins over config.strategy.
        [ValidateSet('', 'primary', 'round_robin', 'weighted')]
        [string]$Strategy = '',
        # Drive-G (2026-07-17): per-consumer host affinity. Name of a
        # consumer section (e.g. 'census_prepass', 'verify_prepass'). When
        # set + the section carries a `host` field, that becomes the primary
        # unless -HostName is pinned. Twin of Python call_leira(consumer=<name>).
        [string]$Consumer
    )

    $cfg = Get-LeiraConfig
    if ($null -eq $FailoverHosts) {
        $configFailover = $cfg['failover_hosts']
        $FailoverHosts = @(if ($null -ne $configFailover) { $configFailover })
    }

    # Drive-G (2026-07-17): per-consumer host affinity. Runs BEFORE strategy
    # so a consumer-pinned host is not overwritten by round-robin/weighted.
    if (-not $HostName -and $Consumer) {
        $consumerHost = _ResolveConsumerHost -Consumer $Consumer
        if ($consumerHost) { $HostName = $consumerHost }
    }

    # Drive-F strategy resolution — per-call wins, then config, then default.
    $effectiveStrategy = if ($Strategy) { $Strategy } else { ($cfg['strategy'] ?? 'primary') }
    if ($Script:ValidStrategies -notcontains $effectiveStrategy) {
        # hipaa-sme Batch-3 NTH-1 fold: warn once/process on unknown strategy.
        _WarnOnceBadStrategy -Value $effectiveStrategy
        $effectiveStrategy = 'primary'
    }
    if (-not $HostName -and $effectiveStrategy -in @('round_robin', 'weighted')) {
        $picked = _NextHostByStrategy -Strategy $effectiveStrategy
        if ($picked) { $HostName = $picked }
    }

    if (-not $FailoverHosts -or $FailoverHosts.Count -eq 0) {
        # Pre-Drive-E behavior — one host, one try.
        if ($HostName) {
            return _InvokeLeiraCallOnce -TaskPrompt $TaskPrompt -Schema $Schema -System $System -HostName $HostName
        }
        return _InvokeLeiraCallOnce -TaskPrompt $TaskPrompt -Schema $Schema -System $System
    }

    # Failover path — build ordered chain [primary, ...failover] dedup'd.
    $primaryName = if ($HostName) { $HostName } else { (_ResolveActiveHost).Name }
    $chain = @($primaryName)
    foreach ($fh in $FailoverHosts) {
        if ($chain -notcontains $fh) { $chain += $fh }
    }

    $lastErr = $null
    for ($i = 0; $i -lt $chain.Count; $i++) {
        $h = $chain[$i]
        try {
            $result = _InvokeLeiraCallOnce -TaskPrompt $TaskPrompt -Schema $Schema -System $System -HostName $h
            if ($Schema -and $i -gt 0 -and $result -is [hashtable]) {
                # Failover fired — record the actual traversal for audit.
                if (-not $result.ContainsKey('_leira_meta')) { $result['_leira_meta'] = @{} }
                $result['_leira_meta']['failover_chain'] = @($chain[0..$i])
            }
            return $result
        }
        catch [LeiraUnavailable] {
            $lastErr = $_.Exception.Message
            continue
        }
    }
    throw [LeiraUnavailable]::new("llm-host all $($chain.Count) hosts exhausted (chain=$($chain -join ', ')); last error: $lastErr")
}

function Get-LeiraHealthcheck {
    <#
    .SYNOPSIS
      Twin of Python `leira_healthcheck` — probe /api/tags on EVERY host in
      scripts/leira_config.json:hosts. Strictly informational; no cooldown
      side-effects, no auto-routing.
    .PARAMETER TimeoutSec
      Per-probe timeout in seconds (default 4).
    .OUTPUTS
      Array of hashtables, sorted by host name for deterministic ordering:
        @{ Name; Url; Reachable; LatencyMs; ModelCount; Error }
      Reachable=$false + Error=<string> when the probe fails; the loop
      continues past a bad host.
    .NOTES
      Drive-C landing (2026-07-17). Failover / preferred-alternate selection
      landed in Drive-E (2026-07-17); healthcheck itself remains
      informational and does not auto-route.
    #>
    [CmdletBinding()] param([int]$TimeoutSec = 4)
    $cfg      = Get-LeiraConfig
    $hostsMap = $cfg['hosts'] ?? @{}
    $results  = @()
    foreach ($name in ($hostsMap.Keys | Sort-Object)) {
        $entry   = $hostsMap[$name] ?? @{}
        $chatUrl = $entry['url'] ?? $cfg['url'] ?? 'http://llm-host:11434/api/chat'
        $base    = ($chatUrl -replace '/api/[^/]+/?$', '')
        $tagsUrl = "$base/api/tags"
        $sw      = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $data = Invoke-RestMethod -Method Get -Uri $tagsUrl -TimeoutSec $TimeoutSec
            $sw.Stop()
            $modelCount = if ($null -ne $data.models) { @($data.models).Count } else { 0 }
            $results += @{
                Name       = $name
                Url        = $chatUrl
                Reachable  = $true
                LatencyMs  = [int]$sw.ElapsedMilliseconds
                ModelCount = $modelCount
                Error      = $null
            }
        }
        catch {
            $sw.Stop()
            $msg = $_.Exception.Message
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
            $results += @{
                Name       = $name
                Url        = $chatUrl
                Reachable  = $false
                LatencyMs  = [int]$sw.ElapsedMilliseconds
                ModelCount = $null
                Error      = $msg
            }
        }
    }
    return , $results
}

# ---- Small utility — probe reachability without consuming a real call ------
function Test-LeiraReachable {
    [CmdletBinding()] param()
    if ((_CooldownRemaining) -gt 0) { return $false }
    try {
        $baseUrl = _GetBaseUrl
        Invoke-RestMethod -Method Get -Uri "$baseUrl/api/tags" -TimeoutSec 4 | Out-Null
        return $true
    } catch { return $false }
}

Export-ModuleMember -Function `
    Get-LeiraConfig, Get-LeiraConsumerConfig, Get-LeiraContextBytes, `
    Invoke-LeiraCall, Test-LeiraReachable, Get-LeiraActiveHost, `
    Get-LeiraHealthcheck
