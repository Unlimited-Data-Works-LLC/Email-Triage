#Requires -Version 7.0
<#
.SYNOPSIS
  Pester teeth-tests for the PowerShell llm-host offload stack.
  Mirrors tests/test_leira_consumers_scaffold.py (Python) — Pillar 6 of
  `pattern_leira_offload_stack`.

.DESCRIPTION
  Guarantees:
    T1  scripts/leira_prepass.psm1 parses + imports + exports the 5 functions.
    T2  Every PS consumer under scripts/leira_*.ps1 parses + declares Import-Module
        of leira_prepass.psm1 (helper wiring holds).
    T3  Every PS consumer's docstring pins the HIPAA-at-callsite contract.
    T4  DRIFT GUARD: a new scripts/leira_*.ps1 not in $AllPsConsumers below fails-red.
        (This closes the "silent scaffold" hole for PS consumers.)

.NOTES
  - Pester 5+ REQUIRED. Verified 2026-07-17 with Pester 6.0.0 at
    C:\Users\ExampleUser\Documents\PowerShell\Modules\Pester\6.0.0. Install/upgrade:
      Install-Module Pester -Scope CurrentUser -MinimumVersion 5.5.0 -Force -SkipPublisherCheck
  - Run:  Invoke-Pester -Path tests/leira_ps_consumers_scaffold.Tests.ps1 -Output Detailed
  - LIVE llm-host calls are NOT exercised here (they would need a network + running qwen model).
    A separate opt-in integration file lives at tests/integration/leira_live.Tests.ps1 when needed.
  - pwsh 7 ONLY (feedback_use_pwsh7_not_ps51).
#>

BeforeDiscovery {
    # DISCOVERY-TIME: only what -ForEach needs. These do NOT survive into It blocks in Pester 5+.
    $repoRoot   = Split-Path -Parent $PSScriptRoot
    $scriptsDir = Join-Path $repoRoot 'scripts'
    $Script:DiscoveredConsumers = @(
        if (Test-Path $scriptsDir) {
            Get-ChildItem -Path $scriptsDir -Filter 'leira_*.ps1' -File `
                -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        }
    )
}

BeforeAll {
    # EXECUTION-TIME: what It blocks read via $Script:*.
    $Script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $Script:ScriptsDir = Join-Path $Script:RepoRoot 'scripts'
    $Script:ModulePath = Join-Path $Script:ScriptsDir 'leira_prepass.psm1'

    # ---- DRIFT-GUARD allowlist ---------------------------------------------
    # Add every new scripts/leira_*.ps1 to this list. A new file that isn't here
    # will fail T4. This is the SAME contract as Python's `_CONSUMERS_YYYY_MM_DD`.
    $Script:AllPsConsumers = @(
        # Format: '<basename>.ps1'  (path relative to scripts/)
        # 2026-07 block — no PS consumers yet; module ships, consumers land later.
    )

    $Script:DiscoveredConsumers = @(
        if (Test-Path $Script:ScriptsDir) {
            Get-ChildItem -Path $Script:ScriptsDir -Filter 'leira_*.ps1' -File `
                -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        }
    )
}

Describe 'T1 — leira_prepass.psm1 wiring' {
    It 'parses without errors' {
        $errs = $null
        [void][System.Management.Automation.PSParser]::Tokenize(
            (Get-Content -Raw $Script:ModulePath), [ref]$errs)
        $errs | Should -BeNullOrEmpty
    }

    It 'imports cleanly' {
        { Import-Module $Script:ModulePath -Force -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports the 7 required functions' {
        Import-Module $Script:ModulePath -Force
        # 2026-07-17 multi-host: Get-LeiraActiveHost joined the exported
        # surface (PS twin of Python active_host_name L141). Drive-C added
        # Get-LeiraHealthcheck (7th) — twin of Python leira_healthcheck.
        $expected = @(
            'Get-LeiraConfig',
            'Get-LeiraConsumerConfig',
            'Get-LeiraContextBytes',
            'Invoke-LeiraCall',
            'Test-LeiraReachable',
            'Get-LeiraActiveHost',
            'Get-LeiraHealthcheck'
        )
        $mod = Get-Module -Name 'leira_prepass'
        $mod | Should -Not -BeNullOrEmpty
        foreach ($fn in $expected) {
            $mod.ExportedFunctions.Keys | Should -Contain $fn
        }
    }

    It 'T5 — LeiraUnavailable IS-A OllamaCallError (inheritance contract)' {
        # Pin for the 2026-07-17 bug where LeiraUnavailable inherited System.Exception
        # instead of OllamaCallError; consumers doing `catch [OllamaCallError]` missed
        # every unavailable throw (docstring L26-30 contract broken).
        # Types defined inside a module are NOT visible in the outer scope after
        # Import-Module; reach them by invoking a scriptblock inside the module's
        # session state (the same trick Pester uses for InModuleScope).
        $mod  = Import-Module $Script:ModulePath -Force -PassThru
        $lu   = & $mod { [LeiraUnavailable] }
        $oce  = & $mod { [OllamaCallError] }
        $lu  | Should -Not -BeNullOrEmpty
        $oce | Should -Not -BeNullOrEmpty
        $lu.IsSubclassOf($oce) | Should -BeTrue -Because 'LeiraUnavailable must subclass OllamaCallError so consumers can catch both with one clause'
    }

    It 'T6 — Get-LeiraConsumerConfig returns a non-empty section for census_prepass' {
        # Pin for the 2026-07-17 bug where Get-LeiraConsumerConfig read a nonexistent
        # $cfg[''consumers''] wrapper — consumer sections sit at the TOP level of
        # leira_config.json. A silent {} return then falls through to hardcoded
        # defaults + defeats config tuning.
        Import-Module $Script:ModulePath -Force
        $section = Get-LeiraConsumerConfig -Name 'census_prepass'
        $section | Should -Not -BeNullOrEmpty
        $section.Count | Should -BeGreaterThan 0
        $section.ContainsKey('context_usage_ratio') | Should -BeTrue
    }

    It 'T7 — every $cfg[literal] key in leira_prepass.psm1 exists in leira_config.json (drift pin, count-agnostic)' {
        # Directive #1 pin (project_style_guide): SSOT ships a count-agnostic
        # STRUCTURAL pin. Property test — scan the module for every literal
        # $cfg[''key''] access and assert every extracted key resolves to a
        # real leira_config.json entry (or an explicit doc''d allowlist).
        # This closes the "silent-fallback-to-defaults" drift class the 3
        # config-key bugs (cooldown_s / call_timeout_s / ollama_base_url)
        # were instances of. Future edits cannot silently reintroduce it.
        $psm1Text   = Get-Content -Raw $Script:ModulePath
        $configPath = Join-Path $Script:ScriptsDir 'leira_config.json'
        $configHash = Get-Content -Raw $configPath | ConvertFrom-Json -AsHashtable
        $configKeys = @($configHash.Keys)

        # Extract every $cfg['key'] / $cfg["key"] literal access from the module.
        $rx      = [regex]'\$cfg\[[''"]([A-Za-z_][A-Za-z0-9_]*)[''"]\]'
        $matches = $rx.Matches($psm1Text)
        $keys    = @($matches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $keys.Count | Should -BeGreaterThan 0 -Because 'the module should have at least one $cfg[''...''] literal access; if zero, regex or module drifted'

        # Explicit allowlist — keys that legitimately do NOT appear in
        # leira_config.json at this file's snapshot (e.g. keys read from a
        # nested hosts.<name> entry, or documented env-only knobs). Extend only
        # with a CITED reason. Empty for now.
        $allowlist = @()

        $unknown = @($keys | Where-Object { ($_ -notin $configKeys) -and ($_ -notin $allowlist) })
        $unknown | Should -BeNullOrEmpty -Because "each `$cfg[literal] must resolve to a real leira_config.json key (or be doc''d in `$allowlist). Silent-fallback-to-defaults drift class. Offending keys: $($unknown -join ', ')"
    }
}

Describe 'T8-T12 — multi-host resolution (design_leira_multihost_full)' {
    BeforeAll {
        # Preserve caller env — each It restores what it clobbered. Some CI envs
        # already set OLLAMA_HOST / LEIRA_URL; a leaked assignment across Its
        # would silently pass or corrupt a downstream test.
        $Script:SavedOllamaHost = $env:OLLAMA_HOST
        $Script:SavedLeiraUrl   = $env:LEIRA_URL
        $Script:SavedOllamaUrl  = $env:OLLAMA_URL
        $Script:SavedBaseUrl    = $env:LEIRA_OLLAMA_BASE_URL
    }
    AfterAll {
        # db-sme Drive NTH#3: wrap the 4 restores in a try/finally so a
        # Pester-runtime crash between BeforeAll and AfterAll doesn't leak
        # env vars to sibling Describes / the parent shell. Each restore is
        # its own try so one failure doesn't skip the remaining three.
        try { $env:OLLAMA_HOST           = $Script:SavedOllamaHost } catch { }
        try { $env:LEIRA_URL             = $Script:SavedLeiraUrl   } catch { }
        try { $env:OLLAMA_URL            = $Script:SavedOllamaUrl  } catch { }
        try { $env:LEIRA_OLLAMA_BASE_URL = $Script:SavedBaseUrl    } catch { }
    }

    It 'T8 — Get-LeiraActiveHost returns the default host name when no env set' {
        # Cache-invalidate + null-out relevant env so we're testing the config path.
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        Get-LeiraActiveHost | Should -Be 'llm-host'
    }

    It 'T9 — OLLAMA_HOST=llm-host routes explicitly to hosts.llm-host' {
        $env:OLLAMA_HOST = 'llm-host'; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        Get-LeiraActiveHost | Should -Be 'llm-host'
    }

    It 'T10 — OLLAMA_HOST=<unknown> raises LeiraConfigError (typo trap; Python parity)' {
        # The core multi-host contract: an EXPLICIT env naming an unknown host
        # MUST NOT silently return the default host. The Python side raises
        # LeiraConfigError; PS parity requires the same behavior via the twin
        # exception. Caveat: types defined inside a module are only reachable
        # via `& $module { ... }` (T5 pattern) — a bare `catch [LeiraConfigError]`
        # would not resolve the name in the outer scope.
        $env:OLLAMA_HOST = 'the ML host'; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        { Get-LeiraActiveHost } | Should -Throw
        # Verify the exception class-name is LeiraConfigError (not OllamaCallError
        # or LeiraUnavailable — those signal call-time failures, not misconfig).
        try {
            Get-LeiraActiveHost
            throw 'expected LeiraConfigError but no exception raised'
        }
        catch {
            $_.Exception.GetType().Name | Should -Be 'LeiraConfigError'
            $_.Exception.Message | Should -Match "OLLAMA_HOST='the ML host'"
            $_.Exception.Message | Should -Match 'known: \[llm-host\]'
        }
    }

    It 'T11 — LEIRA_URL env override bypasses the hosts map (raw URL path)' {
        $env:OLLAMA_HOST = $null; $env:OLLAMA_URL = $null
        $env:LEIRA_URL   = 'http://ad-hoc-host:11434/api/chat'
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        Get-LeiraActiveHost | Should -Be '<env-url>'
    }

    It 'T12 — OLLAMA_URL env override bypasses the hosts map (LEIRA_URL parity)' {
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null
        $env:OLLAMA_URL  = 'http://another-adhoc:11434/api/chat'
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        Get-LeiraActiveHost | Should -Be '<env-url>'
    }

    It 'T13 — LeiraConfigError IS-A System.Exception + distinct from OllamaCallError' {
        # Startup-time misconfig is a distinct class from call-time failure so
        # consumers can differentiate `catch [LeiraConfigError]` (fix env/config
        # and re-run) from `catch [OllamaCallError]` (retry / fail-open). Assert
        # both class-defined-ness and non-inheritance from OllamaCallError.
        $mod  = Import-Module $Script:ModulePath -Force -PassThru
        $lce  = & $mod { [LeiraConfigError] }
        $oce  = & $mod { [OllamaCallError] }
        $lce  | Should -Not -BeNullOrEmpty
        $lce.IsSubclassOf([System.Exception]) | Should -BeTrue
        $lce.IsSubclassOf($oce) | Should -BeFalse -Because 'LeiraConfigError must NOT subclass OllamaCallError — startup misconfig is a distinct class from call-time failure'
    }
}

Describe 'T14-T16 — per-call host arg (Drive-B, 2026-07-17)' {
    # PS twin of Python `call_leira(host=<name>)`. Contract: unknown host
    # name raises LeiraConfigError BEFORE any HTTP; known name resolves via
    # _ResolveHostByName + routes to that host's URL.
    BeforeAll {
        $Script:SavedOllamaHost = $env:OLLAMA_HOST
        $Script:SavedLeiraUrl   = $env:LEIRA_URL
        $Script:SavedOllamaUrl  = $env:OLLAMA_URL
    }
    AfterAll {
        try { $env:OLLAMA_HOST = $Script:SavedOllamaHost } catch { }
        try { $env:LEIRA_URL   = $Script:SavedLeiraUrl   } catch { }
        try { $env:OLLAMA_URL  = $Script:SavedOllamaUrl  } catch { }
    }

    It 'T14 — _ResolveHostByName known name returns the hosts.<name> entry' {
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        $entry = & $mod { _ResolveHostByName -Name 'llm-host' }
        $entry.Name | Should -Be 'llm-host'
        $entry.Url  | Should -Match '/api/chat$'
    }

    It 'T15 — _ResolveHostByName unknown name raises LeiraConfigError (typo trap)' {
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        $threw = $false
        $thrownType = $null
        $thrownMsg = $null
        try {
            & $mod { _ResolveHostByName -Name 'the ML host' }
        }
        catch {
            $threw = $true
            $thrownType = $_.Exception.GetType().Name
            $thrownMsg = $_.Exception.Message
        }
        $threw | Should -BeTrue
        $thrownType | Should -Be 'LeiraConfigError'
        $thrownMsg | Should -BeLike "*'the ML host'*"
        $thrownMsg | Should -BeLike "*known:*"
    }

    It 'T20 — Invoke-LeiraCall -HostName <known> skips _Discover (db-sme MF-1 fold)' {
        # db-sme MF-1: -HostName path was calling _Discover unconditionally
        # → an unreachable MODULE host blocked a valid -HostName escape hatch
        # with LeiraUnavailable. Fold gates _Discover behind (-not $HostName);
        # this test pins the contract via the $DiscoverCallCount spy.
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        # Bound the failing call to a couple seconds so the retry loop doesn't
        # dominate test wall-clock (real llm-host not reachable in tests).
        $env:LEIRA_MAX_RETRIES = '1'
        $env:LEIRA_CALL_TIMEOUT_S = '1'
        $env:LEIRA_BASE_BACKOFF_S = '0'
        try {
            $mod = Import-Module $Script:ModulePath -Force -PassThru
            & $mod { $Script:ActiveHost = $null; $Script:Discovered = $null; $Script:DiscoverCallCount = 0 }
            # Wipe cooldown so we start fresh.
            $cd = Join-Path $env:TEMP 'leira_cooldown.until'
            if (Test-Path $cd) { Remove-Item $cd -Force }
            try {
                Invoke-LeiraCall -TaskPrompt 'hi' -HostName 'llm-host' | Out-Null
            }
            catch {
                # Real llm-host not up in test env — call is expected to fail
                # via retry-loop exhaustion; the pin is on the spy count.
            }
            $count = & $mod { $Script:DiscoverCallCount }
            $count | Should -Be 0 -Because '-HostName path must NOT call _Discover (db-sme MF-1); an unreachable module host would otherwise block a valid per-call HostName failover'
        }
        finally {
            $env:LEIRA_MAX_RETRIES   = $null
            $env:LEIRA_CALL_TIMEOUT_S = $null
            $env:LEIRA_BASE_BACKOFF_S = $null
        }
    }

    It 'T16 — Invoke-LeiraCall -HostName ''the ML host'' throws LeiraConfigError (unknown host)' {
        # Per-call route: unknown -HostName bubbles LeiraConfigError immediately
        # (via _ResolveHostByName) — NO HTTP is attempted, so this test needs
        # no live Ollama. Contract: distinct from LeiraUnavailable so consumers
        # can differentiate misconfig from call failure.
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        $mod = Import-Module $Script:ModulePath -Force -PassThru
        & $mod { $Script:ActiveHost = $null }
        # Wipe any stale cooldown so we're not short-circuited by _CooldownRemaining
        # before we reach _ResolveHostByName.
        $cd = Join-Path $env:TEMP 'leira_cooldown.until'
        if (Test-Path $cd) { Remove-Item $cd -Force }
        $threw = $false
        $thrownType = $null
        try {
            Invoke-LeiraCall -TaskPrompt 'hi' -HostName 'the ML host' | Out-Null
        }
        catch {
            $threw = $true
            $thrownType = $_.Exception.GetType().Name
        }
        $threw | Should -BeTrue
        $thrownType | Should -Be 'LeiraConfigError' -Because 'Invoke-LeiraCall -HostName <unknown> must raise LeiraConfigError before HTTP; got a different class'
    }
}

Describe 'T35-T38 — per-consumer host affinity (Drive-G, 2026-07-17)' {
    # PS twin of Python _resolve_consumer_host + call_leira consumer= kwarg.
    BeforeEach {
        Import-Module $Script:ModulePath -Force
    }

    It 'T35 — unknown consumer name returns $null (legal)' {
        InModuleScope leira_prepass {
            _ResolveConsumerHost -Consumer 'nonexistent' | Should -BeNullOrEmpty
        }
    }

    It 'T36 — consumer section without host field returns $null' {
        InModuleScope leira_prepass {
            _ResolveConsumerHost -Consumer 'census_prepass' | Should -BeNullOrEmpty
        }
    }

    It 'T37 — consumer with host field returns that host' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                my_consumer = @{ host = 'llm-host' }
            }
            _ResolveConsumerHost -Consumer 'my_consumer' | Should -Be 'llm-host'
        }
    }

    It 'T38 — Consumer affinity routes call + explicit -HostName + strategy override precedence' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                }
                verify_prepass = @{ host = 'consumer_pinned' }
            }
            $Script:RotationCounter = 0
            $script:seenHost = $null
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:seenHost = $HostName
                return @{ ok = $true }
            }

            # Case A: -Consumer only -> uses consumer.host
            Invoke-LeiraCall -TaskPrompt 'hi' -Consumer 'verify_prepass' | Out-Null
            $script:seenHost | Should -Be 'consumer_pinned' -Because '-Consumer must route to consumer.host'

            # Case B: -HostName + -Consumer -> HostName wins
            Invoke-LeiraCall -TaskPrompt 'hi' -HostName 'explicit' -Consumer 'verify_prepass' | Out-Null
            $script:seenHost | Should -Be 'explicit' -Because '-HostName must win over -Consumer'

            # Case C: -Consumer + -Strategy -> Consumer wins over strategy
            Invoke-LeiraCall -TaskPrompt 'hi' -Consumer 'verify_prepass' -Strategy 'round_robin' | Out-Null
            $script:seenHost | Should -Be 'consumer_pinned' -Because '-Consumer must win over -Strategy'
        }
    }
}

Describe 'T39-T40 — cross-language rotation counter sync (punch , 2026-07-17)' {
    BeforeEach {
        Import-Module $Script:ModulePath -Force
        InModuleScope leira_prepass { $Script:RotationCounter = 0 }
        # Clear sidecar between tests to avoid cross-test bleed.
        $sc = Join-Path $env:TEMP 'leira_rotation.next'
        if (Test-Path $sc) { Remove-Item $sc -Force -ErrorAction SilentlyContinue }
    }

    It 'T39 — pre-existing sidecar value overrides module counter (cross-language sync)' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                    c = @{ url = 'http://c:11434/api/chat' }
                }
            }
            # Simulate Python twin having advanced the counter to 4.
            Set-Content -Path $Script:RotationSidecarPath -Value '4' -Encoding utf8
            $Script:RotationCounter = 0  # module value should be overridden
            $picked = _NextHostByStrategy -Strategy 'round_robin'
            # 4 % 3 = 1 -> 'b' (sorted a/b/c).
            $picked | Should -Be 'b'
            # Sidecar should now hold 5.
            $persisted = [int](Get-Content -Raw $Script:RotationSidecarPath).Trim()
            $persisted | Should -Be 5
        }
    }

    It 'T40 — malformed sidecar fails open (module counter fallback)' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                }
            }
            Set-Content -Path $Script:RotationSidecarPath -Value 'not-a-number' -Encoding utf8
            $Script:RotationCounter = 0
            $picked = _NextHostByStrategy -Strategy 'round_robin'
            $picked | Should -Be 'a'
        }
    }
}

Describe 'T30-T34 — round-robin / weighted (Drive-F, 2026-07-17)' {
    # PS twin of Python _build_rotation_pool / _next_host_by_strategy.
    BeforeEach {
        Import-Module $Script:ModulePath -Force
        InModuleScope leira_prepass { $Script:RotationCounter = 0 }
        # Punch  (2026-07-17): clear the rotation sidecar so cross-test
        # bleed from T39/T40 doesn't skew the round-robin sequence pin.
        $sc = Join-Path $env:TEMP 'leira_rotation.next'
        if (Test-Path $sc) { Remove-Item $sc -Force -ErrorAction SilentlyContinue }
    }

    It 'T30 — primary strategy returns an empty rotation pool' {
        InModuleScope leira_prepass {
            # Wrap in @() so an empty array does not unwrap to $null and lose .Count.
            @(_BuildRotationPool -Strategy 'primary').Count | Should -Be 0
            (_NextHostByStrategy -Strategy 'primary') | Should -BeNullOrEmpty
        }
    }

    It 'T31 — round_robin pool is sorted host names' {
        InModuleScope leira_prepass {
            # Override cached config with three fake hosts.
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                    c = @{ url = 'http://c:11434/api/chat' }
                }
            }
            (_BuildRotationPool -Strategy 'round_robin') | Should -Be @('a', 'b', 'c')
        }
    }

    It 'T32 — weighted pool repeats by hosts.<name>.weight' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    alpha = @{ url = 'http://alpha:11434/api/chat'; weight = 3 }
                    beta  = @{ url = 'http://beta:11434/api/chat';  weight = 1 }
                }
            }
            $pool = _BuildRotationPool -Strategy 'weighted'
            (@($pool | Where-Object { $_ -eq 'alpha' })).Count | Should -Be 3
            (@($pool | Where-Object { $_ -eq 'beta'  })).Count | Should -Be 1
            $pool.Count | Should -Be 4
        }
    }

    It 'T33 — round_robin advances counter across successive calls' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                    c = @{ url = 'http://c:11434/api/chat' }
                }
            }
            # Wipe any per-host cooldowns for a/b/c.
            foreach ($h in @('a', 'b', 'c')) {
                $p = _CooldownPathFor -HostName $h
                if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
            }
            $seq = 1..6 | ForEach-Object { _NextHostByStrategy -Strategy 'round_robin' }
            $seq | Should -Be @('a', 'b', 'c', 'a', 'b', 'c')
        }
    }

    It 'T34 — round_robin skips cooldown host + explicit -HostName wins over strategy' {
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    a = @{ url = 'http://a:11434/api/chat' }
                    b = @{ url = 'http://b:11434/api/chat' }
                    c = @{ url = 'http://c:11434/api/chat' }
                }
            }
            foreach ($h in @('a', 'b', 'c')) {
                $p = _CooldownPathFor -HostName $h
                if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
            }
            # Bench b.
            _SetCooldownFor -HostName 'b' -Seconds 120
            $picks = 1..4 | ForEach-Object { _NextHostByStrategy -Strategy 'round_robin' }
            ($picks -contains 'b') | Should -BeFalse -Because 'benched host must be skipped'
            # Restore state.
            $p = _CooldownPathFor -HostName 'b'
            if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
        }

        # Explicit -HostName test — orchestrator level. Mock _InvokeLeiraCallOnce
        # to record the routed host.
        InModuleScope leira_prepass {
            $Script:CachedConfig = @{
                hosts = @{
                    pinned = @{ url = 'http://pinned:11434/api/chat' }
                    other  = @{ url = 'http://other:11434/api/chat' }
                }
                strategy = 'round_robin'
            }
            $script:seenHost = $null
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:seenHost = $HostName
                return @{ ok = $true }
            }
            Invoke-LeiraCall -TaskPrompt 'hi' -HostName 'pinned' | Out-Null
            $script:seenHost | Should -Be 'pinned' -Because 'explicit -HostName must win over strategy'
        }
    }
}

Describe 'T25-T29 — cross-host failover (Drive-E, 2026-07-17)' {
    # PS twin of Python call_leira orchestrator. Uses Pester Mock with
    # -ModuleName to intercept _InvokeLeiraCallOnce inside module scope
    # (naked `function` redefinition in a `& $mod { }` scriptblock does NOT
    # persist to the module's function table — the mock has to go through
    # Pester's session-state injection instead).
    BeforeEach {
        Import-Module $Script:ModulePath -Force
        $env:OLLAMA_HOST = $null; $env:LEIRA_URL = $null; $env:OLLAMA_URL = $null
        InModuleScope leira_prepass { $Script:ActiveHost = $null }
    }

    It 'T25 — no failover configured -> single _InvokeLeiraCallOnce call' {
        InModuleScope leira_prepass {
            Mock _InvokeLeiraCallOnce { return @{ ok = $true } }
            $result = Invoke-LeiraCall -TaskPrompt 'hi' -Schema @{ required = @() } -FailoverHosts @()
            Should -Invoke _InvokeLeiraCallOnce -Exactly 1
            $result.ok | Should -Be $true
        }
    }

    It 'T26 — primary fails, second succeeds -> _leira_meta.failover_chain records traversal' {
        InModuleScope leira_prepass {
            $script:calls = @()
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:calls += $HostName
                if ($HostName -eq '' -or $HostName -eq 'llm-host') {
                    throw [LeiraUnavailable]::new("host=$HostName benched")
                }
                return @{ content = 'ok' }
            }
            $result = Invoke-LeiraCall -TaskPrompt 'hi' -Schema @{ required = @() } -FailoverHosts @('beshaba')
            $script:calls | Should -Be @('llm-host', 'beshaba')
            $result.content | Should -Be 'ok'
            $result['_leira_meta']['failover_chain'] | Should -Be @('llm-host', 'beshaba')
        }
    }

    It 'T27 — LeiraConfigError bubbles immediately (no failover attempt)' {
        InModuleScope leira_prepass {
            $script:calls = @()
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:calls += $HostName
                throw [LeiraConfigError]::new("unknown host $HostName")
            }
            $threw = $false
            $thrownType = $null
            try {
                Invoke-LeiraCall -TaskPrompt 'hi' -FailoverHosts @('one', 'two') | Out-Null
            }
            catch {
                $threw = $true
                $thrownType = $_.Exception.GetType().Name
            }
            $threw | Should -BeTrue
            $thrownType | Should -Be 'LeiraConfigError'
            $script:calls.Count | Should -Be 1 -Because 'config-error must NOT chain'
        }
    }

    It 'T28 — all hosts exhausted -> LeiraUnavailable' {
        InModuleScope leira_prepass {
            $script:calls = @()
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:calls += $HostName
                throw [LeiraUnavailable]::new("host=$HostName dead")
            }
            $threw = $false; $thrownType = $null; $msg = $null
            try {
                Invoke-LeiraCall -TaskPrompt 'hi' -FailoverHosts @('a', 'b') | Out-Null
            }
            catch {
                $threw = $true
                $thrownType = $_.Exception.GetType().Name
                $msg = $_.Exception.Message
            }
            $threw | Should -BeTrue
            $thrownType | Should -Be 'LeiraUnavailable'
            $msg | Should -BeLike '*exhausted*'
            $script:calls | Should -Be @('llm-host', 'a', 'b')
        }
    }

    It 'T29 — failover chain dedups primary from failover list' {
        InModuleScope leira_prepass {
            $script:calls = @()
            Mock _InvokeLeiraCallOnce {
                param([string]$TaskPrompt, [hashtable]$Schema, [string]$System, [string]$HostName)
                $script:calls += $HostName
                throw [LeiraUnavailable]::new("host=$HostName")
            }
            try { Invoke-LeiraCall -TaskPrompt 'hi' -FailoverHosts @('llm-host', 'b') | Out-Null } catch { }
            $script:calls | Should -Be @('llm-host', 'b') -Because 'primary must be deduped from failover list'
        }
    }
}

Describe 'T21-T24 — per-host cooldown (Drive-D, 2026-07-17)' {
    # PS twin of Python _in_cooldown_for / _set_cooldown_for / _cooldown_path_for.
    # Legacy global sidecar retained for backward-compat "all benched" reads.
    BeforeAll {
        $Script:GlobalCooldownPath = Join-Path $env:TEMP 'leira_cooldown.until'
    }
    AfterEach {
        # db-sme Batch-2 NTH#5 fold: clean up per-host sidecars each test
        # touches so isolation is by construction, not by accident. Covers
        # every host name any test in this Describe writes.
        Import-Module $Script:ModulePath -Force
        foreach ($h in @('llm-host', 'the ML host', '<env-url>', '../evil/host')) {
            try {
                $p = & (Get-Module leira_prepass) { param($n) _CooldownPathFor -HostName $n } $h
                if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
            } catch { }
        }
        if (Test-Path $Script:GlobalCooldownPath) {
            Remove-Item $Script:GlobalCooldownPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'T21 — per-host cooldown scopes to the named host (sibling stays unblocked)' {
        Import-Module $Script:ModulePath -Force
        # Clear before.
        foreach ($p in @(
            (& (Get-Module leira_prepass) { _CooldownPathFor -HostName 'the ML host' }),
            (& (Get-Module leira_prepass) { _CooldownPathFor -HostName 'llm-host' }),
            $Script:GlobalCooldownPath
        )) {
            if (Test-Path $p) { Remove-Item $p -Force }
        }
        & (Get-Module leira_prepass) { _SetCooldownFor -HostName 'the ML host' -Seconds 120 }
        $the ML host = & (Get-Module leira_prepass) { _CooldownRemainingFor -HostName 'the ML host' }
        $llm-host  = & (Get-Module leira_prepass) { _CooldownRemainingFor -HostName 'llm-host' }
        $the ML host | Should -BeGreaterThan 100
        $llm-host  | Should -Be 0 -Because 'llm-host must remain callable while the ML host is benched (Drive-D per-host scope)'
    }

    It 'T22 — legacy global sidecar blocks ALL hosts (backward-compat)' {
        Import-Module $Script:ModulePath -Force
        foreach ($p in @(
            (& (Get-Module leira_prepass) { _CooldownPathFor -HostName 'the ML host' }),
            (& (Get-Module leira_prepass) { _CooldownPathFor -HostName 'llm-host' })
        )) {
            if (Test-Path $p) { Remove-Item $p -Force }
        }
        $until = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 60
        Set-Content -Path $Script:GlobalCooldownPath -Value ([string]$until) -Encoding utf8
        foreach ($h in @('llm-host', 'the ML host', 'any-name')) {
            # Rename loop var from $host to $h — $host is a PowerShell
            # automatic read-only variable; assigning shadows it.
            $rem = & (Get-Module leira_prepass) { param($n) _CooldownRemainingFor -HostName $n } $h
            $rem | Should -BeGreaterThan 0 -Because "global cooldown must still block host=$h (backward-compat)"
        }
        # Cleanup
        if (Test-Path $Script:GlobalCooldownPath) { Remove-Item $Script:GlobalCooldownPath -Force }
    }

    It 'T23 — cooldown path is distinct per host' {
        Import-Module $Script:ModulePath -Force
        $p1 = & (Get-Module leira_prepass) { _CooldownPathFor -HostName 'llm-host' }
        $p2 = & (Get-Module leira_prepass) { _CooldownPathFor -HostName 'the ML host' }
        $p1 | Should -Not -Be $p2
        $p1 | Should -Match 'llm-host'
        $p2 | Should -Match 'the ML host'
    }

    It 'T24 — _SanitizeHostForPath strips unsafe chars' {
        Import-Module $Script:ModulePath -Force
        $env_sanitized = & (Get-Module leira_prepass) { _SanitizeHostForPath -Name '<env-url>' }
        $env_sanitized | Should -Not -Match '[<>]'
        $trav = & (Get-Module leira_prepass) { _SanitizeHostForPath -Name '../evil/host' }
        $trav | Should -Not -Match '\.\.'
        $trav | Should -Not -Match '[/\\]'
    }
}

Describe 'T17-T19 — Get-LeiraHealthcheck (Drive-C, 2026-07-17)' {
    # PS twin of Python leira_healthcheck. Informational — no cooldown,
    # no auto-routing.
    BeforeAll {
        # Wipe cooldown so we can pin the no-side-effect contract at T19.
        $Script:CooldownPath = Join-Path $env:TEMP 'leira_cooldown.until'
        if (Test-Path $Script:CooldownPath) {
            Remove-Item $Script:CooldownPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'T17 — Get-LeiraHealthcheck returns a hashtable per host with expected keys' {
        Import-Module $Script:ModulePath -Force
        $results = Get-LeiraHealthcheck -TimeoutSec 1
        $results | Should -Not -BeNullOrEmpty
        foreach ($r in $results) {
            $r.ContainsKey('Name')       | Should -BeTrue
            $r.ContainsKey('Url')        | Should -BeTrue
            $r.ContainsKey('Reachable')  | Should -BeTrue
            $r.ContainsKey('LatencyMs')  | Should -BeTrue
            $r.ContainsKey('ModelCount') | Should -BeTrue
            $r.ContainsKey('Error')      | Should -BeTrue
            $r.Reachable | Should -BeOfType [bool]
        }
    }

    It 'T18 — Get-LeiraHealthcheck emits exactly one row per configured host (count-agnostic)' {
        # Structural pin: results count == hosts.<name> count. Adding a new
        # host to the config auto-extends coverage; a silently-skipped host
        # trips this pin.
        Import-Module $Script:ModulePath -Force
        $cfg      = Get-LeiraConfig
        $expected = ($cfg['hosts'] ?? @{}).Keys | Sort-Object
        $results  = Get-LeiraHealthcheck -TimeoutSec 1
        $seen     = @($results | ForEach-Object { $_.Name }) | Sort-Object
        $seen | Should -Be $expected -Because 'healthcheck must cover every hosts.<name> entry'
    }

    It 'T19 — Get-LeiraHealthcheck must not arm the cooldown sidecar' {
        # Drawer §Non-goals contract — informational only. A failed probe
        # (test env cannot reach llm-host) MUST NOT create the cooldown file.
        Import-Module $Script:ModulePath -Force
        if (Test-Path $Script:CooldownPath) {
            Remove-Item $Script:CooldownPath -Force -ErrorAction SilentlyContinue
        }
        Get-LeiraHealthcheck -TimeoutSec 1 | Out-Null
        (Test-Path $Script:CooldownPath) | Should -BeFalse -Because 'healthcheck must not confuse downstream Invoke-LeiraCall by tripping the shared cooldown'
    }
}

Describe 'T2 + T3 — per-consumer scaffold' {
    Context 'consumer <_>' -ForEach $Script:DiscoveredConsumers -AllowNullOrEmptyForEach {
        BeforeAll {
            $Script:ConsumerPath = Join-Path (Split-Path -Parent $PSScriptRoot) "scripts/$_"
            $Script:ConsumerText = Get-Content -Raw $Script:ConsumerPath
        }

        It 'parses without errors' {
            $errs = $null
            [void][System.Management.Automation.PSParser]::Tokenize($Script:ConsumerText, [ref]$errs)
            $errs | Should -BeNullOrEmpty
        }

        It 'imports leira_prepass.psm1 (helper wiring holds)' {
            $Script:ConsumerText | Should -Match 'Import-Module[^\r\n]*leira_prepass\.psm1'
        }

        It 'pins the HIPAA-at-callsite contract in its docstring' {
            # Same contract line the Python consumers carry — enforcement is the caller's job.
            $Script:ConsumerText | Should -Match 'HIPAA[^\r\n]*(callsite|caller''s job|does not enforce)'
        }
    }
}

Describe 'T4 — drift guard (silent-consumer detector)' {
    It 'every scripts/leira_*.ps1 is registered in $AllPsConsumers' {
        $unregistered = @($Script:DiscoveredConsumers | Where-Object { $_ -notin $Script:AllPsConsumers })
        if ($unregistered.Count -gt 0) {
            $msg = "New PS consumer(s) not listed in `$AllPsConsumers (this file, top): " +
                   ($unregistered -join ', ') +
                   ". Add them to close the drift guard + confirm the HIPAA/pattern contract."
            $unregistered | Should -BeNullOrEmpty -Because $msg
        }
    }

    It 'every $AllPsConsumers entry actually exists on disk' {
        $missing = @($Script:AllPsConsumers | Where-Object { $_ -notin $Script:DiscoveredConsumers })
        $missing | Should -BeNullOrEmpty
    }
}
