#Requires -Version 7.0
<#
.SYNOPSIS
  Symmetry pin — PowerShell twin.

.DESCRIPTION
  Consumes the SHARED vectors at tests/leira_multihost_vectors.json (also
  consumed by tests/test_leira_multihost_symmetry.py — the Python twin). If
  either twin's behavior diverges from the JSON expectation, the vector fails
  in that twin only, pinpointing the drift. Both twins iterate the vectors
  count-agnostically (Pester -ForEach here; pytest.mark.parametrize there) so
  adding a new vector to the JSON auto-extends the pin without touching
  either twin.

  Prime Directive #1 (project_style_guide): every SSOT ships its
  count-agnostic structural pin in the same change. The JSON is the SSOT;
  this file + the Python twin are the pin.

.NOTES
  pwsh 7 REQUIRED. Pester 5+.
  Run: Invoke-Pester -Path tests/leira_multihost_symmetry.Tests.ps1 -Output Detailed

  Landed 2026-07-17 in Drive-A of the llm-host multi-host completion arc; closes
  the DA follow-on NTH from Drive-16 (state_2026-07-17_0900_edt).
#>

BeforeDiscovery {
    # DISCOVERY-TIME: hydrate vectors so -ForEach can enumerate them into It
    # blocks. Anything Pester needs before It bodies run must live here (Pester
    # 5+ contract — $Script:* set inside BeforeAll is NOT visible to -ForEach).
    $repoRoot     = Split-Path -Parent $PSScriptRoot
    $vectorsPath  = Join-Path $repoRoot 'tests/leira_multihost_vectors.json'
    $Script:MultihostVectors = @(
        if (Test-Path $vectorsPath) {
            (Get-Content -Raw $vectorsPath | ConvertFrom-Json).vectors
        }
    )
}

BeforeAll {
    # EXECUTION-TIME: hydrate paths + a fresh vector snapshot for It bodies.
    $Script:RepoRoot     = Split-Path -Parent $PSScriptRoot
    $Script:ModulePath   = Join-Path $Script:RepoRoot 'scripts/leira_prepass.psm1'
    $Script:VectorsPath  = Join-Path $Script:RepoRoot 'tests/leira_multihost_vectors.json'
    $Script:VectorsRaw   = Get-Content -Raw $Script:VectorsPath | ConvertFrom-Json

    # Preserve caller env — each vector clobbers OLLAMA_HOST / LEIRA_URL /
    # OLLAMA_URL / LEIRA_OLLAMA_BASE_URL, so snapshot for AfterAll restore
    # (db-sme Drive NTH#3 shape — try/finally per var).
    $Script:SavedOllamaHost = $env:OLLAMA_HOST
    $Script:SavedLeiraUrl   = $env:LEIRA_URL
    $Script:SavedOllamaUrl  = $env:OLLAMA_URL
    $Script:SavedBaseUrl    = $env:LEIRA_OLLAMA_BASE_URL
}

AfterAll {
    try { $env:OLLAMA_HOST           = $Script:SavedOllamaHost } catch { }
    try { $env:LEIRA_URL             = $Script:SavedLeiraUrl   } catch { }
    try { $env:OLLAMA_URL            = $Script:SavedOllamaUrl  } catch { }
    try { $env:LEIRA_OLLAMA_BASE_URL = $Script:SavedBaseUrl    } catch { }
}

Describe 'llm-host multi-host symmetry vectors' {
    It 'meta — vector file loaded + non-empty' {
        $Script:VectorsRaw.vectors | Should -Not -BeNullOrEmpty -Because 'the SSOT vector list drives the parametrized pin; empty list = inert pin'
    }

    It 'meta — per-vector shape mirrors the Python meta-pin (DA NTH#1 fold)' {
        # DA Batch-1 NTH#1: PS meta-pin previously asserted non-empty only,
        # while Python asserts per-vector shape. Twin drift — a malformed
        # vector (dup id, unsupported env knob, missing keys, both raises +
        # name set) tripped Python but slid past PS. Fold same-drive.
        $seenIds = [System.Collections.Generic.HashSet[string]]::new()
        $supported = @('OLLAMA_HOST', 'OLLAMA_URL', 'LEIRA_URL')
        foreach ($v in $Script:VectorsRaw.vectors) {
            $v.id   | Should -Not -BeNullOrEmpty -Because 'every vector needs an id'
            $v.name | Should -Not -BeNullOrEmpty -Because "vector $($v.id) needs a name"
            $seenIds.Add($v.id) | Should -BeTrue -Because "duplicate vector id: $($v.id)"
            $v.env  | Should -Not -Be $null -Because "vector $($v.id) missing env map"
            if ($null -ne $v.env) {
                foreach ($k in $v.env.PSObject.Properties.Name) {
                    ($supported -contains $k) | Should -BeTrue -Because "vector $($v.id): unsupported env knob '$k' (only $($supported -join ' / '))"
                }
            }
            if ($v.PSObject.Properties.Name -contains 'expect_raises' -and $v.expect_raises) {
                # Mutual exclusion — a vector cannot both raise AND resolve.
                ($v.PSObject.Properties.Name -contains 'expect_active_host_name') | Should -BeFalse -Because "vector $($v.id): expect_raises and expect_active_host_name are mutually exclusive"
            } else {
                $v.expect_active_host_name | Should -Not -BeNullOrEmpty -Because "vector $($v.id) needs expect_active_host_name (or expect_raises)"
            }
            if ($v.PSObject.Properties.Name -contains 'expect_active_host_url' -and $v.expect_active_host_url) {
                # db-sme NTH fold + drawer rule 1/2 discriminator — '<env-url>'
                # is the SENTINEL name for raw-URL bypass; url pin implies name.
                $v.expect_active_host_name | Should -Be '<env-url>' -Because "vector $($v.id): expect_active_host_url implies name == '<env-url>'"
            }
        }
    }

    Context "vector <_.id>" -ForEach $Script:MultihostVectors {
        BeforeAll {
            # Pester 5+: the current -ForEach item lands in $_ during
            # discovery. BeforeAll re-hydrates from $_ so each It sees the
            # right vector.
            $Script:Vec = $_
            # Wipe all four knobs; the vector re-applies only what it needs.
            $env:OLLAMA_HOST           = $null
            $env:LEIRA_URL             = $null
            $env:OLLAMA_URL            = $null
            $env:LEIRA_OLLAMA_BASE_URL = $null
            foreach ($k in $Script:Vec.env.PSObject.Properties.Name) {
                Set-Item -Path ("Env:{0}" -f $k) -Value $Script:Vec.env.$k
            }
        }

        It 'resolves per the SSOT expectation' {
            $mod = Import-Module $Script:ModulePath -Force -PassThru
            # ActiveHost is cached per-process; reset it so each vector
            # re-runs _ResolveActiveHost fresh (docstring §Cache-staleness
            # contract — test-only escape hatch).
            & $mod { $Script:ActiveHost = $null }

            if ($Script:Vec.expect_raises) {
                $threw = $false
                $thrownType = $null
                $thrownMessage = $null
                try {
                    Get-LeiraActiveHost | Out-Null
                }
                catch {
                    $threw          = $true
                    $thrownType     = $_.Exception.GetType().Name
                    $thrownMessage  = $_.Exception.Message
                }
                $threw | Should -BeTrue -Because "vector $($Script:Vec.id) expects $($Script:Vec.expect_raises); no throw seen"
                $thrownType | Should -Be $Script:Vec.expect_raises -Because "vector $($Script:Vec.id) — wrong exception class"
                foreach ($needle in ($Script:Vec.expect_message_contains ?? @())) {
                    $thrownMessage | Should -BeLike "*$needle*" -Because "vector $($Script:Vec.id) — msg missing '$needle'; got: $thrownMessage"
                }
                return
            }

            $gotName = Get-LeiraActiveHost
            $gotName | Should -Be $Script:Vec.expect_active_host_name -Because "vector $($Script:Vec.id): Get-LeiraActiveHost wrong"

            if ($null -ne $Script:Vec.expect_active_host_url) {
                # Reach into module scope to read the resolved URL — the Url
                # field is not part of the public accessor (only Name is).
                $gotUrl = & $mod { $Script:ActiveHost.Url }
                $gotUrl | Should -Be $Script:Vec.expect_active_host_url -Because "vector $($Script:Vec.id): resolved URL mismatch"
            }
        }
    }
}
