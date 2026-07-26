#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
  push-ci-shepherd.ps1 - PowerShell 7 port of .the AI assistant/agents/push-ci-shepherd.md

  Deterministic: git push (idempotent) -> enumerate workflow runs on the pushed SHA
  -> poll each to terminal via `gh api .../actions/runs/<id> .conclusion` (authoritative)
  -> emit a fixed GREEN / RED verdict block, and append one JSON line per cycle to a
  CI-verdicts log. Multi-cycle backlog drain up to a cap.

  Runs OUTSIDE AI development tooling, so it SURVIVES cc session compaction / teardown / reaping.
  Launch it detached to fully decouple:
    Start-Process pwsh -ArgumentList '-NoProfile','-File','scripts/push-ci-shepherd.ps1' -WindowStyle Hidden

.NOTES
  - pwsh 7 ONLY (never Windows PowerShell 5.1) - feedback_use_pwsh7_not_ps51.
  - Read-only GitHub: `gh` GET only. Never touches the working tree, never opens PRs,
    never reruns / force-pushes. It simply does not implement those verbs.
  - `.conclusion` from `gh api` is the source of truth; it does NOT use
    `gh run watch --exit-status` (returns 0 on FAILED - feedback_gh_run_watch_exit_status_unreliable).
  - Exit code: 0 = GREEN (all cycles), 1 = RED / PARTIAL, 2 = usage / setup error.
  - The CI-verdicts log defaults to <repo>/.ci-shepherd/verdicts.jsonl - a DIFFERENT file
    from the defer-gate learner's verdicts.jsonl (different schema; do not conflate).

.PARAMETER Target
  HEAD (default) | <branch> | <branch>@<sha> (verify branch tip == sha before pushing).

.EXAMPLE
  pwsh -File scripts/push-ci-shepherd.ps1 -Target feat/v0.2.0
.EXAMPLE
  pwsh -File scripts/push-ci-shepherd.ps1 -DryRun            # no push; enumerate + watch HEAD's runs
#>
[CmdletBinding()]
param(
  [string]$Target = 'HEAD',
  [int]$CycleCap = $(if ($env:PUSH_SHEPHERD_CYCLE_CAP) { [int]$env:PUSH_SHEPHERD_CYCLE_CAP } else { 5 }),
  [switch]$SingleCycle,
  [int]$PollSeconds = 20,
  [int]$PerRunTimeoutMin = 20,
  [int]$AppearTimeoutSec = 60,
  [string]$VerdictsLog,
  [string]$ChannelUrl,
  [string]$ChannelSecret,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Native commands: we inspect $LASTEXITCODE ourselves, so don't let non-zero throw.
$PSNativeCommandUseErrorActionPreference = $false

function Die([string]$Message, [int]$Code = 2) {
  [Console]::Error.WriteLine("push-ci-shepherd: $Message")
  exit $Code
}

# --- tool + repo preflight ---------------------------------------------------
foreach ($t in 'git', 'gh') {
  if (-not (Get-Command $t -ErrorAction SilentlyContinue)) { Die "'$t' not found on PATH" }
}

$repoRoot = (git rev-parse --show-toplevel 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $repoRoot) { Die 'not inside a git repository' }
$repoRoot = $repoRoot.Trim()

$originUrl = (git remote get-url origin 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $originUrl) { Die 'no `origin` remote' }
if ($originUrl -match 'github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?/?$') {
  $owner = $Matches[1]; $repo = $Matches[2]
} else {
  Die "cannot parse owner/repo from origin url: $originUrl"
}

if (-not $VerdictsLog) { $VerdictsLog = Join-Path $repoRoot '.ci-shepherd/verdicts.jsonl' }
$logDir = Split-Path -Parent $VerdictsLog
if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

# --- target resolution -------------------------------------------------------
$requestedSha = $null
if ($Target -eq 'HEAD') {
  $branch = (git rev-parse --abbrev-ref HEAD).Trim()
} elseif ($Target -match '^(?<b>.+)@(?<s>[0-9a-fA-F]{7,40})$') {
  $branch = $Matches['b']; $requestedSha = $Matches['s'].ToLower()
} else {
  $branch = $Target
}
if (-not $branch -or $branch -eq 'HEAD') { Die 'could not resolve a branch name (detached HEAD?) - pass an explicit <branch>' }

# --- helpers -----------------------------------------------------------------
function Get-Sha([string]$Ref) {
  $s = (git rev-parse $Ref 2>$null)
  if ($LASTEXITCODE -ne 0 -or -not $s) { return $null }
  return $s.Trim().ToLower()
}

# Poll one run to a terminal state. Returns the authoritative conclusion string,
# or 'timed_out' / 'api_error'.
function Wait-Run([long]$Id) {
  $deadline = (Get-Date).AddMinutes($PerRunTimeoutMin)
  while ($true) {
    $line = (gh api "repos/$owner/$repo/actions/runs/$Id" --jq '(.status) + "|" + (.conclusion // "")' 2>$null)
    if ($LASTEXITCODE -ne 0) { return 'api_error' }
    $status, $conclusion = ($line.Trim() -split '\|', 2)
    if ($status -eq 'completed') { return ($conclusion ? $conclusion : 'completed_no_conclusion') }
    if ((Get-Date) -ge $deadline) { return 'timed_out' }
    Start-Sleep -Seconds $PollSeconds
  }
}

# Enumerate the runs on a SHA, retrying until they appear (cap AppearTimeoutSec).
function Get-RunsForSha([string]$Sha) {
  $deadline = (Get-Date).AddSeconds($AppearTimeoutSec)
  while ($true) {
    $raw = (gh run list --branch $branch --limit 20 --json databaseId,name,workflowName,status,conclusion,headSha,createdAt 2>$null)
    if ($LASTEXITCODE -eq 0 -and $raw) {
      $all = $raw | ConvertFrom-Json
      $mine = @($all | Where-Object { $_.headSha.ToLower() -eq $Sha })
      if ($mine.Count -gt 0) { return $mine }
    }
    if ((Get-Date) -ge $deadline) { return @() }
    Start-Sleep -Seconds 15
  }
}

function Format-Elapsed([timespan]$Span) {
  if ($Span.TotalSeconds -lt 60) { return ('{0}s' -f [int]$Span.TotalSeconds) }
  return ('{0}m {1:00}s' -f [int]$Span.TotalMinutes, $Span.Seconds)
}

function Emit-Verdict([hashtable]$Rec) {
  # append-only JSONL for machine consumers (survives cc reaping)
  ($Rec | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $VerdictsLog -Encoding utf8
  # optional live push into a AI development tooling($ChannelUrl) {
    try {
      $headers = @{}
      if ($ChannelSecret) { $headers['X-Channel-Secret'] = $ChannelSecret }
      $body = "CI $($Rec.verdict): $($Rec.branch)@$($Rec.sha.Substring(0,[Math]::Min(8,$Rec.sha.Length))) - " +
              (($Rec.runs | ForEach-Object { "$($_.workflow)=$($_.conclusion)" }) -join ', ')
      Invoke-RestMethod -Uri $ChannelUrl -Method Post -Headers $headers -Body $body -TimeoutSec 10 | Out-Null
    } catch {
      [Console]::Error.WriteLine("push-ci-shepherd: channel POST failed (non-fatal): $($_.Exception.Message)")
    }
  }
}

# --- one cycle: push -> enumerate -> watch -> report -------------------------
function Invoke-Cycle([int]$CycleNum) {
  $cycleSha = Get-Sha $branch
  if (-not $cycleSha) { Die "cannot resolve branch '$branch'" }
  if ($requestedSha -and $CycleNum -eq 1) {
    if (-not ($cycleSha.StartsWith($requestedSha) -or $requestedSha.StartsWith($cycleSha))) {
      Die "drift: '$branch' tip $cycleSha does not match requested $requestedSha"
    }
  }

  # push (idempotent)
  $remoteSha = Get-Sha "origin/$branch"
  if ($cycleSha -eq $remoteSha) {
    $pushResult = 'no-op (already synced)'
  } elseif ($DryRun) {
    $pushResult = 'skipped (dry-run)'
  } else {
    $pushOut = (git push origin $branch 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
      Write-Output "SHA: $cycleSha"
      Write-Output "Branch: $branch"
      Write-Output "Push: ERROR: $($pushOut.Trim())"
      Write-Output ''
      Write-Output 'Verdict: RED (push failed)'
      Emit-Verdict @{ ts = (Get-Date).ToString('o'); cycle = $CycleNum; sha = $cycleSha; branch = $branch; verdict = 'RED'; push = 'error'; error = $pushOut.Trim(); runs = @() }
      $script:CycleVerdict = 'RED'; $script:CycleSha = $cycleSha; return
    }
    $pushResult = 'pushed'
  }

  # enumerate + watch
  $start = Get-Date
  $runs = @(Get-RunsForSha $cycleSha)
  if ($runs.Count -eq 0) {
    Write-Output "SHA: $cycleSha"
    Write-Output "Branch: $branch"
    Write-Output "Push: $pushResult"
    Write-Output ''
    Write-Output "Runs: none appeared on GitHub within ${AppearTimeoutSec}s of push"
    Write-Output ''
    Write-Output 'Verdict: PARTIAL (no runs found)'
    Emit-Verdict @{ ts = (Get-Date).ToString('o'); cycle = $CycleNum; sha = $cycleSha; branch = $branch; verdict = 'PARTIAL'; push = $pushResult; runs = @() }
    $script:CycleVerdict = 'PARTIAL'; $script:CycleSha = $cycleSha; return
  }

  $results = @(foreach ($r in $runs) {
    [pscustomobject]@{ workflow = $r.workflowName; databaseId = [long]$r.databaseId; conclusion = (Wait-Run ([long]$r.databaseId)) }
  })
  $elapsed = Format-Elapsed ((Get-Date) - $start)

  $failing = @($results | Where-Object { $_.conclusion -ne 'success' })
  $verdict = if ($failing.Count -eq 0) { 'GREEN' }
             elseif ($failing.Count -eq $results.Count) { 'RED' }
             else { "PARTIAL ($($failing.Count)/$($results.Count) failing)" }

  # fixed output block (headers verbatim so a caller can grep)
  Write-Output "SHA: $cycleSha"
  Write-Output "Branch: $branch"
  Write-Output "Push: $pushResult"
  Write-Output ''
  Write-Output "Runs (found $($results.Count) in ${elapsed}):"
  foreach ($x in $results) { Write-Output ("- {0,-22} -> {1,-10} [{2}]" -f $x.workflow, $x.conclusion, $x.databaseId) }
  Write-Output ''
  Write-Output "Verdict: $verdict"

  if ($failing.Count -gt 0) {
    Write-Output ''
    Write-Output 'Failures:'
    foreach ($f in $failing) {
      Write-Output "- $($f.workflow) [$($f.databaseId)]:"
      Write-Output "    Conclusion: $($f.conclusion)"
      Write-Output "    URL: https://github.com/$owner/$repo/actions/runs/$($f.databaseId)"
      if ($f.conclusion -eq 'failure') {
        $tail = (gh run view $f.databaseId --log-failed 2>$null | Select-Object -Last 20 | Out-String)
        if ($tail.Trim()) {
          Write-Output '    Tail (last 20 lines of the failing step):'
          Write-Output '      ```'
          foreach ($l in ($tail -split "`n")) { if ($l.Trim()) { Write-Output "      $($l.TrimEnd())" } }
          Write-Output '      ```'
        } else {
          Write-Output '    (no failing-step log returned by gh)'
        }
      } else {
        Write-Output "    (no step-log - conclusion '$($f.conclusion)', not a step failure)"
      }
    }
  }

  $shortVerdict = $verdict.Split(' ')[0]
  Emit-Verdict @{
    ts = (Get-Date).ToString('o'); cycle = $CycleNum; sha = $cycleSha; branch = $branch
    verdict = $shortVerdict; push = $pushResult; elapsed = $elapsed
    runs = @($results | ForEach-Object { @{ workflow = $_.workflow; databaseId = $_.databaseId; conclusion = $_.conclusion } })
  }
  $script:CycleVerdict = $shortVerdict; $script:CycleSha = $cycleSha; return
}

# --- main: cycle + backlog drain --------------------------------------------
$overall = 'GREEN'
$lastSha = $null
$script:CycleVerdict = 'GREEN'
$script:CycleSha = $null
for ($cycle = 1; $cycle -le $CycleCap; $cycle++) {
  if ($cycle -gt 1) { Write-Output ''; Write-Output "--- cycle $cycle ---" }
  Invoke-Cycle $cycle
  $lastSha = $script:CycleSha
  if ($script:CycleVerdict -ne 'GREEN') { $overall = $script:CycleVerdict; break }

  if ($SingleCycle -or $DryRun) { break }

  # backlog drain: more local commits waiting above the pushed tip?
  $ahead = (git rev-list --count '@{upstream}..HEAD' 2>$null)
  $ahead = if ($LASTEXITCODE -eq 0 -and $ahead) { [int]$ahead.Trim() } else { 0 }
  if ($ahead -le 0) { break }
  if ($cycle -eq $CycleCap) {
    Write-Output ''
    Write-Output "Overall: PARTIAL (cycle cap $CycleCap hit; $ahead commit(s) still ahead of remote)"
    exit 1
  }
  Write-Output ''
  Write-Output "($ahead commit(s) queued locally - draining next cycle)"
}

Write-Output ''
Write-Output "Overall: $overall (remote at $lastSha)"
if ($overall -eq 'GREEN') { exit 0 } else { exit 1 }
