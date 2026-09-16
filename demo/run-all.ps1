<#
.SYNOPSIS
    Orchestrates the four Windows deterministic-detection scenarios in demo order.

.DESCRIPTION
    Runs, in this order:
        1. lab\scenarios\encoded-powershell.ps1         (T1059.001)
        2. lab\scenarios\scheduled-task-persistence.ps1 (T1053.005)
        3. lab\scenarios\service-install-persistence.ps1 (T1543.003)
        4. lab\scenarios\create-account-persistence.ps1 (T1136.001)

    Between scenarios: a short pause + a banner headline in the console, so
    the reviewer watching the agent's terminal (Terminal A) can associate
    each incoming alert group with the scenario that produced it.

    Each scenario is self-cleaning (`try/finally` in each script); this
    orchestrator does no cleanup of its own — a partial run leaves the
    host in the correct state regardless of where it stopped.

.NOTES
    Usage:
        Terminal A (as Administrator):
            target\release\agent.exe run
        Terminal B (as Administrator):
            pwsh -File demo\run-all.ps1

    See demo\README.md for the surrounding context and demo\expected-alerts.md
    for the exact alert lines the agent should print.

    Prerequisites: run this script AND the agent as Administrator. Each
    underlying scenario needs it (schtasks /Create, sc.exe create, net user
    /add all require elevation) and the agent needs it to read the Security
    log and enable audit subcategories.

    Timing: 3 iterations per scenario × 1s per iteration + 5s inter-scenario
    pause × 3 gaps = roughly 30 seconds total runtime, plus the eventlog
    sensor's 2-second poll lag on the persistence alerts.

.LINK
    demo\README.md
#>

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ScenariosDir = Join-Path $RepoRoot "lab\scenarios"

$Steps = @(
    @{
        Technique = "T1059.001 — Command and Scripting Interpreter: PowerShell (EncodedCommand)"
        Script    = Join-Path $ScenariosDir "encoded-powershell.ps1"
    },
    @{
        Technique = "T1053.005 — Scheduled Task/Job: Scheduled Task"
        Script    = Join-Path $ScenariosDir "scheduled-task-persistence.ps1"
    },
    @{
        Technique = "T1543.003 — Create or Modify System Process: Windows Service"
        Script    = Join-Path $ScenariosDir "service-install-persistence.ps1"
    },
    @{
        Technique = "T1136.001 — Create Account: Local Account"
        Script    = Join-Path $ScenariosDir "create-account-persistence.ps1"
    }
)

# Fail fast if any scenario is missing rather than half-running the demo.
foreach ($step in $Steps) {
    if (-not (Test-Path $step.Script)) {
        throw "missing scenario script: $($step.Script) — run this from a clean checkout of the repo, or check that all four PRs (T1059.001/T1053.005/T1543.003/T1136.001) are on the current branch."
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  Synthaea demo — 4 techniques, 3 iterations each"
Write-Host "  Watch Terminal A (agent) for alerts as this script runs."
Write-Host "============================================================"
Write-Host ""

for ($i = 0; $i -lt $Steps.Count; $i++) {
    $step = $Steps[$i]
    Write-Host ""
    Write-Host "───────────────────────────────────────────────────────────"
    Write-Host " Step $($i + 1)/$($Steps.Count) — $($step.Technique)"
    Write-Host "───────────────────────────────────────────────────────────"
    & pwsh -File $step.Script
    if ($i -lt $Steps.Count - 1) {
        Write-Host ""
        Write-Host "(pausing 5 seconds before the next step so alerts stay readable...)"
        Start-Sleep -Seconds 5
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  Demo complete. Expected: 12 alerts total in Terminal A"
Write-Host "  (3 per technique, 4 techniques). See demo\expected-alerts.md"
Write-Host "  for the exact lines and per-step troubleshooting."
Write-Host "============================================================"
