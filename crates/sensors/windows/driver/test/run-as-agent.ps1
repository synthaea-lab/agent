<#
.SYNOPSIS
    Runs a PowerShell script with the agent's identity (NT SERVICE\SynthaEDR),
    for lab checks of SynthaeaFilter's port (#136, ADR-0012 guardrail 5).
    Lab VM only, elevated.

.DESCRIPTION
    The driver only accepts a client whose token holds the SynthaEDR service
    SID. In production that is the watchdog service and the agent it spawns.
    Here, a throwaway service named SynthaEDR (LocalSystem, `sidtype
    unrestricted`) runs the given script once, its output is collected, and
    the service is deleted.

    The throwaway service is `cmd /c start`, which launches PowerShell
    detached and exits at once: the SCM then gives up on the "service" after
    30 s (error 1053), but the detached PowerShell keeps running with the
    service's token, service SID included, and is not bound by that timeout.

    The target may be a .ps1 script or an executable.

    Refuses to run if a SynthaEDR service already exists (a real watchdog
    install): it never touches that.

.EXAMPLE
    .\run-as-agent.ps1 -Script .\port-check.ps1

.EXAMPLE
    .\run-as-agent.ps1 -Script .\port_probe.exe -Arguments 25
#>
param(
    [Parameter(Mandatory)] [string]$Script,
    [string[]]$Arguments = @(),
    [int]$TimeoutSec = 90
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'SynthaEDR'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run elevated: creating a service needs Administrators.'
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "A '$ServiceName' service already exists (a real watchdog install?). Not touching it."
}

$scriptPath = (Resolve-Path $Script).Path
$workDir = Join-Path $env:ProgramData 'Synthaea\lab'
New-Item -ItemType Directory $workDir -Force | Out-Null
$id = [guid]::NewGuid().ToString('N').Substring(0, 8)
$log = Join-Path $workDir "run-as-agent-$id.log"
$wrapper = Join-Path $workDir "run-as-agent-$id.ps1"

# Arguments become single-quoted PowerShell literals in the wrapper.
$argList = ($Arguments | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ' '

# Runs as the service: the target, then a marker so the caller knows it finished.
@"
`$ErrorActionPreference = 'Continue'
'__RUN_AS_AGENT_STARTED__' | Out-File -Encoding utf8 '$log'
try { & '$scriptPath' $argList *>&1 | Out-File -Append -Encoding utf8 '$log' }
catch { "wrapper error: `$_" | Out-File -Append -Encoding utf8 '$log' }
'__RUN_AS_AGENT_DONE__' | Out-File -Append -Encoding utf8 '$log'
"@ | Set-Content -Path $wrapper -Encoding utf8

# No quotes around the paths: none has spaces, and cmd /c keeps the inner
# quotes of `start ""` only when the command line doesn't start with one.
$cmd = Join-Path $env:WINDIR 'System32\cmd.exe'
$powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach ($p in $cmd, $powershell, $wrapper) {
    if ($p -match '\s') { throw "Path with a space, unsupported here: $p" }
}
$binPath = "$cmd /c start `"`" /b $powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper"

try {
    New-Service -Name $ServiceName -BinaryPathName $binPath -StartupType Manual | Out-Null
    sc.exe sidtype $ServiceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc sidtype failed ($LASTEXITCODE)" }

    # StartService blocks until the SCM times out (1053): expected, see above.
    # Run it in the background so we can watch the log meanwhile.
    $sc = Start-Process sc.exe -ArgumentList 'start', $ServiceName -WindowStyle Hidden -PassThru

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        Start-Sleep -Milliseconds 500
        $done = (Test-Path $log) -and (Select-String -Path $log -Pattern '__RUN_AS_AGENT_DONE__' -Quiet)
    } until ($done -or (Get-Date) -gt $deadline)

    if (-not $done) {
        $started = (Test-Path $log) -and (Select-String -Path $log -Pattern '__RUN_AS_AGENT_STARTED__' -Quiet)
        Write-Warning "No completion marker after $TimeoutSec s (wrapper started: $started); partial output below."
    }
    if (Test-Path $log) {
        Get-Content $log | Where-Object { $_ -notmatch '^__RUN_AS_AGENT_(STARTED|DONE)__$' }
    }
}
finally {
    if ($sc -and -not $sc.HasExited) { $sc.Kill() }
    sc.exe delete $ServiceName | Out-Null
    Remove-Item $wrapper, $log -ErrorAction SilentlyContinue
}
