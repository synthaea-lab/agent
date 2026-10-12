<#
.SYNOPSIS
    Milestone 2a check for SynthaeaFilter's communication port (#136,
    ADR-0012 guardrails 2 and 5). Lab VM only, with the filter loaded.

.DESCRIPTION
    Calls fltlib!FilterConnectCommunicationPort through P/Invoke (no build
    step) and checks that the driver:
      1. accepts a client with the right connection context;
      2. refuses a second client while the first is connected;
      3. refuses a missing context, a wrong size, a wrong magic, a wrong version.
    Those checks need the agent's identity (NT SERVICE\SynthaEDR in the
    token, ADR-0012 guardrail 5): run this script through run-as-agent.ps1.

    Run directly, it checks the two refusals instead:
      - elevated, not the agent: refused by the connect callback (guardrail 5);
      - not elevated: refused by the port's security descriptor.
    Both are "access denied" (0x80070005); DebugView tells them apart (only
    the first logs "not the agent").
#>

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SynPort {
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out IntPtr hPort);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    // ctx == null: no context at all. Otherwise the bytes are sent as-is.
    public static int Connect(byte[] ctx, out IntPtr port) {
        if (ctx == null) {
            return FilterConnectCommunicationPort("\\SynthaeaPort", 0, IntPtr.Zero, 0, IntPtr.Zero, out port);
        }
        IntPtr buf = Marshal.AllocHGlobal(ctx.Length);
        try {
            Marshal.Copy(ctx, 0, buf, ctx.Length);
            return FilterConnectCommunicationPort("\\SynthaeaPort", 0, buf, (ushort)ctx.Length, IntPtr.Zero, out port);
        } finally {
            Marshal.FreeHGlobal(buf);
        }
    }
}
'@

function New-Context([uint32]$Magic, [uint32]$Version) {
    [BitConverter]::GetBytes($Magic) + [BitConverter]::GetBytes($Version)
}

$Magic = [uint32]0x544E5953   # 'SYNT'
$good  = New-Context $Magic 1

# Each check expects one exact HRESULT, not just "failed": a refusal for the
# wrong reason (port missing, driver not loaded) must not read as a pass.
$S_OK           = 0
$E_ACCESSDENIED = [int]0x80070005   # security descriptor (guardrail 5)
$E_COUNT_LIMIT  = [int]0x800704D6   # MaxConnections = 1 (guardrail 5)
$E_INVALIDARG   = [int]0x80070057   # our connect callback (guardrail 2)

function Show([string]$Name, [int]$Hr, [int]$Expected) {
    $verdict = if ($Hr -eq $Expected) { 'PASS' } else { 'FAIL' }
    '{0}  {1,-45} hr=0x{2:X8} (expected 0x{3:X8})' -f $verdict, $Name, $Hr, $Expected
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$me).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
# NT SERVICE\SynthaEDR (`sc showsid SynthaEDR`), mirrored in SynthaeaFilter.c.
$AgentSid = 'S-1-5-80-3000362003-865703788-3960528645-4228801270-24284304'
$isAgent = @($me.Groups | ForEach-Object { $_.Value }) -contains $AgentSid
"user: $($me.Name)  elevated: $elevated  agent SID: $isAgent"

$h1 = [IntPtr]::Zero
$hr = [SynPort]::Connect($good, [ref]$h1)
if ($elevated -and -not $isAgent) {
    Show '1. elevated non-agent client refused (guardrail 5)' $hr $E_ACCESSDENIED
    if ($hr -eq 0) { [void][SynPort]::CloseHandle($h1) }
    'Not the agent: only check 1 applies. Run through run-as-agent.ps1 for the full suite.'
    return
}
if ($elevated) {
    Show '1. good context connects' $hr $S_OK
    if ($hr -ne $S_OK) {
        if ($hr -eq $E_COUNT_LIMIT) {
            'Check 1 failed: another client is still connected (a handle left open in this or another session). Close it or close that PowerShell window, then rerun.'
        } else {
            'Check 1 failed: is the filter loaded (fltmc filters)? Stopping, later checks would be meaningless.'
        }
        return
    }
} else {
    Show '1. non-elevated client refused' $hr $E_ACCESSDENIED
}

if (-not $elevated) {
    'Not elevated: only check 1 applies. Stopping here.'
    if ($hr -eq 0) { [void][SynPort]::CloseHandle($h1) }
    return
}

$h2 = [IntPtr]::Zero
$hr2 = [SynPort]::Connect($good, [ref]$h2)
Show '2. second client refused while first connected' $hr2 $E_COUNT_LIMIT
if ($hr2 -eq 0) { [void][SynPort]::CloseHandle($h2) }
if ($hr -eq 0) { [void][SynPort]::CloseHandle($h1) }
Start-Sleep -Milliseconds 200   # let DisconnectNotify run

$bad = @(
    @{ Name = '3a. no context refused';        Ctx = $null },
    @{ Name = '3b. short context refused';     Ctx = [BitConverter]::GetBytes($Magic) },
    @{ Name = '3c. long context refused';      Ctx = $good + [byte[]](0,0,0,0) },
    @{ Name = '3d. wrong magic refused';       Ctx = New-Context 0x41414141 1 },
    @{ Name = '3e. wrong version refused';     Ctx = New-Context $Magic 2 }
)
foreach ($case in $bad) {
    $h = [IntPtr]::Zero
    $r = [SynPort]::Connect($case.Ctx, [ref]$h)
    Show $case.Name $r $E_INVALIDARG
    if ($r -eq 0) { [void][SynPort]::CloseHandle($h) }
}

$h3 = [IntPtr]::Zero
$hr3 = [SynPort]::Connect($good, [ref]$h3)
Show '4. good context connects again after refusals' $hr3 $S_OK
if ($hr3 -eq 0) { [void][SynPort]::CloseHandle($h3) }
