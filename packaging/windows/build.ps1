<#
.SYNOPSIS
    Builds the Synthaea agent MSI (#37) with WiX v3 (candle.exe + light.exe).

.DESCRIPTION
    Requires a release build already on disk (cargo build --release -p agent
    -p watchdog, from the repo root) and WiX v3 installed - see README.md in
    this directory for the install command. Not idempotent in a meaningful
    sense (each run just overwrites out\SynthaeaAgent.msi); safe to re-run.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$release = Join-Path $repoRoot "target\release"

foreach ($exe in @("agent.exe", "watchdog.exe")) {
    $path = Join-Path $release $exe
    if (-not (Test-Path $path)) {
        throw "missing $path - run: cargo build --release -p agent -p watchdog"
    }
}

$wixBin = "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin"
$candle = Join-Path $wixBin "candle.exe"
$light = Join-Path $wixBin "light.exe"
foreach ($tool in @($candle, $light)) {
    if (-not (Test-Path $tool)) {
        throw "$tool not found - install WiX v3 first (see README.md in this directory)"
    }
}

$outDir = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$wixobj = Join-Path $outDir "Product.wixobj"
$msi = Join-Path $outDir "SynthaeaAgent.msi"
$wxs = Join-Path $PSScriptRoot "Product.wxs"

Write-Host "[info] candle: $wxs -> $wixobj"
& $candle "-dRepoRoot=$repoRoot" -out $wixobj $wxs
if ($LASTEXITCODE -ne 0) {
    throw "candle.exe failed with exit code $LASTEXITCODE"
}

Write-Host "[info] light: $wixobj -> $msi"
& $light -out $msi $wixobj
if ($LASTEXITCODE -ne 0) {
    throw "light.exe failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Built: $msi"
Write-Host "Install (elevated):   msiexec /i `"$msi`" /quiet /l*v install.log"
Write-Host "Uninstall (elevated): msiexec /x `"$msi`" /quiet /l*v uninstall.log"
