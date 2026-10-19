<#
.SYNOPSIS
    Builds the Synthaea agent MSI (#37) with WiX v3 (candle.exe + light.exe).

.DESCRIPTION
    Requires a release build already on disk, WITHOUT the public test signing key
    (cargo build --release --no-default-features --features agent/dynamic-onnx
    -p agent -p watchdog, from the repo root; ADR-0027, #753) and WiX v3 installed -
    see README.md in this directory for the install command. The script refuses
    to build the MSI from binaries that carry the test key. Not idempotent in a meaningful
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
        throw "missing $path - run: cargo build --release --no-default-features --features agent/dynamic-onnx -p agent -p watchdog"
    }
}

# The shipped artifacts must not carry the public test signing key (ADR-0027, #753): the
# marker the updater's `test-key` feature links in is looked up in the binaries themselves,
# the same check tools/assert-no-test-key.sh makes for the Linux packages. Latin-1 (code
# page 28591, available on Windows PowerShell 5.1 as well as PowerShell 7) maps each byte
# to one character, so the ASCII marker is found wherever it sits in the file.
$testKeyMarker = "SYNTHAEA-PUBLIC-TEST-KEY-SET-V1"
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
foreach ($exe in @("agent.exe", "watchdog.exe")) {
    $path = Join-Path $release $exe
    if ((Get-Item $path).Length -eq 0) {
        throw "$path is empty: nothing was checked for the test signing key"
    }
    $text = $latin1.GetString([System.IO.File]::ReadAllBytes($path))
    if ($text.Contains($testKeyMarker)) {
        throw "$path carries the public test signing key set. Rebuild without default features: cargo build --release --no-default-features --features agent/dynamic-onnx -p agent -p watchdog"
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
