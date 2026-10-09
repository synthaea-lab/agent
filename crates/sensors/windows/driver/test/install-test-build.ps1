<#
.SYNOPSIS
    Installs a SynthaeaFilter build on the lab VM and proves which binary
    `fltmc load` will run (#136). Lab VM only, elevated, test-signing on.

.DESCRIPTION
    The INF installs the driver into the driver store and points the
    service's ImagePath there, so copying a .sys over
    System32\drivers\SynthaeaFilter.sys changes nothing: that file is never
    loaded. This script unloads the filter, installs the package with
    pnputil, then checks the SHA-256 of the file ImagePath actually names
    against the package's .sys, and stops if they differ.

.PARAMETER Package
    Folder holding SynthaeaFilter.inf, synthaeafilter.cat and SynthaeaFilter.sys.

.EXAMPLE
    .\install-test-build.ps1 -Package $env:USERPROFILE\Desktop\SynthaeaLab
#>
param([Parameter(Mandatory)] [string]$Package)

$ErrorActionPreference = 'Stop'

$inf = Join-Path $Package 'SynthaeaFilter.inf'
$sys = Join-Path $Package 'SynthaeaFilter.sys'
foreach ($f in $inf, $sys) { if (-not (Test-Path $f)) { throw "Missing $f" } }
$expected = (Get-FileHash $sys).Hash

fltmc unload SynthaeaFilter 2>$null | Out-Null

pnputil /add-driver $inf /install | Out-Null
if ($LASTEXITCODE -ne 0) { throw "pnputil failed ($LASTEXITCODE)" }

$image = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SynthaeaFilter').ImagePath
$resolved = $image -replace '^\\SystemRoot', $env:WINDIR -replace '^\\\?\?\\', ''
if ($resolved -notmatch '^[A-Za-z]:') { $resolved = Join-Path $env:WINDIR $resolved }
$loaded = (Get-FileHash $resolved).Hash

"ImagePath: $image"
"package  SHA-256: $expected"
"ImagePath SHA-256: $loaded"
if ($loaded -ne $expected) {
    throw 'ImagePath does not point at this build: fltmc load would run another binary.'
}
'OK: fltmc load SynthaeaFilter will run this build.'
