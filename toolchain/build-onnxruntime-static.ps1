<#
.SYNOPSIS
    Builds onnxruntime v1.30.0 from source as static .lib files for Windows
    (MSVC), implementing ADR-0002 decision #2 (static linking, single-binary
    deployment). Windows counterpart of build-onnxruntime-static.sh (#337).

.DESCRIPTION
    This script only builds onnxruntime. Run ort-static-link-flags.ps1 next to
    turn the result into RUSTFLAGS, then build the `ml` crate with
    `--no-default-features` (see lab/provisioning/onnxruntime-static-build.md).

    The build is CPU-only on purpose: no DirectML, no CUDA. The prebuilt
    archive the `dynamic-onnx` dev feature downloads links DirectML, and the
    agent then imports directml.dll, d3d12.dll and dxgi.dll for an execution
    provider it never uses. The C runtime stays the default dynamic one (/MD),
    the same as rustc's MSVC target; mixing /MT libraries into a Rust binary
    fails at link time with duplicate CRT symbols.

    Prerequisites: Visual Studio 2022 Build Tools with the "Desktop
    development with C++" workload (MSVC 14.3x and a Windows SDK), Git and
    Python 3 on PATH. CMake is taken from PATH, else from the Build Tools.

    Output: .\onnxruntime\build\Windows\Release\Release\*.lib

.PARAMETER Clean
    Remove an existing onnxruntime checkout before cloning.

.PARAMETER Jobs
    Parallel build jobs (default: number of logical processors).

.EXAMPLE
    .\lab\provisioning\build-onnxruntime-static.ps1
    $env:ORT_LIB_LOCATION = "$PWD\onnxruntime\build\Windows\Release\Release"
    .\lab\provisioning\ort-static-link-flags.ps1 | Invoke-Expression
    cargo test -p ml --release --no-default-features
#>

[CmdletBinding()]
param(
    [switch]$Clean,
    [int]$Jobs = [Environment]::ProcessorCount
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$OnnxDir = Join-Path $RepoRoot 'onnxruntime'
$OnnxVersion = 'v1.30.0'

# onnxruntime's generated .vcxproj passes /DEF: paths unquoted, so a space anywhere in
# the build path fails deep inside MSVC with `LNK1181: cannot open input file
# '<second word of the path>\...\symbols.def'` (seen under a profile directory named
# "First Last", review of #692), and the link flags cannot carry a space either. Say
# so before a 40-minute build, not after.
if ($OnnxDir -match '\s') {
    throw "The build path contains a space: $OnnxDir. Check the repository out under a space-free path (for example C:\src\edr) and run this script from there."
}

function Assert-Tool([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name not found on PATH. $Hint"
    }
}

Assert-Tool 'git' 'Install Git for Windows.'
Assert-Tool 'python' 'Install Python 3 and tick "Add to PATH".'

# Visual Studio Build Tools: the generator and the C++ toolset must be there
# before onnxruntime's build.bat runs, which would otherwise fail deep inside
# CMake with a message about a missing generator.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw 'vswhere.exe not found: install Visual Studio 2022 Build Tools (C++ workload).'
}
$vsPath = & $vswhere -latest -products * -version '[17.0,18.0)' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) {
    throw 'No Visual Studio 2022 (17.x) with the MSVC x64 toolset (Microsoft.VisualStudio.Component.VC.Tools.x86.x64) found; the CMake generator is forced to Visual Studio 17 2022.'
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $vsCmake = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    if (-not (Test-Path (Join-Path $vsCmake 'cmake.exe'))) {
        throw 'cmake not found on PATH or in the Build Tools. Install CMake 3.28+ or the "C++ CMake tools for Windows" component.'
    }
    $env:PATH = "$vsCmake;$env:PATH"
}

Write-Host '[onnxruntime] Building static libraries for ADR-0002 (issue #337)'
Write-Host "  Version: $OnnxVersion"
Write-Host "  Visual Studio: $vsPath"
Write-Host "  Jobs: $Jobs"

if ($Clean -and (Test-Path $OnnxDir)) {
    Write-Host "[onnxruntime] Removing existing checkout: $OnnxDir"
    Remove-Item -Recurse -Force $OnnxDir
}

if (-not (Test-Path $OnnxDir)) {
    Write-Host "[onnxruntime] Cloning $OnnxVersion (shallow clone)"
    git clone --depth 1 --branch $OnnxVersion https://github.com/microsoft/onnxruntime.git $OnnxDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
} else {
    Write-Host "[onnxruntime] Using existing checkout: $OnnxDir"
}

Push-Location $OnnxDir
try {
    # --compile_no_warning_as_error: a newer MSVC than the one onnxruntime was
    # validated with can raise warnings it promotes to errors; same reason the
    # Linux build passes it (#647).
    Write-Host '[onnxruntime] Building (30 to 90 minutes on a cold cache)'
    & .\build.bat `
        --config Release `
        --update --build `
        --parallel $Jobs `
        --no_telemetry `
        --skip_tests `
        --compile_no_warning_as_error `
        --cmake_generator 'Visual Studio 17 2022' `
        --cmake_extra_defines onnxruntime_BUILD_UNIT_TESTS=OFF
    if ($LASTEXITCODE -ne 0) { throw "onnxruntime build.bat failed (exit $LASTEXITCODE)" }

    # re2 is an orphaned CMake target in a static-only build: the CPU provider
    # only takes its include path and never links it, so nothing schedules it,
    # and ort-sys then fails with "could not find native static library re2"
    # (same cause as the Linux build). It lives in a sub-project, which
    # `cmake --build --target re2` does not find with the Visual Studio
    # generator, so build its project file directly.
    $re2Project = Join-Path $OnnxDir 'build\Windows\Release\_deps\re2-build\re2.vcxproj'
    if (-not (Test-Path $re2Project)) { throw "re2 project not found: $re2Project" }
    $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    Write-Host '[onnxruntime] Building re2 explicitly'
    & $msbuild $re2Project /p:Configuration=Release /m /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "building re2 failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$BuildDir = Join-Path $OnnxDir 'build\Windows\Release\Release'
$libs = @(Get-ChildItem -Path (Join-Path $OnnxDir 'build\Windows\Release') -Recurse -Filter '*.lib' -ErrorAction SilentlyContinue)
if ($libs.Count -eq 0) {
    throw "No .lib files found under $OnnxDir\build\Windows\Release. The build may have failed silently; check the log above."
}

Write-Host '[onnxruntime] Build complete'
Write-Host "  Static libraries: $($libs.Count) .lib files"
Write-Host "  Location: $BuildDir"
Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. `$env:ORT_LIB_LOCATION = `"$BuildDir`""
Write-Host '  2. .\lab\provisioning\ort-static-link-flags.ps1 | Invoke-Expression'
Write-Host '  3. cargo test -j 1 -p ml --release --no-default-features'
Write-Host '  4. Check the result has no onnxruntime, directml or d3d12 dependency:'
Write-Host '       python tools\check-pe-imports.py target\release\deps\ml-*.exe'
