<#
.SYNOPSIS
    Prints the RUSTFLAGS needed to statically link a source-built onnxruntime
    into the `ml` crate on Windows (MSVC). Windows counterpart of
    ort-static-link-flags.sh (#337, ADR-0002).

.DESCRIPTION
    `ort-sys` v2.0.0-rc.13 hardcodes the list of static libraries it links, and
    that list is incomplete for onnxruntime 1.30.0 built from source (see #110):
    the build produces many abseil sub-libraries, utf8_range and model_package
    that really are linked into onnxruntime's own libraries but sit in
    directories ort-sys never searches. Rather than keep a list that drifts with
    every onnxruntime release, this walks $env:ORT_LIB_LOCATION for every .lib
    the build produced and emits `-L native=<dir>` for its directory and
    `-C link-arg=<path>` for it (not `-l static=`, which bundles every library into
    every crate's rlib; see the comment in the script body).

    As on Linux, re2 is never scheduled by onnxruntime's own build graph, so
    its .lib does not exist until it is built explicitly;
    build-onnxruntime-static.ps1 does that. Without it ort-sys stops with
    "could not find native static library `re2`".

    Output is one line that sets $env:RUSTFLAGS, meant to be piped to
    Invoke-Expression. A summary goes to the error stream so it does not end up
    in the expression. RUSTFLAGS is split on whitespace, so a path containing a
    space does not work: build onnxruntime under a space-free path.

.EXAMPLE
    $env:ORT_LIB_LOCATION = "$PWD\onnxruntime\build\Windows\Release\Release"
    .\lab\provisioning\ort-static-link-flags.ps1 | Invoke-Expression
    cargo build -p ml --release --no-default-features
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if (-not $env:ORT_LIB_LOCATION) {
    throw 'set ORT_LIB_LOCATION to the onnxruntime build\Windows\Release\Release directory'
}
if (-not (Test-Path $env:ORT_LIB_LOCATION -PathType Container)) {
    throw "ORT_LIB_LOCATION does not exist: $env:ORT_LIB_LOCATION"
}

# The Visual Studio generator writes one Release\ folder per target under
# build\Windows\Release, so search from the parent of ORT_LIB_LOCATION when it
# points at the main output folder.
$root = $env:ORT_LIB_LOCATION
$parent = Split-Path $root -Parent
if ((Split-Path $root -Leaf) -eq 'Release' -and (Split-Path $parent -Leaf) -eq 'Release') {
    $root = $parent
}

$libs = @(Get-ChildItem -Path $root -Recurse -Filter '*.lib' | Sort-Object FullName)
if ($libs.Count -eq 0) {
    throw "no .lib files found under $root - did the build actually run?"
}

$dirs = [ordered]@{}
$names = [ordered]@{}
$flags = New-Object System.Collections.Generic.List[string]

foreach ($lib in $libs) {
    $dir = $lib.DirectoryName
    $name = $lib.BaseName
    if ($dir -match '\s') {
        throw "library directory contains a space, RUSTFLAGS cannot carry it: $dir"
    }
    if (-not $dirs.Contains($dir)) {
        $flags.Add('-L'); $flags.Add("native=$dir")
        $dirs[$dir] = $true
    }
    if (-not $names.Contains($name)) {
        # Each library goes to the linker as a path (-C link-arg), not as
        # `-l static=<name>`. RUSTFLAGS reaches every crate, and `-l static=`
        # bundles the library into each rlib: 101 libraries (1.1 GB) grew a
        # target directory to 276 GB and filled the disk. `-l static:-bundle=`
        # avoids that but is refused for any library ort-sys also names itself
        # ("overriding linking modifiers from command line is not supported"),
        # and ort-sys names most of them. A plain link argument has neither
        # problem: nothing is copied, and a library given twice is ignored.
        $flags.Add('-C'); $flags.Add("link-arg=$($lib.FullName)")
        $names[$name] = $true
    }
}

# onnxruntime's own objects call Win32 functions that Rust's MSVC target does
# not link by default: telemetry.cc uses CommandLineToArgvW (shell32), and the
# link fails with "LNK2019 unresolved external symbol __imp_CommandLineToArgvW"
# otherwise. A prebuilt download carries this in ort-sys's own list; a source
# build does not. shell32.dll is a system DLL present on every Windows install.
$flags.Add('-l'); $flags.Add('dylib=shell32')

Write-Output ('$env:RUSTFLAGS = "' + ($flags -join ' ') + '"')
[Console]::Error.WriteLine("# $($dirs.Count) directories, $($names.Count) libraries")
