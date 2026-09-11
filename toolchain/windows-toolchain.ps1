<#
.SYNOPSIS
    Provisioning for the lab's Windows VMs (#22): Rust + MSVC linker/Windows SDK
    toolchain for building `agent`/`watchdog` with the ETW and Windows Event
    Log sensors, and the Windows service (SCM) support the watchdog needs.

.DESCRIPTION
    Provider-neutral, like ../MATRIX.md and lab/provisioning/linux-toolchain.sh:
    a harness (Vagrant winrm provisioner, a plain `Invoke-Command` over
    WinRM/PSRemoting, a cloud-init-equivalent user-data script) is only
    responsible for running this inside the VM. Idempotent - safe to re-run
    (e.g. `vagrant provision win11`) without redoing already-completed steps.

    Unlike the Linux eBPF toolchain, nothing here needs a specific LLVM/kernel
    version: `windows-sys`/`ferrisetw` (ETW) and `windows-service` (SCM) are
    pure-Rust FFI bindings against DLLs Windows already ships (advapi32,
    kernel32, ...) - the only extra piece beyond Rust itself is the MSVC
    linker + Windows SDK (`link.exe`, import libs), which on Windows comes
    from Visual Studio's Build Tools, not from Rust or cargo.
#>

[CmdletBinding()]
param(
    # Skips the Build Tools install step (useful on a box that already has a
    # full Visual Studio install with the C++ workload).
    [switch]$SkipBuildTools
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest's progress bar is very slow over winrm.

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

# -- Git ---------------------------------------------------------------------
# Mirrors linux-toolchain.sh's package list (which includes git): a fresh lab
# VM has no git, and getting the repo onto it is the very first thing every
# workflow after this script needs (clone, `vagrant rsync`-less winrm setups,
# CI checkouts). winget ships on Windows 10 2004+/11 but NOT on most Windows
# Server images (confirmed missing on winserver in #22 testing) - falls back
# to a pinned Git for Windows installer in that case rather than resolving
# "latest" (matches rustup-init/vs_buildtools below: a fixed, known-good URL).
Write-Section "Git"

if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "[ok] git already installed ($((Get-Command git).Source))"
} elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "[info] installing git via winget"
    winget install --id Git.Git -e --source winget `
        --accept-package-agreements --accept-source-agreements --silent
    if ($LASTEXITCODE -ne 0) {
        throw "winget install Git.Git failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[info] winget not present (common on Server images) - installing Git for Windows directly"
    $gitInstaller = Join-Path $env:TEMP "git-for-windows.exe"
    Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe" `
        -OutFile $gitInstaller
    # /VERYSILENT: Inno Setup's unattended flag (Git for Windows is built with
    # Inno Setup, not MSI - different silent-install convention than
    # vs_buildtools.exe below). /NORESTART: same reasoning as Build Tools.
    $proc = Start-Process -FilePath $gitInstaller -ArgumentList @(
        "/VERYSILENT", "/NORESTART", "/NOCANCEL", "/SP-", "/CLOSEAPPLICATIONS"
    ) -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        throw "Git for Windows installer failed with exit code $($proc.ExitCode)"
    }
    Write-Host "[ok] Git for Windows installed"
}

# Same reasoning as cargo's bin dir below: a fresh install doesn't update
# PATH in this already-running process.
$gitBin = "${env:ProgramFiles}\Git\cmd"
if ((-not (Get-Command git -ErrorAction SilentlyContinue)) -and (Test-Path $gitBin)) {
    $env:Path = "$gitBin;$env:Path"
}
if (Get-Command git -ErrorAction SilentlyContinue) {
    git --version
} else {
    Write-Host "[warn] git installed but not resolvable on PATH in this session - a new shell should see it" -ForegroundColor Yellow
}

# -- Rust (rustup) ----------------------------------------------------------
Write-Section "Rust (rustup, stable-msvc)"

$cargoHome = Join-Path $env:USERPROFILE ".cargo"
$cargoExe = Join-Path $cargoHome "bin\cargo.exe"

if (-not (Test-Path $cargoExe)) {
    $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
    Write-Host "[info] downloading rustup-init.exe"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" `
        -OutFile $rustupInit
    # -y: no interactive prompts. --default-host pins the MSVC toolchain (the
    # one that actually links against the Windows SDK below) rather than
    # letting rustup guess.
    & $rustupInit -y --default-host x86_64-pc-windows-msvc --default-toolchain stable --profile default
    if ($LASTEXITCODE -ne 0) {
        throw "rustup-init failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "[ok] cargo already installed ($cargoExe)"
}

# rustup/cargo's bin dir needs to be on PATH for the rest of this script (a
# fresh install doesn't take effect in the current process) and for every
# later provisioning step / interactive session.
$cargoBin = Join-Path $cargoHome "bin"
if ($env:Path -notlike "*$cargoBin*") {
    $env:Path = "$cargoBin;$env:Path"
}
[Environment]::SetEnvironmentVariable(
    "Path",
    "$cargoBin;" + [Environment]::GetEnvironmentVariable("Path", "User"),
    "User"
)

& "$cargoBin\rustc.exe" --version
& "$cargoBin\cargo.exe" --version

# -- MSVC Build Tools + Windows SDK -----------------------------------------
# The Rust MSVC toolchain (the rustup default above) links with `link.exe`
# from Visual Studio's C++ toolset, plus the Windows SDK import libraries
# (kernel32.lib, advapi32.lib, ...) that windows-sys/windows-service bind
# against - neither ships with Rust itself. `vswhere` (installed by any VS
# product since 2017, including Build Tools) is the supported way to check
# what's already there before downloading anything.
if ($SkipBuildTools) {
    Write-Section "MSVC Build Tools + Windows SDK (skipped: -SkipBuildTools)"
} else {
    Write-Section "MSVC Build Tools + Windows SDK"

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vcToolsPresent = $false
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath
        $vcToolsPresent = -not [string]::IsNullOrWhiteSpace($found)
    }

    if ($vcToolsPresent) {
        Write-Host "[ok] MSVC C++ toolset already installed ($found)"
    } else {
        Write-Host "[info] installing Visual Studio Build Tools (VCTools workload + Windows 11 SDK)"
        $bootstrapper = Join-Path $env:TEMP "vs_buildtools.exe"
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $bootstrapper

        # --wait: the harness's provisioning step must block until this is
        # actually done, not just launched. --norestart: a mid-provisioning
        # reboot would silently truncate the rest of this script; if one
        # really is required, the exit code below says so explicitly instead.
        $proc = Start-Process -FilePath $bootstrapper -ArgumentList @(
            "--quiet", "--wait", "--norestart",
            "--add", "Microsoft.VisualStudio.Workload.VCTools",
            "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
            "--includeRecommended"
        ) -PassThru -Wait

        # 3010 = ERROR_SUCCESS_REBOOT_REQUIRED - installed fine, but a reboot
        # is pending; still a success for provisioning purposes.
        if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
            throw "vs_buildtools.exe failed with exit code $($proc.ExitCode)"
        }
        if ($proc.ExitCode -eq 3010) {
            Write-Host "[warn] Build Tools installed but a reboot is pending - reboot before building" -ForegroundColor Yellow
        } else {
            Write-Host "[ok] Build Tools installed"
        }
    }
}

# -- Verification ------------------------------------------------------------
Write-Section "Verification"

# link.exe itself only resolves inside a "Developer" shell (vcvarsall.bat sets
# up its own PATH/INCLUDE/LIB) - a plain build works because cargo's MSVC
# linker-search (via the `cc`/`link-args` machinery in rustc, which shells out
# to `vswhere`-discovered paths itself) doesn't need this script's shell to
# already have it on PATH. This check just confirms *something* would find
# it, so a broken install fails here instead of confusingly deep in a `cargo
# build`.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $installPath = & $vswhere -latest -products * -property installationPath
    if ($installPath) {
        Write-Host "[ok] Visual Studio / Build Tools at $installPath"
    } else {
        Write-Host "[warn] vswhere found no VC++ installation - a `cargo build` will fail to link" -ForegroundColor Yellow
    }
} else {
    Write-Host "[warn] vswhere.exe not found - cannot confirm the MSVC toolset is installed" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "== Done ==" -ForegroundColor Cyan
Write-Host "Open a new shell (PATH changes need a fresh session) and build with:"
Write-Host "  cargo build --release -p agent -p watchdog"
