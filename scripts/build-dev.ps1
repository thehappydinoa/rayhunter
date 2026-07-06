# Build Rayhunter from source for development on Windows.
# Prerequisites: Rust (rustup) and Node.js (npm).
#
# Usage: .\scripts\build-dev.ps1 [build|frontend|check]

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir

# Crates with bundled C code (e.g. the installer's libusb) compile with gcc
# from PATH. Git for Windows ships its own mingw64\bin with older copies of
# gcc's dependency DLLs; if it precedes the real mingw toolchain on PATH,
# cc1.exe fails with STATUS_ENTRYPOINT_NOT_FOUND and no error message.
# Prepending gcc's own directory makes its DLLs win the search order.
$gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
if ($gcc) {
    $gccDir = Split-Path $gcc.Source
    if (($env:PATH -split ';')[0] -ne $gccDir) {
        $env:PATH = "$gccDir;$env:PATH"
    }
}

function Check-Dependencies {
    $missing = $false

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Host "Error: cargo not found. Install Rust via https://www.rust-lang.org/tools/install"
        $missing = $true
    }

    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host "Error: npm not found. Install Node.js via https://docs.npmjs.com/downloading-and-installing-node-js-and-npm"
        $missing = $true
    }

    if ($missing) {
        exit 1
    }

    # Ensure the ARM cross-compilation target is installed
    $targets = rustup target list --installed
    if ($targets -notcontains "armv7-unknown-linux-musleabihf") {
        Write-Host "Installing ARM target (armv7-unknown-linux-musleabihf)..."
        rustup target add armv7-unknown-linux-musleabihf
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

function Build-Frontend {
    Write-Host "Building web frontend..."
    Push-Location daemon/web
    try {
        npm install
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm run build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
}

function Build-WifiTools {
    if ((Test-Path "tools/build-wpa-supplicant/out/wpa_supplicant") -and
        (Test-Path "tools/build-wpa-supplicant/out/wpa_cli") -and
        (Test-Path "tools/build-wpa-supplicant/out/iw")) {
        Write-Host "WiFi tools already built, skipping."
        return
    }

    # The WiFi tools (wpa_supplicant, wpa_cli, iw) require a musl C
    # cross-compiler, which is not readily available on Windows. They are only
    # needed for the WiFi client feature on some devices; the installer will
    # warn if they are missing.
    Write-Host "Warning: Skipping WiFi tools; building them is not supported on Windows."
    Write-Host "If you need them, build in WSL or download a release artifact."
}

function Build-Daemon {
    Write-Host "Building daemon..."
    cargo build-daemon-firmware-devel
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "Building rootshell..."
    cargo build-rootshell-firmware-devel
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$Command = if ($args.Count -ge 1) { $args[0] } else { "build" }

switch ($Command) {
    "build" {
        Check-Dependencies
        Build-Frontend
        Build-WifiTools
        Build-Daemon
        Write-Host ""
        Write-Host "Build complete! To install to a device, run:"
        Write-Host "  .\scripts\install-dev.ps1 <device>"
        Write-Host ""
        Write-Host "Replace <device> with your device type (e.g. orbic, tplink)."
    }
    "frontend" {
        Build-Frontend
    }
    "check" {
        Check-Dependencies
    }
    { $_ -in "help", "--help", "-h" } {
        Write-Host "Usage: .\scripts\build-dev.ps1 [command]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  build     Build frontend, daemon, and rootshell (default)"
        Write-Host "  frontend  Build only the web frontend"
        Write-Host "  check     Check dependencies only"
    }
    default {
        Write-Host "Unknown command: $Command"
        Write-Host "Run '.\scripts\build-dev.ps1 help' for usage."
        exit 1
    }
}
