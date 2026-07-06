# Install a development build of Rayhunter to a device.
# Run .\scripts\build-dev.ps1 first.
#
# Usage: .\scripts\install-dev.ps1 <device> [options...]
# Example: .\scripts\install-dev.ps1 orbic --admin-password mypass

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectDir

# Building the installer compiles bundled libusb C code with gcc from PATH.
# Git for Windows ships its own mingw64\bin with older copies of gcc's
# dependency DLLs; if it precedes the real mingw toolchain on PATH, cc1.exe
# fails with STATUS_ENTRYPOINT_NOT_FOUND and no error message. Prepending
# gcc's own directory makes its DLLs win the search order.
$gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
if ($gcc) {
    $gccDir = Split-Path $gcc.Source
    if (($env:PATH -split ';')[0] -ne $gccDir) {
        $env:PATH = "$gccDir;$env:PATH"
    }
}

cargo run -p installer --bin installer -- @args
exit $LASTEXITCODE
