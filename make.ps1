# Windows counterpart of make.sh: rebuild the daemon and hot-push it to a
# device over ADB. Requires adb on PATH and a device with Rayhunter (and
# therefore /bin/rootshell) already installed.
$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot\daemon\web
try {
    npm install
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    npm run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

Set-Location $PSScriptRoot
cargo build-daemon-firmware-devel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

adb shell '/bin/rootshell -c "/etc/init.d/rayhunter_daemon stop"'
adb push target/armv7-unknown-linux-musleabihf/firmware-devel/rayhunter-daemon `
    /data/rayhunter/rayhunter-daemon
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# adb push from Windows cannot preserve an executable bit (NTFS has none), so
# the pushed file lands as 0666 and the daemon would fail to start on boot.
# chmod as the plain adb user: it owns the file, and rootshell's chmod can be
# denied here.
adb shell 'chmod 755 /data/rayhunter/rayhunter-daemon'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "rebooting the device..."
adb shell '/bin/rootshell -c "reboot"'
