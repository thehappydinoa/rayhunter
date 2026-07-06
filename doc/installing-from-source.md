# Installing from source

Building Rayhunter from source, either for development or otherwise, involves a
number of external dependencies. Unless you need to do this, we recommend you
use our [compiled builds](https://github.com/EFForg/rayhunter/releases).

At a high level, we have:

* A JS frontend written in SvelteKit (`./daemon/web/`)
* A Rust binary `rayhunter-daemon` (`./daemon/`) that runs on the device, and bundles the frontend.
* A Rust binary `installer` (`./installer`) that runs on the computer and bundles `rayhunter-daemon`.

It's recommended to work either on Mac/Linux, natively on Windows (see
[Building on Windows](#building-on-windows) below), or WSL on Windows.

## Building frontend and backend

First, install dependencies:

- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js/npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
- C compiler tools (`apt install build-essential` on Linux, `xcode-select --install` on Mac)

Then you can build everything with:

```sh
./scripts/build-dev.sh
./scripts/install-dev.sh orbic  # replace 'orbic' with your device type
```

## Building on Windows

Rayhunter can be built and installed natively on Windows (no WSL required)
using the PowerShell equivalents of the build scripts:

```powershell
.\scripts\build-dev.ps1
.\scripts\install-dev.ps1 orbic  # replace 'orbic' with your device type
```

Prerequisites:

- [Rust](https://www.rust-lang.org/tools/install) via rustup
- [Node.js/npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
- A C compiler for the installer's bundled libusb:
  - with the MSVC host toolchain (rustup's default on Windows), install the
    [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
    (which rustup prompts for anyway);
  - with the GNU host toolchain, install MSYS2's
    `mingw-w64-x86_64-gcc` package and put `C:\msys64\mingw64\bin` on `PATH`.

The daemon and rootshell cross-compile to ARM with Rust's built-in `rust-lld`
linker, so no ARM C cross-compiler is needed. The WiFi tools
(`wpa_supplicant`, `wpa_cli`, `iw`) cannot be built natively on Windows; the
build script skips them and the installer will warn if a device needs them.
Build them in WSL, or use a release artifact, if you need the WiFi client
feature.

For fast development iteration on a device that already has Rayhunter and ADB
access, `make.ps1` (the Windows counterpart of `make.sh`) rebuilds the daemon
and pushes it over ADB. Note that `adb push` from Windows cannot preserve the
executable bit, so the daemon must be `chmod 755`'d after pushing —
`make.ps1` handles this.

Known pitfall: Git for Windows ships its own `mingw64\bin` with older copies
of gcc's dependency DLLs. If it precedes the MSYS2 toolchain on `PATH`, gcc's
`cc1.exe` fails with `STATUS_ENTRYPOINT_NOT_FOUND` and cc-rs reports an opaque
"Compiler family detection failed" error. The PowerShell scripts work around
this automatically by prepending gcc's own directory to `PATH`.

## Running the daemon on your PC

If you don't have a target device handy, you can run `rayhunter-daemon` on your
PC with `debug_mode = true`. This skips DIAG, the device display, key input,
the battery worker, and the WiFi client, so recording-related endpoints will
not work, but the frontend and read-only APIs do.

```sh
mkdir -p ./qmdl && printf 'entries = []\n' > ./qmdl/manifest.toml
cat > config.toml <<'EOF'
qmdl_store_path = "./qmdl"
port = 8080
debug_mode = true
EOF
cargo run -p rayhunter-daemon -- ./config.toml
```

Open `http://127.0.0.1:8080`.

## Hot-reloading the frontend

If you are working on the frontend, you normally have to repeat all of the above steps everytime to see a change.

You can instead run the frontend separately on your PC while the Rust parts
continue running on your target device:

```sh
cd daemon/web

# Assumes rayhunter-daemon is listening on localhost:8080
npm run dev

# Use a custom target IP:port where the backend runs
API_TARGET=http://192.168.1.1:8080 npm run dev
```

The UI will listen on `localhost:5173` and instantly show any frontend changes
you make. Backend changes require building everything from the top (daemon and installer).

## Installer utils, getting a shell

Check `./scripts/install-dev.sh util --help`
for useful utilities for transferring files, opening shells. The exact tools
available wildly depend on the device you're working on, and they are
usually documented the relevant device's page under [Supported
Devices](./supported-devices.md).

A lot of devices run a trimmed down version of Android and have ADB (Android
Debug Bridge) support. The USB-based installers (`orbic-usb`, `pinephone`,
`uz801`) use ADB to perform the installation.

You might want to install and use actual ADB to connect to the device, push
files and generally poke around. The installer contains some tools to enable ADB:

```sh
adb kill-server

# Enables ADB on either of these devices
./scripts/install-dev.sh util tmobile-start-adb
./scripts/install-dev.sh orbic-usb

adb shell
```

Note though that we can't assist with any issues setting ADB up, _especially
not_ on Windows. There have been too many driver issues to make this the
"golden path" for most users or contributors. There have been instances where
people managed to brick their orbic devices using ADB on Windows.

## Troubleshooting

You may need to turn off your VPN in order to load the frontend succesfully - even with local network sharing enabled, VPNs can interfere with the connection to the backend.

Specifically for WSL users:

- The HyperV firewall also tends to interfere with the connection between frontend and backend. You can turn it off in your WSL settings.

- WSL2 has a known compatibility issue which may prevent vite from detecting file system changes and therefore affects HMR (hot module replacement).
If your hot reloading does not work, some have success using polling to detect changes. To do so, specify the following setting in vite.config.ts:
```ts
server: {
    watch: { usePolling: true }
}
```