# netvis (C++ rewrite)

GlassWire-style per-process bandwidth monitor, DNS ad/tracker blocker, and
per-process firewall for Windows. This is a from-scratch C++ port of the
original Go version (`../netvis`), using [Dear ImGui](https://github.com/ocornut/imgui)
(Win32 + DirectX11 backend) instead of Fyne, and WinDivert loaded dynamically
via `LoadLibrary`/`GetProcAddress` (no official WinDivert SDK/headers needed
to build - just `WinDivert.dll` + `WinDivert64.sys` sitting next to the exe
at runtime, same as the Go version).

## Build

Requires Visual Studio with the "Desktop development with C++" workload
(the Community edition is fine and free).

Right-click `build_and_run.bat` → **Run as administrator**, then check
`build.log` for compiler output and `output.log`/`netvis.log` for what the
app did when it ran. WinDivert requires Administrator to open its driver
handle, so the exe has to be launched elevated - building doesn't need
elevation, but this script also launches the exe right after building, so
just run the whole thing elevated.

If you'd rather build without running: open a "Developer Command Prompt for
VS", `cd` into this folder, and run the `cl.exe` command from
`build_and_run.bat` by hand.

## What it does

- **Bandwidth monitor**: sniffs all IPv4/IPv6 traffic at the WinDivert
  network layer (non-intercepting - just watching), maps each packet to
  the owning process via `GetExtendedTcpTable`/`GetExtendedUdpTable`, and
  shows a live per-process table plus a GlassWire-style rolling graph.
- **Ad/tracker blocker**: intercepts plain DNS (UDP 53) and spoofs an
  NXDOMAIN reply for blocklisted domains (IPv4 only in v1); drops
  DNS-over-TLS (TCP 853) outright since it can't be inspected; drops
  DNS-over-HTTPS by blocking known public resolver IPs on TCP 443. Add your
  own entries via `blocklist.txt` / `allowlist.txt` next to the exe (one
  domain per line, `#` for comments) - these merge with the built-in
  defaults in `src/blocklist.h`.
- **Per-process block**: click Block next to any process. This does two
  things at once - opens a SOCKET-layer WinDivert handle scoped to that
  PID so *new* connection attempts fail immediately, and (lazily, only
  while at least one process is blocked) a broader NETWORK-layer handle
  that drops any packet - either direction - whose port currently belongs
  to a blocked PID, which is what actually kills connections the process
  already had open. The network-layer handle closes again the moment
  nothing is blocked, so it's not touching your traffic the rest of the
  time.

Blocking is tied to the PID, not the exe path - if a blocked process
restarts under a new PID you need to block it again.

## Diagnostics

Everything logs to `netvis.log` next to the exe (timestamped, appended
across runs) - since this is a GUI-subsystem app there's no console to
print to. If something doesn't seem to work (a block isn't taking effect,
capture didn't start, etc.), that log is the first place to look.

## Project layout

```
src/            all application code
external/imgui/ vendored Dear ImGui (MIT) + Win32/DX11 backend
WinDivert.dll,
WinDivert64.sys the WinDivert driver (basil00/WinDivert, LGPL/GPL - see
                their repo for licensing if you plan to distribute this)
```
