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
  while at least one process is blocked or rate-limited) a broader
  NETWORK-layer handle that drops any packet - either direction - whose
  port currently belongs to a blocked PID, which is what actually kills
  connections the process already had open. The network-layer handle
  closes again the moment nothing is blocked/limited, so it's not
  touching your traffic the rest of the time.
- **Per-process traffic limit**: right-click a process → "Limit traffic..."
  and set a KB/s cap. The same network-layer handle above tracks bytes
  seen per PID in 1-second windows and drops packets once the cap is
  exceeded for that window, resuming next window. It's a hard cap, not
  smooth shaping, but it's simple and effective for "keep this app under
  N KB/s".
- **Auto-block high-traffic processes**: checkbox above the table. When
  on, any process whose combined Down/s + Up/s exceeds the configured
  KB/s threshold gets auto-blocked the same way a manual Block click
  would (a small built-in denylist protects things like `svchost.exe`/
  `lsass.exe`/netvis itself from ever being auto-blocked).
- **Right-click → Open file location**: opens Explorer with the process's
  exe selected.
- **DNS cache auto-flush**: on startup, netvis flushes the Windows DNS
  resolver cache, so stale entries from before the blocker/monitor came up
  don't skew things (handy when re-testing the ad blocker right after a
  rebuild).

Blocking/limiting is tied to the PID, not the exe path - if a blocked
process restarts under a new PID you need to re-apply it.

## Traffic generator (test tool)

`tools/trafficgen/` is a tiny standalone console exe for testing the
bandwidth monitor and auto-block feature: every random 10-20 seconds it
bursts ~1 second of real download traffic (from Cloudflare's public
speed-test endpoint) and then goes quiet again. Build it with
`tools\trafficgen\build.bat` (same VS toolchain as the main project), run
`trafficgen.exe`, and watch it show up as a bursty row in netvis - a good
way to confirm auto-block actually triggers without needing to open a
real bandwidth-heavy app.

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
