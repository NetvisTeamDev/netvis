# netvis

A GlassWire-style live bandwidth monitor for Windows: a live traffic graph,
a per-process table (with app icons) showing who's using your connection
and how much, a system-wide DNS ad/tracker blocker, and the ability to cut
a specific process off the network with one click. This covers ideas #2
("who's using my bandwidth"), #1 (ad blocker), and #4 (per-app firewall)
from your list; the rest (scheduler, split-tunnel, latency-spike detector,
auto-throttle) can build on the same foundation, see Roadmap below.

## How it works

- **`internal/capture`** opens a [WinDivert](https://reqrypt.org/windivert.html)
  handle in *sniff* mode via direct syscalls into `WinDivert.dll` (not the
  `godivert` Go binding - see the note at the top of `capture_windows.go`
  for why: that library was written for WinDivert's pre-2.0 ABI and
  corrupts memory against a modern WinDivert.dll). Sniff mode copies
  packets to us without removing them from the network stack, so this part
  can never break your internet even if it crashes.
- **`internal/netmap`** reads the same OS tables `netstat -ano` reads
  (`GetExtendedTcpTable` / `GetExtendedUdpTable`) to map a local port to the
  PID that owns it, refreshed every second.
- **`internal/procname`** resolves a PID to an exe name and full path
  (cached).
- **`internal/winicon`** extracts a small icon for an exe path
  (`SHGetFileInfoW` + `GetIconInfo` + `GetDIBits`, encoded to PNG), cached
  by path so each icon is only extracted once.
- **`internal/monitor`** glues capture/netmap/procname together into
  per-process byte counters and per-second rates.
- **`internal/blocker`** opens a *second*, separate WinDivert handle (no
  sniff flag - it actually intercepts), scoped to outbound DNS-shaped
  traffic. See "The ad blocker" below for what it catches and how.
- **`internal/pidblock`** opens a `WINDIVERT_LAYER_SOCKET` handle per
  blocked PID, filtered to `processId == N`. Socket-layer events that never
  get re-injected are blocked by WinDivert itself - so "block this
  process" is just "open a handle for its PID and never call
  `WinDivertSend`".
- **`internal/ui`** renders all of it in Fyne: a rolling traffic graph
  (custom `canvas.Raster`), the process table, and a blocked-count label,
  refreshed once a second.

## The ad blocker

Three kinds of outbound traffic get intercepted:

1. **Plain UDP DNS queries (port 53).** Parsed, and if the domain (or any
   parent of it) is in the blocklist, a forged NXDOMAIN response is sent
   straight back to the requesting app instead of letting the query
   through. This makes the block feel instant - a normal failed lookup -
   instead of the app hanging until a multi-second timeout.
2. **DNS-over-TLS (port 853)**: dropped outright. There's no legitimate
   non-DNS use of that port on a typical machine, and the contents are
   encrypted so we can't be selective - blocking it forces apps back onto
   plain DNS, which we *can* filter.
3. **DNS-over-HTTPS to well-known public resolvers** (Cloudflare, Google,
   Quad9, OpenDNS) **on port 443**: also dropped outright. This is what
   closes the "secure DNS" bypass browsers increasingly default to - if a
   browser can't reach its DoH resolver, it falls back to the OS resolver,
   which lands back in case 1.

Ships with a curated default list of ~150 ad/tracker domains
(`internal/blocker/blocklist.go`). To extend it, drop a `blocklist.txt`
next to `netvis.exe` (one domain per line, `#` for comments). If the list
is ever too aggressive, add exceptions the same way in `allowlist.txt`.

## Per-process blocking

Click **Block** next to any process in the table to cut it off from making
*new* network connections; click **Unblock** to restore it. This uses
WinDivert's socket layer, so it's a real block at the OS level, not just
hiding rows in the table. Sockets the process already had open before you
blocked it may keep working until they close naturally - this stops new
connection attempts, not existing ones. Blocking is tied to the specific
PID: if the process restarts, you'll need to click Block again.

## Requirements

- Windows 10/11, 64-bit
- Go 1.21+
- A C compiler in `PATH` (Fyne needs CGO). [TDM-GCC](https://jmeubank.github.io/tdm-gcc/)
  or MSYS2's `mingw-w64` both work.
- Administrator rights to run the built exe (WinDivert loads a kernel driver)

## Setup

1. **Get WinDivert.** Download the WinDivert 2.2 zip from
   <https://reqrypt.org/windivert.html> (or the releases page of
   <https://github.com/basil00/WinDivert>). From the `x64` folder, copy
   `WinDivert.dll` and `WinDivert64.sys` into this project folder, next to
   where `netvis.exe` will end up.

2. **Fetch Go dependencies** (from this folder, in a terminal on your
   Windows machine):

   ```
   go get fyne.io/fyne/v2@latest
   go mod tidy
   ```

3. **Build:**

   ```
   go build -o netvis.exe .
   ```

4. **Run as Administrator.** Right-click `netvis.exe` -> "Run as
   administrator" (or launch an elevated terminal first). WinDivert needs
   this to load its driver; without it you'll get an error on startup.

For faster iteration while developing, `go run .` works too (still needs
admin + the DLL/driver in the working directory).

## Known limitations (v1)

- Tracks TCP and UDP only (no ICMP, so ping traffic won't show up in the
  bandwidth table).
- Traffic is attributed to "Unknown" if the connection-table snapshot
  doesn't have the port yet (e.g. very short-lived UDP sends between
  refreshes). This is normal and matches what GlassWire and similar tools
  call "System"/"Unknown" traffic.
- IPv6 extension headers aren't walked (fixed 40-byte IPv6 header assumed),
  so a packet using them could be misparsed. Rare in practice.
- Rates recompute once a second with no smoothing, so a single-second burst
  shows at full size rather than averaged. The traffic graph is a rolling
  60-second window that resets when the app restarts (not persisted).
- The ad blocker's NXDOMAIN spoofing only covers IPv4 queries; blocked IPv6
  queries are silently dropped (no forged response) - still blocked, just
  without the fast-fail. It also won't catch anything that connects to a
  hardcoded ad-server IP without a DNS lookup first, or DoH resolvers
  outside the built-in IP list. Domain matching is exact-suffix based, not
  wildcard/regex.
- Per-process blocking stops *new* connections, not already-open ones (see
  "Per-process blocking" above), and doesn't survive the process
  restarting under a new PID.
- No system tray yet - closing the window exits netvis and lifts all
  blocks.

## Roadmap toward your other picked ideas

- **#7 bandwidth scheduler** and **#6 auto-throttle background updaters**:
  reuse `internal/pidblock`'s pattern (or a network-layer variant of it),
  gated by a time-of-day or "is another app active" rule instead of a
  manual button.
- **#10 split-tunnel proxy router**: rewrite the destination IP/port bytes
  in the raw packet buffer before `WinDivertSend` (same trick
  `blocker_windows.go`'s `buildNXDOMAINResponse` uses to rewrite headers)
  to redirect specific apps' traffic through a local proxy.
- **#11 latency/bufferbloat detector**: you already have per-app byte
  rates and a graph widget; add a rolling ping sample and correlate spikes
  with which app was uploading/downloading heavily at that moment.
