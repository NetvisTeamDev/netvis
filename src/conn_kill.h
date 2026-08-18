// Force-closing live TCP connections, so a domain you just added to the
// blocklist stops loading NOW rather than when the open tab's connection
// happens to idle out.
//
// DNS-layer blocking only stops NEW lookups and NEW connections; a page
// that's already up keeps its established socket. To make blocking feel
// instant we also tear those sockets down - by resolving the domain's current
// IPs and asking the TCP stack to delete the matching connection blocks
// (which sends an RST). Requires Administrator, which netvis already has.
//
// The socket headers stay out of this interface on purpose: main.cpp includes
// <windows.h> early, and pulling <winsock2.h> in after that is the classic
// winsock1/winsock2 clash. So the signatures here use only plain types and
// the real Winsock/IP Helper calls live in conn_kill.cpp (compiled
// winsock2-first, the same arrangement connlist uses).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace connkill {

// True if `s` is a bare IPv4 or IPv6 literal (so the blocklist can tell an
// address the user typed from a domain, and ban it directly).
bool IsIPLiteral(const std::string& s);

// Dotted-quad text for a network-byte-order IPv4 address. Lives here so
// main.cpp never has to pull in the Winsock headers just to format an IP.
std::string IPv4ToString(uint32_t netOrder);

// Resolve `host` to its current IPv4 addresses (network byte order), appended
// to `out`. MUST be called while the host still resolves - i.e. BEFORE it's
// added to the blocklist, otherwise netvis NXDOMAINs its own lookup. No-op on
// failure.
void ResolveHostIPv4(const std::string& host, std::vector<uint32_t>& out);

// Force-close every IPv4 TCP connection whose remote address is in `ipsNet`
// (network byte order). Returns how many were closed.
//
// IPv4 only: there's no user-space equivalent for IPv6, but killing the v4
// flow already forces a reconnect, and that reconnect's DNS is blocked.
// Collateral on a shared CDN IP is a one-time blip, not a break: an allowed
// site sharing that IP just reconnects, because its own DNS still resolves.
int ResetConnectionsTo(const std::vector<uint32_t>& ipsNet);

} // namespace connkill
