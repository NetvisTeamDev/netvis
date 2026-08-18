// IP-level banning, enforced by the Windows Firewall.
//
// DNS blocking stops a *name* from resolving; this stops an *address* from
// being reached at all - every port, every protocol (so QUIC/UDP too),
// IPv4 and IPv6, inbound and outbound. It's the right tool for "ban this
// address": the OS firewall drops the packets in the kernel, which no
// user-space packet loop can match for coverage or reliability, and it needs
// no changes to netvis's capture path.
//
// netvis owns a small, named set of rules ("netvis-ban-*"). SetBlockedIPs
// rewrites that set to exactly the addresses given - add, remove and startup
// reconciliation all go through the same call, so the firewall always matches
// netvis's current ban list and nothing leaks between sessions. Clear removes
// them entirely (uninstall).
//
// Requires Administrator, which netvis always runs as. Best-effort: failures
// are logged, never fatal.
#pragma once
#include <string>
#include <vector>

namespace ipban {

// Replace netvis's firewall ban rules so they block exactly `ips` (a mix of
// IPv4 and IPv6 literals is fine). An empty list clears the rules.
void SetBlockedIPs(const std::vector<std::string>& ips);

// Remove every netvis ban rule. For uninstall / teardown.
void Clear();

} // namespace ipban
