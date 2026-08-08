// On-demand lister of a single process's active TCP/UDP connections (IPv4
// + IPv6), for the "View connections" right-click option. Unlike NetMap
// (which only tracks local port -> PID for the block/limit enforcement
// hot path), this pulls the full row including the remote endpoint and
// TCP state, since that's what's actually useful to look at.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "netmap.h" // Proto

struct ConnInfo {
    Proto proto;
    std::string localAddr;
    uint16_t localPort = 0;
    std::string remoteAddr;  // empty for UDP - connectionless, no fixed peer
    uint16_t remotePort = 0; // 0 for UDP
    std::string state;       // TCP only (e.g. "ESTABLISHED", "LISTEN"); empty for UDP
};

// Fresh snapshot of every connection currently owned by `pid`. Queries the
// OS connection tables directly (not cached) - meant to be called
// on-demand, e.g. once a second while a "view connections" popup is open,
// not from a hot path.
std::vector<ConnInfo> ConnectionsForPid(uint32_t pid);
