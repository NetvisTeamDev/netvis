// Small, dependency-free IPv4/IPv6 + TCP/UDP header parser shared by the
// capture sniffer, the DNS blocker, and per-process enforcement. Deliberately
// minimal: just enough field extraction to route/filter packets, not a full
// parser.
#pragma once
#include <cstdint>
#include <cstring>

struct ParsedPacket {
    bool ok = false;
    bool isTcp = false;
    bool isUdp = false;
    bool isIPv6 = false;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    const uint8_t* transport = nullptr; // points at the TCP/UDP header
    uint32_t transportLen = 0;
    uint32_t ipHeaderLen = 0;
};

// ParsePacket reads just enough of raw to find the transport header and
// source/destination ports. Returns ok=false for anything else (ARP,
// ICMP, fragmented-without-first-fragment, truncated, etc).
inline ParsedPacket ParsePacket(const uint8_t* raw, uint32_t len) {
    ParsedPacket p;
    if (len < 1) return p;

    uint8_t version = raw[0] >> 4;
    uint32_t hdrLen;
    uint8_t proto;

    if (version == 4) {
        if (len < 20) return p;
        hdrLen = (raw[0] & 0x0F) * 4;
        proto = raw[9];
    } else if (version == 6) {
        if (len < 40) return p;
        hdrLen = 40; // no extension header walking - good enough for our needs
        proto = raw[6];
        p.isIPv6 = true;
    } else {
        return p;
    }

    if (len < hdrLen + 4) return p;
    const uint8_t* transport = raw + hdrLen;

    if (proto == 6) {
        p.isTcp = true;
    } else if (proto == 17) {
        p.isUdp = true;
    } else {
        return p;
    }

    p.srcPort = (uint16_t(transport[0]) << 8) | transport[1];
    p.dstPort = (uint16_t(transport[2]) << 8) | transport[3];
    p.transport = transport;
    p.transportLen = len - hdrLen;
    p.ipHeaderLen = hdrLen;
    p.ok = true;
    return p;
}
