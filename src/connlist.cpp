// winsock2.h must come before any header that drags in windows.h (here,
// that's connlist.h -> netmap.h), or windows.h pulls in the legacy
// winsock.h first and everything that follows redefines half of it.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "connlist.h"

#include <iphlpapi.h>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

// Ports are stored network-byte-order in the low 16 bits of a DWORD field
// (same layout NetMap::Refresh already relies on).
uint16_t PortFromDword(DWORD raw) {
    return (uint16_t(raw & 0xFF) << 8) | uint16_t((raw >> 8) & 0xFF);
}

std::string TcpStateName(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

std::string IPv4Str(DWORD addr) {
    in_addr a;
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "?";
    return buf;
}

std::string IPv6Str(const UCHAR* addr16) {
    in6_addr a;
    memcpy(&a, addr16, sizeof(a));
    char buf[INET6_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET6, &a, buf, sizeof(buf))) return "?";
    return buf;
}

void CollectTCP(ULONG family, uint32_t pid, std::vector<ConnInfo>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    if (family == AF_INET) {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) continue;
            ConnInfo c;
            c.proto = Proto::TCP;
            c.localAddr = IPv4Str(row.dwLocalAddr);
            c.localPort = PortFromDword(row.dwLocalPort);
            c.remoteAddr = IPv4Str(row.dwRemoteAddr);
            c.remotePort = PortFromDword(row.dwRemotePort);
            c.state = TcpStateName(row.dwState);
            out.push_back(std::move(c));
        }
    } else {
        auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) continue;
            ConnInfo c;
            c.proto = Proto::TCP;
            c.localAddr = IPv6Str(row.ucLocalAddr);
            c.localPort = PortFromDword(row.dwLocalPort);
            c.remoteAddr = IPv6Str(row.ucRemoteAddr);
            c.remotePort = PortFromDword(row.dwRemotePort);
            c.state = TcpStateName(row.dwState);
            out.push_back(std::move(c));
        }
    }
}

void CollectUDP(ULONG family, uint32_t pid, std::vector<ConnInfo>& out) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;

    // UDP is connectionless - the OS table only has the local endpoint, no
    // fixed remote peer, so remoteAddr/remotePort/state stay at defaults.
    if (family == AF_INET) {
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) continue;
            ConnInfo c;
            c.proto = Proto::UDP;
            c.localAddr = IPv4Str(row.dwLocalAddr);
            c.localPort = PortFromDword(row.dwLocalPort);
            out.push_back(std::move(c));
        }
    } else {
        auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != pid) continue;
            ConnInfo c;
            c.proto = Proto::UDP;
            c.localAddr = IPv6Str(row.ucLocalAddr);
            c.localPort = PortFromDword(row.dwLocalPort);
            out.push_back(std::move(c));
        }
    }
}

} // namespace

std::vector<ConnInfo> ConnectionsForPid(uint32_t pid) {
    std::vector<ConnInfo> out;
    CollectTCP(AF_INET, pid, out);
    CollectTCP(AF_INET6, pid, out);
    CollectUDP(AF_INET, pid, out);
    CollectUDP(AF_INET6, pid, out);
    return out;
}
