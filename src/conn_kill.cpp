// winsock2.h before anything that pulls in windows.h, or the legacy winsock.h
// wins and the winsock2 declarations collide with it. Same ordering rule as
// connlist.cpp.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "conn_kill.h"

#include <iphlpapi.h>
#include <unordered_set>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace connkill {

bool IsIPLiteral(const std::string& s) {
    in_addr a4;
    in6_addr a6;
    return inet_pton(AF_INET, s.c_str(), &a4) == 1 || inet_pton(AF_INET6, s.c_str(), &a6) == 1;
}

std::string IPv4ToString(uint32_t netOrder) {
    in_addr a;
    a.S_un.S_addr = netOrder;
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "";
    return buf;
}

void ResolveHostIPv4(const std::string& host, std::vector<uint32_t>& out) {
    if (host.empty()) return;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        out.push_back((uint32_t)sa->sin_addr.S_un.S_addr); // already network byte order
    }
    freeaddrinfo(res);
}

int ResetConnectionsTo(const std::vector<uint32_t>& ipsNet) {
    if (ipsNet.empty()) return 0;
    std::unordered_set<uint32_t> ips(ipsNet.begin(), ipsNet.end());

    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
        ERROR_INSUFFICIENT_BUFFER)
        return 0;
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return 0;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    int killed = 0;
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        const auto& row = table->table[i];
        if (!ips.count((uint32_t)row.dwRemoteAddr)) continue;

        // Only states that actually have a control block worth deleting.
        // Listeners have no remote peer; the closing states are already going
        // away. SetTcpEntry only accepts the DELETE_TCB transition anyway.
        if (row.dwState != MIB_TCP_STATE_ESTAB && row.dwState != MIB_TCP_STATE_SYN_SENT &&
            row.dwState != MIB_TCP_STATE_SYN_RCVD && row.dwState != MIB_TCP_STATE_CLOSE_WAIT)
            continue;

        // The address/port fields are handed back exactly as SetTcpEntry
        // wants them (network byte order), so the row is copied straight over.
        MIB_TCPROW del{};
        del.dwState = MIB_TCP_STATE_DELETE_TCB;
        del.dwLocalAddr = row.dwLocalAddr;
        del.dwLocalPort = row.dwLocalPort;
        del.dwRemoteAddr = row.dwRemoteAddr;
        del.dwRemotePort = row.dwRemotePort;
        if (SetTcpEntry(&del) == NO_ERROR) killed++;
    }
    return killed;
}

} // namespace connkill
