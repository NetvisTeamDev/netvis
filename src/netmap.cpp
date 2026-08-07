#include <winsock2.h>
#include <ws2tcpip.h>
#include "netmap.h"
#include <iphlpapi.h>
#include <chrono>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace {

// Ports are stored network-byte-order in the low 16 bits of a DWORD field.
uint16_t PortFromDword(DWORD raw) {
    return (uint16_t(raw & 0xFF) << 8) | uint16_t((raw >> 8) & 0xFF);
}

void ReadTCP(ULONG family, std::unordered_map<ConnKey, uint32_t, ConnKeyHash>& out) {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    if (family == AF_INET) {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            out[{Proto::TCP, PortFromDword(row.dwLocalPort)}] = row.dwOwningPid;
        }
    } else {
        auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            out[{Proto::TCP, PortFromDword(row.dwLocalPort)}] = row.dwOwningPid;
        }
    }
}

void ReadUDP(ULONG family, std::unordered_map<ConnKey, uint32_t, ConnKeyHash>& out) {
    ULONG size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;

    if (family == AF_INET) {
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            out[{Proto::UDP, PortFromDword(row.dwLocalPort)}] = row.dwOwningPid;
        }
    } else {
        auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            out[{Proto::UDP, PortFromDword(row.dwLocalPort)}] = row.dwOwningPid;
        }
    }
}

} // namespace

void NetMap::Refresh() {
    std::unordered_map<ConnKey, uint32_t, ConnKeyHash> next;
    ReadTCP(AF_INET, next);
    ReadTCP(AF_INET6, next);
    ReadUDP(AF_INET, next);
    ReadUDP(AF_INET6, next);

    std::lock_guard<std::mutex> lock(mu_);
    table_ = std::move(next);
}

bool NetMap::Lookup(Proto proto, uint16_t localPort, uint32_t* pid) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = table_.find({proto, localPort});
    if (it == table_.end()) return false;
    *pid = it->second;
    return true;
}

void NetMap::RunPeriodic(int intervalMs, const std::atomic<bool>& running) {
    Refresh();
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        if (!running.load()) return;
        Refresh();
    }
}
