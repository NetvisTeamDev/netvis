// Maps local (protocol, port) to the owning PID, by reading the same
// tables `netstat -ano` reads (GetExtendedTcpTable / GetExtendedUdpTable).
#pragma once
#include <windows.h>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <thread>

enum class Proto : uint8_t { TCP, UDP };

struct ConnKey {
    Proto proto;
    uint16_t localPort;
    bool operator==(const ConnKey& o) const { return proto == o.proto && localPort == o.localPort; }
};
struct ConnKeyHash {
    size_t operator()(const ConnKey& k) const {
        return (size_t(k.proto) << 16) ^ k.localPort;
    }
};

class NetMap {
public:
    // Re-reads the OS connection tables and atomically swaps them in.
    // Cheap enough to call every second or two.
    void Refresh();

    bool Lookup(Proto proto, uint16_t localPort, uint32_t* pid) const;

    // Runs Refresh once immediately, then every `intervalMs` until
    // `running` is cleared. Meant to be run on its own thread.
    void RunPeriodic(int intervalMs, const std::atomic<bool>& running);

private:
    mutable std::mutex mu_;
    std::unordered_map<ConnKey, uint32_t, ConnKeyHash> table_;
};
