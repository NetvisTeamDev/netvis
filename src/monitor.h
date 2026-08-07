// Aggregates WinDivert sniffed traffic into per-process bandwidth stats,
// refreshed once a second - the data backing the main table + graph.
#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "netmap.h"
#include "procname.h"
#include "windivert_shim.h"

struct AppStats {
    uint32_t pid = 0;
    std::string name;
    std::string exePath;
    double rateDown = 0; // bytes/sec, this tick
    double rateUp = 0;
    uint64_t totalDown = 0; // bytes, since netvis started
    uint64_t totalUp = 0;
};

constexpr uint32_t kUnknownPID = 0xFFFFFFFF;

class Monitor {
public:
    ~Monitor();

    // Opens a sniffing (non-intercepting) WinDivert handle at the network
    // layer and starts the capture/aggregation/netmap-refresh threads.
    // Returns false with `error` set on failure - typically: not running
    // as Administrator, or WinDivert.dll/WinDivert64.sys missing.
    bool Start(std::string* error);
    void Stop();

    std::vector<AppStats> Snapshot();

private:
    void CaptureLoop();
    void TickLoop();

    wd::Api api_;
    HANDLE handle_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread captureThread_;
    std::thread tickThread_;
    std::thread netmapThread_;

    NetMap netmap_;
    ProcNames names_;

    struct Counters {
        uint64_t down = 0;
        uint64_t up = 0;
    };
    std::mutex countersMu_;
    std::unordered_map<uint32_t, Counters> counters_; // written by capture thread, read by tick thread

    std::mutex snapshotMu_;
    std::vector<AppStats> snapshot_;
};
