// Cuts a specific process off the network via two mechanisms combined:
//   1. A SOCKET-layer WinDivert handle scoped to "processId == N", never
//      re-injected - blocks new bind/connect/listen calls immediately.
//   2. A shared NETWORK-layer handle (opened lazily, only while >=1 PID is
//      blocked) that drops any packet - either direction - whose local
//      port currently belongs to a blocked PID, via a live netmap lookup.
//      This is what actually kills connections a process already had open
//      before you clicked Block, which matters a lot for something like a
//      browser that mostly runs on connections it already had warmed up.
// Blocking is tied to the specific PID, not the exe path - if the process
// restarts under a new PID it needs to be blocked again.
#pragma once
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "netmap.h"
#include "windivert_shim.h"

class PidBlockManager {
public:
    ~PidBlockManager();

    bool IsBlocked(uint32_t pid);

    // Returns "" on success, otherwise an error message (e.g. WinDivertOpen
    // failed - almost always means "not running as Administrator").
    std::string Block(uint32_t pid);
    std::string Unblock(uint32_t pid);

    std::vector<uint32_t> BlockedPIDs();
    void UnblockAll();

private:
    bool StartEnforcementLocked(std::string* error); // caller holds mu_
    void EnforceLoop(HANDLE handle);
    bool ShouldDrop(const uint8_t* raw, uint32_t len, const wd::Address& addr);

    wd::Api api_;
    std::mutex mu_;
    std::unordered_map<uint32_t, HANDLE> blocks_;

    bool enforcing_ = false;
    HANDLE netHandle_ = nullptr;
    std::atomic<bool> netmapRunning_{false};
    std::thread enforceThread_;
    std::thread netmapThread_;
    NetMap netmap_;
};
