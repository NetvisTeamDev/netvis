// Cuts a specific process off the network, or throttles it, via mechanisms
// built on a shared NETWORK-layer enforcement handle:
//   1. Full block: a SOCKET-layer WinDivert handle scoped to
//      "processId == N", never re-injected - blocks new bind/connect/listen
//      calls immediately - PLUS the network-layer handle below drops any
//      packet already in flight for that PID's ports, which is what
//      actually kills connections a process already had open before you
//      clicked Block (matters a lot for something like a browser that
//      mostly runs on connections it already had warmed up).
//   2. Rate limit: the same NETWORK-layer handle tracks bytes seen per
//      second for a limited PID (via a live netmap port->PID lookup) and
//      drops packets once the configured cap is exceeded for the current
//      1-second window, letting traffic resume next window. Cruder than a
//      real token bucket/shaping queue, but simple and effective enough for
//      "keep this app under N KB/s".
// The network-layer handle is opened lazily and stays open as long as
// there's at least one blocked OR rate-limited PID.
// Blocking/limiting is tied to the specific PID, not the exe path - if the
// process restarts under a new PID it needs to be re-applied.
#pragma once
#include <atomic>
#include <chrono>
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

    // A rate limit: download and upload are capped independently (either,
    // both, or neither), and the whole thing can optionally auto-expire
    // after durationSecs (0 = forever).
    struct LimitSpec {
        bool limitDown = false;
        uint64_t downBps = 0;
        bool limitUp = false;
        uint64_t upBps = 0;
        bool hasDuration = false;
        int durationSecs = 0;
        int remainingSecs = 0; // output only, from GetLimit
    };

    // Applies a rate limit to a PID instead of a full block. Returns "" on
    // success, otherwise an error message. A spec that limits neither
    // direction clears any existing limit.
    std::string SetLimit(uint32_t pid, const LimitSpec& spec);
    void ClearLimit(uint32_t pid);
    bool IsLimited(uint32_t pid);
    bool GetLimit(uint32_t pid, LimitSpec* out); // false if not limited

    // Drops any limits whose duration has elapsed, stopping enforcement if
    // that leaves nothing blocked or limited. Call periodically (e.g. once
    // a second) from the UI thread - safe to join threads there.
    void PurgeExpired();

private:
    struct LimitState {
        bool limitDown = false;
        uint64_t capDown = 0;
        bool limitUp = false;
        uint64_t capUp = 0;
        uint64_t usedDown = 0;
        uint64_t usedUp = 0;
        std::chrono::steady_clock::time_point windowStart;
        bool hasExpiry = false;
        std::chrono::steady_clock::time_point expiry;
    };

    bool StartEnforcementLocked(std::string* error); // caller holds mu_
    void StopEnforcementIfIdleLocked(HANDLE* outHandle, bool* outStop); // caller holds mu_
    void JoinEnforcement(HANDLE stopHandle);
    void EnforceLoop(HANDLE handle);
    bool ShouldDrop(const uint8_t* raw, uint32_t len, const wd::Address& addr);

    wd::Api api_;
    std::mutex mu_;
    std::unordered_map<uint32_t, HANDLE> blocks_;
    std::unordered_map<uint32_t, LimitState> limits_;

    bool enforcing_ = false;
    HANDLE netHandle_ = nullptr;
    std::atomic<bool> netmapRunning_{false};
    std::thread enforceThread_;
    std::thread netmapThread_;
    NetMap netmap_;
};
