#include "pidblock.h"
#include "packet_parse.h"
#include "log.h"
#include <cstdio>
#include <cstring>
#include <chrono>

namespace {

bool LocalPortOf(const uint8_t* raw, uint32_t len, const wd::Address& addr, Proto* proto, uint16_t* port) {
    ParsedPacket pkt = ParsePacket(raw, len);
    if (!pkt.ok) return false;
    *proto = pkt.isTcp ? Proto::TCP : Proto::UDP;
    *port = wd::IsOutbound(addr) ? pkt.srcPort : pkt.dstPort;
    return true;
}

} // namespace

PidBlockManager::~PidBlockManager() { UnblockAll(); }

bool PidBlockManager::IsBlocked(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    return blocks_.count(pid) != 0;
}

bool PidBlockManager::StartEnforcementLocked(std::string* error) {
    if (!api_.Open) { // lazily load the API on first use
        if (!wd::LoadApi(api_, error)) return false;
    }
    // "true" matches every packet, both directions - we need inbound too so
    // a blocked process can't send OR receive, which kills already-open
    // connections much faster than dropping outbound alone.
    HANDLE h = api_.Open("true", wd::LAYER_NETWORK, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = "WinDivertOpen (pidblock enforcement) failed.";
        Log("pidblock: failed to start network-layer enforcement");
        return false;
    }
    netHandle_ = h;
    enforcing_ = true;
    netmapRunning_.store(true);
    netmapThread_ = std::thread(&NetMap::RunPeriodic, &netmap_, 250, std::cref(netmapRunning_));
    enforceThread_ = std::thread(&PidBlockManager::EnforceLoop, this, h);
    Log("pidblock: network-layer enforcement started");
    return true;
}

void PidBlockManager::EnforceLoop(HANDLE handle) {
    std::vector<uint8_t> buf(wd::MTU_MAX);
    while (true) {
        wd::Address addr;
        uint32_t recvLen = 0;
        if (!api_.Recv(handle, buf.data(), (uint32_t)buf.size(), &recvLen, &addr))
            return; // handle closed - enforcement stopped
        if (ShouldDrop(buf.data(), recvLen, addr)) continue;
        uint32_t sendLen = recvLen;
        api_.Send(handle, buf.data(), recvLen, &sendLen, &addr);
    }
}

bool PidBlockManager::ShouldDrop(const uint8_t* raw, uint32_t len, const wd::Address& addr) {
    Proto proto;
    uint16_t port;
    if (!LocalPortOf(raw, len, addr, &proto, &port)) return false;
    uint32_t pid;
    if (!netmap_.Lookup(proto, port, &pid)) return false;

    std::lock_guard<std::mutex> lock(mu_);
    if (blocks_.count(pid)) {
        static std::mutex logMu;
        static std::chrono::steady_clock::time_point nextLog;
        auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> logLock(logMu);
            if (now >= nextLog) {
                nextLog = now + std::chrono::seconds(2);
                Log("pidblock: dropping %s port %u (pid %u)", proto == Proto::TCP ? "tcp" : "udp", port, pid);
            }
        }
        return true;
    }

    auto it = limits_.find(pid);
    if (it != limits_.end()) {
        LimitState& st = it->second;
        auto now = std::chrono::steady_clock::now();
        if (now - st.windowStart >= std::chrono::seconds(1)) {
            st.windowStart = now;
            st.usedThisWindow = 0;
        }
        if (st.usedThisWindow + len > st.capBytesPerSec) {
            static std::mutex logMu;
            static std::chrono::steady_clock::time_point nextLog;
            {
                std::lock_guard<std::mutex> logLock(logMu);
                if (now >= nextLog) {
                    nextLog = now + std::chrono::seconds(2);
                    Log("pidblock: throttling pid %u (over %llu B/s cap)", pid, (unsigned long long)st.capBytesPerSec);
                }
            }
            return true; // over quota for this window - drop, resumes next window
        }
        st.usedThisWindow += len;
        return false;
    }

    return false;
}

std::string PidBlockManager::Block(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    if (blocks_.count(pid)) return "";

    if (!enforcing_) {
        std::string err;
        if (!StartEnforcementLocked(&err)) return err;
    }

    char filter[64];
    snprintf(filter, sizeof(filter), "processId == %u", pid);
    // RECV_ONLY is required for SOCKET-layer handles: sending a socket
    // event back isn't a meaningful operation (there's nothing to divert -
    // we're either observing or, by never re-injecting, blocking), and
    // WinDivert rejects the open at this layer without the flag.
    HANDLE h = api_.Open(filter, wd::LAYER_SOCKET, 0, wd::FLAG_RECV_ONLY);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        char msg[160];
        snprintf(msg, sizeof(msg), "WinDivertOpen (pidblock %u) failed (GetLastError=%lu).", pid, (unsigned long)gle);
        Log("pidblock: Block(%u) failed: %s", pid, msg);
        return msg;
    }

    blocks_[pid] = h;
    Log("pidblock: Block(%u): socket-layer handle opened, now blocked", pid);
    // Socket-layer events that are never re-injected are blocked - so a
    // thread that just drains and drops is the entire mechanism. Detached:
    // it exits on its own once Unblock() closes the handle.
    std::thread([this, h]() {
        std::vector<uint8_t> buf(256);
        while (true) {
            wd::Address addr;
            uint32_t recvLen = 0;
            if (!api_.Recv(h, buf.data(), (uint32_t)buf.size(), &recvLen, &addr)) return;
            // Deliberately no Send call here.
        }
    }).detach();

    return "";
}

std::string PidBlockManager::Unblock(uint32_t pid) {
    HANDLE h = nullptr;
    HANDLE stopNetHandle = nullptr;
    bool stopEnforcement = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = blocks_.find(pid);
        if (it == blocks_.end()) return "";
        h = it->second;
        blocks_.erase(it);

        if (blocks_.empty() && limits_.empty() && enforcing_) {
            stopNetHandle = netHandle_;
            stopEnforcement = true;
            enforcing_ = false;
            netHandle_ = nullptr;
        }
    }

    BOOL ok = api_.Close(h);

    if (stopEnforcement) {
        netmapRunning_.store(false);
        api_.Close(stopNetHandle); // unblocks the pending Recv in EnforceLoop
        if (enforceThread_.joinable()) enforceThread_.join();
        if (netmapThread_.joinable()) netmapThread_.join();
        Log("pidblock: network-layer enforcement stopped (no more blocked/limited PIDs)");
    }

    Log("pidblock: Unblock(%u): %s", pid, ok ? "unblocked" : "WinDivertClose failed");
    return ok ? "" : "WinDivertClose failed while unblocking.";
}

std::string PidBlockManager::SetLimit(uint32_t pid, uint64_t bytesPerSec) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enforcing_) {
        std::string err;
        if (!StartEnforcementLocked(&err)) return err;
    }
    LimitState& st = limits_[pid];
    st.capBytesPerSec = bytesPerSec;
    st.usedThisWindow = 0;
    st.windowStart = std::chrono::steady_clock::now();
    Log("pidblock: SetLimit(%u) = %llu bytes/sec", pid, (unsigned long long)bytesPerSec);
    return "";
}

void PidBlockManager::ClearLimit(uint32_t pid) {
    HANDLE stopNetHandle = nullptr;
    bool stopEnforcement = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!limits_.count(pid)) return;
        limits_.erase(pid);

        if (blocks_.empty() && limits_.empty() && enforcing_) {
            stopNetHandle = netHandle_;
            stopEnforcement = true;
            enforcing_ = false;
            netHandle_ = nullptr;
        }
    }

    if (stopEnforcement) {
        netmapRunning_.store(false);
        api_.Close(stopNetHandle);
        if (enforceThread_.joinable()) enforceThread_.join();
        if (netmapThread_.joinable()) netmapThread_.join();
        Log("pidblock: network-layer enforcement stopped (no more blocked/limited PIDs)");
    }

    Log("pidblock: ClearLimit(%u)", pid);
}

bool PidBlockManager::IsLimited(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    return limits_.count(pid) != 0;
}

uint64_t PidBlockManager::GetLimit(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = limits_.find(pid);
    return it == limits_.end() ? 0 : it->second.capBytesPerSec;
}

std::vector<uint32_t> PidBlockManager::BlockedPIDs() {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<uint32_t> pids;
    pids.reserve(blocks_.size());
    for (const auto& [pid, h] : blocks_) pids.push_back(pid);
    return pids;
}

void PidBlockManager::UnblockAll() {
    for (uint32_t pid : BlockedPIDs()) Unblock(pid);
}
