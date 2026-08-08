#include "monitor.h"
#include "packet_parse.h"
#include "log.h"
#include <chrono>
#include <algorithm>
#include <windows.h>

namespace {

// OS-level "is this PID still a real, running process" check - distinct
// from "has it sent traffic recently", which is all counters_ tracks on
// its own. A process that exits mid-session should disappear (or be
// marked closed) even though its historical byte counts are still sitting
// in counters_.
bool IsProcessAlive(uint32_t pid) {
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD exitCode = 0;
    bool alive = ::GetExitCodeProcess(h, &exitCode) && exitCode == STILL_ACTIVE;
    ::CloseHandle(h);
    return alive;
}

} // namespace

Monitor::~Monitor() { Stop(); }

bool Monitor::Start(std::string* error) {
    if (!wd::LoadApi(api_, error)) return false;

    // Sniff everything at the network layer: non-intercepting, so we never
    // need to (and must not) call Send - the OS forwards packets normally
    // regardless of what we do with our copy.
    handle_ = api_.Open("true", wd::LAYER_NETWORK, 0, wd::FLAG_SNIFF);
    if (handle_ == INVALID_HANDLE_VALUE) {
        if (error) *error = "WinDivertOpen failed - run as Administrator, and make sure "
                             "WinDivert.dll/WinDivert64.sys are next to the exe.";
        Log("monitor: Start failed: %s", error ? error->c_str() : "?");
        handle_ = nullptr;
        return false;
    }
    Log("monitor: capture started");

    running_.store(true);
    captureThread_ = std::thread(&Monitor::CaptureLoop, this);
    tickThread_ = std::thread(&Monitor::TickLoop, this);
    // 250ms rather than 1s: short-lived connections (a quick HTTP request,
    // a DNS lookup) can open and close within a single second, and a stale
    // netmap means their traffic gets attributed to "(unknown)" instead of
    // the right process - which matters a lot for auto-block/limit, since
    // "(unknown)" rows can't be blocked at all.
    netmapThread_ = std::thread(&NetMap::RunPeriodic, &netmap_, 250, std::cref(running_));
    return true;
}

void Monitor::Stop() {
    if (!running_.exchange(false)) return;
    if (handle_) api_.Close(handle_);
    if (captureThread_.joinable()) captureThread_.join();
    if (tickThread_.joinable()) tickThread_.join();
    if (netmapThread_.joinable()) netmapThread_.join();
    handle_ = nullptr;
}

void Monitor::CaptureLoop() {
    std::vector<uint8_t> buf(wd::MTU_MAX);
    while (running_.load()) {
        wd::Address addr;
        uint32_t recvLen = 0;
        if (!api_.Recv(handle_, buf.data(), (uint32_t)buf.size(), &recvLen, &addr))
            return; // handle closed (Stop) or errored - either way, stop

        ParsedPacket pkt = ParsePacket(buf.data(), recvLen);
        if (!pkt.ok) continue;

        bool outbound = wd::IsOutbound(addr);
        uint16_t localPort = outbound ? pkt.srcPort : pkt.dstPort;
        Proto proto = pkt.isTcp ? Proto::TCP : Proto::UDP;

        uint32_t pid;
        if (!netmap_.Lookup(proto, localPort, &pid)) pid = kUnknownPID;

        std::lock_guard<std::mutex> lock(countersMu_);
        Counters& c = counters_[pid];
        if (outbound)
            c.up += recvLen;
        else
            c.down += recvLen;
    }
}

void Monitor::TickLoop() {
    std::unordered_map<uint32_t, Counters> prev;
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!running_.load()) return;

        std::unordered_map<uint32_t, Counters> cur;
        {
            std::lock_guard<std::mutex> lock(countersMu_);
            cur = counters_;
        }

        std::vector<AppStats> rows;
        rows.reserve(cur.size());
        std::unordered_map<uint32_t, bool> alive;
        std::vector<uint32_t> toForget;
        for (const auto& [pid, c] : cur) {
            alive[pid] = true;
            AppStats s;
            s.pid = pid;
            s.totalDown = c.down;
            s.totalUp = c.up;
            auto pit = prev.find(pid);
            if (pit != prev.end()) {
                s.rateDown = double(c.down - pit->second.down);
                s.rateUp = double(c.up - pit->second.up);
            }
            if (pid != kUnknownPID) {
                s.name = names_.Name(pid);
                s.exePath = names_.Path(pid);
            }
            if (s.name.empty()) s.name = (pid == kUnknownPID) ? "(unknown)" : ("pid " + std::to_string(pid));

            // "(unknown)" isn't a real single process, so liveness doesn't
            // apply to it - always show it (existing behavior).
            s.alive = (pid == kUnknownPID) || IsProcessAlive(pid);
            if (s.alive) {
                deadTicks_.erase(pid); // handles the (rare) PID-reuse case
            } else {
                int& ticks = deadTicks_[pid];
                ticks++;
                if (ticks > kDeadTicksToForget) toForget.push_back(pid);
            }
            rows.push_back(std::move(s));
        }
        names_.Prune(alive);
        prev = std::move(cur);

        if (!toForget.empty()) {
            std::lock_guard<std::mutex> lock(countersMu_);
            for (uint32_t pid : toForget) {
                counters_.erase(pid);
                deadTicks_.erase(pid);
                prev.erase(pid);
            }
            rows.erase(std::remove_if(rows.begin(), rows.end(),
                                       [&](const AppStats& s) {
                                           return std::find(toForget.begin(), toForget.end(), s.pid) != toForget.end();
                                       }),
                       rows.end());
        }

        std::sort(rows.begin(), rows.end(), [](const AppStats& a, const AppStats& b) {
            return (a.totalDown + a.totalUp) > (b.totalDown + b.totalUp);
        });

        std::lock_guard<std::mutex> lock(snapshotMu_);
        snapshot_ = std::move(rows);
    }
}

std::vector<AppStats> Monitor::Snapshot() {
    std::lock_guard<std::mutex> lock(snapshotMu_);
    return snapshot_;
}
