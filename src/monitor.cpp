#include "monitor.h"
#include "packet_parse.h"
#include "log.h"
#include <chrono>
#include <algorithm>
#include <cstring>
#include <windows.h>

namespace {

// OS-level "is this PID still a real, running process" check - distinct
// from "has it sent traffic recently", which is all counters_ tracks on
// its own. A process that exits mid-session should disappear (or be
// marked closed) even though its historical byte counts are still sitting
// in counters_.
// Classifies by whichever endpoint looks like a well-known service port.
// The remote port is the meaningful one (the local side is an ephemeral
// high port), but we check both since direction isn't always obvious.
TrafficType ClassifyPorts(bool isTcp, uint16_t a, uint16_t b) {
    auto either = [&](uint16_t p) { return a == p || b == p; };

    if (either(53) || either(853) || either(5353)) return TrafficType::DNS;
    if (either(443)) return isTcp ? TrafficType::HTTPS : TrafficType::QUIC;
    if (either(80) || either(8080) || either(8000)) return TrafficType::HTTP;
    if (either(25) || either(110) || either(143) || either(465) || either(587) || either(993) || either(995))
        return TrafficType::Email;
    if (either(445) || either(139) || either(20) || either(21)) return TrafficType::FileShare;
    if (either(3389) || either(5900)) return TrafficType::RemoteDesktop;
    return TrafficType::Other;
}

// netvis's own PID. Its traffic (the license check, hostname lookups) is
// an artifact of the tool doing its job, not something the user is doing,
// so it never belongs in the table, the graph, the alerts or the
// auto-block logic. Cached once - it can't change while we're running.
uint32_t SelfPid() {
    static const uint32_t pid = ::GetCurrentProcessId();
    return pid;
}

bool IsProcessAlive(uint32_t pid) {
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD exitCode = 0;
    bool alive = ::GetExitCodeProcess(h, &exitCode) && exitCode == STILL_ACTIVE;
    ::CloseHandle(h);
    return alive;
}

} // namespace

const char* TrafficTypeName(TrafficType t) {
    switch (t) {
        case TrafficType::HTTPS: return "HTTPS";
        case TrafficType::QUIC: return "QUIC";
        case TrafficType::HTTP: return "HTTP";
        case TrafficType::DNS: return "DNS";
        case TrafficType::Email: return "Email";
        case TrafficType::FileShare: return "File sharing";
        case TrafficType::RemoteDesktop: return "Remote desktop";
        default: return "Other";
    }
}

Monitor::~Monitor() { Stop(); }

bool Monitor::Start(std::string* error) {
    if (!wd::LoadApi(api_, error)) return false;

    // Sniff everything at the network layer: non-intercepting, so we never
    // need to (and must not) call Send - the OS forwards packets normally
    // regardless of what we do with our copy.
    handle_ = api_.Open("true", wd::LAYER_NETWORK, 0, wd::FLAG_SNIFF);
    if (handle_ == INVALID_HANDLE_VALUE) {
        // WinDivertOpen fails for several distinct reasons, and reporting all
        // of them as "run as Administrator" sends people (who often already
        // ARE admin) chasing the wrong thing. Read the real error and say what
        // actually happened - the driver-signature / driver-blocked cases are
        // common in VMs and with Memory Integrity on, and have nothing to do
        // with elevation.
        DWORD e = GetLastError();
        if (error) {
            switch (e) {
            case ERROR_ACCESS_DENIED: // 5
                *error = "netvis needs Administrator. Right-click it and choose "
                         "\"Run as administrator\".";
                break;
            case ERROR_FILE_NOT_FOUND: // 2
                *error = "WinDivert.dll / WinDivert64.sys are missing next to netvis.exe - "
                         "reinstall netvis.";
                break;
            case ERROR_INVALID_IMAGE_HASH: // 577
                *error = "Windows blocked the WinDivert driver's signature (577). This is "
                         "usually Memory Integrity (Core Isolation) or Secure Boot: turn "
                         "Memory Integrity off in Windows Security > Device security > Core "
                         "isolation, reboot, then start netvis.";
                break;
            case ERROR_DRIVER_BLOCKED: // 1275
                *error = "Windows blocked the WinDivert kernel driver (1275). This is common "
                         "in virtual machines and when Memory Integrity or some anti-virus is "
                         "on - the driver netvis needs can't load in this environment. Turn "
                         "off Memory Integrity / allow the driver, or run on a real machine.";
                break;
            case ERROR_DRIVER_FAILED_PRIOR_UNLOAD: // 654
                *error = "A previous WinDivert driver is still unloading. Reboot and start "
                         "netvis again.";
                break;
            default:
                *error = "WinDivert couldn't start (error " + std::to_string((unsigned long)e) +
                         "). Make sure you're Administrator and that the WinDivert files sit "
                         "next to netvis.exe.";
                break;
            }
        }
        Log("monitor: Start failed: WinDivertOpen err=%lu", (unsigned long)e);
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

        // Drop our own packets here, at the single point every counter is
        // fed from - so netvis can't show, graph, alert on or throttle
        // itself no matter which feature is looking at the data.
        if (pid == SelfPid()) continue;

        TrafficType type = ClassifyPorts(pkt.isTcp, pkt.srcPort, pkt.dstPort);

        std::lock_guard<std::mutex> lock(countersMu_);
        Counters& c = counters_[pid];
        if (outbound)
            c.up += recvLen;
        else
            c.down += recvLen;
        c.byType[(size_t)type] += recvLen;
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
            memcpy(s.byType, c.byType, sizeof(s.byType));
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
