// winsock2 before anything pulling in windows.h - see connlist.cpp
#include <winsock2.h>
#include <ws2tcpip.h>

#include "alerts.h"
#include "procname.h"
#include "log.h"

#include <iphlpapi.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "iphlpapi.lib")

namespace {

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string NowHHMMSS() {
    time_t t = time(nullptr);
    tm lt;
    localtime_s(&lt, &t);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    return buf;
}

uint16_t PortFromDword(DWORD raw) {
    return (uint16_t(raw & 0xFF) << 8) | uint16_t((raw >> 8) & 0xFF);
}

// Comma-joined list of the DNS servers currently configured on every
// active adapter - compared as a whole so any add/remove/change shows up.
std::string CurrentDnsServers() {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                             nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
        return "";
    std::vector<uint8_t> buf(size);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                             nullptr, addresses, &size) != NO_ERROR)
        return "";

    std::vector<std::string> servers;
    for (auto* a = addresses; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
            char host[NI_MAXHOST] = {};
            if (getnameinfo(d->Address.lpSockaddr, d->Address.iSockaddrLength, host, sizeof(host), nullptr, 0,
                            NI_NUMERICHOST) == 0) {
                // Link-local IPv6 resolver entries are noisy and change on
                // their own; they'd cause false "DNS changed" alerts.
                std::string s = host;
                if (s.rfind("fe80:", 0) == 0) continue;
                servers.push_back(std::move(s));
            }
        }
    }
    std::sort(servers.begin(), servers.end());
    servers.erase(std::unique(servers.begin(), servers.end()), servers.end());

    std::string joined;
    for (size_t i = 0; i < servers.size(); i++) {
        if (i) joined += ", ";
        joined += servers[i];
    }
    return joined;
}

} // namespace

Alerts::~Alerts() { Stop(); }

void Alerts::Start(std::vector<std::string> knownExes) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& e : knownExes) seenExes_.insert(ToLower(std::move(e)));
    }
    running_.store(true);
    thread_ = std::thread(&Alerts::Run, this);
}

void Alerts::Stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void Alerts::Run() {
    while (running_.load()) {
        CheckConnections();
        CheckDnsServers();
        // Poll in short slices so Stop() doesn't wait a full second.
        for (int i = 0; i < 10 && running_.load(); i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Alerts::CheckConnections() {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<uint8_t> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());

    // Decided under the lock, raised after releasing it - Push() takes the
    // same (non-recursive) mutex, so raising inline would deadlock.
    struct Pending {
        AlertKind kind;
        std::string title, detail;
        uint32_t pid;
        std::string exe;
    };
    std::vector<Pending> pending;

    {
        std::lock_guard<std::mutex> lock(mu_);
        bool firstScan = !firstScanDone_;

        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            uint32_t pid = row.dwOwningPid;
            if (pid == 0 || pid == 4) continue; // System / idle - always has sockets, never interesting
            // Never alert on ourselves. netvis talking to its own licensing
            // server is not news, and "netvis connected to the internet" as
            // the first thing you see is just confusing.
            if (pid == GetCurrentProcessId()) continue;

            std::string exe = names_.Name(pid);
            if (exe.empty()) continue;
            std::string lexe = ToLower(exe);
            bool listening = row.dwState == MIB_TCP_STATE_LISTEN;

            if (!listening) {
                if (seenExes_.insert(lexe).second && !firstScan) {
                    // Written for someone who did not ask for a network
                    // event feed and is being shown one anyway. It says what
                    // happened, whether that is normally fine, and what
                    // would make it worth a second look - in that order,
                    // because the first question anybody has about an alert
                    // is whether they need to care.
                    pending.push_back({AlertKind::FirstConnection,
                                       exe + " connected to the internet",
                                       "", pid, lexe});
                }
                continue;
            }

            uint16_t port = PortFromDword(row.dwLocalPort);
            std::string key = lexe + ":" + std::to_string(port);
            if (seenListeners_.insert(key).second && !firstScan) {
                // "Started listening" is precise and means nothing to most
                // people. What it means in practice is that other machines
                // can now start a conversation with this one, which is the
                // part worth saying out loud.
                char title[160];
                snprintf(title, sizeof(title), "%s is accepting connections on port %u",
                         exe.c_str(), port);
                pending.push_back({AlertKind::NewListener, title, "", pid, lexe});
            }
        }
        // The first pass just records the existing state of the machine -
        // otherwise launching netvis would alert on every app already
        // running, which is noise, not information.
        firstScanDone_ = true;
    }

    for (auto& p : pending) Push(p.kind, std::move(p.title), std::move(p.detail), p.pid, std::move(p.exe));
}

void Alerts::CheckDnsServers() {
    std::string current = CurrentDnsServers();
    if (current.empty()) return;

    std::string previous;
    bool initialised;
    {
        std::lock_guard<std::mutex> lock(mu_);
        previous = lastDnsServers_;
        initialised = dnsInitialised_;
        lastDnsServers_ = current;
        dnsInitialised_ = true;
    }

    if (!initialised || current == previous) return;
    // The old message was the two readings with an arrow between them,
    // which assumes the reader knows what a DNS server is and what it would
    // mean for one to change. Both servers are still named - that is the
    // detail anyone troubleshooting actually needs - but the sentence around
    // them now says what they are for.
    Push(AlertKind::DnsChanged, "Your DNS servers changed",
         "Now using " + current + " (was " + previous + "). Usually a new network or a VPN.",
         0);
}

void Alerts::Push(AlertKind kind, std::string title, std::string detail, uint32_t pid, std::string exe) {
    Alert a;
    a.kind = kind;
    a.title = std::move(title);
    a.detail = std::move(detail);
    a.timestamp = NowHHMMSS();
    a.at = (int64_t)time(nullptr);
    a.pid = pid;
    a.exe = std::move(exe);
    Log("alert: %s - %s", a.title.c_str(), a.detail.c_str());

    if (onAlert_) onAlert_(a); // outside the lock - the handler may do slow UI/shell work

    std::lock_guard<std::mutex> lock(mu_);
    alerts_.push_front(std::move(a));
    if (alerts_.size() > 200) alerts_.pop_back();
    unread_.fetch_add(1);
}

std::vector<Alert> Alerts::Recent() {
    std::lock_guard<std::mutex> lock(mu_);
    return std::vector<Alert>(alerts_.begin(), alerts_.end());
}

void Alerts::Clear() {
    std::lock_guard<std::mutex> lock(mu_);
    alerts_.clear();
    unread_.store(0);
}

std::vector<std::string> Alerts::KnownExes() {
    std::lock_guard<std::mutex> lock(mu_);
    return std::vector<std::string>(seenExes_.begin(), seenExes_.end());
}
