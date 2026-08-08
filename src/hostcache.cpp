// winsock2 before anything that might drag in windows.h - see connlist.cpp
#include <winsock2.h>
#include <ws2tcpip.h>

#include "hostcache.h"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "ws2_32.lib")

namespace {

// A few workers so one slow/timing-out lookup doesn't stall the rest of
// the queue - a connections list can easily hold a dozen distinct hosts.
constexpr int kWorkerCount = 4;

enum class Entry : uint8_t { Queued, Resolved, NoName };

// Addresses where a reverse lookup is meaningless: the unspecified address
// (what a listening socket reports) and loopback.
bool IsUnresolvable(const std::string& ip) {
    return ip.empty() || ip == "0.0.0.0" || ip == "::" || ip == "127.0.0.1" || ip == "::1";
}

// Blocking reverse lookup. Returns "" if the address has no PTR record.
std::string ReverseLookup(const std::string& ip) {
    char host[NI_MAXHOST] = {};

    if (ip.find(':') != std::string::npos) {
        sockaddr_in6 sa6 = {};
        sa6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) != 1) return "";
        if (getnameinfo(reinterpret_cast<sockaddr*>(&sa6), sizeof(sa6), host, sizeof(host), nullptr, 0,
                        NI_NAMEREQD) != 0)
            return "";
    } else {
        sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return "";
        if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD) != 0)
            return "";
    }
    return host;
}

} // namespace

// Shared between HostCache and its workers via shared_ptr so the workers
// can be detached: a thread parked inside getnameinfo() can't be
// interrupted, and joining it on shutdown would hang the app's exit for as
// long as that lookup takes. Detaching is only safe because the state
// outlives HostCache itself this way.
struct HostCacheState {
    std::mutex mu;
    std::condition_variable cv;
    std::unordered_map<std::string, Entry> status;
    std::unordered_map<std::string, std::string> names;
    std::deque<std::string> queue;
    bool running = true;
};

namespace {

void WorkerLoop(std::shared_ptr<HostCacheState> state) {
    for (;;) {
        std::string ip;
        {
            std::unique_lock<std::mutex> lock(state->mu);
            state->cv.wait(lock, [&] { return !state->running || !state->queue.empty(); });
            if (!state->running) return;
            ip = std::move(state->queue.front());
            state->queue.pop_front();
        }

        std::string name = ReverseLookup(ip); // outside the lock - this is the slow part

        {
            std::lock_guard<std::mutex> lock(state->mu);
            if (name.empty()) {
                state->status[ip] = Entry::NoName;
            } else {
                state->status[ip] = Entry::Resolved;
                state->names[ip] = std::move(name);
            }
        }
    }
}

} // namespace

HostCache::HostCache() : state_(std::make_shared<HostCacheState>()) {
    // getnameinfo needs Winsock initialised. WSAStartup is reference
    // counted, so calling it here is safe even if something else already
    // did - and there's no matching WSACleanup because the workers are
    // detached and may still be running at shutdown.
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    for (int i = 0; i < kWorkerCount; i++) std::thread(WorkerLoop, state_).detach();
}

HostCache::~HostCache() {
    std::lock_guard<std::mutex> lock(state_->mu);
    state_->running = false;
    state_->cv.notify_all();
}

HostCache::Status HostCache::Get(const std::string& ip, std::string* hostname) {
    if (IsUnresolvable(ip)) return Status::NoName;

    std::lock_guard<std::mutex> lock(state_->mu);
    auto it = state_->status.find(ip);
    if (it == state_->status.end()) {
        state_->status[ip] = Entry::Queued;
        state_->queue.push_back(ip);
        state_->cv.notify_one();
        return Status::Unresolved;
    }

    switch (it->second) {
        case Entry::Resolved:
            if (hostname) *hostname = state_->names[ip];
            return Status::Resolved;
        case Entry::NoName:
            return Status::NoName;
        default:
            return Status::Unresolved;
    }
}
