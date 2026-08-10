// Notable-event feed: the things you'd actually want to be told about,
// as opposed to the continuous byte counts the rest of the app shows.
//
// Detects three kinds of event, all by polling cheap OS state once a
// second from a background thread:
//   - a process touching the network for the first time ever (tracked by
//     exe name across runs, so "first time" survives a restart)
//   - a process starting to LISTEN on a port - the classic signature of
//     something opening a way in, and normally rare enough to be worth
//     surfacing
//   - the system's DNS servers changing underneath you, which is worth
//     knowing about both for troubleshooting and because it's what a
//     hijack looks like
#pragma once
#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "procname.h"

enum class AlertKind : uint8_t {
    FirstConnection,
    NewListener,
    DnsChanged,
    AutoBlocked,
};

struct Alert {
    AlertKind kind;
    std::string title;
    std::string detail;
    std::string timestamp; // "HH:MM:SS"
    uint32_t pid = 0;      // 0 when not process-specific
};

class Alerts {
public:
    ~Alerts();

    // `knownExes` seeds the set of processes already considered "seen
    // before" (loaded from disk), so a fresh install doesn't fire an alert
    // for every app on the machine at once.
    void Start(std::vector<std::string> knownExes);
    void Stop();

    std::vector<Alert> Recent();      // newest first
    size_t UnreadCount() const { return unread_.load(); }
    void MarkAllRead() { unread_.store(0); }
    void Clear();

    // Every exe name that has been seen connecting, for persisting.
    std::vector<std::string> KnownExes();

    // Called (on the alerts thread) whenever a new alert is raised, so the
    // app can show a system notification even while the UI loop is parked
    // in the background. Set it before Start().
    void SetOnAlert(std::function<void(const Alert&)> cb) { onAlert_ = std::move(cb); }

    // Raises an alert from outside (e.g. the UI thread when auto-block
    // fires). Goes through the same path as internal alerts, so it shows in
    // the feed and triggers the notification callback.
    void Raise(AlertKind kind, std::string title, std::string detail, uint32_t pid) {
        Push(kind, std::move(title), std::move(detail), pid);
    }

private:
    void Run();
    void CheckConnections();
    void CheckDnsServers();
    void Push(AlertKind kind, std::string title, std::string detail, uint32_t pid);

    std::atomic<bool> running_{false};
    std::thread thread_;

    std::mutex mu_;
    std::deque<Alert> alerts_;
    std::unordered_set<std::string> seenExes_;     // lowercased exe names that have connected before
    std::unordered_set<std::string> seenListeners_; // "exe:port" pairs already reported
    std::string lastDnsServers_;
    bool dnsInitialised_ = false;
    bool firstScanDone_ = false; // first poll seeds current state instead of alerting on all of it
    ProcNames names_;
    std::function<void(const Alert&)> onAlert_;

    std::atomic<size_t> unread_{0};
};
