// Asynchronous reverse-DNS cache: turns "142.250.185.78" into
// "fra16s52-in-f14.1e100.net" for the connections view.
//
// Reverse lookups are network round-trips and routinely take hundreds of
// milliseconds - occasionally seconds when the PTR record doesn't exist
// and the resolver waits for a timeout. Doing them inline while drawing a
// frame would visibly freeze the UI, so Get() never blocks: it returns
// whatever is already known and quietly queues anything it hasn't seen for
// a pool of background worker threads to resolve. Callers just re-ask each
// frame and the answer appears when it's ready.
#pragma once
#include <memory>
#include <string>

struct HostCacheState;

class HostCache {
public:
    HostCache();
    ~HostCache();

    HostCache(const HostCache&) = delete;
    HostCache& operator=(const HostCache&) = delete;

    enum class Status {
        Unresolved, // queued or not requested yet - no name available
        Resolved,   // `hostname` holds a real PTR name
        NoName,     // lookup finished, the address genuinely has no PTR record
    };

    // Non-blocking. Returns the current status for `ip`, filling `hostname`
    // when Status::Resolved. First call for an address queues the lookup.
    Status Get(const std::string& ip, std::string* hostname);

private:
    std::shared_ptr<HostCacheState> state_;
};
