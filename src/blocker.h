// DNS-based ad/tracker blocker. Intercepts (not sniffs) these cases:
//   - plain DNS over UDP 53, IPv4: parses the question, and if the domain
//     matches the blocklist (and isn't allowlisted), spoofs an NXDOMAIN
//     response instead of letting the query reach a real DNS server.
//   - plain DNS over UDP 53, IPv6: same lookup, but the query is simply
//     dropped rather than answered - building a spoofed IPv6 reply is a
//     lot more work for a case that resolves to "the lookup fails" either
//     way. Previously IPv6 DNS passed through untouched, which was a
//     straightforward way to bypass blocking entirely.
//   - plain DNS over TCP 53 (both families): same, dropped. Used as a
//     fallback by resolvers when a UDP reply is truncated, and by anything
//     deliberately avoiding UDP.
//   - DNS-over-TLS (TCP 853): can't inspect the query (it's encrypted), so
//     just drops the connection attempt outright. Rare in practice but
//     some apps use it to bypass DNS-level blocking entirely.
//   - DNS-over-HTTPS (TCP 443 to a handful of known public resolver IPs):
//     same idea - can't inspect it, so block by destination IP.
// Everything else passes through untouched (fail-open) - a bug in this
// code should never look like "the internet stopped working".
#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "windivert_shim.h"

class Blocker {
public:
    ~Blocker();

    // Loads blocklist.txt/allowlist.txt (if present next to the exe,
    // merged with built-in defaults for the blocklist), opens an
    // intercepting WinDivert handle, and starts the worker thread.
    bool Start(std::string* error);
    void Close();

    int64_t BlockedCount() const { return blockedCount_.load(); }

    // Most-recently-blocked entries, newest first, for the UI.
    std::vector<std::string> Recent();

    // When disabled, every packet is passed straight through - the
    // WinDivert handle stays open (so toggling is instant), it just stops
    // doing anything. Also flushes the OS DNS cache, in both directions:
    // turning blocking ON otherwise appears to do nothing until cached
    // ad-domain lookups expire, and turning it OFF leaves cached spoofed
    // NXDOMAIN results behind, so sites stay broken. Flushing makes the
    // toggle take effect immediately either way.
    void SetEnabled(bool enabled);
    bool Enabled() const { return enabled_.load(); }

private:
    void Run();
    void HandlePacket(std::vector<uint8_t>& raw, uint32_t len, wd::Address& addr);
    void Reinject(const std::vector<uint8_t>& raw, uint32_t len, const wd::Address& addr);
    void RecordBlock(const std::string& label);
    void LoadLists();
    std::string BuildFilter() const;

    wd::Api api_;
    HANDLE handle_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread thread_;

    std::unordered_set<std::string> blocklist_;
    std::unordered_set<std::string> allowlist_;
    std::unordered_set<std::string> dohIPs_;

    std::atomic<int64_t> blockedCount_{0};
    std::mutex recentMu_;
    std::deque<std::string> recent_;

    std::atomic<bool> enabled_{true};
};
