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
//   - DNS-over-HTTPS (TCP 443): the real fix for the biggest DNS-blocking
//     bypass there is. Two layers:
//       * the TLS ClientHello names its destination host in the clear (SNI),
//         so a connection to a known DoH resolver hostname is dropped for
//         ANY IP - see tls_sni.h. This also drops HTTPS to a blocklisted
//         ad/tracker domain outright, closing the gap where a domain was
//         resolved out of band (cached, hardcoded IP, a DoH we missed).
//       * a fixed list of known resolver IPs is kept as a backstop for the
//         cases where the ClientHello can't be read (session resumption, a
//         hello split across segments).
//     Blocking DoH makes browsers fall back to plain DNS, which the cases
//     above filter fully - so this doesn't lose per-domain precision, it
//     restores it. Firefox is nudged off DoH entirely via its canary domain.
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

    // Builds the initial blocklist from the user domains + (if useDefault)
    // the built-in malicious-domain database, opens an intercepting
    // WinDivert handle, and starts the worker thread.
    bool Start(std::string* error, std::vector<std::string> userDomains, bool useDefault);
    void Close();

    // Live-swaps the blocklist (e.g. after the user edits it) without
    // reopening the WinDivert handle. Thread-safe with the packet worker.
    // Also flushes the OS DNS cache so edits take effect right away.
    void Reload(std::vector<std::string> userDomains, bool useDefault);

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
    void LoadStaticLists();          // allowlist + DoH IPs (never change at runtime)
    void RebuildBlocklistLocked();   // caller holds listsMu_
    void FlushDnsCache();
    bool IsBlockedDomain(const std::string& domain); // locks listsMu_; true if blocked and not allowlisted

    wd::Api api_;
    HANDLE handle_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread thread_;

    // blocklist_/allowlist_ are read by the packet worker and rewritten by
    // Reload() from the UI thread, so they're guarded by listsMu_. dohIPs_
    // is fixed after Start (used to build the filter) and needs no lock.
    std::mutex listsMu_;
    std::unordered_set<std::string> blocklist_;
    std::unordered_set<std::string> allowlist_;
    std::unordered_set<std::string> dohIPs_;    // backstop: block 443 to these
    std::unordered_set<std::string> dohHosts_;  // block 443 by ClientHello SNI
    std::vector<std::string> userDomains_;
    bool useDefault_ = true;

    // Returns true (and fills reason) if this ClientHello SNI should be
    // dropped: a known DoH resolver host, or a blocklisted ad/tracker domain.
    bool ShouldBlockSNI(const std::string& sni, std::string& reason);

    std::string BuildFilter() const;

    std::atomic<int64_t> blockedCount_{0};
    std::mutex recentMu_;
    std::deque<std::string> recent_;

    std::atomic<bool> enabled_{true};
};
