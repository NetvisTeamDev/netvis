#include "blocker.h"
#include "blocklist.h"
#include "packet_parse.h"
#include "tls_sni.h"
#include "app_paths.h"
#include "log.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace {

std::string ToLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// True if domain equals, or is a subdomain of, something in set.
bool MatchesSuffixSet(const std::string& domain, const std::unordered_set<std::string>& set) {
    if (set.empty()) return false;
    std::string d = domain;
    while (true) {
        if (set.count(d)) return true;
        auto dot = d.find('.');
        if (dot == std::string::npos) return false;
        d = d.substr(dot + 1);
    }
}

std::string IPv4ToString(const uint8_t* addr4) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr4[0], addr4[1], addr4[2], addr4[3]);
    return buf;
}

struct DnsQuestion {
    bool ok = false;
    std::string domain;
    uint32_t end = 0; // offset (from start of DNS message) right after QTYPE/QCLASS
};

DnsQuestion ParseDNSQuestion(const uint8_t* dns, uint32_t len) {
    DnsQuestion q;
    if (len < 12) return q;
    uint32_t pos = 12;
    std::string domain;
    while (true) {
        if (pos >= len) return q;
        uint8_t labelLen = dns[pos];
        if (labelLen == 0) { pos += 1; break; }
        if (labelLen & 0xC0) return q; // compression pointer - not expected as the first question label, bail
        pos += 1;
        if (pos + labelLen > len) return q;
        if (!domain.empty()) domain += '.';
        domain.append(reinterpret_cast<const char*>(dns + pos), labelLen);
        pos += labelLen;
    }
    if (pos + 4 > len) return q; // QTYPE(2) + QCLASS(2)
    pos += 4;
    q.ok = true;
    q.domain = domain;
    q.end = pos;
    return q;
}

// Builds a spoofed NXDOMAIN reply: IPv4 + UDP + (echoed DNS id/question,
// zeroed answer/authority/additional). origIP points at the original
// outbound query's IPv4 header; dns/dnsQuestionEnd delimit its DNS
// header+question, which we echo back verbatim except for the flags/counts.
std::vector<uint8_t> BuildNXDOMAINResponse(const uint8_t* origIP, uint32_t ipHdrLen,
                                            const uint8_t* dns, uint32_t dnsQuestionEnd) {
    uint32_t dnsLen = dnsQuestionEnd;
    std::vector<uint8_t> pkt(ipHdrLen + 8 + dnsLen);

    memcpy(pkt.data(), origIP, ipHdrLen);
    for (int i = 0; i < 4; i++) std::swap(pkt[12 + i], pkt[16 + i]); // swap src/dst IP
    uint16_t totalLen = (uint16_t)pkt.size();
    pkt[2] = uint8_t(totalLen >> 8);
    pkt[3] = uint8_t(totalLen & 0xFF);
    pkt[10] = 0; pkt[11] = 0; // IP checksum, recomputed by WinDivertHelperCalcChecksums

    const uint8_t* origUDP = origIP + ipHdrLen;
    uint8_t* newUDP = pkt.data() + ipHdrLen;
    newUDP[0] = origUDP[2]; newUDP[1] = origUDP[3]; // src port = orig dst port (53)
    newUDP[2] = origUDP[0]; newUDP[3] = origUDP[1]; // dst port = orig src port
    uint16_t udpLen = (uint16_t)(8 + dnsLen);
    newUDP[4] = uint8_t(udpLen >> 8);
    newUDP[5] = uint8_t(udpLen & 0xFF);
    newUDP[6] = 0; newUDP[7] = 0; // UDP checksum, recomputed

    uint8_t* newDNS = pkt.data() + ipHdrLen + 8;
    memcpy(newDNS, dns, dnsLen); // keep transaction ID + echoed question
    newDNS[2] = 0x81; newDNS[3] = 0x83; // QR=1 RD=1 RA=1 RCODE=3 (NXDOMAIN)
    newDNS[4] = 0; newDNS[5] = 1;       // QDCOUNT=1
    newDNS[6] = 0; newDNS[7] = 0;       // ANCOUNT=0
    newDNS[8] = 0; newDNS[9] = 0;       // NSCOUNT=0
    newDNS[10] = 0; newDNS[11] = 0;     // ARCOUNT=0
    return pkt;
}

void LoadDomainFile(const std::string& path, std::unordered_set<std::string>& out) {
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        size_t start = line.find_first_not_of(' ');
        if (start == std::string::npos) continue;
        line = line.substr(start);
        if (line.empty() || line[0] == '#') continue;
        out.insert(ToLowerCopy(line));
    }
}

} // namespace

Blocker::~Blocker() { Close(); }

void Blocker::LoadStaticLists() {
    for (const auto& ip : KnownDoHIPs()) dohIPs_.insert(ip);
    for (const auto& h : KnownDoHHosts()) dohHosts_.insert(h);
    LoadDomainFile(ExeDir() + "\\allowlist.txt", allowlist_);
}

void Blocker::RebuildBlocklistLocked() {
    blocklist_.clear();
    if (useDefault_) {
        // The built-in malicious-domain database: the curated defaults plus
        // the large blocklist.txt that ships next to the exe.
        for (const auto& d : DefaultBlocklist()) blocklist_.insert(d);
        LoadDomainFile(ExeDir() + "\\blocklist.txt", blocklist_);
    }
    for (const auto& d : userDomains_) blocklist_.insert(ToLowerCopy(d));

    // Always block Firefox's DoH canary while the blocker is on, regardless
    // of the default lists - NXDOMAIN'ing it is what makes Firefox turn its
    // own DoH off and route back through the plain DNS we filter. Left out of
    // the check if the user has explicitly allowlisted it.
    blocklist_.insert(FirefoxDoHCanary());
}

bool Blocker::IsBlockedDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(listsMu_);
    return !MatchesSuffixSet(domain, allowlist_) && MatchesSuffixSet(domain, blocklist_);
}

void Blocker::FlushDnsCache() {
    HMODULE dnsapi = ::LoadLibraryW(L"dnsapi.dll");
    if (!dnsapi) return;
    using FlushFn = BOOL(WINAPI*)();
    if (auto flush = reinterpret_cast<FlushFn>(::GetProcAddress(dnsapi, "DnsFlushResolverCache"))) flush();
    ::FreeLibrary(dnsapi);
}

void Blocker::Reload(std::vector<std::string> userDomains, bool useDefault) {
    {
        std::lock_guard<std::mutex> lock(listsMu_);
        userDomains_ = std::move(userDomains);
        useDefault_ = useDefault;
        RebuildBlocklistLocked();
        Log("blocker: blocklist reloaded (%zu domains, useDefault=%d)", blocklist_.size(), (int)useDefault_);
    }
    FlushDnsCache(); // so removed entries stop being spoofed and new ones start immediately
}

std::string Blocker::BuildFilter() const {
    std::ostringstream ss;
    // tcp.DstPort == 53 is included alongside udp: resolvers fall back to
    // DNS-over-TCP whenever a UDP answer comes back truncated, and some
    // clients use it directly - without it that's an easy bypass.
    //
    // For 443 we divert two things and nothing else, to keep the intercept
    // handle off the general HTTPS firehose:
    //   * TLS ClientHello packets only - `tcp.Payload[0]==0x16` is a TLS
    //     handshake record and `tcp.Payload[5]==0x01` narrows it to
    //     ClientHello, so this matches one packet per new HTTPS connection,
    //     not every data segment. That one packet carries the SNI.
    //     (WinDivert treats an out-of-range payload index as no-match, so a
    //     short packet simply doesn't match - no need to guard the length.)
    //   * known DoH resolver IPs, as a backstop for connections whose
    //     ClientHello we can't read (session resumption, or a hello split
    //     across segments). All 443 traffic to those IPs is diverted so it
    //     can be dropped.
    ss << "outbound and (udp.DstPort == 53 or tcp.DstPort == 53 or tcp.DstPort == 853 or "
          "(tcp.DstPort == 443 and ((tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01)";
    for (const auto& ip : dohIPs_) {
        ss << " or ip.DstAddr == " << ip;
    }
    ss << ")))";
    return ss.str();
}

bool Blocker::ShouldBlockSNI(const std::string& sni, std::string& reason) {
    if (sni.empty()) return false;
    std::lock_guard<std::mutex> lock(listsMu_);
    // A user allowlist entry wins over everything, same as for plain DNS.
    if (MatchesSuffixSet(sni, allowlist_)) return false;
    if (MatchesSuffixSet(sni, dohHosts_)) { reason = "[DoH-SNI] " + sni; return true; }
    if (MatchesSuffixSet(sni, blocklist_)) { reason = "[TLS-SNI] " + sni; return true; }
    return false;
}

void Blocker::SetEnabled(bool enabled) {
    enabled_.store(enabled);
    Log("blocker: %s", enabled ? "enabled" : "disabled");
    // Both directions need a cache flush to take effect promptly - see the
    // note on the declaration in blocker.h.
    FlushDnsCache();
}

bool Blocker::Start(std::string* error, std::vector<std::string> userDomains, bool useDefault) {
    LoadStaticLists();
    {
        std::lock_guard<std::mutex> lock(listsMu_);
        userDomains_ = std::move(userDomains);
        useDefault_ = useDefault;
        RebuildBlocklistLocked();
    }
    if (!wd::LoadApi(api_, error)) return false;

    std::string filter = BuildFilter();
    handle_ = api_.Open(filter.c_str(), wd::LAYER_NETWORK, 0, 0); // intercepting
    if (handle_ == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (error) {
            if (e == ERROR_ACCESS_DENIED)
                *error = "the ad blocker needs Administrator.";
            else if (e == ERROR_DRIVER_BLOCKED)
                *error = "Windows blocked the WinDivert driver (1275) - common in VMs or with "
                         "Memory Integrity on.";
            else if (e == ERROR_INVALID_IMAGE_HASH)
                *error = "Windows blocked the WinDivert driver signature (577) - turn off Memory "
                         "Integrity / Core Isolation and reboot.";
            else
                *error = "WinDivert (blocker) couldn't start (error " +
                         std::to_string((unsigned long)e) + ").";
        }
        Log("blocker: Start failed: WinDivertOpen err=%lu", (unsigned long)e);
        handle_ = nullptr;
        return false;
    }
    Log("blocker: started, blocklist=%zu allowlist=%zu dohIPs=%zu dohHosts=%zu",
        blocklist_.size(), allowlist_.size(), dohIPs_.size(), dohHosts_.size());

    running_.store(true);
    thread_ = std::thread(&Blocker::Run, this);
    return true;
}

void Blocker::Close() {
    if (!running_.exchange(false)) return;
    if (handle_) api_.Close(handle_);
    if (thread_.joinable()) thread_.join();
    handle_ = nullptr;
}

void Blocker::Run() {
    std::vector<uint8_t> buf(wd::MTU_MAX);
    while (running_.load()) {
        wd::Address addr;
        uint32_t recvLen = 0;
        if (!api_.Recv(handle_, buf.data(), (uint32_t)buf.size(), &recvLen, &addr))
            return;
        HandlePacket(buf, recvLen, addr);
    }
}

void Blocker::HandlePacket(std::vector<uint8_t>& raw, uint32_t len, wd::Address& addr) {
    if (!enabled_.load()) {
        static std::mutex disabledLogMu;
        static std::chrono::steady_clock::time_point nextDisabledLog;
        std::lock_guard<std::mutex> lock(disabledLogMu);
        auto now = std::chrono::steady_clock::now();
        if (now >= nextDisabledLog) {
            nextDisabledLog = now + std::chrono::seconds(5);
            Log("blocker: disabled, passing everything through");
        }
        Reinject(raw, len, addr);
        return;
    }

    ParsedPacket pkt = ParsePacket(raw.data(), len);
    if (!pkt.ok) { Reinject(raw, len, addr); return; }

    // DNS over TCP 53: the DNS message is prefixed with a 2-byte length,
    // and it may be split across segments. Rather than reassembling a TCP
    // stream, parse the common case (whole query in one segment) and drop
    // it if blocked - a dropped query means the lookup fails, same end
    // result as NXDOMAIN. Anything unparseable passes through (fail-open).
    if (pkt.isTcp && pkt.dstPort == 53) {
        if (pkt.transportLen > 20) {
            uint32_t tcpHdrLen = (uint32_t)((pkt.transport[12] >> 4) * 4);
            if (tcpHdrLen >= 20 && pkt.transportLen > tcpHdrLen + 2) {
                const uint8_t* dns = pkt.transport + tcpHdrLen + 2; // skip the 2-byte length prefix
                uint32_t dnsLen = pkt.transportLen - tcpHdrLen - 2;
                DnsQuestion q = ParseDNSQuestion(dns, dnsLen);
                if (q.ok) {
                    std::string domain = ToLowerCopy(q.domain);
                    if (IsBlockedDomain(domain)) {
                        RecordBlock("[DNS-TCP] " + domain);
                        return; // drop
                    }
                }
            }
        }
        Reinject(raw, len, addr);
        return;
    }

    if (pkt.isUdp && pkt.dstPort == 53) {
        const uint8_t* dns = pkt.transport + 8;
        uint32_t dnsLen = pkt.transportLen - 8;

        // IPv6: same blocklist decision, but drop instead of spoofing -
        // fabricating a valid IPv6 reply is substantially more work and
        // "query dropped" already means the lookup fails.
        if (pkt.isIPv6) {
            DnsQuestion q6 = ParseDNSQuestion(dns, dnsLen);
            if (q6.ok) {
                std::string domain6 = ToLowerCopy(q6.domain);
                if (IsBlockedDomain(domain6)) {
                    RecordBlock("[DNS-IPv6] " + domain6);
                    return; // drop
                }
            }
            Reinject(raw, len, addr);
            return;
        }

        DnsQuestion q = ParseDNSQuestion(dns, dnsLen);
        if (!q.ok) { Reinject(raw, len, addr); return; }
        std::string domain = ToLowerCopy(q.domain);

        if (IsBlockedDomain(domain)) {
            auto resp = BuildNXDOMAINResponse(raw.data(), pkt.ipHeaderLen, dns, q.end);
            wd::Address respAddr;
            memcpy(respAddr, addr, sizeof(respAddr));
            // Flip Outbound off: this is a fabricated reply arriving from
            // "the network", not another outbound packet.
            uint32_t flags;
            memcpy(&flags, respAddr + 8, sizeof(flags));
            flags &= ~(1u << 9);
            memcpy(respAddr + 8, &flags, sizeof(flags));

            uint32_t sendLen = (uint32_t)resp.size();
            api_.CalcChecksums(resp.data(), sendLen, &respAddr, 0);
            api_.Send(handle_, resp.data(), sendLen, &sendLen, &respAddr);
            RecordBlock("[DNS] " + domain);
            return; // original query is dropped, not reinjected
        }
        Reinject(raw, len, addr);
        return;
    }

    if (pkt.isTcp && pkt.dstPort == 853) {
        RecordBlock("[DNS-over-TLS]");
        return; // drop
    }

    if (pkt.isTcp && pkt.dstPort == 443) {
        // Backstop: any 443 traffic to a known resolver IP is DoH (IPv4 only -
        // the known-IP list is v4, and this is where dst lives in the header).
        if (!pkt.isIPv6) {
            std::string dstIP = IPv4ToString(raw.data() + 16);
            if (dohIPs_.count(dstIP)) {
                RecordBlock("[DoH-IP] " + dstIP);
                return; // drop
            }
        }

        // The main path: read the SNI out of the ClientHello (works the same
        // for v4 and v6) and drop known DoH hosts and blocklisted domains.
        if (pkt.transportLen > 20) {
            uint32_t tcpHdrLen = (uint32_t)((pkt.transport[12] >> 4) * 4);
            if (tcpHdrLen >= 20 && pkt.transportLen > tcpHdrLen) {
                const uint8_t* payload = pkt.transport + tcpHdrLen;
                uint32_t payloadLen = pkt.transportLen - tcpHdrLen;
                std::string sni = tls::ExtractSNI(payload, payloadLen);
                std::string reason;
                if (ShouldBlockSNI(sni, reason)) {
                    RecordBlock(reason);
                    return; // drop the ClientHello - the connection never forms
                }
            }
        }
        Reinject(raw, len, addr);
        return;
    }

    Reinject(raw, len, addr); // fail-open
}

void Blocker::Reinject(const std::vector<uint8_t>& raw, uint32_t len, const wd::Address& addr) {
    uint32_t sendLen = len;
    api_.Send(handle_, raw.data(), len, &sendLen, &addr);
}

void Blocker::RecordBlock(const std::string& label) {
    blockedCount_.fetch_add(1);
    std::lock_guard<std::mutex> lock(recentMu_);
    recent_.push_front(label);
    if (recent_.size() > 50) recent_.pop_back();
}

std::vector<std::string> Blocker::Recent() {
    std::lock_guard<std::mutex> lock(recentMu_);
    return std::vector<std::string>(recent_.begin(), recent_.end());
}
