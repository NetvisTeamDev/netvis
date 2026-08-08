#include "blocker.h"
#include "blocklist.h"
#include "packet_parse.h"
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

void Blocker::LoadLists() {
    for (const auto& d : DefaultBlocklist()) blocklist_.insert(d);
    for (const auto& ip : KnownDoHIPs()) dohIPs_.insert(ip);

    std::string dir = ExeDir();
    LoadDomainFile(dir + "\\blocklist.txt", blocklist_);
    LoadDomainFile(dir + "\\allowlist.txt", allowlist_);
}

std::string Blocker::BuildFilter() const {
    std::ostringstream ss;
    ss << "outbound and (udp.DstPort == 53 or tcp.DstPort == 853 or (tcp.DstPort == 443 and (";
    bool first = true;
    for (const auto& ip : dohIPs_) {
        if (!first) ss << " or ";
        first = false;
        ss << "ip.DstAddr == " << ip;
    }
    if (first) ss << "false"; // no DoH IPs configured - shouldn't happen, but stay valid
    ss << ")))";
    return ss.str();
}

bool Blocker::Start(std::string* error) {
    LoadLists();
    if (!wd::LoadApi(api_, error)) return false;

    std::string filter = BuildFilter();
    handle_ = api_.Open(filter.c_str(), wd::LAYER_NETWORK, 0, 0); // intercepting
    if (handle_ == INVALID_HANDLE_VALUE) {
        if (error) *error = "WinDivertOpen (blocker) failed - run as Administrator.";
        Log("blocker: Start failed");
        handle_ = nullptr;
        return false;
    }
    Log("blocker: started, blocklist=%zu allowlist=%zu dohIPs=%zu", blocklist_.size(), allowlist_.size(), dohIPs_.size());

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

    if (pkt.isUdp && pkt.dstPort == 53) {
        if (pkt.isIPv6) { Reinject(raw, len, addr); return; } // IPv4-only spoofing (v1)
        const uint8_t* dns = pkt.transport + 8;
        uint32_t dnsLen = pkt.transportLen - 8;
        DnsQuestion q = ParseDNSQuestion(dns, dnsLen);
        if (!q.ok) { Reinject(raw, len, addr); return; }
        std::string domain = ToLowerCopy(q.domain);

        if (MatchesSuffixSet(domain, allowlist_)) { Reinject(raw, len, addr); return; }
        if (MatchesSuffixSet(domain, blocklist_)) {
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

    if (pkt.isTcp && pkt.dstPort == 443 && !pkt.isIPv6) {
        std::string dstIP = IPv4ToString(raw.data() + 16);
        if (dohIPs_.count(dstIP)) {
            RecordBlock("[DNS-over-HTTPS] " + dstIP);
            return; // drop
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
