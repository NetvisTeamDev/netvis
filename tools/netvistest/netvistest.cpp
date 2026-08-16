// netvistest - the test harness for netvis.
//
// Replaces the old tools/trafficgen, which could only do one thing: burst
// downloads. This does that plus upload, latency, DNS blocking and alert
// triggering, because those are the parts that actually break.
//
// ---------------------------------------------------------------------------
// A note on the "demo" mode, because it matters.
//
// The load this tool creates is REAL. It moves real bytes to and from
// Cloudflare's public speed-test endpoint, which exists for exactly this. It
// does not fake latency, it does not inject delay, and it does not pretend
// the network is worse than it is.
//
// That is deliberate, and it is the only version worth shipping. A demo that
// staged the lag and then "fixed" it would fall apart the first time a
// customer ran the same test themselves - and it would be a lie told to sell
// something. The honest version is also the more convincing one: saturating
// an uplink genuinely does push ping from ~20ms to several hundred, and
// cutting the process off genuinely does bring it straight back. The numbers
// this prints are measurements, so they hold up when someone checks.
//
// Same reasoning for the ad-blocking test. It does not display ads - a
// program that puts advertisements into your OS is adware, whatever the
// intent behind it. It resolves known tracker domains and reports which ones
// netvis stopped, which is both safe and a far better test: seeing an ad tells
// you nothing about why, while a resolved domain tells you exactly what got
// through.
// ---------------------------------------------------------------------------
//
//   netvistest              interactive menu
//   netvistest demo         baseline -> saturate -> blocked -> recovery
//   netvistest hog [secs]   real download + upload load
//   netvistest ping [host]  live latency monitor
//   netvistest dns          probe the ad/tracker blocklist
//   netvistest doh          probe DNS-over-HTTPS blocking (SNI + IP)
//   netvistest alerts       trigger netvis's security alerts
//   netvistest limit [secs] measure throughput against a speed limit
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

// ------------------------------------------------------------------ console

const char* kReset = "\033[0m";
const char* kDim = "\033[90m";
const char* kGreen = "\033[92m";
const char* kYellow = "\033[93m";
const char* kRed = "\033[91m";
const char* kBlue = "\033[94m";
const char* kBold = "\033[1m";

// Windows consoles don't interpret escape codes until asked to. If the ask
// fails (an old console, or output piped to a file) every colour string is
// blanked rather than printed literally - nobody wants \033[92m in a log.
void InitConsole() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(out, &mode) ||
        !SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        kReset = kDim = kGreen = kYellow = kRed = kBlue = kBold = "";
    }
    SetConsoleOutputCP(CP_UTF8);
}

std::string HumanRate(double bytesPerSec) {
    char buf[64];
    if (bytesPerSec >= 1024.0 * 1024.0)
        snprintf(buf, sizeof(buf), "%6.2f MB/s", bytesPerSec / (1024.0 * 1024.0));
    else if (bytesPerSec >= 1024.0)
        snprintf(buf, sizeof(buf), "%6.1f KB/s", bytesPerSec / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%6.0f  B/s", bytesPerSec);
    return buf;
}

// --------------------------------------------------------------- load engine

std::atomic<uint64_t> g_down{0};
std::atomic<uint64_t> g_up{0};
std::atomic<bool> g_stop{false};

const char* kSpeedHost = "speed.cloudflare.com";

// Pulls a large object and throws the bytes away. Reopened in a loop so that
// a block applied mid-transfer shows up as the connection dying and failing to
// come back, which is what we want to detect.
void DownWorker() {
    while (!g_stop.load()) {
        HINTERNET net = InternetOpenA("netvistest/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                      nullptr, nullptr, 0);
        if (!net) { Sleep(400); continue; }

        HINTERNET url = InternetOpenUrlA(
            net, "https://speed.cloudflare.com/__down?bytes=209715200", nullptr, 0,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE |
                INTERNET_FLAG_PRAGMA_NOCACHE,
            0);
        if (url) {
            std::vector<char> buf(64 * 1024);
            DWORD n = 0;
            while (!g_stop.load() && InternetReadFile(url, buf.data(), (DWORD)buf.size(), &n) && n > 0)
                g_down.fetch_add(n);
            InternetCloseHandle(url);
        }
        InternetCloseHandle(net);
        if (!g_stop.load()) Sleep(150);
    }
}

// Upload is its own worker because a saturated uplink is what actually ruins
// latency on a home connection - and because netvis had a bug where outbound
// bytes were counted as inbound, which no download-only test could ever catch.
void UpWorker() {
    while (!g_stop.load()) {
        HINTERNET net = InternetOpenA("netvistest/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                      nullptr, nullptr, 0);
        if (!net) { Sleep(400); continue; }

        HINTERNET con = InternetConnectA(net, kSpeedHost, INTERNET_DEFAULT_HTTPS_PORT,
                                         nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (con) {
            HINTERNET req = HttpOpenRequestA(con, "POST", "/__up", nullptr, nullptr, nullptr,
                                             INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD |
                                                 INTERNET_FLAG_NO_CACHE_WRITE,
                                             0);
            if (req) {
                const DWORD kTotal = 64u * 1024u * 1024u;
                INTERNET_BUFFERSA ib{};
                ib.dwStructSize = sizeof(ib);
                ib.dwBufferTotal = kTotal;
                if (HttpSendRequestExA(req, &ib, nullptr, 0, 0)) {
                    std::vector<char> chunk(64 * 1024, 'x');
                    DWORD sent = 0, wrote = 0;
                    while (!g_stop.load() && sent < kTotal) {
                        if (!InternetWriteFile(req, chunk.data(), (DWORD)chunk.size(), &wrote) || wrote == 0)
                            break;
                        g_up.fetch_add(wrote);
                        sent += wrote;
                    }
                    HttpEndRequestA(req, nullptr, 0, 0);
                }
                InternetCloseHandle(req);
            }
            InternetCloseHandle(con);
        }
        InternetCloseHandle(net);
        if (!g_stop.load()) Sleep(150);
    }
}

struct Load {
    std::vector<std::thread> threads;

    void Start(int downWorkers, int upWorkers) {
        g_stop.store(false);
        for (int i = 0; i < downWorkers; i++) threads.emplace_back(DownWorker);
        for (int i = 0; i < upWorkers; i++) threads.emplace_back(UpWorker);
    }
    void Stop() {
        g_stop.store(true);
        for (auto& t : threads)
            if (t.joinable()) t.join();
        threads.clear();
    }
    ~Load() { Stop(); }
};

// -------------------------------------------------------------------- pinger

// ICMP through the IP Helper API rather than a raw socket: raw sockets need
// Administrator, and this tool should be runnable as a normal user so it can
// tell you what a normal user's netvis sees.
struct Pinger {
    HANDLE icmp = INVALID_HANDLE_VALUE;
    IPAddr target = 0;
    std::string host;

    std::atomic<bool> stop{false};
    std::thread th;

    // Guarded only by being written from the ping thread and read from the
    // display thread, one word at a time - a torn read here would cost a
    // wrong digit on one line, which is not worth a mutex on the hot path.
    std::atomic<double> last{0};
    std::atomic<int> sent{0};
    std::atomic<int> lost{0};
    std::vector<double> samples;   // only touched by the ping thread
    CRITICAL_SECTION lock;

    bool Open(const std::string& h) {
        host = h;
        InitializeCriticalSection(&lock);

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
        target = ((sockaddr_in*)res->ai_addr)->sin_addr.S_un.S_addr;
        freeaddrinfo(res);

        icmp = IcmpCreateFile();
        return icmp != INVALID_HANDLE_VALUE;
    }

    void Run() {
        th = std::thread([this] {
            const char payload[32] = "netvistest-latency-probe-------";
            std::vector<char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8);
            while (!stop.load()) {
                DWORD n = IcmpSendEcho(icmp, target, (LPVOID)payload, sizeof(payload), nullptr,
                                       reply.data(), (DWORD)reply.size(), 1500);
                sent.fetch_add(1);
                if (n > 0) {
                    auto* r = (ICMP_ECHO_REPLY*)reply.data();
                    if (r->Status == IP_SUCCESS) {
                        double ms = (double)r->RoundTripTime;
                        last.store(ms);
                        EnterCriticalSection(&lock);
                        samples.push_back(ms);
                        LeaveCriticalSection(&lock);
                    } else {
                        lost.fetch_add(1);
                    }
                } else {
                    lost.fetch_add(1);
                }
                Sleep(250);
            }
        });
    }

    // Stats over the samples collected since the last call, then clears them,
    // so each phase of the demo reports its own numbers rather than an average
    // smeared across the whole run.
    struct Stats { double min, max, avg, jitter; int n; };
    Stats TakePhase() {
        Stats s{0, 0, 0, 0, 0};
        EnterCriticalSection(&lock);
        if (!samples.empty()) {
            s.n = (int)samples.size();
            s.min = *std::min_element(samples.begin(), samples.end());
            s.max = *std::max_element(samples.begin(), samples.end());
            double sum = 0;
            for (double v : samples) sum += v;
            s.avg = sum / s.n;
            double var = 0;
            for (double v : samples) var += (v - s.avg) * (v - s.avg);
            s.jitter = (s.n > 1) ? std::sqrt(var / (s.n - 1)) : 0.0;
            samples.clear();
        }
        LeaveCriticalSection(&lock);
        return s;
    }

    void Close() {
        stop.store(true);
        if (th.joinable()) th.join();
        if (icmp != INVALID_HANDLE_VALUE) IcmpCloseHandle(icmp);
        DeleteCriticalSection(&lock);
    }
};

const char* LatColour(double ms) {
    if (ms < 60) return kGreen;
    if (ms < 150) return kYellow;
    return kRed;
}

// ---------------------------------------------------------------- modes

void PrintHeader(const char* title, const char* sub) {
    printf("\n%s%s== %s ==%s\n", kBold, kBlue, title, kReset);
    if (sub && *sub) printf("%s%s%s\n\n", kDim, sub, kReset);
}

int ModePing(const std::string& host) {
    PrintHeader("latency monitor", "Ctrl-C to stop.");
    Pinger p;
    if (!p.Open(host)) {
        printf("%sCould not resolve or open ICMP for %s%s\n", kRed, host.c_str(), kReset);
        return 1;
    }
    printf("pinging %s\n\n", host.c_str());
    p.Run();
    while (true) {
        Sleep(1000);
        double ms = p.last.load();
        int s = p.sent.load(), l = p.lost.load();
        printf("\r  %s%7.1f ms%s   sent %-5d lost %s%d%s (%.0f%%)   ",
               LatColour(ms), ms, kReset, s,
               l ? kRed : kDim, l, kReset, s ? (100.0 * l / s) : 0.0);
        fflush(stdout);
    }
}

int ModeHog(int seconds) {
    PrintHeader("bandwidth load",
                "Real traffic to Cloudflare's public speed-test endpoint.\n"
                "Watch this process appear in netvis with live Down/Up rates.");
    printf("  PID %s%lu%s - look for netvistest.exe in the Processes tab\n\n",
           kBold, (unsigned long)GetCurrentProcessId(), kReset);

    Load load;
    load.Start(4, 2);

    uint64_t pd = 0, pu = 0;
    for (int t = 0; t < seconds; t++) {
        Sleep(1000);
        uint64_t d = g_down.load(), u = g_up.load();
        printf("\r  down %s%s%s   up %s%s%s   total %.1f MB   %ds/%ds  ",
               kGreen, HumanRate((double)(d - pd)).c_str(), kReset,
               kBlue, HumanRate((double)(u - pu)).c_str(), kReset,
               (d + u) / (1024.0 * 1024.0), t + 1, seconds);
        fflush(stdout);
        pd = d; pu = u;
    }
    load.Stop();
    printf("\n\n  moved %.1f MB down, %.1f MB up\n",
           g_down.load() / (1024.0 * 1024.0), g_up.load() / (1024.0 * 1024.0));
    printf("%s  Check in netvis: this PID's Down/Up columns should roughly match.\n"
           "  If Upload stayed at 0 while the numbers above moved, outbound\n"
           "  accounting is broken again.%s\n", kDim, kReset);
    return 0;
}

// The one to record. Three phases, all measured, nothing staged.
int ModeDemo(const std::string& host) {
    PrintHeader("latency under load",
                "Phase 1 measures your idle ping. Phase 2 saturates the line with real\n"
                "traffic and measures again. Turn on auto-block in netvis before starting\n"
                "and phase 3 measures what happens once this process is cut off.");

    Pinger p;
    if (!p.Open(host)) {
        printf("%sCould not resolve or open ICMP for %s%s\n", kRed, host.c_str(), kReset);
        return 1;
    }
    printf("  target %s   PID %s%lu%s\n\n", host.c_str(), kBold,
           (unsigned long)GetCurrentProcessId(), kReset);
    p.Run();

    // --- phase 1: idle -----------------------------------------------------
    printf("%s[1/3] baseline - keep the line quiet for 10s%s\n", kBold, kReset);
    for (int t = 0; t < 10; t++) {
        Sleep(1000);
        printf("\r      %s%6.1f ms%s   %2ds/10s   ", LatColour(p.last.load()), p.last.load(), kReset, t + 1);
        fflush(stdout);
    }
    auto base = p.TakePhase();
    printf("\r      avg %s%.1f ms%s   min %.1f   max %.1f   jitter %.1f            \n\n",
           LatColour(base.avg), base.avg, kReset, base.min, base.max, base.jitter);

    // --- phase 2: saturated ------------------------------------------------
    printf("%s[2/3] saturating the connection%s\n", kBold, kReset);
    Load load;
    load.Start(4, 2);

    bool blocked = false;
    int quiet = 0, elapsed = 0;
    uint64_t pd = 0, pu = 0;
    double peakRate = 0;
    const int kMaxWait = 90;

    while (elapsed < kMaxWait && !blocked) {
        Sleep(1000);
        elapsed++;
        uint64_t d = g_down.load(), u = g_up.load();
        double rate = (double)((d - pd) + (u - pu));
        pd = d; pu = u;
        peakRate = (std::max)(peakRate, rate);

        printf("\r      %s%6.1f ms%s   moving %s   %2ds   ",
               LatColour(p.last.load()), p.last.load(), kReset, HumanRate(rate).c_str(), elapsed);
        fflush(stdout);

        // "Blocked" means throughput collapsed and stayed collapsed while the
        // workers were still trying - which is what netvis cutting the process
        // off looks like from in here. Requiring a real peak first stops a slow
        // start from being read as a block.
        if (peakRate > 400 * 1024 && rate < 40 * 1024) {
            if (++quiet >= 3) blocked = true;
        } else {
            quiet = 0;
        }
    }
    auto loaded = p.TakePhase();
    printf("\r      avg %s%.1f ms%s   min %.1f   max %.1f   jitter %.1f            \n",
           LatColour(loaded.avg), loaded.avg, kReset, loaded.min, loaded.max, loaded.jitter);

    if (blocked)
        printf("      %s* netvis cut this process off after %ds *%s\n\n", kGreen, elapsed, kReset);
    else
        printf("      %s(nothing blocked it - is auto-block on, and is the threshold\n"
               "       below the rate above?)%s\n\n", kYellow, kReset);

    // --- phase 3: after ----------------------------------------------------
    printf("%s[3/3] after%s\n", kBold, kReset);
    for (int t = 0; t < 12; t++) {
        Sleep(1000);
        printf("\r      %s%6.1f ms%s   %2ds/12s   ", LatColour(p.last.load()), p.last.load(), kReset, t + 1);
        fflush(stdout);
    }
    auto after = p.TakePhase();
    printf("\r      avg %s%.1f ms%s   min %.1f   max %.1f   jitter %.1f            \n",
           LatColour(after.avg), after.avg, kReset, after.min, after.max, after.jitter);

    load.Stop();
    p.Close();

    // --- the table ---------------------------------------------------------
    printf("\n%s%s  %-22s %10s %10s %10s%s\n", kBold, kBlue, "phase", "avg ms", "max ms", "jitter", kReset);
    printf("  %-22s %s%10.1f%s %10.1f %10.1f\n", "idle", LatColour(base.avg), base.avg, kReset, base.max, base.jitter);
    printf("  %-22s %s%10.1f%s %10.1f %10.1f\n", "line saturated", LatColour(loaded.avg), loaded.avg, kReset, loaded.max, loaded.jitter);
    printf("  %-22s %s%10.1f%s %10.1f %10.1f\n", blocked ? "after netvis cut it" : "after load stopped",
           LatColour(after.avg), after.avg, kReset, after.max, after.jitter);

    if (base.avg > 0.5 && loaded.avg > base.avg) {
        printf("\n  Saturating the line cost %s%.0f ms%s (%.1fx). ",
               kRed, loaded.avg - base.avg, kReset, loaded.avg / base.avg);
        if (blocked)
            printf("Cutting the process off\n  brought it back to within %.0f ms of idle.\n",
                   after.avg - base.avg);
        else
            printf("\n");
    }
    printf("\n%s  Every number above was measured on this run. Nothing is simulated -\n"
           "  which is what makes it safe to put in front of a customer.%s\n", kDim, kReset);
    return 0;
}

// --------------------------------------------------------------- DNS probe

struct Probe { const char* domain; bool shouldBlock; };

// Trackers and ad networks that any decent blocklist covers, plus a control
// group that must keep working. A blocklist that scores 40/40 on the first
// group and also kills the second one is not a good blocklist, it is a broken
// internet connection - so both halves are reported.
const Probe kProbes[] = {
    {"doubleclick.net", true},              {"googlesyndication.com", true},
    {"google-analytics.com", true},         {"googletagmanager.com", true},
    {"adservice.google.com", true},         {"connect.facebook.net", true},
    {"scorecardresearch.com", true},        {"adnxs.com", true},
    {"criteo.com", true},                   {"taboola.com", true},
    {"outbrain.com", true},                 {"quantserve.com", true},
    {"moatads.com", true},                  {"amazon-adsystem.com", true},
    {"rubiconproject.com", true},           {"pubmatic.com", true},
    {"casalemedia.com", true},              {"adsrvr.org", true},
    {"bluekai.com", true},                  {"demdex.net", true},
    {"hotjar.com", true},                   {"mixpanel.com", true},
    {"branch.io", true},                    {"appsflyer.com", true},

    {"google.com", false},                  {"cloudflare.com", false},
    {"microsoft.com", false},               {"github.com", false},
    {"wikipedia.org", false},               {"netvis.cc", false},
};

// A domain counts as blocked if it fails to resolve at all, or resolves to a
// null address - the two things a DNS-layer blocker does.
bool Resolves(const char* domain, std::string& addr) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(domain, nullptr, &hints, &res) != 0 || !res) return false;

    char ip[INET_ADDRSTRLEN] = {0};
    auto* sa = (sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    addr = ip;
    return !(addr == "0.0.0.0" || addr == "127.0.0.1");
}

int ModeDns() {
    PrintHeader("ad & tracker blocking",
                "Resolves known tracker domains and reports which ones netvis stopped.\n"
                "No ads are displayed - what matters is whether the lookup got through.");

    // netvis flushes the resolver cache when it starts, but this tool may run
    // long after that, and a cached hit would look like a block that isn't
    // there any more (or the reverse).
    printf("  flushing the DNS cache first...\n");
    system("ipconfig /flushdns >nul 2>&1");
    Sleep(500);

    int adTotal = 0, adBlocked = 0, ctlTotal = 0, ctlBroken = 0;
    printf("\n  %-30s %-16s %s\n", "domain", "resolved to", "result");
    printf("  %s%s%s\n", kDim, "----------------------------------------------------------------", kReset);

    for (const auto& p : kProbes) {
        std::string addr;
        bool ok = Resolves(p.domain, addr);
        if (p.shouldBlock) {
            adTotal++;
            if (!ok) adBlocked++;
            printf("  %-30s %-16s %s%s%s\n", p.domain, ok ? addr.c_str() : "-",
                   ok ? kYellow : kGreen, ok ? "got through" : "BLOCKED", kReset);
        } else {
            ctlTotal++;
            if (!ok) ctlBroken++;
            printf("  %-30s %-16s %s%s%s\n", p.domain, ok ? addr.c_str() : "-",
                   ok ? kDim : kRed, ok ? "ok (expected)" : "BROKEN - false positive", kReset);
        }
    }

    printf("\n  %sTrackers blocked: %d/%d (%.0f%%)%s\n", kBold, adBlocked, adTotal,
           adTotal ? 100.0 * adBlocked / adTotal : 0.0, kReset);
    if (ctlBroken)
        printf("  %sWARNING: %d/%d ordinary sites were also blocked. The blocklist is\n"
               "  too aggressive - that breaks browsing, not just ads.%s\n",
               kRed, ctlBroken, ctlTotal, kReset);
    else
        printf("  %sNo false positives: all %d ordinary sites still resolve.%s\n",
               kGreen, ctlTotal, kReset);

    if (adBlocked == 0)
        printf("\n  %sNothing was blocked. Is \"Block trackers & malicious domains\"\n"
               "  switched on in the Settings tab?%s\n", kYellow, kReset);
    return 0;
}

// ------------------------------------------------------------------ DoH probe

// Tries to reach a DoH endpoint by HOSTNAME and reports whether netvis stopped
// it. This exercises the SNI path specifically: the connection is made to the
// resolver's real hostname, so a block here means netvis read the ClientHello
// and dropped it - not that an IP happened to be on a list.
//
// A short timeout is the whole mechanism: when netvis drops the ClientHello,
// the TLS handshake never completes and the connection hangs until it times
// out, which is what "blocked" looks like from out here. A resolver that is
// NOT blocked answers a real DoH query in well under a second.
struct DohTarget { const char* host; const char* path; };

const DohTarget kDohTargets[] = {
    {"cloudflare-dns.com", "/dns-query?name=example.com&type=A"},
    {"dns.google", "/resolve?name=example.com&type=A"},
    {"dns.quad9.net", "/dns-query?name=example.com&type=A"},
    {"doh.opendns.com", "/dns-query?name=example.com&type=A"},
    {"dns.adguard-dns.com", "/dns-query?name=example.com&type=A"},
};

// Returns true if the endpoint answered (DoH got through), false if it was
// blocked or unreachable. `ms` gets how long it took.
bool TryDoH(const DohTarget& t, long& ms) {
    auto t0 = std::chrono::steady_clock::now();
    bool got = false;

    HINTERNET net = InternetOpenA("netvistest-doh/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                  nullptr, nullptr, 0);
    if (net) {
        // Keep every phase on a short leash so a dropped ClientHello shows up
        // as a quick "blocked" rather than a 30s stall.
        DWORD tmo = 4000;
        InternetSetOptionA(net, INTERNET_OPTION_CONNECT_TIMEOUT, &tmo, sizeof(tmo));
        InternetSetOptionA(net, INTERNET_OPTION_SEND_TIMEOUT, &tmo, sizeof(tmo));
        InternetSetOptionA(net, INTERNET_OPTION_RECEIVE_TIMEOUT, &tmo, sizeof(tmo));

        HINTERNET con = InternetConnectA(net, t.host, INTERNET_DEFAULT_HTTPS_PORT, nullptr,
                                         nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (con) {
            const char* accept[] = {"application/dns-json", "application/dns-message", nullptr};
            HINTERNET req = HttpOpenRequestA(con, "GET", t.path, nullptr, nullptr, accept,
                                             INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD |
                                                 INTERNET_FLAG_NO_CACHE_WRITE,
                                             0);
            if (req) {
                if (HttpSendRequestA(req, nullptr, 0, nullptr, 0)) {
                    DWORD code = 0, sz = sizeof(code);
                    if (HttpQueryInfoA(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                                       &code, &sz, nullptr) &&
                        code >= 200 && code < 500) {
                        got = true; // a real HTTP answer came back = not blocked
                    }
                }
                InternetCloseHandle(req);
            }
            InternetCloseHandle(con);
        }
        InternetCloseHandle(net);
    }
    ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return got;
}

int ModeDoh() {
    PrintHeader("DNS-over-HTTPS blocking",
                "Tries to reach public DoH resolvers by hostname. Each one netvis stops\n"
                "is a browser that can no longer route DNS around your blocklist.");

    printf("  %-26s %-10s %s\n", "resolver", "time", "result");
    printf("  %s%s%s\n", kDim, "--------------------------------------------------", kReset);

    int total = 0, blocked = 0;
    for (const auto& t : kDohTargets) {
        long ms = 0;
        bool through = TryDoH(t, ms);
        total++;
        if (!through) blocked++;
        printf("  %-26s %s%5ld ms%s   %s%s%s\n", t.host, kDim, ms, kReset,
               through ? kYellow : kGreen, through ? "got through" : "BLOCKED", kReset);
    }

    // Control: an ordinary HTTPS site must still work. If the SNI path were
    // too broad it would show up here as a blocked control, the same shape as
    // the false-positive check in the DNS probe.
    DohTarget ctl{"example.com", "/"};
    long cms = 0;
    bool ctlOk = TryDoH(ctl, cms);
    printf("  %s%-26s %s%5ld ms%s   %s%s%s\n", kReset, "example.com (control)", kDim, cms, kReset,
           ctlOk ? kGreen : kRed, ctlOk ? "ok (expected)" : "BROKEN - false positive", kReset);

    printf("\n  %sDoH resolvers blocked: %d/%d%s\n", kBold, blocked, total, kReset);
    if (!ctlOk)
        printf("  %sWARNING: an ordinary HTTPS site was also blocked. The SNI filter is\n"
               "  catching too much - that breaks browsing, not just DoH.%s\n", kRed, kReset);
    if (blocked == 0)
        printf("\n  %sNothing was blocked. Is \"Block trackers & malicious domains\" on?\n"
               "  DoH blocking rides on the same switch.%s\n", kYellow, kReset);
    else if (blocked < total)
        printf("\n  %sSome got through - probably a resolver whose ClientHello was split\n"
               "  across packets. The known-IP backstop covers the common ones; add the\n"
               "  hostname to KnownDoHHosts() if a new one keeps slipping past.%s\n", kDim, kReset);
    return 0;
}

// ------------------------------------------------------------- alert triggers

int ModeAlerts() {
    PrintHeader("security alerts",
                "Does what netvis is supposed to notice, so you can check it notices.");

    // 1. A program reaching the internet under a name netvis has never seen.
    //    Copying this exe under a fresh random name is the cheapest honest way
    //    to produce a genuinely-new process rather than one already in the
    //    known-exes list.
    char tmp[MAX_PATH] = {0}, self[MAX_PATH] = {0};
    GetTempPathA(sizeof(tmp), tmp);
    GetModuleFileNameA(nullptr, self, sizeof(self));
    char fresh[MAX_PATH];
    snprintf(fresh, sizeof(fresh), "%snetvis_probe_%lu.exe", tmp, (unsigned long)GetTickCount());

    printf("  1. first-contact alert\n");
    if (CopyFileA(self, fresh, FALSE)) {
        std::string cmd = std::string("\"") + fresh + "\" __phonehome";
        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            printf("     launched %s%s%s\n", kDim, fresh, kReset);
            WaitForSingleObject(pi.hProcess, 15000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            printf("     %sexpect: \"a program reached the internet for the first time\"%s\n",
                   kGreen, kReset);
        } else {
            printf("     %scould not launch the probe%s\n", kRed, kReset);
        }
        DeleteFileA(fresh);
    } else {
        printf("     %scould not copy self to %s%s\n", kRed, tmp, kReset);
    }

    // 2. A process that starts accepting inbound connections.
    printf("\n  2. listening-socket alert\n");
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv != INVALID_SOCKET) {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = INADDR_ANY;
        a.sin_port = htons(45789);
        if (bind(srv, (sockaddr*)&a, sizeof(a)) == 0 && listen(srv, 4) == 0) {
            printf("     listening on 0.0.0.0:45789 for 20s\n");
            printf("     %sexpect: \"this program started accepting incoming connections\"%s\n",
                   kGreen, kReset);
            Sleep(20000);
        } else {
            printf("     %scould not bind port 45789 (already in use?)%s\n", kYellow, kReset);
        }
        closesocket(srv);
    }

    printf("\n  %sBoth alerts should also raise a Windows notification if \"System\n"
           "  notification on every alert\" is on.%s\n", kDim, kReset);
    return 0;
}

// The child spawned by ModeAlerts: make one outbound connection and leave.
int PhoneHome() {
    HINTERNET net = InternetOpenA("netvis-probe/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (net) {
        HINTERNET url = InternetOpenUrlA(net, "https://speed.cloudflare.com/__down?bytes=65536",
                                         nullptr, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
        if (url) {
            char buf[8192];
            DWORD n = 0;
            while (InternetReadFile(url, buf, sizeof(buf), &n) && n > 0) {}
            InternetCloseHandle(url);
        }
        InternetCloseHandle(net);
    }
    Sleep(3000);
    return 0;
}

// --------------------------------------------------------------- limit check

int ModeLimit(int seconds) {
    PrintHeader("speed limit check",
                "Set a limit on netvistest.exe in netvis first (right-click ->\n"
                "Limit traffic...), then run this and see whether it is enforced.");
    printf("  PID %s%lu%s - measuring for %ds\n\n", kBold,
           (unsigned long)GetCurrentProcessId(), kReset, seconds);

    Load load;
    load.Start(4, 2);

    std::vector<double> dRates, uRates;
    uint64_t pd = 0, pu = 0;
    for (int t = 0; t < seconds; t++) {
        Sleep(1000);
        uint64_t d = g_down.load(), u = g_up.load();
        double dr = (double)(d - pd), ur = (double)(u - pu);
        pd = d; pu = u;
        // The first two seconds are ramp-up, not steady state.
        if (t >= 2) { dRates.push_back(dr); uRates.push_back(ur); }
        printf("\r  down %s   up %s   %2ds/%ds  ",
               HumanRate(dr).c_str(), HumanRate(ur).c_str(), t + 1, seconds);
        fflush(stdout);
    }
    load.Stop();

    auto avg = [](const std::vector<double>& v) {
        if (v.empty()) return 0.0;
        double s = 0; for (double x : v) s += x; return s / v.size();
    };
    auto peak = [](const std::vector<double>& v) {
        return v.empty() ? 0.0 : *std::max_element(v.begin(), v.end());
    };

    printf("\n\n  %-10s %14s %14s\n", "", "sustained", "peak");
    printf("  %-10s %14s %14s\n", "download", HumanRate(avg(dRates)).c_str(), HumanRate(peak(dRates)).c_str());
    printf("  %-10s %14s %14s\n", "upload", HumanRate(avg(uRates)).c_str(), HumanRate(peak(uRates)).c_str());
    printf("\n%s  Compare the sustained figures against the limit you set. Peak can\n"
           "  overshoot briefly - a limiter that never overshoots is dropping\n"
           "  traffic rather than pacing it.%s\n", kDim, kReset);
    return 0;
}

// ---------------------------------------------------------------------- menu

void Usage() {
    printf("\n%snetvistest%s - test harness for netvis\n\n", kBold, kReset);
    printf("  netvistest demo [host]    baseline -> saturated -> blocked, with a table\n");
    printf("  netvistest hog [secs]     real download + upload load\n");
    printf("  netvistest ping [host]    live latency monitor\n");
    printf("  netvistest dns            probe the ad/tracker blocklist\n");
    printf("  netvistest doh            probe DNS-over-HTTPS blocking\n");
    printf("  netvistest alerts         trigger netvis's security alerts\n");
    printf("  netvistest limit [secs]   measure throughput against a speed limit\n\n");
}

int Menu() {
    while (true) {
        printf("\n%s%s  netvis test harness%s   %s(PID %lu)%s\n", kBold, kBlue, kReset, kDim,
               (unsigned long)GetCurrentProcessId(), kReset);
        printf("  1  latency demo      idle -> saturated -> blocked, with a summary table\n");
        printf("  2  bandwidth load    real traffic, watch it in the Processes tab\n");
        printf("  3  latency monitor   live ping\n");
        printf("  4  ad blocking       probe tracker domains\n");
        printf("  5  DoH blocking       probe DNS-over-HTTPS\n");
        printf("  6  security alerts   first contact + listening socket\n");
        printf("  7  speed limit       measure against a limit you set\n");
        printf("  0  quit\n\n  choice: ");
        fflush(stdout);

        char line[32] = {0};
        if (!fgets(line, sizeof(line), stdin)) return 0;
        switch (line[0]) {
            case '1': ModeDemo("8.8.8.8"); break;
            case '2': ModeHog(45); break;
            case '3': ModePing("8.8.8.8"); break;
            case '4': ModeDns(); break;
            case '5': ModeDoh(); break;
            case '6': ModeAlerts(); break;
            case '7': ModeLimit(25); break;
            case '0': return 0;
            default: printf("  ?\n"); break;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitConsole();

    int rc = 0;
    std::string mode = argc > 1 ? argv[1] : "";
    std::string arg = argc > 2 ? argv[2] : "";

    if (mode == "__phonehome")   rc = PhoneHome();
    else if (mode == "demo")     rc = ModeDemo(arg.empty() ? "8.8.8.8" : arg);
    else if (mode == "hog")      rc = ModeHog(arg.empty() ? 45 : atoi(arg.c_str()));
    else if (mode == "ping")     rc = ModePing(arg.empty() ? "8.8.8.8" : arg);
    else if (mode == "dns")      rc = ModeDns();
    else if (mode == "doh")      rc = ModeDoh();
    else if (mode == "alerts")   rc = ModeAlerts();
    else if (mode == "limit")    rc = ModeLimit(arg.empty() ? 25 : atoi(arg.c_str()));
    else if (mode.empty())       rc = Menu();
    else { Usage(); rc = 2; }

    WSACleanup();
    return rc;
}
