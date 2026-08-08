// trafficgen - tiny console tool for testing netvis's traffic detection
// (auto-block, per-process bandwidth graph, etc). Every 5 seconds, it
// bursts real download traffic for about a second by repeatedly pulling
// from Cloudflare's public speed-test endpoint (speed.cloudflare.com/__down),
// then goes quiet again until the next burst. This is genuine network
// traffic against a real, public speed-test service meant for exactly
// this - not a flood/attack against anything.
//
// Run it, note the PID it prints, and watch it show up in netvis's table
// with bursty Down/s during each ~1s window - a good way to verify the
// "auto-block high-traffic processes" feature actually catches something.
#include <windows.h>
#include <wininet.h>

#include <cstdio>
#include <chrono>
#include <thread>

#pragma comment(lib, "wininet.lib")

namespace {

// Bursts downloads for roughly durationMs milliseconds.
void Burst(int durationMs) {
    HINTERNET hInternet = InternetOpenA("trafficgen/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) {
        printf("  InternetOpen failed (%lu)\n", GetLastError());
        return;
    }

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(durationMs);
    uint64_t totalBytes = 0;
    int requests = 0;

    while (std::chrono::steady_clock::now() < deadline) {
        // 2MB per request - big enough to generate a visible spike, small
        // enough that a handful per second doesn't take forever to land.
        HINTERNET hUrl = InternetOpenUrlA(
            hInternet, "https://speed.cloudflare.com/__down?bytes=2000000", nullptr, 0,
            INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI, 0);
        if (!hUrl) break;

        char buf[65536];
        DWORD read = 0;
        while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) {
            totalBytes += read;
            if (std::chrono::steady_clock::now() >= deadline) break;
        }
        InternetCloseHandle(hUrl);
        requests++;
    }

    InternetCloseHandle(hInternet);
    printf("  burst done: %d requests, %.1f MB\n", requests, totalBytes / 1024.0 / 1024.0);
}

} // namespace

int main() {
    printf("trafficgen - PID %lu\n", GetCurrentProcessId());
    printf("Bursts ~1s of real download traffic every 5s. Ctrl+C to stop.\n\n");

    const int kIdleMs = 5000;
    while (true) {
        printf("[idle %.1fs]\n", kIdleMs / 1000.0);
        std::this_thread::sleep_for(std::chrono::milliseconds(kIdleMs));

        printf("[burst]\n");
        Burst(1000);
    }
    return 0;
}
