#include "ipban.h"
#include "log.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

// Serialises rule rewrites: netvis rebuilds the whole set on every change,
// and callers fire these from background threads, so two overlapping netsh
// runs must not interleave their delete/add pairs.
std::mutex g_rulesMu;

// Rule names netvis owns. One per direction and address family, because
// netsh won't accept a mix of IPv4 and IPv6 literals in a single remoteip
// list. Anything named "netvis-ban-*" is ours to delete and recreate.
const wchar_t* kRules[] = {
    L"netvis-ban-out-v4", L"netvis-ban-in-v4",
    L"netvis-ban-out-v6", L"netvis-ban-in-v6",
};

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

bool IsIPv4(const std::string& s) {
    in_addr a;
    return inet_pton(AF_INET, s.c_str(), &a) == 1;
}
bool IsIPv6(const std::string& s) {
    in6_addr a;
    return inet_pton(AF_INET6, s.c_str(), &a) == 1;
}

// Full path to netsh, so an odd PATH can't send us somewhere else while we're
// running elevated.
std::wstring NetshPath() {
    wchar_t sys[MAX_PATH];
    UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"netsh.exe";
    return std::wstring(sys) + L"\\netsh.exe";
}

// Run one netsh invocation hidden and wait for it. Returns its exit code, or
// -1 if it couldn't be launched. cmdline is the full command line (arg0
// included); CreateProcessW may modify the buffer, so it's a mutable copy.
int RunNetsh(const std::wstring& args) {
    std::wstring cmd = L"\"" + NetshPath() + L"\" " + args;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        Log("ipban: CreateProcess(netsh) failed (%lu)", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

void DeleteRule(const wchar_t* name) {
    // Deleting a non-existent rule returns non-zero; that's fine, we only
    // care that afterwards it's gone.
    RunNetsh(std::wstring(L"advfirewall firewall delete rule name=\"") + name + L"\"");
}

// Adds a block rule for one direction/family with a comma-separated remoteip
// list. netsh caps a command line's length, so very long lists are chunked
// across several rules of the same name (multiple rules with one name are
// allowed and all take effect).
void AddRule(const wchar_t* name, const wchar_t* dir, const std::vector<std::string>& ips) {
    const size_t kChunk = 200; // keep each command comfortably short
    for (size_t start = 0; start < ips.size(); start += kChunk) {
        std::wstring list;
        for (size_t i = start; i < ips.size() && i < start + kChunk; i++) {
            if (!list.empty()) list += L",";
            list += Widen(ips[i]);
        }
        std::wstring args = std::wstring(L"advfirewall firewall add rule name=\"") + name +
                            L"\" dir=" + dir + L" action=block enable=yes profile=any remoteip=" + list;
        int rc = RunNetsh(args);
        if (rc != 0) Log("ipban: add %ls returned %d", name, rc);
    }
}

} // namespace

namespace ipban {

void SetBlockedIPs(const std::vector<std::string>& ips) {
    std::lock_guard<std::mutex> lock(g_rulesMu);
    // Always start from a clean slate so the rules mirror exactly this list.
    for (auto* r : kRules) DeleteRule(r);

    std::vector<std::string> v4, v6;
    for (const auto& ip : ips) {
        if (IsIPv4(ip)) v4.push_back(ip);
        else if (IsIPv6(ip)) v6.push_back(ip);
        // anything that isn't an IP literal is ignored - domains are handled
        // by the DNS blocker, not here.
    }

    if (!v4.empty()) {
        AddRule(L"netvis-ban-out-v4", L"out", v4);
        AddRule(L"netvis-ban-in-v4", L"in", v4);
    }
    if (!v6.empty()) {
        AddRule(L"netvis-ban-out-v6", L"out", v6);
        AddRule(L"netvis-ban-in-v6", L"in", v6);
    }
    Log("ipban: firewall now blocks %zu IPv4 + %zu IPv6 address(es)", v4.size(), v6.size());
}

void Clear() {
    std::lock_guard<std::mutex> lock(g_rulesMu);
    for (auto* r : kRules) DeleteRule(r);
    Log("ipban: cleared all ban rules");
}

} // namespace ipban
