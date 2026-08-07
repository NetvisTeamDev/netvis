#include "procname.h"
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace {

std::string NarrowFromWide(const wchar_t* w) {
    if (!w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}

std::string BaseName(const std::string& path) {
    auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

} // namespace

const ProcNames::Entry& ProcNames::Resolve(uint32_t pid) {
    Entry& e = cache_[pid]; // default-constructed (resolved=false) if new
    if (e.resolved) return e;
    e.resolved = true; // resolve at most once per PID, even on failure -
                        // avoids hammering OpenProcess every tick for a
                        // PID we can't get permission to inspect.

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return e;

    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) {
        e.path = NarrowFromWide(buf);
        e.name = BaseName(e.path);
    }
    CloseHandle(h);
    return e;
}

std::string ProcNames::Name(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    return Resolve(pid).name;
}

std::string ProcNames::Path(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mu_);
    return Resolve(pid).path;
}

void ProcNames::Prune(const std::unordered_map<uint32_t, bool>& alive) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (alive.find(it->first) == alive.end())
            it = cache_.erase(it);
        else
            ++it;
    }
}
