// Small helper: the directory the running exe lives in, used to find
// blocklist.txt/allowlist.txt and to write log files next to netvis.exe
// (same convention the rest of the app uses).
#pragma once
#include <windows.h>
#include <string>

inline std::string ExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return ".";
    std::wstring w(buf, n);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dirW = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);

    int len = WideCharToMultiByte(CP_UTF8, 0, dirW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return ".";
    std::string dir(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, dirW.c_str(), -1, dir.data(), len, nullptr, nullptr);
    return dir;
}
