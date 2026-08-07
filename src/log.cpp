#include "log.h"
#include "app_paths.h"
#include <cstdio>
#include <ctime>
#include <mutex>
#include <windows.h>

namespace {
std::mutex g_mu;
FILE* g_file = nullptr;
}

void LogInit() {
    std::lock_guard<std::mutex> lock(g_mu);
    std::string path = ExeDir() + "\\netvis.log";
    g_file = fopen(path.c_str(), "a");
}

void Log(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_file) return;

    SYSTEMTIME t;
    GetLocalTime(&t);
    fprintf(g_file, "%04d/%02d/%02d %02d:%02d:%02d ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_file, fmt, args);
    va_end(args);

    fprintf(g_file, "\n");
    fflush(g_file);
}
