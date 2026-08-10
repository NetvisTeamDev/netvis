#include "blocklist_store.h"
#include "log.h"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace {

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string ProgramFilesNetvisDir() {
    char base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramFiles", base, sizeof(base));
    std::string dir;
    if (n > 0 && n < sizeof(base)) dir = std::string(base) + "\\netvis";
    else dir = "C:\\Program Files\\netvis";
    CreateDirectoryA(dir.c_str(), nullptr); // ignore "already exists"
    return dir;
}

} // namespace

namespace blocklist_store {

std::string DbPath() { return ProgramFilesNetvisDir() + "\\blocklist.db"; }

std::vector<std::string> Load() {
    std::vector<std::string> out;
    std::ifstream f(DbPath());
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        out.push_back(ToLower(line));
    }
    return out;
}

void Save(const std::vector<std::string>& domains) {
    std::string path = DbPath();
    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        Log("blocklist_store: could not write %s", path.c_str());
        return;
    }
    f << "# netvis firewall blocklist - one domain per line, # for comments\n";
    for (const auto& d : domains) f << d << "\n";
    Log("blocklist_store: saved %zu domains to %s", domains.size(), path.c_str());
}

std::vector<std::string> ParseFile(const std::string& path) {
    std::vector<std::string> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        // hosts-file style "0.0.0.0 domain" -> take the last token.
        std::istringstream iss(line);
        std::string tok, last;
        while (iss >> tok) last = tok;
        if (last.empty()) continue;
        if (last == "0.0.0.0" || last == "127.0.0.1" || last == "::1") continue; // whole line was just an IP
        out.push_back(ToLower(last));
    }
    return out;
}

} // namespace blocklist_store
