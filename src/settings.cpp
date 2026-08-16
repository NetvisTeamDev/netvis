#include "settings.h"
#include "app_paths.h"
#include "log.h"

#include <windows.h>
#include <fstream>
#include <sstream>

namespace {

// Central per-machine data dir, C:\Program Files\netvis (created if needed).
// Kept alongside blocklist.db so all of netvis's persistent state lives in
// one place rather than scattered next to the exe.
std::string NetvisDataDir() {
    char base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramFiles", base, sizeof(base));
    std::string dir = (n > 0 && n < sizeof(base)) ? (std::string(base) + "\\netvis") : "C:\\Program Files\\netvis";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

std::string SettingsPath() {
    std::string dir = NetvisDataDir();
    std::string path = dir + "\\netvis_settings.txt";
    // One-time migration: if an old settings file sits next to the exe,
    // move its contents to the new location so users don't lose their
    // toggles and per-app usage history.
    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::string oldPath = ExeDir() + "\\netvis_settings.txt";
        if (GetFileAttributesA(oldPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            MoveFileA(oldPath.c_str(), path.c_str());
        }
    }
    return path;
}

// Splits "key=value" once, so values containing '=' survive intact.
bool SplitKeyValue(const std::string& line, std::string* key, std::string* value) {
    auto eq = line.find('=');
    if (eq == std::string::npos) return false;
    *key = line.substr(0, eq);
    *value = line.substr(eq + 1);
    return true;
}

} // namespace

Settings Settings::Load() {
    Settings s;
    std::ifstream f(SettingsPath());
    if (!f) return s;

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        std::string key, value;
        if (!SplitKeyValue(line, &key, &value)) continue;

        if (key == "pin") s.pinned.insert(value);
        else if (key == "exempt") s.autoBlockExempt.insert(value);
        else if (key == "known") s.knownExes.insert(value);
        else if (key == "adblock") s.adBlockerEnabled = (value == "1");
        else if (key == "autoblock_threshold") s.autoBlockThreshold = atof(value.c_str());
        else if (key == "autoblock_unit") s.autoBlockUnitIdx = atoi(value.c_str());
        else if (key == "run_in_background") s.runInBackground = (value == "1");
        else if (key == "notify_on_alert") s.notifyOnAlert = (value == "1");
        else if (key == "use_default_blocklist") s.useDefaultBlocklist = (value == "1");
        else if (key == "run_on_startup") s.runOnStartup = (value == "1");
        else if (key == "theme") s.themeMode = atoi(value.c_str());
        else if (key == "limit" || key == "lifetime") {
            // "limit=<exe>|<number>"
            auto bar = value.find('|');
            if (bar == std::string::npos) continue;
            std::string exe = value.substr(0, bar);
            uint64_t n = strtoull(value.c_str() + bar + 1, nullptr, 10);
            if (key == "limit") s.limits[exe] = n;
            else s.lifetimeBytes[exe] = n;
        }
    }

    Log("settings: loaded %zu pins, %zu exempt, %zu limits, %zu known exes", s.pinned.size(),
        s.autoBlockExempt.size(), s.limits.size(), s.knownExes.size());
    return s;
}

void Settings::Save() const {
    std::ofstream f(SettingsPath(), std::ios::trunc);
    if (!f) {
        Log("settings: could not write %s", SettingsPath().c_str());
        return;
    }

    f << "# netvis settings - edit while the app is closed, it rewrites this on exit\n";
    f << "adblock=" << (adBlockerEnabled ? 1 : 0) << "\n";
    f << "autoblock_threshold=" << autoBlockThreshold << "\n";
    f << "autoblock_unit=" << autoBlockUnitIdx << "\n";
    f << "run_in_background=" << (runInBackground ? 1 : 0) << "\n";
    f << "notify_on_alert=" << (notifyOnAlert ? 1 : 0) << "\n";
    f << "use_default_blocklist=" << (useDefaultBlocklist ? 1 : 0) << "\n";
    f << "run_on_startup=" << (runOnStartup ? 1 : 0) << "\n";
    f << "theme=" << themeMode << "\n";

    for (const auto& p : pinned) f << "pin=" << p << "\n";
    for (const auto& e : autoBlockExempt) f << "exempt=" << e << "\n";
    for (const auto& [exe, bps] : limits) f << "limit=" << exe << "|" << bps << "\n";
    for (const auto& [exe, bytes] : lifetimeBytes) f << "lifetime=" << exe << "|" << bytes << "\n";
    for (const auto& k : knownExes) f << "known=" << k << "\n";

    Log("settings: saved");
}
