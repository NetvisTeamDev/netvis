#include "settings.h"
#include "app_paths.h"
#include "log.h"

#include <fstream>
#include <sstream>

namespace {

std::string SettingsPath() { return ExeDir() + "\\netvis_settings.txt"; }

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
        else if (key == "autoblock") s.autoBlockEnabled = (value == "1");
        else if (key == "autoblock_threshold") s.autoBlockThreshold = atof(value.c_str());
        else if (key == "autoblock_unit") s.autoBlockUnitIdx = atoi(value.c_str());
        else if (key == "run_in_background") s.runInBackground = (value == "1");
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
    f << "autoblock=" << (autoBlockEnabled ? 1 : 0) << "\n";
    f << "autoblock_threshold=" << autoBlockThreshold << "\n";
    f << "autoblock_unit=" << autoBlockUnitIdx << "\n";
    f << "run_in_background=" << (runInBackground ? 1 : 0) << "\n";

    for (const auto& p : pinned) f << "pin=" << p << "\n";
    for (const auto& e : autoBlockExempt) f << "exempt=" << e << "\n";
    for (const auto& [exe, bps] : limits) f << "limit=" << exe << "|" << bps << "\n";
    for (const auto& [exe, bytes] : lifetimeBytes) f << "lifetime=" << exe << "|" << bytes << "\n";
    for (const auto& k : knownExes) f << "known=" << k << "\n";

    Log("settings: saved");
}
