// Everything that should survive closing the app, in one small text file
// (netvis_settings.txt, next to the exe).
//
// Deliberately a flat key/value text format rather than a database: it's a
// few hundred lines at most, it's readable and hand-editable when
// something goes wrong, and it avoids taking on a dependency for what
// amounts to a handful of sets and counters.
//
// Note that per-process state is keyed by lowercased exe NAME, not PID -
// PIDs are meaningless across restarts, and "always keep Steam pinned" is
// what the user actually meant when they pinned it.
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct Settings {
    std::unordered_set<std::string> pinned;
    std::unordered_set<std::string> autoBlockExempt;
    std::unordered_map<std::string, uint64_t> limits; // exe name -> bytes/sec
    std::unordered_set<std::string> knownExes;        // seeds the alerts "seen before" set

    // Lifetime bytes per exe, so usage isn't lost on restart.
    std::unordered_map<std::string, uint64_t> lifetimeBytes;

    bool adBlockerEnabled = true;
    bool autoBlockEnabled = false;
    double autoBlockThreshold = 1.0;
    int autoBlockUnitIdx = 1;
    bool runInBackground = false;

    // Loads from disk; missing file just yields defaults.
    static Settings Load();
    void Save() const;
};
