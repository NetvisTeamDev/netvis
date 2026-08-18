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
    // Auto-block is deliberately NOT persisted: it cuts programs off the
    // internet on its own, so it starts off every launch and has to be
    // switched on knowingly. The threshold below IS remembered, so turning
    // it on is one click.
    double autoBlockThreshold = 1.0;
    int autoBlockUnitIdx = 1;
    // Default on: netvis is a monitor/blocker that's meant to keep working
    // after you close the window - it also starts with Windows, so quitting
    // outright on the close button is the surprising behaviour, not staying
    // resident. Closing hides to the tray; "Exit" from the tray really quits.
    bool runInBackground = true;
    bool notifyOnAlert = true;
    bool useDefaultBlocklist = true; // whether to merge the built-in malicious-domain database
    // Whether the user wants netvis to start with Windows. The scheduled
    // task used to be the only record of this, which broke in two ways: an
    // uninstall deletes the task but keeps this file, so a reinstall never
    // recreated it; and a task made by a build in one folder kept pointing
    // there after the app moved to Program Files. The intent lives here now,
    // and the task is re-registered from it on every launch.
    bool runOnStartup = true;

    // 0 = follow Windows, 1 = light, 2 = dark. Defaults to following the
    // system, which is what most people expect a modern app to do.
    int themeMode = 0;

    // Loads from disk; missing file just yields defaults.
    static Settings Load();
    void Save() const;
};
