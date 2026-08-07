// Resolves a PID to its process name and full exe path, with a small
// cache since this gets called every tick for every PID we've seen.
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

class ProcNames {
public:
    // Returns the process's base name (e.g. "chrome.exe"), or "" if it
    // can't be resolved (already exited, access denied, etc).
    std::string Name(uint32_t pid);

    // Returns the full path to the exe, or "" if it can't be resolved.
    std::string Path(uint32_t pid);

    // Drops cache entries for PIDs not in `alive` - call this once per
    // tick with the current PID set so exited processes' entries don't
    // accumulate forever.
    void Prune(const std::unordered_map<uint32_t, bool>& alive);

private:
    struct Entry {
        std::string name;
        std::string path;
        bool resolved = false;
    };
    const Entry& Resolve(uint32_t pid);

    std::mutex mu_;
    std::unordered_map<uint32_t, Entry> cache_;
};
