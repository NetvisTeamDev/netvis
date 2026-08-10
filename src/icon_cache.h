// Turns exe paths into ImGui-displayable textures. Pixel extraction (disk
// + GDI work) happens on background threads so a burst of newly-seen
// processes doesn't stall a frame; the actual D3D11 texture upload happens
// lazily on the UI thread (Get()) since D3D11 device calls aren't safe to
// make off it.
#pragma once
#include <d3d11.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "winicon.h"

class IconCache {
public:
    explicit IconCache(ID3D11Device* device) : device_(device) {}
    ~IconCache();

    // Returns a texture SRV for `key`, or nullptr if it's not ready yet
    // (extraction kicked off in the background - call again next frame) or
    // if extraction failed. `key` is a stable identity (the lowercased exe
    // name) so every process sharing a name shows the same icon; `exePath`
    // is where the icon is actually read from. Extraction only starts once
    // some caller supplies a non-empty path for that key, so a process
    // instance whose path couldn't be resolved doesn't poison the name with
    // a permanent "no icon".
    ID3D11ShaderResourceView* Get(const std::string& key, const std::string& exePath);

private:
    void WarmAsync(const std::string& key, const std::string& exePath);

    ID3D11Device* device_;
    std::mutex mu_;
    std::unordered_set<std::string> requested_;
    std::unordered_map<std::string, IconPixels> pending_; // ready pixel data, not yet uploaded
    std::unordered_map<std::string, ID3D11ShaderResourceView*> textures_; // uploaded, UI-thread only
};
