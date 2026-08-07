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

    // Returns a texture SRV for path, or nullptr if it's not ready yet
    // (extraction kicked off in the background - call again next frame)
    // or if extraction failed (won't retry).
    ID3D11ShaderResourceView* Get(const std::string& path);

private:
    void WarmAsync(const std::string& path);

    ID3D11Device* device_;
    std::mutex mu_;
    std::unordered_set<std::string> requested_;
    std::unordered_map<std::string, IconPixels> pending_; // ready pixel data, not yet uploaded
    std::unordered_map<std::string, ID3D11ShaderResourceView*> textures_; // uploaded, UI-thread only
};
