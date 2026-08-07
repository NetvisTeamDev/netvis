#include "icon_cache.h"
#include <thread>

IconCache::~IconCache() {
    for (auto& [path, srv] : textures_)
        if (srv) srv->Release();
}

void IconCache::WarmAsync(const std::string& path) {
    std::thread([this, path]() {
        IconPixels px = ExtractIconRGBA(path);
        std::lock_guard<std::mutex> lock(mu_);
        pending_[path] = std::move(px); // stored even on failure (ok=false) so we don't retry every frame
    }).detach();
}

ID3D11ShaderResourceView* IconCache::Get(const std::string& path) {
    if (path.empty()) return nullptr;

    bool needsWarm = false;
    IconPixels px;
    bool havePixels = false;

    {
        std::lock_guard<std::mutex> lock(mu_);
        auto tex = textures_.find(path);
        if (tex != textures_.end()) return tex->second;

        if (!requested_.count(path)) {
            requested_.insert(path);
            needsWarm = true;
        } else {
            auto pend = pending_.find(path);
            if (pend != pending_.end()) {
                if (pend->second.ok) {
                    px = std::move(pend->second);
                    havePixels = true;
                }
                pending_.erase(pend); // drop it either way - success handled below, failure means "don't retry"
            }
        }
    }

    if (needsWarm) {
        WarmAsync(path);
        return nullptr;
    }
    if (!havePixels) return nullptr; // still extracting, or extraction failed

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = px.width;
    desc.Height = px.height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sub = {};
    sub.pSysMem = px.rgba.data();
    sub.SysMemPitch = px.width * 4;

    ID3D11Texture2D* tex2d = nullptr;
    if (FAILED(device_->CreateTexture2D(&desc, &sub, &tex2d))) return nullptr;

    ID3D11ShaderResourceView* srv = nullptr;
    HRESULT hr = device_->CreateShaderResourceView(tex2d, nullptr, &srv);
    tex2d->Release();
    if (FAILED(hr)) return nullptr;

    std::lock_guard<std::mutex> lock(mu_);
    textures_[path] = srv;
    return srv;
}
