#include "icon_cache.h"
#include <windows.h>
#include <objbase.h>
#include <thread>

#pragma comment(lib, "ole32.lib")

IconCache::~IconCache() {
    for (auto& [path, srv] : textures_)
        if (srv) srv->Release();
}

void IconCache::WarmAsync(const std::string& key, const std::string& exePath) {
    std::thread([this, key, exePath]() {
        // SHGetFileInfo (used inside ExtractIconRGBA) goes through the shell,
        // which requires COM to be initialized on the calling thread. Every
        // extraction runs on its own fresh thread, so without this the shell
        // call succeeds or fails unpredictably - which is exactly the
        // "icons randomly show up as the letter badge" behavior. Initialize
        // COM per worker thread and the real icon comes back reliably.
        HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        IconPixels px = ExtractIconRGBA(exePath);
        if (SUCCEEDED(hr)) ::CoUninitialize();

        std::lock_guard<std::mutex> lock(mu_);
        pending_[key] = std::move(px); // stored either way; Get() decides whether to retry
    }).detach();
}

ID3D11ShaderResourceView* IconCache::Get(const std::string& key, const std::string& exePath) {
    if (key.empty()) return nullptr;

    bool needsWarm = false;
    IconPixels px;
    bool havePixels = false;

    {
        std::lock_guard<std::mutex> lock(mu_);
        auto tex = textures_.find(key);
        if (tex != textures_.end()) return tex->second;

        auto pend = pending_.find(key);
        if (pend != pending_.end()) {
            if (pend->second.ok) {
                px = std::move(pend->second);
                havePixels = true;
                failed_.erase(key);
            } else {
                // Extraction failed. Schedule another go instead of giving
                // up for the lifetime of the process: 2s, 5s, 15s, 60s,
                // 300s. Transient causes (the shell still starting after a
                // reboot, a process not fully up yet) clear within seconds;
                // an exe that genuinely has no icon settles into the letter
                // badge after five cheap attempts.
                static const uint64_t backoffMs[kMaxAttempts] = {2000, 5000, 15000, 60000, 300000};
                Failure& f = failed_[key];
                if (f.attempts < kMaxAttempts) {
                    f.nextTryMs = ::GetTickCount64() + backoffMs[f.attempts];
                    f.attempts++;
                    requested_.erase(key); // let it be requested again once the delay is up
                }
            }
            pending_.erase(pend);
        } else if (!requested_.count(key) && !exePath.empty()) {
            // Only start extraction once we actually have a path to read
            // from - a pathless instance of this exe must not lock the name
            // into a permanent "no icon" state.
            auto f = failed_.find(key);
            bool waiting = f != failed_.end() &&
                           (f->second.attempts >= kMaxAttempts || ::GetTickCount64() < f->second.nextTryMs);
            if (!waiting) {
                requested_.insert(key);
                needsWarm = true;
            }
        }
    }

    if (needsWarm) {
        WarmAsync(key, exePath);
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
    textures_[key] = srv;
    return srv;
}
