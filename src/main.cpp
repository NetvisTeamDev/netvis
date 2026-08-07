// netvis - GlassWire-style bandwidth monitor / ad blocker / per-process
// firewall for Windows. Dear ImGui + Win32 + DirectX11 UI.
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "monitor.h"
#include "blocker.h"
#include "pidblock.h"
#include "icon_cache.h"
#include "traffic_graph.h"
#include "log.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {

std::string FormatBytes(uint64_t b) {
    static const char* units = "KMGTPE";
    if (b < 1024) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
        return buf;
    }
    double div = 1024.0;
    int exp = 0;
    for (uint64_t n = b / 1024; n >= 1024; n /= 1024) { div *= 1024.0; exp++; }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f %cB", (double)b / div, units[exp]);
    return buf;
}

std::string FormatRate(double bytesPerSec) {
    return FormatBytes((uint64_t)std::max(0.0, bytesPerSec)) + "/s";
}

} // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    LogInit();
    Log("netvis starting");

    WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, hInstance,
                       nullptr, nullptr, nullptr, nullptr, L"netvis", nullptr};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"netvis - bandwidth monitor",
                                 WS_OVERLAPPEDWINDOW, 100, 100, 940, 640,
                                 nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // --- app state ---
    Monitor mon;
    std::string monErr;
    bool monOk = mon.Start(&monErr);

    Blocker blk;
    std::string blkErr;
    bool blkOk = blk.Start(&blkErr);

    PidBlockManager pidMgr;
    IconCache icons(g_pd3dDevice);
    TrafficGraph graph(60);

    std::vector<AppStats> rows;
    double lastTickTime = ImGui::GetTime();
    std::string uiStatus;
    if (!monOk) uiStatus = "Capture failed: " + monErr;
    else if (!blkOk) uiStatus = "Ad blocker failed: " + blkErr;
    else uiStatus = "Capturing traffic - running as Administrator";

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        double now = ImGui::GetTime();
        if (monOk && now - lastTickTime >= 1.0) {
            lastTickTime = now;
            rows = mon.Snapshot();
            double totalDown = 0, totalUp = 0;
            for (const auto& r : rows) { totalDown += r.rateDown; totalUp += r.rateUp; }
            graph.Push(totalDown, totalUp);
        }

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("netvis", nullptr,
                      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                          ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        ImGui::TextWrapped("%s", uiStatus.c_str());
        ImGui::Text("Ads/trackers blocked: %lld", (long long)(blkOk ? blk.BlockedCount() : 0));
        ImGui::Spacing();

        graph.Draw(ImVec2(ImGui::GetContentRegionAvail().x, 80));
        ImGui::Spacing();

        if (ImGui::BeginTable("apps", 6,
                               ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                   ImGuiTableFlags_ScrollY,
                               ImGui::GetContentRegionAvail())) {
            ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 2.2f);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70);
            ImGui::TableSetupColumn("Down/s", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("Up/s", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("Total", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("Block", ImGuiTableColumnFlags_WidthFixed, 90);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            for (const auto& r : rows) {
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ID3D11ShaderResourceView* tex = icons.Get(r.exePath);
                if (tex) {
                    ImGui::Image((ImTextureID)(intptr_t)tex, ImVec2(16, 16));
                    ImGui::SameLine();
                }
                ImGui::TextUnformatted(r.name.c_str());

                ImGui::TableSetColumnIndex(1);
                if (r.pid == kUnknownPID) ImGui::TextUnformatted("-");
                else ImGui::Text("%u", r.pid);

                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(FormatRate(r.rateDown).c_str());

                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(FormatRate(r.rateUp).c_str());

                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(FormatBytes(r.totalDown + r.totalUp).c_str());

                ImGui::TableSetColumnIndex(5);
                if (r.pid == kUnknownPID) {
                    ImGui::TextDisabled("-");
                } else {
                    ImGui::PushID((int)r.pid);
                    bool blocked = pidMgr.IsBlocked(r.pid);
                    if (ImGui::SmallButton(blocked ? "Unblock" : "Block")) {
                        std::string err = blocked ? pidMgr.Unblock(r.pid) : pidMgr.Block(r.pid);
                        uiStatus = err.empty()
                                       ? "Capturing traffic - running as Administrator"
                                       : ("Block/unblock failed: " + err);
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }

        ImGui::End();

        ImGui::Render();
        const float clear_color[4] = {0.06f, 0.06f, 0.08f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    Log("netvis shutting down");
    pidMgr.UnblockAll();
    blk.Close();
    mon.Stop();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2,
        D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2,
            D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;

    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_ResizeWidth = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
