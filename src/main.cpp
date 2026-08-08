// netvis - GlassWire-style bandwidth monitor / ad blocker / per-process
// firewall for Windows. Dear ImGui + Win32 + DirectX11 UI.
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "monitor.h"
#include "blocker.h"
#include "pidblock.h"
#include "icon_cache.h"
#include "traffic_graph.h"
#include "connlist.h"
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

static ImFont* g_fontRegular = nullptr;
static ImFont* g_fontBold = nullptr;

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

// Plain ImGui::Text() isn't selectable, so there's no way to Ctrl+C a
// process name, PID, or IP:port out of the GUI - a real bandwidth/firewall
// tool gets used for exactly that a lot. This renders `text` as a
// borderless, read-only InputText instead, which looks like normal text
// but supports click-drag selection and copy like any real text field.
void CopyableText(const char* idSuffix, const std::string& text) {
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(1, 1, 1, 0.06f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(1, 1, 1, 0.10f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, ImGui::GetStyle().FramePadding.y));

    char buf[256];
    snprintf(buf, sizeof(buf), "%s", text.c_str());
    float w = ImGui::CalcTextSize(text.empty() ? " " : text.c_str()).x + 6.0f;
    ImGui::SetNextItemWidth(w);
    std::string id = std::string("##copy_") + idSuffix;
    ImGui::InputText(id.c_str(), buf, sizeof(buf), ImGuiInputTextFlags_ReadOnly | ImGuiInputTextFlags_NoHorizontalScroll);

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(3);
}

// Shared KB/s - MB/s - GB/s unit picker for the auto-block threshold and
// per-process traffic limit inputs.
constexpr uint64_t kUnitMultipliers[3] = {1024ull, 1024ull * 1024, 1024ull * 1024 * 1024};
const char* kUnitLabels[3] = {"KB/s", "MB/s", "GB/s"};

// Picks whichever of KB/MB/GB keeps the displayed value in a sane range,
// for pre-filling an input with an existing bytes/sec value.
void BytesPerSecToUnit(uint64_t bytesPerSec, double* outValue, int* outUnitIdx) {
    if (bytesPerSec >= kUnitMultipliers[2]) {
        *outUnitIdx = 2;
        *outValue = (double)bytesPerSec / (double)kUnitMultipliers[2];
    } else if (bytesPerSec >= kUnitMultipliers[1]) {
        *outUnitIdx = 1;
        *outValue = (double)bytesPerSec / (double)kUnitMultipliers[1];
    } else {
        *outUnitIdx = 0;
        *outValue = (double)bytesPerSec / (double)kUnitMultipliers[0];
    }
}

// Sorts by whichever table column the user clicked, matching the column
// order in the "apps" table (App=0, PID=1, Down/s=2, Up/s=3, Total=4).
void SortRows(std::vector<AppStats>& rows, int column, bool ascending) {
    auto compare = [column](const AppStats& a, const AppStats& b) -> int {
        switch (column) {
            case 0:
                return _stricmp(a.name.c_str(), b.name.c_str());
            case 1:
                return (a.pid < b.pid) ? -1 : (a.pid > b.pid ? 1 : 0);
            case 2:
                return (a.rateDown < b.rateDown) ? -1 : (a.rateDown > b.rateDown ? 1 : 0);
            case 3:
                return (a.rateUp < b.rateUp) ? -1 : (a.rateUp > b.rateUp ? 1 : 0);
            default: {
                uint64_t ta = a.totalDown + a.totalUp, tb = b.totalDown + b.totalUp;
                return (ta < tb) ? -1 : (ta > tb ? 1 : 0);
            }
        }
    };
    std::sort(rows.begin(), rows.end(),
              [&](const AppStats& a, const AppStats& b) { return ascending ? compare(a, b) < 0 : compare(a, b) > 0; });
}

std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// Processes we never want to auto-block, even if they briefly spike over
// the traffic threshold - blocking these would look like "the internet/PC
// stopped working" rather than "an app got throttled".
bool IsAutoBlockProtected(const std::string& name) {
    static const char* protectedNames[] = {
        "netvis.exe", "System", "System Idle Process", "svchost.exe",
        "wininit.exe", "services.exe", "lsass.exe", "csrss.exe",
    };
    for (const char* p : protectedNames)
        if (_stricmp(name.c_str(), p) == 0) return true;
    return false;
}

// A cohesive dark, rounded, generously-spaced theme - meant to look like a
// real shipped app rather than an ImGui demo. Palette is a dark slate
// background with a single blue accent used consistently for anything
// interactive/active (checkmarks, sliders, active tabs, selection).
void ApplyModernStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    style.WindowRounding = 8.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 5.0f;
    style.PopupRounding = 7.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 5.0f;

    style.WindowPadding = ImVec2(16, 14);
    style.FramePadding = ImVec2(10, 6);
    style.ItemSpacing = ImVec2(10, 8);
    style.ItemInnerSpacing = ImVec2(8, 6);
    style.CellPadding = ImVec2(10, 7);
    style.IndentSpacing = 20.0f;
    style.ScrollbarSize = 14.0f;
    style.GrabMinSize = 10.0f;

    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f; // thin defined edges on inputs/buttons instead of relying on subtle bg contrast alone
    style.TabBorderSize = 0.0f;
    style.SeparatorTextBorderSize = 1.0f;

    // Wider spread between layers than a typical "just increment by 0.03"
    // dark palette - flat, closely-spaced grays are what makes a dark UI
    // read as hazy/washed-out instead of crisp. Base is near-black, and
    // each layer up is a clearly distinct step, not a gentle gradient.
    const ImVec4 bgDark       = ImVec4(0.043f, 0.047f, 0.059f, 1.00f);
    const ImVec4 bgMed        = ImVec4(0.075f, 0.082f, 0.098f, 1.00f);
    const ImVec4 bgLight      = ImVec4(0.130f, 0.145f, 0.173f, 1.00f);
    const ImVec4 bgLighter    = ImVec4(0.184f, 0.204f, 0.243f, 1.00f);
    const ImVec4 accent       = ImVec4(0.271f, 0.608f, 1.000f, 1.00f);
    const ImVec4 accentHover  = ImVec4(0.400f, 0.690f, 1.000f, 1.00f);
    const ImVec4 accentActive = ImVec4(0.196f, 0.502f, 0.878f, 1.00f);
    const ImVec4 textMain     = ImVec4(0.961f, 0.965f, 0.973f, 1.00f);
    const ImVec4 textDim      = ImVec4(0.635f, 0.659f, 0.694f, 1.00f);
    const ImVec4 border       = ImVec4(0.294f, 0.318f, 0.361f, 1.00f);

    colors[ImGuiCol_Text] = textMain;
    colors[ImGuiCol_TextDisabled] = textDim;
    colors[ImGuiCol_WindowBg] = bgDark;
    colors[ImGuiCol_ChildBg] = bgMed;
    colors[ImGuiCol_PopupBg] = ImVec4(bgMed.x, bgMed.y, bgMed.z, 0.98f);
    colors[ImGuiCol_Border] = border;
    colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg] = bgLight;
    colors[ImGuiCol_FrameBgHovered] = bgLighter;
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.220f, 0.243f, 0.290f, 1.00f);
    colors[ImGuiCol_TitleBg] = bgDark;
    colors[ImGuiCol_TitleBgActive] = bgDark;
    colors[ImGuiCol_TitleBgCollapsed] = bgDark;
    colors[ImGuiCol_MenuBarBg] = bgMed;
    colors[ImGuiCol_ScrollbarBg] = bgDark;
    colors[ImGuiCol_ScrollbarGrab] = bgLight;
    colors[ImGuiCol_ScrollbarGrabHovered] = bgLighter;
    colors[ImGuiCol_ScrollbarGrabActive] = accent;
    colors[ImGuiCol_CheckMark] = accent;
    colors[ImGuiCol_SliderGrab] = accent;
    colors[ImGuiCol_SliderGrabActive] = accentActive;
    colors[ImGuiCol_Button] = bgLight;
    colors[ImGuiCol_ButtonHovered] = bgLighter;
    colors[ImGuiCol_ButtonActive] = accentActive;
    colors[ImGuiCol_Header] = ImVec4(accent.x, accent.y, accent.z, 0.35f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(accent.x, accent.y, accent.z, 0.55f);
    colors[ImGuiCol_HeaderActive] = ImVec4(accent.x, accent.y, accent.z, 0.75f);
    colors[ImGuiCol_Separator] = border;
    colors[ImGuiCol_SeparatorHovered] = accent;
    colors[ImGuiCol_SeparatorActive] = accentActive;
    colors[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_ResizeGripHovered] = accent;
    colors[ImGuiCol_ResizeGripActive] = accentActive;
    colors[ImGuiCol_Tab] = bgMed;
    colors[ImGuiCol_TabHovered] = accentHover;
    colors[ImGuiCol_TabSelected] = accent;
    colors[ImGuiCol_TabDimmed] = bgMed;
    colors[ImGuiCol_TabDimmedSelected] = bgLight;
    colors[ImGuiCol_TableHeaderBg] = bgLight;
    colors[ImGuiCol_TableBorderStrong] = border;
    colors[ImGuiCol_TableBorderLight] = ImVec4(border.x, border.y, border.z, 0.55f);
    colors[ImGuiCol_TableRowBg] = ImVec4(1, 1, 1, 0.00f);
    colors[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.05f);
    colors[ImGuiCol_TextSelectedBg] = ImVec4(accent.x, accent.y, accent.z, 0.35f);
    colors[ImGuiCol_DragDropTarget] = accent;
    colors[ImGuiCol_NavCursor] = accent;
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1, 1, 1, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.65f);
}

} // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    LogInit();
    Log("netvis starting");

    // Flush the OS DNS resolver cache on startup, so any domains resolved
    // (and cached) before the blocker/monitor came up don't linger and
    // skew testing (e.g. re-testing an ad blocker score right after a
    // rebuild). DnsFlushResolverCache isn't declared in the public SDK
    // headers (it's what ipconfig /flushdns calls under the hood, but
    // dnsapi.dll exports it), so it's loaded dynamically. Best-effort -
    // failure just means the cache goes stale until it naturally expires.
    {
        HMODULE dnsapi = ::LoadLibraryW(L"dnsapi.dll");
        if (dnsapi) {
            using FlushFn = BOOL(WINAPI*)();
            auto flush = reinterpret_cast<FlushFn>(::GetProcAddress(dnsapi, "DnsFlushResolverCache"));
            if (flush) {
                BOOL ok = flush();
                Log("netvis: DnsFlushResolverCache -> %s", ok ? "ok" : "failed");
            } else {
                Log("netvis: DnsFlushResolverCache not found in dnsapi.dll");
            }
            ::FreeLibrary(dnsapi);
        } else {
            Log("netvis: LoadLibrary(dnsapi.dll) failed");
        }
    }

    // Without this, Windows has no idea this app understands DPI scaling,
    // so on any scaled display (125%/150%/200% - the default on most
    // laptops and 4K monitors) it silently renders us at 96 DPI and then
    // bitmap-stretches the whole window to fit - which is what actually
    // causes a soft/hazy/"foggy" look, not the ImGui styling. Has to
    // happen before any window is created.
    ImGui_ImplWin32_EnableDpiAwareness();

    // Scale the initial window size for the current display's DPI so it
    // doesn't end up tiny in physical terms on a high-DPI screen now that
    // Windows isn't scaling it on our behalf anymore.
    HDC screenDC = ::GetDC(nullptr);
    int systemDpi = ::GetDeviceCaps(screenDC, LOGPIXELSX);
    ::ReleaseDC(nullptr, screenDC);
    float initialDpiScale = systemDpi / 96.0f;

    WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, hInstance,
                       nullptr, nullptr, nullptr, nullptr, L"netvis", nullptr};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"netvis - bandwidth monitor", WS_OVERLAPPEDWINDOW, 100, 100,
                                 (int)(940 * initialDpiScale), (int)(640 * initialDpiScale), nullptr, nullptr,
                                 wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // The exact per-monitor DPI scale for the window we just created (more
    // precise than the system-wide value used to size the window above,
    // and what actually matters for crisp text/UI on this specific
    // monitor).
    float dpiScale = ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd);
    Log("netvis: DPI scale = %.2f", dpiScale);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Dear ImGui's built-in font is a small bitmap font, which looks
    // pixelated/blurry at normal UI sizes once it's scaled. Load the real
    // Segoe UI TTF that ships with every Windows install instead, with
    // oversampling for crisp anti-aliased text. Falls back to the default
    // bitmap font if for some reason the system font files aren't there.
    {
        ImFontConfig cfg;
        cfg.OversampleH = 3;
        cfg.OversampleV = 3;
        cfg.PixelSnapH = true; // snap glyph origins to whole pixels - crisper at UI text sizes than free subpixel placement
        g_fontRegular = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 18.0f * dpiScale, &cfg);

        ImFontConfig boldCfg = cfg;
        boldCfg.MergeMode = false;
        g_fontBold = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 20.0f * dpiScale, &boldCfg);

        if (!g_fontRegular) {
            Log("netvis: segoeui.ttf not found, falling back to default ImGui font");
            g_fontRegular = io.Fonts->AddFontDefault();
        }
        if (!g_fontBold) g_fontBold = g_fontRegular;
        io.FontDefault = g_fontRegular;
    }

    ApplyModernStyle();
    if (dpiScale > 1.01f) ImGui::GetStyle().ScaleAllSizes(dpiScale);

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
    bool showClosedProcesses = false;
    double lastTickTime = ImGui::GetTime();
    bool autoBlockEnabled = false;
    double autoBlockThresholdValue = 1.0;
    int autoBlockUnitIdx = 1; // MB/s default
    std::unordered_set<std::string> autoBlockExempt; // lowercased exe names the user marked immune, e.g. via right-click
    int limitModalPid = -1;
    std::string limitModalName;
    bool openLimitModal = false;
    double limitInputValue = 512;
    int limitUnitIdx = 0; // KB/s default
    int sortColumn = 4;      // default: Total, descending (busiest first) - matches the old fixed sort
    bool sortAscending = false;
    int connViewPid = -1;
    std::string connViewName;
    bool openConnView = false;
    std::vector<ConnInfo> connViewRows;
    double connViewLastRefresh = 0.0;
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
            SortRows(rows, sortColumn, sortAscending);

            double totalDown = 0, totalUp = 0;
            for (const auto& r : rows) { totalDown += r.rateDown; totalUp += r.rateUp; }
            graph.Push(totalDown, totalUp);

            if (autoBlockEnabled) {
                double thresholdBytesPerSec = autoBlockThresholdValue * (double)kUnitMultipliers[autoBlockUnitIdx];
                for (const auto& r : rows) {
                    if (r.pid == kUnknownPID) continue;
                    if (pidMgr.IsBlocked(r.pid)) continue;
                    if (IsAutoBlockProtected(r.name)) continue;
                    if (autoBlockExempt.count(ToLowerAscii(r.name))) continue;
                    if (r.rateDown + r.rateUp <= thresholdBytesPerSec) continue;
                    std::string err = pidMgr.Block(r.pid);
                    if (err.empty()) {
                        Log("auto-block: %s (pid %u) exceeded %.2f %s, blocked", r.name.c_str(), r.pid,
                            autoBlockThresholdValue, kUnitLabels[autoBlockUnitIdx]);
                        uiStatus = "Auto-blocked " + r.name + " (high traffic)";
                    } else {
                        Log("auto-block: %s (pid %u) failed: %s", r.name.c_str(), r.pid, err.c_str());
                    }
                }
            }
        }

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 18));
        ImGui::Begin("netvis", nullptr,
                      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                          ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);
        ImGui::PopStyleVar();

        // --- header: title + status ---
        ImGui::PushFont(g_fontBold, 0.0f);
        ImGui::TextUnformatted("netvis");
        ImGui::PopFont();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f), "  bandwidth monitor & firewall");

        bool statusOk = monOk && blkOk;
        ImVec4 statusColor = statusOk ? ImVec4(0.35f, 0.78f, 0.45f, 1.0f) : ImVec4(0.95f, 0.55f, 0.30f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, statusColor);
        CopyableText("status", uiStatus);
        ImGui::PopStyleColor();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- toolbar: ad blocker stat + the two auto-behavior toggles ---
        ImGui::PushFont(g_fontBold, 0.0f);
        ImGui::TextColored(ImVec4(0.259f, 0.588f, 0.980f, 1.0f), "%lld", (long long)(blkOk ? blk.BlockedCount() : 0));
        ImGui::PopFont();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("ads/trackers blocked");

        if (blkOk) {
            ImGui::SameLine();
            ImGui::Dummy(ImVec2(24, 0));
            ImGui::SameLine();
            bool blockerEnabled = blk.Enabled();
            if (ImGui::Checkbox("Ad blocker enabled", &blockerEnabled)) {
                blk.SetEnabled(blockerEnabled);
            }
        }
        if (monOk) {
            ImGui::SameLine();
            ImGui::Dummy(ImVec2(24, 0));
            ImGui::SameLine();
            ImGui::Checkbox("Auto-block high-traffic processes", &autoBlockEnabled);
            if (autoBlockEnabled) {
                ImGui::SameLine();
                ImGui::SetNextItemWidth(80);
                ImGui::InputDouble("##autoBlockThreshold", &autoBlockThresholdValue, 0.0, 0.0, "%.2f");
                if (autoBlockThresholdValue < 0.01) autoBlockThresholdValue = 0.01;
                ImGui::SameLine();
                ImGui::SetNextItemWidth(90);
                ImGui::Combo("threshold##autoBlockUnit", &autoBlockUnitIdx, kUnitLabels, 3);
            }
        }
        ImGui::Spacing();
        ImGui::Spacing();

        graph.Draw(ImVec2(ImGui::GetContentRegionAvail().x, 90));
        {
            const ImGuiColorEditFlags swatchFlags =
                ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoBorder | ImGuiColorEditFlags_NoInputs;
            ImGui::ColorButton("##dlSwatch", ImVec4(0x35 / 255.0f, 0xc7 / 255.0f, 0x5f / 255.0f, 1.0f), swatchFlags,
                                ImVec2(10, 10));
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f), "Download");
            ImGui::SameLine(0, 16);
            ImGui::ColorButton("##upSwatch", ImVec4(0x66 / 255.0f, 0x96 / 255.0f, 0xfa / 255.0f, 1.0f), swatchFlags,
                                ImVec2(10, 10));
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f), "Upload");
        }
        ImGui::Spacing();
        ImGui::Spacing();

        // Small, right-aligned, sitting right above the table rather than
        // in the busier toolbar above - it's a display filter for this
        // table specifically, not an app-wide behavior toggle like the
        // ad-blocker/auto-block checkboxes.
        if (monOk) {
            const char* label = "Show closed processes";
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(3, 3));
            float boxW = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x + ImGui::CalcTextSize(label).x;
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(0.0f, ImGui::GetContentRegionAvail().x - boxW));
            ImGui::Checkbox(label, &showClosedProcesses);
            ImGui::PopStyleVar();
        }

        if (ImGui::BeginTable("apps", 6,
                               ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                   ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable,
                               ImGui::GetContentRegionAvail())) {
            ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 2.2f);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70);
            // PreferSortDescending on the rate/total columns: these jump
            // around a lot second to second, so the useful sort direction
            // is always "busiest first" - defaulting to ascending (as
            // ImGui does without this flag) surfaces a wall of idle 0 B/s
            // rows instead, which looks like the numbers are stuck at 0.
            ImGui::TableSetupColumn("Down/s", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, 100);
            ImGui::TableSetupColumn("Up/s", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, 100);
            ImGui::TableSetupColumn("Total", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort |
                                                 ImGuiTableColumnFlags_PreferSortDescending,
                                     100);
            ImGui::TableSetupColumn("Block", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 90);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::PushFont(g_fontBold, 0.0f);
            ImGui::TableHeadersRow();
            ImGui::PopFont();

            // Click-to-sort: apply whatever column/direction the header
            // click chose. Persisted in sortColumn/sortAscending so the
            // 1/sec tick above keeps re-applying it to freshly fetched
            // rows without needing another click.
            if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs()) {
                if (specs->SpecsCount > 0) {
                    int newColumn = specs->Specs[0].ColumnIndex;
                    bool newAscending = specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
                    if (specs->SpecsDirty || newColumn != sortColumn || newAscending != sortAscending) {
                        sortColumn = newColumn;
                        sortAscending = newAscending;
                        SortRows(rows, sortColumn, sortAscending);
                        specs->SpecsDirty = false;
                    }
                }
            }

            for (const auto& r : rows) {
                // Closed (exited) processes stay in the data for a while
                // (see Monitor::kDeadTicksToForget) so this checkbox can
                // show them, but by default they just disappear - nobody
                // wants a table that still lists "Brave" five minutes
                // after closing it.
                if (!r.alive && !showClosedProcesses) continue;

                ImGui::TableNextRow();
                ImGui::PushID((int)r.pid);
                if (!r.alive) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.635f, 0.659f, 0.694f, 1.0f));

                ImGui::TableSetColumnIndex(0);

                // Invisible full-row selectable, drawn first so the icon,
                // text and Block button (drawn after, with overlap allowed)
                // render on top of it but it still catches right-clicks
                // anywhere on the row for the context menu below. Hover/
                // active tint is suppressed - it's only here to catch
                // clicks, not to highlight the row.
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
                ImGui::Selectable("##rowsel", false,
                                   ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap);
                ImGui::PopStyleColor(2);
                if (r.pid != kUnknownPID && ImGui::BeginPopupContextItem("rowctx")) {
                    ImGui::PushFont(g_fontBold, 0.0f);
                    ImGui::Text("%s (PID %u)", r.name.c_str(), r.pid);
                    ImGui::PopFont();
                    ImGui::Separator();
                    if (ImGui::MenuItem("Open file location", nullptr, false, !r.exePath.empty())) {
                        std::string args = "/select,\"" + r.exePath + "\"";
                        ::ShellExecuteA(nullptr, "open", "explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
                    }
                    if (ImGui::MenuItem("View connections...")) {
                        connViewPid = (int)r.pid;
                        connViewName = r.name;
                        openConnView = true;
                    }
                    bool limited = pidMgr.IsLimited(r.pid);
                    if (ImGui::MenuItem(limited ? "Change traffic limit..." : "Limit traffic...")) {
                        limitModalPid = (int)r.pid;
                        limitModalName = r.name;
                        uint64_t existing = limited ? pidMgr.GetLimit(r.pid) : (512ull * 1024); // default 512 KB/s
                        BytesPerSecToUnit(existing, &limitInputValue, &limitUnitIdx);
                        openLimitModal = true;
                    }
                    if (limited && ImGui::MenuItem("Remove traffic limit")) {
                        pidMgr.ClearLimit(r.pid);
                    }
                    ImGui::Separator();
                    {
                        std::string lname = ToLowerAscii(r.name);
                        bool exempt = autoBlockExempt.count(lname) != 0;
                        if (ImGui::MenuItem("Exempt from auto-block", nullptr, exempt)) {
                            if (exempt) autoBlockExempt.erase(lname);
                            else autoBlockExempt.insert(lname);
                        }
                    }
                    ImGui::EndPopup();
                }
                ImGui::SameLine(0, 0);

                ID3D11ShaderResourceView* tex = icons.Get(r.exePath);
                if (tex) {
                    // Icon is a fixed-pixel bitmap, not scaled by
                    // ImGui::GetStyle().ScaleAllSizes() like everything
                    // else, so on a scaled display it ends up smaller than
                    // the surrounding (DPI-scaled) text. Also, the name
                    // next to it is a CopyableText (an InputText under the
                    // hood), which is taller than a plain text line - it
                    // has frame padding around the text - so centering
                    // against GetTextLineHeight() undershot and still left
                    // the icon sitting high. GetFrameHeight() is what
                    // InputText/Button actually render at, so center
                    // against that instead.
                    float iconSize = 16.0f * dpiScale;
                    float itemH = ImGui::GetFrameHeight();
                    float startY = ImGui::GetCursorPosY();
                    ImGui::SetCursorPosY(startY + std::max(0.0f, (itemH - iconSize) * 0.5f));
                    ImGui::Image((ImTextureID)(intptr_t)tex, ImVec2(iconSize, iconSize));
                    ImGui::SameLine();
                    ImGui::SetCursorPosY(startY);
                }
                CopyableText("name", r.name);
                if (pidMgr.IsLimited(r.pid)) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(limited to %s)", FormatRate((double)pidMgr.GetLimit(r.pid)).c_str());
                }
                if (autoBlockExempt.count(ToLowerAscii(r.name))) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(auto-block exempt)");
                }

                ImGui::TableSetColumnIndex(1);
                if (r.pid == kUnknownPID) ImGui::TextUnformatted("-");
                else CopyableText("pid", std::to_string(r.pid));

                ImGui::TableSetColumnIndex(2);
                CopyableText("down", FormatRate(r.rateDown));

                ImGui::TableSetColumnIndex(3);
                CopyableText("up", FormatRate(r.rateUp));

                ImGui::TableSetColumnIndex(4);
                CopyableText("total", FormatBytes(r.totalDown + r.totalUp));

                ImGui::TableSetColumnIndex(5);
                if (r.pid == kUnknownPID) {
                    ImGui::TextDisabled("-");
                } else if (!r.alive) {
                    ImGui::TextDisabled("closed");
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
                if (!r.alive) ImGui::PopStyleColor();
                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        if (openLimitModal) {
            ImGui::OpenPopup("Set traffic limit");
            openLimitModal = false;
        }
        if (ImGui::BeginPopupModal("Set traffic limit", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::PushFont(g_fontBold, 0.0f);
            ImGui::Text("Limit %s (PID %d)", limitModalName.c_str(), limitModalPid);
            ImGui::PopFont();
            ImGui::Spacing();
            ImGui::SetNextItemWidth(120);
            ImGui::InputDouble("##limitValue", &limitInputValue, 0.0, 0.0, "%.2f");
            if (limitInputValue < 0.01) limitInputValue = 0.01;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(90);
            ImGui::Combo("##limitUnit", &limitUnitIdx, kUnitLabels, 3);
            if (ImGui::Button("Apply")) {
                uint64_t bytesPerSec = (uint64_t)(limitInputValue * (double)kUnitMultipliers[limitUnitIdx]);
                std::string err = pidMgr.SetLimit((uint32_t)limitModalPid, bytesPerSec);
                uiStatus = err.empty() ? uiStatus : ("Limit failed: " + err);
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }

        if (openConnView) {
            ImGui::OpenPopup("View connections");
            openConnView = false;
            connViewRows = ConnectionsForPid((uint32_t)connViewPid);
            connViewLastRefresh = ImGui::GetTime();
        }
        ImGui::SetNextWindowSize(ImVec2(600, 380), ImGuiCond_FirstUseEver);
        if (ImGui::BeginPopupModal("View connections", nullptr)) {
            ImGui::PushFont(g_fontBold, 0.0f);
            ImGui::Text("%s (PID %d)", connViewName.c_str(), connViewPid);
            ImGui::PopFont();
            ImGui::TextDisabled("%zu active connections - refreshes every second", connViewRows.size());
            ImGui::Separator();
            ImGui::Spacing();

            double connNow = ImGui::GetTime();
            if (connNow - connViewLastRefresh >= 1.0) {
                connViewRows = ConnectionsForPid((uint32_t)connViewPid);
                connViewLastRefresh = connNow;
            }

            if (ImGui::BeginTable("conns", 4,
                                   ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                       ImGuiTableFlags_ScrollY,
                                   ImVec2(0, ImGui::GetContentRegionAvail().y - 40))) {
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 55);
                ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 110);
                ImGui::PushFont(g_fontBold, 0.0f);
                ImGui::TableHeadersRow();
                ImGui::PopFont();

                int connRowIdx = 0;
                for (const auto& c : connViewRows) {
                    ImGui::TableNextRow();
                    ImGui::PushID(connRowIdx++);
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(c.proto == Proto::TCP ? "TCP" : "UDP");
                    ImGui::TableSetColumnIndex(1);
                    CopyableText("local", c.localAddr + ":" + std::to_string(c.localPort));
                    ImGui::TableSetColumnIndex(2);
                    if (c.remoteAddr.empty()) ImGui::TextDisabled("-");
                    else CopyableText("remote", c.remoteAddr + ":" + std::to_string(c.remotePort));
                    ImGui::TableSetColumnIndex(3);
                    if (c.state.empty()) ImGui::TextDisabled("-");
                    else ImGui::TextUnformatted(c.state.c_str());
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::Spacing();
            if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
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
