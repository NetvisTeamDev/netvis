// netvis - GlassWire-style bandwidth monitor / ad blocker / per-process
// firewall for Windows. Dear ImGui + Win32 + DirectX11 UI.
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <shellapi.h>
#include <commdlg.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
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
#include "hostcache.h"
#include "alerts.h"
#include "settings.h"
#include "blocklist_store.h"
#include "startup.h"
#include "license.h"
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

// --- run-in-background / system tray ---
// When enabled, closing the window hides it to a tray icon instead of
// quitting, so the monitor/blocker/limits keep running. These are file
// statics because WndProc (a static callback) needs them.
static constexpr UINT WM_NETVIS_TRAY = WM_APP + 1;
static constexpr UINT TRAY_CMD_OPEN = 1001;
static constexpr UINT TRAY_CMD_EXIT = 1002;
static bool g_runInBackground = false; // mirrors the checkbox, refreshed each frame
static bool g_windowHidden = false;
static UINT g_showMsg = 0; // registered message a second instance broadcasts to un-hide the first
static HICON g_appIcon = nullptr; // the embedded app icon, reused for the tray
static NOTIFYICONDATAW g_trayIcon = {};
static bool g_trayAdded = false;
static std::atomic<bool> g_notifyEnabled{false}; // read from the alerts thread

// Set whenever the app is "opened" again without the process restarting -
// a tray click, the tray menu, or a second launch handing off to us. The
// main loop sees this and re-runs the licensing gate, so opening netvis
// always costs a license check, not just the very first launch of the day.
static std::atomic<bool> g_licenseRecheck{false};

static void AddTrayIcon(HWND hwnd) {
    if (g_trayAdded) return;
    g_trayIcon = {};
    g_trayIcon.cbSize = sizeof(g_trayIcon);
    g_trayIcon.hWnd = hwnd;
    g_trayIcon.uID = 1;
    g_trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_trayIcon.uCallbackMessage = WM_NETVIS_TRAY;
    g_trayIcon.hIcon = g_appIcon ? g_appIcon : ::LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy_s(g_trayIcon.szTip, L"netvis");
    ::Shell_NotifyIconW(NIM_ADD, &g_trayIcon);
    g_trayAdded = true;
}

static void RemoveTrayIcon() {
    if (!g_trayAdded) return;
    ::Shell_NotifyIconW(NIM_DELETE, &g_trayIcon);
    g_trayAdded = false;
}

// Shows a Windows balloon/toast on the tray icon. Safe to call from any
// thread (the alerts thread uses it), and works whether the window is
// visible or hidden, as long as the tray icon exists.
static void ShowTrayNotification(const std::string& title, const std::string& body) {
    if (!g_trayAdded) return;
    NOTIFYICONDATAW nid = g_trayIcon;
    nid.uFlags = NIF_INFO;
    // NIIF_USER + hBalloonIcon shows netvis's own icon on the toast instead
    // of the generic system info glyph.
    if (g_appIcon) {
        nid.dwInfoFlags = NIIF_USER;
        nid.hBalloonIcon = g_appIcon;
    } else {
        nid.dwInfoFlags = NIIF_INFO;
    }
    auto widen = [](const std::string& s, wchar_t* out, int cap) {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out, cap);
        if (n <= 0) out[0] = 0;
    };
    widen(title, nid.szInfoTitle, (int)(sizeof(nid.szInfoTitle) / sizeof(wchar_t)));
    widen(body, nid.szInfo, (int)(sizeof(nid.szInfo) / sizeof(wchar_t)));
    ::Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void RestoreWindow(HWND hwnd) {
    g_windowHidden = false;
    ::ShowWindow(hwnd, SW_SHOW);
    ::ShowWindow(hwnd, SW_RESTORE);
    ::SetForegroundWindow(hwnd);
    // Un-hiding from the tray *is* opening the app as far as the user is
    // concerned, so it has to be licensed the same as a cold start.
    g_licenseRecheck.store(true);
    // Tray icon stays put (it's persistent now, so notifications keep
    // working while the window is open).
}


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

// Duration unit picker for timed limits.
const char* kDurationLabels[3] = {"minutes", "hours", "days"};
constexpr int kDurationSeconds[3] = {60, 3600, 86400};

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

std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// Deterministic, pleasant color from a process name - used to tint the
// placeholder icon for processes whose real exe icon can't be extracted,
// so the same app always gets the same badge color.
ImU32 ColorForName(const std::string& name) {
    uint32_t h = 2166136261u;
    for (char c : name) { h ^= (uint8_t)std::tolower((unsigned char)c); h *= 16777619u; }
    static const ImU32 palette[] = {
        IM_COL32(0x4c, 0x8b, 0xf5, 255), IM_COL32(0x35, 0xc7, 0x7a, 255), IM_COL32(0xe0, 0x8f, 0x3a, 255),
        IM_COL32(0xc7, 0x5b, 0xe0, 255), IM_COL32(0xe0, 0x5b, 0x6b, 255), IM_COL32(0x2f, 0xb2, 0xc7, 255),
        IM_COL32(0x8f, 0xb4, 0x3a, 255), IM_COL32(0xd0, 0xb0, 0x40, 255),
    };
    return palette[h % (sizeof(palette) / sizeof(palette[0]))];
}

// Draws a process icon into the current cell: the real extracted exe icon
// if available, otherwise a colored rounded badge with the first letter -
// so every row shows something, aligned. Advances the cursor and leaves it
// ready for SameLine text.
void DrawProcessIcon(ID3D11ShaderResourceView* tex, const std::string& name, float dpiScale) {
    float iconSize = 16.0f * dpiScale;
    // The name beside this is a CopyableText (InputText) whose height is
    // GetFrameHeight(), taller than a plain text line - center against that
    // so the icon sits level with the name rather than riding high.
    float itemH = ImGui::GetFrameHeight();
    float startY = ImGui::GetCursorPosY();
    ImGui::SetCursorPosY(startY + std::max(0.0f, (itemH - iconSize) * 0.5f));

    if (tex) {
        ImGui::Image((ImTextureID)(intptr_t)tex, ImVec2(iconSize, iconSize));
    } else {
        ImVec2 sp = ImGui::GetCursorScreenPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(sp, ImVec2(sp.x + iconSize, sp.y + iconSize), ColorForName(name), iconSize * 0.25f);
        char letter[2] = {(char)std::toupper((unsigned char)(name.empty() ? '?' : name[0])), 0};
        ImVec2 ts = ImGui::CalcTextSize(letter);
        dl->AddText(ImVec2(sp.x + (iconSize - ts.x) * 0.5f, sp.y + (iconSize - ts.y) * 0.5f),
                    IM_COL32(255, 255, 255, 235), letter);
        ImGui::Dummy(ImVec2(iconSize, iconSize));
    }
    ImGui::SameLine();
    ImGui::SetCursorPosY(startY);
}

// Sorts by whichever table column the user clicked, matching the column
// order in the "apps" table (App=0, PID=1, Downloaded=2, Uploaded=3).
// Pinned processes (by PID) are held at the top regardless of the sort.
void SortRows(std::vector<AppStats>& rows, int column, bool ascending,
              const std::unordered_set<uint32_t>& pinned) {
    auto compare = [column](const AppStats& a, const AppStats& b) -> int {
        switch (column) {
            case 0:
                return _stricmp(a.name.c_str(), b.name.c_str());
            case 1:
                return (a.pid < b.pid) ? -1 : (a.pid > b.pid ? 1 : 0);
            case 3:
                return (a.totalUp < b.totalUp) ? -1 : (a.totalUp > b.totalUp ? 1 : 0);
            default: // 2 = downloaded (also the fallback/default sort)
                return (a.totalDown < b.totalDown) ? -1 : (a.totalDown > b.totalDown ? 1 : 0);
        }
    };
    std::sort(rows.begin(), rows.end(), [&](const AppStats& a, const AppStats& b) {
        bool pa = pinned.count(a.pid) != 0;
        bool pb = pinned.count(b.pid) != 0;
        if (pa != pb) return pa; // pinned rows first, then normal sorting within each group
        return ascending ? compare(a, b) < 0 : compare(a, b) > 0;
    });
}

// PTR records are often long and machine-generated
// ("fra16s52-in-f14.1e100.net"), which is noisy in a table. Trim to the
// registrable domain ("1e100.net") - enough to tell you who you're talking
// to, and the full address is still one hover away.
std::string ShortenHostname(const std::string& host) {
    // Two-level public suffixes where keeping only the last two labels
    // would leave a useless "co.uk"-style fragment.
    static const char* twoLevelSuffixes[] = {
        ".co.uk", ".org.uk", ".ac.uk", ".gov.uk", ".co.jp", ".co.kr", ".co.nz",
        ".co.za",  ".com.au", ".com.br", ".com.cn", ".com.mx", ".com.tr", ".net.au",
    };

    int wanted = 2;
    std::string lower = ToLowerAscii(host);
    for (const char* suffix : twoLevelSuffixes) {
        size_t sl = strlen(suffix);
        if (lower.size() > sl && lower.compare(lower.size() - sl, sl, suffix) == 0) {
            wanted = 3;
            break;
        }
    }

    size_t cut = std::string::npos;
    for (int i = 0; i < wanted; i++) {
        size_t dot = host.find_last_of('.', cut == std::string::npos ? std::string::npos : cut - 1);
        if (dot == std::string::npos) return host; // fewer labels than we wanted - already short
        cut = dot;
    }
    return host.substr(cut + 1);
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

// Startup licensing gate. Runs its own little render loop before any of
// the real app starts, so nothing captures traffic until the machine is
// licensed. Returns false if the user gave up (closed the window / Quit),
// in which case wWinMain exits.
//
// The network calls happen on a worker thread: WinHTTP blocks, and a
// server that's down would otherwise freeze the window for seconds with
// nothing on screen.
bool RunLicenseGate(ImGuiIO& io, float dpiScale) {
    enum class Phase { Checking, NeedKey, Activating, Offline };

    struct Shared {
        std::atomic<bool> busy{true};
        std::atomic<int> authResult{-1}; // license::Status, -1 = not finished
        std::atomic<bool> activated{false};
        std::mutex mu;
        std::string error;
    };
    auto shared = std::make_shared<Shared>();

    auto startAuth = [shared]() {
        shared->busy.store(true);
        shared->authResult.store(-1);
        std::thread([shared] {
            license::Status s = license::Authenticate();
            shared->authResult.store((int)s);
            shared->busy.store(false);
        }).detach();
    };

    auto startActivate = [shared](std::string key) {
        shared->busy.store(true);
        std::thread([shared, key] {
            std::string err;
            bool ok = license::Activate(key, &err);
            {
                std::lock_guard<std::mutex> lock(shared->mu);
                shared->error = ok ? "" : err;
            }
            shared->activated.store(ok);
            shared->busy.store(false);
        }).detach();
    };

    Phase phase = Phase::Checking;
    static char keyBuf[512] = {};
    bool quit = false;
    bool expired = false; // came from a licence that ran out, not a fresh install

    startAuth();

    while (true) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) quit = true;
        }
        if (quit) return false;

        // Phase transitions, driven by whatever the worker finished.
        if (!shared->busy.load()) {
            if (phase == Phase::Checking) {
                int r = shared->authResult.load();
                if (r == (int)license::Status::Licensed) return true;
                expired = (r == (int)license::Status::Expired);
                phase = (r == (int)license::Status::Unreachable) ? Phase::Offline : Phase::NeedKey;
            } else if (phase == Phase::Activating) {
                if (shared->activated.load()) {
                    Log("license: activation succeeded, starting netvis");
                    return true;
                }
                phase = Phase::NeedKey;
            }
        }

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(40, 34));
        ImGui::Begin("activate", nullptr,
                      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                          ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar);
        ImGui::PopStyleVar();

        // Everything on this screen is centred as one column. These helpers
        // place the next item by measuring it first - ImGui lays out
        // left-to-right, so centring means setting the cursor yourself.
        float full = ImGui::GetContentRegionAvail().x;
        auto centerNext = [&](float itemWidth) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (full - itemWidth) * 0.5f);
        };
        auto centeredText = [&](const char* text) {
            centerNext(ImGui::CalcTextSize(text).x);
            ImGui::TextUnformatted(text);
        };
        auto centeredColored = [&](ImVec4 col, const char* text) {
            centerNext(ImGui::CalcTextSize(text).x);
            ImGui::TextColored(col, "%s", text);
        };

        // Push the block down so it sits nearer the middle of the window
        // rather than clinging to the top edge.
        ImGui::Dummy(ImVec2(0, io.DisplaySize.y * 0.14f));

        {
            const char* title = "netvis";
            ImGui::PushFont(g_fontBold, 52.0f * dpiScale);
            centerNext(ImGui::CalcTextSize(title).x);
            ImGui::TextUnformatted(title);
            ImGui::PopFont();
        }
        centeredColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f), "Firewall & bandwidth manager");

        ImGui::Dummy(ImVec2(0, 26.0f * dpiScale));

        switch (phase) {
        case Phase::Checking:
            centeredText("Checking your license...");
            break;

        case Phase::Offline: {
            centeredColored(ImVec4(0.95f, 0.65f, 0.35f, 1.0f), "Can't reach the licensing server.");
            ImGui::Spacing();
            centeredColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f),
                            "netvis checks your license when it opens.");
            centeredColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f),
                            "Check your internet connection and try again.");
            ImGui::Dummy(ImVec2(0, 20.0f * dpiScale));

            float bw = 140.0f * dpiScale, qw = 100.0f * dpiScale;
            centerNext(bw + qw + ImGui::GetStyle().ItemSpacing.x);
            if (ImGui::Button("Try again", ImVec2(bw, 0))) {
                phase = Phase::Checking;
                startAuth();
            }
            ImGui::SameLine();
            if (ImGui::Button("Quit", ImVec2(qw, 0))) return false;
            break;
        }

        case Phase::NeedKey:
        case Phase::Activating: {
            if (expired) {
                centeredColored(ImVec4(0.95f, 0.65f, 0.35f, 1.0f), "Your licence has run out.");
                ImGui::Spacing();
                centeredText("Enter a new key to carry on for another 6 months.");
                ImGui::Spacing();
                centeredColored(ImVec4(0.45f, 0.47f, 0.51f, 1.0f), "Get one at netvis.cc");
            } else {
                centeredText("Enter your license key to activate this computer.");
                ImGui::Spacing();
                centeredColored(ImVec4(0.45f, 0.47f, 0.51f, 1.0f),
                                "A key activates one computer for 6 months.");
            }
            ImGui::Dummy(ImVec2(0, 14.0f * dpiScale));

            bool busy = (phase == Phase::Activating);
            // A 30-character key fits on one line, so it gets a single wide
            // field rather than a paste box - and Enter submits it.
            float boxW = (std::min)(420.0f * dpiScale, full);
            centerNext(boxW);
            ImGui::SetNextItemWidth(boxW);
            ImGui::BeginDisabled(busy);
            bool submitted = ImGui::InputTextWithHint("##key", "paste your license key", keyBuf,
                                                       sizeof(keyBuf), ImGuiInputTextFlags_EnterReturnsTrue |
                                                                            ImGuiInputTextFlags_CharsUppercase |
                                                                            ImGuiInputTextFlags_AutoSelectAll);
            ImGui::EndDisabled();

            // Dashes, spaces and line breaks are what you get from copying a
            // key out of an email, so strip them rather than rejecting the
            // paste. Same routine the network call uses.
            std::string key = license::Normalize(keyBuf);
            bool complete = license::PlausibleKey(key);

            // No character counter any more: keys are no longer one fixed
            // length, so counting up to a number would be wrong for half of
            // them. The Activate button lighting up is the signal instead.
            ImGui::Spacing();

            {
                std::lock_guard<std::mutex> lock(shared->mu);
                if (!shared->error.empty()) {
                    ImGui::Spacing();
                    centeredColored(ImVec4(0.90f, 0.35f, 0.40f, 1.0f), shared->error.c_str());
                }
            }

            ImGui::Dummy(ImVec2(0, 18.0f * dpiScale));
            float aw = 140.0f * dpiScale, qw = 100.0f * dpiScale;
            centerNext(aw + qw + ImGui::GetStyle().ItemSpacing.x);
            ImGui::BeginDisabled(busy || !complete);
            if (ImGui::Button("Activate", ImVec2(aw, 0)) || (submitted && complete && !busy)) {
                phase = Phase::Activating;
                {
                    std::lock_guard<std::mutex> lock(shared->mu);
                    shared->error.clear();
                }
                startActivate(key);
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Quit", ImVec2(qw, 0))) return false;

            if (busy) {
                ImGui::Spacing();
                centeredText("Activating...");
            }
            break;
        }
        }

        ImGui::End();

        ImGui::Render();
        const float clear_color[4] = {0.06f, 0.06f, 0.08f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }
}

} // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    LogInit();
    Log("netvis starting");

    // Single instance. Two copies both driving WinDivert would fight over
    // capture/blocking and each would leave its own tray icon, so if one is
    // already running we just ask it to come to the front (in case it's
    // hidden in the tray) and exit. The mutex is held for the whole process
    // lifetime; Windows releases it automatically on exit.
    g_showMsg = ::RegisterWindowMessageW(L"netvis_show_window_v1");
    HANDLE instanceMutex = ::CreateMutexW(nullptr, FALSE, L"netvis_single_instance_v1");
    if (instanceMutex && ::GetLastError() == ERROR_ALREADY_EXISTS) {
        Log("netvis: another instance is already running - signalling it and exiting");
        ::PostMessage(HWND_BROADCAST, g_showMsg, 0, 0);
        return 0;
    }

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

    // The app icon is embedded as resource ID 1 (see netvis.rc). Load the
    // large and small variants so the taskbar, Alt-Tab, title bar and tray
    // all show it. Falls back to the generic app icon if the resource is
    // somehow missing (e.g. an older build).
    HICON iconLarge = (HICON)::LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    HICON iconSmall = (HICON)::LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                          ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON),
                                          LR_SHARED);
    if (!iconLarge) iconLarge = ::LoadIcon(nullptr, IDI_APPLICATION);
    if (!iconSmall) iconSmall = iconLarge;
    g_appIcon = iconSmall;

    WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, hInstance,
                       iconLarge, nullptr, nullptr, nullptr, L"netvis", iconSmall};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"netvis - bandwidth monitor", WS_OVERLAPPEDWINDOW, 100, 100,
                                 (int)(940 * initialDpiScale), (int)(640 * initialDpiScale), nullptr, nullptr,
                                 wc.hInstance, nullptr);
    ::SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)iconLarge);
    ::SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)iconSmall);

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

    // Tray icon lives for the whole run (not just background mode), so
    // alert notifications can appear whether the window is open or hidden.
    AddTrayIcon(hwnd);

    // 1-second timer so the message loop wakes (and runs the monitoring
    // tick / auto-block) even while hidden in the tray with no other input.
    ::SetTimer(hwnd, 2, 1000, nullptr);

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

    // Licensing gate: nothing below this line runs - no capture, no
    // blocking, no tray behaviour - until the server confirms this machine
    // is activated (or the user redeems a key here and now).
    if (!RunLicenseGate(io, dpiScale)) {
        Log("netvis: not licensed, exiting");
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        RemoveTrayIcon();
        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 0;
    }

    // --- app state ---
    Settings settings = Settings::Load();

    Monitor mon;
    std::string monErr;
    bool monOk = mon.Start(&monErr);

    // User firewall blocklist (persisted in Program Files\netvis\blocklist.db).
    std::vector<std::string> userBlocklist = blocklist_store::Load();
    bool useDefaultBlocklist = settings.useDefaultBlocklist;

    Blocker blk;
    std::string blkErr;
    bool blkOk = blk.Start(&blkErr, userBlocklist, useDefaultBlocklist);

    PidBlockManager pidMgr;
    IconCache icons(g_pd3dDevice);
    TrafficGraph graph(60);

    std::vector<AppStats> rows;
    bool showClosedProcesses = false;
    uint64_t lastTickMs = 0; // wall-clock of the last monitoring tick (0 = fire on first loop)
    bool autoBlockEnabled = false;
    double autoBlockThresholdValue = 1.0;
    int autoBlockUnitIdx = 1; // MB/s default
    // Keyed by PID, not name: two processes sharing an exe name (e.g.
    // several chrome.exe) must be pinned/exempted individually. PIDs don't
    // survive a restart, so these are intentionally not persisted.
    std::unordered_set<uint32_t> autoBlockExempt;
    std::unordered_set<uint32_t> pinnedProcs;
    autoBlockThresholdValue = settings.autoBlockThreshold;
    autoBlockUnitIdx = settings.autoBlockUnitIdx;
    if (blkOk) blk.SetEnabled(settings.adBlockerEnabled);

    Alerts alerts;
    g_notifyEnabled.store(settings.notifyOnAlert);
    alerts.SetOnAlert([](const Alert& a) {
        if (g_notifyEnabled.load()) ShowTrayNotification(a.title, a.detail);
    });
    alerts.Start(std::vector<std::string>(settings.knownExes.begin(), settings.knownExes.end()));
    bool showAlerts = false;
    bool notifyOnAlert = settings.notifyOnAlert;
    std::string lastNotifiedAlert; // title+timestamp of the newest alert we've toasted, to avoid repeats

    bool showBlocklist = false;
    bool focusBlocklist = false;
    char newDomainBuf[256] = "";
    std::string blocklistStatus;

    // Applies the current user list + default toggle to the blocker and
    // saves it to disk. Called whenever the blocklist is edited.
    auto applyBlocklist = [&]() {
        blocklist_store::Save(userBlocklist);
        if (blkOk) blk.Reload(userBlocklist, useDefaultBlocklist);
    };

    int detailPid = -1; // process whose detail panel is open, -1 = none
    std::string detailName;
    bool focusDetail = false; // raise the detail window on the frame it opens
    bool focusAlerts = false;
    int limitModalPid = -1;
    std::string limitModalName;
    bool openLimitModal = false;
    // Limit-modal working state: separate download/upload caps and an
    // optional duration, each with its own enable checkbox.
    bool limDownOn = false;
    double limDownVal = 512;
    int limDownUnit = 0; // KB/s
    bool limUpOn = false;
    double limUpVal = 256;
    int limUpUnit = 0;
    bool limDurOn = false;
    int limDurValue = 30;
    int limDurUnit = 0; // 0=minutes, 1=hours, 2=days

    // Opens the limit modal for a PID, pre-filling from its existing limit
    // if it has one, or sensible defaults otherwise.
    auto openLimitFor = [&](uint32_t pid, const std::string& name) {
        limitModalPid = (int)pid;
        limitModalName = name;
        PidBlockManager::LimitSpec ls;
        if (pidMgr.GetLimit(pid, &ls)) {
            limDownOn = ls.limitDown;
            if (ls.limitDown) BytesPerSecToUnit(ls.downBps, &limDownVal, &limDownUnit);
            limUpOn = ls.limitUp;
            if (ls.limitUp) BytesPerSecToUnit(ls.upBps, &limUpVal, &limUpUnit);
            limDurOn = ls.hasDuration;
            if (ls.hasDuration) {
                int secs = std::max(60, ls.remainingSecs);
                if (secs % 86400 == 0) { limDurUnit = 2; limDurValue = secs / 86400; }
                else if (secs % 3600 == 0) { limDurUnit = 1; limDurValue = secs / 3600; }
                else { limDurUnit = 0; limDurValue = std::max(1, (secs + 59) / 60); }
            }
        } else {
            limDownOn = false;
            limDownVal = 512;
            limDownUnit = 0;
            limUpOn = false;
            limUpVal = 256;
            limUpUnit = 0;
            limDurOn = false;
            limDurValue = 30;
            limDurUnit = 0;
        }
        openLimitModal = true;
    };
    int sortColumn = 2;      // default: Downloaded, descending (busiest first)
    bool sortAscending = false;
    int connViewPid = -1;
    std::string connViewName;
    bool openConnView = false;
    std::vector<ConnInfo> connViewRows;
    double connViewLastRefresh = 0.0;
    bool resolveHostnames = true;
    HostCache hostCache;

    bool runInBackground = settings.runInBackground;
    bool runOnStartup = startup::IsEnabled(); // source of truth is the scheduled task, not settings
    // Default ON, but only the first time ever - after that the user's
    // choice (task present or not) is respected, so turning it off sticks.
    if (!settings.startupDefaultApplied) {
        settings.startupDefaultApplied = true;
        if (!runOnStartup) {
            startup::SetEnabled(true);
            runOnStartup = startup::IsEnabled();
        }
    }

    // Licensing re-checks while the app is already running. The flag is a
    // shared_ptr so the detached worker can safely clear it even if it
    // outlives the loop during shutdown.
    constexpr uint64_t kLicenseRecheckMs = 6ull * 60 * 60 * 1000; // 6 hours
    uint64_t lastLicenseCheckMs = ::GetTickCount64(); // the startup gate just checked
    auto licenseCheckBusy = std::make_shared<std::atomic<bool>>(false);

    std::string uiStatus;
    if (!monOk) uiStatus = "Capture failed: " + monErr;
    else if (!blkOk) uiStatus = "Ad blocker failed: " + blkErr;
    else uiStatus = "Capturing traffic - running as Administrator";

    bool done = false;
    while (!done) {
        g_runInBackground = runInBackground; // let WndProc see the current choice
        g_notifyEnabled.store(notifyOnAlert); // let the alerts thread see it

        // While hidden to the tray there's nothing to draw, so block until a
        // message arrives (tray click, etc.) instead of spinning the render
        // loop at 100% CPU. Background worker threads (monitor, blocker,
        // limits) keep running the whole time - they're independent of this
        // loop.
        if (g_windowHidden) ::WaitMessage();

        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        uint64_t nowMs = ::GetTickCount64();

        // Re-opened (tray click, tray menu, or a second launch handing off
        // to this instance) - or a background re-check found the license
        // gone. Either way the gate runs again, and if it isn't satisfied
        // we shut down through the normal path below.
        if (g_licenseRecheck.exchange(false)) {
            if (!RunLicenseGate(io, dpiScale)) {
                Log("netvis: license check failed on re-open, exiting");
                break;
            }
        }

        // Periodic re-check so an instance that lives in the tray for days
        // still notices a revoked license. Only an explicit "no" from the
        // server counts - if it's merely unreachable we leave the running
        // session alone rather than kicking someone off over a network
        // blip. (Reaching the server is required to *open* netvis; losing
        // it mid-session is not the user's fault.)
        if (nowMs - lastLicenseCheckMs >= kLicenseRecheckMs) {
            lastLicenseCheckMs = nowMs;
            if (!licenseCheckBusy->exchange(true)) {
                auto busy = licenseCheckBusy;
                std::thread([busy] {
                    if (license::Authenticate() == license::Status::NotLicensed)
                        g_licenseRecheck.store(true);
                    busy->store(false);
                }).detach();
            }
        }

        // Monitoring tick, once a second - driven by wall-clock (not
        // ImGui::GetTime, which only advances on rendered frames) so it
        // keeps running while the window is hidden in the tray. A 1s timer
        // (set below) wakes the message loop when hidden so this fires.
        if (monOk && nowMs - lastTickMs >= 1000) {
            lastTickMs = nowMs;
            pidMgr.PurgeExpired(); // drop any timed limits that have elapsed
            rows = mon.Snapshot();
            SortRows(rows, sortColumn, sortAscending, pinnedProcs);

            double totalDown = 0, totalUp = 0;
            for (const auto& r : rows) { totalDown += r.rateDown; totalUp += r.rateUp; }
            graph.Push(totalDown, totalUp);

            if (autoBlockEnabled) {
                double thresholdBytesPerSec = autoBlockThresholdValue * (double)kUnitMultipliers[autoBlockUnitIdx];
                for (const auto& r : rows) {
                    if (r.pid == kUnknownPID) continue;
                    if (pidMgr.IsBlocked(r.pid)) continue;
                    if (IsAutoBlockProtected(r.name)) continue;
                    if (autoBlockExempt.count(r.pid)) continue;
                    if (r.rateDown + r.rateUp <= thresholdBytesPerSec) continue;
                    std::string err = pidMgr.Block(r.pid);
                    if (err.empty()) {
                        double mbps = (r.rateDown + r.rateUp) / (1024.0 * 1024.0);
                        Log("auto-block: %s (pid %u) exceeded %.2f %s, blocked", r.name.c_str(), r.pid,
                            autoBlockThresholdValue, kUnitLabels[autoBlockUnitIdx]);
                        char detail[160];
                        snprintf(detail, sizeof(detail),
                                 "Using %.2f MB/s, over the %.2f %s auto-block threshold - cut off.", mbps,
                                 autoBlockThresholdValue, kUnitLabels[autoBlockUnitIdx]);
                        // Shows in the Alerts feed and fires a notification
                        // (if enabled) via the same path as other alerts.
                        alerts.Raise(AlertKind::AutoBlocked, r.name + " auto-blocked", detail, r.pid);
                    } else {
                        Log("auto-block: %s (pid %u) failed: %s", r.name.c_str(), r.pid, err.c_str());
                    }
                }
            }
        }

        if (g_windowHidden) continue; // done with background work; skip rendering while in the tray

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 18));
        // NoBringToFrontOnFocus matters: this window is fullscreen and
        // redrawn every frame, so without it, clicking anywhere in the
        // table raises it above the detail/alerts windows and paints over
        // them - they look like they vanished when they're just behind it.
        ImGui::Begin("netvis", nullptr,
                      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                          ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                          ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::PopStyleVar();

        // --- header: title + status, with the Alerts button pinned to the
        // top-right corner so it's clearly its own thing, away from the
        // ad-blocker/auto-block toggles below. ---
        ImGui::PushFont(g_fontBold, 0.0f);
        ImGui::TextUnformatted("netvis");
        ImGui::PopFont();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImVec4(0.557f, 0.584f, 0.627f, 1.0f), "  bandwidth monitor & firewall");

        {
            size_t unread = alerts.UnreadCount();
            char label[64];
            if (unread > 0) snprintf(label, sizeof(label), "Alerts (%zu)", unread);
            else snprintf(label, sizeof(label), "Alerts");
            float btnW = ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2 + 8;
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() +
                                  std::max(0.0f, ImGui::GetContentRegionAvail().x - btnW));
            if (unread > 0) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.85f, 0.45f, 0.20f, 1.0f));
            if (ImGui::Button(label)) {
                showAlerts = true;
                focusAlerts = true;
                alerts.MarkAllRead();
            }
            if (unread > 0) ImGui::PopStyleColor();
        }

        bool statusOk = monOk && blkOk;
        ImVec4 statusColor = statusOk ? ImVec4(0.35f, 0.78f, 0.45f, 1.0f) : ImVec4(0.95f, 0.55f, 0.30f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, statusColor);
        CopyableText("status", uiStatus);
        ImGui::PopStyleColor();

        // Renewal warning, only near the end of the term - nobody needs a
        // countdown for five months, and a permanent nag would just get
        // tuned out by the time it mattered.
        {
            int days = license::LastDaysLeft();
            if (days >= 0 && days <= 14) {
                ImVec4 warn = (days <= 3) ? ImVec4(0.90f, 0.35f, 0.40f, 1.0f)
                                          : ImVec4(0.95f, 0.65f, 0.35f, 1.0f);
                if (days == 0)
                    ImGui::TextColored(warn, "Your licence expires today - renew at netvis.cc");
                else
                    ImGui::TextColored(warn, "Your licence expires in %d day%s - renew at netvis.cc", days,
                                        days == 1 ? "" : "s");
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- toolbar: ad blocker stat + the two auto-behavior toggles ---
        // Everything here sits on one line but has three different heights
        // (bold count, regular label, checkbox frame), and ImGui top-aligns
        // items within a line - so each is explicitly centered against the
        // tallest one instead of hanging off the top.
        {
            ImGui::PushFont(g_fontBold, 0.0f);
            float boldH = ImGui::GetTextLineHeight();
            ImGui::PopFont();
            float rowH = std::max(boldH, ImGui::GetFrameHeight());
            float rowY = ImGui::GetCursorPosY();
            auto centerInRow = [&](float itemH) { ImGui::SetCursorPosY(rowY + (rowH - itemH) * 0.5f); };

            if (blkOk) {
                centerInRow(ImGui::GetFrameHeight());
                bool blockerEnabled = blk.Enabled();
                if (ImGui::Checkbox("Block trackers & malicious domains", &blockerEnabled)) {
                    blk.SetEnabled(blockerEnabled);
                }
                ImGui::SameLine(0, 28);
            }

            centerInRow(boldH);
            ImGui::PushFont(g_fontBold, 0.0f);
            ImGui::TextColored(ImVec4(0.259f, 0.588f, 0.980f, 1.0f), "%lld",
                                (long long)(blkOk ? blk.BlockedCount() : 0));
            ImGui::PopFont();

            ImGui::SameLine(0, 8);
            centerInRow(ImGui::GetTextLineHeight());
            ImGui::TextUnformatted("malicious sites blocked");

            if (blkOk) {
                ImGui::SameLine(0, 28);
                centerInRow(ImGui::GetFrameHeight());
                if (ImGui::Button("Edit firewall blocklist...")) {
                    showBlocklist = true;
                    focusBlocklist = true;
                }
            }
        }
        if (monOk) {
            ImGui::Checkbox("Auto-block high-traffic processes", &autoBlockEnabled);
            // Threshold stays visible and editable whether or not the box is
            // ticked - you need to set the limit *before* arming something
            // that cuts programs off the internet, not after.
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80 * dpiScale);
            ImGui::InputDouble("##autoBlockThreshold", &autoBlockThresholdValue, 0.0, 0.0, "%.2f");
            if (autoBlockThresholdValue < 0.01) autoBlockThresholdValue = 0.01;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(90 * dpiScale);
            ImGui::Combo("threshold##autoBlockUnit", &autoBlockUnitIdx, kUnitLabels, 3);
        }
        ImGui::Checkbox("Run in background when window is closed", &runInBackground);
        ImGui::SameLine(0, 28);
        ImGui::Checkbox("System notification on every alert", &notifyOnAlert);
        ImGui::SameLine(0, 28);
        if (ImGui::Checkbox("Run when Windows starts", &runOnStartup)) {
            startup::SetEnabled(runOnStartup);
            runOnStartup = startup::IsEnabled(); // reflect what actually took effect
        }
        ImGui::Spacing();
        ImGui::Spacing();

        // Legend + live values ABOVE the graph (so nothing overlaps the
        // plotted area): Download on the left, Upload to its right.
        {
            auto swatch = [&](ImU32 col) {
                float sz = 10.0f * dpiScale;
                float lineH = ImGui::GetTextLineHeight();
                ImVec2 p = ImGui::GetCursorScreenPos();
                float y = p.y + (lineH - sz) * 0.5f;
                ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x, y), ImVec2(p.x + sz, y + sz), col, 2.0f);
                ImGui::Dummy(ImVec2(sz, lineH));
            };
            swatch(IM_COL32(0x35, 0xc7, 0x5f, 0xFF));
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.38f, 0.90f, 0.56f, 1.0f), "Download %s", FormatRate(graph.CurrentDown()).c_str());
            ImGui::SameLine(0, 28);
            swatch(IM_COL32(0x66, 0x96, 0xfa, 0xFF));
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.56f, 0.70f, 1.00f, 1.0f), "Upload %s", FormatRate(graph.CurrentUp()).c_str());
        }
        ImGui::Spacing();
        graph.Draw(ImVec2(ImGui::GetContentRegionAvail().x, 90));
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

        bool needResort = false;
        if (ImGui::BeginTable("apps", 5,
                               ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                   ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable,
                               ImGui::GetContentRegionAvail())) {
            ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthStretch, 2.2f);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70);
            // These columns now show cumulative bytes (total downloaded /
            // uploaded since netvis started), not instantaneous speed - the
            // live rate is still on the graph and in the per-app details.
            // PreferSortDescending so a click surfaces the busiest apps.
            ImGui::TableSetupColumn("Downloaded", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort |
                                                      ImGuiTableColumnFlags_PreferSortDescending,
                                     110);
            ImGui::TableSetupColumn("Uploaded", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, 110);
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
                        SortRows(rows, sortColumn, sortAscending, pinnedProcs);
                        specs->SpecsDirty = false;
                    }
                }
            }

            for (const auto& r : rows) {
                // The "(unknown)" bucket holds traffic whose local port
                // couldn't be tied to a process (very short-lived sockets,
                // protocols we don't map). It's meaningless as a table row -
                // you can't act on it - so it's hidden here. It still counts
                // toward the graph totals, which are summed separately.
                if (r.pid == kUnknownPID) continue;

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
                // Double-click anywhere on the row is the quick path into
                // the detail panel; the context menu has it too.
                if (r.pid != kUnknownPID && ImGui::IsItemHovered() &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    detailPid = (int)r.pid;
                    detailName = r.name;
                    focusDetail = true;
                }
                if (r.pid != kUnknownPID && ImGui::BeginPopupContextItem("rowctx")) {
                    ImGui::PushFont(g_fontBold, 0.0f);
                    ImGui::Text("%s (PID %u)", r.name.c_str(), r.pid);
                    ImGui::PopFont();
                    ImGui::Separator();
                    if (ImGui::MenuItem("Details...")) {
                        detailPid = (int)r.pid;
                        detailName = r.name;
                        focusDetail = true;
                    }
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
                        openLimitFor(r.pid, r.name);
                    }
                    if (limited && ImGui::MenuItem("Remove traffic limit")) {
                        pidMgr.ClearLimit(r.pid);
                    }
                    ImGui::Separator();
                    {
                        bool pinned = pinnedProcs.count(r.pid) != 0;
                        if (ImGui::MenuItem("Pin to top", nullptr, pinned)) {
                            if (pinned) pinnedProcs.erase(r.pid);
                            else pinnedProcs.insert(r.pid);
                            // Deferred: we're mid-iteration over `rows`
                            // right now, and re-sorting it here would
                            // invalidate the loop out from under us.
                            needResort = true;
                        }
                        bool exempt = autoBlockExempt.count(r.pid) != 0;
                        if (ImGui::MenuItem("Exempt from auto-block", nullptr, exempt)) {
                            if (exempt) autoBlockExempt.erase(r.pid);
                            else autoBlockExempt.insert(r.pid);
                        }
                    }
                    ImGui::EndPopup();
                }
                ImGui::SameLine(0, 0);

                DrawProcessIcon(icons.Get(ToLowerAscii(r.name), r.exePath), r.name, dpiScale);
                CopyableText("name", r.name);
                if (pinnedProcs.count(r.pid)) {
                    ImGui::SameLine(0, 6);
                    ImGui::TextColored(ImVec4(0.271f, 0.608f, 1.000f, 1.0f), "*");
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Pinned to top");
                }
                if (pidMgr.IsLimited(r.pid)) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(limited)");
                }
                if (autoBlockExempt.count(r.pid)) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(auto-block exempt)");
                }

                ImGui::TableSetColumnIndex(1);
                if (r.pid == kUnknownPID) ImGui::TextUnformatted("-");
                else CopyableText("pid", std::to_string(r.pid));

                ImGui::TableSetColumnIndex(2);
                CopyableText("down", FormatBytes(r.totalDown));

                ImGui::TableSetColumnIndex(3);
                CopyableText("up", FormatBytes(r.totalUp));

                ImGui::TableSetColumnIndex(4);
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
        if (needResort) SortRows(rows, sortColumn, sortAscending, pinnedProcs);

        if (openLimitModal) {
            ImGui::OpenPopup("Set traffic limit");
            openLimitModal = false;
        }
        if (ImGui::BeginPopupModal("Set traffic limit", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::PushFont(g_fontBold, 0.0f);
            ImGui::Text("Limit %s (PID %d)", limitModalName.c_str(), limitModalPid);
            ImGui::PopFont();
            ImGui::Spacing();

            // Each row: an enable checkbox, then its value + unit inputs
            // (greyed out when the checkbox is off). The value column starts
            // past the widest label - measured, not hard-coded, so nothing
            // overlaps at any DPI or font.
            float checkboxW = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x;
            float valueColX = 0.0f;
            for (const char* lbl : {"Limit download", "Limit upload", "For a set time"})
                valueColX = std::max(valueColX, checkboxW + ImGui::CalcTextSize(lbl).x);
            valueColX += 24.0f; // gap between label and value

            float valW = 90.0f;
            // Combo widths measured from their longest option + the dropdown
            // arrow, so "minutes" isn't clipped the way a hard-coded width
            // clipped it before.
            float arrowW = ImGui::GetFrameHeight();
            float rateUnitW = ImGui::CalcTextSize("GB/s").x + arrowW + 16.0f;
            float durUnitW = ImGui::CalcTextSize("minutes").x + arrowW + 16.0f;
            // A stepped int field needs room for the number plus both +/-
            // buttons (each about a frame-height wide), or the number gets
            // squeezed to nothing - which is why the minutes box looked empty.
            float durValW = ImGui::GetFrameHeight() * 2 + 70.0f;

            ImGui::Checkbox("Limit download", &limDownOn);
            ImGui::SameLine(valueColX);
            ImGui::BeginDisabled(!limDownOn);
            ImGui::SetNextItemWidth(valW);
            ImGui::InputDouble("##dnval", &limDownVal, 0.0, 0.0, "%.2f");
            if (limDownVal < 0.01) limDownVal = 0.01;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(rateUnitW);
            ImGui::Combo("##dnunit", &limDownUnit, kUnitLabels, 3);
            ImGui::EndDisabled();

            ImGui::Checkbox("Limit upload", &limUpOn);
            ImGui::SameLine(valueColX);
            ImGui::BeginDisabled(!limUpOn);
            ImGui::SetNextItemWidth(valW);
            ImGui::InputDouble("##upval", &limUpVal, 0.0, 0.0, "%.2f");
            if (limUpVal < 0.01) limUpVal = 0.01;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(rateUnitW);
            ImGui::Combo("##upunit", &limUpUnit, kUnitLabels, 3);
            ImGui::EndDisabled();

            ImGui::Checkbox("For a set time", &limDurOn);
            ImGui::SameLine(valueColX);
            ImGui::BeginDisabled(!limDurOn);
            ImGui::SetNextItemWidth(durValW);
            ImGui::InputInt("##durval", &limDurValue);
            if (limDurValue < 1) limDurValue = 1;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(durUnitW);
            ImGui::Combo("##durunit", &limDurUnit, kDurationLabels, 3);
            ImGui::EndDisabled();

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            bool nothing = !limDownOn && !limUpOn;
            ImGui::BeginDisabled(nothing);
            if (ImGui::Button("Apply")) {
                PidBlockManager::LimitSpec spec;
                spec.limitDown = limDownOn;
                spec.downBps = (uint64_t)(limDownVal * (double)kUnitMultipliers[limDownUnit]);
                spec.limitUp = limUpOn;
                spec.upBps = (uint64_t)(limUpVal * (double)kUnitMultipliers[limUpUnit]);
                spec.hasDuration = limDurOn;
                spec.durationSecs = limDurValue * kDurationSeconds[limDurUnit];
                std::string err = pidMgr.SetLimit((uint32_t)limitModalPid, spec);
                uiStatus = err.empty() ? uiStatus : ("Limit failed: " + err);
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndDisabled();
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
            ImGui::SameLine();
            ImGui::Dummy(ImVec2(16, 0));
            ImGui::SameLine();
            ImGui::Checkbox("Show hostnames", &resolveHostnames);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Reverse-DNS each remote address. Names appear as lookups finish;\n"
                                   "hover a row to see the raw IP.");
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
                    if (c.remoteAddr.empty()) {
                        ImGui::TextDisabled("-");
                    } else {
                        // Show the short domain while a name is known, the
                        // plain IP otherwise. No "resolving..." filler -
                        // lookups land within a second and the row just
                        // updates itself, which is quieter than showing
                        // churn in the table.
                        std::string shown = c.remoteAddr;
                        std::string fullHost;
                        if (resolveHostnames && hostCache.Get(c.remoteAddr, &fullHost) == HostCache::Status::Resolved)
                            shown = ShortenHostname(fullHost);

                        CopyableText("remote", shown + ":" + std::to_string(c.remotePort));
                        // Hovering reveals what the short name is hiding:
                        // the full PTR name and the actual IP.
                        if (ImGui::IsItemHovered() && shown != c.remoteAddr)
                            ImGui::SetTooltip("%s\n%s:%u", fullHost.c_str(), c.remoteAddr.c_str(), c.remotePort);
                    }
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

        // --- per-app detail panel ---
        if (detailPid >= 0) {
            const AppStats* app = nullptr;
            for (const auto& r : rows)
                if ((int)r.pid == detailPid) { app = &r; break; }

            bool open = true;
            ImGui::SetNextWindowSize(ImVec2(560, 460), ImGuiCond_FirstUseEver);
            if (focusDetail) {
                ImGui::SetNextWindowFocus();
                focusDetail = false;
            }
            if (ImGui::Begin((detailName + " - details###appdetail").c_str(), &open)) {
                if (!app) {
                    ImGui::TextDisabled("This process is no longer sending traffic.");
                } else {
                    ImGui::PushFont(g_fontBold, 0.0f);
                    ImGui::Text("%s", app->name.c_str());
                    ImGui::PopFont();
                    ImGui::SameLine();
                    ImGui::TextDisabled("PID %u", app->pid);
                    if (!app->exePath.empty()) {
                        ImGui::TextDisabled("%s", app->exePath.c_str());
                    }
                    ImGui::Spacing();

                    ImGui::Text("Down %s", FormatRate(app->rateDown).c_str());
                    ImGui::SameLine(0, 24);
                    ImGui::Text("Up %s", FormatRate(app->rateUp).c_str());
                    ImGui::SameLine(0, 24);
                    ImGui::Text("Total %s", FormatBytes(app->totalDown + app->totalUp).c_str());
                    ImGui::Spacing();

                    ImGui::SeparatorText("Traffic types");
                    uint64_t typeTotal = 0;
                    for (size_t i = 0; i < (size_t)TrafficType::COUNT; i++) typeTotal += app->byType[i];
                    if (typeTotal == 0) {
                        ImGui::TextDisabled("(nothing captured yet)");
                    } else {
                        for (size_t i = 0; i < (size_t)TrafficType::COUNT; i++) {
                            if (app->byType[i] == 0) continue;
                            float frac = (float)((double)app->byType[i] / (double)typeTotal);
                            ImGui::Text("%-15s", TrafficTypeName((TrafficType)i));
                            ImGui::SameLine(150);
                            ImGui::ProgressBar(frac, ImVec2(-1, ImGui::GetTextLineHeight()),
                                                (FormatBytes(app->byType[i]) + "  " +
                                                 std::to_string((int)(frac * 100 + 0.5f)) + "%").c_str());
                        }
                    }
                    ImGui::Spacing();

                    ImGui::SeparatorText("Remote hosts");
                    auto conns = ConnectionsForPid((uint32_t)detailPid);
                    // Collapse to unique remote addresses - a browser can
                    // hold a dozen sockets to the same host and listing
                    // each one separately says nothing extra.
                    std::vector<std::string> hosts;
                    for (const auto& c : conns) {
                        if (c.remoteAddr.empty() || c.remoteAddr == "0.0.0.0" || c.remoteAddr == "::") continue;
                        if (std::find(hosts.begin(), hosts.end(), c.remoteAddr) == hosts.end())
                            hosts.push_back(c.remoteAddr);
                    }
                    if (hosts.empty()) {
                        ImGui::TextDisabled("(no active remote connections)");
                    } else {
                        for (const auto& ip : hosts) {
                            std::string full;
                            std::string shown = ip;
                            if (hostCache.Get(ip, &full) == HostCache::Status::Resolved) shown = ShortenHostname(full);
                            ImGui::BulletText("%s", shown.c_str());
                            if (ImGui::IsItemHovered() && shown != ip) ImGui::SetTooltip("%s\n%s", full.c_str(), ip.c_str());
                        }
                    }
                    ImGui::Spacing();

                    ImGui::SeparatorText("Controls");
                    bool blocked = pidMgr.IsBlocked(app->pid);
                    if (ImGui::Button(blocked ? "Unblock" : "Block")) {
                        std::string err = blocked ? pidMgr.Unblock(app->pid) : pidMgr.Block(app->pid);
                        if (!err.empty()) uiStatus = "Block/unblock failed: " + err;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button(pidMgr.IsLimited(app->pid) ? "Change limit..." : "Limit traffic...")) {
                        openLimitFor(app->pid, app->name);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("View connections...")) {
                        connViewPid = (int)app->pid;
                        connViewName = app->name;
                        openConnView = true;
                    }
                }
            }
            ImGui::End();
            if (!open) detailPid = -1;
        }

        // --- alerts feed ---
        if (showAlerts) {
            ImGui::SetNextWindowSize(ImVec2(560, 420), ImGuiCond_FirstUseEver);
            if (focusAlerts) {
                ImGui::SetNextWindowFocus();
                focusAlerts = false;
            }
            if (ImGui::Begin("Alerts", &showAlerts)) {
                auto list = alerts.Recent();
                ImGui::TextDisabled("%zu events - newest first", list.size());
                ImGui::SameLine();
                if (ImGui::SmallButton("Clear")) alerts.Clear();
                ImGui::Separator();
                ImGui::Spacing();

                if (list.empty()) {
                    ImGui::TextDisabled("Nothing yet. netvis will report apps connecting for the first\n"
                                         "time, processes that start listening for incoming connections,\n"
                                         "and changes to your DNS servers.");
                }
                for (size_t i = 0; i < list.size(); i++) {
                    const auto& a = list[i];
                    ImVec4 color;
                    switch (a.kind) {
                        case AlertKind::NewListener: color = ImVec4(0.95f, 0.55f, 0.30f, 1.0f); break;
                        case AlertKind::DnsChanged: color = ImVec4(0.95f, 0.75f, 0.30f, 1.0f); break;
                        case AlertKind::AutoBlocked: color = ImVec4(0.90f, 0.35f, 0.40f, 1.0f); break;
                        default: color = ImVec4(0.271f, 0.608f, 1.000f, 1.0f); break;
                    }
                    ImGui::PushID((int)i);
                    ImGui::TextColored(color, "%s", a.timestamp.c_str());
                    ImGui::SameLine();
                    ImGui::PushFont(g_fontBold, 0.0f);
                    ImGui::TextUnformatted(a.title.c_str());
                    ImGui::PopFont();
                    ImGui::Indent();
                    ImGui::TextWrapped("%s", a.detail.c_str());
                    ImGui::Unindent();
                    ImGui::Spacing();
                    ImGui::PopID();
                }
            }
            ImGui::End();
        }

        // --- firewall blocklist manager ---
        if (showBlocklist) {
            ImGui::SetNextWindowSize(ImVec2(560, 520), ImGuiCond_FirstUseEver);
            if (focusBlocklist) {
                ImGui::SetNextWindowFocus();
                focusBlocklist = false;
            }
            if (ImGui::Begin("Firewall blocklist", &showBlocklist)) {
                ImGui::TextWrapped("Domains the firewall blocks system-wide (any app, any browser). "
                                    "Stored in Program Files\\netvis\\blocklist.db.");
                ImGui::Spacing();

                if (ImGui::Checkbox("Use built-in malicious-domain database", &useDefaultBlocklist)) {
                    applyBlocklist();
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Merge netvis's bundled list of ~100k known ad/tracker/malware\n"
                                       "domains with your own entries below.");

                ImGui::Spacing();
                if (ImGui::Button("Import from text file...")) {
                    char path[MAX_PATH] = {};
                    OPENFILENAMEA ofn = {sizeof(ofn)};
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFilter = "Text files\0*.txt\0All files\0*.*\0";
                    ofn.lpstrFile = path;
                    ofn.nMaxFile = sizeof(path);
                    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                    if (GetOpenFileNameA(&ofn)) {
                        auto imported = blocklist_store::ParseFile(path);
                        std::unordered_set<std::string> have(userBlocklist.begin(), userBlocklist.end());
                        int added = 0;
                        for (auto& d : imported)
                            if (have.insert(d).second) { userBlocklist.push_back(d); added++; }
                        applyBlocklist();
                        blocklistStatus = "Imported " + std::to_string(added) + " new domain(s).";
                    }
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("One domain per line; lines starting with # are ignored.\n"
                                       "hosts-file lines like \"0.0.0.0 ads.example.com\" also work.");

                ImGui::Spacing();
                ImGui::SetNextItemWidth(-140);
                bool addNow = ImGui::InputTextWithHint("##newdomain", "add a domain, e.g. ads.example.com",
                                                        newDomainBuf, sizeof(newDomainBuf),
                                                        ImGuiInputTextFlags_EnterReturnsTrue);
                ImGui::SameLine();
                if (ImGui::Button("Add domain") || addNow) {
                    std::string d = ToLowerAscii(newDomainBuf);
                    // trim spaces
                    while (!d.empty() && (d.front() == ' ' || d.front() == '\t')) d.erase(d.begin());
                    while (!d.empty() && (d.back() == ' ' || d.back() == '\t' || d.back() == '\r')) d.pop_back();
                    if (!d.empty() &&
                        std::find(userBlocklist.begin(), userBlocklist.end(), d) == userBlocklist.end()) {
                        userBlocklist.push_back(d);
                        applyBlocklist();
                    }
                    newDomainBuf[0] = '\0';
                }

                if (!blocklistStatus.empty()) {
                    ImGui::TextColored(ImVec4(0.35f, 0.78f, 0.45f, 1.0f), "%s", blocklistStatus.c_str());
                }

                ImGui::Spacing();
                ImGui::Text("Your domains (%zu):", userBlocklist.size());
                if (ImGui::BeginTable("userblock", 2,
                                       ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                                       ImVec2(0, ImGui::GetContentRegionAvail().y - 6))) {
                    ImGui::TableSetupColumn("Domain", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 80);
                    int removeIdx = -1;
                    for (int i = 0; i < (int)userBlocklist.size(); i++) {
                        ImGui::TableNextRow();
                        ImGui::PushID(i);
                        ImGui::TableSetColumnIndex(0);
                        ImGui::AlignTextToFramePadding();
                        ImGui::TextUnformatted(userBlocklist[i].c_str());
                        ImGui::TableSetColumnIndex(1);
                        if (ImGui::SmallButton("Remove")) removeIdx = i;
                        ImGui::PopID();
                    }
                    if (userBlocklist.empty()) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextDisabled("(none yet - add or import domains above)");
                    }
                    ImGui::EndTable();
                    if (removeIdx >= 0) {
                        userBlocklist.erase(userBlocklist.begin() + removeIdx);
                        applyBlocklist();
                    }
                }
            }
            ImGui::End();
        }

        ImGui::Render();
        const float clear_color[4] = {0.06f, 0.06f, 0.08f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    Log("netvis shutting down");

    // Persist before tearing anything down, while the state is still valid.
    // (Pins and auto-block exemptions are PID-based and intentionally not
    // persisted - PIDs are meaningless after a restart.)
    settings.adBlockerEnabled = blkOk ? blk.Enabled() : settings.adBlockerEnabled;
    settings.autoBlockThreshold = autoBlockThresholdValue;
    settings.autoBlockUnitIdx = autoBlockUnitIdx;
    settings.runInBackground = runInBackground;
    settings.notifyOnAlert = notifyOnAlert;
    settings.useDefaultBlocklist = useDefaultBlocklist;
    for (const auto& e : alerts.KnownExes()) settings.knownExes.insert(e);
    for (const auto& r : rows) {
        if (r.pid == kUnknownPID || r.name.empty()) continue;
        // Accumulate onto whatever previous runs recorded, so the totals
        // are lifetime rather than per-session.
        settings.lifetimeBytes[ToLowerAscii(r.name)] += r.totalDown + r.totalUp;
    }
    settings.Save();

    alerts.Stop();
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

    // A second instance asking us to surface (registered message, so it's
    // not a fixed case in the switch below).
    if (msg == g_showMsg && g_showMsg != 0) {
        RestoreWindow(hWnd);
        return 0;
    }

    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_ResizeWidth = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_CLOSE:
            // In background mode the close button hides to tray instead of
            // quitting; the app keeps running until "Exit" from the tray.
            if (g_runInBackground) {
                g_windowHidden = true;
                ::ShowWindow(hWnd, SW_HIDE);
                AddTrayIcon(hWnd);
                return 0;
            }
            ::DestroyWindow(hWnd);
            return 0;
        case WM_NETVIS_TRAY:
            if (LOWORD(lParam) == WM_LBUTTONUP || LOWORD(lParam) == WM_LBUTTONDBLCLK) {
                RestoreWindow(hWnd);
            } else if (LOWORD(lParam) == WM_RBUTTONUP) {
                POINT pt;
                ::GetCursorPos(&pt);
                HMENU menu = ::CreatePopupMenu();
                ::AppendMenuW(menu, MF_STRING, TRAY_CMD_OPEN, L"Open netvis");
                ::AppendMenuW(menu, MF_STRING, TRAY_CMD_EXIT, L"Exit");
                ::SetForegroundWindow(hWnd); // required so the menu dismisses on click-away
                UINT cmd = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd, nullptr);
                ::DestroyMenu(menu);
                if (cmd == TRAY_CMD_OPEN) RestoreWindow(hWnd);
                else if (cmd == TRAY_CMD_EXIT) { RemoveTrayIcon(); ::DestroyWindow(hWnd); }
            }
            return 0;
        case WM_DESTROY:
            RemoveTrayIcon();
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
