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
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "monitor.h"
#include "blocker.h"
#include "pidblock.h"
#include "icon_cache.h"
#include "winicon.h"
#include "traffic_graph.h"
#include "connlist.h"
#include "hostcache.h"
#include "alerts.h"
#include "settings.h"
#include "blocklist_store.h"
#include "conn_kill.h"
#include "ipban.h"
#include "startup.h"
#include "license.h"
#include "theme.h"
#include "log.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
// netvis's own icon as a texture, for the license and startup screens. The
// window and tray use the HICON directly; ImGui needs a shader resource view.
static ID3D11ShaderResourceView* g_appIconSRV = nullptr;

static bool CreateDeviceD3D(HWND hWnd);

// Uploads decoded icon pixels as a texture. Small enough not to be worth a
// cache: this runs once, for one image.
static ID3D11ShaderResourceView* CreateTextureFromPixels(const IconPixels& px) {
    if (!px.ok || !g_pd3dDevice) return nullptr;

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

    ID3D11Texture2D* tex = nullptr;
    if (FAILED(g_pd3dDevice->CreateTexture2D(&desc, &sub, &tex))) return nullptr;
    ID3D11ShaderResourceView* srv = nullptr;
    HRESULT hr = g_pd3dDevice->CreateShaderResourceView(tex, nullptr, &srv);
    tex->Release();
    return SUCCEEDED(hr) ? srv : nullptr;
}
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

// Opens a link in the user's browser. Goes through explorer.exe on purpose:
// netvis runs elevated, and a browser launched directly from an elevated
// process inherits that - which modern browsers either refuse outright or
// run as administrator, neither of which anyone wants. Handing the URL to
// explorer drops it back to normal integrity.
static void OpenInBrowser(const char* url) {
    ::ShellExecuteA(nullptr, "open", "explorer.exe", url, nullptr, SW_SHOWNORMAL);
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
// A blue, white-labelled button for actions that change what netvis is
// doing. Grey buttons with dark labels disappeared into the background in
// light mode and read as disabled.
bool ActionButton(const char* label, ImVec2 size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, theme::ActionButton());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::ActionButtonHover());
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::ActionButtonDown());
    ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
    bool clicked = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return clicked;
}

// Ordinary button with the theme's colours stated explicitly rather than
// inherited. Same reason as ActionButton: anything that falls back to the
// global default is one missed palette entry away from being unreadable.
bool NeutralButton(const char* label, ImVec2 size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, theme::NeutralButton());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::NeutralButtonHover());
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::NeutralButtonDown());
    ImGui::PushStyleColor(ImGuiCol_Text, theme::NeutralText());
    bool clicked = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return clicked;
}

// A dropdown's arrow is drawn with ImGuiCol_Button, so it needs the same
// treatment - that arrow was the "black box" next to the threshold units.
void PushComboColors() {
    ImGui::PushStyleColor(ImGuiCol_Button, theme::NeutralButton());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::NeutralButtonHover());
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::NeutralButtonDown());
}
inline void PopComboColors() { ImGui::PopStyleColor(3); }

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
void ApplyModernStyle(bool light) {
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
    // Light is not the dark palette inverted. On white, text needs more
    // contrast to read as solid, so textMain is near-black rather than a
    // mid grey, and textDim stays dark enough to be read rather than
    // merely sensed. Surfaces step DOWN from white as they go up in the
    // stack, the mirror of dark stepping up from black.
    ImVec4 bgDark, bgMed, bgLight, bgLighter, accent, accentHover, accentActive,
        textMain, textDim, border;
    if (light) {
        bgDark       = ImVec4(0.965f, 0.969f, 0.976f, 1.00f);
        bgMed        = ImVec4(1.000f, 1.000f, 1.000f, 1.00f);
        bgLight      = ImVec4(0.898f, 0.910f, 0.925f, 1.00f);
        bgLighter    = ImVec4(0.831f, 0.847f, 0.871f, 1.00f);
        accent       = ImVec4(0.153f, 0.412f, 0.816f, 1.00f);
        accentHover  = ImVec4(0.204f, 0.478f, 0.882f, 1.00f);
        accentActive = ImVec4(0.118f, 0.345f, 0.706f, 1.00f);
        textMain     = ImVec4(0.043f, 0.051f, 0.071f, 1.00f);
        // Secondary text sits much closer to black than the dark theme's
        // grey does to white. On a light background a mid grey reads as
        // faded rather than quiet, so "dim" here means "not bold", not
        // "hard to see".
        textDim      = ImVec4(0.220f, 0.243f, 0.278f, 1.00f);
        border       = ImVec4(0.706f, 0.733f, 0.776f, 1.00f);
    } else {
        bgDark       = ImVec4(0.043f, 0.047f, 0.059f, 1.00f);
        bgMed        = ImVec4(0.075f, 0.082f, 0.098f, 1.00f);
        bgLight      = ImVec4(0.130f, 0.145f, 0.173f, 1.00f);
        bgLighter    = ImVec4(0.184f, 0.204f, 0.243f, 1.00f);
        accent       = ImVec4(0.271f, 0.608f, 1.000f, 1.00f);
        accentHover  = ImVec4(0.400f, 0.690f, 1.000f, 1.00f);
        accentActive = ImVec4(0.196f, 0.502f, 0.878f, 1.00f);
        textMain     = ImVec4(0.961f, 0.965f, 0.973f, 1.00f);
        textDim      = ImVec4(0.635f, 0.659f, 0.694f, 1.00f);
        border       = ImVec4(0.294f, 0.318f, 0.361f, 1.00f);
    }

    colors[ImGuiCol_Text] = textMain;
    colors[ImGuiCol_TextDisabled] = textDim;
    colors[ImGuiCol_WindowBg] = bgDark;
    colors[ImGuiCol_ChildBg] = bgMed;
    colors[ImGuiCol_PopupBg] = ImVec4(bgMed.x, bgMed.y, bgMed.z, 0.98f);
    // A slightly blue border in light mode, so a tinted button has a
    // defined edge instead of bleeding into the page.
    colors[ImGuiCol_Border] = light ? ImVec4(0.639f, 0.706f, 0.808f, 1.00f) : border;
    colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg] = light ? ImVec4(1.000f, 1.000f, 1.000f, 1.00f) : bgLight;
    colors[ImGuiCol_FrameBgHovered] = light ? ImVec4(0.949f, 0.961f, 0.976f, 1.00f) : bgLighter;
    // Pressed/active input background. The old value was a dark slate in
    // both themes, so in light mode clicking a field or a stepper arrow
    // turned it near-black under near-black text - the "grey box with a
    // black arrow" problem.
    colors[ImGuiCol_FrameBgActive] =
        light ? ImVec4(0.898f, 0.933f, 0.980f, 1.00f) : ImVec4(0.220f, 0.243f, 0.290f, 1.00f);
    colors[ImGuiCol_TitleBg] = bgDark;
    colors[ImGuiCol_TitleBgActive] = bgDark;
    colors[ImGuiCol_TitleBgCollapsed] = bgDark;
    colors[ImGuiCol_MenuBarBg] = bgMed;
    colors[ImGuiCol_ScrollbarBg] = bgDark;
    colors[ImGuiCol_ScrollbarGrab] = light ? ImVec4(0.784f, 0.804f, 0.835f, 1.00f) : bgLight;
    colors[ImGuiCol_ScrollbarGrabHovered] = light ? ImVec4(0.706f, 0.729f, 0.769f, 1.00f) : bgLighter;
    colors[ImGuiCol_ScrollbarGrabActive] = accent;
    colors[ImGuiCol_CheckMark] = accent;
    colors[ImGuiCol_SliderGrab] = accent;
    colors[ImGuiCol_SliderGrabActive] = accentActive;
    // Ordinary buttons in light mode get a blue tint rather than plain
    // grey. Grey-on-grey reads as disabled chrome next to the white
    // surfaces around it; a wash of the accent colour says "clickable"
    // without shouting the way a solid blue would.
    colors[ImGuiCol_Button] = light ? ImVec4(0.855f, 0.898f, 0.965f, 1.00f) : bgLight;
    colors[ImGuiCol_ButtonHovered] = light ? ImVec4(0.780f, 0.851f, 0.949f, 1.00f) : bgLighter;
    // ImGui draws every label with one text colour, so a button that turns
    // saturated blue while pressed would put near-black text on blue in
    // light mode. Keep pressed buttons grey there and let the border carry
    // the state.
    colors[ImGuiCol_ButtonActive] = light ? ImVec4(0.694f, 0.796f, 0.925f, 1.00f) : accentActive;
    // Selection tints. Kept weak in light mode so the near-black text on
    // top stays the thing you read.
    colors[ImGuiCol_Header] = ImVec4(accent.x, accent.y, accent.z, light ? 0.18f : 0.35f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(accent.x, accent.y, accent.z, light ? 0.26f : 0.55f);
    colors[ImGuiCol_HeaderActive] = ImVec4(accent.x, accent.y, accent.z, light ? 0.34f : 0.75f);
    colors[ImGuiCol_Separator] = border;
    colors[ImGuiCol_SeparatorHovered] = accent;
    colors[ImGuiCol_SeparatorActive] = accentActive;
    colors[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_ResizeGripHovered] = accent;
    colors[ImGuiCol_ResizeGripActive] = accentActive;
    colors[ImGuiCol_Tab] = bgMed;
    colors[ImGuiCol_TabHovered] = light ? ImVec4(0.847f, 0.886f, 0.957f, 1.00f) : accentHover;
    colors[ImGuiCol_TabSelected] = light ? ImVec4(0.784f, 0.851f, 0.949f, 1.00f) : accent;
    colors[ImGuiCol_TabDimmed] = bgMed;
    colors[ImGuiCol_TabDimmedSelected] = bgLight;
    colors[ImGuiCol_TableHeaderBg] = light ? ImVec4(0.898f, 0.914f, 0.937f, 1.00f) : bgLight;
    colors[ImGuiCol_TableBorderStrong] = border;
    colors[ImGuiCol_TableBorderLight] = ImVec4(border.x, border.y, border.z, 0.55f);
    colors[ImGuiCol_TableRowBg] = ImVec4(1, 1, 1, 0.00f);
    // Zebra striping is an overlay, so it has to invert with the theme -
    // a white wash over a white table is nothing at all.
    colors[ImGuiCol_TableRowBgAlt] = light ? ImVec4(0, 0, 0, 0.035f) : ImVec4(1, 1, 1, 0.05f);
    colors[ImGuiCol_TextSelectedBg] = ImVec4(accent.x, accent.y, accent.z, light ? 0.25f : 0.35f);
    colors[ImGuiCol_DragDropTarget] = accent;
    colors[ImGuiCol_NavCursor] = accent;
    colors[ImGuiCol_NavWindowingHighlight] = light ? ImVec4(0, 0, 0, 0.55f) : ImVec4(1, 1, 1, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.0f, 0.0f, 0.0f, light ? 0.35f : 0.65f);
}

// Draws one full frame showing just the netvis wordmark and a status line.
// Used for "Checking your license..." and, more importantly, for the frame
// left on screen while the app starts up: opening WinDivert and loading a
// 99k-entry blocklist takes long enough that whatever was drawn last stays
// visible, and that shouldn't be the license screen.
void DrawSplashFrame(ImGuiIO& io, float dpiScale, const char* message) {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(40, 34));
    ImGui::Begin("splash", nullptr,
                  ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar);
    ImGui::PopStyleVar();

    float full = ImGui::GetContentRegionAvail().x;
    auto centered = [&](const char* text) {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (full - ImGui::CalcTextSize(text).x) * 0.5f);
        ImGui::TextUnformatted(text);
    };

    ImGui::Dummy(ImVec2(0, io.DisplaySize.y * 0.06f));
    // The app icon, so the first thing a customer sees is branded rather
    // than a bare word. Falls through harmlessly if the texture is missing.
    if (g_appIconSRV) {
        const float iconSize = 96.0f * dpiScale;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (full - iconSize) * 0.5f);
        ImGui::Image((ImTextureID)g_appIconSRV, ImVec2(iconSize, iconSize));
        ImGui::Dummy(ImVec2(0, 12.0f * dpiScale));
    }
    {
        const char* title = "netvis";
        ImGui::PushFont(g_fontBold, 52.0f * dpiScale);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (full - ImGui::CalcTextSize(title).x) * 0.5f);
        ImGui::TextUnformatted(title);
        ImGui::PopFont();
    }
    ImGui::PushStyleColor(ImGuiCol_Text, theme::Dim());
    centered("Firewall & bandwidth manager");
    ImGui::PopStyleColor();

    ImGui::Dummy(ImVec2(0, 26.0f * dpiScale));
    centered(message);

    ImGui::End();
    ImGui::Render();
    float clear_color[4];
    theme::ClearColor(clear_color);
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
    g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(1, 0);
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

    auto startTrial = [shared]() {
        shared->busy.store(true);
        std::thread([shared] {
            std::string err;
            bool ok = license::StartTrial(&err);
            {
                std::lock_guard<std::mutex> lock(shared->mu);
                shared->error = ok ? "" : err;
            }
            shared->activated.store(ok);
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
    bool expired = false; // came from a license that ran out, not a fresh install
    // Until the server has actually answered, the only thing that may be on
    // screen is "checking". Without this, any path that reaches the render
    // code before the worker finishes flashes the key entry form for a
    // frame or two, which reads as "your license is gone".
    bool gotAnswer = false;

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
                gotAnswer = true;
                if (r == (int)license::Status::Licensed) {
                    // Leave a neutral frame up: the app now spends a couple
                    // of seconds starting capture, and this is what stays on
                    // screen during it.
                    DrawSplashFrame(io, dpiScale, "Starting netvis...");
                    return true;
                }
                expired = (r == (int)license::Status::Expired);
                phase = (r == (int)license::Status::Unreachable) ? Phase::Offline : Phase::NeedKey;
            } else if (phase == Phase::Activating) {
                if (shared->activated.load()) {
                    Log("license: activation succeeded, starting netvis");
                    DrawSplashFrame(io, dpiScale, "Starting netvis...");
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
        ImGui::Dummy(ImVec2(0, io.DisplaySize.y * 0.06f));

        if (g_appIconSRV) {
            const float iconSize = 96.0f * dpiScale;
            centerNext(iconSize);
            ImGui::Image((ImTextureID)g_appIconSRV, ImVec2(iconSize, iconSize));
            ImGui::Dummy(ImVec2(0, 12.0f * dpiScale));
        }

        {
            const char* title = "netvis";
            ImGui::PushFont(g_fontBold, 52.0f * dpiScale);
            centerNext(ImGui::CalcTextSize(title).x);
            ImGui::TextUnformatted(title);
            ImGui::PopFont();
        }
        centeredColored(theme::Dim(), "Firewall & bandwidth manager");

        ImGui::Dummy(ImVec2(0, 26.0f * dpiScale));

        switch (gotAnswer ? phase : Phase::Checking) {
        case Phase::Checking:
            centeredText("Checking your license...");
            break;

        case Phase::Offline: {
            centeredColored(theme::Warn(), "Can't reach the licensing server.");
            ImGui::Spacing();
            centeredColored(theme::Dim(),
                            "netvis checks your license when it opens.");
            centeredColored(theme::Dim(),
                            "Check your internet connection and try again.");
            ImGui::Dummy(ImVec2(0, 20.0f * dpiScale));

            float bw = 140.0f * dpiScale, qw = 100.0f * dpiScale;
            centerNext(bw + qw + ImGui::GetStyle().ItemSpacing.x);
            if (NeutralButton("Try again", ImVec2(bw, 0))) {
                phase = Phase::Checking;
                startAuth();
            }
            ImGui::SameLine();
            if (NeutralButton("Quit", ImVec2(qw, 0))) return false;
            break;
        }

        case Phase::NeedKey:
        case Phase::Activating: {
            bool busy = (phase == Phase::Activating);

            // The trial comes FIRST for anyone who hasn't had one. Asking a
            // first-time user for a key before offering the free option
            // reads as demanding money up front, and buries the thing most
            // of them actually want below the fold.
            if (!expired) {
                centeredText("Try netvis free for 14 days.");
                ImGui::Spacing();
                centeredColored(theme::Faint(),
                                "The full version. No card, no account.");
                ImGui::Dummy(ImVec2(0, 14.0f * dpiScale));

                float tw = 260.0f * dpiScale;
                centerNext(tw);
                ImGui::BeginDisabled(busy);
                if (NeutralButton("Start free trial", ImVec2(tw, 0))) {
                    phase = Phase::Activating;
                    {
                        std::lock_guard<std::mutex> lock(shared->mu);
                        shared->error.clear();
                    }
                    startTrial();
                }
                ImGui::EndDisabled();

                ImGui::Dummy(ImVec2(0, 18.0f * dpiScale));
                ImGui::Separator();
                ImGui::Dummy(ImVec2(0, 14.0f * dpiScale));
                centeredColored(theme::Dim(), "Already have a license key?");
            } else {
                centeredColored(theme::Warn(), "Your license has run out.");
                ImGui::Spacing();
                centeredText("Enter a new key to carry on for another 6 months.");
                ImGui::Spacing();
                centeredColored(theme::Faint(), "Get one at netvis.cc");
            }
            ImGui::Dummy(ImVec2(0, 14.0f * dpiScale));
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
                    centeredColored(theme::Bad(), shared->error.c_str());
                }
            }

            ImGui::Dummy(ImVec2(0, 18.0f * dpiScale));
            float aw = 140.0f * dpiScale, qw = 100.0f * dpiScale;
            centerNext(aw + qw + ImGui::GetStyle().ItemSpacing.x);
            ImGui::BeginDisabled(busy || !complete);
            if (NeutralButton("Activate", ImVec2(aw, 0)) || (submitted && complete && !busy)) {
                phase = Phase::Activating;
                {
                    std::lock_guard<std::mutex> lock(shared->mu);
                    shared->error.clear();
                }
                startActivate(key);
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (NeutralButton("Quit", ImVec2(qw, 0))) return false;

            if (busy) {
                ImGui::Spacing();
                centeredText("Working...");
            }
            break;
        }
        }

        ImGui::End();

        ImGui::Render();
        float clear_color[4];
    theme::ClearColor(clear_color);
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }
}

} // namespace

namespace theme {
// Resolves Auto against the Windows setting, then restyles everything.
// Defined here rather than in the header so it can reach ApplyModernStyle,
// which lives in this file's anonymous namespace with the rest of the
// styling. Called at startup and whenever the choice changes, so a switch
// takes effect on the very next frame.
void Apply(Mode m) {
    detail::g_mode = m;
    detail::g_light = (m == Mode::Light) || (m == Mode::Auto && SystemPrefersLight());
    ApplyModernStyle(detail::g_light);
}
} // namespace theme


int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    LogInit();
    Log("netvis starting");

    // Single instance. Two copies both driving WinDivert would fight over
    // capture/blocking and each would leave its own tray icon, so if one is
    // already running we just ask it to come to the front (in case it's
    // hidden in the tray) and exit. The mutex is held for the whole process
    // lifetime; Windows releases it automatically on exit.
    g_showMsg = ::RegisterWindowMessageW(L"netvis_show_window_v1");

    // The background copy is normally started by the scheduled "run at
    // startup" task, while the copy launched from the Start menu is elevated
    // through the manifest. Those can be different tokens, and a mutex created
    // by one with default security can be invisible to the other - so the
    // second copy wouldn't detect the first and would start a DUPLICATE (two
    // tray icons, two WinDivert handles fighting over capture). Two fixes:
    //   - the mutex lives in the Global\ namespace with a null DACL, so any
    //     token in any session can open it and ERROR_ALREADY_EXISTS is
    //     reliable regardless of who started the other copy;
    //   - when it already exists, find the running window and post to it
    //     directly instead of only broadcasting - a broadcast to a hidden,
    //     tray-resident window can be dropped, which is why "open it again"
    //     sometimes did nothing (or looked like a new instance).
    SECURITY_DESCRIPTOR sd;
    ::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    ::SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE); // null DACL: everyone may open it
    SECURITY_ATTRIBUTES sa{sizeof(sa), &sd, FALSE};
    HANDLE instanceMutex = ::CreateMutexW(&sa, FALSE, L"Global\\netvis_single_instance_v1");
    if (instanceMutex && ::GetLastError() == ERROR_ALREADY_EXISTS) {
        Log("netvis: another instance is already running - surfacing it and exiting");
        HWND existing = ::FindWindowW(L"netvis", nullptr);
        if (existing) ::PostMessageW(existing, g_showMsg, 0, 0);
        else ::PostMessageW(HWND_BROADCAST, g_showMsg, 0, 0);
        ::CloseHandle(instanceMutex);
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

    // Let a second instance's "surface yourself" message reach this window
    // even if it arrives from a process at a different integrity level -
    // without this, UIPI silently filters the cross-process post and the
    // running copy never comes to the front.
    ::ChangeWindowMessageFilterEx(hwnd, g_showMsg, MSGFLT_ALLOW, nullptr);

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

    // Decode the embedded icon at 256px for the license/startup screens.
    // Loaded fresh at that size rather than reusing iconLarge, which is
    // whatever size Windows picked for the title bar and would look soft
    // blown up to ~96 points.
    {
        HICON big = (HICON)::LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 256, 256, 0);
        if (big) {
            g_appIconSRV = CreateTextureFromPixels(IconFromHICON(big));
            ::DestroyIcon(big);
        }
        if (!g_appIconSRV) Log("netvis: could not build the app icon texture");
    }

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

    theme::Apply(static_cast<theme::Mode>(Settings::Load().themeMode));
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
    // 0 = Processes, 1 = Settings. Deliberately not persisted: the app
    // should open on what it is for, not on wherever you last poked.
    int activeTab = 0;
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

    // IPs banned this session on top of the persisted list: the addresses a
    // blocked domain resolved to at the moment it was added. They aren't
    // persisted (the domain's DNS block already covers it after a restart,
    // and its IPs rotate), but while the session runs they stay in the
    // firewall so a browser can't reconnect to a cached IP over QUIC.
    // Keyed by the list entry (a domain) so removing that entry can drop
    // exactly its addresses again. A flat list couldn't be un-banned per
    // entry, which is half of why bans never lifted.
    std::unordered_map<std::string, std::vector<std::string>> runtimeBannedIPs;

    // Rewrites the OS firewall ban rules to match the current ban set: every
    // bare-IP entry the user added to the blocklist, plus this session's
    // resolved-domain IPs. Runs netsh, which is slow, so it's fired on a
    // detached thread - ipban serialises the rewrites internally.
    //
    // Gated on the blocker being ON: with blocking off, the desired set is
    // empty, so this CLEARS every rule. That's the other half of the fix -
    // firewall rules are OS state, independent of netvis's capture handle, so
    // turning the blocker off did nothing to them and IPs stayed banned. Now
    // the master switch controls the bans too, and flipping it back on
    // re-applies them from the lists. Also called on startup, which reconciles
    // the rules with the saved state and clears anything stale from last run.
    auto rebuildFirewall = [&]() {
        std::vector<std::string> ips;
        if (blkOk && blk.Enabled()) {
            for (const auto& e : userBlocklist)
                if (connkill::IsIPLiteral(e)) ips.push_back(e);
            for (const auto& kv : runtimeBannedIPs)
                for (const auto& ip : kv.second) ips.push_back(ip);
        }
        std::thread([ips]() { ipban::SetBlockedIPs(ips); }).detach();
    };

    // Applies the current user list + default toggle to the blocker and
    // saves it to disk. Called whenever the blocklist is edited. IP entries
    // are harmless in the blocker's domain list (they never match a DNS
    // question); the firewall is what actually enforces them, via
    // rebuildFirewall.
    auto applyBlocklist = [&]() {
        blocklist_store::Save(userBlocklist);
        if (blkOk) blk.Reload(userBlocklist, useDefaultBlocklist);
    };

    // Reconcile the firewall with whatever IP entries were loaded from disk.
    rebuildFirewall();

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
    // The saved preference decides; the scheduled task is just how it's
    // carried out. Re-registering it on every launch costs a few
    // milliseconds and makes the whole thing self-healing: it comes back
    // after an uninstall removed it, and it always points at the exe that
    // is actually running rather than wherever the last build lived.
    bool runOnStartup = settings.runOnStartup;
    if (runOnStartup) startup::SetEnabled(true);
    runOnStartup = startup::IsEnabled(); // reflect what actually took effect
    Log("netvis: run at startup = %d (task %s)", (int)settings.runOnStartup,
        runOnStartup ? "present" : "missing");

    // Persist the preference toggles the moment they change, not only at a
    // clean shutdown. The old code saved once, at the very end of the loop -
    // so any toggle was lost whenever the process didn't exit gracefully: a
    // reboot killing the tray-resident copy, End Task, or the taskkill in
    // build_and_run.bat. That's why "run in background" (and the theme, and
    // the rest) kept reverting. This snapshots just the preferences - not the
    // lifetime byte counters, which are only accumulated at shutdown, so
    // calling it mid-session can't double-count them.
    auto persistPrefs = [&]() {
        settings.adBlockerEnabled = blkOk ? blk.Enabled() : settings.adBlockerEnabled;
        settings.autoBlockThreshold = autoBlockThresholdValue;
        settings.autoBlockUnitIdx = autoBlockUnitIdx;
        settings.runInBackground = runInBackground;
        settings.notifyOnAlert = notifyOnAlert;
        settings.runOnStartup = runOnStartup;
        settings.themeMode = (int)theme::Current();
        settings.useDefaultBlocklist = useDefaultBlocklist;
        settings.Save();
    };

    // Licensing re-checks while the app is already running. The flag is a
    // shared_ptr so the detached worker can safely clear it even if it
    // outlives the loop during shutdown.
    constexpr uint64_t kLicenseRecheckMs = 6ull * 60 * 60 * 1000; // 6 hours
    uint64_t lastLicenseCheckMs = ::GetTickCount64(); // the startup gate just checked
    auto licenseCheckBusy = std::make_shared<std::atomic<bool>>(false);

    // Upgrading from trial to paid without restarting: a Buy button beside
    // the countdown, and somewhere to paste the key it produces. Buying is
    // pointless if the key can only be redeemed after the trial has run out.
    bool showUpgrade = false;
    char upgradeKeyBuf[512] = {};
    struct KeyOp {
        std::atomic<bool> busy{false};
        std::atomic<bool> ok{false};
        std::mutex mu;
        std::string error;
    };
    auto keyOp = std::make_shared<KeyOp>();
    std::string licenseToast;      // brief "thanks" line under the title
    uint64_t licenseToastUntil = 0;

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
                    // Both answers mean "this machine may no longer run":
                    // NotLicensed for a revoked or unknown machine, Expired
                    // when the term simply ran out. Watching only the first
                    // let a trial expire mid-session and carry on running
                    // until the next launch.
                    license::Status s = license::Authenticate();
                    if (s == license::Status::NotLicensed || s == license::Status::Expired)
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

        // --- header: tab strip on the left, license/alerts on the right ---
        //
        // No wordmark and no tagline. The window title bar already says
        // netvis; repeating it inside costs a line of vertical space on
        // every screen and makes the app look like a widget someone
        // embedded rather than the thing you opened.
        {
            auto tab = [&](const char* label, int id) {
                bool active = (activeTab == id);
                // The selected tab keeps a saturated blue in both themes, so
                // its label needs white explicitly - ImGui has one global
                // text colour, and in light mode that's near-black.
                if (active) {
                    ImGui::PushStyleColor(ImGuiCol_Button, theme::TabActive());
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::TabActiveHover());
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::TabActive());
                    ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button, theme::TabIdle());
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::TabIdleHover());
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::TabIdleHover());
                }
                if (ImGui::Button(label, ImVec2(110 * dpiScale, 0))) activeTab = id;
                ImGui::PopStyleColor(active ? 4 : 3);
            };
            tab("Processes", 0);
            ImGui::SameLine(0, 8);
            tab("Settings", 1);

            size_t unread = alerts.UnreadCount();
            char label[64];
            if (unread > 0) snprintf(label, sizeof(label), "Alerts (%zu)", unread);
            else snprintf(label, sizeof(label), "Alerts");
            float btnW = ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2 + 8;

            // License state lives up here, right of the tabs: visible from
            // both tabs, and clear of the process table's Block buttons.
            float trialW = 0.0f;
            char badge[64] = {};
            const char* buyLabel = "Buy";
            float buyW = 0.0f;
            bool onTrial = license::LastWasTrial();
            if (onTrial) {
                int days = license::LastDaysLeft();
                if (days <= 0) snprintf(badge, sizeof(badge), "Trial - last day");
                else snprintf(badge, sizeof(badge), "Trial - %d day%s left", days, days == 1 ? "" : "s");
                buyW = ImGui::CalcTextSize(buyLabel).x + ImGui::GetStyle().FramePadding.x * 2 + 8;
                trialW = ImGui::CalcTextSize(badge).x + buyW + ImGui::GetStyle().ItemSpacing.x * 2 +
                         14.0f * dpiScale;
            }

            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() +
                                  std::max(0.0f, ImGui::GetContentRegionAvail().x - btnW - trialW));

            if (onTrial) {
                int days = license::LastDaysLeft();
                ImVec4 col = (days <= 3) ? theme::Warn()
                                         : theme::Dim();
                // A small dot instead of an icon: it reads as a status light
                // and costs nothing at any DPI.
                float dot = 8.0f * dpiScale;
                ImVec2 p = ImGui::GetCursorScreenPos();
                ImGui::GetWindowDrawList()->AddCircleFilled(
                    ImVec2(p.x + dot * 0.5f, p.y + ImGui::GetFrameHeight() * 0.5f), dot * 0.5f,
                    (days <= 3) ? IM_COL32(0xf2, 0xa6, 0x59, 0xFF) : IM_COL32(0x46, 0xe0, 0x76, 0xFF));
                ImGui::Dummy(ImVec2(dot, ImGui::GetFrameHeight()));
                ImGui::SameLine(0, 6);

                ImGui::AlignTextToFramePadding();
                ImGui::TextColored(col, "%s", badge);
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Button, theme::BuyButton());
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::BuyButtonHover());
                ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
                if (ImGui::Button(buyLabel)) {
                    showUpgrade = true;
                    {
                        std::lock_guard<std::mutex> lock(keyOp->mu);
                        keyOp->error.clear();
                    }
                    keyOp->ok.store(false);
                }
                ImGui::PopStyleColor(3);
                ImGui::SameLine();
            }
            if (unread > 0) {
                ImGui::PushStyleColor(ImGuiCol_Button, theme::AlertButton());
                ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
            }
            bool alertClicked = (unread > 0) ? ImGui::Button(label) : NeutralButton(label);
            if (alertClicked) {
                showAlerts = true;
                focusAlerts = true;
                alerts.MarkAllRead();
            }
            if (unread > 0) ImGui::PopStyleColor(2);
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Messages that matter on either tab.
        if (!licenseToast.empty()) {
            if (::GetTickCount64() > licenseToastUntil) licenseToast.clear();
            else ImGui::TextColored(theme::Ok(), "%s", licenseToast.c_str());
        }
        {
            int days = license::LastDaysLeft();
            // A trial is always inside 14 days, so warning on that basis
            // would nag from day one - the header badge already shows the
            // countdown. Warn late instead.
            int warnBelow = license::LastWasTrial() ? 3 : 14;
            if (days >= 0 && days <= warnBelow) {
                ImVec4 warn = (days <= 3) ? theme::Bad()
                                          : theme::Warn();
                const char* what = license::LastWasTrial() ? "trial" : "license";
                if (days == 0)
                    ImGui::TextColored(warn, "Your %s expires today - buy at netvis.cc", what);
                else
                    ImGui::TextColored(warn, "Your %s expires in %d day%s - buy at netvis.cc", what, days,
                                        days == 1 ? "" : "s");
            }
        }

        if (activeTab == 1) {
            // ================= SETTINGS =================
            // Grouped under headings rather than a wall of checkboxes: the
            // two that change what netvis does to your traffic are worth
            // separating from the ones that only change how it behaves.
            auto heading = [&](const char* text) {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextUnformatted(text);
                ImGui::PopStyleColor();
                ImGui::Spacing();
            };

            heading("PROTECTION");

            if (blkOk) {
                bool blockerEnabled = blk.Enabled();
                if (ImGui::Checkbox("Block trackers & malicious domains", &blockerEnabled)) {
                    blk.SetEnabled(blockerEnabled);
                    persistPrefs();
                    rebuildFirewall(); // off clears the IP bans, on re-applies them
                }
                ImGui::SameLine(0, 28);
                if (ActionButton("Edit blocklist...")) {
                    showBlocklist = true;
                    focusBlocklist = true;
                }
                ImGui::Indent();
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextUnformatted("System-wide, at the DNS layer - every browser and every app.");
                ImGui::PopStyleColor();
                ImGui::Unindent();
            } else {
                ImGui::TextColored(theme::Warn(), "Blocker unavailable: %s",
                                    blkErr.c_str());
            }

            ImGui::Spacing();
            if (monOk) {
                ImGui::Checkbox("Auto-block high-traffic processes", &autoBlockEnabled);
                ImGui::Indent();
                ImGui::SetNextItemWidth(90 * dpiScale);
                ImGui::InputDouble("##autoBlockThreshold", &autoBlockThresholdValue, 0.0, 0.0, "%.2f");
                if (autoBlockThresholdValue < 0.01) autoBlockThresholdValue = 0.01;
                ImGui::SameLine();
                ImGui::SetNextItemWidth(100 * dpiScale);
                PushComboColors();
                ImGui::Combo("threshold##autoBlockUnit", &autoBlockUnitIdx, kUnitLabels, 3);
            PopComboColors();
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextUnformatted("Anything above this gets cut off. Games, calls and browsers are\n"
                                        "never auto-blocked. Starts off every launch.");
                ImGui::PopStyleColor();
                ImGui::Unindent();
            }

            heading("NETVIS");
            if (ImGui::Checkbox("Run in background when window is closed", &runInBackground))
                persistPrefs();
            if (ImGui::Checkbox("System notification on every alert", &notifyOnAlert))
                persistPrefs();
            if (ImGui::Checkbox("Run when Windows starts", &runOnStartup)) {
                startup::SetEnabled(runOnStartup);
                runOnStartup = startup::IsEnabled(); // reflect what actually took effect
                settings.runOnStartup = runOnStartup; // remember the intent, not just the task
                persistPrefs();
            }

            heading("APPEARANCE");
            {
                auto seg = [&](const char* label, theme::Mode m) {
                    bool active = theme::Current() == m;
                    ImGui::PushStyleColor(ImGuiCol_Button, active ? theme::TabActive() : theme::TabIdle());
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                                           active ? theme::TabActiveHover() : theme::TabIdleHover());
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active ? theme::TabActive() : theme::TabIdleHover());
                    if (active) ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
                    if (ImGui::Button(label, ImVec2(88 * dpiScale, 0))) {
                        theme::Apply(m);
                        settings.themeMode = (int)m;
                        persistPrefs();
                        // Style sizes are scaled at startup for this
                        // monitor's DPI; re-applying the palette resets them
                        // to the unscaled defaults, so scale again.
                        if (dpiScale > 1.01f) ImGui::GetStyle().ScaleAllSizes(dpiScale);
                    }
                    ImGui::PopStyleColor(active ? 4 : 3);
                };
                seg("Auto", theme::Mode::Auto);
                ImGui::SameLine(0, 8);
                seg("Light", theme::Mode::Light);
                ImGui::SameLine(0, 8);
                seg("Dark", theme::Mode::Dark);
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextUnformatted("Auto follows the Windows light/dark setting.");
                ImGui::PopStyleColor();
            }

            heading("LICENSE");
            {
                int days = license::LastDaysLeft();
                if (license::LastWasTrial()) {
                    ImGui::Text("Free trial - %d day%s left", days, days == 1 ? "" : "s");
                    ImGui::SameLine(0, 20);
                    if (NeutralButton("Buy a license...")) {
                        showUpgrade = true;
                        {
                            std::lock_guard<std::mutex> lock(keyOp->mu);
                            keyOp->error.clear();
                        }
                        keyOp->ok.store(false);
                    }
                } else if (days >= 0) {
                    ImGui::Text("Licensed - %d day%s remaining", days, days == 1 ? "" : "s");
                } else {
                    ImGui::TextUnformatted("Licensed");
                }
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextUnformatted("This computer only. Traffic data never leaves your PC.");
                ImGui::PopStyleColor();
            }

            ImGui::End();
        } else {
            // ================= PROCESSES =================
            bool statusOk = monOk && blkOk;
            ImVec4 statusColor = statusOk ? theme::Ok()
                                          : theme::Warn();
            ImGui::PushStyleColor(ImGuiCol_Text, statusColor);
            CopyableText("status", uiStatus);
            ImGui::PopStyleColor();

            // The blocked counter only appears when blocking is actually on -
            // a permanent "0 malicious sites blocked" reads like the feature
            // is broken rather than switched off. Count and label sit on one
            // baseline instead of the count hanging above the words.
            if (blkOk && blk.Enabled()) {
                ImGui::Spacing();
                ImGui::AlignTextToFramePadding();
                ImGui::PushFont(g_fontBold, 0.0f);
                ImGui::TextColored(theme::Accent(), "%lld",
                                    (long long)blk.BlockedCount());
                ImGui::PopFont();
                ImGui::SameLine(0, 8);
                ImGui::AlignTextToFramePadding();
                ImGui::TextUnformatted("malicious sites blocked");
            }

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
            swatch(theme::GraphDownLine());
            ImGui::SameLine(0, 6);
            ImGui::TextColored(theme::GraphDownText(), "Download %s", FormatRate(graph.CurrentDown()).c_str());
            ImGui::SameLine(0, 28);
            swatch(theme::GraphUpLine());
            ImGui::SameLine(0, 6);
            ImGui::TextColored(theme::GraphUpText(), "Upload %s", FormatRate(graph.CurrentUp()).c_str());
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
                    // Blue with a white label, matching the other action
                    // buttons - this is the one users click most.
                    ImGui::PushStyleColor(ImGuiCol_Button, theme::ActionButton());
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::ActionButtonHover());
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::ActionButtonDown());
                    ImGui::PushStyleColor(ImGuiCol_Text, theme::OnAccent());
                    bool blockClicked = ImGui::SmallButton(blocked ? "Unblock" : "Block");
                    ImGui::PopStyleColor(4);
                    if (blockClicked) {
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
            PushComboColors();
            ImGui::Combo("##dnunit", &limDownUnit, kUnitLabels, 3);
            PopComboColors();
            ImGui::EndDisabled();

            ImGui::Checkbox("Limit upload", &limUpOn);
            ImGui::SameLine(valueColX);
            ImGui::BeginDisabled(!limUpOn);
            ImGui::SetNextItemWidth(valW);
            ImGui::InputDouble("##upval", &limUpVal, 0.0, 0.0, "%.2f");
            if (limUpVal < 0.01) limUpVal = 0.01;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(rateUnitW);
            PushComboColors();
            ImGui::Combo("##upunit", &limUpUnit, kUnitLabels, 3);
            PopComboColors();
            ImGui::EndDisabled();

            ImGui::Checkbox("For a set time", &limDurOn);
            ImGui::SameLine(valueColX);
            ImGui::BeginDisabled(!limDurOn);
            ImGui::SetNextItemWidth(durValW);
            // InputInt draws its own -/+ buttons using ImGuiCol_Button, so
            // they inherit the global default unless it's pushed here. That
            // is why they stayed dark while everything around them turned
            // light.
            PushComboColors();
            ImGui::PushStyleColor(ImGuiCol_Text, theme::NeutralText());
            ImGui::InputInt("##durval", &limDurValue);
            ImGui::PopStyleColor();
            PopComboColors();
            if (limDurValue < 1) limDurValue = 1;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(durUnitW);
            PushComboColors();
            ImGui::Combo("##durunit", &limDurUnit, kDurationLabels, 3);
            PopComboColors();
            ImGui::EndDisabled();

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            bool nothing = !limDownOn && !limUpOn;
            ImGui::BeginDisabled(nothing);
            if (NeutralButton("Apply")) {
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
            if (NeutralButton("Cancel")) ImGui::CloseCurrentPopup();
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
            if (NeutralButton("Close")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }

            ImGui::End();
        } // end of the Processes tab

        // --- buy / redeem a license while the trial is running ---
        if (showUpgrade) {
            ImGui::SetNextWindowSize(ImVec2(460 * dpiScale, 0), ImGuiCond_Appearing);
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                                     ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            if (ImGui::Begin("Buy a license", &showUpgrade,
                              ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize)) {
                bool busy = keyOp->busy.load();

                if (keyOp->ok.load()) {
                    // Take the confirmation down on its own. Leaving a
                    // "thanks" dialog for the user to dismiss, next to a
                    // countdown that should no longer exist, is exactly the
                    // leftover state this was meant to clear.
                    keyOp->ok.store(false);
                    showUpgrade = false;
                    upgradeKeyBuf[0] = '\0';
                    licenseToast = "License activated - thanks. netvis is yours for the next 6 months.";
                    licenseToastUntil = ::GetTickCount64() + 15000;
                } else {
                    int days = license::LastDaysLeft();
                    if (days >= 0)
                        ImGui::TextWrapped("Your trial has %d day%s left. A license is $25 and covers "
                                            "this computer for 6 months.", days, days == 1 ? "" : "s");
                    else
                        ImGui::TextWrapped("A license is $25 and covers this computer for 6 months.");

                    ImGui::Spacing();
                    ImGui::BeginDisabled(busy);
                    if (NeutralButton("Buy at netvis.cc", ImVec2(180 * dpiScale, 0)))
                        OpenInBrowser("https://netvis.cc/buy");
                    ImGui::EndDisabled();

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();
                    ImGui::TextUnformatted("Already have your key? Paste it here:");
                    ImGui::Spacing();

                    ImGui::SetNextItemWidth(-1);
                    ImGui::BeginDisabled(busy);
                    bool entered = ImGui::InputTextWithHint("##upgradekey", "license key", upgradeKeyBuf,
                                                             sizeof(upgradeKeyBuf),
                                                             ImGuiInputTextFlags_EnterReturnsTrue |
                                                                 ImGuiInputTextFlags_CharsUppercase);
                    ImGui::EndDisabled();

                    std::string key = license::Normalize(upgradeKeyBuf);
                    bool complete = license::PlausibleKey(key);

                    {
                        std::lock_guard<std::mutex> lock(keyOp->mu);
                        if (!keyOp->error.empty()) {
                            ImGui::Spacing();
                            ImGui::TextColored(theme::Bad(), "%s",
                                                keyOp->error.c_str());
                        }
                    }

                    ImGui::Spacing();
                    ImGui::BeginDisabled(busy || !complete);
                    if (NeutralButton("Activate", ImVec2(120 * dpiScale, 0)) ||
                        (entered && complete && !busy)) {
                        keyOp->busy.store(true);
                        {
                            std::lock_guard<std::mutex> lock(keyOp->mu);
                            keyOp->error.clear();
                        }
                        // Off the UI thread: activation is two network round
                        // trips, and the app is running - freezing the whole
                        // window for a couple of seconds would look broken.
                        std::thread([keyOp, key] {
                            std::string err;
                            bool ok = license::Activate(key, &err);
                            {
                                std::lock_guard<std::mutex> lock(keyOp->mu);
                                keyOp->error = ok ? "" : err;
                            }
                            keyOp->ok.store(ok);
                            keyOp->busy.store(false);
                        }).detach();
                    }
                    ImGui::EndDisabled();
                    if (busy) {
                        ImGui::SameLine();
                        ImGui::TextUnformatted("Activating...");
                    }
                }
            }
            ImGui::End();
        }

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
                    if (ActionButton(blocked ? "Unblock" : "Block")) {
                        std::string err = blocked ? pidMgr.Unblock(app->pid) : pidMgr.Block(app->pid);
                        if (!err.empty()) uiStatus = "Block/unblock failed: " + err;
                    }
                    ImGui::SameLine();
                    if (ImGui::Button(pidMgr.IsLimited(app->pid) ? "Change limit..." : "Limit traffic...")) {
                        openLimitFor(app->pid, app->name);
                    }
                    ImGui::SameLine();
                    if (ActionButton("View connections...")) {
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
                if (NeutralButton("Clear")) alerts.Clear();
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
                        case AlertKind::NewListener: color = theme::Warn(); break;
                        case AlertKind::DnsChanged: color = ImVec4(0.95f, 0.75f, 0.30f, 1.0f); break;
                        case AlertKind::AutoBlocked: color = theme::Bad(); break;
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

                // The whole list does nothing while the master switch is off,
                // which is the usual reason "I added a domain but it still
                // loads". Say so, loudly, right where they're editing.
                if (blkOk && !blk.Enabled()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, theme::Warn());
                    ImGui::TextWrapped("Blocking is currently OFF. These domains won't be blocked until you "
                                        "turn on \"Block trackers & malicious domains\" in Settings.");
                    ImGui::PopStyleColor();
                    ImGui::SameLine();
                    if (ActionButton("Turn on")) {
                        blk.SetEnabled(true);
                        persistPrefs();
                        rebuildFirewall(); // re-apply the IP bans now blocking is on
                    }
                    ImGui::Spacing();
                }

                // A domain already open in a browser keeps its live connection
                // until the tab is reloaded - blocking stops new lookups and
                // new connections at once (the DNS cache is flushed on every
                // change), but it can't tear down a page that's already up.
                ImGui::PushStyleColor(ImGuiCol_Text, theme::Faint());
                ImGui::TextWrapped("Changes apply immediately. If a site is already open, reload the tab "
                                    "(Ctrl+Shift+R) - an existing connection stays up until then.");
                ImGui::PopStyleColor();
                ImGui::Spacing();

                if (ImGui::Checkbox("Use built-in malicious-domain database", &useDefaultBlocklist)) {
                    applyBlocklist();
                    persistPrefs();
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Merge netvis's bundled list of ~100k known ad/tracker/malware\n"
                                       "domains with your own entries below.");

                ImGui::Spacing();
                if (NeutralButton("Import from text file...")) {
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
                        rebuildFirewall(); // pick up any bare-IP entries in the import
                        blocklistStatus = "Imported " + std::to_string(added) + " new domain(s).";
                    }
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("One domain per line; lines starting with # are ignored.\n"
                                       "hosts-file lines like \"0.0.0.0 ads.example.com\" also work.");

                ImGui::Spacing();
                ImGui::SetNextItemWidth(-140);
                bool addNow = ImGui::InputTextWithHint("##newdomain", "add a domain or IP, e.g. ads.example.com or 203.0.113.5",
                                                        newDomainBuf, sizeof(newDomainBuf),
                                                        ImGuiInputTextFlags_EnterReturnsTrue);
                ImGui::SameLine();
                if (NeutralButton("Add domain") || addNow) {
                    std::string d = ToLowerAscii(newDomainBuf);
                    // trim spaces
                    while (!d.empty() && (d.front() == ' ' || d.front() == '\t')) d.erase(d.begin());
                    while (!d.empty() && (d.back() == ' ' || d.back() == '\t' || d.back() == '\r')) d.pop_back();
                    if (!d.empty() &&
                        std::find(userBlocklist.begin(), userBlocklist.end(), d) == userBlocklist.end()) {
                        // An entry is either a bare address or a domain. Both
                        // end up banned at the IP level and have their live
                        // connections torn down; a domain additionally gets
                        // DNS-blocked so its future (rotating) IPs never
                        // resolve either. rebuildFirewall() reads the ban set
                        // from userBlocklist (IP entries) + runtimeBannedIPs,
                        // so we only have to feed those.
                        std::vector<uint32_t> ipsToKill;

                        if (connkill::IsIPLiteral(d)) {
                            // The literal itself is banned once it's in the
                            // list; resolve it (a no-op for text->v4) so the
                            // TCP reset below has something to match.
                            connkill::ResolveHostIPv4(d, ipsToKill);
                        } else {
                            // Resolve BEFORE blocking - once listed, netvis
                            // NXDOMAINs its own lookup. Capture www. too, and
                            // remember the IPs under this entry so removing it
                            // later un-bans exactly them.
                            connkill::ResolveHostIPv4(d, ipsToKill);
                            connkill::ResolveHostIPv4("www." + d, ipsToKill);
                            auto& bucket = runtimeBannedIPs[d];
                            for (uint32_t ip : ipsToKill) {
                                std::string s = connkill::IPv4ToString(ip);
                                if (!s.empty()) bucket.push_back(s);
                            }
                        }

                        userBlocklist.push_back(d);
                        applyBlocklist();     // DNS block (domains) + persist
                        rebuildFirewall();    // ban every collected IP at the firewall

                        // Close what's open right now: RST the IPv4 TCP flows
                        // immediately; the firewall handles the rest (UDP/QUIC,
                        // IPv6, and any new attempt).
                        int killed = connkill::ResetConnectionsTo(ipsToKill);
                        blocklistStatus = "Banned " + d;
                        if (killed > 0) blocklistStatus += " and closed " + std::to_string(killed) + " connection(s)";
                        blocklistStatus += ".";
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
                        if (NeutralButton("Remove")) removeIdx = i;
                        ImGui::PopID();
                    }
                    if (userBlocklist.empty()) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextDisabled("(none yet - add or import domains above)");
                    }
                    ImGui::EndTable();
                    if (removeIdx >= 0) {
                        // Forget this entry's remembered addresses too, so its
                        // firewall rules actually lift - whether it was a bare
                        // IP (dropped from userBlocklist below) or a domain
                        // (whose resolved IPs live in runtimeBannedIPs).
                        const std::string& gone = userBlocklist[removeIdx];
                        runtimeBannedIPs.erase(gone);
                        userBlocklist.erase(userBlocklist.begin() + removeIdx);
                        applyBlocklist();
                        rebuildFirewall();
                    }
                }
            }
            ImGui::End();
        }

        ImGui::Render();
        float clear_color[4];
    theme::ClearColor(clear_color);
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
    settings.runOnStartup = runOnStartup;
    settings.themeMode = (int)theme::Current();
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
