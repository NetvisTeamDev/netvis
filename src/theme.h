// Light / dark / auto theming, in one place.
//
// Every colour the UI draws by hand goes through here rather than being
// written inline, because the alternative is what this file replaced: a
// dark grey repeated in a dozen call sites, all of which become invisible
// the moment the background turns white.
//
// Light isn't the dark palette inverted. Text on white needs more contrast
// than text on near-black to read as solid rather than washed out, so the
// light values are deliberately darker than a mechanical inversion would
// give - and the greens and blues are pulled down too, since a colour that
// glows nicely on black turns to pastel on white.
#pragma once
#include <windows.h>
#include "imgui.h"

namespace theme {

enum class Mode { Auto = 0, Light = 1, Dark = 2 };

namespace detail {
inline Mode g_mode = Mode::Dark;
inline bool g_light = false;
} // namespace detail

// What Windows itself is set to. Falls back to dark if the value is
// missing, which is also what netvis looks best in.
inline bool SystemPrefersLight() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0,
                      KEY_READ, &key) != ERROR_SUCCESS)
        return false;
    DWORD value = 0, size = sizeof(value), type = 0;
    LONG rc = RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type, (LPBYTE)&value, &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_DWORD && value != 0;
}

inline bool IsLight() { return detail::g_light; }
inline Mode Current() { return detail::g_mode; }

// ---- palette -------------------------------------------------------------

// Secondary text: labels, hints, units. The single most important colour to
// get right, because it's used everywhere and it's the first thing to
// disappear when the background flips.
inline ImVec4 Dim() {
    return IsLight() ? ImVec4(0.192f, 0.212f, 0.247f, 1.0f) : ImVec4(0.557f, 0.584f, 0.627f, 1.0f);
}
// Tertiary: explanatory lines under a setting. Still has to be readable.
inline ImVec4 Faint() {
    return IsLight() ? ImVec4(0.298f, 0.322f, 0.361f, 1.0f) : ImVec4(0.45f, 0.47f, 0.51f, 1.0f);
}
inline ImVec4 Ok() {
    return IsLight() ? ImVec4(0.11f, 0.51f, 0.26f, 1.0f) : ImVec4(0.35f, 0.78f, 0.45f, 1.0f);
}
inline ImVec4 Warn() {
    return IsLight() ? ImVec4(0.72f, 0.42f, 0.05f, 1.0f) : ImVec4(0.95f, 0.65f, 0.35f, 1.0f);
}
inline ImVec4 Bad() {
    return IsLight() ? ImVec4(0.75f, 0.15f, 0.20f, 1.0f) : ImVec4(0.90f, 0.35f, 0.40f, 1.0f);
}
inline ImVec4 Accent() {
    return IsLight() ? ImVec4(0.13f, 0.36f, 0.75f, 1.0f) : ImVec4(0.259f, 0.588f, 0.980f, 1.0f);
}

// Graph colours. Down/Up keep their identity across themes but drop in
// brightness for light, where a neon green on white is unreadable.
inline ImU32 GraphDownLine() { return IsLight() ? IM_COL32(0x1a, 0x9a, 0x4a, 0xFF) : IM_COL32(0x46, 0xe0, 0x76, 0xFF); }
inline ImU32 GraphUpLine()   { return IsLight() ? IM_COL32(0x2d, 0x63, 0xc9, 0xFF) : IM_COL32(0x7f, 0xa8, 0xff, 0xFF); }
inline ImU32 GraphDownFill() { return IsLight() ? IM_COL32(0x2a, 0xb0, 0x5c, 0x55) : IM_COL32(0x35, 0xc7, 0x5f, 0xB0); }
inline ImU32 GraphUpFill()   { return IsLight() ? IM_COL32(0x4c, 0x8b, 0xf5, 0x40) : IM_COL32(0x66, 0x96, 0xfa, 0x80); }
inline ImU32 GraphDownClear(){ return IsLight() ? IM_COL32(0x2a, 0xb0, 0x5c, 0x00) : IM_COL32(0x35, 0xc7, 0x5f, 0x00); }
inline ImU32 GraphUpClear()  { return IsLight() ? IM_COL32(0x4c, 0x8b, 0xf5, 0x00) : IM_COL32(0x66, 0x96, 0xfa, 0x00); }
inline ImU32 GraphBg()       { return IsLight() ? IM_COL32(247, 248, 250, 255) : IM_COL32(18, 20, 25, 255); }
inline ImU32 GraphBorder()   { return IsLight() ? IM_COL32(205, 210, 218, 255) : IM_COL32(55, 60, 70, 255); }
inline ImU32 GraphGrid(bool mid) {
    if (IsLight()) return mid ? IM_COL32(0, 0, 0, 34) : IM_COL32(0, 0, 0, 16);
    return mid ? IM_COL32(255, 255, 255, 26) : IM_COL32(255, 255, 255, 12);
}
inline ImU32 GraphCrosshair() { return IsLight() ? IM_COL32(0, 0, 0, 75) : IM_COL32(255, 255, 255, 60); }
inline ImU32 GraphHeadGlow()  { return IsLight() ? IM_COL32(0x1a, 0x9a, 0x4a, 0x40) : IM_COL32(0x46, 0xe0, 0x76, 0x50); }
inline ImU32 GraphHeadDot()   { return IsLight() ? IM_COL32(0x0f, 0x6b, 0x33, 0xFF) : IM_COL32(0xbe, 0xff, 0xd6, 0xFF); }
inline ImVec4 GraphDownText() { return IsLight() ? ImVec4(0.06f, 0.45f, 0.22f, 1.0f) : ImVec4(0.38f, 0.90f, 0.56f, 1.0f); }
inline ImVec4 GraphUpText()   { return IsLight() ? ImVec4(0.13f, 0.33f, 0.70f, 1.0f) : ImVec4(0.56f, 0.70f, 1.00f, 1.0f); }

// What the swap chain is cleared to, so the window matches the theme
// before ImGui draws anything on top.
inline void ClearColor(float out[4]) {
    if (IsLight()) { out[0] = 0.965f; out[1] = 0.969f; out[2] = 0.976f; }
    else           { out[0] = 0.06f;  out[1] = 0.06f;  out[2] = 0.08f;  }
    out[3] = 1.0f;
}

// Tab strip: the unselected tab has to sit visibly against the window
// background in both themes.
inline ImVec4 TabIdle()        { return IsLight() ? ImVec4(0.88f, 0.89f, 0.91f, 1.0f) : ImVec4(0.13f, 0.14f, 0.17f, 1.0f); }
inline ImVec4 TabIdleHover()   { return IsLight() ? ImVec4(0.83f, 0.85f, 0.88f, 1.0f) : ImVec4(0.18f, 0.20f, 0.24f, 1.0f); }
inline ImVec4 TabActive()      { return IsLight() ? ImVec4(0.18f, 0.44f, 0.82f, 1.0f) : ImVec4(0.24f, 0.46f, 0.85f, 1.0f); }
inline ImVec4 TabActiveHover() { return IsLight() ? ImVec4(0.22f, 0.50f, 0.90f, 1.0f) : ImVec4(0.28f, 0.52f, 0.92f, 1.0f); }
inline ImVec4 BuyButton()      { return IsLight() ? ImVec4(0.11f, 0.48f, 0.26f, 1.0f) : ImVec4(0.20f, 0.55f, 0.30f, 1.0f); }
inline ImVec4 BuyButtonHover() { return IsLight() ? ImVec4(0.14f, 0.56f, 0.31f, 1.0f) : ImVec4(0.24f, 0.66f, 0.36f, 1.0f); }
inline ImVec4 AlertButton()    { return IsLight() ? ImVec4(0.78f, 0.40f, 0.12f, 1.0f) : ImVec4(0.85f, 0.45f, 0.20f, 1.0f); }

// Action buttons - the ones that DO something to your traffic, like Block
// or opening the blocklist editor. Blue with white text in both themes, so
// they read as buttons rather than as grey chrome, and so the label never
// ends up dark-on-dark.
inline ImVec4 ActionButton()      { return IsLight() ? ImVec4(0.153f, 0.412f, 0.816f, 1.0f) : ImVec4(0.226f, 0.494f, 0.878f, 1.0f); }
inline ImVec4 ActionButtonHover() { return IsLight() ? ImVec4(0.204f, 0.478f, 0.882f, 1.0f) : ImVec4(0.290f, 0.573f, 0.945f, 1.0f); }
inline ImVec4 ActionButtonDown()  { return IsLight() ? ImVec4(0.118f, 0.345f, 0.706f, 1.0f) : ImVec4(0.180f, 0.420f, 0.780f, 1.0f); }

// Ordinary buttons: Close, Cancel, Apply, the arrow on a dropdown. These
// used to inherit whatever ImGuiCol_Button happened to be, which is how
// they ended up dark-on-dark in light mode. Stated explicitly here and
// pushed at each call site, so they cannot drift again.
inline ImVec4 NeutralButton()      { return IsLight() ? ImVec4(0.855f, 0.898f, 0.965f, 1.0f) : ImVec4(0.130f, 0.145f, 0.173f, 1.0f); }
inline ImVec4 NeutralButtonHover() { return IsLight() ? ImVec4(0.780f, 0.851f, 0.949f, 1.0f) : ImVec4(0.184f, 0.204f, 0.243f, 1.0f); }
inline ImVec4 NeutralButtonDown()  { return IsLight() ? ImVec4(0.694f, 0.796f, 0.925f, 1.0f) : ImVec4(0.220f, 0.243f, 0.290f, 1.0f); }
inline ImVec4 NeutralText()        { return IsLight() ? ImVec4(0.043f, 0.051f, 0.071f, 1.0f) : ImVec4(0.961f, 0.965f, 0.973f, 1.0f); }

// Text drawn on top of a saturated button (active tab, Buy, Alerts).
// White in both themes, because those buttons stay strongly coloured and
// the global text colour is near-black in light mode.
inline ImVec4 OnAccent() { return ImVec4(1.0f, 1.0f, 1.0f, 1.0f); }

// Applies the whole ImGui style for the resolved theme. Declared here,
// defined in main.cpp next to the rest of the styling.
void Apply(Mode m);

} // namespace theme
