#include "winicon.h"
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")

namespace {

std::wstring WidenUtf8(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring w(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}

} // namespace

IconPixels ExtractIconRGBA(const std::string& exePath) {
    IconPixels out;
    std::wstring wpath = WidenUtf8(exePath);
    if (wpath.empty()) return out;

    SHFILEINFOW sfi = {};
    if (!SHGetFileInfoW(wpath.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON))
        return out;
    HICON hIcon = sfi.hIcon;
    if (!hIcon) return out;

    ICONINFO info = {};
    if (!GetIconInfo(hIcon, &info)) { DestroyIcon(hIcon); return out; }

    BITMAP bmp = {};
    if (!GetObjectW(info.hbmColor, sizeof(bmp), &bmp)) {
        if (info.hbmColor) DeleteObject(info.hbmColor);
        if (info.hbmMask) DeleteObject(info.hbmMask);
        DestroyIcon(hIcon);
        return out;
    }

    int w = bmp.bmWidth, h = bmp.bmHeight;
    std::vector<uint8_t> bgra(size_t(w) * h * 4);

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h; // negative = top-down
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    HDC hdc = GetDC(nullptr);
    int got = GetDIBits(hdc, info.hbmColor, 0, h, bgra.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    ReleaseDC(nullptr, hdc);

    if (info.hbmColor) DeleteObject(info.hbmColor);
    if (info.hbmMask) DeleteObject(info.hbmMask);
    DestroyIcon(hIcon);
    if (got == 0) return out;

    // Many small icons have no real alpha channel (all zero) - in that
    // case treat as fully opaque rather than rendering invisible.
    bool hasAlpha = false;
    for (size_t i = 3; i < bgra.size(); i += 4) {
        if (bgra[i] != 0) { hasAlpha = true; break; }
    }

    out.rgba.resize(bgra.size());
    for (int i = 0; i < w * h; i++) {
        uint8_t b = bgra[i * 4 + 0], g = bgra[i * 4 + 1], r = bgra[i * 4 + 2], a = bgra[i * 4 + 3];
        out.rgba[i * 4 + 0] = r;
        out.rgba[i * 4 + 1] = g;
        out.rgba[i * 4 + 2] = b;
        out.rgba[i * 4 + 3] = hasAlpha ? a : 255;
    }
    out.width = w;
    out.height = h;
    out.ok = true;
    return out;
}
