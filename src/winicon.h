// Extracts a process's exe icon as raw top-down RGBA pixels (straight
// alpha), suitable for uploading straight into a GPU texture. Pure Win32:
// SHGetFileInfoW to get an HICON, GetIconInfo + GetDIBits to pull pixels.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct IconPixels {
    bool ok = false;
    int width = 0;
    int height = 0;
    std::vector<uint8_t> rgba; // width*height*4 bytes, row-major, top-down
};

IconPixels ExtractIconRGBA(const std::string& exePath);
