// GlassWire-style rolling bandwidth graph: a filled area for download and
// a line for upload, auto-scaled to the busiest sample currently in view.
// Drawn directly with ImDrawList rather than ImGui::PlotLines so download
// and upload can be layered with different fill styles, and so we can
// draw our own labeled Y-axis gridlines.
#pragma once
#include <algorithm>
#include <cstdio>
#include <deque>
#include <string>
#include "imgui.h"

struct TrafficSample {
    double down = 0, up = 0; // bytes/sec
};

namespace trafficgraph_detail {

// Compact "123 KB/s" style formatter - kept local to this header so it has
// no dependency on the app's own FormatRate() in main.cpp.
inline std::string FormatRateShort(double bytesPerSec) {
    if (bytesPerSec < 1024.0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.0f B/s", bytesPerSec);
        return buf;
    }
    static const char* units = "KMGTPE";
    double v = bytesPerSec / 1024.0;
    int exp = 0;
    while (v >= 1024.0) {
        v /= 1024.0;
        exp++;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f %cB/s", v, units[exp]);
    return buf;
}

} // namespace trafficgraph_detail

class TrafficGraph {
public:
    explicit TrafficGraph(size_t capacity) : capacity_(capacity) {}

    void Push(double down, double up) {
        samples_.push_back({down, up});
        while (samples_.size() > capacity_) samples_.pop_front();
    }

    // Changes the rolling window length (in samples - one per Push, which
    // the caller drives at 1/sec, so this is effectively seconds of
    // history). Shrinking trims from the front; growing just means it
    // takes longer to fill back up to the new width.
    void SetCapacity(size_t newCapacity) {
        if (newCapacity == capacity_ || newCapacity == 0) return;
        capacity_ = newCapacity;
        while (samples_.size() > capacity_) samples_.pop_front();
    }
    size_t Capacity() const { return capacity_; }

    // `size` is the total footprint (including the Y-axis label gutter on
    // the left) - matches what the caller reserves via ImGui layout.
    void Draw(ImVec2 size) const {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 origin = ImGui::GetCursorScreenPos();

        const float labelGutter = 58.0f;
        const float rounding = 8.0f;
        ImVec2 p0 = ImVec2(origin.x + labelGutter, origin.y);
        ImVec2 p1 = ImVec2(origin.x + size.x, origin.y + size.y);
        float chartW = p1.x - p0.x;

        dl->AddRectFilled(p0, p1, IM_COL32(20, 22, 27, 255), rounding);

        const double floor = 8.0 * 1024.0; // 8 KB/s, keeps an idle graph from jittering at full height
        double maxVal = floor;
        for (const auto& s : samples_) {
            maxVal = std::max({maxVal, s.down, s.up});
        }

        // Y-axis gridlines with speed labels - capped at 4 labels total
        // (0%, 33%, 67%, 100% of the current max) so they have room to
        // breathe at this graph height instead of overlapping each other.
        const int kDivisions = 3;
        const ImU32 labelColor = IM_COL32(150, 158, 172, 255);
        for (int i = 0; i <= kDivisions; i++) {
            float frac = (float)i / (float)kDivisions;
            float y = p1.y - frac * size.y;
            if (i > 0 && i < kDivisions) {
                dl->AddLine(ImVec2(p0.x + 1, y), ImVec2(p1.x - 1, y), IM_COL32(255, 255, 255, 12), 1.0f);
            } else if (i == kDivisions) {
                dl->AddLine(ImVec2(p0.x + 1, y), ImVec2(p1.x - 1, y), IM_COL32(255, 255, 255, 22), 1.0f);
            }
            std::string label = trafficgraph_detail::FormatRateShort(maxVal * frac);
            ImVec2 textSize = ImGui::CalcTextSize(label.c_str());
            float ty = y - textSize.y * 0.5f;
            ty = std::max(origin.y, std::min(ty, origin.y + size.y - textSize.y));
            dl->AddText(ImVec2(origin.x + labelGutter - 8 - textSize.x, ty), labelColor, label.c_str());
        }

        if (!samples_.empty()) {
            int n = (int)samples_.size();
            float stepX = chartW / std::max(1, (int)capacity_ - 1);
            float xOffset = (float)(capacity_ - n) * stepX; // right-align when buffer isn't full yet

            // Filled download area.
            for (int i = 0; i < n - 1; i++) {
                float x0 = p0.x + xOffset + i * stepX;
                float x1 = p0.x + xOffset + (i + 1) * stepX;
                float h0 = (float)(samples_[i].down / maxVal) * (size.y - 4);
                float h1 = (float)(samples_[i + 1].down / maxVal) * (size.y - 4);
                dl->AddQuadFilled(ImVec2(x0, p1.y - 2), ImVec2(x0, p1.y - 2 - h0), ImVec2(x1, p1.y - 2 - h1),
                                   ImVec2(x1, p1.y - 2), IM_COL32(0x35, 0xc7, 0x5f, 0x90));
            }
            // Upload line.
            for (int i = 0; i < n - 1; i++) {
                float x0 = p0.x + xOffset + i * stepX;
                float x1 = p0.x + xOffset + (i + 1) * stepX;
                float y0 = p1.y - 2 - (float)(samples_[i].up / maxVal) * (size.y - 4);
                float y1 = p1.y - 2 - (float)(samples_[i + 1].up / maxVal) * (size.y - 4);
                dl->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(0x66, 0x96, 0xfa, 0xFF), 2.0f);
            }
        }

        dl->AddRect(p0, p1, IM_COL32(55, 60, 70, 255), rounding);
        ImGui::Dummy(size);
    }

private:
    size_t capacity_;
    std::deque<TrafficSample> samples_;
};
