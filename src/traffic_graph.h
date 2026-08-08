// GlassWire-style rolling bandwidth graph. Download and upload are each
// drawn as a gradient-filled area (solid at the line, fading to nothing at
// the baseline) with a crisp curve on top, over labeled round-number
// Y-axis gridlines. Hovering shows a crosshair and the exact values at
// that moment; the current rates and the visible peak are called out on
// the graph itself. Everything is drawn with ImDrawList rather than
// ImGui::PlotLines so we control every pixel of it.
#pragma once
#include <algorithm>
#include <cmath>
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

// Rounds an axis maximum up to a "nice" 1/2/5 x 10^n value, so gridlines
// land on clean numbers (1, 2, 5, 10 MB/s) and the axis doesn't twitch to
// a new odd maximum every single second as the busiest sample changes.
inline double NiceCeil(double v) {
    if (v <= 0) return 1;
    double pow10 = std::pow(10.0, std::floor(std::log10(v)));
    double frac = v / pow10;
    double niceFrac = frac <= 1.0 ? 1.0 : frac <= 2.0 ? 2.0 : frac <= 5.0 ? 5.0 : 10.0;
    return niceFrac * pow10;
}

} // namespace trafficgraph_detail

class TrafficGraph {
public:
    explicit TrafficGraph(size_t capacity) : capacity_(capacity) {}

    void Push(double down, double up) {
        samples_.push_back({down, up});
        while (samples_.size() > capacity_) samples_.pop_front();
    }

    void SetCapacity(size_t newCapacity) {
        if (newCapacity == capacity_ || newCapacity == 0) return;
        capacity_ = newCapacity;
        while (samples_.size() > capacity_) samples_.pop_front();
    }
    size_t Capacity() const { return capacity_; }

    // `size` is the total footprint (including the Y-axis label gutter on
    // the left) - matches what the caller reserves via ImGui layout.
    void Draw(ImVec2 size) const {
        using trafficgraph_detail::FormatRateShort;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 origin = ImGui::GetCursorScreenPos();

        const double floorVal = 8.0 * 1024.0; // 8 KB/s - stops an idle graph filling to full height
        double rawMax = floorVal;
        for (const auto& s : samples_) rawMax = std::max({rawMax, s.down, s.up});
        double maxVal = trafficgraph_detail::NiceCeil(rawMax);

        // No Y-axis scale on the left - the numbers overlapped at higher
        // DPI and the in-graph Down/Up readout carries the same info more
        // cleanly. The chart uses the full width, with a small left inset.
        const float rounding = 8.0f;
        const float pad = 3.0f; // keeps the fill off the top/bottom rounded corners
        ImVec2 p0 = ImVec2(origin.x, origin.y);
        ImVec2 p1 = ImVec2(origin.x + size.x, origin.y + size.y);
        float chartW = p1.x - p0.x;
        float baseY = p1.y - pad;
        float plotH = size.y - pad * 2;

        dl->AddRectFilled(p0, p1, IM_COL32(18, 20, 25, 255), rounding);

        // Unlabeled gridlines for reference (25/50/75/100% of the nice max).
        for (int i = 1; i <= 4; i++) {
            float y = baseY - (float)i / 4.0f * plotH;
            ImU32 lineCol = (i == 4) ? IM_COL32(255, 255, 255, 26) : IM_COL32(255, 255, 255, 12);
            dl->AddLine(ImVec2(p0.x + 1, y), ImVec2(p1.x - 1, y), lineCol, 1.0f);
        }

        int n = (int)samples_.size();
        float stepX = chartW / std::max(1, (int)capacity_ - 1);
        float xOffset = (float)(capacity_ - n) * stepX; // right-align while the buffer fills

        auto sampleX = [&](int i) { return p0.x + xOffset + i * stepX; };
        auto downY = [&](int i) { return baseY - (float)(samples_[i].down / maxVal) * plotH; };
        auto upY = [&](int i) { return baseY - (float)(samples_[i].up / maxVal) * plotH; };

        // Gradient-filled areas, rendered as vertical strips so the fill
        // can fade from solid at the curve down to transparent at the
        // baseline (AddQuadFilled only does a single flat color). Download
        // first, upload (usually smaller) layered on top.
        auto fillArea = [&](bool isDown, ImU32 topCol, ImU32 botCol) {
            for (int i = 0; i < n - 1; i++) {
                float x0 = sampleX(i), x1 = sampleX(i + 1);
                float y0 = isDown ? downY(i) : upY(i);
                float y1 = isDown ? downY(i + 1) : upY(i + 1);
                int ix0 = (int)x0, ix1 = (int)x1;
                for (int px = ix0; px <= ix1; px++) {
                    float t = (x1 > x0) ? (px - x0) / (x1 - x0) : 0.0f;
                    float y = y0 + (y1 - y0) * t;
                    dl->AddRectFilledMultiColor(ImVec2((float)px, y), ImVec2((float)px + 1.5f, baseY), topCol, topCol,
                                                 botCol, botCol);
                }
            }
        };
        auto strokeLine = [&](bool isDown, ImU32 col) {
            for (int i = 0; i < n - 1; i++) {
                float y0 = isDown ? downY(i) : upY(i);
                float y1 = isDown ? downY(i + 1) : upY(i + 1);
                dl->AddLine(ImVec2(sampleX(i), y0), ImVec2(sampleX(i + 1), y1), col, 2.0f);
            }
        };

        if (n >= 2) {
            dl->PushClipRect(p0, p1, true);
            fillArea(true, IM_COL32(0x35, 0xc7, 0x5f, 0xB0), IM_COL32(0x35, 0xc7, 0x5f, 0x00));
            fillArea(false, IM_COL32(0x66, 0x96, 0xfa, 0x80), IM_COL32(0x66, 0x96, 0xfa, 0x00));
            strokeLine(true, IM_COL32(0x46, 0xe0, 0x76, 0xFF));
            strokeLine(false, IM_COL32(0x7f, 0xa8, 0xff, 0xFF));

            // Soft glow dot on the newest download point - a small "live"
            // cue at the leading edge of the graph.
            float lx = sampleX(n - 1), ly = downY(n - 1);
            dl->AddCircleFilled(ImVec2(lx, ly), 5.0f, IM_COL32(0x46, 0xe0, 0x76, 0x50));
            dl->AddCircleFilled(ImVec2(lx, ly), 2.5f, IM_COL32(0xbe, 0xff, 0xd6, 0xFF));
            dl->PopClipRect();
        }

        // Peak marker: a hollow ring + label at the highest download sample
        // in view, so the busiest moment is called out even after it's
        // scrolled back in time.
        if (n >= 2) {
            int peakIdx = 0;
            for (int i = 1; i < n; i++)
                if (samples_[i].down > samples_[peakIdx].down) peakIdx = i;
            if (samples_[peakIdx].down > floorVal) {
                float px = sampleX(peakIdx), py = downY(peakIdx);
                dl->AddCircle(ImVec2(px, py), 4.0f, IM_COL32(0xe6, 0xf0, 0xff, 0xCC), 12, 1.5f);
                std::string plabel = "peak " + FormatRateShort(samples_[peakIdx].down);
                ImVec2 ts = ImGui::CalcTextSize(plabel.c_str());
                float tx = std::min(px + 6, p1.x - ts.x - 4);
                float ty = std::max(py - ts.y - 4, p0.y + 2);
                dl->AddText(ImVec2(tx, ty), IM_COL32(0xe6, 0xf0, 0xff, 0xDD), plabel.c_str());
            }
        }

        // Live current-value readout, top-left inside the chart.
        {
            float tx = p0.x + 10, ty = p0.y + 8;
            std::string d = "Down  " + FormatRateShort(samples_.empty() ? 0.0 : samples_.back().down);
            std::string u = "Up  " + FormatRateShort(samples_.empty() ? 0.0 : samples_.back().up);
            dl->AddText(ImVec2(tx, ty), IM_COL32(0x62, 0xe6, 0x8f, 0xFF), d.c_str());
            dl->AddText(ImVec2(tx, ty + ImGui::GetTextLineHeight() + 2), IM_COL32(0x8f, 0xb4, 0xff, 0xFF), u.c_str());
        }

        dl->AddRect(p0, p1, IM_COL32(55, 60, 70, 255), rounding);

        // Reserve the space and make the area hoverable for the crosshair.
        ImGui::Dummy(size);

        if (n >= 1 && ImGui::IsItemHovered()) {
            ImVec2 mouse = ImGui::GetIO().MousePos;
            if (mouse.x >= p0.x && mouse.x <= p1.x) {
                int i = (int)std::lround((mouse.x - p0.x - xOffset) / stepX);
                i = std::max(0, std::min(i, n - 1));
                float sx = sampleX(i);

                dl->AddLine(ImVec2(sx, p0.y + 1), ImVec2(sx, p1.y - 1), IM_COL32(255, 255, 255, 60), 1.0f);
                dl->AddCircleFilled(ImVec2(sx, downY(i)), 3.5f, IM_COL32(0x46, 0xe0, 0x76, 0xFF));
                dl->AddCircleFilled(ImVec2(sx, upY(i)), 3.5f, IM_COL32(0x7f, 0xa8, 0xff, 0xFF));

                int secondsAgo = (n - 1) - i;
                ImGui::BeginTooltip();
                if (secondsAgo == 0) ImGui::TextUnformatted("now");
                else ImGui::Text("%ds ago", secondsAgo);
                ImGui::TextColored(ImVec4(0.38f, 0.90f, 0.56f, 1.0f), "Down  %s",
                                    FormatRateShort(samples_[i].down).c_str());
                ImGui::TextColored(ImVec4(0.56f, 0.70f, 1.00f, 1.0f), "Up    %s",
                                    FormatRateShort(samples_[i].up).c_str());
                ImGui::EndTooltip();
            }
        }
    }

private:
    size_t capacity_;
    std::deque<TrafficSample> samples_;
};
