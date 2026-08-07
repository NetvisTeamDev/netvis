// GlassWire-style rolling bandwidth graph: a filled area for download and
// a line for upload, auto-scaled to the busiest sample currently in view.
// Drawn directly with ImDrawList rather than ImGui::PlotLines so download
// and upload can be layered with different fill styles.
#pragma once
#include <algorithm>
#include <deque>
#include "imgui.h"

struct TrafficSample {
    double down = 0, up = 0; // bytes/sec
};

class TrafficGraph {
public:
    explicit TrafficGraph(size_t capacity) : capacity_(capacity) {}

    void Push(double down, double up) {
        samples_.push_back({down, up});
        while (samples_.size() > capacity_) samples_.pop_front();
    }

    void Draw(ImVec2 size) const {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        ImVec2 p1 = ImVec2(p0.x + size.x, p0.y + size.y);
        dl->AddRectFilled(p0, p1, IM_COL32(15, 15, 20, 255));

        if (!samples_.empty()) {
            const double floor = 8.0 * 1024.0; // 8 KB/s, keeps an idle graph from jittering at full height
            double maxVal = floor;
            for (const auto& s : samples_) {
                maxVal = std::max({maxVal, s.down, s.up});
            }

            int n = (int)samples_.size();
            float stepX = size.x / std::max(1, (int)capacity_ - 1);
            float xOffset = (float)(capacity_ - n) * stepX; // right-align when buffer isn't full yet

            // Filled download area.
            for (int i = 0; i < n - 1; i++) {
                float x0 = p0.x + xOffset + i * stepX;
                float x1 = p0.x + xOffset + (i + 1) * stepX;
                float h0 = (float)(samples_[i].down / maxVal) * size.y;
                float h1 = (float)(samples_[i + 1].down / maxVal) * size.y;
                dl->AddQuadFilled(ImVec2(x0, p1.y), ImVec2(x0, p1.y - h0), ImVec2(x1, p1.y - h1), ImVec2(x1, p1.y),
                                   IM_COL32(0x35, 0xc7, 0x5f, 0xB0));
            }
            // Upload line.
            for (int i = 0; i < n - 1; i++) {
                float x0 = p0.x + xOffset + i * stepX;
                float x1 = p0.x + xOffset + (i + 1) * stepX;
                float y0 = p1.y - (float)(samples_[i].up / maxVal) * size.y;
                float y1 = p1.y - (float)(samples_[i + 1].up / maxVal) * size.y;
                dl->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(0x4a, 0xa3, 0xf5, 0xFF), 2.0f);
            }
        }

        dl->AddRect(p0, p1, IM_COL32(60, 60, 70, 255));
        ImGui::Dummy(size);
    }

private:
    size_t capacity_;
    std::deque<TrafficSample> samples_;
};
