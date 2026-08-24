// GlassWire-style rolling bandwidth graph. Download and upload are each
// drawn as a gradient-filled area (solid at the line, fading to nothing at
// the baseline) with a crisp curve on top, over labeled round-number
// Y-axis gridlines. Hovering shows a crosshair and the exact values at
// that moment. Everything is drawn with ImDrawList rather than
// ImGui::PlotLines so we control every pixel of it.
#pragma once
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <deque>
#include <string>
#include <vector>
#include "imgui.h"
#include "theme.h"

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

// The axis maximum without a decimal place. NiceCeil always returns a whole
// number of its unit, so the ".0" in "50.0 KB/s" is a digit that can only
// ever be zero - and a scale reads as a scale, rather than as a
// measurement, when it is written the way a person would say it.
inline std::string FormatRateAxis(double bytesPerSec) {
    char buf[32];
    if (bytesPerSec < 1024.0) {
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
    snprintf(buf, sizeof(buf), "%.0f %cB/s", v, units[exp]);
    return buf;
}

// Rounds an axis maximum up to a round number, so the top of the axis lands
// somewhere memorable (1, 2, 5, 10 MB/s) and doesn't twitch to a new odd
// maximum every second as the busiest sample changes.
//
// Rounded within the 1024-based unit it will be *displayed* in, not the
// decimal one. A decimal ceiling of two million bytes per second is a
// perfectly round number right up until FormatRateShort divides it by 1024
// and labels the axis "1.9 MB/s", which looks like a measurement rather
// than a scale.
inline double NiceCeil(double v) {
    if (v <= 0) return 1;
    double unit = 1.0;
    while (v / unit >= 1024.0) unit *= 1024.0;
    double frac = v / unit; // in [1, 1024)
    static const double steps[] = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1024};
    for (double step : steps)
        if (frac <= step) return step * unit;
    return 1024.0 * unit;
}

// Builds a smooth curve through the sample points, using monotone cubic
// interpolation (Fritsch-Carlson).
//
// Straight lines between one-second samples make the graph a row of sharp
// spikes. An ordinary spline rounds them off but overshoots: it draws peaks
// higher than any sample and troughs below zero, which on a bandwidth graph
// is not smoothing, it is inventing traffic that never happened. The
// monotone variant limits the tangents so the curve stays within the range
// of the points either side of it - it never rises above a peak it did not
// measure, and it never dips below the baseline.
//
// `perSegment` is how many line segments each interval becomes.
inline void MonotoneCurve(const std::vector<ImVec2>& p, int perSegment, std::vector<ImVec2>& out) {
    out.clear();
    int n = (int)p.size();
    if (n < 3 || perSegment < 1) {
        out = p;
        return;
    }

    // Secant slopes, then a starting tangent at each point.
    std::vector<float> d(n - 1), m(n);
    for (int i = 0; i < n - 1; i++) {
        float dx = p[i + 1].x - p[i].x;
        d[i] = (dx != 0.0f) ? (p[i + 1].y - p[i].y) / dx : 0.0f;
    }
    m[0] = d[0];
    m[n - 1] = d[n - 2];
    for (int i = 1; i < n - 1; i++) {
        // Opposite signs means this point is a local peak or trough, and a
        // flat tangent is what keeps the curve from sailing past it.
        m[i] = (d[i - 1] * d[i] <= 0.0f) ? 0.0f : (d[i - 1] + d[i]) * 0.5f;
    }

    // The limiter itself: keep each tangent pair inside a circle of radius
    // 3, which is the condition for the cubic to stay monotone.
    for (int i = 0; i < n - 1; i++) {
        if (d[i] == 0.0f) {
            m[i] = m[i + 1] = 0.0f;
            continue;
        }
        float a = m[i] / d[i], b = m[i + 1] / d[i];
        float s = a * a + b * b;
        if (s > 9.0f) {
            float t = 3.0f / std::sqrt(s);
            m[i] = t * a * d[i];
            m[i + 1] = t * b * d[i];
        }
    }

    out.reserve((size_t)(n - 1) * perSegment + 1);
    for (int i = 0; i < n - 1; i++) {
        float h = p[i + 1].x - p[i].x;
        for (int k = 0; k < perSegment; k++) {
            float t = (float)k / (float)perSegment;
            float t2 = t * t, t3 = t2 * t;
            // Hermite basis.
            float h00 = 2 * t3 - 3 * t2 + 1, h10 = t3 - 2 * t2 + t;
            float h01 = -2 * t3 + 3 * t2, h11 = t3 - t2;
            out.push_back(ImVec2(p[i].x + t * h, h00 * p[i].y + h10 * h * m[i] + h01 * p[i + 1].y +
                                                     h11 * h * m[i + 1]));
        }
    }
    out.push_back(p[n - 1]);
}

// Fills the area between a curve and the baseline with a vertical gradient,
// written directly into the draw list as one triangle strip: each point
// contributes a vertex on the curve carrying the solid colour and one on
// the baseline carrying the transparent one, and the GPU interpolates
// between them.
//
// This used to be approximated by stacking one small rectangle per pixel
// column. Each was a point and a half wide but only a point apart, so every
// column was painted roughly twice over and the overlapping alpha built up
// into the soft haze that made the whole graph look out of focus. Their
// tops were also flat, so a sloped curve came out as a staircase. Real
// vertex colours cost one draw call and have neither problem.
inline void FillUnderCurve(ImDrawList* dl, const std::vector<ImVec2>& curve, float baseY, ImU32 top,
                           ImU32 bottom) {
    int n = (int)curve.size();
    if (n < 2) return;

    // The public accessor rather than dl->_Data->TexUvWhitePixel, which
    // would drag imgui_internal.h into this header.
    const ImVec2 uv = ImGui::GetFontTexUvWhitePixel();
    const int quads = n - 1;
    dl->PrimReserve(quads * 6, n * 2);

    // Captured before the writes, which advance it.
    unsigned int base = dl->_VtxCurrentIdx;
    for (int i = 0; i < n; i++) {
        dl->PrimWriteVtx(curve[i], uv, top);
        dl->PrimWriteVtx(ImVec2(curve[i].x, baseY), uv, bottom);
    }
    for (int i = 0; i < quads; i++) {
        unsigned int a = base + (unsigned)i * 2; // curve, left
        dl->PrimWriteIdx((ImDrawIdx)a);
        dl->PrimWriteIdx((ImDrawIdx)(a + 1)); // baseline, left
        dl->PrimWriteIdx((ImDrawIdx)(a + 2)); // curve, right
        dl->PrimWriteIdx((ImDrawIdx)(a + 1));
        dl->PrimWriteIdx((ImDrawIdx)(a + 3)); // baseline, right
        dl->PrimWriteIdx((ImDrawIdx)(a + 2));
    }
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

    double CurrentDown() const { return samples_.empty() ? 0.0 : samples_.back().down; }
    double CurrentUp() const { return samples_.empty() ? 0.0 : samples_.back().up; }

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

        // The chart fills its whole footprint, less a small inset that keeps
        // the plot off the rounded corners, and a gutter along the bottom
        // for the time axis.
        //
        // There is still no column of Y-axis numbers down the side: they
        // overlapped each other at higher DPI, and four of them were four
        // times the ink needed to say what the height means. One label on
        // the top gridline says the same thing.
        const float rounding = 8.0f;
        const float pad = 3.0f;
        const float labelSize = std::floor(ImGui::GetFontSize() * 0.78f);
        // The time axis gets a gutter of its own, but only on a chart tall
        // enough to spare it. The Windows build draws this at 90 points,
        // where a fixed gutter would take a quarter of the plot and leave
        // the traffic squashed into what was left - so on a short chart the
        // axis is dropped rather than the data being shrunk to fit it. Give
        // the graph more height and the axis appears by itself.
        const float axisH = (size.y >= 110.0f) ? labelSize + 8.0f : 0.0f;
        const bool showTimeAxis = axisH > 0.0f;
        ImVec2 p0 = ImVec2(origin.x, origin.y);
        ImVec2 p1 = ImVec2(origin.x + size.x, origin.y + size.y);
        float chartW = p1.x - p0.x;
        float baseY = p1.y - pad - axisH;
        float plotH = size.y - pad * 2 - axisH;

        // The chart's own furniture, from the theme module - the same values
        // the rest of the window is drawn with, so light mode is one switch
        // rather than a second set of colours living here.
        const ImU32 panelCol = theme::GraphBg();
        const ImU32 gridStrong = theme::GraphGrid(true);
        const ImU32 gridFaint = theme::GraphGrid(false);
        const ImU32 borderCol = theme::GraphBorder();
        const ImU32 hoverLineCol = theme::GraphCrosshair();
        // Axis labels, deliberately quiet: they are there to be read when
        // looked for, not to compete with the traffic.
        const ImU32 axisTextCol = theme::GraphAxisText();

        const ImU32 downLine = theme::GraphDownLine();
        const ImU32 downFill = theme::GraphDownFill();
        const ImU32 downFade = theme::GraphDownClear();
        const ImU32 upLine = theme::GraphUpLine();
        const ImU32 upFill = theme::GraphUpFill();
        const ImU32 upFade = theme::GraphUpClear();
        const ImU32 liveGlow = theme::GraphHeadGlow();
        const ImU32 liveDot = theme::GraphHeadDot();

        dl->AddRectFilled(p0, p1, panelCol, rounding);

        // Horizontal gridlines at 25/50/75/100% of the nice max.
        for (int i = 1; i <= 4; i++) {
            float y = baseY - (float)i / 4.0f * plotH;
            ImU32 lineCol = (i == 4) ? gridStrong : gridFaint;
            dl->AddLine(ImVec2(p0.x + 1, y), ImVec2(p1.x - 1, y), lineCol, 1.0f);
        }

        int n = (int)samples_.size();
        float stepX = chartW / std::max(1, (int)capacity_ - 1);
        float xOffset = (float)(capacity_ - n) * stepX; // right-align while the buffer fills

        // Vertical gridlines every quarter of the window, so a spike can be
        // placed in time rather than just being somewhere along the middle.
        // The newest sample sits on the right edge, so these count backwards
        // from it.
        for (int q = 1; q <= 3; q++) {
            float x = p1.x - (float)q * (chartW / 4.0f);
            dl->AddLine(ImVec2(x, p0.y + 1), ImVec2(x, baseY), gridFaint, 1.0f);
        }

        // What the full height means. Sitting just under the top gridline
        // rather than on it, so the line stays unbroken.
        ImFont* font = ImGui::GetFont();
        std::string maxLabel = trafficgraph_detail::FormatRateAxis(maxVal);
        dl->AddText(font, labelSize, ImVec2(p0.x + 10.0f, baseY - plotH + 3.0f), axisTextCol,
                    maxLabel.c_str());

        // The two ends of the time axis, in the gutter below the plot. Only
        // the ends: the gridlines already divide the span evenly, and a
        // label under each one would be four numbers saying what "one
        // minute, oldest on the left" says once.
        if (showTimeAxis) {
            char span[32];
            snprintf(span, sizeof(span), "%zus ago", capacity_ > 0 ? capacity_ - 1 : 0);
            float labelY = baseY + 4.0f;
            dl->AddText(font, labelSize, ImVec2(p0.x + 10.0f, labelY), axisTextCol, span);
            float nowW = font->CalcTextSizeA(labelSize, FLT_MAX, 0.0f, "now").x;
            dl->AddText(font, labelSize, ImVec2(p1.x - 10.0f - nowW, labelY), axisTextCol, "now");
        }

        auto sampleX = [&](int i) { return p0.x + xOffset + i * stepX; };
        auto downY = [&](int i) { return baseY - (float)(samples_[i].down / maxVal) * plotH; };
        auto upY = [&](int i) { return baseY - (float)(samples_[i].up / maxVal) * plotH; };

        // Each series is smoothed once and then drawn twice - the gradient
        // under it and the stroke along it follow the same list of points,
        // so the line always sits exactly on the edge of its own fill.
        //
        // Eight segments per sample is enough that the curve reads as a
        // curve at any window width this thing gets opened at, without
        // filling the vertex buffer for the sake of it.
        auto buildCurve = [&](bool isDown, std::vector<ImVec2>& out) {
            std::vector<ImVec2> pts;
            pts.reserve((size_t)n);
            for (int i = 0; i < n; i++) pts.push_back(ImVec2(sampleX(i), isDown ? downY(i) : upY(i)));
            trafficgraph_detail::MonotoneCurve(pts, 8, out);
        };

        if (n >= 2) {
            dl->PushClipRect(p0, p1, true);

            std::vector<ImVec2> downCurve, upCurve;
            buildCurve(true, downCurve);
            buildCurve(false, upCurve);

            // Taller series underneath, so the shorter one is never buried.
            // Download used to be drawn first on the assumption that upload
            // is the smaller of the two, which is true right up until you
            // send a file - and then a wall of upload swallowed the download
            // curve completely.
            double peakDown = 0, peakUp = 0;
            for (const auto& smp : samples_) {
                peakDown = std::max(peakDown, smp.down);
                peakUp = std::max(peakUp, smp.up);
            }
            const bool downBehind = peakDown >= peakUp;
            const std::vector<ImVec2>& backCurve = downBehind ? downCurve : upCurve;
            const std::vector<ImVec2>& frontCurve = downBehind ? upCurve : downCurve;

            trafficgraph_detail::FillUnderCurve(dl, backCurve, baseY, downBehind ? downFill : upFill,
                                                downBehind ? downFade : upFade);
            trafficgraph_detail::FillUnderCurve(dl, frontCurve, baseY, downBehind ? upFill : downFill,
                                                downBehind ? upFade : downFade);

            // One anti-aliased polyline per series rather than a separate
            // AddLine per segment: those each carried their own AA fringe
            // and overlapped at every joint, which thickened the line into a
            // blur wherever the graph changed direction - that is, at every
            // spike.
            dl->AddPolyline(backCurve.data(), (int)backCurve.size(), downBehind ? downLine : upLine,
                            ImDrawFlags_None, 1.8f);
            dl->AddPolyline(frontCurve.data(), (int)frontCurve.size(), downBehind ? upLine : downLine,
                            ImDrawFlags_None, 1.8f);

            // Soft glow dot on the newest download point - a small "live"
            // cue at the leading edge of the graph.
            float lx = sampleX(n - 1), ly = downY(n - 1);
            dl->AddCircleFilled(ImVec2(lx, ly), 5.0f, liveGlow);
            dl->AddCircleFilled(ImVec2(lx, ly), 2.5f, liveDot);
            dl->PopClipRect();
        }


        // (The current Down/Up values are rendered by the caller above the
        // chart now, so they don't overlap the plotted area.)

        dl->AddRect(p0, p1, borderCol, rounding);

        // Reserve the space and make the area hoverable for the crosshair.
        ImGui::Dummy(size);

        if (n >= 1 && ImGui::IsItemHovered()) {
            ImVec2 mouse = ImGui::GetIO().MousePos;
            if (mouse.x >= p0.x && mouse.x <= p1.x) {
                int i = (int)std::lround((mouse.x - p0.x - xOffset) / stepX);
                i = std::max(0, std::min(i, n - 1));
                float sx = sampleX(i);

                dl->AddLine(ImVec2(sx, p0.y + 1), ImVec2(sx, baseY), hoverLineCol, 1.0f);
                dl->AddCircleFilled(ImVec2(sx, downY(i)), 3.5f, downLine);
                dl->AddCircleFilled(ImVec2(sx, upY(i)), 3.5f, upLine);

                int secondsAgo = (n - 1) - i;
                ImGui::BeginTooltip();
                if (secondsAgo == 0) ImGui::TextUnformatted("now");
                else ImGui::Text("%ds ago", secondsAgo);
                ImGui::TextColored(theme::GraphDownText(), "Down  %s",
                                    FormatRateShort(samples_[i].down).c_str());
                ImGui::TextColored(theme::GraphUpText(), "Up    %s",
                                    FormatRateShort(samples_[i].up).c_str());
                ImGui::EndTooltip();
            }
        }
    }

private:
    size_t capacity_;
    std::deque<TrafficSample> samples_;
};
