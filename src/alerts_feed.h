// The alerts feed, drawn as cards.
//
// Split out of main.cpp rather than written inline there for one practical
// reason: main.cpp cannot be compiled anywhere except Windows, and this can.
// Everything here is ImGui and the theme module, so it builds and runs on a
// developer's Mac against a stub theme, which is how it gets exercised
// before it ever reaches a Windows machine.
//
// Header-only on purpose - a new .cpp would mean editing compile.bat, and
// there is no reason to touch the build for four hundred lines of drawing.
//
// This is the same design as the macOS port's feed. What is deliberately NOT
// carried over from that port:
//
//   * The feed lives in its own window here, and stays there. On the Mac it
//     is a section of the main window because the Mac build is organised
//     into sections; this one is organised around floating panels and works
//     perfectly well that way.
//   * The Mac feed carries a line explaining that only processes running as
//     you are visible. That is a limitation of reading sockets unprivileged
//     on macOS. netvis runs elevated on Windows and sees everything, so the
//     line would be false here.
#pragma once
#include <cstdio>
#include <ctime>
#include <string>

#include "imgui.h"

#include "alerts.h"
#include "theme.h"

namespace alertsfeed {

// How long ago something happened, in words: "just now", "4 min ago",
// "2 hr ago", "3 days ago".
//
// The feed used to print a bare wall-clock time against every entry, which
// answers the wrong question. Reading "14:22:07" means working out what time
// it is now and subtracting, where what the eye is actually asking is
// whether this happened a moment ago or this morning. The exact time is
// still one hover away.
//
// Negative inputs (a clock that moved backwards) read as "just now" rather
// than as something in the future.
inline std::string RelativeTime(long long secondsAgo) {
    if (secondsAgo < 45) return "just now";
    if (secondsAgo < 90) return "1 min ago";
    long long minutes = (secondsAgo + 30) / 60;
    if (minutes < 60) return std::to_string(minutes) + " min ago";
    long long hours = minutes / 60;
    if (hours < 24) return std::to_string(hours) + (hours == 1 ? " hr ago" : " hrs ago");
    long long days = hours / 24;
    return std::to_string(days) + (days == 1 ? " day ago" : " days ago");
}

namespace detail {

// What each kind is called and what colour it carries.
//
// The kind used to be encoded in the colour of the timestamp and nowhere
// else, which asks the reader to learn a colour code nobody told them
// about - and leaves anyone who cannot separate the two warning colours
// with no information at all. The colour stays, but it is now attached to
// a word.
struct KindStyle {
    const char* label;
    ImVec4 color;
};

inline KindStyle StyleFor(AlertKind kind) {
    switch (kind) {
        case AlertKind::NewListener: return {"Incoming", theme::Warn()};
        case AlertKind::DnsChanged: return {"Network", theme::Warn()};
        case AlertKind::AutoBlocked: return {"Blocked", theme::Bad()};
        default: return {"New app", theme::Accent()};
    }
}

// A small rounded label in the kind's colour, on a tinted bed of the same
// colour. Reserves its own layout space, so it sits in a row like any other
// item.
inline void KindPill(const KindStyle& style, float fontSize) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* font = ImGui::GetFont();
    const ImVec2 pad(9.0f, 3.0f);
    ImVec2 text = font->CalcTextSizeA(fontSize, 3.4e38f, 0.0f, style.label);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 size(text.x + pad.x * 2.0f, text.y + pad.y * 2.0f);

    ImVec4 bed = style.color;
    bed.w = 0.16f;
    dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(bed),
                      size.y * 0.5f);
    dl->AddText(font, fontSize, ImVec2(pos.x + pad.x, pos.y + pad.y),
                ImGui::GetColorU32(style.color), style.label);
    ImGui::Dummy(size);
}

// One alert, as a card.
//
// The feed used to be a run of two-line entries separated by a blank line: a
// timestamp and a title on one line, an indented sentence under it, then the
// next one. At a glance it read as a wall of text with no boundary between
// one event and the next. A card gives each event an edge, and the colour
// goes on a strip down its side where it labels the whole entry rather than
// tinting one field of it.
inline void DrawCard(const Alert& a, long long now, ImFont* boldFont) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const KindStyle kind = StyleFor(a.kind);
    const float rounding = 10.0f;
    const float accentW = 4.0f;
    const ImVec2 pad(16.0f, 12.0f);
    float smallFont = ImGui::GetFontSize() * 0.8f;
    smallFont = (float)(int)(smallFont > 1.0f ? smallFont : 1.0f);

    const float width = ImGui::GetContentRegionAvail().x;
    const ImVec2 cardMin = ImGui::GetCursorScreenPos();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    // The card's background has to be painted under content that has not
    // been laid out yet - its height is whatever the wrapped text turns out
    // to need. Splitting the draw list lets the background be written after
    // the fact into a channel that is composited underneath.
    dl->ChannelsSplit(2);
    dl->ChannelsSetCurrent(1);

    ImGui::Dummy(ImVec2(0.0f, pad.y - style.ItemSpacing.y));
    ImGui::Indent(pad.x + accentW);
    const float contentW = width - (pad.x + accentW) - pad.x;

    // Kind on the left, how long ago on the right. Both are labels about
    // the entry rather than part of its message, so they share a line above
    // it and stay out of the sentence.
    KindPill(kind, smallFont);
    {
        std::string ago = RelativeTime(now - (long long)a.at);
        ImFont* font = ImGui::GetFont();
        float w = font->CalcTextSizeA(smallFont, 3.4e38f, 0.0f, ago.c_str()).x;
        ImVec2 pillMax = ImGui::GetItemRectMax();
        ImVec2 at(cardMin.x + width - pad.x - w,
                  ImGui::GetItemRectMin().y + (ImGui::GetItemRectSize().y - smallFont) * 0.5f);
        if (at.x > pillMax.x + 8.0f)
            dl->AddText(font, smallFont, at, ImGui::GetColorU32(theme::Dim()), ago.c_str());
    }

    ImGui::PushFont(boldFont, 0.0f);
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + contentW);
    ImGui::TextWrapped("%s", a.title.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopFont();

    ImGui::PushStyleColor(ImGuiCol_Text, theme::Dim());
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + contentW);
    ImGui::TextWrapped("%s", a.detail.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();

    ImGui::Unindent(pad.x + accentW);
    ImGui::Dummy(ImVec2(0.0f, pad.y - style.ItemSpacing.y));

    const ImVec2 cardMax(cardMin.x + width, ImGui::GetCursorScreenPos().y);
    const bool hovered = ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(cardMin, cardMax);

    dl->ChannelsSetCurrent(0);
    ImVec4 bg = ImGui::GetStyleColorVec4(hovered ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg);
    dl->AddRectFilled(cardMin, cardMax, ImGui::GetColorU32(bg), rounding);
    dl->AddRect(cardMin, cardMax, ImGui::GetColorU32(ImGuiCol_Border), rounding);
    dl->AddRectFilled(cardMin, ImVec2(cardMin.x + accentW, cardMax.y),
                      ImGui::GetColorU32(kind.color), rounding, ImDrawFlags_RoundCornersLeft);
    dl->ChannelsMerge();

    // The exact time, and which process it was, on hover. Neither is worth
    // a line of its own on every card - the relative time answers "when"
    // for almost every reading of the feed, and the process name is already
    // in the title - but both are exactly what is wanted once an entry has
    // caught someone's eye.
    if (hovered) {
        ImGui::BeginTooltip();
        ImGui::Text("At %s", a.timestamp.c_str());
        if (a.pid) ImGui::Text("PID %u", a.pid);
        ImGui::EndTooltip();
    }
}

} // namespace detail

// Draws the whole feed into whatever is currently being laid out - the
// caller owns the window. Returns true if the user asked to clear it, which
// the caller acts on, so this function never mutates the alert list itself.
inline bool Draw(const std::vector<Alert>& list, ImFont* boldFont) {
    bool clearRequested = false;
    const long long now = (long long)time(nullptr);

    ImGui::AlignTextToFramePadding();
    if (list.empty())
        ImGui::TextDisabled("No alerts");
    else
        ImGui::TextDisabled("%zu alert%s, newest first", list.size(), list.size() == 1 ? "" : "s");

    if (!list.empty()) {
        const char* clear = "Clear";
        float w = ImGui::CalcTextSize(clear).x + ImGui::GetStyle().FramePadding.x * 2;
        // Measured after SameLine, not before. Before it, the region is the
        // whole width of the next row rather than what is left of this one,
        // and adding that to the cursor puts the button off the edge of the
        // window - present, hit-testable, invisible.
        ImGui::SameLine();
        float avail = ImGui::GetContentRegionAvail().x;
        if (avail > w) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + avail - w);
        // Borderless: emptying the feed is a housekeeping action, not the
        // thing this window is for, and a filled button competes with the
        // alerts for attention.
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
        if (ImGui::Button(clear)) clearRequested = true;
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Remove every alert from this list");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (list.empty()) {
        // The empty state is the screen most people see first and, if
        // nothing on the machine misbehaves, the only one they ever see. It
        // says what will appear here rather than that nothing has, so an
        // empty feed reads as "nothing has happened" instead of "this does
        // not work".
        float wrap = ImGui::GetContentRegionAvail().x;
        if (wrap > 520.0f) wrap = 520.0f;
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap);
        ImGui::PushFont(boldFont, 0.0f);
        ImGui::TextUnformatted("Nothing to report");
        ImGui::PopFont();
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Text, theme::Dim());
        ImGui::TextWrapped("netvis will tell you here when an app uses the internet for the first "
                           "time, when something starts accepting incoming connections, and when "
                           "your DNS servers change.");
        ImGui::PopStyleColor();
        ImGui::PopTextWrapPos();
        return clearRequested;
    }

    // Scrolls on its own so the count and Clear stay put at the top of the
    // window while the feed moves under them.
    ImGui::BeginChild("alertsfeed", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground);
    for (size_t i = 0; i < list.size(); i++) {
        ImGui::PushID((int)i);
        detail::DrawCard(list[i], now, boldFont);
        ImGui::PopID();
        ImGui::Dummy(ImVec2(0.0f, 2.0f));
    }
    ImGui::EndChild();

    return clearRequested;
}

} // namespace alertsfeed
