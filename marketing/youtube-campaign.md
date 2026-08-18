# netvis — YouTube Launch Campaign

**Type:** Product launch / trial acquisition · **Channel:** YouTube (own channel, organic) · **Budget:** ~$0 · **Duration:** 6 weeks · **Owner:** solo (you)

---

## 1. Campaign overview

**Name:** *"See what's using your internet."*

**Summary:** A six-week run of short, search-driven "how do I…" screen-capture videos that each solve a real Windows networking annoyance, using netvis as the tool that solves it — turning viewers into free-trial installs, and trials into $25 buyers.

**Primary objective (SMART):** 300 free-trial installs from YouTube within 6 weeks of the first upload, tracked via a UTM link to netvis.cc.

**Secondary objectives:**
- 500 subscribers (a base that makes future uploads get recommended).
- 30 paying licenses ($25 each) — a ~10% trial→paid rate, your real proof the funnel works.
- 100 members in the Discord (your warm audience + word of mouth).

Why these are the right size: with zero spend, reach comes from YouTube search + recommendations, which compound slowly. The numbers are deliberately modest — the win in 6 weeks is *proving the loop works at all*, not scale. Scale is what paid buys later, once you have revenue and a cert.

---

## 2. Target audience

**Primary — "Who is eating my internet?"** Windows users (18–40, gamers, streamers, people on video calls, remote workers) who hit a concrete, recurring frustration: the connection dies mid-call/mid-match, upload is busy for no reason, an updater takes the whole line. They don't know *which program*. They search YouTube for a fix.
- **Pain:** unexplained lag, bandwidth, upload; "Task Manager shows a number, not who."
- **Where they are:** YouTube search ("how to see what's using my internet"), r/pcgaming, r/Windows10, r/techsupport, r/pcmasterrace.
- **Stage:** problem-aware, solution-searching — the best kind, because they act now.

**Secondary — the privacy/tech-tips crowd.** People who like knowing what their PC talks to, block ads system-wide, care that data stays local. They watch tech YouTubers and try tools.
- **Pain:** ads/trackers everywhere, "what is this app phoning home to?", extensions aren't enough.
- **Where:** r/privacy, r/pihole, r/selfhosted, privacy YouTube comment sections.
- **Stage:** interest-driven — they'll try a free tool for curiosity, then keep it.

---

## 3. Key messages

**Core message:** *Windows tells you how much data you used. netvis tells you which program used it — and lets you cut it off.*

**Supporting messages (with proof points to show on screen):**
1. **"One click and it's offline."** — the per-process Block button. *Proof:* live demo, block an updater mid-download, watch it stop.
2. **"Your ping, protected."** — auto-block cuts the greedy process the instant it crosses a threshold. *Proof:* the `netvistest` before/after ping table — idle 20ms → saturated 300ms → cut → back to 22ms. This is your single most convincing 30 seconds.
3. **"Ads and trackers, for the whole PC — even the ones extensions can't stop."** — DNS + DoH blocking, system-wide. *Proof:* the `dns` test showing trackers BLOCKED and normal sites fine.
4. **"It never leaves your computer."** — no account, no telemetry, all local. *Proof:* say it plainly, on camera; it's a real differentiator and privacy viewers reward it.

**Voice:** keep it exactly like the site — direct, technical, zero hype, no "revolutionary/game-changing." You're a developer showing a real tool, not an ad. That's *why* people will trust it. Don't oversell; let the demo do the arguing.

---

## 4. Channel strategy

Everything is owned/earned — no paid. Three surfaces, one doing the heavy lifting:

| Surface | Role | Format | Effort |
|---|---|---|---|
| **YouTube (long-ish: 4–8 min)** | The engine. Search-optimized "how to" videos that rank and keep earning views for months. | Screen capture + your voice. No face needed. | Medium |
| **YouTube Shorts / TikTok / Reels** | Discovery. The ping demo and the "watch this app phone home" moment are made for shorts. | 20–40s vertical clips cut from the long videos. | Low |
| **Reddit + Discord (earned)** | Distribution + community. Answer real "what's using my bandwidth" threads with a genuinely helpful reply; link the video, not the product. | Text, honest, non-spammy. | Low-Medium |

**The YouTube-specific rules that matter at zero budget:**
- **Title = the search query.** People type "how to see what is using my internet windows" — make that the literal title. Search intent is where a 0-sub channel actually gets views.
- **Thumbnail = the payoff, not a logo.** "300ms → 22ms" or a big red *BLOCKED* on a process. Legible on a phone.
- **First 15 seconds = the problem, then the fix on screen.** No intro, no "hey guys." Retention is everything for the algorithm.
- **One video = one problem = one keyword.** Don't make "netvis overview" videos; make "stop Windows Update ruining your ping" videos.

**Reddit rule:** never drop a raw product link. Find a real thread, give a real answer, and *if* the video genuinely helps, link it. One good comment beats ten posts. Read each subreddit's self-promo rules first — several will ban you for a product link.

---

## 5. Content calendar (6 weeks)

Cadence: **1 long video + 2 shorts per week.** Shorts are cut from that week's long video, so it's really one production per week. Batch-record when you can.

| Week | Long video (title = search query) | Shorts (from it) | Also | Milestone |
|---|---|---|---|---|
| **0 (prep)** | — | — | Channel art, netvis.cc UTM link, pin Discord invite, record demos with `netvistest` | Channel live, funnel ready |
| **1** | "How to see which app is using your internet (Windows)" | "Task Manager won't tell you this" · "Blocking an app in 1 click" | Soft post in Discord/close friends | First upload live |
| **2** | "Stop Windows Update from ruining your ping" | The 300ms→22ms ping demo · "auto-block in action" | Answer 2–3 Reddit bandwidth threads | Ping demo short published |
| **3** | "Block ads & trackers on your whole PC (no extension)" | "Extensions can't do this" · DoH bypass in 30s | r/privacy + r/pihole helpful comments | — |
| **4** | "What is this app sending? Watch any program's connections" | "Caught it phoning home" · HTTPS/QUIC/DNS split | Discord: ask early users for feedback | 100+ trials cumulative (check) |
| **5** | "Cap any app's download/upload speed on Windows" | "Put Steam on a leash" · 30-min timed limit | Pin best-performing video, refresh its thumbnail | — |
| **6** | "I built a firewall that bans any IP instantly" (the builder story) | "ban an IP, watch it die" · "why I made this" | Recap post; ask happy users for a comment/testimonial | Review results, plan next 6 weeks |

Leave week 5–6 flexible: if one video overperforms, make a follow-up on the *same* topic immediately — that's where the algorithm is already sending you people.

---

## 6. Content pieces needed

**Must-have (before week 1):**
- Channel banner + avatar (use the netvis logo/graph mark). *Canva free is fine.*
- A UTM download link: `https://netvis.cc/?utm_source=youtube&utm_campaign=launch` so you can tell YouTube traffic apart in your logs.
- 4–5 clean screen recordings: per-process block, the `netvistest` ping demo, the DNS/DoH block test, the connection inspector catching an app, a speed limit. **These are reused across every video** — record them once, well.
- A repeatable video outline: *problem (15s) → "here's the fix" → demo → "it's free for 14 days, link below" → done.*

**Must-have (per video):**
- Title written as the search query, 2–3 thumbnail options, description with the UTM link in the first line + 3–5 keywords, pinned comment with the link.

**Nice-to-have:**
- A 20-second "what is netvis" clip to pin on the channel.
- A simple end-screen pointing to the previous video + subscribe.

---

## 7. Success metrics

Keep tracking dead simple — you don't have analytics connectors wired, and you don't need them at this scale.

**Primary KPI:** free-trial installs from YouTube — **target 300 / 6 weeks.** Track via the UTM link (your server logs) or just the download count delta while YouTube is your only channel.

**Secondary KPIs:**
| Metric | Target | Tracked in |
|---|---|---|
| Subscribers | 500 | YouTube Studio |
| Avg. view duration | >50% | YouTube Studio (this predicts reach) |
| Click-through to netvis.cc | >4% of views | UTM / Studio "external" |
| Paying licenses | 30 | Polar dashboard |
| Trial → paid | ~10% | Polar vs. install count |
| Discord members | 100 | Discord |

**Cadence:** glance at Studio weekly (watch time + which title got impressions), full review at week 6. The one number that matters early is **average view duration** — if people watch, YouTube shows the video to more people for free. Optimize hooks for that above all.

---

## 8. Risks and mitigations

- **Slow start (0-sub channels get little reach).** → Win on *search*, not recommendations: title videos as exact queries so you don't need an audience to get the first views. Expect weeks 1–2 to be quiet; compounding kicks in around week 4+.
- **Comes across as an ad → people bounce.** → Lead with the problem and the on-screen fix, mention netvis once, keep the developer-showing-a-tool voice. Never say "revolutionary."
- **Reddit self-promo bans.** → Be a helpful commenter first; link only when the video truly answers the thread; read each sub's rules. Treat Reddit as amplification, not a billboard.
- **SmartScreen warning scares off installs.** → Until the code-signing cert is in, add one honest line in every video description: *"Windows may show a SmartScreen warning — click More info → Run anyway. It's normal for new, unsigned software."* Turning the objection into a caption kills most of its power.

---

## 9. Next steps (this week)

1. Set up the channel: banner, avatar, a 20s pinned "what is netvis" clip.
2. Create the UTM download link and confirm you can see YouTube traffic in your server logs.
3. Record the 4–5 reusable demos with `netvistest` — the ping before/after is priority #1.
4. Script + record **Video 1** ("How to see which app is using your internet — Windows"), make 3 thumbnails, publish.
5. Cut 2 shorts from it. Post the ping short the same week.
6. Line up 3 Reddit threads to answer helpfully next week.

---

*Assumptions: Windows-only product, $25/6-month license with a 14-day no-card trial, solo operator, ~$0 spend, netvis.cc live with download + Polar checkout, Discord support server active. Adjust the calendar if you'd rather batch a month of videos before launching, or if a cert lands and you want to add light paid retargeting in weeks 4–6.*
