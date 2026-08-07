// Default ad/tracker domain suffixes and known DNS-over-HTTPS resolver IPs
// (used to also catch DoH, which bypasses plain-DNS blocking entirely).
// The user can extend/override via blocklist.txt / allowlist.txt next to
// the exe.
#pragma once
#include <vector>
#include <string>

inline const std::vector<std::string>& DefaultBlocklist() {
    static const std::vector<std::string> list = {
        // --- Google ads / analytics ---
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "google-analytics.com", "googletagmanager.com", "googletagservices.com",
        "adservice.google.com", "pagead2.googlesyndication.com", "ad.doubleclick.net",
        "stats.g.doubleclick.net", "analytics.google.com", "adsense.google.com",

        // --- Amazon ads ---
        "amazon-adsystem.com", "aax.amazon-adsystem.com", "s.amazon-adsystem.com",

        // --- Ad exchanges / SSPs / DSPs ---
        "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "adform.net", "adroll.com", "casalemedia.com", "smartadserver.com",
        "advertising.com", "yieldmo.com", "media.net", "bidswitch.net",
        "contextweb.com", "sharethrough.com", "spotxchange.com", "indexexchange.com",
        "33across.com", "triplelift.com", "sonobi.com", "gumgum.com",

        // --- Social platform ad endpoints ---
        "ads.facebook.com", "ads.pinterest.com", "ads.linkedin.com",
        "ads-twitter.com", "analytics.twitter.com", "ads.tiktok.com",
        "analytics.tiktok.com", "connect.facebook.net",

        // --- Video / CTV ad-specific ---
        "innovid.com", "springserve.com", "freewheel.tv", "adsafeprotected.com",
        "moatads.com", "doubleverify.com", "serving-sys.com",

        // --- Misc trackers / telemetry ---
        "mixpanel.com", "segment.io", "segment.com", "hotjar.com",
        "newrelic.com", "nr-data.net", "fullstory.com", "amplitude.com",
        "quantserve.com", "scorecardresearch.com", "chartbeat.com",
        "crazyegg.com", "mouseflow.com", "clicktale.net", "optimizely.com",
        "branch.io", "appsflyer.com", "adjust.com", "kochava.com",
        "flurry.com", "vungle.com", "applovin.com", "unityads.unity3d.com",
        "bugsnag.com", "sentry.io", "crashlytics.com",
    };
    return list;
}

// Known DoH resolver IPs, so blocking "tcp.DstPort == 443 && (these IPs)"
// catches DNS-over-HTTPS, which otherwise looks like ordinary HTTPS.
inline const std::vector<std::string>& KnownDoHIPs() {
    static const std::vector<std::string> ips = {
        "1.1.1.1", "1.0.0.1",                   // Cloudflare
        "8.8.8.8", "8.8.4.4",                   // Google
        "9.9.9.9", "149.112.112.112",           // Quad9
        "208.67.222.222", "208.67.220.220",     // OpenDNS
        "45.90.28.0", "45.90.30.0",             // NextDNS (representative)
    };
    return ips;
}
