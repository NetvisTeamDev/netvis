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
        "1.1.1.2", "1.0.0.2",                   // Cloudflare (malware-blocking)
        "1.1.1.3", "1.0.0.3",                   // Cloudflare (family)
        "8.8.8.8", "8.8.4.4",                   // Google
        "9.9.9.9", "149.112.112.112",           // Quad9
        "9.9.9.10", "149.112.112.10",           // Quad9 (unsecured)
        "9.9.9.11", "149.112.112.11",           // Quad9 (ECS)
        "208.67.222.222", "208.67.220.220",     // OpenDNS
        "208.67.222.123", "208.67.220.123",     // OpenDNS FamilyShield
        "45.90.28.0", "45.90.30.0",             // NextDNS (representative)
        "94.140.14.14", "94.140.15.15",         // AdGuard DNS
        "94.140.14.15", "94.140.15.16",         // AdGuard (family)
        "76.76.2.0", "76.76.10.0",              // ControlD
        "194.242.2.2",                          // Mullvad
        "185.228.168.9", "185.228.169.9",       // CleanBrowsing
        "76.76.19.19", "76.223.122.150",        // Alternate DNS
        "45.11.45.11",                          // DNS.SB
        "193.110.81.0", "185.253.5.0",          // dns0.eu
    };
    return ips;
}
