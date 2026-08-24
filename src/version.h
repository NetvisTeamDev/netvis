// Single source of truth for the app version.
//
// Keep this in sync with installer\netvis.iss (#define AppVersion) and bump
// both on every release - the updater compares the manifest's version against
// this string to decide whether a newer build exists.
#pragma once
#define NETVIS_VERSION "1.0.0"
