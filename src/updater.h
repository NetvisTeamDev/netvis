// Signed auto-update for netvis.
//
// The trust model is the same as the license check, with a SEPARATE key.
// netvis fetches a small JSON manifest and its detached signature, verifies
// the signature against kUpdatePublicKey (whose private half lives only on the
// release machine), and only then trusts the version/url/hash inside. The
// download is checked against the SHA-256 the signed manifest names, so even
// if someone controls the server they can neither forge a manifest nor swap
// the installer for a different file.
//
//   netvis.cc/updates/windows/update.json       the manifest (signed bytes)
//   netvis.cc/updates/windows/update.json.sig    its signature (raw r||s hex)
//   netvis.cc/updates/windows/netvis-windows-<v>.exe   the installer
#pragma once
#include <string>

namespace updater {

struct Release {
    bool checked = false; // the check completed (reached the server + verified)
    bool newer = false;   // a verified, newer version than this build exists
    std::string version;  // the manifest's version
    std::string url;      // download URL (enforced to be on netvis.cc)
    std::string sha256;   // expected hash of the download
    std::string notes;    // optional short release notes
};

// Fetches and verifies the manifest, and compares its version to this build.
// Does network + crypto; call it off the UI thread. A failure to reach or
// verify leaves checked=false; a good check with no newer build leaves
// checked=true, newer=false.
Release Check();

// Downloads the release named by `r`, verifies its SHA-256 against the signed
// manifest, and launches the installer to apply it. The installer stops the
// running netvis and replaces it, so after this returns true the app should
// exit. Returns false with *error set on any failure.
bool Apply(const Release& r, std::string* error);

// This build's version string (NETVIS_VERSION).
const char* CurrentVersion();

} // namespace updater
