// Licensing client: asks the netvis licensing server whether this machine
// is allowed to run, and redeems a license key if it isn't.
//
// Two calls, mirroring the server's two endpoints:
//   Authenticate()  GET  /authentificate/<hwid>
//   Activate(key)   POST /validate/<key>   body {"hwid":..,"os":"windows"}
#pragma once
#include <string>

namespace license {

// Stable per-machine fingerprint: the Windows MachineGuid plus the system
// volume serial, hashed. Survives reboots and app reinstalls; changes if
// the OS is reinstalled, which is the behaviour you want from a HWID.
const std::string& HWID();

// Server base URL, e.g. "http://127.0.0.1:8443". Read once from
// "server=<url>" in %ProgramFiles%\netvis\license.cfg; falls back to
// kDefaultServer below if the file is missing.
const std::string& ServerURL();
extern const char* const kDefaultServer;

enum class Status {
    Licensed,     // server says this machine may run
    NotLicensed,  // server answered, but this machine isn't activated (or is revoked)
    Unreachable,  // couldn't reach the server at all
};

// GET /authentificate/<hwid>
Status Authenticate();

// POST /validate/<key>. On failure `error` gets a message suitable for
// showing the user.
bool Activate(const std::string& key, std::string* error);

// Length the server requires. Used to sanity-check input before we bother
// the network.
constexpr int kKeyLength = 200;

} // namespace license
