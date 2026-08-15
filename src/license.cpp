#include "license.h"
#include "log.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace license {

// The licensing server, compiled in. Deliberately not configurable at
// runtime: a settings file holding this address is a one-line licence
// bypass, since anyone could point netvis at a server of their own that
// answers "licensed" to everything. Changing it means a rebuild.
//
// It is https for the same reason - redirecting the name with a hosts file
// gets you a certificate error rather than a working fake server, because
// WinHTTP validates against the Windows certificate store.
const char* const kServer = "https://netvis.cc";

namespace {

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

// ---- HWID ---------------------------------------------------------------

// MachineGuid is written by Windows at install time and never changes on
// its own - the closest thing Windows has to a machine serial that any
// process can read. Explicitly 64-bit view, because a 32-bit build would
// otherwise be redirected to the WOW6432Node copy and get a different value.
std::string MachineGuid() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return "";
    wchar_t buf[128] = {};
    DWORD size = sizeof(buf), type = 0;
    LONG rc = RegQueryValueExW(key, L"MachineGuid", nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return "";

    char out[128] = {};
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, out, sizeof(out), nullptr, nullptr);
    return out;
}

std::string SystemVolumeSerial() {
    DWORD serial = 0;
    if (!GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) return "";
    char buf[16];
    snprintf(buf, sizeof(buf), "%08lX", (unsigned long)serial);
    return buf;
}

// SHA-256, hex, truncated to 32 chars. Hashing means the raw MachineGuid
// never leaves the machine, and 128 bits is far more than enough to keep
// two customers from colliding.
std::string HashHex(const std::string& in) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;

    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return out;
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(hash, (const BYTE*)in.data(), (DWORD)in.size(), 0)) {
            BYTE digest[32];
            DWORD len = sizeof(digest);
            if (CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0)) {
                char hex[65];
                for (DWORD i = 0; i < len; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
                out.assign(hex, 32); // 128 bits is plenty
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

// ---- tiny JSON helpers --------------------------------------------------

// The server's replies are flat and machine-generated, so a full JSON
// parser would be overkill. These just look for the one field we care about.
bool JsonBoolTrue(const std::string& body, const char* field) {
    std::string needle = std::string("\"") + field + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return false;
    p = body.find(':', p + needle.size());
    if (p == std::string::npos) return false;
    p = body.find_first_not_of(" \t", p + 1);
    if (p == std::string::npos) return false;
    return body.compare(p, 4, "true") == 0;
}

std::string JsonString(const std::string& body, const char* field) {
    std::string needle = std::string("\"") + field + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return "";
    p = body.find(':', p + needle.size());
    if (p == std::string::npos) return "";
    size_t q = body.find('"', p);
    if (q == std::string::npos) return "";
    size_t e = body.find('"', q + 1);
    if (e == std::string::npos) return "";
    return body.substr(q + 1, e - q - 1);
}

// ---- HTTP ---------------------------------------------------------------

struct Response {
    bool sent = false; // false = couldn't reach the server at all
    DWORD status = 0;
    std::string body;
};

// One-shot WinHTTP request. `path` must already start with '/'.
Response Request(const wchar_t* verb, const std::string& path, const std::string& body) {
    Response out;

    std::wstring url = Widen(ServerURL());
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) {
        Log("license: configured server URL is not valid");
        return out;
    }
    bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;

    HINTERNET session = WinHttpOpen(L"netvis", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return out;

    // Don't let a hung server hold up app startup.
    WinHttpSetTimeouts(session, 4000, 4000, 6000, 6000);

    HINTERNET conn = WinHttpConnect(session, host, uc.nPort, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        return out;
    }

    std::wstring wpath = Widen(path);
    HINTERNET req = WinHttpOpenRequest(conn, verb, wpath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return out;
    }

    const wchar_t* headers = body.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS
                                          : L"Content-Type: application/json\r\n";
    BOOL ok = WinHttpSendRequest(req, headers, (DWORD)-1,
                                 body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                                 (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(req, nullptr);

    if (ok) {
        out.sent = true;
        DWORD size = sizeof(out.status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &out.status, &size, WINHTTP_NO_HEADER_INDEX);

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(req, chunk.data(), avail, &read)) break;
            out.body.append(chunk, 0, read);
            if (out.body.size() > 64 * 1024) break; // the server never sends anything this big
        }
    } else {
        Log("license: request failed, GetLastError=%lu", (unsigned long)GetLastError());
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return out;
}

} // namespace

// ---- public -------------------------------------------------------------

const std::string& HWID() {
    static const std::string id = [] {
        std::string raw = MachineGuid() + "|" + SystemVolumeSerial();
        std::string h = HashHex(raw);
        if (h.empty()) h = "unknown"; // hashing can only fail if CryptoAPI is broken
        Log("license: hwid computed");
        return h;
    }();
    return id;
}

const std::string& ServerURL() {
    static const std::string url = kServer;
    return url;
}

namespace {
std::atomic<int> g_lastDaysLeft{-1};

// Pulls an integer field out of a flat JSON object, or -1 if absent.
int JsonInt(const std::string& body, const char* field) {
    std::string needle = std::string("\"") + field + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return -1;
    p = body.find(':', p + needle.size());
    if (p == std::string::npos) return -1;
    p = body.find_first_not_of(" \t", p + 1);
    if (p == std::string::npos || !isdigit((unsigned char)body[p])) return -1;
    return atoi(body.c_str() + p);
}
} // namespace

int LastDaysLeft() { return g_lastDaysLeft.load(); }

Result AuthenticateEx() {
    Result out;
    Response r = Request(L"GET", "/authentificate/" + HWID(), "");
    if (!r.sent) {
        Log("license: server unreachable");
        out.status = Status::Unreachable;
        return out;
    }
    if (r.status == 200 && JsonBoolTrue(r.body, "ok")) {
        out.status = Status::Licensed;
        out.daysLeft = JsonInt(r.body, "days_left");
        g_lastDaysLeft.store(out.daysLeft);
        Log("license: machine is licensed (%d days left)", out.daysLeft);
        return out;
    }
    // The server distinguishes "ran out" from "never activated" so the user
    // gets told to renew rather than being asked for a key they already own.
    if (JsonString(r.body, "error") == "expired") {
        Log("license: licence expired");
        g_lastDaysLeft.store(0);
        out.status = Status::Expired;
        return out;
    }
    Log("license: not licensed (http %lu)", (unsigned long)r.status);
    out.status = Status::NotLicensed;
    return out;
}

Status Authenticate() { return AuthenticateEx().status; }

std::string Normalize(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (unsigned char c : raw) {
        char u = (char)toupper(c);
        // Letters, digits, dash and underscore are key material; spaces and
        // line breaks from a paste are not. Dashes matter here - Polar's
        // keys are NETVIS_1C285B2D-6CE6-..., and stripping them would turn
        // a valid key into a rejected one.
        if ((u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9') || u == '-' || u == '_') out += u;
    }
    return out;
}

bool PlausibleKey(const std::string& normalized) {
    return (int)normalized.size() >= kKeyMinLength && (int)normalized.size() <= kKeyMaxLength;
}

bool Activate(const std::string& rawKey, std::string* error) {
    // Normalise here too, not just in the UI, so any other caller gets the
    // same forgiving behaviour.
    std::string key = Normalize(rawKey);
    if (!PlausibleKey(key)) {
        if (error) *error = "That doesn't look like a license key.";
        return false;
    }

    std::string body = "{\"hwid\":\"" + HWID() + "\",\"os\":\"windows\"}";
    Response r = Request(L"POST", "/validate/" + key, body);

    if (!r.sent) {
        if (error) *error = "Couldn't reach the licensing server. Check your internet connection.";
        return false;
    }
    if (r.status == 200 && JsonBoolTrue(r.body, "ok")) {
        Log("license: activated this machine");
        return true;
    }
    std::string serverMsg = JsonString(r.body, "error");
    if (error) *error = serverMsg.empty() ? "The server rejected that license key." : serverMsg;
    Log("license: activation failed (http %lu): %s", (unsigned long)r.status, error ? error->c_str() : "");
    return false;
}

} // namespace license
