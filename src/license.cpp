#include "license.h"
#include "log.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#include <fstream>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace license {

// Where the client points when there's no license.cfg. Localhost while
// you're developing; put the real domain in license.cfg to move it.
const char* const kDefaultServer = "http://127.0.0.1:8443";

namespace {

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string NetvisDir() {
    char base[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramFiles", base, sizeof(base));
    std::string dir = (n > 0 && n < sizeof(base)) ? std::string(base) + "\\netvis" : "C:\\Program Files\\netvis";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
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
    static const std::string url = [] {
        std::string path = NetvisDir() + "\\license.cfg";
        std::ifstream f(path);
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                line = Trim(line);
                if (line.empty() || line[0] == '#') continue;
                if (line.rfind("server=", 0) == 0) {
                    std::string v = Trim(line.substr(7));
                    while (!v.empty() && v.back() == '/') v.pop_back();
                    if (!v.empty()) {
                        Log("license: using server from license.cfg");
                        return v;
                    }
                }
            }
        }
        // Write the default out once so there's an obvious file to edit
        // when the server moves to a real domain.
        std::ofstream o(path, std::ios::app);
        if (o.tellp() == std::streampos(0)) {
            o << "# netvis licensing server. Change this when you move off localhost,\n"
                 "# e.g. server=https://licensing.yourdomain.com\n"
              << "server=" << kDefaultServer << "\n";
        }
        Log("license: using default server");
        return std::string(kDefaultServer);
    }();
    return url;
}

Status Authenticate() {
    Response r = Request(L"GET", "/authentificate/" + HWID(), "");
    if (!r.sent) {
        Log("license: server unreachable");
        return Status::Unreachable;
    }
    if (r.status == 200 && JsonBoolTrue(r.body, "ok")) {
        Log("license: machine is licensed");
        return Status::Licensed;
    }
    Log("license: not licensed (http %lu)", (unsigned long)r.status);
    return Status::NotLicensed;
}

bool Activate(const std::string& key, std::string* error) {
    if ((int)key.size() != kKeyLength) {
        if (error) *error = "A license key is " + std::to_string(kKeyLength) + " characters long.";
        return false;
    }
    // Keys are base32 (A-Z, 2-7); reject anything else before we go to the
    // network, and before it can end up in a URL.
    for (char c : key) {
        bool valid = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
        if (!valid) {
            if (error) *error = "That key contains characters a license key can't have.";
            return false;
        }
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
