#include "updater.h"
#include "version.h"
#include "license.h" // VerifyDetached, kUpdatePublicKey
#include "log.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <shellapi.h>

#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace updater {

namespace {

// Everything is served from this one host over HTTPS. Fixed here for the same
// reason the license server is: nothing at runtime should be able to point the
// updater somewhere else. The download URL inside the manifest is checked
// against this too, even though the manifest is signed - defence in depth.
const wchar_t* kHost = L"netvis.cc";
const char* kHostAscii = "netvis.cc";
const std::string kManifestPath = "/updates/windows/update.json";
const std::string kSigPath = "/updates/windows/update.json.sig";

std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

// ---- HTTP ---------------------------------------------------------------

struct GetResult {
    bool ok = false;
    DWORD status = 0;
    std::string body;
};

// Opens an HTTPS request to netvis.cc for `path`. Caller drives the read.
// Returns the request/connection/session handles via out-params so both the
// small GET and the streamed download can share the setup.
bool OpenGet(const std::string& path, HINTERNET& session, HINTERNET& conn, HINTERNET& req) {
    session = WinHttpOpen(L"netvis-updater", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    WinHttpSetTimeouts(session, 5000, 5000, 30000, 60000);

    conn = WinHttpConnect(session, kHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(session); session = nullptr; return false; }

    req = WinHttpOpenRequest(conn, L"GET", Widen(path).c_str(), nullptr, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        conn = session = nullptr; return false;
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        req = conn = session = nullptr; return false;
    }
    return true;
}

DWORD StatusOf(HINTERNET req) {
    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    return status;
}

// Small GET (manifest, signature). Caps the body so a hostile server can't
// make us allocate forever; these files are a few hundred bytes.
GetResult HttpGetSmall(const std::string& path) {
    GetResult out;
    HINTERNET s = nullptr, c = nullptr, r = nullptr;
    if (!OpenGet(path, s, c, r)) return out;
    out.status = StatusOf(r);
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(r, &avail) && avail > 0) {
        std::string chunk(avail, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(r, chunk.data(), avail, &read)) break;
        out.body.append(chunk, 0, read);
        if (out.body.size() > 256 * 1024) break;
    }
    out.ok = out.status == 200;
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return out;
}

// Streams a download straight to `destFile`. No size cap in memory (it goes to
// disk); the SHA-256 check afterwards is what makes the result trustworthy.
bool HttpDownload(const std::string& path, const std::wstring& destFile) {
    HINTERNET s = nullptr, c = nullptr, r = nullptr;
    if (!OpenGet(path, s, c, r)) return false;
    bool ok = StatusOf(r) == 200;
    HANDLE fh = INVALID_HANDLE_VALUE;
    if (ok) {
        fh = CreateFileW(destFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fh == INVALID_HANDLE_VALUE) ok = false;
    }
    if (ok) {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(r, &avail) && avail > 0) {
            std::vector<char> buf(avail);
            DWORD read = 0;
            if (!WinHttpReadData(r, buf.data(), avail, &read)) { ok = false; break; }
            DWORD wrote = 0;
            if (!WriteFile(fh, buf.data(), read, &wrote, nullptr) || wrote != read) { ok = false; break; }
        }
    }
    if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);
    return ok;
}

// ---- helpers ------------------------------------------------------------

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

// True if version `a` is strictly newer than `b`, comparing dotted numeric
// components (1.10.0 > 1.9.0). Non-numeric or missing parts count as 0.
bool VersionNewer(const std::string& a, const std::string& b) {
    auto parts = [](const std::string& v) {
        std::vector<long> out;
        size_t i = 0;
        while (i < v.size()) {
            long n = 0;
            bool any = false;
            while (i < v.size() && v[i] >= '0' && v[i] <= '9') { n = n * 10 + (v[i] - '0'); i++; any = true; }
            out.push_back(any ? n : 0);
            while (i < v.size() && v[i] != '.') i++; // skip pre-release suffixes
            if (i < v.size() && v[i] == '.') i++;
        }
        return out;
    };
    std::vector<long> va = parts(a), vb = parts(b);
    size_t n = va.size() > vb.size() ? va.size() : vb.size();
    for (size_t i = 0; i < n; i++) {
        long x = i < va.size() ? va[i] : 0;
        long y = i < vb.size() ? vb[i] : 0;
        if (x != y) return x > y;
    }
    return false;
}

std::string ToLowerHex(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'F') c = char(c - 'A' + 'a');
    return s;
}

// SHA-256 of a file on disk, lowercase hex, using CryptoAPI (no extra deps).
std::string Sha256OfFile(const std::wstring& path) {
    HANDLE fh = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return "";
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
            std::vector<BYTE> buf(64 * 1024);
            DWORD read = 0;
            bool ok = true;
            while (ReadFile(fh, buf.data(), (DWORD)buf.size(), &read, nullptr) && read > 0) {
                if (!CryptHashData(hash, buf.data(), read, 0)) { ok = false; break; }
            }
            if (ok) {
                BYTE digest[32];
                DWORD len = sizeof(digest);
                if (CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0) && len == 32) {
                    char hex[65];
                    for (DWORD i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
                    out.assign(hex, 64);
                }
            }
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
    }
    CloseHandle(fh);
    return out;
}

// Turns an absolute manifest URL into a path we can fetch, but only if it
// really is https://netvis.cc/... - a signed manifest still shouldn't be able
// to point the downloader at an arbitrary host.
bool PathFromNetvisURL(const std::string& url, std::string& pathOut) {
    const std::string prefix = std::string("https://") + kHostAscii;
    if (url.compare(0, prefix.size(), prefix) != 0) return false;
    std::string rest = url.substr(prefix.size());
    if (rest.empty() || rest[0] != '/') return false;
    pathOut = rest;
    return true;
}

std::wstring TempPathFor(const std::string& version) {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring name = L"netvis-update-" + Widen(version) + L".exe";
    return std::wstring(tmp) + name;
}

} // namespace

// ---- public -------------------------------------------------------------

const char* CurrentVersion() { return NETVIS_VERSION; }

Release Check() {
    Release out;

    GetResult manifest = HttpGetSmall(kManifestPath);
    if (!manifest.ok) {
        Log("updater: manifest unreachable (http %lu)", (unsigned long)manifest.status);
        return out; // checked stays false
    }
    GetResult sig = HttpGetSmall(kSigPath);
    if (!sig.ok) {
        Log("updater: signature unreachable (http %lu)", (unsigned long)sig.status);
        return out;
    }

    // Trim whitespace/newlines around the signature; verify over the EXACT
    // manifest bytes we received.
    std::string sigHex;
    for (char c : sig.body)
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) sigHex += c;

    if (!license::VerifyDetached(manifest.body, sigHex, license::kUpdatePublicKey)) {
        Log("updater: manifest signature INVALID - ignoring");
        out.checked = true; // we reached the server, but won't trust this
        return out;
    }

    out.checked = true;
    out.version = JsonString(manifest.body, "version");
    out.url = JsonString(manifest.body, "url");
    out.sha256 = ToLowerHex(JsonString(manifest.body, "sha256"));
    out.notes = JsonString(manifest.body, "notes");

    if (out.version.empty() || out.url.empty() || out.sha256.size() != 64) {
        Log("updater: manifest verified but malformed - ignoring");
        out.newer = false;
        return out;
    }
    out.newer = VersionNewer(out.version, NETVIS_VERSION);
    Log("updater: current %s, latest %s -> %s", NETVIS_VERSION, out.version.c_str(),
        out.newer ? "update available" : "up to date");
    return out;
}

bool Apply(const Release& r, std::string* error) {
    auto fail = [&](const char* m) { if (error) *error = m; Log("updater: %s", m); return false; };

    if (!r.newer || r.url.empty() || r.sha256.size() != 64)
        return fail("no verified update to apply");

    std::string path;
    if (!PathFromNetvisURL(r.url, path))
        return fail("update URL is not on netvis.cc - refusing");

    std::wstring dest = TempPathFor(r.version);
    Log("updater: downloading %s", r.url.c_str());
    if (!HttpDownload(path, dest))
        return fail("download failed");

    std::string got = Sha256OfFile(dest);
    if (got.empty() || got != r.sha256) {
        DeleteFileW(dest.c_str());
        return fail("downloaded file failed its SHA-256 check - discarded");
    }
    Log("updater: download verified, launching installer");

    // Launch the installer silently. Its manifest is requireAdministrator, so
    // Windows raises the UAC prompt; it then stops the running netvis (taskkill
    // in the installer) and replaces it. /NORESTART leaves relaunching to us or
    // the user, so nothing starts a second copy mid-swap.
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"open";
    sei.lpFile = dest.c_str();
    sei.lpParameters = L"/SILENT /SUPPRESSMSGBOXES /NORESTART";
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei))
        return fail("could not launch the installer");

    return true; // caller should now exit so the installer can replace files
}

} // namespace updater
