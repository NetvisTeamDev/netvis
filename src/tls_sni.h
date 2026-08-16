// Reads the SNI (server name) out of a TLS ClientHello, without decrypting
// anything.
//
// This is the whole trick behind blocking DoH properly. A DNS-over-HTTPS
// request looks like ordinary HTTPS on port 443, so you can't tell it apart
// by port - but the very first packet a TLS client sends, the ClientHello,
// carries the destination hostname in the clear, in the Server Name
// Indication extension. So netvis can see that a connection is headed for
// "cloudflare-dns.com" and drop it, for ANY IP address, while never touching
// the encrypted body. No root certificate, no man-in-the-middle, no decryption
// - just reading a field the client itself sends unencrypted.
//
// (The one thing that hides the SNI is Encrypted Client Hello. That isn't a
// hole here: ECH needs its keys fetched from a DNS HTTPS record first, and
// once DoH is forced back to plain DNS - which is the point of all this - a
// blocked domain's records are NXDOMAIN'd before any ECH key can arrive.)
//
// The parser is deliberately paranoid. Every read is bounds-checked against
// the buffer, and anything malformed, truncated, or split across packets
// returns an empty string rather than reading past the end - a crash in the
// blocker thread would take ad-blocking down with it.
#pragma once
#include <cstdint>
#include <string>

namespace tls {

// True if buf looks like the start of a TLS handshake ClientHello record.
// Cheap enough to gate the fuller parse on.
inline bool IsClientHello(const uint8_t* buf, uint32_t len) {
    //  [0]    content type 0x16 = handshake
    //  [1..2] legacy record version
    //  [3..4] record length
    //  [5]    handshake type 0x01 = ClientHello
    return len >= 6 && buf[0] == 0x16 && buf[5] == 0x01;
}

// Returns the lowercased SNI host name, or "" if there isn't one / the record
// is malformed or incomplete. `payload` points at the TCP payload (the TLS
// record), `len` is its length.
inline std::string ExtractSNI(const uint8_t* payload, uint32_t len) {
    if (!IsClientHello(payload, len)) return "";

    // A tiny cursor with bounds checks. need(n) guarantees n more bytes.
    uint32_t p = 0;
    auto avail = [&](uint32_t n) -> bool { return p + n <= len; };

    // Record header (5) + handshake header (4). We already know [0]=0x16 and
    // [5]=0x01 from IsClientHello.
    p = 5;                       // start of the handshake message
    if (!avail(4)) return "";
    p += 4;                      // handshake type (1) + length (3)

    if (!avail(2)) return "";
    p += 2;                      // client_version
    if (!avail(32)) return "";
    p += 32;                     // random

    // session_id
    if (!avail(1)) return "";
    uint8_t sidLen = payload[p]; p += 1;
    if (!avail(sidLen)) return "";
    p += sidLen;

    // cipher_suites
    if (!avail(2)) return "";
    uint32_t csLen = (uint32_t(payload[p]) << 8) | payload[p + 1]; p += 2;
    if (!avail(csLen)) return "";
    p += csLen;

    // compression_methods
    if (!avail(1)) return "";
    uint8_t cmLen = payload[p]; p += 1;
    if (!avail(cmLen)) return "";
    p += cmLen;

    // extensions
    if (!avail(2)) return "";
    uint32_t extTotal = (uint32_t(payload[p]) << 8) | payload[p + 1]; p += 2;
    uint32_t extEnd = p + extTotal;
    if (extEnd > len) extEnd = len;   // clamp: a truncated tail just means we scan what we have

    while (p + 4 <= extEnd) {
        uint32_t extType = (uint32_t(payload[p]) << 8) | payload[p + 1];
        uint32_t extLen = (uint32_t(payload[p + 2]) << 8) | payload[p + 3];
        p += 4;
        if (p + extLen > extEnd) return "";   // extension runs past the buffer

        if (extType == 0x0000) {              // server_name
            uint32_t e = p;
            uint32_t eEnd = p + extLen;
            // ServerNameList: list length (2), then entries of
            // { name_type (1), name_len (2), name }.
            if (e + 2 > eEnd) return "";
            e += 2;                            // skip server_name_list length
            while (e + 3 <= eEnd) {
                uint8_t nameType = payload[e];
                uint32_t nameLen = (uint32_t(payload[e + 1]) << 8) | payload[e + 2];
                e += 3;
                if (e + nameLen > eEnd) return "";
                if (nameType == 0x00) {        // host_name
                    std::string host;
                    host.reserve(nameLen);
                    for (uint32_t i = 0; i < nameLen; i++) {
                        char c = (char)payload[e + i];
                        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
                        host.push_back(c);
                    }
                    return host;
                }
                e += nameLen;
            }
            return "";                         // server_name ext with no host_name
        }
        p += extLen;
    }
    return "";                                 // no SNI extension present
}

} // namespace tls
