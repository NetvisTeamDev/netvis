// Minimal WinDivert binding: declares just the handful of functions/
// constants netvis needs, loaded dynamically via LoadLibrary/GetProcAddress
// so we don't need the official WinDivert SDK (headers + import lib) to
// build - only WinDivert.dll + WinDivert64.sys need to sit next to the exe
// at runtime, same approach used in the original Go version.
//
// Struct layout / bit offsets below were reverse-engineered against real
// WinDivert 2.2.x behavior (see WINDIVERT_ADDRESS notes) - the archived
// unofficial language bindings that exist for some ecosystems use a
// pre-2.0 ABI and will corrupt memory against a modern WinDivert.dll, so
// don't be tempted to copy signatures from anywhere except the real
// basil00/WinDivert C header.
#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace wd {

constexpr int LAYER_NETWORK = 0;
constexpr int LAYER_SOCKET = 3;
constexpr uint64_t FLAG_SNIFF = 0x0001;
constexpr uint64_t FLAG_RECV_ONLY = 0x0004; // required by WinDivert for SOCKET/FLOW layer handles - sending back a socket event is not a meaningful operation, so the driver rejects WinDivertOpen at those layers unless this is set.
constexpr uint32_t MTU_MAX = 65535 + 40; // WINDIVERT_MTU_MAX

// WINDIVERT_ADDRESS is 80 bytes. We only need to read the Outbound bit out
// of it and otherwise treat it as an opaque blob to pass back to Send
// unchanged, so a raw byte array is enough - no need to reproduce the full
// bitfield struct.
constexpr int ADDRESS_SIZE = 80;
using Address = uint8_t[ADDRESS_SIZE];

// Byte offset 8 holds a little-endian uint32 of bitfields, packed from the
// least significant bit up:
//
//   bits  0-7   Layer
//   bits  8-15  Event
//   bit  16     Sniffed
//   bit  17     Outbound
//   bit  18     Loopback
//   bit  19     Impostor
//   bit  20     IPv6
//
// So Outbound is bit 17. This previously read bit 9, which lands inside
// Event - and Event is 0 for an ordinary captured packet, so the answer was
// always "inbound". Every byte the machine sent was counted as download,
// the upload line of the graph never moved, and upload rate limits could
// never fire because no packet was ever seen as outbound.
inline bool IsOutbound(const Address& addr) {
    uint32_t flags;
    memcpy(&flags, addr + 8, sizeof(flags));
    return (flags >> 17) & 1;
}

inline void ZeroAddress(Address& addr) { memset(addr, 0, sizeof(addr)); }

// Function pointer types matching the real WinDivert 2.x C ABI.
using OpenFn = HANDLE(WINAPI*)(const char* filter, int layer, int16_t priority, uint64_t flags);
using RecvFn = BOOL(WINAPI*)(HANDLE handle, void* pPacket, uint32_t packetLen, uint32_t* pRecvLen, Address* pAddr);
using SendFn = BOOL(WINAPI*)(HANDLE handle, const void* pPacket, uint32_t packetLen, uint32_t* pSendLen, const Address* pAddr);
using CloseFn = BOOL(WINAPI*)(HANDLE handle);
using CalcChecksumsFn = BOOL(WINAPI*)(void* pPacket, uint32_t packetLen, Address* pAddr, uint64_t flags);

struct Api {
    OpenFn Open = nullptr;
    RecvFn Recv = nullptr;
    SendFn Send = nullptr;
    CloseFn Close = nullptr;
    CalcChecksumsFn CalcChecksums = nullptr;
    HMODULE dll = nullptr;
};

// Loads WinDivert.dll (must be next to the exe, or on PATH) and resolves
// the functions above. Returns false with `error` set on failure - most
// commonly because the exe wasn't run as Administrator, or WinDivert.dll /
// WinDivert64.sys aren't present.
bool LoadApi(Api& api, std::string* error);

} // namespace wd
