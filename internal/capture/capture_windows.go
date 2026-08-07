//go:build windows

// Package capture passively observes IP traffic using WinDivert directly,
// via raw syscalls into WinDivert.dll, in "sniff" mode: packets are copied
// to us but never removed from the network stack, so this can never break
// the user's connectivity even if the program crashes mid-packet.
//
// This talks to WinDivert.dll directly rather than through a Go binding
// library. The available community binding (williamfhe/godivert) was
// written against WinDivert's pre-2.0 C ABI. WinDivert 2.x reordered the
// WinDivertRecv/WinDivertSend parameters (pRecvLen now comes before pAddr,
// not after) and changed the WINDIVERT_ADDRESS layout, so that binding
// corrupts memory when paired with a modern WinDivert.dll - which is
// exactly what was crashing netvis (panic: slice bounds out of range,
// from a garbage packet length written into the wrong memory slot).
package capture

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	layerNetwork = 0 // WINDIVERT_LAYER_NETWORK

	flagSniff = 0x0001 // WINDIVERT_FLAG_SNIFF

	addressSize = 80    // sizeof(WINDIVERT_ADDRESS), see doc comment on outboundBit
	bufferSize  = 65575 // WINDIVERT_MTU_MAX (40 + 0xFFFF): largest possible IP packet
)

var (
	winDivertDLL = syscall.NewLazyDLL("WinDivert.dll")
	procOpen     = winDivertDLL.NewProc("WinDivertOpen")
	procRecv     = winDivertDLL.NewProc("WinDivertRecv")
	procClose    = winDivertDLL.NewProc("WinDivertClose")
)

// Event is a single observed packet, reduced to what the monitor needs to
// attribute it to a process.
type Event struct {
	Proto     string // "tcp" or "udp"
	LocalPort uint16
	Bytes     uint64
	Inbound   bool
}

// Sniffer captures IP traffic passively.
type Sniffer struct {
	handle uintptr
	events chan Event
	closed atomic.Bool
}

// New opens a WinDivert handle in sniff mode. This requires the process to
// be running elevated (Administrator) and WinDivert.dll / WinDivert64.sys
// to be present next to the executable - see README.md.
func New() (*Sniffer, error) {
	filterPtr, err := syscall.BytePtrFromString("true")
	if err != nil {
		return nil, err
	}

	// HANDLE WinDivertOpen(filter, layer, priority, flags)
	handle, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layerNetwork),
		uintptr(0), // priority
		uintptr(flagSniff),
	)
	if handle == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return nil, fmt.Errorf("WinDivertOpen failed: %w", callErr)
	}

	return &Sniffer{
		handle: handle,
		events: make(chan Event, 4096),
	}, nil
}

// Events returns the channel captured events are published on. Consume it
// promptly - if the buffer fills, further events are dropped rather than
// blocking capture (see handlePacket).
func (s *Sniffer) Events() <-chan Event {
	return s.events
}

// Run reads packets until Close is called or the driver reports a real
// error. Intended to be run in its own goroutine; blocks until then.
func (s *Sniffer) Run() error {
	buf := make([]byte, bufferSize)

	for {
		var addr [addressSize]byte
		var recvLen uint32

		// BOOL WinDivertRecv(handle, pPacket, packetLen, pRecvLen, pAddr)
		ret, _, callErr := procRecv.Call(
			s.handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ret == 0 {
			if s.closed.Load() {
				return nil // Close() unblocked us on purpose - not an error
			}
			return fmt.Errorf("WinDivertRecv failed: %w", callErr)
		}

		s.handlePacket(buf[:recvLen], &addr)
	}
}

func (s *Sniffer) handlePacket(raw []byte, addr *[addressSize]byte) {
	proto, srcPort, dstPort, ok := parseTransportPorts(raw)
	if !ok {
		return // not TCP/UDP (e.g. ICMP), or too short to parse - skip
	}

	inbound := !outbound(addr)

	localPort := srcPort
	if inbound {
		localPort = dstPort
	}

	ev := Event{
		Proto:     proto,
		LocalPort: localPort,
		Bytes:     uint64(len(raw)),
		Inbound:   inbound,
	}

	select {
	case s.events <- ev:
	default:
		// Monitor can't keep up - drop rather than block the capture loop.
	}
}

// outbound reads the "Outbound" bit out of a WINDIVERT_ADDRESS.
//
// Layout (see windivert.h): INT64 Timestamp (offset 0); then a UINT32
// bitfield (offset 8) packing Layer:8, Event:8, Sniffed:1, Outbound:1,
// Loopback:1, Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1,
// UDPChecksum:1, Reserved1:8 - Windows packs bitfields LSB-first, so
// Outbound is bit 17 overall (bit 9 of that dword). Then UINT32 Reserved2
// (offset 12); then a 64-byte union (offset 16), giving 80 bytes total.
func outbound(addr *[addressSize]byte) bool {
	flags := binary.LittleEndian.Uint32(addr[8:12])
	return (flags>>9)&1 != 0
}

// parseTransportPorts pulls the protocol and ports out of a raw IPv4/IPv6
// packet. Returns ok=false for anything that isn't TCP or UDP (e.g. ICMP),
// or that's too short to parse safely.
func parseTransportPorts(raw []byte) (proto string, srcPort, dstPort uint16, ok bool) {
	if len(raw) < 1 {
		return "", 0, 0, false
	}

	var hdrLen int
	var protocolByte byte

	switch version := raw[0] >> 4; version {
	case 4:
		if len(raw) < 20 {
			return "", 0, 0, false
		}
		hdrLen = int(raw[0]&0x0F) * 4
		protocolByte = raw[9]
	case 6:
		if len(raw) < 40 {
			return "", 0, 0, false
		}
		hdrLen = 40 // fixed IPv6 header; extension headers not handled (v1 limitation)
		protocolByte = raw[6]
	default:
		return "", 0, 0, false
	}

	switch protocolByte {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		return "", 0, 0, false
	}

	if len(raw) < hdrLen+4 {
		return "", 0, 0, false
	}
	transport := raw[hdrLen:]
	srcPort = binary.BigEndian.Uint16(transport[0:2])
	dstPort = binary.BigEndian.Uint16(transport[2:4])
	return proto, srcPort, dstPort, true
}

// Close stops the capture loop and releases the WinDivert handle.
func (s *Sniffer) Close() error {
	s.closed.Store(true)
	ret, _, callErr := procClose.Call(s.handle)
	if ret == 0 {
		return callErr
	}
	return nil
}
