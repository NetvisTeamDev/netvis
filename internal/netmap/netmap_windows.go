//go:build windows

// Package netmap maps local (protocol, port) pairs to the PID that owns
// them, by reading the same tables Windows' own `netstat -ano` reads
// (GetExtendedTcpTable / GetExtendedUdpTable from iphlpapi.dll).
package netmap

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	afInet  = 2  // AF_INET
	afInet6 = 23 // AF_INET6

	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID

	errInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
)

var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTbl = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTbl = iphlpapi.NewProc("GetExtendedUdpTable")
)

// Conn identifies a local endpoint we saw traffic on.
type Conn struct {
	Proto     string // "tcp" or "udp"
	LocalPort uint16
}

// Table is a snapshot mapping a local (proto, port) to the owning PID.
// Safe for concurrent use: one goroutine should call Refresh (or
// RunPeriodicRefresh) while others call Lookup.
type Table struct {
	mu   sync.RWMutex
	byPt map[Conn]uint32
}

// NewTable returns an empty table. Call Refresh (or RunPeriodicRefresh)
// before relying on Lookup.
func NewTable() *Table {
	return &Table{byPt: make(map[Conn]uint32)}
}

// Lookup returns the PID that currently owns the given local port for the
// given protocol ("tcp" or "udp"), and whether it was found.
func (t *Table) Lookup(proto string, localPort uint16) (uint32, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pid, ok := t.byPt[Conn{Proto: proto, LocalPort: localPort}]
	return pid, ok
}

// Refresh re-reads the OS connection tables (TCP/UDP, v4/v6) and atomically
// swaps them in. Cheap enough to call every second or two.
func (t *Table) Refresh() error {
	next := make(map[Conn]uint32)

	if err := readTCP(afInet, next); err != nil {
		return fmt.Errorf("netmap: tcp4: %w", err)
	}
	if err := readTCP(afInet6, next); err != nil {
		return fmt.Errorf("netmap: tcp6: %w", err)
	}
	if err := readUDP(afInet, next); err != nil {
		return fmt.Errorf("netmap: udp4: %w", err)
	}
	if err := readUDP(afInet6, next); err != nil {
		return fmt.Errorf("netmap: udp6: %w", err)
	}

	t.mu.Lock()
	t.byPt = next
	t.mu.Unlock()
	return nil
}

// RunPeriodicRefresh calls Refresh once immediately and then on every tick
// of interval, until stop is closed. Errors are swallowed (the table just
// keeps its previous, slightly stale contents) since a single failed read
// shouldn't take the whole monitor down.
func (t *Table) RunPeriodicRefresh(interval time.Duration, stop <-chan struct{}) {
	_ = t.Refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_ = t.Refresh()
		}
	}
}

// getTable calls a GetExtended{Tcp,Udp}Table-shaped function, growing the
// buffer until it fits, and returns the raw table bytes.
func getTable(proc *syscall.LazyProc, af uint32, class uint32) ([]byte, error) {
	size := uint32(8192)
	for tries := 0; tries < 5; tries++ {
		buf := make([]byte, size)
		ret, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder = FALSE, don't need it sorted
			uintptr(af),
			uintptr(class),
			0, // Reserved
		)
		switch ret {
		case 0:
			if int(size) > len(buf) {
				size = uint32(len(buf))
			}
			return buf[:size], nil
		case errInsufficientBuffer:
			continue // size now holds the required size; retry with it
		default:
			return nil, fmt.Errorf("iphlpapi call failed: code %d", ret)
		}
	}
	return nil, fmt.Errorf("could not read table after retries")
}

func readTCP(af uint32, out map[Conn]uint32) error {
	buf, err := getTable(procGetExtendedTcpTbl, af, tcpTableOwnerPidAll)
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	const headerLen = 4

	rowSize := 24 // MIB_TCPROW_OWNER_PID (v4): 6 x DWORD
	if af == afInet6 {
		rowSize = 56 // MIB_TCP6ROW_OWNER_PID
	}

	for i := uint32(0); i < n; i++ {
		start := headerLen + int(i)*rowSize
		if start+rowSize > len(buf) {
			break
		}
		row := buf[start : start+rowSize]

		var localPortRaw, pid uint32
		if af == afInet {
			// dwState(0:4) dwLocalAddr(4:8) dwLocalPort(8:12) dwRemoteAddr(12:16) dwRemotePort(16:20) dwOwningPid(20:24)
			localPortRaw = binary.LittleEndian.Uint32(row[8:12])
			pid = binary.LittleEndian.Uint32(row[20:24])
		} else {
			// ucLocalAddr[16](0:16) dwLocalScopeId(16:20) dwLocalPort(20:24) ucRemoteAddr[16](24:40) dwRemoteScopeId(40:44) dwRemotePort(44:48) dwState(48:52) dwOwningPid(52:56)
			localPortRaw = binary.LittleEndian.Uint32(row[20:24])
			pid = binary.LittleEndian.Uint32(row[52:56])
		}
		out[Conn{Proto: "tcp", LocalPort: portFromDword(localPortRaw)}] = pid
	}
	return nil
}

func readUDP(af uint32, out map[Conn]uint32) error {
	buf, err := getTable(procGetExtendedUdpTbl, af, udpTableOwnerPid)
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	const headerLen = 4

	rowSize := 12 // MIB_UDPROW_OWNER_PID (v4): 3 x DWORD
	if af == afInet6 {
		rowSize = 28 // MIB_UDP6ROW_OWNER_PID
	}

	for i := uint32(0); i < n; i++ {
		start := headerLen + int(i)*rowSize
		if start+rowSize > len(buf) {
			break
		}
		row := buf[start : start+rowSize]

		var localPortRaw, pid uint32
		if af == afInet {
			// dwLocalAddr(0:4) dwLocalPort(4:8) dwOwningPid(8:12)
			localPortRaw = binary.LittleEndian.Uint32(row[4:8])
			pid = binary.LittleEndian.Uint32(row[8:12])
		} else {
			// ucLocalAddr[16](0:16) dwLocalScopeId(16:20) dwLocalPort(20:24) dwOwningPid(24:28)
			localPortRaw = binary.LittleEndian.Uint32(row[20:24])
			pid = binary.LittleEndian.Uint32(row[24:28])
		}
		out[Conn{Proto: "udp", LocalPort: portFromDword(localPortRaw)}] = pid
	}
	return nil
}

// portFromDword extracts a port number from the low 16 bits of a DWORD
// field where Windows stores it in network byte order (big-endian).
func portFromDword(raw uint32) uint16 {
	b0 := byte(raw)
	b1 := byte(raw >> 8)
	return uint16(b0)<<8 | uint16(b1)
}
