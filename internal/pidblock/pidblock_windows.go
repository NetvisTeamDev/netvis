//go:build windows

// Package pidblock lets you cut a specific process off the network by
// opening a WinDivert handle at the SOCKET layer scoped to that process's
// PID (filter: "processId == N"), and never re-injecting any of the
// socket events it sees. The SOCKET layer can block (but not modify)
// events, so simply dropping every event for that PID prevents it from
// completing new bind/connect/listen calls. This is the same technique
// used by WinDivert-based firewalls like SimpleWall.
//
// Limitations (v1): this stops *new* connection attempts. Sockets the
// process already had open before you blocked it may keep working until
// they close naturally. Blocking is tied to the specific PID, not the exe
// path - if the process restarts under a new PID, you need to block it
// again (this is also why blocks aren't persisted across netvis restarts).
package pidblock

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const (
	layerSocket = 3 // WINDIVERT_LAYER_SOCKET
	addressSize = 80
)

var (
	winDivertDLL = syscall.NewLazyDLL("WinDivert.dll")
	procOpen     = winDivertDLL.NewProc("WinDivertOpen")
	procRecv     = winDivertDLL.NewProc("WinDivertRecv")
	procClose    = winDivertDLL.NewProc("WinDivertClose")
)

type blockedProc struct {
	handle uintptr
}

// Manager tracks which PIDs are currently cut off from the network.
type Manager struct {
	mu     sync.Mutex
	blocks map[uint32]*blockedProc
}

// NewManager returns an empty, ready-to-use Manager.
func NewManager() *Manager {
	return &Manager{blocks: make(map[uint32]*blockedProc)}
}

// IsBlocked reports whether pid is currently blocked.
func (m *Manager) IsBlocked(pid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.blocks[pid]
	return ok
}

// Block cuts pid off from making new network connections. No-op if it's
// already blocked. Requires Administrator privileges, same as capture and
// blocker.
func (m *Manager) Block(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blocks[pid]; ok {
		return nil
	}

	filterStr := fmt.Sprintf("processId == %d", pid)
	filterPtr, err := syscall.BytePtrFromString(filterStr)
	if err != nil {
		return err
	}

	// HANDLE WinDivertOpen(filter, layer, priority, flags)
	handle, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layerSocket),
		uintptr(0), // priority
		uintptr(0), // flags: 0 = intercepting (not sniff) - required to block
	)
	if handle == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return fmt.Errorf("WinDivertOpen (pidblock %d) failed: %w", pid, callErr)
	}

	bp := &blockedProc{handle: handle}
	m.blocks[pid] = bp
	go bp.run()
	return nil
}

// run just drains socket-layer events for this PID and drops every one of
// them. At WINDIVERT_LAYER_SOCKET, an event that's never re-injected via
// WinDivertSend is blocked - so simply never sending is the whole trick.
func (bp *blockedProc) run() {
	buf := make([]byte, 256)
	for {
		var addr [addressSize]byte
		var recvLen uint32

		ret, _, _ := procRecv.Call(
			bp.handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ret == 0 {
			return // handle closed (Unblock) or errored - either way, stop
		}
		// Deliberately no WinDivertSend call here.
	}
}

// Unblock restores normal networking for pid. No-op if it wasn't blocked.
func (m *Manager) Unblock(pid uint32) error {
	m.mu.Lock()
	bp, ok := m.blocks[pid]
	if ok {
		delete(m.blocks, pid)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}

	ret, _, callErr := procClose.Call(bp.handle)
	if ret == 0 {
		return callErr
	}
	return nil
}

// BlockedPIDs returns a snapshot of every currently-blocked PID.
func (m *Manager) BlockedPIDs() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	pids := make([]uint32, 0, len(m.blocks))
	for pid := range m.blocks {
		pids = append(pids, pid)
	}
	return pids
}

// UnblockAll releases every currently-blocked PID - call this on shutdown
// so a killed netvis doesn't leave processes permanently cut off (closing
// the handle is enough; nothing else references the block once the WinDivert
// handle is gone).
func (m *Manager) UnblockAll() {
	for _, pid := range m.BlockedPIDs() {
		m.Unblock(pid)
	}
}
