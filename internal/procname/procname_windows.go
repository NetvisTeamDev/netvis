//go:build windows

// Package procname resolves a Windows PID to a human-friendly executable
// name and its full path, with caching (these don't change for the life
// of a process).
package procname

import (
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

const processQueryLimitedInformation = 0x1000

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

type entry struct {
	name string
	path string // may be empty even when name is set, if the exe path itself couldn't be read
}

// Resolver resolves PIDs to executable names and full paths.
type Resolver struct {
	mu    sync.Mutex
	cache map[uint32]entry
}

// NewResolver returns an empty, ready-to-use Resolver.
func NewResolver() *Resolver {
	return &Resolver{cache: make(map[uint32]entry)}
}

// Name returns a friendly name for pid: the executable's filename if it can
// be inspected, otherwise a "PID <n>" fallback (e.g. the process already
// exited, or it's a protected/SYSTEM process we don't have rights to open).
func (r *Resolver) Name(pid uint32) string {
	return r.resolve(pid).name
}

// Path returns the full executable path for pid, and whether one is
// available (it won't be for the synthetic System/Idle PIDs, or if we
// don't have permission to inspect the process).
func (r *Resolver) Path(pid uint32) (string, bool) {
	e := r.resolve(pid)
	return e.path, e.path != ""
}

func (r *Resolver) resolve(pid uint32) entry {
	if pid == 0 {
		return entry{name: "System Idle Process"}
	}
	if pid == 4 {
		return entry{name: "System"}
	}

	r.mu.Lock()
	if e, ok := r.cache[pid]; ok {
		r.mu.Unlock()
		return e
	}
	r.mu.Unlock()

	path := queryPath(pid)
	e := entry{path: path}
	if path != "" {
		e.name = filepath.Base(path)
	} else {
		e.name = fmt.Sprintf("PID %d", pid)
	}

	r.mu.Lock()
	r.cache[pid] = e
	r.mu.Unlock()
	return e
}

// Forget drops a cached PID. Useful once a PID's traffic has gone quiet for
// a while, both to reclaim memory and to avoid ever showing a stale name if
// Windows reuses the PID for a different executable later.
func (r *Resolver) Forget(pid uint32) {
	r.mu.Lock()
	delete(r.cache, pid)
	r.mu.Unlock()
}

func queryPath(pid uint32) string {
	handle, _, _ := procOpenProcess.Call(
		uintptr(processQueryLimitedInformation),
		0, // bInheritHandle = FALSE
		uintptr(pid),
	)
	if handle == 0 {
		return ""
	}
	defer procCloseHandle.Call(handle)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		handle,
		0, // dwFlags = 0 (Win32 path format)
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}
