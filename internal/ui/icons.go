//go:build windows

package ui

import (
	"sync"

	"fyne.io/fyne/v2"

	"netvis/internal/winicon"
)

// iconCache memoizes extracted icons by exe path. A nil entry (present key,
// nil value) means extraction was already tried and failed - we don't want
// to retry (and pay the syscall cost) every single tick for processes with
// no readable icon.
var (
	iconCacheMu sync.Mutex
	iconCache   = map[string]fyne.Resource{}
)

// warmIcon extracts and caches the icon for path if it isn't already
// cached. Safe to call from a background goroutine - this is the intended
// use, so the (comparatively slow, syscall-heavy) extraction never happens
// on Fyne's UI goroutine during table cell rendering.
func warmIcon(path string) {
	if path == "" {
		return
	}
	iconCacheMu.Lock()
	_, ok := iconCache[path]
	iconCacheMu.Unlock()
	if ok {
		return
	}

	data, err := winicon.ExtractPNG(path)
	var res fyne.Resource
	if err == nil {
		res = fyne.NewStaticResource(path, data)
	}

	iconCacheMu.Lock()
	iconCache[path] = res // cache the failure (nil) too, so we don't retry every tick
	iconCacheMu.Unlock()
}

// iconFor returns a cached icon resource for path, or nil if there isn't
// one (not cached yet, or extraction failed).
func iconFor(path string) fyne.Resource {
	if path == "" {
		return nil
	}
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	return iconCache[path]
}
