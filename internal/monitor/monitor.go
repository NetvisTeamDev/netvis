//go:build windows

// Package monitor ties capture, netmap and procname together into
// per-process bandwidth stats that a UI can poll.
package monitor

import (
	"sort"
	"sync"
	"time"

	"netvis/internal/capture"
	"netvis/internal/netmap"
	"netvis/internal/procname"
)

// unknownPID is the bucket used for traffic whose owning process couldn't
// be resolved (e.g. the connection table hadn't been refreshed yet, or a
// short-lived UDP send/receive happened between refreshes). Real PIDs never
// reach this value, so it's safe to use as a sentinel.
const unknownPID = 0xFFFFFFFF

// AppStats is a point-in-time view of one process's network usage.
type AppStats struct {
	PID       uint32
	Name      string
	ExePath   string // full path to the executable, if known (used for icon lookup)
	RateDown  float64 // bytes/sec over the last tick
	RateUp    float64 // bytes/sec over the last tick
	TotalDown uint64  // bytes since the monitor started
	TotalUp   uint64
}

type interval struct {
	down uint64
	up   uint64
}

// Monitor aggregates raw capture events into per-process bandwidth stats.
// Create one with New, call Start once, and poll Snapshot from a UI timer.
type Monitor struct {
	sniffer  *capture.Sniffer
	netTable *netmap.Table
	names    *procname.Resolver

	tickEvery time.Duration
	stop      chan struct{}

	mu      sync.Mutex
	current map[uint32]*interval // this tick's byte counts, reset every tick
	totals  map[uint32]*AppStats // cumulative, carried across ticks
}

// New opens the underlying WinDivert capture handle. Requires Administrator
// privileges and WinDivert's DLL/driver next to the executable.
func New() (*Monitor, error) {
	sniffer, err := capture.New()
	if err != nil {
		return nil, err
	}
	return &Monitor{
		sniffer:   sniffer,
		netTable:  netmap.NewTable(),
		names:     procname.NewResolver(),
		tickEvery: time.Second,
		stop:      make(chan struct{}),
		current:   make(map[uint32]*interval),
		totals:    make(map[uint32]*AppStats),
	}, nil
}

// Start begins capturing, refreshing the connection table, and aggregating
// into per-second rates. Returns immediately.
func (m *Monitor) Start() {
	go m.sniffer.Run()
	go m.netTable.RunPeriodicRefresh(time.Second, m.stop)
	go m.consumeLoop()
	go m.tickLoop()
}

// Stop shuts down capture and all background goroutines.
func (m *Monitor) Stop() {
	close(m.stop)
	m.sniffer.Close()
}

func (m *Monitor) consumeLoop() {
	for {
		select {
		case <-m.stop:
			return
		case ev, ok := <-m.sniffer.Events():
			if !ok {
				return
			}
			pid, found := m.netTable.Lookup(ev.Proto, ev.LocalPort)
			if !found {
				pid = unknownPID
			}

			m.mu.Lock()
			c, ok := m.current[pid]
			if !ok {
				c = &interval{}
				m.current[pid] = c
			}
			if ev.Inbound {
				c.down += ev.Bytes
			} else {
				c.up += ev.Bytes
			}
			m.mu.Unlock()
		}
	}
}

func (m *Monitor) tickLoop() {
	ticker := time.NewTicker(m.tickEvery)
	defer ticker.Stop()
	seconds := m.tickEvery.Seconds()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.mu.Lock()

			for pid, c := range m.current {
				stat, ok := m.totals[pid]
				if !ok {
					var path string
					if pid != unknownPID {
						path, _ = m.names.Path(pid)
					}
					stat = &AppStats{PID: pid, Name: m.nameFor(pid), ExePath: path}
					m.totals[pid] = stat
				}
				stat.RateDown = float64(c.down) / seconds
				stat.RateUp = float64(c.up) / seconds
				stat.TotalDown += c.down
				stat.TotalUp += c.up
			}
			// Zero out the rate for processes that were silent this tick,
			// so the UI doesn't show a stale non-zero speed forever.
			for pid, stat := range m.totals {
				if _, active := m.current[pid]; !active {
					stat.RateDown = 0
					stat.RateUp = 0
				}
			}

			m.current = make(map[uint32]*interval)
			m.mu.Unlock()
		}
	}
}

func (m *Monitor) nameFor(pid uint32) string {
	if pid == unknownPID {
		return "Unknown"
	}
	return m.names.Name(pid)
}

// Snapshot returns the current per-process stats, sorted by total bandwidth
// (down+up) descending. Safe to call from any goroutine.
func (m *Monitor) Snapshot() []AppStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]AppStats, 0, len(m.totals))
	for _, s := range m.totals {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].TotalDown + out[i].TotalUp) > (out[j].TotalDown + out[j].TotalUp)
	})
	return out
}
