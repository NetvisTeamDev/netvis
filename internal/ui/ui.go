//go:build windows

// Package ui renders the Fyne window: a live traffic graph, a table of
// per-process bandwidth usage (with icons and per-process block buttons),
// and a blocked-ads counter - all polling once a second.
package ui

import (
	"fmt"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"netvis/internal/blocker"
	"netvis/internal/monitor"
	"netvis/internal/pidblock"
)

var columns = []string{"App", "PID", "Down/s", "Up/s", "Total", "Block"}

const unknownPID = 0xFFFFFFFF

// Run builds and shows the main window, blocking until it's closed. mon
// must already have Start called on it, and blk should already be running
// (e.g. via `go blk.Run()`); Run calls Stop/Close/UnblockAll on all three
// when the window closes.
func Run(mon *monitor.Monitor, blk *blocker.Blocker, pidMgr *pidblock.Manager) {
	a := app.NewWithID("dev.netvis.bandwidth")
	w := a.NewWindow("netvis - bandwidth monitor")
	w.Resize(fyne.NewSize(720, 560))

	// rowsBox holds the latest snapshot. It's written from a background
	// ticker and read from the table's cell-update callbacks (which Fyne
	// may invoke off the goroutine that called Refresh), so we use
	// atomic.Value instead of a plain variable to keep that safe.
	var rowsBox atomic.Value
	rowsBox.Store(mon.Snapshot())
	getRows := func() []monitor.AppStats {
		return rowsBox.Load().([]monitor.AppStats)
	}

	graph := newTrafficGraph(60)
	graphRaster := graph.raster()

	var table *widget.Table
	table = widget.NewTable(
		func() (int, int) { return len(getRows()) + 1, len(columns) }, // +1 header row
		func() fyne.CanvasObject {
			icon := canvas.NewImageFromResource(nil)
			icon.FillMode = canvas.ImageFillContain
			icon.SetMinSize(fyne.NewSize(16, 16))
			label := widget.NewLabel("")
			btn := widget.NewButton("", nil)
			return container.NewHBox(icon, label, btn)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			row := obj.(*fyne.Container)
			icon := row.Objects[0].(*canvas.Image)
			label := row.Objects[1].(*widget.Label)
			btn := row.Objects[2].(*widget.Button)

			icon.Hide()
			btn.Hide()
			label.Show()

			if id.Row == 0 {
				label.TextStyle = fyne.TextStyle{Bold: true}
				label.SetText(columns[id.Col])
				return
			}
			label.TextStyle = fyne.TextStyle{}

			rows := getRows()
			if id.Row-1 >= len(rows) {
				label.SetText("")
				return
			}
			r := rows[id.Row-1]

			switch id.Col {
			case 0:
				label.SetText(r.Name)
				if res := iconFor(r.ExePath); res != nil {
					icon.Resource = res
					icon.Refresh()
					icon.Show()
				}
			case 1:
				if r.PID == unknownPID {
					label.SetText("-")
				} else {
					label.SetText(fmt.Sprintf("%d", r.PID))
				}
			case 2:
				label.SetText(formatRate(r.RateDown))
			case 3:
				label.SetText(formatRate(r.RateUp))
			case 4:
				label.SetText(formatBytes(r.TotalDown + r.TotalUp))
			case 5:
				label.Hide()
				pid := r.PID
				if pid == unknownPID {
					btn.SetText("-")
					btn.Disable()
					btn.OnTapped = nil
				} else {
					btn.Enable()
					if pidMgr.IsBlocked(pid) {
						btn.SetText("Unblock")
					} else {
						btn.SetText("Block")
					}
					btn.OnTapped = func() {
						if pidMgr.IsBlocked(pid) {
							pidMgr.Unblock(pid)
						} else {
							pidMgr.Block(pid)
						}
						table.Refresh()
					}
				}
				btn.Show()
			}
		},
	)
	table.SetColumnWidth(0, 220)
	table.SetColumnWidth(1, 70)
	table.SetColumnWidth(2, 100)
	table.SetColumnWidth(3, 100)
	table.SetColumnWidth(4, 100)
	table.SetColumnWidth(5, 90)

	status := widget.NewLabel("Capturing traffic - must be run as Administrator")
	blockedLabel := widget.NewLabel("Ads/trackers blocked: 0")
	top := container.NewVBox(status, blockedLabel, graphRaster)
	content := container.NewBorder(top, nil, nil, nil, table)
	w.SetContent(content)

	stopUI := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopUI:
				return
			case <-ticker.C:
				rows := mon.Snapshot()

				var totalDown, totalUp float64
				for _, r := range rows {
					totalDown += r.RateDown
					totalUp += r.RateUp
					warmIcon(r.ExePath) // off the UI goroutine, before Refresh
				}
				graph.push(totalDown, totalUp)
				rowsBox.Store(rows)
				blockedCount := blk.Stats().BlockedCount

				// Fyne (2.4+) requires all widget mutations to happen on its
				// own UI goroutine. This ticker runs on a background
				// goroutine, so calling table.Refresh()/SetText() directly
				// here races with anything Fyne itself does on the UI
				// goroutine (e.g. the Block button's OnTapped handler) -
				// that race is exactly what was corrupting the table
				// widget's internal state and crashing the app on click.
				// fyne.Do hands the closure to the UI goroutine instead of
				// running it here, which eliminates the race.
				fyne.Do(func() {
					table.Refresh()
					graphRaster.Refresh()
					blockedLabel.SetText(fmt.Sprintf("Ads/trackers blocked: %d", blockedCount))
				})
			}
		}
	}()

	w.SetOnClosed(func() {
		close(stopUI)
		mon.Stop()
		blk.Close()
		pidMgr.UnblockAll()
	})

	w.ShowAndRun()
}

func formatRate(bytesPerSec float64) string {
	return formatBytes(uint64(bytesPerSec)) + "/s"
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), units[exp])
}
