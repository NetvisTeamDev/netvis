// Command netvis is a GlassWire-style per-process bandwidth monitor for
// Windows. See README.md for setup (WinDivert + Administrator rights).
package main

import (
	"fmt"
	"os"

	"netvis/internal/blocker"
	"netvis/internal/monitor"
	"netvis/internal/pidblock"
	"netvis/internal/ui"
)

func main() {
	mon, err := monitor.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start capture:", err)
		fmt.Fprintln(os.Stderr, "netvis must be run as Administrator, with WinDivert.dll and")
		fmt.Fprintln(os.Stderr, "WinDivert64.sys next to the .exe. See README.md.")
		os.Exit(1)
	}

	blk, err := blocker.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start ad blocker:", err)
		os.Exit(1)
	}

	pidMgr := pidblock.NewManager()

	mon.Start()
	go blk.Run()

	ui.Run(mon, blk, pidMgr)
}
