//go:build windows

package ui

import (
	"image"
	"image/color"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
)

// sample is one tick's worth of total (all-process) bandwidth.
type sample struct {
	down, up float64 // bytes/sec
}

// trafficGraph is a GlassWire-style rolling line graph: a filled green
// area for download and a blue line for upload, auto-scaled to whatever
// the busiest sample in the window was. Backed by a canvas.Raster, so it
// redraws by regenerating a small image each tick rather than managing
// individual line/shape objects.
type trafficGraph struct {
	mu      sync.Mutex
	samples []sample
	cap     int
}

func newTrafficGraph(capacity int) *trafficGraph {
	return &trafficGraph{cap: capacity}
}

// push adds the latest total down/up rate, dropping the oldest sample once
// the window is full.
func (g *trafficGraph) push(down, up float64) {
	g.mu.Lock()
	g.samples = append(g.samples, sample{down: down, up: up})
	if len(g.samples) > g.cap {
		g.samples = g.samples[len(g.samples)-g.cap:]
	}
	g.mu.Unlock()
}

// raster returns the drawable widget. Call .Refresh() on it after each
// push to redraw with the latest data.
func (g *trafficGraph) raster() *canvas.Raster {
	r := canvas.NewRaster(g.generate)
	r.SetMinSize(fyne.NewSize(0, 80))
	return r
}

var (
	downColor = color.NRGBA{R: 0x35, G: 0xc7, B: 0x5f, A: 0xB0} // translucent green fill
	upColor   = color.NRGBA{R: 0x4a, G: 0xa3, B: 0xf5, A: 0xFF} // solid blue line
)

func (g *trafficGraph) generate(w, h int) image.Image {
	g.mu.Lock()
	samples := append([]sample(nil), g.samples...)
	g.mu.Unlock()

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	if len(samples) == 0 || w <= 0 || h <= 0 {
		return img
	}

	// Auto-scale to the busiest sample in view, with a floor so a mostly
	// idle graph doesn't look like it's jittering at full height.
	const floor = 8 * 1024.0 // 8 KB/s
	maxVal := floor
	for _, s := range samples {
		if s.down > maxVal {
			maxVal = s.down
		}
		if s.up > maxVal {
			maxVal = s.up
		}
	}

	n := len(samples)
	for x := 0; x < w; x++ {
		idx := x * n / w
		if idx >= n {
			idx = n - 1
		}
		s := samples[idx]

		downH := int(s.down / maxVal * float64(h))
		if downH > h {
			downH = h
		}
		upH := int(s.up / maxVal * float64(h))
		if upH > h {
			upH = h
		}

		for y := h - downH; y < h; y++ {
			if y >= 0 {
				img.SetNRGBA(x, y, downColor)
			}
		}
		for dy := 0; dy < 2; dy++ {
			y := h - upH - dy
			if y >= 0 && y < h {
				img.SetNRGBA(x, y, upColor)
			}
		}
	}
	return img
}
