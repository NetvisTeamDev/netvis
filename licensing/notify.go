package main

// Discord notifications for the events worth knowing about: a trial started, a
// key activated (a sale), someone clicking Buy. Plus an hourly digest of the
// noisy stuff (page views, downloads) so the channel gets a summary instead of
// a message per hit.
//
// Two rules keep this safe:
//   - It never blocks a request. Handlers call a fire-and-forget method that
//     drops the event if the queue is full; the actual HTTP POST to Discord
//     happens on a worker goroutine.
//   - The webhook URL is a secret (anyone holding it can post to your channel),
//     so it lives in config.json - never in the source, never committed.
//
// A disabled notifier (no webhook configured) is a no-op, so the server runs
// fine without it.

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	colGreen = 3066993  // trial
	colGold  = 15844367 // sale / activation
	colBlue  = 3447003  // buy clicked
	colGrey  = 9807270  // digest
	colTeal  = 1752220  // app launched
)

// Named dEmbed (not "embed") because this package already imports the "embed"
// package for //go:embed, and the two names would collide.
type dEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp"`
}

type notifier struct {
	url   string
	queue chan dEmbed

	pv, uniq, trials, sales, buys, downloads, launched int64 // atomics, drained by the digest
	seen                                               sync.Map
	launchSeen                                         sync.Map // persistent: one "new machine" ping per hwid
}

func newNotifier(url string) *notifier {
	n := &notifier{url: url}
	if url == "" {
		return n // disabled: every method below early-returns
	}
	n.queue = make(chan dEmbed, 256)
	go n.worker()
	go n.digestLoop()
	log.Print("discord notifications enabled")
	return n
}

func (n *notifier) enabled() bool { return n != nil && n.url != "" }

// send enqueues an instant notification. Non-blocking: if the queue is backed
// up (Discord down, or a flood) the event is dropped rather than stalling a
// request handler.
func (n *notifier) send(title, desc string, color int) {
	if !n.enabled() {
		return
	}
	select {
	case n.queue <- dEmbed{Title: title, Description: desc, Color: color,
		Timestamp: time.Now().UTC().Format(time.RFC3339)}:
	default:
	}
}

// pageView counts a real page load for the hourly digest (not every asset).
func (n *notifier) pageView(ip string) {
	if !n.enabled() {
		return
	}
	atomic.AddInt64(&n.pv, 1)
	if _, seen := n.seen.LoadOrStore(ip, true); !seen {
		atomic.AddInt64(&n.uniq, 1)
	}
}

func (n *notifier) countDownload() {
	if n.enabled() {
		atomic.AddInt64(&n.downloads, 1)
	}
}

// appLaunched records that a machine actually started netvis. The client calls
// /authentificate on every launch - even a fresh install that hasn't started a
// trial yet - so this is the signal that answers "people download it, but do
// they run it?". The hourly digest gets the count; the first time any machine
// is ever seen it also gets an instant ping, so a new person running netvis
// shows up in real time next to the download that (hopefully) preceded it.
func (n *notifier) appLaunched(hwid string) {
	if !n.enabled() {
		return
	}
	atomic.AddInt64(&n.launched, 1)
	if _, seen := n.launchSeen.LoadOrStore(hwid, true); !seen {
		n.send("🚀 Opened on a new device", "`"+tail(hwid, 8)+"`", colTeal)
	}
}

func (n *notifier) worker() {
	for e := range n.queue {
		n.post(e)
		time.Sleep(1200 * time.Millisecond) // stay comfortably under Discord's webhook rate limit
	}
}

func (n *notifier) post(e dEmbed) {
	body, _ := json.Marshal(map[string]any{"embeds": []dEmbed{e}})
	resp, err := http.Post(n.url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("discord: post failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		// Respect Retry-After and try once more.
		if s := resp.Header.Get("Retry-After"); s != "" {
			if secs, e2 := strconv.Atoi(s); e2 == nil && secs > 0 && secs < 60 {
				time.Sleep(time.Duration(secs) * time.Second)
				if r2, e3 := http.Post(n.url, "application/json", bytes.NewReader(body)); e3 == nil {
					r2.Body.Close()
				}
			}
		}
	}
}

func (n *notifier) digestLoop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		pv := atomic.SwapInt64(&n.pv, 0)
		uq := atomic.SwapInt64(&n.uniq, 0)
		dl := atomic.SwapInt64(&n.downloads, 0)
		la := atomic.SwapInt64(&n.launched, 0)
		tr := atomic.SwapInt64(&n.trials, 0)
		sl := atomic.SwapInt64(&n.sales, 0)
		n.seen = sync.Map{} // reset unique tracking each window (also bounds memory)
		if pv == 0 && dl == 0 && la == 0 && tr == 0 && sl == 0 {
			continue // nothing happened - stay quiet
		}
		desc := "Page views: **" + strconv.FormatInt(pv, 10) + "** (" +
			strconv.FormatInt(uq, 10) + " unique)\nDownloads: **" +
			strconv.FormatInt(dl, 10) + "**\nLaunches: **" +
			strconv.FormatInt(la, 10) + "**\nTrials: **" +
			strconv.FormatInt(tr, 10) + "**   Activations: **" +
			strconv.FormatInt(sl, 10) + "**"
		n.post(dEmbed{Title: "📊 Last hour", Description: desc, Color: colGrey,
			Timestamp: time.Now().UTC().Format(time.RFC3339)})
	}
}

// tail returns the last n characters of s, for showing an identifier without
// dumping the whole thing into a chat channel.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
