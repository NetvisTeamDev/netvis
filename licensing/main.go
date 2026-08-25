// netvis licensing server.
//
// Two public endpoints, exactly as the client uses them:
//
//	POST /validate/<license-key>      body: {"hwid":"...","os":"windows"}
//	     Burns the key: if it exists it is DELETED and the HWID is recorded
//	     as activated. One key = one machine, forever.
//
//	GET  /authentificate/<hwid>
//	     Answers whether that machine is allowed to run netvis.
//
// Everything else is admin work and is deliberately NOT reachable over the
// network - key generation, listing and revoking are subcommands of this
// same binary that talk to the SQLite file directly. Nothing to brute
// force, no admin password to leak, and the server can only ever burn keys
// that were already created locally.
//
//	go run . serve            start the HTTP server
//	go run . gen -n 10        create 10 license keys
//	go run . keys             list unused keys
//	go run . users            list activated machines
//	go run . revoke <hwid>    block a machine
//	go run . unrevoke <hwid>  unblock it again
//	go run . delkey <key>     destroy an unused key
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// The public website, compiled into the binary. One file to copy to the
// server, and the pages can't go missing or fall out of sync with it.
// Release builds of netvis.exe are the exception - they're served from a
// downloads/ folder on disk so you can publish a new build without
// rebuilding this server.
//
//go:embed website
var websiteFS embed.FS

// A license key is 30 characters drawn from the base32 alphabet: 150 bits
// of randomness, which is far past anything guessable, while staying short
// enough that a customer can read one off a screen and type it.
//
// The alphabet has no 0, 1, 8 or 9, so there's no O/0 or I/1 ambiguity to
// misread. Case and separators are normalised away on the way in, so
// "abcde-fghij" and "ABCDEFGHIJ" are the same key.
const KeyLength = 30
const keyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// ---------------------------------------------------------------- config

// Config is read from config.json next to the binary. Every field has a
// working default, so a missing file is fine.
type Config struct {
	// Listen address. Keep it on 127.0.0.1 while developing; set it to
	// ":8443" (or "0.0.0.0:8443") when you put this behind a real domain.
	Listen string `json:"listen"`
	// Path to the SQLite database.
	DB string `json:"db"`
	// Serve HTTPS directly using these files. Leave TLS false if you're
	// terminating TLS at a reverse proxy (nginx/Caddy), which is the
	// easier path once you have a real domain.
	TLS      bool   `json:"tls"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// Requests allowed per IP per rolling minute. A client may spend them
	// all in one second; it just can't exceed this in any 60-second span.
	RateLimitPerMinute int `json:"rate_limit_per_minute"`
	// Set this only when the server sits behind a reverse proxy you
	// control (nginx/Caddy). It makes the limiter trust X-Forwarded-For -
	// which is a header anyone can forge, so with no proxy in front it
	// would let a single machine pretend to be thousands.
	TrustProxy bool `json:"trust_proxy"`

	// --- Polar (the shop). Both come from the Polar dashboard; neither is
	// secret - the organization id is public and the checkout link is what
	// customers click.
	PolarOrganizationID string `json:"polar_organization_id"`
	// Set to "https://sandbox-api.polar.sh" to test against Polar's sandbox,
	// which is a completely separate server with its own organization, its
	// own ids and no real money. Empty means production.
	PolarAPIBase string `json:"polar_api_base"`
	// Where the Buy button sends people, e.g.
	// "https://buy.polar.sh/polar_cl_xxxxx". Kept in config rather than the
	// page so it can change without rebuilding.
	CheckoutURL string `json:"checkout_url"`

	// Private half of the key that signs answers to /authentificate, as 64
	// hex characters from `licensing genkeys`. Secret: anyone holding it can
	// mint licenses. Empty means answers go out unsigned, which any client
	// built with a public key will refuse.
	ResponsePrivateKey string `json:"response_private_key"`

	// Discord webhook that gets notified of trials, activations and Buy
	// clicks, plus an hourly traffic digest. Secret - anyone with the URL can
	// post to your channel - so it stays in config.json, never in the source.
	// Empty disables notifications entirely.
	DiscordWebhook string `json:"discord_webhook"`
}

func loadConfig() Config {
	c := Config{
		Listen:             "127.0.0.1:8443",
		DB:                 "licenses.db",
		CertFile:           "cert.pem",
		KeyFile:            "key.pem",
		RateLimitPerMinute: 30,
	}
	data, err := os.ReadFile("config.json")
	if err != nil {
		return c // no config file - defaults are fine
	}
	if err := json.Unmarshal(data, &c); err != nil {
		// Hand-edited over ssh, so the usual culprit is a comma left behind
		// after deleting the last setting. JSON's own message doesn't say
		// that, and the service just exits.
		log.Fatalf("config.json is not valid JSON: %v\n"+
			"(a trailing comma before the closing brace is the usual cause - "+
			"check it with: python3 -m json.tool %s)", err, "config.json")
	}
	if c.RateLimitPerMinute <= 0 {
		c.RateLimitPerMinute = 30
	}
	return c
}

// ---------------------------------------------------------- rate limiting

// Sliding-window limiter, keyed by client IP. Keeping the timestamp of
// each recent request (rather than a counter that resets on the minute)
// is what makes the limit hold across window boundaries - with a resetting
// counter a client could send `max` at 11:59:59 and `max` again at
// 12:00:00 and never be stopped.
type limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newLimiter(max int) *limiter {
	l := &limiter{hits: map[string][]time.Time{}, max: max, window: time.Minute}
	go l.reap()
	return l
}

// allow records a request and reports whether it's within the limit. On
// refusal it also returns how long until the oldest request ages out,
// which is exactly when the caller may try again.
func (l *limiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	h := l.hits[ip]
	i := 0
	for i < len(h) && h[i].Before(cutoff) {
		i++
	}
	h = h[i:]

	if len(h) >= l.max {
		l.hits[ip] = h
		return false, time.Until(h[0].Add(l.window))
	}
	l.hits[ip] = append(h, now)
	return true, 0
}

// Drops IPs that have gone quiet, so the map can't grow without bound.
func (l *limiter) reap() {
	for range time.Tick(5 * time.Minute) {
		cutoff := time.Now().Add(-l.window)
		l.mu.Lock()
		for ip, h := range l.hits {
			if len(h) == 0 || h[len(h)-1].Before(cutoff) {
				delete(l.hits, ip)
			}
		}
		l.mu.Unlock()
	}
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func rateLimited(next http.Handler, l *limiter, trustProxy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, trustProxy)
		ok, retry := l.allow(ip)
		if !ok {
			secs := int(retry.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			log.Printf("rate limited %s", ip)
			deny(w, http.StatusTooManyRequests, "too many requests - try again shortly")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// -------------------------------------------------------------- database

func openDB(path string) *sql.DB {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			key        TEXT PRIMARY KEY,
			note       TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS activations (
			hwid         TEXT PRIMARY KEY,
			os           TEXT NOT NULL,
			key          TEXT NOT NULL,
			activated_at TEXT NOT NULL,
			expires_at   TEXT NOT NULL DEFAULT '',
			polar_activation_id TEXT NOT NULL DEFAULT '',
			is_trial     INTEGER NOT NULL DEFAULT 0,
			revoked      INTEGER NOT NULL DEFAULT 0
		);
	`); err != nil {
		log.Fatalf("create tables: %v", err)
	}
	// Older databases predate expires_at; add it rather than making anyone
	// start over. An empty value means "never expires", which is exactly
	// what those early activations were sold as.
	for _, stmt := range []string{
		`ALTER TABLE activations ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE activations ADD COLUMN polar_activation_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE activations ADD COLUMN is_trial INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Fatalf("migrate activations: %v", err)
		}
	}
	// The database is the whole product - don't let it be world-readable.
	_ = os.Chmod(path, 0o600)
	return db
}

func newKey() string {
	buf := make([]byte, KeyLength)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("out of randomness: %v", err)
	}
	out := make([]byte, KeyLength)
	for i, b := range buf {
		// len(keyAlphabet) is 32 and 256 is an exact multiple of it, so
		// this modulo is uniform - no character is more likely than any
		// other, and there's no bias to reject and retry around.
		out[i] = keyAlphabet[int(b)%len(keyAlphabet)]
	}
	return string(out)
}

// normalizeKey tidies what the customer sends: upper case, with spaces and
// line breaks dropped. People paste keys out of emails, and that shouldn't
// be a failed activation.
//
// Dashes and underscores are KEPT, because Polar's keys contain them
// (NETVIS_1C285B2D-6CE6-...) and stripping them would break the lookup.
// Our own keys never contain either, so they're unaffected.
func normalizeKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// onlyKeyAlphabet reports whether every character is from our own key
// alphabet - which is how a locally generated key is told apart from a
// Polar one without asking either system.
func onlyKeyAlphabet(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(keyAlphabet, r) {
			return false
		}
	}
	return true
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// How long one key buys. Sold as "6 months".
const licenseMonths = 6

// Free trial, once per machine.
const trialDays = 14

// parseExpiry reads a stored expires_at. An empty string means the license
// never expires - that's how activations sold before expiry existed were
// treated, and those customers keep what they paid for.
func parseExpiry(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// renewedExpiry extends from whatever is left rather than from today, so a
// customer who renews early doesn't lose the days they already paid for.
func renewedExpiry(current string) time.Time {
	from := time.Now().UTC()
	if t, ok := parseExpiry(current); ok && t.After(from) {
		from = t
	}
	return from.AddDate(0, licenseMonths, 0)
}

func daysLeft(expires time.Time) int {
	d := int(time.Until(expires).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// normOS maps whatever the client reported onto the two platforms we
// support, so the admin listing stays tidy.
func normOS(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "windows", "win", "win32", "win64":
		return "windows"
	case "macos", "mac", "darwin", "osx":
		return "macos"
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

// --------------------------------------------------------------- server

type server struct {
	db      *sql.DB
	cfg     Config
	signKey *ecdsa.PrivateKey // nil when no key is configured
	notify  *notifier         // Discord notifications; a no-op when unconfigured
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func deny(w http.ResponseWriter, code int, reason string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": reason})
}

// POST /validate/<license-key>
//
// Body: {"hwid":"<machine id>","os":"windows"|"macos"}
//
// If the key exists it is consumed (deleted) and the HWID is activated.
// Deleting inside the same transaction that inserts the activation is what
// makes this safe against two machines redeeming the same key at once -
// the second transaction finds no row to delete and loses.
func (s *server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		deny(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	// Two shapes of key are accepted: our own 30-character ones from
	// `licensing gen`, and Polar's PREFIX_<uuid> ones that customers get
	// when they buy. Which one it is decides where it gets checked.
	key := normalizeKey(strings.TrimPrefix(r.URL.Path, "/validate/"))
	if len(key) < 20 || len(key) > 100 {
		deny(w, http.StatusBadRequest, "malformed license key")
		return
	}
	isLocalKey := len(key) == KeyLength && onlyKeyAlphabet(key)

	var req struct {
		HWID string `json:"hwid"`
		OS   string `json:"os"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		deny(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.HWID == "" || len(req.HWID) > 128 {
		deny(w, http.StatusBadRequest, "missing hwid")
		return
	}

	// What does this machine already have? Three cases: nothing (a fresh
	// activation), a license with time left (don't burn the key - tell them
	// to keep it), or an expired/expiring one (this key renews it).
	var revoked, currentIsTrial int
	var currentExpiry string
	err := s.db.QueryRow(`SELECT revoked, expires_at, is_trial FROM activations WHERE hwid = ?`, req.HWID).
		Scan(&revoked, &currentExpiry, &currentIsTrial)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	if existing && revoked != 0 {
		deny(w, http.StatusForbidden, "this machine has been revoked")
		return
	}
	// A machine on trial can always redeem a key - that's the whole point of
	// letting people buy from inside the app on day two rather than making
	// them wait for the trial to run out.
	if existing && currentIsTrial == 0 {
		if exp, ok := parseExpiry(currentExpiry); !ok {
			// A pre-expiry, never-expires license. Nothing to renew.
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "already_activated"})
			return
		} else if daysLeft(exp) > 7 {
			// Plenty of time left - refuse politely rather than silently
			// eating a key they just paid for. They can use it when it runs
			// out, or on another PC.
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true, "status": "already_activated",
				"expires_at": currentExpiry, "days_left": daysLeft(exp),
			})
			return
		}
	}

	// Extends from the current expiry when renewing early, so no paid days
	// are thrown away. Upgrading from a trial starts the six months fresh
	// instead: trial days weren't paid for, and starting now is what the
	// customer expects when they hand over money.
	from := currentExpiry
	if currentIsTrial != 0 {
		from = ""
	}
	expiry := renewedExpiry(from).Format(time.RFC3339)
	status := "activated"
	if existing && currentIsTrial == 0 {
		status = "renewed"
	}

	polarActivationID := ""

	tx, err := s.db.Begin()
	if err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	defer tx.Rollback()

	if isLocalKey {
		// One of ours: consume it. Deleting inside this transaction is what
		// makes two machines redeeming the same key at once safe - the
		// second finds no row to delete and loses.
		res, err := tx.Exec(`DELETE FROM keys WHERE key = ?`, key)
		if err != nil {
			deny(w, http.StatusInternalServerError, "server error")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			deny(w, http.StatusForbidden, "unknown or already used license key")
			return
		}
	} else {
		// One key, one machine - checked here as well as at Polar. Polar
		// only enforces this when the benefit has an activation limit set;
		// if it doesn't, this is the only thing standing between one
		// purchase and an office full of installs.
		var otherHWID string
		err := tx.QueryRow(`SELECT hwid FROM activations WHERE key = ? AND hwid != ?`, key, req.HWID).
			Scan(&otherHWID)
		if err == nil {
			log.Printf("refused: key already used by %s, tried from %s", otherHWID, req.HWID)
			deny(w, http.StatusForbidden, "this key is already in use on another computer")
			return
		} else if !errors.Is(err, sql.ErrNoRows) {
			deny(w, http.StatusInternalServerError, "server error")
			return
		}

		// A key the customer bought. Polar owns it: it checks the key is
		// real and unspent, burns one of its activation slots if it has
		// them, and tells us when the license runs out.
		act, err := s.activatePolarKey(key, req.HWID)
		if err != nil {
			switch {
			case errors.Is(err, errKeyUnknown):
				deny(w, http.StatusForbidden, "unknown or already used license key")
			case errors.Is(err, errKeyInUse):
				deny(w, http.StatusForbidden, "this key is already in use on another computer")
			default:
				// Polar unreachable or misbehaving. Say so plainly instead of
				// blaming the customer's key, and don't record anything.
				log.Printf("polar: activation failed for hwid=%s: %v", req.HWID, err)
				deny(w, http.StatusBadGateway,
					"couldn't reach the license service just now - please try again in a minute")
			}
			return
		}
		// Polar decides the term for keys it issued.
		expiry = polarExpiry(act)
		polarActivationID = act.ID
	}

	if _, err := tx.Exec(`
		INSERT INTO activations (hwid, os, key, activated_at, expires_at, polar_activation_id, is_trial)
		VALUES (?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT(hwid) DO UPDATE SET key = excluded.key, expires_at = excluded.expires_at,
			os = excluded.os, polar_activation_id = excluded.polar_activation_id,
			-- paying clears the trial flag, otherwise the customer keeps
			-- seeing the trial countdown after they've bought
			is_trial = 0`,
		req.HWID, normOS(req.OS), key, now(), expiry, polarActivationID); err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	if err := tx.Commit(); err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}

	log.Printf("%s hwid=%s os=%s until=%s", status, req.HWID, normOS(req.OS), expiry)
	atomic.AddInt64(&s.notify.sales, 1)
	s.notify.send("💰 Sale — license activated",
		"`"+tail(req.HWID, 8)+"` · "+normOS(req.OS), colGold)
	days := 0
	if exp, ok := parseExpiry(expiry); ok {
		days = daysLeft(exp)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "status": status, "expires_at": expiry, "days_left": days,
	})
}

// POST /trial/<hwid>   body: {"os":"windows"}
//
// Starts the one free trial this machine is allowed. There is nothing on
// the customer's disk to tamper with: the trial is a row here, and the
// expiry it produces is delivered through the same signed /authentificate
// answer as a paid license. Reinstalling, clearing settings or moving the
// clock changes nothing.
//
// One trial per machine FOREVER - including after it has expired. That's
// the whole point: an expired trial must not be restartable.
func (s *server) handleTrial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		deny(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	hwid := strings.TrimPrefix(r.URL.Path, "/trial/")
	if hwid == "" || len(hwid) > 128 {
		deny(w, http.StatusBadRequest, "missing hwid")
		return
	}

	var req struct {
		OS string `json:"os"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)

	var existingTrial int
	err := s.db.QueryRow(`SELECT is_trial FROM activations WHERE hwid = ?`, hwid).Scan(&existingTrial)
	if err == nil {
		// Already known. Either it's licensed (nothing to do) or its trial
		// has been used - both mean no new trial.
		if existingTrial != 0 {
			deny(w, http.StatusForbidden, "the free trial has already been used on this computer")
		} else {
			deny(w, http.StatusForbidden, "this computer already has a license")
		}
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}

	expiry := time.Now().UTC().AddDate(0, 0, trialDays).Format(time.RFC3339)
	// INSERT without ON CONFLICT: if two requests race, the second fails on
	// the primary key rather than silently extending the first one's trial.
	if _, err := s.db.Exec(`
		INSERT INTO activations (hwid, os, key, activated_at, expires_at, is_trial)
		VALUES (?, ?, '', ?, ?, 1)`,
		hwid, normOS(req.OS), now(), expiry); err != nil {
		deny(w, http.StatusForbidden, "the free trial has already been used on this computer")
		return
	}

	log.Printf("trial started hwid=%s os=%s until=%s", hwid, normOS(req.OS), expiry)
	atomic.AddInt64(&s.notify.trials, 1)
	s.notify.send("🎉 Trial started",
		"`"+tail(hwid, 8)+"` · "+normOS(req.OS), colGreen)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "status": "trial", "expires_at": expiry, "days_left": trialDays,
	})
}

// GET /authentificate/<hwid>
//
// The everyday call: netvis asks on each launch whether this machine may
// run. Answers {"ok":true} or {"ok":false}.
func (s *server) handleAuthentificate(w http.ResponseWriter, r *http.Request) {
	hwid := strings.TrimPrefix(r.URL.Path, "/authentificate/")
	if hwid == "" || len(hwid) > 128 {
		deny(w, http.StatusBadRequest, "missing hwid")
		return
	}

	// Every launch hits this endpoint, before any trial exists, so it's the
	// one place that sees whether a downloaded copy is actually being run.
	s.notify.appLaunched(hwid)

	var osName, at, expiresAt string
	var revoked, isTrial int
	err := s.db.QueryRow(
		`SELECT os, activated_at, expires_at, revoked, is_trial FROM activations WHERE hwid = ?`, hwid).
		Scan(&osName, &at, &expiresAt, &revoked, &isTrial)
	if errors.Is(err, sql.ErrNoRows) {
		deny(w, http.StatusForbidden, "not activated")
		return
	}
	if err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	if revoked != 0 {
		deny(w, http.StatusForbidden, "revoked")
		return
	}

	resp := map[string]any{"ok": true, "os": osName, "activated_at": at, "trial": isTrial != 0}

	// The client sends a fresh nonce per launch and the signature covers
	// it, so yesterday's captured "yes" is worthless today.
	nonce := r.URL.Query().Get("n")
	if len(nonce) > 128 {
		deny(w, http.StatusBadRequest, "bad nonce")
		return
	}
	if exp, ok := parseExpiry(expiresAt); ok {
		if time.Now().After(exp) {
			// The distinct error matters: the client can tell "your license
			// ran out, here's how to renew" apart from "never activated",
			// and an expired trial gets its own wording again.
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok": false, "error": "expired", "expires_at": expiresAt,
				"trial": isTrial != 0,
			})
			return
		}
		resp["expires_at"] = expiresAt
		resp["days_left"] = daysLeft(exp)
	}

	if s.signKey != nil {
		sig, err := signAnswer(s.signKey, hwid, expiresAt, nonce)
		if err != nil {
			log.Printf("signing failed: %v", err)
			deny(w, http.StatusInternalServerError, "server error")
			return
		}
		resp["nonce"] = nonce
		resp["sig"] = sig
	}
	writeJSON(w, http.StatusOK, resp)
}

func cmdServe(cfg Config, db *sql.DB) {
	s := &server{db: db, cfg: cfg, notify: newNotifier(cfg.DiscordWebhook)}
	if cfg.ResponsePrivateKey != "" {
		key, err := parseSigningKey(cfg.ResponsePrivateKey)
		if err != nil {
			log.Fatalf("response_private_key: %v", err)
		}
		s.signKey = key
		log.Print("answers to /authentificate will be signed")
	} else {
		log.Print("WARNING: no response_private_key set - answers are unsigned, and any")
		log.Print("client built with a public key will refuse them. Run: licensing genkeys")
	}
	mux := http.NewServeMux()

	// Licensing API. Strictly limited - a client only ever makes one of
	// these per app launch.
	api := newLimiter(cfg.RateLimitPerMinute)
	mux.Handle("/validate/", rateLimited(http.HandlerFunc(s.handleValidate), api, cfg.TrustProxy))
	mux.Handle("/authentificate/", rateLimited(http.HandlerFunc(s.handleAuthentificate), api, cfg.TrustProxy))
	mux.Handle("/trial/", rateLimited(http.HandlerFunc(s.handleTrial), api, cfg.TrustProxy))

	// The website, on its own much looser limit: one page view is already
	// several requests (html, css, screenshot, icon), so the API's budget
	// would 429 a visitor who just hit reload a few times.
	site, err := fs.Sub(websiteFS, "website")
	if err != nil {
		log.Fatalf("website: %v", err)
	}
	pages := newLimiter(300)
	fileServer := http.FileServer(http.FS(site))
	mux.Handle("/", rateLimited(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Count only real page loads for the digest, not every css/js/image
		// request a page pulls in.
		if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
			s.notify.pageView(clientIP(r, cfg.TrustProxy))
		}
		fileServer.ServeHTTP(w, r)
	}), pages, cfg.TrustProxy))

	// The Buy button. Sends people to Polar, which handles payment, VAT,
	// and emailing them the key.
	mux.Handle("/buy", rateLimited(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.CheckoutURL == "" {
			http.Error(w, "The shop isn't set up yet - please check back shortly.",
				http.StatusServiceUnavailable)
			return
		}
		s.notify.send("🛒 Buy clicked", "", colBlue)
		http.Redirect(w, r, cfg.CheckoutURL, http.StatusSeeOther)
	}), pages, cfg.TrustProxy))

	// Release downloads come off the disk, from a downloads/ folder beside
	// the binary, so publishing a new build is a file copy.
	//
	// Directory listings are turned off: by default Go's file server renders
	// an index for /downloads/, which lets anyone browse what's there -
	// including builds that aren't announced yet.
	downloads := http.StripPrefix("/downloads/", http.FileServer(http.Dir("downloads")))
	mux.Handle("/downloads/", rateLimited(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		// Count .exe fetches (the installer) for the digest; ignore other bits.
		if strings.HasSuffix(r.URL.Path, ".exe") {
			s.notify.countDownload()
		}
		downloads.ServeHTTP(w, r)
	}), pages, cfg.TrustProxy))

	// Auto-update files, served from an updates/ folder beside the binary:
	//   updates/windows/{update.json, update.json.sig, netvis-windows-<ver>.exe}
	//   updates/macos/{update.json, update.json.sig, netvis-macos-<ver>.dmg}
	//
	// Two things matter here. First, byte-for-byte: the manifest signature
	// covers the exact bytes of update.json, so the file server hands them
	// back unchanged (Go's FileServer never rewrites a body) and nothing in
	// front of it may either - keep /updates/ out of any gzip/transform rule.
	// Second, caching: the manifest is short-lived so a new release is seen
	// quickly, while the versioned build (its name changes every release) can
	// be cached forever. Directory listings are off, same as downloads.
	updates := http.StripPrefix("/updates/", http.FileServer(http.Dir("updates")))
	mux.Handle("/updates/", rateLimited(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".json") || strings.HasSuffix(r.URL.Path, ".sig") {
			w.Header().Set("Cache-Control", "public, max-age=300")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		updates.ServeHTTP(w, r)
	}), pages, cfg.TrustProxy))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           securityHeaders(mux, cfg.TLS || cfg.TrustProxy),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	if cfg.TLS {
		fmt.Printf("netvis licensing server on https://%s\n", cfg.Listen)
		log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
	}
	fmt.Printf("netvis licensing server on http://%s\n", cfg.Listen)
	log.Fatal(srv.ListenAndServe())
}

// securityHeaders wraps every response - website, API and downloads alike -
// with the set of headers a browser needs in order to refuse the classic
// attacks on a site like this one.
//
// The policy is deliberately strict, and the page was written to fit it
// rather than the other way round: all script lives in app.js (so no
// 'unsafe-inline' and no hashes to re-derive on every edit), and the stagger
// delays that used to be style="" attributes are classes now (so style-src
// needs no exception either). The one thing that is allowed beyond 'self' is
// data: for images, which the CSS grain texture uses.
//
// https is true when the site is reachable over TLS - either terminated here
// or, as in production, at Caddy. HSTS is only sent then: promising a browser
// that a plain-http development server will always be https is a good way to
// lock yourself out of localhost for a year.
func securityHeaders(next http.Handler, https bool) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"object-src 'none'; " +
		"upgrade-insecure-requests"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		// Stops a browser from second-guessing a Content-Type - the reason a
		// .txt upload can otherwise end up executed as script.
		h.Set("X-Content-Type-Options", "nosniff")
		// frame-ancestors above covers modern browsers; this covers the rest.
		h.Set("X-Frame-Options", "DENY")
		// Send the full URL to ourselves, only the origin to anyone else, and
		// nothing at all when downgrading to http.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Nothing here needs a camera, a microphone or a location, so no
		// embedded content should be able to ask for one in our name.
		h.Set("Permissions-Policy",
			"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "+
				"microphone=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		if https {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------ admin CLI

func cmdGen(db *sql.DB, args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	n := fs.Int("n", 1, "how many keys to generate")
	note := fs.String("note", "", "optional label, e.g. an order number")
	out := fs.String("out", "", "also append the keys to this file")
	_ = fs.Parse(args)

	if *n < 1 || *n > 10000 {
		log.Fatal("-n must be between 1 and 10000")
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback()

	keys := make([]string, 0, *n)
	for i := 0; i < *n; i++ {
		k := newKey()
		if _, err := tx.Exec(
			`INSERT INTO keys (key, note, created_at) VALUES (?, ?, ?)`, k, *note, now()); err != nil {
			log.Fatal(err)
		}
		keys = append(keys, k)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	for _, k := range keys {
		fmt.Println(k)
	}
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		for _, k := range keys {
			fmt.Fprintln(f, k)
		}
		fmt.Fprintf(os.Stderr, "\n%d key(s) also written to %s\n", len(keys), *out)
	}
	fmt.Fprintf(os.Stderr, "\n%d key(s) generated.\n", len(keys))
}

// Prints nothing but the keys, one per line, so the output can be piped
// straight into a file or pasted into a store without cleaning it up. The
// count goes to stderr, which keeps it off the pipe.
func cmdKeys(db *sql.DB) {
	rows, err := db.Query(`SELECT key FROM keys ORDER BY created_at`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			log.Fatal(err)
		}
		count++
		fmt.Println(key)
	}
	fmt.Fprintf(os.Stderr, "\n%d unused key(s).\n", count)
}

func cmdUsers(db *sql.DB) {
	rows, err := db.Query(
		`SELECT hwid, os, activated_at, expires_at, revoked, is_trial FROM activations ORDER BY activated_at`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Printf("%-24s  %-8s  %-22s  %s\n", "HWID", "OS", "ACTIVATED", "STATE")
	total, live := 0, 0
	for rows.Next() {
		var hwid, osName, at, expiresAt string
		var revoked, isTrial int
		if err := rows.Scan(&hwid, &osName, &at, &expiresAt, &revoked, &isTrial); err != nil {
			log.Fatal(err)
		}
		total++

		state := ""
		switch exp, ok := parseExpiry(expiresAt); {
		case revoked != 0:
			state = "REVOKED"
		case !ok:
			state = "active (no expiry)"
			live++
		case time.Now().After(exp):
			state = "EXPIRED " + exp.Format("2006-01-02")
		default:
			state = fmt.Sprintf("active, %d days left", daysLeft(exp))
			live++
		}
		if isTrial != 0 {
			state = "TRIAL - " + state
		}
		fmt.Printf("%-24s  %-8s  %-22s  %s\n", hwid, osName, at, state)
	}
	fmt.Fprintf(os.Stderr, "\n%d machine(s), %d active.\n", total, live)
}

func setRevoked(db *sql.DB, hwid string, revoked bool) {
	v := 0
	if revoked {
		v = 1
	}
	res, err := db.Exec(`UPDATE activations SET revoked = ? WHERE hwid = ?`, v, hwid)
	if err != nil {
		log.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		log.Fatalf("no machine with hwid %s", hwid)
	}
	if revoked {
		fmt.Printf("%s revoked.\n", hwid)
	} else {
		fmt.Printf("%s re-enabled.\n", hwid)
	}
}

// forget removes a machine's activation entirely, so it counts as never
// activated and can be licensed again from scratch.
//
// Distinct from revoke, which keeps the row and marks it blocked: a revoked
// machine is refused even with a fresh key, which is what you want for
// abuse, and exactly what you don't want when someone reinstalls Windows
// or you're testing.
func cmdForget(s *server, hwid string) {
	var key, activationID string
	err := s.db.QueryRow(`SELECT key, polar_activation_id FROM activations WHERE hwid = ?`, hwid).
		Scan(&key, &activationID)
	if errors.Is(err, sql.ErrNoRows) {
		log.Fatalf("no machine with hwid %s", hwid)
	} else if err != nil {
		log.Fatal(err)
	}

	// Hand the activation slot back to Polar first. Deleting our row alone
	// would leave the key stuck at Polar's limit, so it could never be used
	// again - on this machine or any other.
	if activationID != "" {
		if err := s.deactivatePolarKey(key, activationID); err != nil {
			log.Printf("warning: could not free the activation at Polar: %v", err)
			log.Print("the machine is still forgotten here; free the slot from the Polar dashboard")
		} else {
			fmt.Println("activation slot released at Polar - the same key works again")
		}
	}

	if _, err := s.db.Exec(`DELETE FROM activations WHERE hwid = ?`, hwid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s forgotten - it can be activated again.\n", hwid)
}

func cmdDelKey(db *sql.DB, key string) {
	res, err := db.Exec(`DELETE FROM keys WHERE key = ?`, key)
	if err != nil {
		log.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		log.Fatal("no such unused key")
	}
	fmt.Println("key destroyed.")
}

func usage() {
	fmt.Print(`netvis licensing server

  serve                 run the HTTP server
  gen -n 10 [-note ..] [-out keys.txt]
                        generate license keys
  keys                  list unused keys
  users                 list activated machines, with days remaining
  revoke <hwid>         stop a machine from running netvis
  unrevoke <hwid>       allow it again
  forget <hwid>         delete a machine's activation so it can be
                        licensed again from scratch (reinstalls, testing)
  delkey <key>          destroy an unused key
  genkeys               create the key that signs license answers
  polarcheck <key>      ask Polar about a key and print its raw answer -
                        use this when an activation is refused

Admin commands run against the local database file only - they are never
exposed over the network.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	// Release-side tooling: signs update manifests with a key that lives only
	// on this machine. Handled before the DB/config open so it can run on a
	// build machine that has neither.
	switch os.Args[1] {
	case "genupdatekeys":
		cmdGenUpdateKeys(os.Args[2:])
		return
	case "signupdate":
		cmdSignUpdate(os.Args[2:])
		return
	}

	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()

	need := func(what string) string {
		if len(os.Args) < 3 {
			log.Fatalf("usage: %s %s <%s>", os.Args[0], os.Args[1], what)
		}
		return os.Args[2]
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(cfg, db)
	case "gen":
		cmdGen(db, os.Args[2:])
	case "keys":
		cmdKeys(db)
	case "users":
		cmdUsers(db)
	case "revoke":
		setRevoked(db, need("hwid"), true)
	case "unrevoke":
		setRevoked(db, need("hwid"), false)
	case "forget":
		cmdForget(&server{db: db, cfg: cfg}, need("hwid"))
	case "genkeys":
		cmdGenKeys()
	case "polarcheck":
		cmdPolarCheck(&server{db: db, cfg: cfg}, need("key"))
	case "delkey":
		cmdDelKey(db, need("key"))
	default:
		usage()
	}
}
