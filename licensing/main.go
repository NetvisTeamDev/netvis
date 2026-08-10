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
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base32"
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

// A license key is 125 random bytes rendered as unpadded base32, which is
// exactly 200 characters of A-Z/2-7. Uppercase-only and unambiguous, so a
// customer can retype one if they have to.
const keyRandomBytes = 125
const KeyLength = 200

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

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
		log.Fatalf("config.json is not valid JSON: %v", err)
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
			revoked      INTEGER NOT NULL DEFAULT 0
		);
	`); err != nil {
		log.Fatalf("create tables: %v", err)
	}
	// The database is the whole product - don't let it be world-readable.
	_ = os.Chmod(path, 0o600)
	return db
}

func newKey() string {
	buf := make([]byte, keyRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("out of randomness: %v", err)
	}
	return b32.EncodeToString(buf)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

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

type server struct{ db *sql.DB }

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
	key := strings.TrimPrefix(r.URL.Path, "/validate/")
	if len(key) != KeyLength {
		deny(w, http.StatusBadRequest, "malformed license key")
		return
	}

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

	// Already activated? Say so instead of eating another key - a customer
	// reinstalling shouldn't have to buy a second license.
	var revoked int
	err := s.db.QueryRow(`SELECT revoked FROM activations WHERE hwid = ?`, req.HWID).Scan(&revoked)
	if err == nil {
		if revoked != 0 {
			deny(w, http.StatusForbidden, "this machine has been revoked")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "already_activated"})
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM keys WHERE key = ?`, key)
	if err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		deny(w, http.StatusForbidden, "unknown or already used license key")
		return
	}

	if _, err := tx.Exec(
		`INSERT INTO activations (hwid, os, key, activated_at) VALUES (?, ?, ?, ?)`,
		req.HWID, normOS(req.OS), key, now()); err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}
	if err := tx.Commit(); err != nil {
		deny(w, http.StatusInternalServerError, "server error")
		return
	}

	log.Printf("activated hwid=%s os=%s", req.HWID, normOS(req.OS))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "activated"})
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

	var osName, at string
	var revoked int
	err := s.db.QueryRow(
		`SELECT os, activated_at, revoked FROM activations WHERE hwid = ?`, hwid).
		Scan(&osName, &at, &revoked)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "os": osName, "activated_at": at,
	})
}

func cmdServe(cfg Config, db *sql.DB) {
	s := &server{db: db}
	mux := http.NewServeMux()

	// Licensing API. Strictly limited - a client only ever makes one of
	// these per app launch.
	api := newLimiter(cfg.RateLimitPerMinute)
	mux.Handle("/validate/", rateLimited(http.HandlerFunc(s.handleValidate), api, cfg.TrustProxy))
	mux.Handle("/authentificate/", rateLimited(http.HandlerFunc(s.handleAuthentificate), api, cfg.TrustProxy))

	// The website, on its own much looser limit: one page view is already
	// several requests (html, css, screenshot, icon), so the API's budget
	// would 429 a visitor who just hit reload a few times.
	site, err := fs.Sub(websiteFS, "website")
	if err != nil {
		log.Fatalf("website: %v", err)
	}
	pages := newLimiter(300)
	mux.Handle("/", rateLimited(http.FileServer(http.FS(site)), pages, cfg.TrustProxy))

	// Release downloads come off the disk, from a downloads/ folder beside
	// the binary, so publishing a new netvis.exe is a file copy.
	mux.Handle("/downloads/", rateLimited(
		http.StripPrefix("/downloads/", http.FileServer(http.Dir("downloads"))), pages, cfg.TrustProxy))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
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

func cmdKeys(db *sql.DB) {
	rows, err := db.Query(`SELECT key, note, created_at FROM keys ORDER BY created_at`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var key, note, created string
		if err := rows.Scan(&key, &note, &created); err != nil {
			log.Fatal(err)
		}
		count++
		fmt.Printf("%s  %s  %s\n", created, key, note)
	}
	fmt.Fprintf(os.Stderr, "\n%d unused key(s).\n", count)
}

func cmdUsers(db *sql.DB) {
	rows, err := db.Query(
		`SELECT hwid, os, activated_at, revoked FROM activations ORDER BY activated_at`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Printf("%-24s  %-8s  %-22s %s\n", "HWID", "OS", "ACTIVATED", "STATE")
	total, live := 0, 0
	for rows.Next() {
		var hwid, osName, at string
		var revoked int
		if err := rows.Scan(&hwid, &osName, &at, &revoked); err != nil {
			log.Fatal(err)
		}
		state := "active"
		if revoked != 0 {
			state = "REVOKED"
		} else {
			live++
		}
		total++
		fmt.Printf("%-24s  %-8s  %-22s %s\n", hwid, osName, at, state)
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
  users                 list activated machines
  revoke <hwid>         stop a machine from running netvis
  unrevoke <hwid>       allow it again
  delkey <key>          destroy an unused key

Admin commands run against the local database file only - they are never
exposed over the network.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
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
	case "delkey":
		cmdDelKey(db, need("key"))
	default:
		usage()
	}
}
