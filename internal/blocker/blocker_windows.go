//go:build windows

// Package blocker intercepts outbound DNS traffic and drops the parts that
// resolve or reach known ad/tracker domains, so nothing on the machine can
// resolve (and therefore connect to) them - a system-wide, browser-
// independent ad blocker built on the same WinDivert plumbing as
// internal/capture.
//
// Unlike internal/capture (which runs in WINDIVERT_FLAG_SNIFF mode and
// only ever observes traffic), this handle actually intercepts. Three
// kinds of traffic are matched:
//
//  1. Plain UDP DNS queries (port 53): parsed, and if the domain matches
//     the blocklist, a forged NXDOMAIN response is sent straight back to
//     the requesting app instead of re-injecting the query. This makes
//     the block feel instant (a normal failed lookup) rather than making
//     the app hang until a multi-second timeout.
//  2. DNS-over-TLS (port 853): always dropped outright. There's no
//     legitimate non-DNS use of that port, and we can't peek inside it to
//     be selective, so blocking it forces apps back onto plain DNS, which
//     we *can* filter.
//  3. DNS-over-HTTPS to a short list of well-known public resolver IPs
//     (Cloudflare/Google/Quad9/OpenDNS) on port 443: also dropped
//     outright. This is what closes the "secure DNS" bypass that browsers
//     increasingly default to - if a browser can't reach its DoH
//     resolver, it falls back to the OS resolver, which goes over plain
//     UDP 53 and lands back in case 1.
//
// See README's Known limitations for what this still doesn't catch.
package blocker

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	layerNetwork = 0 // WINDIVERT_LAYER_NETWORK

	addressSize = 80   // sizeof(WINDIVERT_ADDRESS), see the bit-layout note on outbound()
	bufferSize  = 1500 // generous for DNS-sized UDP/TCP control packets
)

// dohResolverIPs are well-known public DNS-over-HTTPS resolvers. Traffic
// to these IPs on port 443 is blocked outright (see package doc).
var dohResolverIPs = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
}

var (
	winDivertDLL            = syscall.NewLazyDLL("WinDivert.dll")
	procOpen                = winDivertDLL.NewProc("WinDivertOpen")
	procRecv                = winDivertDLL.NewProc("WinDivertRecv")
	procSend                = winDivertDLL.NewProc("WinDivertSend")
	procClose               = winDivertDLL.NewProc("WinDivertClose")
	procHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

// Blocker intercepts and drops DNS/encrypted-DNS traffic to blocked
// domains/resolvers.
type Blocker struct {
	handle    uintptr
	blocklist map[string]struct{}
	allowlist map[string]struct{}
	dohIPs    map[string]struct{}
	closed    atomic.Bool

	blockedCount atomic.Int64

	mu     sync.Mutex
	recent []string // most recent blocked entries, newest first, capped at 50
}

// New opens a second WinDivert handle (separate from internal/capture's -
// WinDivert supports multiple concurrent handles fine), scoped to outbound
// DNS/DoT/DoH traffic only. Requires Administrator privileges and
// WinDivert.dll/WinDivert64.sys next to the executable, same as capture.
func New() (*Blocker, error) {
	filterPtr, err := syscall.BytePtrFromString(buildFilter())
	if err != nil {
		return nil, err
	}

	// HANDLE WinDivertOpen(filter, layer, priority, flags)
	// flags = 0: a real intercepting handle, not sniff-mode - we decide
	// per-packet whether it gets re-injected.
	handle, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layerNetwork),
		uintptr(0), // priority
		uintptr(0), // flags
	)
	if handle == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return nil, fmt.Errorf("WinDivertOpen (blocker) failed: %w", callErr)
	}

	dohSet := make(map[string]struct{}, len(dohResolverIPs))
	for _, ip := range dohResolverIPs {
		dohSet[ip] = struct{}{}
	}

	return &Blocker{
		handle:    handle,
		blocklist: loadList("blocklist.txt"),
		allowlist: loadList("allowlist.txt"),
		dohIPs:    dohSet,
	}, nil
}

// buildFilter constructs the WinDivert filter string matching: outbound
// UDP:53, outbound TCP:853 (DoT), and outbound TCP:443 to a known DoH IP.
func buildFilter() string {
	dohConds := make([]string, 0, len(dohResolverIPs))
	for _, ip := range dohResolverIPs {
		dohConds = append(dohConds, fmt.Sprintf("ip.DstAddr == %s", ip))
	}
	return fmt.Sprintf(
		"outbound and (udp.DstPort == 53 or tcp.DstPort == 853 or (tcp.DstPort == 443 and (%s)))",
		strings.Join(dohConds, " or "),
	)
}

// Stats is a point-in-time snapshot of blocking activity.
type Stats struct {
	BlockedCount int64
	Recent       []string // most recent blocked entries, newest first
}

// Stats returns the current counters. Safe to call from any goroutine.
func (b *Blocker) Stats() Stats {
	b.mu.Lock()
	recent := append([]string(nil), b.recent...)
	b.mu.Unlock()
	return Stats{
		BlockedCount: b.blockedCount.Load(),
		Recent:       recent,
	}
}

// Run reads intercepted packets until Close is called, dropping the
// blocked ones (spoofing a fast NXDOMAIN for plain DNS queries where
// possible) and re-injecting everything else unchanged. Intended to be
// run in its own goroutine; blocks until shutdown or a real error.
func (b *Blocker) Run() error {
	buf := make([]byte, bufferSize)

	for {
		var addr [addressSize]byte
		var recvLen uint32

		// BOOL WinDivertRecv(handle, pPacket, packetLen, pRecvLen, pAddr)
		ret, _, callErr := procRecv.Call(
			b.handle,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ret == 0 {
			if b.closed.Load() {
				return nil // Close() unblocked us on purpose - not an error
			}
			return fmt.Errorf("WinDivertRecv (blocker) failed: %w", callErr)
		}

		// Copy out of buf before handling: buf gets reused next iteration,
		// but a spoofed-response build or a delayed reinject might still
		// reference these bytes.
		raw := append([]byte(nil), buf[:recvLen]...)
		b.handlePacket(raw, addr)
	}
}

func (b *Blocker) handlePacket(raw []byte, addr [addressSize]byte) {
	info, ok := parsePacket(raw)
	if !ok {
		b.reinject(raw, addr) // can't parse - fail open, don't break traffic
		return
	}

	if info.protocol == 17 && info.dstPort == 53 {
		if domain, ok := parseDNSQuestion(info.payload); ok && !b.isAllowed(domain) && b.isBlocked(domain) {
			b.recordBlock(domain)
			if resp, respAddr, ok := buildNXDOMAINResponse(raw, addr); ok {
				b.injectResponse(resp, respAddr)
			}
			return
		}
		b.reinject(raw, addr)
		return
	}

	if info.protocol == 6 && info.dstPort == 853 {
		b.recordBlock("[DNS-over-TLS] " + info.dstIP)
		return
	}

	if info.protocol == 6 && info.dstPort == 443 {
		if _, known := b.dohIPs[info.dstIP]; known {
			b.recordBlock("[DNS-over-HTTPS] " + info.dstIP)
			return
		}
	}

	// Shouldn't normally happen given our filter, but fail open rather
	// than silently eating traffic we didn't mean to touch.
	b.reinject(raw, addr)
}

func (b *Blocker) reinject(raw []byte, addr [addressSize]byte) {
	sendLen := uint32(len(raw))
	procSend.Call(
		b.handle,
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(len(raw)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
}

func (b *Blocker) injectResponse(packet []byte, addr [addressSize]byte) {
	// Our hand-built packet has placeholder/zero checksums - let WinDivert
	// compute the real IP/UDP checksums for us.
	procHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&addr[0])),
		uintptr(0),
	)
	var sendLen uint32
	procSend.Call(
		b.handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
}

// isBlocked checks domain and each of its parent suffixes ("a.b.c" then
// "b.c" then "c") against the block set, so blocking "example.com" also
// blocks "ads.example.com" without false-matching "notexample.com".
func (b *Blocker) isBlocked(domain string) bool {
	return matchesSuffixSet(domain, b.blocklist)
}

// isAllowed is the same suffix logic as isBlocked, but against the
// allowlist - lets you carve out exceptions if the default list is ever
// too aggressive for something you use.
func (b *Blocker) isAllowed(domain string) bool {
	return matchesSuffixSet(domain, b.allowlist)
}

func matchesSuffixSet(domain string, set map[string]struct{}) bool {
	domain = strings.TrimSuffix(domain, ".")
	for {
		if _, ok := set[domain]; ok {
			return true
		}
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			return false
		}
		domain = domain[idx+1:]
	}
}

func (b *Blocker) recordBlock(what string) {
	b.blockedCount.Add(1)
	b.mu.Lock()
	b.recent = append([]string{what}, b.recent...)
	if len(b.recent) > 50 {
		b.recent = b.recent[:50]
	}
	b.mu.Unlock()
}

// Close stops the intercept loop and releases the WinDivert handle.
func (b *Blocker) Close() error {
	b.closed.Store(true)
	ret, _, callErr := procClose.Call(b.handle)
	if ret == 0 {
		return callErr
	}
	return nil
}

// pktInfo is the slice of a raw IP packet's header fields we care about.
type pktInfo struct {
	protocol byte // 6 = TCP, 17 = UDP
	dstIP    string
	dstPort  uint16
	payload  []byte // transport-layer payload (after the UDP/TCP header)
}

func parsePacket(raw []byte) (pktInfo, bool) {
	if len(raw) < 1 {
		return pktInfo{}, false
	}

	var hdrLen int
	var protocol byte
	var dstIP string
	switch version := raw[0] >> 4; version {
	case 4:
		if len(raw) < 20 {
			return pktInfo{}, false
		}
		hdrLen = int(raw[0]&0x0F) * 4
		protocol = raw[9]
		dstIP = net.IP(raw[16:20]).String()
	case 6:
		if len(raw) < 40 {
			return pktInfo{}, false
		}
		hdrLen = 40
		protocol = raw[6]
		dstIP = net.IP(raw[24:40]).String()
	default:
		return pktInfo{}, false
	}
	if len(raw) < hdrLen {
		return pktInfo{}, false
	}
	transport := raw[hdrLen:]

	var dstPort uint16
	var payload []byte
	switch protocol {
	case 17: // UDP
		if len(transport) < 8 {
			return pktInfo{}, false
		}
		dstPort = binary.BigEndian.Uint16(transport[2:4])
		payload = transport[8:]
	case 6: // TCP
		if len(transport) < 20 {
			return pktInfo{}, false
		}
		dstPort = binary.BigEndian.Uint16(transport[2:4])
		dataOffset := int(transport[12]>>4) * 4
		if dataOffset < 20 || dataOffset > len(transport) {
			dataOffset = 20
		}
		payload = transport[dataOffset:]
	default:
		return pktInfo{}, false
	}

	return pktInfo{protocol: protocol, dstIP: dstIP, dstPort: dstPort, payload: payload}, true
}

// parseDNSQuestion extracts the QNAME of the first question in a DNS
// message. Only the first question can be parsed this simply because it's
// guaranteed not to use compression pointers (those reference earlier
// parts of the message, and nothing precedes the first question). Returns
// ok=false for anything malformed, too short, or using a pointer this early.
func parseDNSQuestion(payload []byte) (string, bool) {
	if len(payload) < 12 {
		return "", false
	}
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount == 0 {
		return "", false
	}

	pos := 12
	var labels []string
	for {
		if pos >= len(payload) {
			return "", false
		}
		length := int(payload[pos])
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			return "", false // compression pointer - shouldn't appear this early
		}
		pos++
		if pos+length > len(payload) {
			return "", false
		}
		labels = append(labels, string(payload[pos:pos+length]))
		pos += length
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.ToLower(strings.Join(labels, ".")), true
}

// questionSectionEnd returns the offset just past the first question's
// QTYPE+QCLASS, i.e. the length of the question section including the 12
// byte header. Used by buildNXDOMAINResponse to echo the question back.
func questionSectionEnd(msg []byte) (int, bool) {
	pos := 12
	for {
		if pos >= len(msg) {
			return 0, false
		}
		length := int(msg[pos])
		if length == 0 {
			pos++
			break
		}
		if length&0xC0 == 0xC0 {
			return 0, false
		}
		pos++
		if pos+length > len(msg) {
			return 0, false
		}
		pos += length
	}
	if pos+4 > len(msg) {
		return 0, false
	}
	return pos + 4, true // + QTYPE(2) + QCLASS(2)
}

// buildNXDOMAINResponse crafts a forged "no such domain" DNS response to a
// query packet, so the requesting app fails fast instead of waiting out a
// timeout. IPv4 only in v1 (see README) - returns ok=false for IPv6 or
// anything that doesn't parse cleanly, and the caller just drops silently
// in that case.
func buildNXDOMAINResponse(query []byte, addr [addressSize]byte) ([]byte, [addressSize]byte, bool) {
	if len(query) < 20 || query[0]>>4 != 4 {
		return nil, addr, false
	}
	ipHdrLen := int(query[0]&0x0F) * 4
	if len(query) < ipHdrLen+8 || query[9] != 17 { // must be UDP
		return nil, addr, false
	}
	udpStart := ipHdrLen
	dnsStart := udpStart + 8
	if len(query) < dnsStart+12 {
		return nil, addr, false
	}
	dnsMsg := query[dnsStart:]

	qEnd, ok := questionSectionEnd(dnsMsg)
	if !ok || dnsStart+qEnd > len(query) {
		return nil, addr, false
	}
	question := dnsMsg[12:qEnd]

	// DNS response: same transaction ID, echo the question, no answers,
	// RCODE=NXDOMAIN(3).
	resp := make([]byte, 12+len(question))
	copy(resp[0:2], dnsMsg[0:2])          // transaction ID
	resp[2] = 0x80 | (dnsMsg[2] & 0x01)   // QR=1 (response), keep RD bit from query
	resp[3] = 0x80 | 0x03                 // RA=1, RCODE=NXDOMAIN
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT=1; AN/NS/AR counts stay 0
	copy(resp[12:], question)

	udpLen := 8 + len(resp)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], binary.BigEndian.Uint16(query[udpStart+2:udpStart+4])) // srcPort = orig dstPort (53)
	binary.BigEndian.PutUint16(udp[2:4], binary.BigEndian.Uint16(query[udpStart:udpStart+2]))    // dstPort = orig srcPort
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// checksum left as 0 - recalculated by WinDivertHelperCalcChecksums

	ip := append([]byte(nil), query[:ipHdrLen]...)
	copy(ip[12:16], query[16:20]) // srcAddr = orig dstAddr (spoof as the real DNS server)
	copy(ip[16:20], query[12:16]) // dstAddr = orig srcAddr (the querying app)
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+udpLen))
	ip[8] = 64 // reset TTL to a sane default
	// checksum left as-is - recalculated by WinDivertHelperCalcChecksums

	packet := make([]byte, 0, ipHdrLen+udpLen)
	packet = append(packet, ip...)
	packet = append(packet, udp...)
	packet = append(packet, resp...)

	// Flip the Outbound bit off: this packet is now "arriving" (inbound),
	// not leaving. See internal/capture's outbound() doc comment for the
	// WINDIVERT_ADDRESS bit layout this relies on.
	respAddr := addr
	flags := binary.LittleEndian.Uint32(respAddr[8:12])
	flags &^= 1 << 9
	binary.LittleEndian.PutUint32(respAddr[8:12], flags)

	return packet, respAddr, true
}

// loadList reads a domain-per-line file next to the executable (blank
// lines and lines starting with '#' ignored). Used for both blocklist.txt
// and allowlist.txt. For the blocklist, the embedded defaults are merged
// in too.
func loadList(filename string) map[string]struct{} {
	set := make(map[string]struct{}, len(defaultBlocklist)+64)
	if filename == "blocklist.txt" {
		for _, d := range defaultBlocklist {
			set[d] = struct{}{}
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return set
	}
	f, err := os.Open(filepath.Join(filepath.Dir(exe), filename))
	if err != nil {
		return set // no extra file - fine, defaults (if any) still apply
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return set
}
