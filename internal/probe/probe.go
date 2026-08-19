// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package probe performs the network reachability tests. The interface is
// deliberately narrow so the v0.2 agent transport can replace the local
// dialer without touching the verification logic.
package probe

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// BannerPrefix identifies a warden listener. A peer that answers with this
// prefix is a listener we placed there, not a service that happened to be
// running. Everything about strict mode depends on this distinction.
//
// Wire format: "WARDEN/1 <token> <version>\n". The version is optional so a
// listener from an older build still validates, but reporting the mismatch
// beats debugging an obscure flag error across two machines.
const BannerPrefix = "WARDEN/1 "

// bannerMaxBytes caps how much of the peer's first line we read.
const bannerMaxBytes = 128

// defaultBannerTimeout bounds the wait for a banner. Real services that never
// speak first would otherwise stall every probe for the full dial timeout.
const defaultBannerTimeout = 500 * time.Millisecond

// Outcome is what the network actually did.
type Outcome string

const (
	// OutcomeOpen means the TCP handshake completed.
	OutcomeOpen Outcome = "open"
	// OutcomeRefused means an RST came back. The host was reached, so the
	// packet crossed the boundary: the port is closed, not the path.
	// Mistaking this for "blocked" is the classic segmentation-testing bug.
	OutcomeRefused Outcome = "refused"
	// OutcomeFiltered means silence or an unreachable: the path is cut.
	OutcomeFiltered Outcome = "filtered"
	// OutcomeSkipped means this probe is not implemented yet.
	OutcomeSkipped Outcome = "skipped"
	// OutcomeError means the probe itself failed.
	OutcomeError Outcome = "error"
)

// Traversed reports whether the packet reached the destination host.
func (o Outcome) Traversed() bool {
	return o == OutcomeOpen || o == OutcomeRefused
}

// Result is a single observation.
type Result struct {
	Outcome Outcome
	Latency time.Duration
	Detail  string
	// Banner is the first line the peer sent, trimmed and truncated. Empty
	// when the peer said nothing within the banner timeout.
	Banner string
	// ListenerConfirmed is true when the peer identified itself as a warden
	// listener with a valid token. This is proof, not a claim.
	ListenerConfirmed bool
	// ListenerVersion is the build the listener announced, empty when it
	// predates versioned banners.
	ListenerVersion string
}

// Prober checks one endpoint. Implementations must be safe for concurrent use.
type Prober interface {
	Check(ctx context.Context, host, proto string, port int) Result
}

// TCPProber dials from the machine running Warden. It only implements TCP:
// UDP and ICMP cannot be judged from the sender alone, since silence means
// both "blocked" and "no service", so they wait for the receiving agent.
type TCPProber struct {
	Timeout time.Duration
	// BannerTimeout bounds the wait for a listener banner.
	BannerTimeout time.Duration
	// ExpectToken, when set, must match the token presented by the listener.
	// Empty accepts any well-formed warden banner.
	ExpectToken string
}

// Check implements Prober.
func (p TCPProber) Check(ctx context.Context, host, proto string, port int) Result {
	if proto != "tcp" {
		return Result{
			Outcome: OutcomeSkipped,
			Detail:  proto + " probing needs a receiving agent, planned for v0.2",
		}
	}

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err == nil {
		banner := readBanner(conn, p.bannerTimeout())
		_ = conn.Close()
		_, listenerVersion, _ := ParseBanner(banner)
		return Result{
			Outcome:           OutcomeOpen,
			Latency:           elapsed,
			Banner:            banner,
			ListenerConfirmed: MatchBanner(banner, p.ExpectToken),
			ListenerVersion:   listenerVersion,
		}
	}
	return Result{Outcome: Classify(err), Latency: elapsed, Detail: err.Error()}
}

func (p TCPProber) bannerTimeout() time.Duration {
	if p.BannerTimeout > 0 {
		return p.BannerTimeout
	}
	return defaultBannerTimeout
}

// Banner builds the line a listener announces.
func Banner(token, version string) string {
	if version == "" {
		return BannerPrefix + token + "\n"
	}
	return BannerPrefix + token + " " + version + "\n"
}

// ParseBanner splits a warden banner into its token and version.
func ParseBanner(banner string) (token, version string, ok bool) {
	if !strings.HasPrefix(banner, BannerPrefix) {
		return "", "", false
	}
	fields := strings.Fields(strings.TrimPrefix(banner, BannerPrefix))
	if len(fields) == 0 {
		return "", "", false
	}
	if len(fields) > 1 {
		version = fields[1]
	}
	return fields[0], version, true
}

// MatchBanner reports whether a banner proves a warden listener answered.
// The token comparison is constant time: the token tells an operator whether
// a measurement can be trusted, and leaking it through timing would let a
// rogue service impersonate a listener.
func MatchBanner(banner, expectToken string) bool {
	token, _, ok := ParseBanner(banner)
	if !ok {
		return false
	}
	if expectToken == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectToken)) == 1
}

// readBanner reads the peer's first line, if it speaks first. Failure to read
// is not an error: most real services wait for the client.
func readBanner(conn net.Conn, timeout time.Duration) string {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	buf := make([]byte, bannerMaxBytes)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	line := string(buf[:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// Classify maps a dial error onto an outcome. It matches on message text
// rather than errno constants because those diverge across Linux, Windows
// and macOS, and this tool has to give the same answer on all three.
func Classify(err error) Outcome {
	if err == nil {
		return OutcomeOpen
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return OutcomeFiltered
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return OutcomeFiltered
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"),
		strings.Contains(msg, "reset by peer"),
		strings.Contains(msg, "connection was reset"),
		strings.Contains(msg, "forcibly closed"):
		return OutcomeRefused
	case strings.Contains(msg, "unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "timed out"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "i/o deadline"):
		return OutcomeFiltered
	}
	return OutcomeError
}
