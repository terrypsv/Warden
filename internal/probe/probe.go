// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package probe performs the network reachability tests. The interface is
// deliberately narrow so the v0.2 agent transport can replace the local
// dialer without touching the verification logic.
package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

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
		_ = conn.Close()
		return Result{Outcome: OutcomeOpen, Latency: elapsed}
	}
	return Result{Outcome: Classify(err), Latency: elapsed, Detail: err.Error()}
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
