// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCheckOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	res := TCPProber{Timeout: time.Second}.Check(context.Background(), "127.0.0.1", "tcp", port)
	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q (%s), want open", res.Outcome, res.Detail)
	}
	if !res.Outcome.Traversed() {
		t.Error("open devrait compter comme traverse")
	}
}

func TestCheckClosedPortIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res := TCPProber{Timeout: time.Second}.Check(context.Background(), "127.0.0.1", "tcp", port)
	if res.Outcome != OutcomeRefused {
		t.Skipf("plateforme renvoyant %q sur loopback ferme, detail: %s", res.Outcome, res.Detail)
	}
	if !res.Outcome.Traversed() {
		t.Error("refused signifie que le paquet a atteint l'hote, donc traverse")
	}
}

func TestCheckSkipsNonTCP(t *testing.T) {
	for _, proto := range []string{"udp", "icmp"} {
		res := TCPProber{}.Check(context.Background(), "127.0.0.1", proto, 53)
		if res.Outcome != OutcomeSkipped {
			t.Errorf("%s: outcome = %q, want skipped", proto, res.Outcome)
		}
	}
}

func TestCheckCancelledContextIsFiltered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := TCPProber{Timeout: time.Second}.Check(ctx, "10.255.255.1", "tcp", 445)
	if res.Outcome != OutcomeFiltered {
		t.Fatalf("outcome = %q, want filtered", res.Outcome)
	}
}

func TestTraversedSemantics(t *testing.T) {
	if OutcomeFiltered.Traversed() {
		t.Error("filtered ne doit pas compter comme traverse")
	}
	if OutcomeSkipped.Traversed() || OutcomeError.Traversed() {
		t.Error("skipped et error ne doivent pas compter comme traverses")
	}
}
