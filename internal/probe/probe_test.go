// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package probe

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// serveBanner starts a listener that announces the given text then closes.
// An empty text means the listener stays silent, like most real services.
func serveBanner(t *testing.T, text string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if text != "" {
				_, _ = io.WriteString(conn, text)
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestCheckConfirmsWardenListener(t *testing.T) {
	port := serveBanner(t, BannerPrefix+"deadbeefcafe0001\n")

	p := TCPProber{Timeout: time.Second, ExpectToken: "deadbeefcafe0001"}
	res := p.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q (%s), want open", res.Outcome, res.Detail)
	}
	if !res.ListenerConfirmed {
		t.Errorf("l'ecouteur aurait du etre confirme, banniere recue: %q", res.Banner)
	}
}

func TestCheckRejectsWrongToken(t *testing.T) {
	port := serveBanner(t, BannerPrefix+"aaaaaaaaaaaaaaaa\n")

	p := TCPProber{Timeout: time.Second, ExpectToken: "bbbbbbbbbbbbbbbb"}
	res := p.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q, want open", res.Outcome)
	}
	if res.ListenerConfirmed {
		t.Error("un jeton different ne doit pas confirmer l'ecouteur")
	}
}

func TestCheckSilentServiceIsNotConfirmed(t *testing.T) {
	port := serveBanner(t, "")

	p := TCPProber{Timeout: time.Second, BannerTimeout: 100 * time.Millisecond}
	res := p.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q, want open", res.Outcome)
	}
	if res.ListenerConfirmed {
		t.Error("un service muet ne doit jamais etre pris pour un ecouteur warden")
	}
	if res.Banner != "" {
		t.Errorf("banner = %q, want vide", res.Banner)
	}
}

func TestCheckForeignBannerIsNotConfirmed(t *testing.T) {
	port := serveBanner(t, "SSH-2.0-OpenSSH_9.6\r\n")

	p := TCPProber{Timeout: time.Second}
	res := p.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.ListenerConfirmed {
		t.Error("une banniere SSH ne doit pas confirmer un ecouteur warden")
	}
	if res.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner = %q", res.Banner)
	}
}

func TestMatchBanner(t *testing.T) {
	cases := []struct {
		banner string
		expect string
		want   bool
	}{
		{BannerPrefix + "abc", "abc", true},
		{BannerPrefix + "abc", "", true},
		{BannerPrefix + "abc", "xyz", false},
		{"SSH-2.0-OpenSSH_9.6", "", false},
		{"", "", false},
		{"WARDEN/0 abc", "abc", false},
	}
	for _, c := range cases {
		if got := MatchBanner(c.banner, c.expect); got != c.want {
			t.Errorf("MatchBanner(%q, %q) = %v, want %v", c.banner, c.expect, got, c.want)
		}
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
	if res.ListenerConfirmed {
		t.Error("un port ferme ne peut pas confirmer un ecouteur")
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
