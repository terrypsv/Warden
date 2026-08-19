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
	port := serveBanner(t, Banner("deadbeefcafe0001", "0.1.0"))

	p := TCPProber{Timeout: time.Second, ExpectToken: "deadbeefcafe0001"}
	res := p.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q (%s), want open", res.Outcome, res.Detail)
	}
	if !res.ListenerConfirmed {
		t.Errorf("l'ecouteur aurait du etre confirme, banniere recue: %q", res.Banner)
	}
	if res.ListenerVersion != "0.1.0" {
		t.Errorf("version = %q, want 0.1.0", res.ListenerVersion)
	}
}

func TestCheckAcceptsUnversionedBanner(t *testing.T) {
	port := serveBanner(t, Banner("abc", ""))

	res := TCPProber{Timeout: time.Second, ExpectToken: "abc"}.
		Check(context.Background(), "127.0.0.1", "tcp", port)

	if !res.ListenerConfirmed {
		t.Error("une banniere sans version reste valide")
	}
	if res.ListenerVersion != "" {
		t.Errorf("version = %q, want vide", res.ListenerVersion)
	}
}

func TestCheckRejectsWrongToken(t *testing.T) {
	port := serveBanner(t, Banner("aaaaaaaaaaaaaaaa", "0.1.0"))

	res := TCPProber{Timeout: time.Second, ExpectToken: "bbbbbbbbbbbbbbbb"}.
		Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q, want open", res.Outcome)
	}
	if res.ListenerConfirmed {
		t.Error("un jeton different ne doit pas confirmer l'ecouteur")
	}
}

func TestCheckSilentServiceIsNotConfirmed(t *testing.T) {
	port := serveBanner(t, "")

	res := TCPProber{Timeout: time.Second, BannerTimeout: 100 * time.Millisecond}.
		Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q, want open", res.Outcome)
	}
	if res.ListenerConfirmed {
		t.Error("un service muet ne doit jamais etre pris pour un ecouteur warden")
	}
}

func TestCheckForeignBannerIsNotConfirmed(t *testing.T) {
	port := serveBanner(t, "SSH-2.0-OpenSSH_9.6\r\n")

	res := TCPProber{Timeout: time.Second}.Check(context.Background(), "127.0.0.1", "tcp", port)

	if res.ListenerConfirmed {
		t.Error("une banniere SSH ne doit pas confirmer un ecouteur warden")
	}
	if res.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner = %q", res.Banner)
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		in      string
		token   string
		version string
		ok      bool
	}{
		{"WARDEN/1 abc 0.1.0", "abc", "0.1.0", true},
		{"WARDEN/1 abc", "abc", "", true},
		{"WARDEN/1 ", "", "", false},
		{"SSH-2.0-OpenSSH_9.6", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		token, version, ok := ParseBanner(c.in)
		if ok != c.ok || token != c.token || version != c.version {
			t.Errorf("ParseBanner(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, token, version, ok, c.token, c.version, c.ok)
		}
	}
}

func TestMatchBanner(t *testing.T) {
	cases := []struct {
		banner string
		expect string
		want   bool
	}{
		{"WARDEN/1 abc 0.1.0", "abc", true},
		{"WARDEN/1 abc", "", true},
		{"WARDEN/1 abc", "xyz", false},
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

func TestNetworkForPinsFamily(t *testing.T) {
	cases := map[string]string{
		"10.10.30.50": "tcp4",
		"127.0.0.1":   "tcp4",
		"0.0.0.0":     "tcp4",
		"::1":         "tcp6",
		"fd00::10":    "tcp6",
		"::":          "tcp6",
		"exemple.lan": "tcp",
	}
	for host, want := range cases {
		if got := NetworkFor(host); got != want {
			t.Errorf("NetworkFor(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestCheckOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 indisponible sur cette machine: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, Banner("v6token", "test"))
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	res := TCPProber{Timeout: time.Second, ExpectToken: "v6token"}.
		Check(context.Background(), "::1", "tcp", port)

	if res.Outcome != OutcomeOpen {
		t.Fatalf("outcome = %q (%s), want open", res.Outcome, res.Detail)
	}
	if !res.ListenerConfirmed {
		t.Error("l'ecouteur IPv6 aurait du etre confirme")
	}
}

// Un service qui n'ecoute qu'en IPv4 ne doit pas etre atteint par une sonde
// IPv6, sinon la famille annoncee dans la matrice ne veut rien dire.
func TestIPv4ListenerIsNotReachedOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	port := ln.Addr().(*net.TCPAddr).Port
	res := TCPProber{Timeout: time.Second}.Check(context.Background(), "::1", "tcp", port)

	if res.Outcome == OutcomeOpen {
		t.Error("une sonde IPv6 ne doit pas atteindre un ecouteur IPv4")
	}
}
