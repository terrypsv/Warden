// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package listen opens throwaway TCP listeners inside a zone so probes have
// something deterministic to hit. Without it an unanswered port and a
// filtered path look identical from the far side.
package listen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/terrypsv/Warden/internal/probe"
)

// writeTimeout bounds the banner write so a stalled peer cannot pin a goroutine.
const writeTimeout = 2 * time.Second

// NewToken returns a random token identifying one listener deployment.
func NewToken() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Serve binds every requested port on addr and announces itself to every
// connection with a signed, versioned banner, then closes. The banner is what
// lets the prober prove a listener was really there instead of trusting the
// operator's -listener flag. Ports that cannot be bound are reported and
// skipped rather than aborting the whole run.
//
// Serve returns when ctx is done. Callers wanting an unattended run should
// bound the context: a listener left behind answers later probes and is then
// indistinguishable from a real service, which silently corrupts a later
// measurement.
func Serve(ctx context.Context, addr string, ports []int, token, version string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(ports) == 0 {
		return fmt.Errorf("no ports requested")
	}
	if token == "" {
		return fmt.Errorf("no token provided")
	}

	banner := probe.Banner(token, version)

	var (
		wg        sync.WaitGroup
		listeners []net.Listener
		bound     int
	)

	for _, p := range ports {
		target := net.JoinHostPort(addr, strconv.Itoa(p))
		ln, err := net.Listen("tcp", target)
		if err != nil {
			logf("port %d indisponible: %v", p, err)
			continue
		}
		bound++
		listeners = append(listeners, ln)
		logf("ecoute sur %s", target)

		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				logf("connexion depuis %s vers %s", conn.RemoteAddr(), ln.Addr())
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				_, _ = io.WriteString(conn, banner)
				_ = conn.Close()
			}
		}(ln)
	}

	if bound == 0 {
		return fmt.Errorf("aucun port n'a pu etre ouvert")
	}

	<-ctx.Done()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	wg.Wait()
	logf("arret, %d port(s) libere(s)", bound)
	return nil
}
