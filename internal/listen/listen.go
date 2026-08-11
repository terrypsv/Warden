// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package listen opens throwaway TCP listeners inside a zone so probes have
// something deterministic to hit. Without it an unanswered port and a
// filtered path look identical from the far side.
package listen

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Serve binds every requested port on addr and accepts connections until ctx
// is cancelled. Accepted connections are closed immediately: the handshake
// is the only signal Warden needs. Ports that cannot be bound are reported
// and skipped rather than aborting the whole run.
func Serve(ctx context.Context, addr string, ports []int, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(ports) == 0 {
		return fmt.Errorf("no ports requested")
	}

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
