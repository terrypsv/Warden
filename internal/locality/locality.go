// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package locality verifies that the prober actually runs inside the zone it
// claims to test from.
//
// This exists because of a real and dangerous failure. Run "warden verify
// -from red" on a multi-homed host such as the hypervisor, which has a leg in
// every zone, and the probes leave through whichever interface the routing
// table picks. They never traverse the firewall, so a blocked path answers
// as open and the report shows critical leaks that do not exist. A false
// report that looks credible is worse than no report: it sends the operator
// chasing a problem that is an artifact of where the tool was launched.
//
// The check compares the machine's own addresses against the zone CIDRs in
// the matrix. Two situations are refused:
//
//   - the machine has no address in the declared source zone: it is not where
//     it says it is, so its measurements describe a path nobody asked about.
//   - the machine has addresses in more than one matrix zone: it is
//     multi-homed and bypasses the firewall by construction, so no verdict it
//     produces about segmentation means anything.
package locality

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Zone is the minimal view of a matrix zone this package needs. It is defined
// here rather than imported so the package stays free of matrix internals.
type Zone struct {
	Name string
	CIDR string
}

// LocalAddrs is swappable in tests. In production it reports the machine's
// own unicast addresses.
var LocalAddrs = systemAddrs

// Result describes what the check found, for reporting even when it passes.
type Result struct {
	// SourceZone is the zone the prober claims to run from.
	SourceZone string
	// MatchedSource is true when a local address falls in the source zone.
	MatchedSource bool
	// ZonesPresent lists every matrix zone the machine has an address in.
	ZonesPresent []string
	// LocalInSource are the local addresses that landed in the source zone.
	LocalInSource []string
}

// MultiHomed reports whether the machine straddles more than one zone.
func (r Result) MultiHomed() bool {
	return len(r.ZonesPresent) > 1
}

// Check verifies placement. It returns a Result for reporting and an error
// when the placement makes measurement meaningless.
func Check(sourceZone string, zones []Zone) (Result, error) {
	addrs, err := LocalAddrs()
	if err != nil {
		return Result{}, fmt.Errorf("read local addresses: %w", err)
	}

	nets := make(map[string]*net.IPNet, len(zones))
	for _, z := range zones {
		_, network, err := net.ParseCIDR(z.CIDR)
		if err != nil {
			return Result{}, fmt.Errorf("zone %q: invalid cidr %q: %w", z.Name, z.CIDR, err)
		}
		nets[z.Name] = network
	}
	if _, ok := nets[sourceZone]; !ok {
		return Result{}, fmt.Errorf("unknown source zone %q", sourceZone)
	}

	present := map[string]bool{}
	var inSource []string
	for _, ip := range addrs {
		for name, network := range nets {
			if network.Contains(ip) {
				present[name] = true
				if name == sourceZone {
					inSource = append(inSource, ip.String())
				}
			}
		}
	}

	result := Result{
		SourceZone:    sourceZone,
		MatchedSource: len(inSource) > 0,
		ZonesPresent:  sortedKeys(present),
		LocalInSource: inSource,
	}

	if result.MultiHomed() {
		return result, fmt.Errorf(
			"la machine a une adresse dans plusieurs zones de la matrice (%s): "+
				"elle contourne le pare-feu et ses mesures ne veulent rien dire. "+
				"Lancer warden depuis une machine reellement situee dans la zone %q, "+
				"ou forcer avec -no-locality-check si le contournement est voulu",
			strings.Join(result.ZonesPresent, ", "), sourceZone)
	}
	if !result.MatchedSource {
		return result, fmt.Errorf(
			"aucune adresse locale n'appartient a la zone source %q: "+
				"la machine n'est pas la ou elle pretend etre, et sonderait un chemin "+
				"different de celui declare. Lancer warden depuis la zone %q, "+
				"ou forcer avec -no-locality-check",
			sourceZone, sourceZone)
	}
	return result, nil
}

// systemAddrs returns the machine's own unicast IP addresses, skipping
// loopback and link-local which never correspond to a lab zone.
func systemAddrs() ([]net.IP, error) {
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, addr := range ifaceAddrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip)
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
