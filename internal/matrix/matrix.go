// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package matrix loads and validates the declarative flow matrix: the
// authoritative statement of which network flows are supposed to be
// permitted between zones. Everything Warden checks derives from it.
package matrix

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only matrix schema version this build understands.
const SchemaVersion = 1

// DefaultSweepPorts is used when the matrix does not define sweep_ports.
// These are the ports whose exposure across a zone boundary is most likely
// to matter: remote access, SMB, RDP, WinRM, common web listeners, and the
// Active Directory services an attacker reaches for first.
var DefaultSweepPorts = []int{22, 80, 88, 135, 139, 389, 443, 445, 464, 3268, 3269, 3389, 5985, 8080}

// Action is the expected outcome for a flow.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Proto is the transport under test.
type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoICMP Proto = "icmp"
)

// Family is the address family a zone is tested over.
//
// It is explicit and defaults to IPv4 because "tcp" alone lets the resolver
// decide: the same matrix could then be measured over v4 on one host and v6
// on another, and a dual-stacked target can be firewalled on one family and
// wide open on the other. A segmentation tool that cannot say which family
// it measured is not saying much.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Reference attaches an external framework identifier to a flow so findings
// can be traced back to a control. Frameworks and identifiers are free text
// on purpose: the operator owns the mapping, Warden does not invent one.
type Reference struct {
	Framework string `yaml:"framework" json:"framework"`
	ID        string `yaml:"id" json:"id"`
}

// Zone is a network segment with a reachable probe endpoint inside it.
type Zone struct {
	Name   string `yaml:"name"`
	CIDR   string `yaml:"cidr"`
	Probe  string `yaml:"probe"`
	Family Family `yaml:"family"`
	Note   string `yaml:"note"`
}

// Network returns the dial network for TCP probes toward this zone.
func (z Zone) Network() string {
	if z.Family == FamilyIPv6 {
		return "tcp6"
	}
	return "tcp4"
}

// Flow is one declared intent between two zones.
type Flow struct {
	From       string      `yaml:"from"`
	To         string      `yaml:"to"`
	Proto      Proto       `yaml:"proto"`
	Ports      []int       `yaml:"ports"`
	Action     Action      `yaml:"action"`
	Comment    string      `yaml:"comment"`
	References []Reference `yaml:"references"`
}

// Matrix is the whole declaration.
type Matrix struct {
	Version    int    `yaml:"version"`
	Default    Action `yaml:"default"`
	SweepPorts []int  `yaml:"sweep_ports"`
	Zones      []Zone `yaml:"zones"`
	Flows      []Flow `yaml:"flows"`
}

// Load reads, parses and validates a matrix file.
func Load(path string) (*Matrix, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read matrix: %w", err)
	}
	return Parse(raw)
}

// Parse validates a matrix already held in memory.
func Parse(raw []byte) (*Matrix, error) {
	var m Matrix
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse matrix: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate rejects a matrix that cannot be tested unambiguously. It is
// deliberately strict: a silently mistyped zone name would turn a real leak
// into a passing check, which is worse than no tool at all.
func (m *Matrix) Validate() error {
	if m.Version != SchemaVersion {
		return fmt.Errorf("unsupported matrix version %d (expected %d)", m.Version, SchemaVersion)
	}
	switch m.Default {
	case ActionAllow, ActionDeny:
	default:
		return fmt.Errorf("default must be %q or %q, got %q", ActionAllow, ActionDeny, m.Default)
	}
	if len(m.Zones) < 2 {
		return fmt.Errorf("at least two zones are required, got %d", len(m.Zones))
	}

	known := make(map[string]bool, len(m.Zones))
	for i := range m.Zones {
		z := &m.Zones[i]
		if z.Name == "" {
			return fmt.Errorf("zone %d: name is empty", i)
		}
		if known[z.Name] {
			return fmt.Errorf("zone %q is declared twice", z.Name)
		}
		known[z.Name] = true

		switch z.Family {
		case "":
			z.Family = FamilyIPv4
		case FamilyIPv4, FamilyIPv6:
		default:
			return fmt.Errorf("zone %q: family must be %q or %q, got %q",
				z.Name, FamilyIPv4, FamilyIPv6, z.Family)
		}

		ip, network, err := net.ParseCIDR(z.CIDR)
		if err != nil {
			return fmt.Errorf("zone %q: invalid cidr %q", z.Name, z.CIDR)
		}
		if isIPv4(ip) != (z.Family == FamilyIPv4) {
			return fmt.Errorf("zone %q: cidr %s does not match family %s", z.Name, z.CIDR, z.Family)
		}

		probe := net.ParseIP(z.Probe)
		if probe == nil {
			return fmt.Errorf("zone %q: probe must be a bare IP address, got %q", z.Name, z.Probe)
		}
		if isIPv4(probe) != (z.Family == FamilyIPv4) {
			return fmt.Errorf("zone %q: probe %s does not match family %s", z.Name, z.Probe, z.Family)
		}
		if !network.Contains(probe) {
			return fmt.Errorf("zone %q: probe %s is outside %s", z.Name, z.Probe, z.CIDR)
		}
	}

	for _, p := range m.SweepPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("sweep_ports: %d is out of range", p)
		}
	}

	seenKey := make(map[string]bool)
	for i, f := range m.Flows {
		if !known[f.From] {
			return fmt.Errorf("flow %d: unknown source zone %q", i, f.From)
		}
		if !known[f.To] {
			return fmt.Errorf("flow %d: unknown destination zone %q", i, f.To)
		}
		if f.From == f.To {
			return fmt.Errorf("flow %d: source and destination are the same zone (%q)", i, f.From)
		}
		switch f.Proto {
		case ProtoTCP, ProtoUDP:
			if len(f.Ports) == 0 {
				return fmt.Errorf("flow %d (%s -> %s): %s requires at least one port", i, f.From, f.To, f.Proto)
			}
			for _, p := range f.Ports {
				if p < 1 || p > 65535 {
					return fmt.Errorf("flow %d (%s -> %s): port %d is out of range", i, f.From, f.To, p)
				}
			}
		case ProtoICMP:
			if len(f.Ports) != 0 {
				return fmt.Errorf("flow %d (%s -> %s): icmp does not take ports", i, f.From, f.To)
			}
		default:
			return fmt.Errorf("flow %d: unsupported proto %q", i, f.Proto)
		}
		switch f.Action {
		case ActionAllow, ActionDeny:
		default:
			return fmt.Errorf("flow %d: action must be %q or %q, got %q", i, ActionAllow, ActionDeny, f.Action)
		}
		for _, k := range f.keys() {
			if seenKey[k] {
				return fmt.Errorf("flow %d: %s is declared more than once", i, k)
			}
			seenKey[k] = true
		}
	}
	return nil
}

// Zone returns the zone with the given name.
func (m *Matrix) Zone(name string) (Zone, bool) {
	for _, z := range m.Zones {
		if z.Name == name {
			return z, true
		}
	}
	return Zone{}, false
}

// Case is one concrete check to execute.
type Case struct {
	Key        string
	From       Zone
	To         Zone
	Proto      Proto
	Port       int
	Expected   Action
	Declared   bool
	Comment    string
	References []Reference
}

// Network is the dial network for this case: the address family of the
// destination zone for TCP, the bare protocol name otherwise.
func (c Case) Network() string {
	if c.Proto != ProtoTCP {
		return string(c.Proto)
	}
	return c.To.Network()
}

// Cases expands the matrix into the checks runnable from a single source
// zone. Declared flows yield one case per port. Every remaining
// (destination, sweep port) pair yields an undeclared case carrying the
// default action: that is how flows nobody wrote down get discovered, which
// is the entire point of the tool.
func (m *Matrix) Cases(from string) ([]Case, error) {
	src, ok := m.Zone(from)
	if !ok {
		return nil, fmt.Errorf("unknown source zone %q", from)
	}

	var cases []Case
	covered := make(map[string]bool)

	for _, f := range m.Flows {
		if f.From != from {
			continue
		}
		dst, _ := m.Zone(f.To)
		if f.Proto == ProtoICMP {
			k := flowKey(f.From, f.To, ProtoICMP, 0)
			covered[k] = true
			cases = append(cases, Case{
				Key: k, From: src, To: dst, Proto: ProtoICMP,
				Expected: f.Action, Declared: true,
				Comment: f.Comment, References: f.References,
			})
			continue
		}
		for _, p := range f.Ports {
			k := flowKey(f.From, f.To, f.Proto, p)
			covered[k] = true
			cases = append(cases, Case{
				Key: k, From: src, To: dst, Proto: f.Proto, Port: p,
				Expected: f.Action, Declared: true,
				Comment: f.Comment, References: f.References,
			})
		}
	}

	sweep := m.SweepPorts
	if len(sweep) == 0 {
		sweep = DefaultSweepPorts
	}
	for _, dst := range m.Zones {
		if dst.Name == from {
			continue
		}
		for _, p := range sweep {
			k := flowKey(from, dst.Name, ProtoTCP, p)
			if covered[k] {
				continue
			}
			covered[k] = true
			cases = append(cases, Case{
				Key: k, From: src, To: dst, Proto: ProtoTCP, Port: p,
				Expected: m.Default, Declared: false,
			})
		}
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].Key < cases[j].Key })
	return cases, nil
}

func (f Flow) keys() []string {
	if f.Proto == ProtoICMP {
		return []string{flowKey(f.From, f.To, ProtoICMP, 0)}
	}
	out := make([]string, 0, len(f.Ports))
	for _, p := range f.Ports {
		out = append(out, flowKey(f.From, f.To, f.Proto, p))
	}
	return out
}

func flowKey(from, to string, proto Proto, port int) string {
	if proto == ProtoICMP {
		return fmt.Sprintf("%s->%s:icmp", from, to)
	}
	return fmt.Sprintf("%s->%s:%s/%d", from, to, proto, port)
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}
