// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package discover finds services that answer across a zone boundary but
// appear nowhere in the flow matrix.
//
// Verification answers "does the network do what I declared". Discovery
// answers the question that precedes it: "what did I forget to declare". A
// matrix is written once and the infrastructure keeps moving, so the gap
// between the two grows silently. Everything discover reports is a hole in
// the declaration, not necessarily a hole in the firewall.
package discover

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/terrypsv/Warden/internal/finding"
	"github.com/terrypsv/Warden/internal/matrix"
	"github.com/terrypsv/Warden/internal/probe"
)

// Category is the finding category emitted by this package.
const Category = "service-discovery"

// DefaultPorts is the sweep used when the operator does not supply one. It
// covers the services that actually turn up on a corporate segment rather
// than the full range: a 65535-port sweep is slow, lights up every IDS, and
// finds almost nothing the list below misses.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 67, 69, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139,
	143, 161, 389, 443, 445, 464, 465, 500, 512, 513, 514, 515, 543, 544, 548,
	554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995,
	1080, 1099, 1194, 1352, 1433, 1434, 1521, 1723, 1883, 1900, 2049, 2082,
	2083, 2181, 2375, 2376, 2379, 2483, 2484, 3000, 3128, 3268, 3269, 3306,
	3389, 3690, 4444, 4445, 4786, 4840, 5000, 5060, 5061, 5222, 5353, 5432,
	5555, 5601, 5672, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 6667, 7001,
	7077, 7443, 8000, 8006, 8008, 8009, 8010, 8025, 8080, 8081, 8082, 8088,
	8090, 8091, 8123, 8140, 8161, 8200, 8222, 8291, 8443, 8500, 8530, 8531,
	8600, 8834, 8888, 9000, 9001, 9042, 9090, 9091, 9092, 9100, 9200, 9300,
	9418, 9443, 9990, 10000, 10250, 11211, 15672, 27017, 27018, 32400, 47001,
	49152, 49153, 49154, 50000,
}

// Options configures a discovery pass.
type Options struct {
	// From is the zone the probes leave from.
	From string
	// To restricts discovery to one target zone. Empty means every zone.
	To string
	// Ports is the sweep list. Empty falls back to DefaultPorts.
	Ports []int
	// Parallel caps concurrent probes.
	Parallel int
}

// Service is one port that answered.
type Service struct {
	Zone string
	Addr string
	Port int
	// Declared is true when the matrix mentions this flow explicitly. Sweep
	// coverage does not count: a port reached by the default action was
	// never declared by anyone.
	Declared bool
	// Action is the declared action, empty when undeclared.
	Action matrix.Action
	// ListenerConfirmed marks our own warden listener, which must never be
	// mistaken for a discovery.
	ListenerConfirmed bool
	// Banner is what the peer announced, when it spoke first.
	Banner  string
	Latency time.Duration
}

// Key is the stable identifier of the flow this service sits behind.
func (s Service) Key(from string) string {
	return fmt.Sprintf("%s->%s:tcp/%d", from, s.Zone, s.Port)
}

// Runner executes a discovery pass.
type Runner struct {
	Matrix  *matrix.Matrix
	Prober  probe.Prober
	Options Options
	Version string
}

// Run probes the sweep against every target zone and returns the services
// that answered, our own listeners included so the caller can filter or
// display them explicitly.
func (r *Runner) Run(ctx context.Context) ([]Service, error) {
	if r.Matrix == nil {
		return nil, fmt.Errorf("no matrix loaded")
	}
	if r.Prober == nil {
		return nil, fmt.Errorf("no prober configured")
	}
	if _, ok := r.Matrix.Zone(r.Options.From); !ok {
		return nil, fmt.Errorf("unknown source zone %q", r.Options.From)
	}

	targets, err := r.targets()
	if err != nil {
		return nil, err
	}
	ports := r.Options.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	declared := r.declaredPorts()

	type job struct {
		zone matrix.Zone
		port int
	}
	var jobs []job
	for _, z := range targets {
		for _, p := range ports {
			jobs = append(jobs, job{zone: z, port: p})
		}
	}

	parallel := r.Options.Parallel
	if parallel <= 0 {
		parallel = 64
	}

	results := make([]probe.Result, len(jobs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			j := jobs[idx]
			results[idx] = r.Prober.Check(ctx, j.zone.Probe, "tcp", j.port)
		}(i)
	}
	wg.Wait()

	var found []Service
	for i, j := range jobs {
		res := results[i]
		if res.Outcome != probe.OutcomeOpen {
			continue
		}
		key := fmt.Sprintf("%s->%s:tcp/%d", r.Options.From, j.zone.Name, j.port)
		action, isDeclared := declared[key]
		found = append(found, Service{
			Zone:              j.zone.Name,
			Addr:              j.zone.Probe,
			Port:              j.port,
			Declared:          isDeclared,
			Action:            action,
			ListenerConfirmed: res.ListenerConfirmed,
			Banner:            res.Banner,
			Latency:           res.Latency,
		})
	}

	sort.Slice(found, func(a, b int) bool {
		if found[a].Zone != found[b].Zone {
			return found[a].Zone < found[b].Zone
		}
		return found[a].Port < found[b].Port
	})
	return found, nil
}

// Undeclared filters out our own listeners and everything the matrix already
// mentions, leaving only what the declaration is missing.
func Undeclared(services []Service) []Service {
	var out []Service
	for _, s := range services {
		if s.ListenerConfirmed || s.Declared {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (r *Runner) targets() ([]matrix.Zone, error) {
	if r.Options.To != "" {
		z, ok := r.Matrix.Zone(r.Options.To)
		if !ok {
			return nil, fmt.Errorf("unknown target zone %q", r.Options.To)
		}
		if z.Name == r.Options.From {
			return nil, fmt.Errorf("source and target zone are the same (%q)", z.Name)
		}
		return []matrix.Zone{z}, nil
	}
	var out []matrix.Zone
	for _, z := range r.Matrix.Zones {
		if z.Name == r.Options.From {
			continue
		}
		out = append(out, z)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no target zone besides %q", r.Options.From)
	}
	return out, nil
}

// declaredPorts indexes the flows the operator wrote down. Ports reached only
// through the default sweep are deliberately absent: they are exactly what
// discovery is meant to surface.
func (r *Runner) declaredPorts() map[string]matrix.Action {
	out := make(map[string]matrix.Action)
	for _, f := range r.Matrix.Flows {
		if f.From != r.Options.From || f.Proto != matrix.ProtoTCP {
			continue
		}
		for _, p := range f.Ports {
			out[fmt.Sprintf("%s->%s:tcp/%d", f.From, f.To, p)] = f.Action
		}
	}
	return out
}

// Report turns undeclared services into findings in the shared schema. They
// are reported as review rather than fail: an undeclared service is a gap in
// the declaration, and only a human knows whether the flow is legitimate.
func Report(services []Service, from, version string) *finding.Report {
	report := finding.NewReport("warden", version)
	report.Run.Context["source_zone"] = from
	report.Run.Context["mode"] = "discover"

	undeclared := Undeclared(services)
	report.Run.Context["undeclared"] = strconv.Itoa(len(undeclared))

	for i, s := range undeclared {
		severity := finding.SeverityLow
		if sensitive[s.Port] {
			severity = finding.SeverityMedium
		}
		evidence := []finding.Evidence{{
			Type: "probe",
			Data: fmt.Sprintf("dst=%s proto=tcp port=%d outcome=open latency=%s",
				s.Addr, s.Port, s.Latency.Round(time.Millisecond)),
		}}
		if s.Banner != "" {
			evidence = append(evidence, finding.Evidence{Type: "banner", Data: s.Banner})
		}
		report.Add(finding.Finding{
			ID:          fmt.Sprintf("WRD-DSC-%04d", i+1),
			Title:       "Service joignable absent de la matrice: " + s.Key(from),
			Description: "Un service repond sur ce port, mais aucun flux declare ne le mentionne.",
			Category:    Category,
			Severity:    severity,
			Status:      finding.StatusReview,
			Target:      finding.Target{Type: "service", Identifier: s.Key(from)},
			Expected:    "flux declare dans la matrice",
			Observed:    "port ouvert, non declare",
			Remediation: "Declarer ce flux avec l'action qui correspond a l'intention reelle, " +
				"ou fermer le service s'il n'a pas lieu d'etre joignable depuis cette zone.",
			Declared: false,
			Evidence: evidence,
		})
	}
	report.Finish()
	return report
}

// sensitive raises the severity of a discovery on a port that grants remote
// access or data.
var sensitive = map[int]bool{
	22: true, 23: true, 135: true, 139: true, 445: true, 1433: true,
	3306: true, 3389: true, 5432: true, 5985: true, 5986: true, 6379: true,
	9200: true, 11211: true, 27017: true,
}

// YAMLSuggestion renders a matrix fragment covering the undeclared services.
// The action is deny with an explicit marker: the tool observes reachability,
// it cannot know intent, and silently proposing allow would launder an
// accidental exposure into a documented one.
func YAMLSuggestion(services []Service, from string) string {
	undeclared := Undeclared(services)
	if len(undeclared) == 0 {
		return ""
	}

	byZone := make(map[string][]int)
	var order []string
	for _, s := range undeclared {
		if _, seen := byZone[s.Zone]; !seen {
			order = append(order, s.Zone)
		}
		byZone[s.Zone] = append(byZone[s.Zone], s.Port)
	}
	sort.Strings(order)

	var b strings.Builder
	b.WriteString("# Fragment genere par warden discover, a relire avant integration.\n")
	b.WriteString("# L'action deny est un defaut prudent: seul toi sais si ces flux sont legitimes.\n")
	for _, zone := range order {
		ports := byZone[zone]
		sort.Ints(ports)
		fields := make([]string, 0, len(ports))
		for _, p := range ports {
			fields = append(fields, strconv.Itoa(p))
		}
		fmt.Fprintf(&b, "  - from: %s\n", from)
		fmt.Fprintf(&b, "    to: %s\n", zone)
		b.WriteString("    proto: tcp\n")
		fmt.Fprintf(&b, "    ports: [%s]\n", strings.Join(fields, ", "))
		b.WriteString("    action: deny\n")
		b.WriteString("    comment: detecte par warden discover, action a valider\n")
	}
	return b.String()
}

// ParsePortSpec reads a list of ports and ranges, such as "22,80,8000-8100".
func ParsePortSpec(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	seen := make(map[int]bool)
	var out []int

	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port hors plage: %d", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		return nil
	}

	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(field, "-")
		if !isRange {
			p, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("port invalide %q", field)
			}
			if err := add(p); err != nil {
				return nil, err
			}
			continue
		}
		start, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("debut de plage invalide %q", lo)
		}
		end, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("fin de plage invalide %q", hi)
		}
		if start > end {
			return nil, fmt.Errorf("plage inversee: %d-%d", start, end)
		}
		for p := start; p <= end; p++ {
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("aucun port valide fourni")
	}
	sort.Ints(out)
	return out, nil
}
