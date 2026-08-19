// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package verify runs the expanded matrix against the network and turns raw
// probe outcomes into findings.
package verify

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/terrypsv/Warden/internal/finding"
	"github.com/terrypsv/Warden/internal/matrix"
	"github.com/terrypsv/Warden/internal/probe"
)

// Category is the finding category emitted by this package.
const Category = "network-segmentation"

// sensitivePorts escalate a leak from high to critical. Reaching remote
// administration or file sharing across a boundary that should be closed is
// not the same class of problem as reaching a web port.
var sensitivePorts = map[int]bool{
	22: true, 135: true, 139: true, 445: true, 1433: true,
	3306: true, 3389: true, 5432: true, 5985: true, 5986: true,
}

// Options configures a run.
type Options struct {
	// From is the zone Warden is running in.
	From string
	// Parallel caps concurrent probes.
	Parallel int
	// ListenerRequested asks for strict verdicts, where a refusal can only
	// come from the firewall because a listener answers on every port. The
	// request alone is not enough: strict applies per zone, and only where a
	// listener actually proved itself by returning a valid banner. An
	// operator who forgets to start a listener in one zone gets honest
	// review verdicts there instead of undeserved passes.
	ListenerRequested bool
}

// Runner executes a verification pass.
type Runner struct {
	Matrix  *matrix.Matrix
	Prober  probe.Prober
	Options Options
	Version string
}

// ZoneStatus is the readiness of one target zone, as seen from the source.
type ZoneStatus struct {
	Zone string
	// Confirmed is true when a listener answered with a valid banner.
	Confirmed bool
	// Port is the port that answered, zero when none did.
	Port int
	// Version is the build the listener announced, empty when unknown.
	Version string
	// Tried counts the ports probed before giving up.
	Tried int
}

// Preflight checks whether a listener is reachable in every target zone,
// before any compliance verdict is computed. It exists because the strict
// workflow spans several machines: an operator who starts the listener in the
// wrong zone, on ports already taken, or stops it too early, otherwise only
// finds out after a full run whose verdicts are quietly degraded.
//
// Preflight stops probing a zone as soon as one banner comes back, so it is
// cheap enough to run before every measurement.
func (r *Runner) Preflight(ctx context.Context) ([]ZoneStatus, error) {
	if r.Matrix == nil {
		return nil, fmt.Errorf("no matrix loaded")
	}
	if r.Prober == nil {
		return nil, fmt.Errorf("no prober configured")
	}
	cases, err := r.Matrix.Cases(r.Options.From)
	if err != nil {
		return nil, err
	}

	byZone := make(map[string][]matrix.Case)
	var order []string
	for _, c := range cases {
		if c.Proto != matrix.ProtoTCP {
			continue
		}
		if _, seen := byZone[c.To.Name]; !seen {
			order = append(order, c.To.Name)
		}
		byZone[c.To.Name] = append(byZone[c.To.Name], c)
	}
	sort.Strings(order)

	statuses := make([]ZoneStatus, len(order))
	var wg sync.WaitGroup
	for i, zone := range order {
		wg.Add(1)
		go func(idx int, zone string) {
			defer wg.Done()
			st := ZoneStatus{Zone: zone}
			for _, c := range byZone[zone] {
				if ctx.Err() != nil {
					break
				}
				st.Tried++
				res := r.Prober.Check(ctx, c.To.Probe, string(c.Proto), c.Port)
				if res.ListenerConfirmed {
					st.Confirmed = true
					st.Port = c.Port
					st.Version = res.ListenerVersion
					break
				}
			}
			statuses[idx] = st
		}(i, zone)
	}
	wg.Wait()
	return statuses, nil
}

// Run probes every case and returns the report. The error return is for
// setup failures only: a failing check is data, not an error.
func (r *Runner) Run(ctx context.Context) (*finding.Report, error) {
	if r.Matrix == nil {
		return nil, fmt.Errorf("no matrix loaded")
	}
	if r.Prober == nil {
		return nil, fmt.Errorf("no prober configured")
	}
	cases, err := r.Matrix.Cases(r.Options.From)
	if err != nil {
		return nil, err
	}

	version := r.Version
	if version == "" {
		version = "dev"
	}
	report := finding.NewReport("warden", version)
	report.Run.Context["source_zone"] = r.Options.From
	report.Run.Context["default_action"] = string(r.Matrix.Default)
	report.Run.Context["cases"] = strconv.Itoa(len(cases))
	report.Run.Context["listener_requested"] = strconv.FormatBool(r.Options.ListenerRequested)

	parallel := r.Options.Parallel
	if parallel <= 0 {
		parallel = 16
	}

	results := make([]probe.Result, len(cases))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	for i := range cases {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c := cases[idx]
			results[idx] = r.Prober.Check(ctx, c.To.Probe, string(c.Proto), c.Port)
		}(i)
	}
	wg.Wait()

	// A listener proves itself by answering with a valid banner on at least
	// one port of a zone. Absent that proof, strict does not apply there.
	strictZones := make(map[string]bool)
	targetZones := make(map[string]bool)
	zoneVersions := make(map[string]map[string]bool)
	for i, c := range cases {
		targetZones[c.To.Name] = true
		if !results[i].ListenerConfirmed {
			continue
		}
		strictZones[c.To.Name] = true
		if zoneVersions[c.To.Name] == nil {
			zoneVersions[c.To.Name] = make(map[string]bool)
		}
		zoneVersions[c.To.Name][results[i].ListenerVersion] = true
	}

	seq := 0
	for i, c := range cases {
		seq++
		strict := r.Options.ListenerRequested && strictZones[c.To.Name]
		report.Add(r.finding(seq, c, results[i], strict))
	}

	if r.Options.ListenerRequested {
		for _, name := range sortedTrue(targetZones) {
			if !strictZones[name] {
				seq++
				report.Add(r.unconfirmedListener(seq, name))
				continue
			}
			if mismatch := versionMismatch(zoneVersions[name], version); mismatch != "" {
				seq++
				report.Add(r.versionDrift(seq, name, mismatch, version))
			}
		}
	}

	report.Run.Context["strict_zones"] = strings.Join(sortedTrue(strictZones), ",")
	report.Finish()
	return report, nil
}

// StrictZones reports which target zones proved a listener during a run.
func StrictZones(report *finding.Report) []string {
	raw := report.Run.Context["strict_zones"]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func (r *Runner) unconfirmedListener(seq int, zone string) finding.Finding {
	return finding.Finding{
		ID:       fmt.Sprintf("WRD-SEG-%04d", seq),
		Title:    "Mode strict demande mais aucun ecouteur confirme dans la zone " + zone,
		Category: Category,
		Severity: finding.SeverityInfo,
		Status:   finding.StatusReview,
		Target:   finding.Target{Type: "zone", Identifier: zone},
		Expected: "banniere warden sur au moins un port joignable",
		Observed: "aucune banniere recue",
		Remediation: "Lancer warden listen dans cette zone, ou accepter des verdicts blind. " +
			"Note: si tous les ports de la zone sont correctement bloques, aucune banniere ne peut " +
			"remonter et la confirmation est impossible par construction.",
		Declared: false,
	}
}

func (r *Runner) versionDrift(seq int, zone, observed, expected string) finding.Finding {
	return finding.Finding{
		ID:       fmt.Sprintf("WRD-SEG-%04d", seq),
		Title:    "Ecart de version entre la sonde et l'ecouteur de la zone " + zone,
		Category: Category,
		Severity: finding.SeverityLow,
		Status:   finding.StatusReview,
		Target:   finding.Target{Type: "zone", Identifier: zone},
		Expected: expected,
		Observed: observed,
		Remediation: "Redeployer le meme binaire des deux cotes. Deux versions differentes " +
			"peuvent interpreter la matrice ou la banniere differemment, ce qui rend la mesure douteuse.",
		Declared: false,
	}
}

func (r *Runner) finding(seq int, c matrix.Case, res probe.Result, strict bool) finding.Finding {
	status, severity, title, remediation := r.verdict(c, res, strict)

	observed := string(res.Outcome)
	switch {
	case res.Outcome == probe.OutcomeOpen && res.ListenerConfirmed:
		observed = "open (ecouteur warden)"
	case res.Outcome == probe.OutcomeOpen:
		observed = "open (service tiers)"
	case res.Detail != "":
		observed = fmt.Sprintf("%s (%s)", res.Outcome, res.Detail)
	}

	description := c.Comment
	if description == "" && !c.Declared {
		description = "Flux absent de la matrice, evalue avec l'action par defaut."
	}

	evidence := []finding.Evidence{{
		Type: "probe",
		Data: fmt.Sprintf("dst=%s proto=%s port=%d outcome=%s latency=%s mode=%s",
			c.To.Probe, c.Proto, c.Port, res.Outcome, res.Latency.Round(1e6), modeLabel(strict)),
	}}
	if res.Banner != "" {
		evidence = append(evidence, finding.Evidence{Type: "banner", Data: res.Banner})
	}

	return finding.Finding{
		ID:          fmt.Sprintf("WRD-SEG-%04d", seq),
		Title:       title,
		Description: description,
		Category:    Category,
		Severity:    severity,
		Status:      status,
		Target:      finding.Target{Type: "flow", Identifier: c.Key},
		Expected:    string(c.Expected),
		Observed:    observed,
		Remediation: remediation,
		Declared:    c.Declared,
		Evidence:    evidence,
		References:  convert(c.References),
	}
}

func (r *Runner) verdict(c matrix.Case, res probe.Result, strict bool) (finding.Status, finding.Severity, string, string) {
	label := c.Key

	switch res.Outcome {
	case probe.OutcomeSkipped:
		return finding.StatusSkipped, finding.SeverityInfo,
			"Controle non execute: " + label, res.Detail
	case probe.OutcomeError:
		return finding.StatusError, finding.SeverityInfo,
			"Sonde en echec: " + label, "Verifier la joignabilite de la sonde distante."
	}

	if c.Expected == matrix.ActionAllow {
		switch res.Outcome {
		case probe.OutcomeOpen:
			return finding.StatusPass, finding.SeverityInfo,
				"Flux autorise et joignable: " + label, ""
		case probe.OutcomeFiltered:
			return finding.StatusFail, finding.SeverityMedium,
				"Flux declare autorise mais bloque: " + label,
				"Verifier la regle de pare-feu correspondante, ou retirer ce flux de la matrice s'il n'est plus necessaire."
		case probe.OutcomeRefused:
			if strict {
				return finding.StatusFail, finding.SeverityMedium,
					"Flux autorise rejete par le pare-feu: " + label,
					"Un ecouteur confirme repond dans la zone cible, le RST vient donc du filtrage. Corriger la regle."
			}
			return finding.StatusReview, finding.SeverityLow,
				"Flux autorise, RST recu: " + label,
				"Sans ecouteur confirme dans la zone cible, un RST peut signifier port ferme. Lancer warden listen puis relancer avec -listener."
		}
	}

	switch res.Outcome {
	case probe.OutcomeFiltered:
		return finding.StatusPass, finding.SeverityInfo,
			"Flux interdit effectivement bloque: " + label, ""
	case probe.OutcomeOpen:
		severity := finding.SeverityHigh
		if sensitivePorts[c.Port] {
			severity = finding.SeverityCritical
		}
		title := "Fuite de cloisonnement: " + label
		if !c.Declared {
			title = "Flux non declare joignable: " + label
		}
		return finding.StatusFail, severity, title,
			"Ajouter une regle de blocage explicite sur ce flux, ou le declarer dans la matrice s'il est legitime."
	case probe.OutcomeRefused:
		if strict {
			return finding.StatusPass, finding.SeverityInfo,
				"Flux interdit rejete par le pare-feu: " + label,
				"Preferer un blocage silencieux a un reject pour ne pas renseigner un attaquant."
		}
		return finding.StatusReview, finding.SeverityMedium,
			"RST recu sur un flux interdit: " + label,
			"Le paquet a peut-etre traverse le pare-feu. Lancer warden listen dans la zone cible puis relancer avec -listener."
	}

	return finding.StatusError, finding.SeverityInfo,
		"Resultat non interprete: " + label, ""
}

// versionMismatch returns a printable list of listener versions that differ
// from the prober's own, or the empty string when everything agrees. An
// unversioned banner is tolerated: it only means the listener predates the
// versioned format.
func versionMismatch(seen map[string]bool, expected string) string {
	var odd []string
	for v := range seen {
		if v == "" || v == expected {
			continue
		}
		odd = append(odd, v)
	}
	if len(odd) == 0 {
		return ""
	}
	sort.Strings(odd)
	return strings.Join(odd, ", ")
}

func convert(in []matrix.Reference) []finding.Reference {
	if len(in) == 0 {
		return nil
	}
	out := make([]finding.Reference, 0, len(in))
	for _, r := range in {
		out = append(out, finding.Reference{Framework: r.Framework, ID: r.ID})
	}
	return out
}

func modeLabel(strict bool) string {
	if strict {
		return "strict"
	}
	return "blind"
}

func sortedTrue(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
