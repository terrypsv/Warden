// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package verify runs the expanded matrix against the network and turns raw
// probe outcomes into findings.
package verify

import (
	"context"
	"fmt"
	"strconv"
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
	// ListenerReady declares that `warden listen` is up in every target zone
	// on every tested port. It removes the ambiguity of an RST: with a
	// listener present, a refusal can only come from the firewall. Without
	// it, refusals are reported for review instead of being judged.
	ListenerReady bool
}

// Runner executes a verification pass.
type Runner struct {
	Matrix  *matrix.Matrix
	Prober  probe.Prober
	Options Options
	Version string
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
	report.Run.Context["mode"] = mode(r.Options.ListenerReady)
	report.Run.Context["cases"] = strconv.Itoa(len(cases))

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

	for i, c := range cases {
		report.Add(r.finding(i+1, c, results[i]))
	}
	report.Finish()
	return report, nil
}

func (r *Runner) finding(seq int, c matrix.Case, res probe.Result) finding.Finding {
	status, severity, title, remediation := r.verdict(c, res)

	observed := string(res.Outcome)
	if res.Detail != "" {
		observed = fmt.Sprintf("%s (%s)", res.Outcome, res.Detail)
	}

	description := c.Comment
	if description == "" && !c.Declared {
		description = "Flux absent de la matrice, evalue avec l'action par defaut."
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
		Evidence: []finding.Evidence{{
			Type: "probe",
			Data: fmt.Sprintf("dst=%s proto=%s port=%d outcome=%s latency=%s",
				c.To.Probe, c.Proto, c.Port, res.Outcome, res.Latency.Round(1e6)),
		}},
		References: convert(c.References),
	}
}

func (r *Runner) verdict(c matrix.Case, res probe.Result) (finding.Status, finding.Severity, string, string) {
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
			if r.Options.ListenerReady {
				return finding.StatusFail, finding.SeverityMedium,
					"Flux autorise rejete par le pare-feu: " + label,
					"Un ecouteur repond dans la zone cible, le RST vient donc du filtrage. Corriger la regle."
			}
			return finding.StatusReview, finding.SeverityLow,
				"Flux autorise, RST recu: " + label,
				"Sans ecouteur dans la zone cible, un RST peut signifier port ferme. Relancer avec warden listen puis -listener."
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
		if r.Options.ListenerReady {
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

func mode(listenerReady bool) string {
	if listenerReady {
		return "strict"
	}
	return "blind"
}
