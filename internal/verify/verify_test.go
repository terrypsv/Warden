// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package verify

import (
	"context"
	"testing"

	"github.com/terrypsv/Warden/internal/finding"
	"github.com/terrypsv/Warden/internal/matrix"
	"github.com/terrypsv/Warden/internal/probe"
)

// fakeProber returns a scripted result per port, which lets the verdict logic
// be tested without a network.
type fakeProber struct {
	byPort   map[int]probe.Result
	fallback probe.Result
}

func (f fakeProber) Check(_ context.Context, _, _ string, port int) probe.Result {
	if res, ok := f.byPort[port]; ok {
		return res
	}
	return f.fallback
}

const testMatrix = `
version: 1
default: deny
sweep_ports: [445]
zones:
  - name: red
    cidr: 10.10.30.0/24
    probe: 10.10.30.50
  - name: lan
    cidr: 10.10.10.0/24
    probe: 10.10.10.50
flows:
  - from: red
    to: lan
    proto: tcp
    ports: [80]
    action: allow
`

func run(t *testing.T, p probe.Prober, listenerRequested bool) (*finding.Report, map[string]finding.Finding) {
	t.Helper()
	m, err := matrix.Parse([]byte(testMatrix))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := &Runner{
		Matrix:  m,
		Prober:  p,
		Version: "test",
		Options: Options{From: "red", Parallel: 4, ListenerRequested: listenerRequested},
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := make(map[string]finding.Finding, len(report.Findings))
	for _, f := range report.Findings {
		out[f.Target.Identifier] = f
	}
	return report, out
}

// confirmedProber simulates a warden listener answering on 80 and nothing
// listening on 445.
func confirmedProber() fakeProber {
	return fakeProber{
		byPort: map[int]probe.Result{
			80:  {Outcome: probe.OutcomeOpen, ListenerConfirmed: true, Banner: probe.BannerPrefix + "abc"},
			445: {Outcome: probe.OutcomeRefused},
		},
	}
}

// unconfirmedProber simulates a real service on 80 that says nothing, so no
// listener can be proven anywhere.
func unconfirmedProber() fakeProber {
	return fakeProber{
		byPort: map[int]probe.Result{
			80:  {Outcome: probe.OutcomeOpen},
			445: {Outcome: probe.OutcomeRefused},
		},
	}
}

func TestStrictAppliesOnlyWhenListenerProven(t *testing.T) {
	report, got := run(t, confirmedProber(), true)

	if zones := StrictZones(report); len(zones) != 1 || zones[0] != "lan" {
		t.Fatalf("strict zones = %v, want [lan]", zones)
	}
	if s := got["red->lan:tcp/445"].Status; s != finding.StatusPass {
		t.Errorf("ecouteur confirme, RST sur flux interdit: status = %q, want pass", s)
	}
}

func TestStrictRequestedWithoutProofStaysBlind(t *testing.T) {
	report, got := run(t, unconfirmedProber(), true)

	if zones := StrictZones(report); len(zones) != 0 {
		t.Fatalf("strict zones = %v, want vide", zones)
	}
	if s := got["red->lan:tcp/445"].Status; s != finding.StatusReview {
		t.Errorf("sans preuve d'ecouteur, RST doit rester ambigu: status = %q, want review", s)
	}
	// La zone non confirmee doit produire son propre constat, sinon l'operateur
	// croit avoir mesure en strict alors qu'il n'en est rien.
	zoneFinding, ok := got["lan"]
	if !ok {
		t.Fatal("aucun constat sur la zone non confirmee")
	}
	if zoneFinding.Status != finding.StatusReview {
		t.Errorf("constat de zone: status = %q, want review", zoneFinding.Status)
	}
}

func TestOpenOnDeniedFlowIsCriticalLeak(t *testing.T) {
	p := fakeProber{fallback: probe.Result{Outcome: probe.OutcomeOpen}}
	_, got := run(t, p, false)

	leak, ok := got["red->lan:tcp/445"]
	if !ok {
		t.Fatal("controle red->lan:tcp/445 absent")
	}
	if leak.Status != finding.StatusFail {
		t.Errorf("status = %q, want fail", leak.Status)
	}
	if leak.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical (445 est un port sensible)", leak.Severity)
	}
	if leak.Declared {
		t.Error("445 n'est pas declare dans la matrice")
	}
	if got["red->lan:tcp/80"].Status != finding.StatusPass {
		t.Error("flux autorise joignable devrait passer")
	}
}

func TestFilteredMeansCompliantDenyAndBrokenAllow(t *testing.T) {
	p := fakeProber{fallback: probe.Result{Outcome: probe.OutcomeFiltered}}
	_, got := run(t, p, false)

	if s := got["red->lan:tcp/445"].Status; s != finding.StatusPass {
		t.Errorf("flux interdit bloque: status = %q, want pass", s)
	}
	broken := got["red->lan:tcp/80"]
	if broken.Status != finding.StatusFail {
		t.Errorf("flux autorise bloque: status = %q, want fail", broken.Status)
	}
	if broken.Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium", broken.Severity)
	}
}

func TestObservedDistinguishesListenerFromService(t *testing.T) {
	_, got := run(t, confirmedProber(), true)
	if got["red->lan:tcp/80"].Observed != "open (ecouteur warden)" {
		t.Errorf("observed = %q", got["red->lan:tcp/80"].Observed)
	}

	_, got = run(t, unconfirmedProber(), true)
	if got["red->lan:tcp/80"].Observed != "open (service tiers)" {
		t.Errorf("observed = %q", got["red->lan:tcp/80"].Observed)
	}
}

func TestSkippedProtocolsAreReportedAsSkipped(t *testing.T) {
	p := fakeProber{fallback: probe.Result{Outcome: probe.OutcomeSkipped}}
	_, got := run(t, p, false)
	for key, f := range got {
		if f.Status != finding.StatusSkipped {
			t.Errorf("%s: status = %q, want skipped", key, f.Status)
		}
	}
}

func TestRunRejectsMissingSetup(t *testing.T) {
	if _, err := (&Runner{}).Run(context.Background()); err == nil {
		t.Fatal("Run sans matrice devrait echouer")
	}
}
