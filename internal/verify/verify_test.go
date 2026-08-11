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

// fakeProber renvoie un resultat fixe, ce qui permet de tester la logique de
// verdict sans reseau.
type fakeProber struct{ outcome probe.Outcome }

func (f fakeProber) Check(context.Context, string, string, int) probe.Result {
	return probe.Result{Outcome: f.outcome}
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

func run(t *testing.T, outcome probe.Outcome, listenerReady bool) map[string]finding.Finding {
	t.Helper()
	m, err := matrix.Parse([]byte(testMatrix))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := &Runner{
		Matrix:  m,
		Prober:  fakeProber{outcome: outcome},
		Version: "test",
		Options: Options{From: "red", Parallel: 4, ListenerReady: listenerReady},
	}
	report, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := make(map[string]finding.Finding, len(report.Findings))
	for _, f := range report.Findings {
		out[f.Target.Identifier] = f
	}
	return out
}

func TestOpenOnDeniedFlowIsCriticalLeak(t *testing.T) {
	got := run(t, probe.OutcomeOpen, true)

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

	allowed := got["red->lan:tcp/80"]
	if allowed.Status != finding.StatusPass {
		t.Errorf("flux autorise joignable: status = %q, want pass", allowed.Status)
	}
}

func TestFilteredMeansCompliantDenyAndBrokenAllow(t *testing.T) {
	got := run(t, probe.OutcomeFiltered, true)

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

func TestRefusedIsAmbiguousWithoutListener(t *testing.T) {
	blind := run(t, probe.OutcomeRefused, false)
	if s := blind["red->lan:tcp/445"].Status; s != finding.StatusReview {
		t.Errorf("mode blind: status = %q, want review", s)
	}

	strict := run(t, probe.OutcomeRefused, true)
	if s := strict["red->lan:tcp/445"].Status; s != finding.StatusPass {
		t.Errorf("mode strict: status = %q, want pass", s)
	}
}

func TestSkippedProtocolsAreReportedAsSkipped(t *testing.T) {
	got := run(t, probe.OutcomeSkipped, true)
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
