// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package discover

import (
	"context"
	"strings"
	"testing"

	"github.com/terrypsv/Warden/internal/finding"
	"github.com/terrypsv/Warden/internal/matrix"
	"github.com/terrypsv/Warden/internal/probe"
)

type fakeProber struct {
	open map[int]probe.Result
}

func (f fakeProber) Check(_ context.Context, _, _ string, port int) probe.Result {
	if res, ok := f.open[port]; ok {
		return res
	}
	return probe.Result{Outcome: probe.OutcomeFiltered}
}

const testMatrix = `
version: 1
default: deny
zones:
  - name: red
    cidr: 10.10.30.0/24
    probe: 10.10.30.50
  - name: dmz
    cidr: 10.10.20.0/24
    probe: 10.10.20.10
flows:
  - from: red
    to: dmz
    proto: tcp
    ports: [80]
    action: allow
`

func newRunner(t *testing.T, p probe.Prober, ports []int) *Runner {
	t.Helper()
	m, err := matrix.Parse([]byte(testMatrix))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return &Runner{
		Matrix:  m,
		Prober:  p,
		Version: "test",
		Options: Options{From: "red", Ports: ports, Parallel: 4},
	}
}

func TestRunSeparatesDeclaredFromUndeclared(t *testing.T) {
	p := fakeProber{open: map[int]probe.Result{
		80:   {Outcome: probe.OutcomeOpen},
		8081: {Outcome: probe.OutcomeOpen},
	}}
	services, err := newRunner(t, p, []int{80, 445, 8081}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %d, want 2", len(services))
	}

	byPort := map[int]Service{}
	for _, s := range services {
		byPort[s.Port] = s
	}
	if !byPort[80].Declared || byPort[80].Action != matrix.ActionAllow {
		t.Errorf("80 devrait etre declare en allow: %+v", byPort[80])
	}
	if byPort[8081].Declared {
		t.Error("8081 n'est declare nulle part dans la matrice")
	}

	undeclared := Undeclared(services)
	if len(undeclared) != 1 || undeclared[0].Port != 8081 {
		t.Fatalf("undeclared = %+v, want [8081]", undeclared)
	}
}

func TestOwnListenerIsNotADiscovery(t *testing.T) {
	p := fakeProber{open: map[int]probe.Result{
		3389: {
			Outcome:           probe.OutcomeOpen,
			ListenerConfirmed: true,
			Banner:            probe.Banner("abc", "test"),
		},
	}}
	services, err := newRunner(t, p, []int{3389}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(services) != 1 || !services[0].ListenerConfirmed {
		t.Fatalf("services = %+v", services)
	}
	if got := Undeclared(services); len(got) != 0 {
		t.Fatalf("notre propre ecouteur ne doit pas etre signale: %+v", got)
	}
}

func TestReportUsesReviewNotFail(t *testing.T) {
	p := fakeProber{open: map[int]probe.Result{
		3306: {Outcome: probe.OutcomeOpen},
		8081: {Outcome: probe.OutcomeOpen},
	}}
	services, err := newRunner(t, p, []int{3306, 8081}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	report := Report(services, "red", "test")
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
	for _, f := range report.Findings {
		if f.Status != finding.StatusReview {
			t.Errorf("%s: status = %q, want review", f.ID, f.Status)
		}
	}
	// 3306 est un port sensible, sa gravite doit etre plus elevee que 8081.
	byTarget := map[string]finding.Finding{}
	for _, f := range report.Findings {
		byTarget[f.Target.Identifier] = f
	}
	if byTarget["red->dmz:tcp/3306"].Severity != finding.SeverityMedium {
		t.Errorf("3306: severity = %q, want medium", byTarget["red->dmz:tcp/3306"].Severity)
	}
	if byTarget["red->dmz:tcp/8081"].Severity != finding.SeverityLow {
		t.Errorf("8081: severity = %q, want low", byTarget["red->dmz:tcp/8081"].Severity)
	}
}

func TestYAMLSuggestionDefaultsToDeny(t *testing.T) {
	p := fakeProber{open: map[int]probe.Result{
		8081: {Outcome: probe.OutcomeOpen},
		9000: {Outcome: probe.OutcomeOpen},
	}}
	services, err := newRunner(t, p, []int{8081, 9000}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := YAMLSuggestion(services, "red")
	for _, want := range []string{"from: red", "to: dmz", "ports: [8081, 9000]", "action: deny"} {
		if !strings.Contains(got, want) {
			t.Errorf("fragment sans %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "action: allow") {
		t.Error("l'outil ne doit jamais proposer allow: il observe, il ne connait pas l'intention")
	}
}

func TestYAMLSuggestionEmptyWhenNothingFound(t *testing.T) {
	services, err := newRunner(t, fakeProber{}, []int{8081}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := YAMLSuggestion(services, "red"); got != "" {
		t.Errorf("fragment = %q, want vide", got)
	}
}

func TestParsePortSpec(t *testing.T) {
	got, err := ParsePortSpec("80, 22,8000-8002, 22")
	if err != nil {
		t.Fatalf("ParsePortSpec: %v", err)
	}
	want := []int{22, 80, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	for _, bad := range []string{"0", "70000", "8100-8000", "abc", "10-abc"} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Errorf("ParsePortSpec(%q) aurait du echouer", bad)
		}
	}

	if got, err := ParsePortSpec("  "); err != nil || got != nil {
		t.Errorf("une specification vide doit renvoyer nil sans erreur, got %v %v", got, err)
	}
}

func TestRunRejectsBadZones(t *testing.T) {
	r := newRunner(t, fakeProber{}, []int{80})
	r.Options.From = "ghost"
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("zone source inconnue devrait echouer")
	}

	r = newRunner(t, fakeProber{}, []int{80})
	r.Options.To = "red"
	if _, err := r.Run(context.Background()); err == nil {
		t.Error("zone cible identique a la source devrait echouer")
	}
}
