// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package finding

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReportRoundTrip(t *testing.T) {
	r := NewReport("warden", "0.1.0")
	r.Add(Finding{ID: "WRD-SEG-0002", Status: StatusPass, Severity: SeverityInfo})
	r.Add(Finding{ID: "WRD-SEG-0001", Status: StatusFail, Severity: SeverityHigh})
	r.Finish()

	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", back.SchemaVersion, SchemaVersion)
	}
	if len(back.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(back.Findings))
	}
	if back.Findings[0].Status != StatusFail {
		t.Errorf("le premier constat devrait etre un fail, got %q", back.Findings[0].Status)
	}
	if back.Run.FinishedAt.Before(back.Run.StartedAt) {
		t.Error("finished_at anterieur a started_at")
	}
}

func TestCounts(t *testing.T) {
	r := NewReport("warden", "test")
	r.Add(Finding{Status: StatusFail})
	r.Add(Finding{Status: StatusFail})
	r.Add(Finding{Status: StatusPass})

	got := r.Counts()
	if got[StatusFail] != 2 || got[StatusPass] != 1 {
		t.Fatalf("counts = %v", got)
	}
}

func TestDetectedAtIsStamped(t *testing.T) {
	r := NewReport("warden", "test")
	r.Add(Finding{ID: "x"})
	if r.Findings[0].DetectedAt.IsZero() {
		t.Fatal("detected_at n'a pas ete horodate")
	}
}
