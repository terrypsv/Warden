// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package finding defines the report format shared by every tool in the
// suite. Warden, and later the other collectors, emit exactly this JSON so a
// single audit layer can consume all of them without per-tool adapters.
// Treat the shape below as a contract: additive changes only, and bump
// SchemaVersion for anything else.
package finding

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// SchemaVersion identifies the report contract, not the tool version.
const SchemaVersion = "1.0"

// Severity is the impact of a failing check.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status is the verdict of a check.
type Status string

const (
	// StatusPass means observed reality matches the declaration.
	StatusPass Status = "pass"
	// StatusFail means it does not.
	StatusFail Status = "fail"
	// StatusReview means the observation is genuinely ambiguous and a human
	// has to look. Reporting ambiguity honestly beats guessing.
	StatusReview Status = "review"
	// StatusSkipped means the check could not be attempted by design.
	StatusSkipped Status = "skipped"
	// StatusError means the check broke.
	StatusError Status = "error"
)

// Reference ties a finding to an external control.
type Reference struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

// Evidence is raw material backing the verdict.
type Evidence struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// Target is what was examined.
type Target struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// Finding is a single observation.
type Finding struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Category    string      `json:"category"`
	Severity    Severity    `json:"severity"`
	Status      Status      `json:"status"`
	Target      Target      `json:"target"`
	Expected    string      `json:"expected,omitempty"`
	Observed    string      `json:"observed,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	Declared    bool        `json:"declared"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	References  []Reference `json:"references,omitempty"`
	DetectedAt  time.Time   `json:"detected_at"`
}

// Tool identifies the producer of a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Run describes one execution.
type Run struct {
	ID         string            `json:"id"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Host       string            `json:"host"`
	Context    map[string]string `json:"context,omitempty"`
}

// Report is the top-level document.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	Run           Run       `json:"run"`
	Findings      []Finding `json:"findings"`
}

// NewReport starts a report with a random run identifier.
func NewReport(toolName, toolVersion string) *Report {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: toolName, Version: toolVersion},
		Run: Run{
			ID:        randomID(),
			StartedAt: time.Now().UTC(),
			Host:      host,
			Context:   map[string]string{},
		},
		Findings: []Finding{},
	}
}

// Add appends a finding, stamping it if the caller did not.
func (r *Report) Add(f Finding) {
	if f.DetectedAt.IsZero() {
		f.DetectedAt = time.Now().UTC()
	}
	r.Findings = append(r.Findings, f)
}

// Finish stamps the end of the run and orders findings deterministically:
// worst first, then by identifier, so two runs over the same environment
// produce diffable output.
func (r *Report) Finish() {
	r.Run.FinishedAt = time.Now().UTC()
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if rank(a.Status) != rank(b.Status) {
			return rank(a.Status) < rank(b.Status)
		}
		if weight(a.Severity) != weight(b.Severity) {
			return weight(a.Severity) < weight(b.Severity)
		}
		return a.ID < b.ID
	})
}

// Counts returns the number of findings per status.
func (r *Report) Counts() map[Status]int {
	out := make(map[Status]int)
	for _, f := range r.Findings {
		out[f.Status]++
	}
	return out
}

// WriteJSON serialises the report.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteFile serialises the report to disk.
func (r *Report) WriteFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()
	if err := r.WriteJSON(f); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func rank(s Status) int {
	switch s {
	case StatusFail:
		return 0
	case StatusReview:
		return 1
	case StatusError:
		return 2
	case StatusSkipped:
		return 3
	default:
		return 4
	}
}

func weight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

func randomID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("t%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}
