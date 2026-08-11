// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package matrix

import "testing"

const validYAML = `
version: 1
default: deny
sweep_ports: [22, 445]
zones:
  - name: lan
    cidr: 10.10.10.0/24
    probe: 10.10.10.50
  - name: dmz
    cidr: 10.10.20.0/24
    probe: 10.10.20.50
flows:
  - from: lan
    to: dmz
    proto: tcp
    ports: [80, 443]
    action: allow
    comment: acces applicatif
`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Zones) != 2 {
		t.Fatalf("zones = %d, want 2", len(m.Zones))
	}
	if m.Default != ActionDeny {
		t.Fatalf("default = %q, want deny", m.Default)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"version inconnue": "version: 2\ndefault: deny\nzones: []\n",
		"defaut invalide":  "version: 1\ndefault: maybe\nzones: []\n",
		"une seule zone":   "version: 1\ndefault: deny\nzones:\n  - name: lan\n    cidr: 10.0.0.0/24\n    probe: 10.0.0.1\n",
		"champ inconnu":    validYAML + "\nunexpected: true\n",
		"cidr invalide":    "version: 1\ndefault: deny\nzones:\n  - name: a\n    cidr: nope\n    probe: 10.0.0.1\n  - name: b\n    cidr: 10.1.0.0/24\n    probe: 10.1.0.1\n",
		"sonde hors cidr":  "version: 1\ndefault: deny\nzones:\n  - name: a\n    cidr: 10.0.0.0/24\n    probe: 192.168.0.1\n  - name: b\n    cidr: 10.1.0.0/24\n    probe: 10.1.0.1\n",
		"zone inconnue":    validYAML + "\n  - from: lan\n    to: ghost\n    proto: tcp\n    ports: [1]\n    action: allow\n",
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: Parse a reussi alors qu'une erreur etait attendue", name)
		}
	}
}

func TestCasesExpandsDeclaredAndDefault(t *testing.T) {
	m, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases, err := m.Cases("lan")
	if err != nil {
		t.Fatalf("Cases: %v", err)
	}

	// 2 flux declares (80, 443) + 2 ports de balayage (22, 445) vers dmz.
	if len(cases) != 4 {
		t.Fatalf("cases = %d, want 4", len(cases))
	}

	byKey := make(map[string]Case, len(cases))
	for _, c := range cases {
		byKey[c.Key] = c
	}

	declared, ok := byKey["lan->dmz:tcp/80"]
	if !ok {
		t.Fatal("flux declare lan->dmz:tcp/80 absent")
	}
	if !declared.Declared || declared.Expected != ActionAllow {
		t.Errorf("flux declare mal etiquete: %+v", declared)
	}

	swept, ok := byKey["lan->dmz:tcp/445"]
	if !ok {
		t.Fatal("flux de balayage lan->dmz:tcp/445 absent")
	}
	if swept.Declared || swept.Expected != ActionDeny {
		t.Errorf("flux de balayage mal etiquete: %+v", swept)
	}
}

func TestCasesUnknownZone(t *testing.T) {
	m, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := m.Cases("red"); err == nil {
		t.Fatal("Cases a accepte une zone inconnue")
	}
}
