// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package locality

import (
	"net"
	"strings"
	"testing"
)

func withAddrs(t *testing.T, addrs ...string) func() {
	t.Helper()
	var ips []net.IP
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("adresse de test invalide: %q", a)
		}
		ips = append(ips, ip)
	}
	prev := LocalAddrs
	LocalAddrs = func() ([]net.IP, error) { return ips, nil }
	return func() { LocalAddrs = prev }
}

var labZones = []Zone{
	{Name: "lan", CIDR: "10.10.10.0/24"},
	{Name: "dmz", CIDR: "10.10.20.0/24"},
	{Name: "red", CIDR: "10.10.30.0/24"},
}

func TestProberInDeclaredZonePasses(t *testing.T) {
	defer withAddrs(t, "10.10.30.50")()
	result, err := Check("red", labZones)
	if err != nil {
		t.Fatalf("une sonde dans sa zone doit passer: %v", err)
	}
	if !result.MatchedSource {
		t.Error("la source aurait du etre reconnue")
	}
	if result.MultiHomed() {
		t.Error("une seule zone, pas multi-domicilie")
	}
}

// Le coeur du correctif: l'hyperviseur a une patte dans chaque zone. Ses
// mesures contournent le pare-feu et doivent etre refusees.
func TestMultiHomedHostIsRefused(t *testing.T) {
	defer withAddrs(t, "10.10.10.2", "10.10.20.2", "10.10.30.2")()
	result, err := Check("red", labZones)
	if err == nil {
		t.Fatal("une machine multi-domiciliee doit etre refusee")
	}
	if !result.MultiHomed() {
		t.Error("le resultat doit indiquer le multi-homing")
	}
	if len(result.ZonesPresent) != 3 {
		t.Errorf("zones presentes = %v, want 3", result.ZonesPresent)
	}
	if !strings.Contains(err.Error(), "plusieurs zones") {
		t.Errorf("le message doit expliquer le contournement: %v", err)
	}
}

func TestProberOutsideDeclaredZoneIsRefused(t *testing.T) {
	// Adresse dans la DMZ, mais on pretend tester depuis red.
	defer withAddrs(t, "10.10.20.10")()
	_, err := Check("red", labZones)
	if err == nil {
		t.Fatal("sonder red depuis la dmz doit etre refuse")
	}
	if !strings.Contains(err.Error(), "aucune adresse") {
		t.Errorf("message inattendu: %v", err)
	}
}

// Une machine tierce dont l'IP n'est dans aucune zone: refusee aussi, mais
// c'est le cas ou -no-locality-check est legitime.
func TestMachineOutsideAllZonesIsRefused(t *testing.T) {
	defer withAddrs(t, "192.168.1.100")()
	result, err := Check("red", labZones)
	if err == nil {
		t.Fatal("une machine hors de toute zone doit etre refusee par defaut")
	}
	if result.MultiHomed() {
		t.Error("hors de toute zone n'est pas multi-domicilie")
	}
	if len(result.ZonesPresent) != 0 {
		t.Errorf("aucune zone attendue, got %v", result.ZonesPresent)
	}
}

func TestExtraAddressesOutsideZonesAreIgnored(t *testing.T) {
	// Une IP de management hors matrice ne doit pas declencher le multi-homing.
	defer withAddrs(t, "10.10.30.50", "192.168.11.111")()
	result, err := Check("red", labZones)
	if err != nil {
		t.Fatalf("l'adresse hors matrice doit etre ignoree: %v", err)
	}
	if result.MultiHomed() {
		t.Error("une seule zone de la matrice touchee, pas multi-domicilie")
	}
	if len(result.LocalInSource) != 1 || result.LocalInSource[0] != "10.10.30.50" {
		t.Errorf("adresse source inattendue: %v", result.LocalInSource)
	}
}

func TestUnknownSourceZone(t *testing.T) {
	defer withAddrs(t, "10.10.30.50")()
	if _, err := Check("ghost", labZones); err == nil {
		t.Error("zone source inconnue doit echouer")
	}
}

func TestInvalidCIDRInMatrix(t *testing.T) {
	defer withAddrs(t, "10.10.30.50")()
	bad := []Zone{{Name: "red", CIDR: "pas un cidr"}}
	if _, err := Check("red", bad); err == nil {
		t.Error("un cidr invalide doit remonter une erreur")
	}
}

func TestIPv6Zones(t *testing.T) {
	defer withAddrs(t, "fd00:10:30::50")()
	zones := []Zone{
		{Name: "red", CIDR: "fd00:10:30::/64"},
		{Name: "dmz", CIDR: "fd00:10:20::/64"},
	}
	result, err := Check("red", zones)
	if err != nil {
		t.Fatalf("une sonde IPv6 dans sa zone doit passer: %v", err)
	}
	if !result.MatchedSource {
		t.Error("la source IPv6 aurait du etre reconnue")
	}
}
