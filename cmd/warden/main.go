// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Command warden validates network segmentation against a declared flow
// matrix.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/terrypsv/Warden/internal/discover"
	"github.com/terrypsv/Warden/internal/finding"
	"github.com/terrypsv/Warden/internal/listen"
	"github.com/terrypsv/Warden/internal/matrix"
	"github.com/terrypsv/Warden/internal/probe"
	"github.com/terrypsv/Warden/internal/verify"
)

// version is overridden at build time via -ldflags.
var version = "0.1.0-dev"

// Exit codes are part of the interface: CI and cron depend on them.
const (
	exitOK           = 0
	exitUsage        = 1
	exitRuntime      = 2
	exitNonCompliant = 3
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	var err error
	code := exitOK

	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("warden %s\n", version)
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "preflight":
		code, err = cmdPreflight(os.Args[2:])
	case "discover":
		code, err = cmdDiscover(os.Args[2:])
	case "verify":
		code, err = cmdVerify(os.Args[2:])
	case "listen":
		err = cmdListen(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "sous-commande inconnue: %s\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(exitRuntime)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `warden - validation active du cloisonnement reseau

Usage:
  warden validate  -matrix <fichier>
  warden plan      -matrix <fichier> -from <zone>
  warden preflight -matrix <fichier> -from <zone> [-token <jeton>]
  warden verify    -matrix <fichier> -from <zone> [-listener] [-token <jeton>] [-out rapport.json] [-brief]
  warden discover  -matrix <fichier> -from <zone> [-to <zone>] [-ports 22,8000-8100] [-out decouverte.json]
  warden listen    -ports 22,80,443 [-addr 0.0.0.0] [-token <jeton>] [-duration 10m]
  warden version

Mode strict:
  1. Dans chaque zone cible: warden listen -token <jeton> -duration 10m
  2. Depuis la zone source:  warden preflight ... -token <jeton>
  3. Si preflight est vert:  warden verify ... -listener -token <jeton>

  Le mode strict ne s'applique qu'aux zones ou un ecouteur a reellement
  repondu. Une zone non confirmee reste en blind et produit son constat.

Decouverte:
  verify controle ce qui est declare, discover trouve ce qui ne l'est pas.
  Tout service signale par discover est un trou dans la declaration, pas
  forcement dans le pare-feu.

Codes de sortie:
  0 conforme    1 usage    2 erreur d'execution    3 non-conformites detectees
`)
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("matrix", "configs/matrix.yaml", "chemin de la matrice de flux")
	if err := fs.Parse(args); err != nil {
		return err
	}

	m, err := matrix.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("matrice valide: %d zone(s), %d flux declare(s), defaut %s\n",
		len(m.Zones), len(m.Flows), m.Default)
	return nil
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	path := fs.String("matrix", "configs/matrix.yaml", "chemin de la matrice de flux")
	from := fs.String("from", "", "zone depuis laquelle les sondes partent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("-from est obligatoire")
	}

	m, err := matrix.Load(*path)
	if err != nil {
		return err
	}
	cases, err := m.Cases(*from)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FLUX\tCIBLE\tATTENDU\tSOURCE")
	declared := 0
	for _, c := range cases {
		origin := "defaut"
		if c.Declared {
			origin = "declare"
			declared++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Key, c.To.Probe, c.Expected, origin)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Printf("\n%d controle(s): %d declare(s), %d issu(s) de l'action par defaut\n",
		len(cases), declared, len(cases)-declared)
	return nil
}

func cmdPreflight(args []string) (int, error) {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	path := fs.String("matrix", "configs/matrix.yaml", "chemin de la matrice de flux")
	from := fs.String("from", "", "zone depuis laquelle les sondes partent")
	token := fs.String("token", "", "jeton attendu des ecouteurs")
	timeout := fs.Duration("timeout", 2*time.Second, "delai par sonde")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *from == "" {
		return exitUsage, fmt.Errorf("-from est obligatoire")
	}

	m, err := matrix.Load(*path)
	if err != nil {
		return exitRuntime, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	runner := &verify.Runner{
		Matrix:  m,
		Prober:  probe.TCPProber{Timeout: *timeout, ExpectToken: *token},
		Version: version,
		Options: verify.Options{From: *from},
	}

	statuses, err := runner.Preflight(ctx)
	if err != nil {
		return exitRuntime, err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ZONE\tECOUTEUR\tPORT\tVERSION\tPORTS TESTES")
	missing := 0
	for _, st := range statuses {
		state := "absent"
		port := "-"
		listenerVersion := "-"
		if st.Confirmed {
			state = "confirme"
			port = strconv.Itoa(st.Port)
			listenerVersion = st.Version
			if listenerVersion == "" {
				listenerVersion = "inconnue"
			}
		} else {
			missing++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", st.Zone, state, port, listenerVersion, st.Tried)
	}
	if err := tw.Flush(); err != nil {
		return exitRuntime, err
	}
	fmt.Println()

	for _, st := range statuses {
		if st.Confirmed && st.Version != "" && st.Version != version {
			fmt.Printf("attention: zone %s en version %s, sonde en version %s\n", st.Zone, st.Version, version)
		}
	}

	if missing > 0 {
		fmt.Printf("%d zone(s) sans ecouteur confirme. Les verdicts y seront blind.\n", missing)
		fmt.Println("note: une zone entierement bloquee ne peut pas etre confirmee, c'est attendu.")
		return exitNonCompliant, nil
	}
	fmt.Println("toutes les zones cibles sont pretes pour une mesure en mode strict")
	return exitOK, nil
}

func cmdDiscover(args []string) (int, error) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	path := fs.String("matrix", "configs/matrix.yaml", "chemin de la matrice de flux")
	from := fs.String("from", "", "zone depuis laquelle les sondes partent")
	to := fs.String("to", "", "limiter la decouverte a cette zone cible")
	portSpec := fs.String("ports", "", "ports et plages, ex 22,8000-8100. Vide = liste etendue par defaut")
	out := fs.String("out", "", "ecrire le rapport JSON dans ce fichier")
	timeout := fs.Duration("timeout", time.Second, "delai par sonde")
	parallel := fs.Int("parallel", 64, "nombre de sondes simultanees")
	token := fs.String("token", "", "jeton des ecouteurs warden, pour ne pas les confondre avec des services")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *from == "" {
		return exitUsage, fmt.Errorf("-from est obligatoire")
	}

	ports, err := discover.ParsePortSpec(*portSpec)
	if err != nil {
		return exitUsage, err
	}

	m, err := matrix.Load(*path)
	if err != nil {
		return exitRuntime, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	runner := &discover.Runner{
		Matrix:  m,
		Prober:  probe.TCPProber{Timeout: *timeout, ExpectToken: *token},
		Version: version,
		Options: discover.Options{
			From:     *from,
			To:       *to,
			Ports:    ports,
			Parallel: *parallel,
		},
	}

	services, err := runner.Run(ctx)
	if err != nil {
		return exitRuntime, err
	}

	swept := len(ports)
	if swept == 0 {
		swept = len(discover.DefaultPorts)
	}
	fmt.Printf("warden %s - decouverte depuis %s, %d port(s) balaye(s) par zone\n\n", version, *from, swept)

	if len(services) == 0 {
		fmt.Println("aucun service joignable")
		return exitOK, nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ZONE\tPORT\tETAT\tDETAIL")
	for _, s := range services {
		state := "non declare"
		detail := "-"
		switch {
		case s.ListenerConfirmed:
			state = "ecouteur warden"
			detail = "ignore"
		case s.Declared:
			state = "declare"
			detail = string(s.Action)
		case s.Banner != "":
			detail = s.Banner
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", s.Zone, s.Port, state, detail)
	}
	if err := tw.Flush(); err != nil {
		return exitRuntime, err
	}

	undeclared := discover.Undeclared(services)
	fmt.Printf("\n%d service(s) joignable(s), dont %d absent(s) de la matrice\n",
		len(services), len(undeclared))

	if *out != "" {
		if err := discover.Report(services, *from, version).WriteFile(*out); err != nil {
			return exitRuntime, err
		}
		fmt.Printf("rapport JSON: %s\n", *out)
	}

	if fragment := discover.YAMLSuggestion(services, *from); fragment != "" {
		fmt.Printf("\nA integrer dans la matrice apres relecture:\n\n%s", fragment)
		return exitNonCompliant, nil
	}
	return exitOK, nil
}

func cmdVerify(args []string) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("matrix", "configs/matrix.yaml", "chemin de la matrice de flux")
	from := fs.String("from", "", "zone depuis laquelle les sondes partent")
	out := fs.String("out", "", "ecrire le rapport JSON dans ce fichier")
	timeout := fs.Duration("timeout", 2*time.Second, "delai par sonde")
	parallel := fs.Int("parallel", 16, "nombre de sondes simultanees")
	listener := fs.Bool("listener", false, "demander des verdicts stricts, valides zone par zone")
	token := fs.String("token", "", "jeton attendu des ecouteurs, vide accepte toute banniere warden")
	brief := fs.Bool("brief", false, "sortie d'une ligne, pour cron et supervision")
	if err := fs.Parse(args); err != nil {
		return exitUsage, err
	}
	if *from == "" {
		return exitUsage, fmt.Errorf("-from est obligatoire")
	}

	m, err := matrix.Load(*path)
	if err != nil {
		return exitRuntime, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	runner := &verify.Runner{
		Matrix: m,
		Prober: probe.TCPProber{
			Timeout:     *timeout,
			ExpectToken: *token,
		},
		Version: version,
		Options: verify.Options{
			From:              *from,
			Parallel:          *parallel,
			ListenerRequested: *listener,
		},
	}

	report, err := runner.Run(ctx)
	if err != nil {
		return exitRuntime, err
	}

	if *out != "" {
		if err := report.WriteFile(*out); err != nil {
			return exitRuntime, err
		}
	}

	counts := report.Counts()
	if *brief {
		fmt.Printf("warden %s zone=%s strict=%s fail=%d review=%d pass=%d skipped=%d error=%d\n",
			version, *from, strings.Join(verify.StrictZones(report), "|"),
			counts[finding.StatusFail], counts[finding.StatusReview],
			counts[finding.StatusPass], counts[finding.StatusSkipped],
			counts[finding.StatusError])
	} else {
		printSummary(report, counts, *listener, *out)
	}

	if counts[finding.StatusFail] > 0 {
		return exitNonCompliant, nil
	}
	return exitOK, nil
}

func printSummary(report *finding.Report, counts map[finding.Status]int, listenerRequested bool, out string) {
	strictZones := verify.StrictZones(report)

	mode := "blind"
	if listenerRequested {
		if len(strictZones) == 0 {
			mode = "strict demande, aucune zone confirmee"
		} else {
			mode = "strict confirme sur " + strings.Join(strictZones, ", ")
		}
	}

	fmt.Printf("warden %s - run %s - mode %s\n", version, report.Run.ID, mode)
	fmt.Printf("%d controle(s): %d fail, %d review, %d pass, %d skipped, %d error\n\n",
		len(report.Findings),
		counts[finding.StatusFail], counts[finding.StatusReview],
		counts[finding.StatusPass], counts[finding.StatusSkipped],
		counts[finding.StatusError])

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	shown := 0
	for _, f := range report.Findings {
		if f.Status != finding.StatusFail && f.Status != finding.StatusReview {
			continue
		}
		if shown == 0 {
			fmt.Fprintln(tw, "STATUT\tGRAVITE\tCIBLE\tATTENDU\tOBSERVE")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.Status, f.Severity, f.Target.Identifier, f.Expected, shortOutcome(f.Observed))
		shown++
	}
	if shown > 0 {
		_ = tw.Flush()
		fmt.Println()
	} else {
		fmt.Println("aucun ecart entre la matrice et le reseau observe")
	}

	if listenerRequested && len(strictZones) == 0 {
		fmt.Println("note: -listener demande mais aucune banniere warden recue. Les verdicts restent blind.")
	}
	if !listenerRequested && counts[finding.StatusReview] > 0 {
		fmt.Println("note: mode blind, les RST sont ambigus. Lancer warden listen dans les zones cibles puis relancer avec -listener.")
	}
	if out != "" {
		fmt.Printf("rapport JSON: %s\n", out)
	}
}

func shortOutcome(s string) string {
	if i := strings.Index(s, " ("); i > 0 && !strings.HasPrefix(s, "open (") {
		return s[:i]
	}
	return s
}

func cmdListen(args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0", "adresse d'ecoute")
	raw := fs.String("ports", "", "ports TCP separes par des virgules, vide = ports de balayage par defaut")
	token := fs.String("token", "", "jeton a annoncer, genere aleatoirement si vide")
	duration := fs.Duration("duration", 0, "arret automatique apres ce delai, 0 pour rester jusqu'a Ctrl+C")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ports, err := parsePorts(*raw)
	if err != nil {
		return err
	}

	value := *token
	if value == "" {
		value, err = listen.NewToken()
		if err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	limit := "aucune, Ctrl+C pour arreter"
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
		limit = "arret automatique dans " + duration.String()
	}

	fmt.Printf("warden %s - ecoute sur %d port(s), %s\n", version, len(ports), limit)
	fmt.Printf("jeton: %s\n", value)
	fmt.Printf("cote sonde: warden preflight ... -token %s\n\n", value)

	return listen.Serve(ctx, *addr, ports, value, version, func(format string, a ...any) {
		fmt.Printf(time.Now().Format("15:04:05")+" "+format+"\n", a...)
	})
}

func parsePorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return matrix.DefaultSweepPorts, nil
	}
	seen := make(map[int]bool)
	var ports []int
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		p, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("port invalide %q", field)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port hors plage: %d", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("aucun port valide fourni")
	}
	sort.Ints(ports)
	return ports, nil
}
