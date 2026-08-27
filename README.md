# Warden

Validation active du cloisonnement reseau. Tu declares la matrice de flux que
ton architecture est censee appliquer, Warden teste ce qui passe reellement et
signale les trois ecarts qui comptent :

- un flux declare autorise qui ne passe pas (regle manquante ou cassee)
- un flux qui passe alors qu'il n'aurait pas du (fuite de cloisonnement)
- un service joignable qui n'est declare nulle part (trou dans la declaration)

Les deux derniers cas sont ceux que personne ne verifie. Un tableur de flux et
un jeu de regles de pare-feu divergent en quelques semaines, et rien ne le
detecte.

**Logiciel proprietaire.** Voir `LICENSE`. L'acces en lecture a ce depot ne
confere aucun droit d'usage.

## Etat

Mode source unique : le binaire tourne dans une zone et sonde les autres.
Aucun agent a deployer. Le mode agents distribues est prevu en v2, derriere
l'interface `probe.Prober` deja en place.

Couverture actuelle : TCP. UDP et ICMP sont acceptes dans la matrice mais
rapportes en `skipped` : depuis l'emetteur seul, le silence signifie a la fois
"bloque" et "aucun service", donc les juger serait mentir. Ils arrivent avec
l'agent recepteur.

## Installation

Recuperer le binaire de la derniere release, verifier la somme de controle,
puis l'installer :

```bash
sha256sum -c SHA256SUMS --ignore-missing
sudo install -m 755 warden_1.0.0_linux_amd64 /usr/local/bin/warden
warden version
```

Depuis les sources :

```bash
go mod tidy
go build -o warden ./cmd/warden
```

Ou `make check` pour tout enchainer (fmt, vet, test, build).

## Utilisation

```bash
cp configs/matrix.example.yaml configs/matrix.yaml
# adapter zones, sondes et flux

warden validate -matrix configs/matrix.yaml
warden plan     -matrix configs/matrix.yaml -from red
warden verify   -matrix configs/matrix.yaml -from red -out rapport.json
```

### Mesure en mode strict

Dans chaque zone cible, dans une session qui reste ouverte :

```bash
warden listen -token <jeton> -duration 10m -ports 88,135,139,389,443,445,464,3268,3269,3389,5985
```

Depuis la zone source, verifier avant de mesurer :

```bash
warden preflight -matrix configs/matrix.yaml -from red -token <jeton>
warden verify    -matrix configs/matrix.yaml -from red -listener -token <jeton> -out rapport.json
```

### Decouverte

```bash
warden discover -matrix configs/matrix.yaml -from red -to dmz -out decouverte.json
```

`verify` controle ce qui est declare. `discover` trouve ce qui ne l'est pas :
il balaye une liste de services courants, ecarte les ecouteurs Warden grace a
la banniere, et confronte le resultat aux flux explicitement declares. Un port
atteint par le seul balayage par defaut ne compte pas comme declare, c'est
precisement ce qu'il faut faire remonter.

Le fragment YAML propose est en `action: deny` avec un marqueur a valider :
l'outil observe la joignabilite, il ne connait pas l'intention, et proposer
`allow` reviendrait a blanchir une exposition accidentelle en flux documente.

### Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | conforme |
| 1 | erreur d'usage |
| 2 | erreur d'execution |
| 3 | non-conformites detectees |

Exploitable directement en cron ou en CI avec `-brief`.

## Le piege du RST

C'est le point qui fait la difference entre cet outil et un script `nmap`.

Trois reponses possibles a un SYN, et une seule signifie "bloque" :

| Observation | Signification | Le paquet a-t-il traverse ? |
|-------------|---------------|-----------------------------|
| handshake complet | port ouvert et joignable | oui |
| RST recu | hote atteint, port ferme **ou** pare-feu en reject | oui |
| silence ou unreachable | chemin coupe | non |

Un RST veut dire que le paquet est arrive quelque part. Le compter comme
"bloque" est l'erreur classique : elle masque de vraies fuites.

## Les deux modes

**Strict est le mode de mesure. Blind est un mode de reconnaissance.**

En mode strict, un ecouteur `warden listen` repond dans la zone cible. Un RST
ne peut alors venir que du filtrage, et le verdict est net. C'est le seul mode
dont les resultats sont exploitables comme preuve.

En mode blind, sans ecouteur, un RST reste ambigu et produit un constat
`review`. Utile pour une premiere reconnaissance, insuffisant pour conclure.
Sur un pare-feu permissif avec des ports sans service, le bruit devient
important : lors de la validation sur lab reel, 6 constats `review` sur 19
controles, aucun n'indiquant un probleme.

### La confiance ne se declare pas, elle se prouve

Le drapeau `-listener` est une demande, pas une affirmation acceptee. Chaque
ecouteur annonce une banniere `WARDEN/1 <jeton> <version>` a la connexion, et
le prober la verifie. Le mode strict ne s'applique qu'aux zones ou une
banniere valide a reellement ete recue.

Un operateur qui oublie de lancer l'ecouteur dans une zone n'obtient pas des
`pass` immerites : il obtient des `review`, plus un constat explicite signalant
la zone non confirmee. Cette protection existe parce que le cas s'est produit
en conditions reelles, et que les verdicts affiches etaient alors de la
confiance, pas de la mesure.

Limite assumee : si tous les ports d'une zone sont correctement bloques, aucune
banniere ne peut remonter et la confirmation est impossible par construction.
La zone reste en blind, ce qui est le comportement honnete.

Corollaire operationnel : sur OPNsense, prefere `block` (drop silencieux) a
`reject` sur les regles inter-zones. C'est meilleur pour la securite et ca
rend les mesures non ambigues.

## Format de rapport

Le JSON produit suit le schema decrit dans `docs/finding-schema.md`, que
dix outils de la suite emettent: Warden, Clavis, Janus, Aegis, Vigil, Atlas,
Vestige, Aurora, Sylva et Phoenix. Un seul consommateur les agrege sans adaptateur.

## Validation terrain

Premiere campagne sur infrastructure reelle, un lab a quatre zones construit
avec soin par son administrateur. Cinq defauts trouves, zero faux positif :

- regle `pass` residuelle dans le pare-feu, exposant SMB, NetBIOS, RPC et SSH
  d'un controleur de domaine a la zone attaquant
- transit inter-zones autorise par l'hyperviseur, contournant integralement le
  pare-feu
- conflit d'adresse IP entre deux conteneurs
- regles de filtrage non persistantes au redemarrage
- cible applicative joignable et absente de la matrice, trouvee par `discover`

Aucun de ces defauts n'etait visible sur un schema d'architecture.

## Structure

```
cmd/warden          CLI
internal/matrix     chargement et validation de la matrice, expansion en controles
internal/probe      sondes reseau, bannieres, classification des resultats
internal/verify     orchestration, verdicts, preflight
internal/discover   services joignables absents de la matrice
internal/listen     ecouteurs a placer dans les zones cibles
internal/finding    schema de constat commun a la suite
configs             matrice d'exemple
docs                schema de constat, feuille de route
```
