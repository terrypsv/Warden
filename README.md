# Warden

Validation active du cloisonnement reseau. Tu declares la matrice de flux que
ton architecture est censee appliquer, Warden teste ce qui passe reellement et
signale les deux ecarts qui comptent :

- un flux declare autorise qui ne passe pas (regle manquante ou cassee)
- un flux qui passe alors qu'il n'aurait pas du (fuite de cloisonnement)

Le second cas est celui que personne ne verifie. Un tableur de flux et un jeu
de regles de pare-feu divergent en quelques semaines, et rien ne le detecte.

**Logiciel proprietaire.** Voir `LICENSE`. L'acces en lecture a ce depot ne
confere aucun droit d'usage.

## Etat

v0.1.0, mode source unique : le binaire tourne dans une zone et sonde les
autres. Aucun agent a deployer. Le mode agents distribues est prevu en v0.2,
derriere l'interface `probe.Prober` deja en place.

Couverture actuelle : TCP. UDP et ICMP sont acceptes dans la matrice mais
rapportes en `skipped` : depuis l'emetteur seul, le silence signifie a la fois
"bloque" et "aucun service", donc les juger serait mentir. Ils arrivent avec
l'agent recepteur.

## Installation

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

Dans chaque zone cible, avant un `verify` precis :

```bash
warden listen -ports 22,80,135,139,443,445,3389,5985,8080
```

Puis depuis la zone source :

```bash
warden verify -matrix configs/matrix.yaml -from red -listener -out rapport.json
```

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

Warden gere l'ambiguite au lieu de deviner :

- **mode blind** (defaut) : un RST devient un constat `review`, a trancher
  par un humain.
- **mode strict** (`-listener`) : tu garantis qu'un ecouteur repond dans la
  zone cible sur chaque port teste, donc un RST ne peut venir que du
  filtrage. Le verdict devient net.

Corollaire operationnel : sur OPNsense, prefere `block` (drop silencieux) a
`reject` sur les regles inter-zones. C'est meilleur pour la securite et ca
rend les mesures non ambigues.

## Format de rapport

Le JSON produit suit le schema decrit dans `docs/finding-schema.md`, partage
avec les autres outils de la suite. Un seul consommateur pourra agreger tous
les collecteurs sans adaptateur specifique.

## Structure

```
cmd/warden          CLI
internal/matrix     chargement et validation de la matrice, expansion en controles
internal/probe      sondes reseau et classification des resultats
internal/verify     orchestration et logique de verdict
internal/listen     ecouteurs a placer dans les zones cibles
internal/finding    schema de constat commun a la suite
configs             matrice d'exemple
docs                schema de constat, feuille de route
```
