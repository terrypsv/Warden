<img width="511" height="114" alt="ascii-art-text" src="https://github.com/user-attachments/assets/4dcee9b3-18b7-4b5a-84a5-d5b4cf2368dd" />


# Warden

Validation active du cloisonnement réseau. Vous déclarez la matrice de flux que
votre architecture est censée appliquer, Warden teste ce qui passe réellement et
signale les trois écarts qui comptent :

- un flux déclaré autorisé qui ne passe pas (règle manquante ou cassée)
- un flux qui passe alors qu'il n'aurait pas dû (fuite de cloisonnement)
- un service joignable qui n'est déclaré nulle part (trou dans la déclaration)

Les deux derniers cas sont ceux que personne ne vérifie. Un tableur de flux et
un jeu de règles de pare-feu divergent en quelques semaines, et rien ne le
détecte.

**Logiciel propriétaire.** Voir `LICENSE`. L'accès en lecture à ce dépôt ne
confère aucun droit d'usage.

## État

Mode source unique : le binaire tourne dans une zone et sonde les autres.
Aucun agent à déployer. Le mode agents distribués est prévu en v2, derrière
l'interface `probe.Prober` déjà en place.

Couverture actuelle : TCP. UDP et ICMP sont acceptés dans la matrice mais
rapportés en `skipped` : depuis l'émetteur seul, le silence signifie à la fois
"bloqué" et "aucun service", donc les juger serait mentir. Ils arrivent avec
l'agent récepteur.

## Installation

Récupérer le binaire de la dernière release, vérifier la somme de contrôle,
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

Ou `make check` pour tout enchaîner (fmt, vet, test, build).

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

Depuis la zone source, vérifier avant de mesurer :

```bash
warden preflight -matrix configs/matrix.yaml -from red -token <jeton>
warden verify    -matrix configs/matrix.yaml -from red -listener -token <jeton> -out rapport.json
```

### Découverte

```bash
warden discover -matrix configs/matrix.yaml -from red -to dmz -out decouverte.json
```

`verify` contrôle ce qui est déclaré. `discover` trouve ce qui ne l'est pas :
il balaye une liste de services courants, écarte les écouteurs Warden grâce à
la bannière, et confronte le résultat aux flux explicitement déclarés. Un port
atteint par le seul balayage par défaut ne compte pas comme déclaré, c'est
précisément ce qu'il faut faire remonter.

Le fragment YAML proposé est en `action: deny` avec un marqueur à valider :
l'outil observe la joignabilité, il ne connaît pas l'intention, et proposer
`allow` reviendrait à blanchir une exposition accidentelle en flux documenté.

### Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | conforme |
| 1 | erreur d'usage |
| 2 | erreur d'exécution |
| 3 | non-conformités détectées |

Exploitable directement en cron ou en CI avec `-brief`.

## Le piège du RST

C'est le point qui fait la différence entre cet outil et un script `nmap`.

Trois réponses possibles à un SYN, et une seule signifie "bloqué" :

| Observation | Signification | Le paquet a-t-il traversé ? |
|-------------|---------------|-----------------------------|
| handshake complet | port ouvert et joignable | oui |
| RST reçu | hôte atteint, port fermé **ou** pare-feu en reject | oui |
| silence ou unreachable | chemin coupé | non |

Un RST veut dire que le paquet est arrivé quelque part. Le compter comme
"bloqué" est l'erreur classique : elle masque de vraies fuites.

## Les deux modes

**Strict est le mode de mesure. Blind est un mode de reconnaissance.**

En mode strict, un écouteur `warden listen` répond dans la zone cible. Un RST
ne peut alors venir que du filtrage, et le verdict est net. C'est le seul mode
dont les résultats sont exploitables comme preuve.

En mode blind, sans écouteur, un RST reste ambigu et produit un constat
`review`. Utile pour une première reconnaissance, insuffisant pour conclure.
Sur un pare-feu permissif avec des ports sans service, le bruit devient
important : lors de la validation sur lab réel, 6 constats `review` sur 19
contrôles, aucun n'indiquant un problème.

### La confiance ne se déclare pas, elle se prouve

Le drapeau `-listener` est une demande, pas une affirmation acceptée. Chaque
écouteur annonce une bannière `WARDEN/1 <jeton> <version>` à la connexion, et
le prober la vérifie. Le mode strict ne s'applique qu'aux zones où une
bannière valide a réellement été reçue.

Un opérateur qui oublie de lancer l'écouteur dans une zone n'obtient pas des
`pass` immérités : il obtient des `review`, plus un constat explicite signalant
la zone non confirmée. Cette protection existe parce que le cas s'est produit
en conditions réelles, et que les verdicts affichés étaient alors de la
confiance, pas de la mesure.

Limite assumée : si tous les ports d'une zone sont correctement bloqués, aucune
bannière ne peut remonter et la confirmation est impossible par construction.
La zone reste en blind, ce qui est le comportement honnête.

Corollaire opérationnel : sur OPNsense, préférez `block` (drop silencieux) à
`reject` sur les règles inter-zones. C'est meilleur pour la sécurité et ça
rend les mesures non ambiguës.

## Format de rapport

Le JSON produit suit le schéma décrit dans `docs/finding-schema.md`, que
dix outils de la suite émettent: Warden, Clavis, Janus, Aegis, Vigil, Atlas,
Vestige, Aurora, Sylva et Phoenix. Un seul consommateur les agrège sans adaptateur.

## Validation terrain

Première campagne sur infrastructure réelle, un lab à quatre zones construit
avec soin par son administrateur. Cinq défauts trouvés, zéro faux positif :

- règle `pass` résiduelle dans le pare-feu, exposant SMB, NetBIOS, RPC et SSH
  d'un contrôleur de domaine à la zone attaquant
- transit inter-zones autorisé par l'hyperviseur, contournant intégralement le
  pare-feu
- conflit d'adresse IP entre deux conteneurs
- règles de filtrage non persistantes au redémarrage
- cible applicative joignable et absente de la matrice, trouvée par `discover`

Aucun de ces défauts n'était visible sur un schéma d'architecture.

## Structure

```
cmd/warden          CLI
internal/matrix     chargement et validation de la matrice, expansion en contrôles
internal/probe      sondes réseau, bannières, classification des résultats
internal/verify     orchestration, verdicts, preflight
internal/discover   services joignables absents de la matrice
internal/listen     écouteurs à placer dans les zones cibles
internal/finding    schéma de constat commun à la suite
configs             matrice d'exemple
docs                schéma de constat, feuille de route
```
