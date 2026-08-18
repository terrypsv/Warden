<!-- Remplacer la section "## Le piege du RST" du README par ce contenu. -->

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
ecouteur annonce une banniere `WARDEN/1 <jeton>` a la connexion, et le prober
la verifie. Le mode strict ne s'applique qu'aux zones ou une banniere valide a
reellement ete recue.

Un operateur qui oublie de lancer l'ecouteur dans une zone n'obtient pas des
`pass` immerites : il obtient des `review`, plus un constat explicite signalant
la zone non confirmee. Cette protection existe parce que le cas s'est produit
en conditions reelles, et que les verdicts affiches etaient alors de la
confiance, pas de la mesure.

Limite assumee : si tous les ports d'une zone sont correctement bloques, aucune
banniere ne peut remonter et la confirmation est impossible par construction.
La zone reste en blind, ce qui est le comportement honnete.

### Utilisation

Dans chaque zone cible, dans une session qui reste ouverte :

```bash
warden listen -ports 22,80,135,139,443,445,3389,5985,8080
```

La commande affiche le jeton a utiliser. Depuis la zone source :

```bash
warden verify -matrix configs/matrix.yaml -from red -listener -token <jeton> -out rapport.json
```

Sans `-token`, toute banniere `WARDEN/1` bien formee est acceptee. Avec, seul
un ecouteur portant ce jeton confirme la zone.

Corollaire operationnel : sur OPNsense, prefere `block` (drop silencieux) a
`reject` sur les regles inter-zones. C'est meilleur pour la securite et ca
rend les mesures non ambigues.
