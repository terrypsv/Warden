# Feuille de route

## v1.0.0 - source unique (livrée)

- [x] Matrice de flux YAML validée strictement
- [x] Expansion en contrôles, déclarés et par défaut
- [x] Sonde TCP avec classification open / refused / filtered
- [x] Modes blind et strict autour de l'ambiguïté du RST
- [x] Écouteurs `warden listen` pour la zone cible
- [x] Rapport JSON au schéma commun
- [x] Codes de sortie exploitables en cron et CI, mode `-brief`
- [x] Validation terrain sur le lab : red vers dmz, red vers lan
- [x] Bannière signée et confirmation du mode strict zone par zone
- [x] Ports Active Directory dans le balayage par défaut
- [x] `warden preflight` et arrêt automatique des écouteurs
- [x] `warden discover` : services joignables absents de la matrice
- [x] Release multi-plateforme avec SHA256SUMS

## v1.1.0 - familles d'adresses

- [x] Famille explicite par zone, IPv4 par défaut
- [x] Famille pinnée au dial et à l'écoute, plus de résolution ambiguë
- [ ] Tester les deux familles d'une même zone en une exécution

## v2.0.0 - agents par zone

- [ ] Agent `warden agent` avec canal de contrôle authentifié
- [ ] Sondage UDP et ICMP confirmé côté récepteur
- [ ] Détection asymétrique : vérifier les deux sens d'un flux
- [ ] Matrice multi-source en une seule exécution

## v2.1.0 - exploitation

- [ ] Rapport HTML local, comme dans Argus, en loopback avec jeton
- [ ] Comparaison entre deux rapports : ce qui a changé depuis la dernière mesure
- [ ] Import de la configuration OPNsense pour pré-remplir la matrice
- [ ] Ordonnancement périodique et historique

## Hors périmètre

- Scan de découverte généraliste : `warden discover` balaye une liste de
  services courants pour confronter le réseau à la matrice, il ne remplace
  pas nmap et ne fait ni fingerprinting ni énumération de version
- Test de vulnérabilité : Warden mesure des chemins, pas des failles
- Modification de configuration : l'outil observe et rapporte, il ne corrige pas

## Validation terrain, 17 août 2026

Première campagne sur infrastructure réelle (lab personnel, 4 zones).
Cinq défauts trouvés, zéro faux positif :

- règle `pass` résiduelle dans OPNsense, exposant SMB, NetBIOS, RPC et SSH du
  contrôleur de domaine à la zone attaquant
- transit inter-zones autorisé par l'hôte Proxmox (routage actif sans règle
  de blocage entre les ponts), contournant intégralement le pare-feu
- conflit d'adresse IP entre deux conteneurs de la DMZ
- `nftables.service` inactif, donc aucune règle persistante au reboot
- cible applicative joignable et absente de la matrice, trouvée par
  `warden discover`

Correction vérifiée par une seconde mesure : 5 constats critiques ramenés à
zéro, code de sortie 0.
