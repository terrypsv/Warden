# Feuille de route

## v0.1.0 - source unique (livraison cible)

- [x] Matrice de flux YAML validee strictement
- [x] Expansion en controles, declares et par defaut
- [x] Sonde TCP avec classification open / refused / filtered
- [x] Modes blind et strict autour de l'ambiguite du RST
- [x] Ecouteurs `warden listen` pour la zone cible
- [x] Rapport JSON au schema commun
- [x] Codes de sortie exploitables en cron et CI, mode `-brief`
- [ ] Validation terrain sur le lab : red vers dmz, red vers lan, lan vers dmz
- [ ] Release multi-plateforme avec SHA256SUMS

## v0.2.0 - agents par zone

- [ ] Agent `warden agent` avec canal de controle authentifie
- [ ] Sondage UDP et ICMP confirme cote recepteur
- [ ] Detection asymetrique : verifier les deux sens d'un flux
- [ ] Matrice multi-source en une seule execution

## v0.3.0 - exploitation

- [ ] Rapport HTML local, comme dans Argus, en loopback avec jeton
- [ ] Comparaison entre deux rapports : ce qui a change depuis la derniere mesure
- [ ] Import de la configuration OPNsense pour pre-remplir la matrice
- [ ] Ordonnancement periodique et historique

## Hors perimetre

- Scan de decouverte generaliste : c'est le role de nmap, pas de Warden
- Test de vulnerabilite : Warden mesure des chemins, pas des failles
- Modification de configuration : l'outil observe et rapporte, il ne corrige pas
