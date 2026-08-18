# Feuille de route

## v0.1.0 - source unique

- [x] Matrice de flux YAML validee strictement
- [x] Expansion en controles, declares et par defaut
- [x] Sonde TCP avec classification open / refused / filtered
- [x] Modes blind et strict autour de l'ambiguite du RST
- [x] Ecouteurs `warden listen` pour la zone cible
- [x] Rapport JSON au schema commun
- [x] Codes de sortie exploitables en cron et CI, mode `-brief`
- [x] Validation terrain sur le lab : red vers dmz, red vers lan
- [x] Banniere signee et confirmation du mode strict zone par zone
- [ ] Ports Active Directory dans le balayage par defaut
- [ ] `warden discover` : signaler les services absents de la matrice
- [ ] Release multi-plateforme avec SHA256SUMS

## v0.2.0 - agents par zone

- [ ] Agent `warden agent` avec canal de controle authentifie
- [ ] Sondage UDP et ICMP confirme cote recepteur
- [ ] Detection asymetrique : verifier les deux sens d'un flux
- [ ] Matrice multi-source en une seule execution
- [ ] Comportement IPv4 / IPv6 explicite

## v0.3.0 - exploitation

- [ ] Rapport HTML local, comme dans Argus, en loopback avec jeton
- [ ] Comparaison entre deux rapports : ce qui a change depuis la derniere mesure
- [ ] Import de la configuration OPNsense pour pre-remplir la matrice
- [ ] Ordonnancement periodique et historique

## Hors perimetre

- Scan de decouverte generaliste : c'est le role de nmap, pas de Warden
- Test de vulnerabilite : Warden mesure des chemins, pas des failles
- Modification de configuration : l'outil observe et rapporte, il ne corrige pas

## Validation terrain, 17 aout 2026

Premiere campagne sur infrastructure reelle (lab goeland-1, 4 zones).
Quatre defauts trouves, zero faux positif :

- regle `pass RED net -> 10.10.10.10` residuelle dans OPNsense, exposant SMB,
  NetBIOS, RPC et SSH du controleur de domaine a la zone attaquant
- transit inter-zones autorise par l'hote Proxmox (`ip_forward=1`, aucune regle
  de blocage entre vmbr1/2/3), contournant integralement le pare-feu
- conflit d'adresse IP entre deux conteneurs de la DMZ
- `nftables.service` inactif, donc aucune regle persistante au reboot

Correction verifiee par une seconde mesure : 5 constats critiques ramenes a
zero, code de sortie 0.
