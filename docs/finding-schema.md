# Schema de constat (v1.0)

Format commun a tous les outils de la suite. Chaque collecteur emet ce JSON,
la couche d'audit le consomme sans adaptateur specifique.

Regle de compatibilite : **ajouts uniquement**. Tout renommage, suppression ou
changement de semantique d'un champ existant impose de passer la
`schema_version` a `2.0`.

## Enveloppe

```json
{
  "schema_version": "1.0",
  "tool":     { "name": "warden", "version": "0.1.0" },
  "run":      {
    "id": "9f2c1a4e7b8d0356",
    "started_at": "2026-07-30T09:12:44Z",
    "finished_at": "2026-07-30T09:12:51Z",
    "host": "kali",
    "context": { "source_zone": "red", "mode": "strict" }
  },
  "findings": []
}
```

`run.context` est libre : chaque outil y met ce qui permet de rejouer la
mesure a l'identique.

## Constat

```json
{
  "id": "WRD-SEG-0007",
  "title": "Flux non declare joignable: red->lan:tcp/445",
  "description": "Flux absent de la matrice, evalue avec l'action par defaut.",
  "category": "network-segmentation",
  "severity": "critical",
  "status": "fail",
  "target": { "type": "flow", "identifier": "red->lan:tcp/445" },
  "expected": "deny",
  "observed": "open",
  "remediation": "Ajouter une regle de blocage explicite sur ce flux.",
  "declared": false,
  "evidence": [
    { "type": "probe", "data": "dst=10.10.10.50 proto=tcp port=445 outcome=open latency=3ms" }
  ],
  "references": [ { "framework": "MITRE ATT&CK", "id": "T1021" } ],
  "detected_at": "2026-07-30T09:12:47Z"
}
```

### Champs

| Champ | Obligatoire | Notes |
|-------|-------------|-------|
| `id` | oui | prefixe par outil : `WRD-` Warden, `ARG-` Argus, `VGL-` Vigil, `AGS-` Aegis |
| `category` | oui | domaine du controle, ex. `network-segmentation`, `host-hardening` |
| `severity` | oui | `critical`, `high`, `medium`, `low`, `info` |
| `status` | oui | `pass`, `fail`, `review`, `skipped`, `error` |
| `target` | oui | `type` libre par outil (`flow`, `host`, `package`, `rule`) |
| `expected` / `observed` | recommande | texte court, comparable d'un run a l'autre |
| `declared` | oui | le controle vient-il d'une declaration explicite ou d'une regle par defaut |
| `references` | non | mapping vers un referentiel, fourni par l'operateur, jamais invente par l'outil |

### Sur `status`

`review` existe pour les observations reellement ambigues, comme un RST qui
peut venir d'un port ferme ou d'un reject de pare-feu. Un outil de securite
qui tranche au hasard pour eviter une case "a verifier" produit des faux
negatifs, ce qui est pire qu'un aveu d'ignorance.

Regle de sortie : seul `fail` doit faire echouer un pipeline. `review` merite
une alerte, pas un blocage.

### Sur `references`

Les identifiants de referentiel viennent du fichier de configuration de
l'operateur. Aucun outil de la suite ne devine un identifiant ANSSI ou MITRE :
une reference fausse dans un rapport d'audit est un probleme de credibilite,
pas un detail.

## Tri

`Finish()` ordonne les constats : statut (fail, review, error, skipped, pass),
puis gravite, puis identifiant. Deux executions sur le meme environnement
produisent des rapports diffables.
