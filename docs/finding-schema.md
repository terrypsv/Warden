# Schéma de constat (v1.0)

Format partagé par dix outils de la suite: Warden, Clavis, Janus, Aegis, Vigil,
Atlas, Vestige, Aurora, Sylva et Phoenix. Une couche d'audit les consomme sans adaptateur. Quaero et Bastion produisent leur propre rapport: leur matière ne se projette pas en constats sans la déformer.

Règle de compatibilité : **ajouts uniquement**. Tout renommage, suppression ou
changement de sémantique d'un champ existant impose de passer la
`schema_version` à `2.0`.

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
mesure à l'identique.

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
| `id` | oui | préfixe par outil : `WRD-` Warden, `ARG-` Argus, `VGL-` Vigil, `AGS-` Aegis |
| `category` | oui | domaine du contrôle, ex. `network-segmentation`, `host-hardening` |
| `severity` | oui | `critical`, `high`, `medium`, `low`, `info` |
| `status` | oui | `pass`, `fail`, `review`, `skipped`, `error` |
| `target` | oui | `type` libre par outil (`flow`, `host`, `package`, `rule`) |
| `expected` / `observed` | recommandé | texte court, comparable d'un run à l'autre |
| `declared` | oui | le contrôle vient-il d'une déclaration explicite ou d'une règle par défaut |
| `references` | non | mapping vers un référentiel, fourni par l'opérateur, jamais inventé par l'outil |

### Sur `status`

`review` existe pour les observations réellement ambiguës, comme un RST qui
peut venir d'un port fermé ou d'un reject de pare-feu. Un outil de sécurité
qui tranche au hasard pour éviter une case "à vérifier" produit des faux
négatifs, ce qui est pire qu'un aveu d'ignorance.

Règle de sortie : seul `fail` doit faire échouer un pipeline. `review` mérite
une alerte, pas un blocage.

### Sur `references`

Les identifiants de référentiel viennent du fichier de configuration de
l'opérateur. Aucun outil de la suite ne devine un identifiant ANSSI ou MITRE :
une référence fausse dans un rapport d'audit est un problème de crédibilité,
pas un détail.

## Tri

`Finish()` ordonne les constats : statut (fail, review, error, skipped, pass),
puis gravité, puis identifiant. Deux exécutions sur le même environnement
produisent des rapports diffables.
