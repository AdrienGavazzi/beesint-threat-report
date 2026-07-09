# Détection d'anomalies du pipeline

## 1. Contexte

Le pipeline consomme quatre sources externes (NVD, CISA KEV, abuse.ch FeodoTracker, abuse.ch
URLhaus — ThreatFox en cinquième source optionnelle). Ces sources peuvent renvoyer une réponse
vide, tronquée, ou lever une exception (timeout, changement de schéma, rate limit) sans qu'aucune
erreur HTTP explicite ne le signale forcément. Un pipeline qui publierait silencieusement un
rapport creux ou partiel, sans qu'aucun signal ne remonte, serait pire qu'un pipeline qui échoue
bruyamment. Compétence CDC §2 : "Sentry + anomaly checks → Observabilité, data quality
monitoring".

## 2. Approche retenue

Pas de librairie de détection statistique (pas de `great_expectations`, pas de modèle ML, pas de
calcul de z-score/écart-type). Le pipeline tourne une fois par semaine : un modèle statistique
n'aurait pas assez de points pour être plus fiable qu'un signal simple. Deux mécanismes,
volontairement minimalistes :

- **Statut par source** (`sources_status`) : chaque étape d'extraction (`_run_nvd_source`,
  `_run_kev_source`, `_run_feodo_source`, `_run_urlhaus_source`, `_run_threatfox_source` dans
  `orchestrate.py`) est encapsulée dans un `try/except` qui ne laisse jamais remonter d'exception.
  Le résultat (`"ok"` / `"failed"` / `"skipped:*"`) est collecté par source et publié tel quel dans
  le rapport (bloc "lineage pipeline", CDC §16).
- **Tendance KPI vs run précédent** (`trend_pct`) : `transform/kpis.py` compare deux compteurs du
  run courant (`cve_critical_count`, `threatfox_malware_families_count`) à leur valeur du run
  précédent, lue dans `manifest.json`. C'est un signal informatif affiché dans le rapport, pas un
  check qui bloque ou altère le statut du run.

## 3. Checks réellement implémentés

- **Statut d'échec par source** — appelé dans `orchestrate.py` juste après chaque appel
  `_run_*_source`. Sortie : `sources_status[nom_source] = "ok" | "failed" | "skipped:<raison>"`,
  doublée d'un `logger.exception(...)` (log structuré) et d'un breadcrumb Sentry
  (`sentry_breadcrumb_run_step(step, status)`, `publish/telemetry.py`) — jamais d'exception
  bloquante, jamais d'arrêt du run entier pour une seule source en échec.
- **Tendance KPI** — calculée dans `compute_kpis()` (`transform/kpis.py`) via `_trend_pct(current,
  previous)`, appelée après `transform/`, avant `load/`. Compare uniquement au run N-1 (pas à une
  moyenne glissante). Résultat exposé dans les champs `cve_critical_trend_pct` et
  `threatfox_malware_families_trend_pct` du JSON du rapport et repris dans le PDF.
- **Quarantaine de schéma** (`validate_batch` + `_write_quarantine`) est un mécanisme distinct de
  **data quality** (item individuel rejeté par Pydantic), pas d'anomaly detection au sens de ce
  document — volontairement non dupliqué ici (cf. Lot 1 / CDC §10).

Ces deux mécanismes (statut par source, tendance KPI) sont les **seuls** signaux d'anomalie
implémentés à ce stade. Il n'existe pas de détection d'outlier par IP individuelle, ni de
comparaison contre une moyenne historique sur N périodes, ni de seuil (ex. ±50 %) déclenchant un
warning dédié, ni de champ `anomalies: [...]` séparé dans le rapport.

## 4. Implémentation

Le flux : chaque étape d'extraction s'exécute dans son propre `try/except Exception` ; en cas
d'échec, la source retourne un DataFrame vide et le statut `"failed"`, et le run continue avec les
sources restantes (cohérent CDC §4 "continue en dégradé" — jamais d'arrêt total pour une source en
panne). Le statut global du run (`report_status`) ne devient `"partial"` que si au moins une source
a `"failed"` ou si l'écriture Parquet/PDF échoue — un statut `"skipped:*"` (ThreatFox sans clé,
lot 7 optionnel) ne dégrade jamais le statut global. La tendance KPI est calculée une fois par run,
sans branche conditionnelle : si `previous_kpis` est `None` (cold start, pas de `manifest.json`),
`_trend_pct` retourne `None` — affiché comme tel dans le rapport, jamais une exception.

## 5. Outils utilisés

- **Sentry** : `sentry_breadcrumb_run_step()` ajoute un breadcrumb `category="etl"` après chaque
  étape (succès ou échec) — pas de `capture_message`/`capture_exception` dédié à un warning
  d'anomalie de volumétrie, puisque ce check n'existe pas sous cette forme. La quarantaine (data
  quality, distincte) utilise `capture_message` pour chaque item rejeté.
- **Log structuré stdout** : `logger.exception(...)` par source en échec, `log_run_summary()`
  (`publish/telemetry.py`) en fin de run — même pattern que `publish/telemetry.py` (CDC §4).
- Pas de dashboard dédié, pas de nouvel outil introduit pour ces checks.

## 6. Limites

- **Pas de calcul statistique adaptatif** : la tendance KPI compare uniquement au run précédent
  (N-1), pas à une moyenne glissante sur plusieurs périodes lues dans le Parquet historique. Choix
  de simplicité assumé : à une volumétrie d'un run par semaine, quelques semaines d'historique ne
  suffiraient pas à rendre un calcul statistique (écart-type, z-score) plus fiable qu'une lecture
  directe de la tendance brute.
- **Pas de seuil de warning** : `trend_pct` est une donnée affichée, pas un check qui déclenche une
  alerte ou change le statut du run — une variation de +500 % ne produit aucun signal distinct
  d'une variation de +2 %.
- **Pas de distinction "source vide légitime" vs "run sain"** : une source qui répond avec 0
  résultat sans lever d'exception garde le statut `"ok"`, identique à un run avec des données. Seule
  une exception non rattrapée (timeout, erreur réseau, schéma invalide) produit `"failed"`. Une
  vraie semaine calme et une régression silencieuse de l'API amont sont donc actuellement
  indiscernables via `sources_status` seul.
- **Pas d'alerting temps réel** : aucune notification Slack/Discord dédiée à ce jour — Sentry est le
  seul canal, consulté manuellement.
- **Cold start** : au premier run (pas de `manifest.json`), `previous_kpis` est `None` et
  `trend_pct` vaut systématiquement `None` — cas dégradé attendu, cohérent avec CDC §6.

## 7. Bonnes pratiques retenues

- Aucun check n'est bloquant : une source en échec, un schéma rejeté ou une tendance anormale ne
  font jamais planter le run (`continue en dégradé`, CDC §4).
- Séparation claire entre erreur technique (exception réseau/parsing, capturée par
  `sources_status`) et donnée métier surprenante mais valide (tendance KPI) — les deux ne sont
  jamais confondues dans le même champ.
- Les signaux (`sources_status`, `trend_pct`) sont visibles dans le rapport produit lui-même (JSON
  + PDF), pas seulement dans les logs internes ou Sentry — la donnée reste traçable a posteriori,
  y compris pour un lecteur qui n'a pas accès à Sentry.
