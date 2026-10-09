# Dossier config/shuffle

Ce dossier contient la stack Shuffle et un script de synthesis des resultats analyzers.

## Ce que fait ce dossier

- Heberge l orchestrateur SOAR Shuffle.
- Permet d automatiser le traitement post-alerte TheHive.

## Fichiers

- docker-compose.yaml
  - frontend: interface web Shuffle (port 3001).
  - backend: moteur API et execution des workflows.
  - orborus: gestion des executions d apps/actions.
  - shuffle-opensearch: stockage interne des donnees Shuffle.

- results_dynamic.py
  - Script de consolidation des retours Cortex.
  - Parse AbuseIPDB, MISP et VirusTotal.
  - Calcule une severite simplifiee (LOW/MEDIUM/HIGH).
  - Construit un resume court exploitable pour notification (ex: Telegram).

## Utilite dans le workflow SOC

- Recoit les alertes TheHive.
- Lance enrichissements Cortex.
- Ajoute un resume decisionnel pour l analyste.

## Points de vigilance

- Verifier les variables OpenSearch et mots de passe.
- Verifier les volumes mounts (shuffle-apps, shuffle-files).
- Surveiller memoire de shuffle-opensearch.

## Etapes et commandes

Depuis la racine du projet:

```bash
docker compose -f config/shuffle/docker-compose.yaml up -d
docker compose -f config/shuffle/docker-compose.yaml ps
docker compose -f config/shuffle/docker-compose.yaml logs -f backend
```

Acces interface:
- URL par defaut: http://localhost:3001

Arreter la stack Shuffle:

```bash
docker compose -f config/shuffle/docker-compose.yaml down
```

Note: results_dynamic.py est prevu pour un contexte Shuffle (variables dynamiques) et pas pour une execution locale directe.
