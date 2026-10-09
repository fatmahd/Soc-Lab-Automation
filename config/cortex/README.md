# Dossier config/cortex

Ce dossier contient la stack Cortex et son moteur de stockage.

## Ce que fait ce dossier

- Lance Cortex pour executer les analyzers sur les observables.
- Lance un Elasticsearch dedie a Cortex.

## Fichier principal

- docker-compose.yml
  - Service cortex-es: Elasticsearch single-node pour index Cortex.
  - Service cortex: API Cortex exposee sur le port 9001.
  - Monte /opt/cortex/jobs dans /tmp/cortex-jobs pour execution des jobs.
  - Monte le socket Docker pour executer certains analyzers containerises.

## Utilite dans le workflow SOC

- Recoit les observables transmis depuis TheHive/Shuffle.
- Lance les analyzers (VirusTotal, AbuseIPDB, MISP, etc.).
- Retourne des resultats structurees pour enrichir le case.

## Points de vigilance

- Verifier que /opt/cortex/jobs existe sur l hote.
- Verifier que le socket Docker est accessible.
- Surveiller RAM (Elasticsearch + Cortex peuvent etre gourmands).

## Etapes et commandes

Depuis la racine du projet:

```bash
docker compose -f config/cortex/docker-compose.yml up -d
docker compose -f config/cortex/docker-compose.yml ps
docker compose -f config/cortex/docker-compose.yml logs -f cortex
```

Arreter la stack Cortex:

```bash
docker compose -f config/cortex/docker-compose.yml down
```
