# Dossier config

Ce dossier centralise toutes les configurations techniques du SOC lab.

## Ce que fait ce dossier

- Definit les stacks Docker annexes (Cortex, MISP, Shuffle).
- Stocke les regles et configurations Wazuh (manager + agents).
- Centralise les variables d environnement utilisees par les scripts.

## Fichiers et sous-dossiers

- .env.example
  - Modele des variables requises pour integration Wazuh -> TheHive.
  - Inclut aussi les options de deduplication.

- cortex/
  - Docker compose Cortex + Elasticsearch.

- misp/
  - Docker compose MISP + base MariaDB + Redis.
  - Configuration de feeds de threat intelligence.

- shuffle/
  - Docker compose Shuffle (frontend, backend, orborus, opensearch).
  - Script utilitaire de consolidation des resultats analyzers.

- wazuh/
  - Regles custom PHASE4.
  - ossec.conf Linux/Windows pour agents.
  - Regles modularisees Linux et Windows.

## Bonnes pratiques

- Ne jamais committer de secrets reels dans ce dossier.
- Utiliser .env.example comme template, puis creer config/.env localement.
- Apres modification Wazuh, reappliquer via scripts/apply_phase4_wazuh_docker.sh.
