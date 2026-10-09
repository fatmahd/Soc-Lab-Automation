# Dossier docs

Ce dossier contient les guides operatoires du projet.

## Ce que fait ce dossier

- Documente le deploiement et la configuration PHASE4.
- Documente les scenarios de test Linux/Windows.
- Documente les scripts de test et de validation.

## Fichiers

- PHASE4_WAZUH_DOCKER.md
  - Guide principal de deploiement Wazuh + integration TheHive.
  - Inclut verification, debug, deduplication et depannage.

- PHASE4_ATTACK_SIMULATION_WINDOWS_LINUX.md
  - Runbook de simulation d attaques lab Linux et Windows.
  - Donne les rule.id attendus.

- PHASE4_SCRIPTS_DETAILED_GUIDE.md
  - Explication detaillee des scripts de simulation et validation.

## Utilite

- Point d entree principal pour un nouvel analyste/ingenieur SOC.
- Rend le projet reproductible sans transmission orale.

## Etapes et commandes

Ordre de lecture recommande:
1. PHASE4_WAZUH_DOCKER.md
2. PHASE4_ATTACK_SIMULATION_WINDOWS_LINUX.md
3. PHASE4_SCRIPTS_DETAILED_GUIDE.md

Commandes associees (depuis la racine):

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
bash scripts/run_phase4_linux_attack_test.sh --target-ip 10.10.0.22
python3 scripts/validate_phase4_rule_ids.py --mode full --container single-node-wazuh.manager-1
```

