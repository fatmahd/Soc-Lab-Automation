# Dossier config/wazuh/rules

Ce dossier contient les regles Wazuh custom en format modularise.

## Ce que fait ce dossier

- Separe les regles par OS pour faciliter maintenance.
- Permet au script de deploiement de copier chaque fichier XML vers le manager.

## Fichiers

- local_rules.xml
  - Contient une regle silencieuse locale (point d extension).
  - Sert de base valide pour eviter fichier local vide.

- linux/
  - Regles de detection Linux (UFW, auditd, auth, syslog, cron).

- windows/
  - Regles de detection Windows (firewall, Sysmon).

## Convention

- Les prefixes numeriques de fichiers facilitent l ordre de lecture.
- Chaque rule id doit rester unique dans toute la pile custom.

## Etapes et commandes

Verifier les IDs de regles presentes:

```bash
grep -Rho '<rule id="[0-9]\+"' config/wazuh/rules | sort -u
```

Appliquer toutes les regles dans le manager Docker:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```

