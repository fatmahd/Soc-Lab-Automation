# Dossier config/wazuh/rules/linux

Ce dossier contient les regles Linux custom de PHASE4.

## Fichiers et role

- 001-linux-ufw.xml
  - Detection UFW TCP/ICMP.
  - Correlation scan de ports et flood ICMP.

- 003-linux-auditd.xml
  - Detection basee sur auditd (auth echec, exec, identity, config change).

- 004-linux-auth.xml
  - Detection SSH failed/success.
  - Correlation brute-force SSH.
  - Activite sudo et su.

- 005-linux-syslog.xml
  - Detection incidents systeme (services failed, OOM killer).

- 006-linux-cron.xml
  - Detection activite cron root, repetition anormale et echec execution.

## Utilite SOC

- Couvre les vecteurs Linux frequents d un lab:
  - reconnaissance reseau,
  - brute-force,
  - deni de service,
  - persistence et usage privilegies,
  - incidents disponibilite.

## Etapes et commandes

1. Appliquer la configuration PHASE4:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```

2. Lancer simulation Linux:

```bash
bash scripts/run_phase4_linux_attack_test.sh --target-ip 10.10.0.22
```

3. Valider les rule.id Linux detectes:

```bash
python3 scripts/validate_phase4_rule_ids.py --mode linux --container single-node-wazuh.manager-1
```

