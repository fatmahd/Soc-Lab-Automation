# Dossier scripts

Ce dossier contient les scripts executables pour appliquer la configuration et valider les detections.

## Fichiers

- apply_phase4_wazuh_docker.sh
  - Script de deploiement principal cote manager Docker Wazuh.
  - Copie les regles custom XML vers /var/ossec/etc/rules.
  - Deploie integration custom-wazuh-thehive et son .env.
  - Installe requests dans le conteneur si necessaire.
  - Ajuste analysisd.decoder_order_size.
  - Redemarre Wazuh manager et verifie la presence des rule IDs.

- run_phase4_linux_attack_test.sh
  - Simule une campagne Linux:
    - scan TCP,
    - brute-force SSH,
    - ICMP flood court.

- run_phase4_windows_attack_test.ps1
  - Simule une campagne Windows:
    - blocages TCP firewall,
    - failed logon repetes,
    - execution PowerShell encodee.

- validate_phase4_rule_ids.py
  - Valide automatiquement les rule.id observes dans alerts.json.
  - Modes: linux, windows, full, custom.

## Ordre recommande d execution

1. Appliquer config: apply_phase4_wazuh_docker.sh
2. Lancer test Linux puis validation linux
3. Lancer test Windows puis validation windows
4. Lancer validation full

## Utilite

- Standardise les operations et limite les erreurs manuelles.
- Accelere onboarding et troubleshooting.

## Commandes pretes a executer

1. Appliquer PHASE4 sur manager Wazuh Docker:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```

2. Lancer simulation Linux:

```bash
bash scripts/run_phase4_linux_attack_test.sh --target-ip 10.10.0.22
```

3. Lancer simulation Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_phase4_windows_attack_test.ps1 -TargetIp 10.10.0.33
```

4. Valider rule.id Linux:

```bash
python3 scripts/validate_phase4_rule_ids.py --mode linux --container single-node-wazuh.manager-1
```

5. Valider rule.id Windows:

```bash
python3 scripts/validate_phase4_rule_ids.py --mode windows --container single-node-wazuh.manager-1
```

6. Valider toutes les detections:

```bash
python3 scripts/validate_phase4_rule_ids.py --mode full --container single-node-wazuh.manager-1
```
