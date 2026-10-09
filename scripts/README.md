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
