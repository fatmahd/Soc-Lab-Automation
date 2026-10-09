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
