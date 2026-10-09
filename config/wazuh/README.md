# Dossier config/wazuh

Ce dossier contient le coeur de detection Wazuh du projet.

## Ce que fait ce dossier

- Definit les regles custom PHASE4 Linux et Windows.
- Fournit des ossec.conf preconfigures pour agents Linux et Windows.
- Conserve un fichier legacy local_rules_phase4.xml pour compatibilite.

## Fichiers et sous-dossiers

- local_rules_phase4.xml
  - Variante monolithique regroupant regles Linux et Windows dans un seul fichier.
  - Utile comme reference historique ou fallback.

- linux/ossec.conf
  - Configuration agent Linux (collecte syslog, auth, ufw, auditd, cron, etc.).

- windows/ossec.conf
  - Configuration agent Windows (event channels, dont Security avec event firewall).

- rules/
  - Version modularisee des regles custom, organisee par OS.

## Utilite operationnelle

- C est ici que se regle la precision detection (bruit vs couverture).
- Toute evolution detection doit passer par ces regles et etre retestee.
