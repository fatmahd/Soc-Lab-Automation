# Dossier config/wazuh/linux

Ce dossier contient la configuration de reference de l agent Wazuh Linux.

## Fichier

- ossec.conf
  - Configure l envoi vers manager (adresse, port, protocole).
  - Active modules de securite (rootcheck, syscheck, sca, syscollector).
  - Declare les fichiers logs collectes:
    - /var/log/syslog
    - /var/log/auth.log
    - /var/log/kern.log
    - /var/log/ufw.log
    - /var/log/audit/audit.log
    - /var/log/cron.log

## Utilite

- Sans ce fichier, les regles Linux custom ne recoivent pas les bons evenements.
- Garantit la collecte des traces necessaires pour:
  - scan TCP,
  - brute-force SSH,
  - flood ICMP,
  - activite sudo/su/cron/auditd.

## Etapes et commandes

Sur l agent Linux (avec droits root):

```bash
sudo cp config/wazuh/linux/ossec.conf /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

Verification logs agent:

```bash
sudo tail -n 100 /var/ossec/logs/ossec.log
```

