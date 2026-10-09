# Dossier config/wazuh/windows

Ce dossier contient la configuration de reference de l agent Wazuh Windows.

## Fichier

- ossec.conf
  - Configure l envoi au manager Wazuh.
  - Collecte Application, Security et System event channels.
  - Security query conserve les evenements 5152/5156/5157 (firewall), utiles aux regles PHASE4.
  - Active modules syscheck, sca, syscollector, rootcheck.

## Utilite

- Permet la detection Windows firewall, brute force logon, et scenarios Sysmon.
- Evite de filtrer des events critiques pour la correlation.

## Etapes et commandes

Sur l agent Windows (PowerShell admin):

```powershell
Copy-Item config/wazuh/windows/ossec.conf "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Verification des derniers logs agent:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```

