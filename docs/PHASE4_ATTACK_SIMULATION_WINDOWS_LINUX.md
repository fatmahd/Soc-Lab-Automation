# PHASE4 - Simulation d attaques Linux + Windows (lab)

Objectif: lancer des tests controles pour valider Wazuh -> TheHive sur les deux OS.

Important:
- Utiliser uniquement dans ton lab autorise.
- Ne jamais executer ces commandes hors environnement de test.

## 1) Test Linux (UFW + SSH brute force + ICMP flood)

### 1.1 Depuis la machine d attaque (Kali)

Variables:
- IP_LINUX = IP de UBUNTU-SRV1

Commandes:

1. Scan TCP pour declencher les regles port scan Linux
   nmap -sS -Pn -p 1-200 IP_LINUX

2. Brute force SSH (user invalide) pour declencher les regles auth Linux
   hydra -l invaliduser -P /usr/share/wordlists/rockyou.txt ssh://IP_LINUX -t 4 -f

3. ICMP flood court (10-20 secondes max)
   sudo hping3 --icmp --flood IP_LINUX

### 1.2 Regles Wazuh attendues (Linux)

- Port scan / firewall:
  - 100402, 100404, 100407 (base UFW TCP)
  - 100400, 100401, 100403 (correlation port scan)
- SSH brute force:
  - 100460 (failed SSH)
  - 100461 (SSH brute force)
- ICMP flood:
  - 100405 (ICMP activity)
  - 100410 (ICMP flood)

## 2) Test Windows (Firewall + failed logon + Sysmon PowerShell)

### 2.1 Depuis la machine d attaque (Kali)

Variables:
- IP_WINDOWS = IP de WIN-SRV-2019

Commande scan TCP:
   nmap -sS -Pn -p 1-300 IP_WINDOWS

Attendu:
- 100434 (blocked TCP)
- 100435 (possible Windows TCP port scan)

### 2.2 Sur WIN-SRV-2019 (PowerShell admin)

1. Generer des echec de connexion (event 4625)

   Remplacer USER et DOMAIN avant execution:

   for ($i=1; $i -le 10; $i++) {
     cmd /c "net use \\127.0.0.1\IPC$ /user:DOMAIN\\USER WrongPass123!"
   }

2. Generer une execution PowerShell encodee (Sysmon)

   $payload = "Write-Output 'phase4-test'"
   $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
   powershell.exe -EncodedCommand $enc

Attendu:
- 100418 (failed logon observed)
- 100421 (Windows brute-force attempt)
- 100500 (PowerShell executed)
- 100501 (encoded PowerShell)

## 3) Verification rapide Wazuh + TheHive

Sur le manager Wazuh (conteneur):

1. Voir les logs manager
   docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/ossec.log

2. Verifier agents actifs
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

Dans Wazuh Dashboard:
- Verifier les alertes avec les rule.id ci-dessus.
- Verifier level et timestamp pendant les tests.

Dans TheHive:
- Verifier creation automatique des alertes/cases.
- Verifier presence des observables (ip, domain, url, hash, filename, mail).

## 4) Option test local (sans attaque reseau)

Pour valider seulement l extraction des observables:

python automation/test_payloads/run_collect_artifacts_samples.py

Ce test n envoie rien a TheHive; il valide uniquement collect_artifacts.