# PHASE4 - Guide detaille des scripts (Linux, Windows, validation)

Ce guide explique en detail:
1. Comment lancer chaque script.
2. Pourquoi chaque etape existe.
3. Quelle regle Wazuh doit etre declenchee.

Scripts concernes:
- [scripts/run_phase4_linux_attack_test.sh](scripts/run_phase4_linux_attack_test.sh)
- [scripts/run_phase4_windows_attack_test.ps1](scripts/run_phase4_windows_attack_test.ps1)
- [scripts/validate_phase4_rule_ids.py](scripts/validate_phase4_rule_ids.py)

## 1) Script Linux: run_phase4_linux_attack_test.sh

Fichier: [scripts/run_phase4_linux_attack_test.sh](scripts/run_phase4_linux_attack_test.sh)

### 1.1 Objectif

Simuler 3 familles d activites sur la cible Linux:
- Reconnaissance reseau (scan TCP)
- Echecs d authentification SSH repetes
- Flux ICMP tres rapide (flood court)

Ces 3 familles couvrent les regles Linux critiques de ton PHASE4.

### 1.2 Prerequis

Sur la machine d attaque (ex: Kali):
- nmap installe
- hydra installe
- hping3 installe
- timeout disponible
- droits root recommandes

### 1.3 Commande minimale

sudo ./scripts/run_phase4_linux_attack_test.sh --target-ip IP_LINUX

### 1.4 Explication detaillee de chaque etape

Etape A - Scan TCP:
- Action: nmap sur une plage de ports.
- Utilite: creer des connexions TCP multiplies qui vont etre bloquees/journalisees par UFW.
- Effet attendu: generation des regles de base reseau, puis correlation port scan.
- Regles visees: 100402, 100404, 100407, puis 100400/100401/100403.

Etape B - SSH brute force simule:
- Action: hydra avec utilisateur invalide + wordlist.
- Utilite: provoquer des failed password repetes, puis une alerte brute-force.
- Effet attendu: plusieurs evenements SSH en peu de temps.
- Regles visees: 100460 puis 100461.

Etape C - ICMP flood court:
- Action: hping3 en mode icmp flood pendant une duree courte.
- Utilite: valider la chaine de detection DoS/ICMP sans saturer longtemps le lab.
- Effet attendu: activite ICMP de base puis correlation flood.
- Regles visees: 100405 puis 100410.

### 1.5 Options utiles

- --skip-scan
  - Utilite: isoler brute-force + ICMP sans scan.
- --skip-bruteforce
  - Utilite: ne tester que la partie reseau/firewall.
- --skip-icmp
  - Utilite: eviter la phase flood si le lab est sensible.
- --dry-run
  - Utilite: afficher seulement les commandes pour revue avant execution.

## 2) Script Windows: run_phase4_windows_attack_test.ps1

Fichier: [scripts/run_phase4_windows_attack_test.ps1](scripts/run_phase4_windows_attack_test.ps1)

### 2.1 Objectif

Generer des evenements Windows qui alimentent tes regles Wazuh:
- Blocage TCP par firewall (simulateur de pattern scan)
- Echecs de connexion repetes (4625)
- PowerShell encode (Sysmon event 1)

### 2.2 Prerequis

Sur WIN-SRV-2019:
- Ouvrir PowerShell en Administrateur
- Agent Wazuh actif
- Sysmon actif (pour 100500/100501)

### 2.3 Commande minimale

.\scripts\run_phase4_windows_attack_test.ps1 -TargetIp IP_WINDOWS -Domain DOMAIN -User USER

### 2.4 Explication detaillee de chaque etape

Etape A - Regle firewall temporaire + tentatives TCP:
- Action: creer une regle outbound block TCP puis tenter des connexions repetees.
- Utilite: fabriquer rapidement des evenements firewall bloques, utiles pour tester 100434/100435.
- Effet attendu: plusieurs blocages TCP rapproches.
- Regles visees: 100434 puis 100435.

Etape B - Echecs d authentification:
- Action: net use vers IPC$ avec mauvais mot de passe, en boucle.
- Utilite: produire des event 4625 repetes dans une fenetre courte.
- Effet attendu: failed logon puis correlation brute-force.
- Regles visees: 100418 puis 100421.

Etape C - PowerShell encode:
- Action: execution PowerShell avec -EncodedCommand.
- Utilite: simuler un comportement frequemment associe a defense evasion/execution.
- Effet attendu: event creation process PowerShell + pattern encoded command.
- Regles visees: 100500 puis 100501.

Etape D - Nettoyage firewall:
- Action: suppression de la regle temporaire creee par le script.
- Utilite: restaurer l etat initial de la machine apres test.

### 2.5 Options utiles

- -SkipBlockedTcp
  - Utilite: tester uniquement auth + Sysmon.
- -SkipFailedLogon
  - Utilite: tester uniquement firewall + Sysmon.
- -SkipEncodedPowerShell
  - Utilite: tester uniquement firewall + auth.
- -KeepFirewallRule
  - Utilite: conserver la regle pour investigation manuelle, puis suppression manuelle plus tard.

## 3) Script de validation automatique: validate_phase4_rule_ids.py

Fichier: [scripts/validate_phase4_rule_ids.py](scripts/validate_phase4_rule_ids.py)

### 3.1 Objectif

Verifier automatiquement si les rule.id attendus sont visibles dans les alertes recentes.

Le script:
- Lit alerts.json localement ou depuis un conteneur Docker Wazuh.
- Filtre sur une fenetre de temps (ex: 30 min).
- Filtre optionnellement sur un agent precise.
- Compare IDs trouves vs IDs attendus.
- Retourne PASS ou FAIL.

### 3.2 Utilisation type (manager Docker)

Validation Linux:
python scripts/validate_phase4_rule_ids.py --mode linux --container single-node-wazuh.manager-1 --since-minutes 30 --agent ubuntu-srv1

Validation Windows:
python scripts/validate_phase4_rule_ids.py --mode windows --container single-node-wazuh.manager-1 --since-minutes 30 --agent win-srv-2019

Validation complete:
python scripts/validate_phase4_rule_ids.py --mode full --container single-node-wazuh.manager-1 --since-minutes 45

### 3.3 Utilisation type (fichier local)

python scripts/validate_phase4_rule_ids.py --mode linux --alerts-file /var/ossec/logs/alerts/alerts.json --since-minutes 30

### 3.4 Signification des options principales

- --mode linux
  - Utilite: verifier seulement les IDs Linux PHASE4.
- --mode windows
  - Utilite: verifier seulement les IDs Windows PHASE4.
- --mode full
  - Utilite: verifier les 2 piles d un coup.
- --mode custom --expected 100400,100401
  - Utilite: cibler un sous-ensemble particulier.
- --agent
  - Utilite: eviter les faux positifs venant d autres machines.
- --since-minutes
  - Utilite: restreindre la validation a la campagne de test en cours.

### 3.5 Interpretation du resultat

PASS:
- Tous les IDs attendus sont observes.
- La campagne de test est consideree complete pour le scope choisi.

FAIL:
- Un ou plusieurs IDs manquent.
- Actions recommandees:
  1. Rejouer le test correspondant a la regle manquante.
  2. Verifier les logs Wazuh manager.
  3. Verifier que les groupes/rules custom sont bien charges.

## 4) Ordre d execution recommande (operationnel)

1. Lancer script Linux.
2. Lancer validation Linux.
3. Lancer script Windows.
4. Lancer validation Windows.
5. Lancer validation full pour confirmation finale.

## 5) Pourquoi ce workflow est utile

- Standardise les tests de detection pour eviter les validations "a la main" incompletes.
- Rend les campagnes repetables (meme sequence, memes criteres).
- Accelere le troubleshooting: les IDs manquants indiquent exactement quoi corriger.
