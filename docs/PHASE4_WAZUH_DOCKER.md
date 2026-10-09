# PHASE 4 - Wazuh (docker-compose officiel)

Objectif:
- UBUNTU-SRV2: deployer manager + indexer + dashboard Wazuh (docker-compose officiel).
- UBUNTU-SRV1: installer agent Linux vers manager.
- WIN-SRV-2019: installer agent Windows vers manager.
- UBUNTU-SRV3 (ou machine dediee): installer TheHive en Docker Compose.
- Activer detection: scan ports, flood ICMP, brute force.
- Integrer Wazuh -> TheHive pour creer une alerte automatiquement.
- Validation: 2 agents Active + alerte ping visible.

## 1) UBUNTU-SRV2 - prerequis

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Reglage memoire indexer:

```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl -p /etc/sysctl.d/99-wazuh.conf
```

## 2) UBUNTU-SRV2 - deployer Wazuh officiel

```bash
cd /opt
sudo git clone https://github.com/wazuh/wazuh-docker.git
cd /opt/wazuh-docker/single-node
sudo docker compose -f generate-indexer-certs.yml run --rm generator
sudo docker compose up -d
sudo docker compose ps
```

Acces:
- Dashboard: https://IP_UBUNTU_SRV2
- API: https://IP_UBUNTU_SRV2:55000

## 3) UBUNTU-SRV1 - installer agent Linux

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="IP_UBUNTU_SRV2" WAZUH_AGENT_NAME="ubuntu-srv1" apt install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

## 4) WIN-SRV-2019 - installer agent Windows

PowerShell admin:

```powershell
$WAZUH_MANAGER="IP_UBUNTU_SRV2"
$WAZUH_AGENT_NAME="win-srv-2019"
$MSI_URL="https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
$MSI_PATH="$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri $MSI_URL -OutFile $MSI_PATH
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$MSI_PATH`" /qn WAZUH_MANAGER=$WAZUH_MANAGER WAZUH_AGENT_NAME=$WAZUH_AGENT_NAME"
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
Get-Service WazuhSvc
```

## 5) UBUNTU-SRV3 - installer TheHive (Docker Compose officiel)

Prerequis minimaux conseilles pour TheHive:
- 8 vCPU
- 16 Go RAM
- 80 Go disque

Installer prerequis:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git jq
```

Recuperer la stack Docker officielle TheHive:

```bash
cd /opt
sudo git clone https://github.com/StrangeBeeCorp/docker.git
cd /opt/docker/prod1-thehive
```

Initialiser puis demarrer TheHive:

```bash
sudo bash ./scripts/init.sh
sudo docker compose up -d
sudo docker compose ps
```

Premier acces TheHive:
- URL: http://IP_THEHIVE
- Login par defaut: admin@thehive.local
- Mot de passe par defaut: secret
- Change le mot de passe immediatement.

Generer une API key TheHive (obligatoire pour l integration Wazuh):
- Ouvre Profile -> API Keys -> Create
- Copie la cle generee

## 6) Integrer Wazuh -> TheHive (mode Docker manager)

Sur UBUNTU-SRV2, copie le projet sur /opt/soc-lab et prepare .env:

```bash
cd /opt/soc-lab
cp .env.example config/.env 2>/dev/null || true
nano config/.env
```

Variables minimales:
- THEHIVE_URL=http://IP_THEHIVE
- THEHIVE_API_KEY=...

Installer dependance requests dans le conteneur manager:

```bash
docker exec -it single-node-wazuh.manager-1 python3 -m pip install requests
```

Appliquer integration + regles:

```bash
sudo PROJECT_DIR=/opt/soc-lab MANAGER_CONTAINER=single-node-wazuh.manager-1 bash /opt/soc-lab/scripts/apply_phase4_wazuh_docker.sh
```

Fichiers utilises:
- config/wazuh/local_rules_phase4.xml
- automation/wazuh_to_thehive.py
- scripts/apply_phase4_wazuh_docker.sh

## 7) Verifier agents actifs

Dashboard Wazuh:# PHASE 4 - Wazuh (docker-compose officiel)

Objectif:
- UBUNTU-SRV2: deployer manager + indexer + dashboard Wazuh (docker-compose officiel).
- UBUNTU-SRV1: installer agent Linux vers manager.
- WIN-SRV-2019: installer agent Windows vers manager.
- Activer detection: scan ports, flood ICMP, brute force.
- Integrer Wazuh -> TheHive pour creer une alerte automatiquement.
- Validation: 2 agents Active + alerte ping visible.

## 1) UBUNTU-SRV2 - prerequis

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Reglage memoire indexer:

```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl -p /etc/sysctl.d/99-wazuh.conf
```

## 2) UBUNTU-SRV2 - deployer Wazuh officiel

```bash
cd /opt
sudo git clone https://github.com/wazuh/wazuh-docker.git
cd /opt/wazuh-docker/single-node
sudo docker compose -f generate-indexer-certs.yml run --rm generator
sudo docker compose up -d
sudo docker compose ps
```

Acces:
- Dashboard: https://IP_UBUNTU_SRV2
- API: https://IP_UBUNTU_SRV2:55000

## 3) UBUNTU-SRV1 - installer agent Linux

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="IP_UBUNTU_SRV2" WAZUH_AGENT_NAME="ubuntu-srv1" apt install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent --no-pager
```

## 4) WIN-SRV-2019 - installer agent Windows

PowerShell admin:

```powershell
$WAZUH_MANAGER="IP_UBUNTU_SRV2"
$WAZUH_AGENT_NAME="win-srv-2019"
$MSI_URL="https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
$MSI_PATH="$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri $MSI_URL -OutFile $MSI_PATH
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$MSI_PATH`" /qn WAZUH_MANAGER=$WAZUH_MANAGER WAZUH_AGENT_NAME=$WAZUH_AGENT_NAME"
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
Get-Service WazuhSvc
```

## 5) Integrer Wazuh -> TheHive (mode Docker manager)

Sur UBUNTU-SRV2, copie le projet sur /opt/soc-lab et prepare .env:

```bash
cd /opt/soc-lab
cp .env.example config/.env 2>/dev/null || true
nano config/.env
```

Variables minimales:
- THEHIVE_URL=http://IP_THEHIVE:9000
- THEHIVE_API_KEY=...

La dependance requests est installee automatiquement par le script d application ci-dessous.
Le bloc <integration> pour custom-wazuh-thehive est aussi ajoute automatiquement dans ossec.conf (si absent).

Si tu veux la faire manuellement (cas No module named pip), utilise:

```bash
docker exec -it single-node-wazuh.manager-1 sh -lc 'set -e; if ! python3 -m pip --version >/dev/null 2>&1; then if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip; elif command -v dnf >/dev/null 2>&1; then dnf install -y python3-pip; elif command -v yum >/dev/null 2>&1; then yum install -y python3-pip; elif command -v apk >/dev/null 2>&1; then apk add --no-cache py3-pip; else python3 -m ensurepip --upgrade; fi; fi; python3 -m pip install --no-cache-dir requests'
```

Appliquer integration + regles:

```bash
sudo PROJECT_DIR=/opt/soc-lab MANAGER_CONTAINER=single-node-wazuh.manager-1 bash /opt/soc-lab/scripts/apply_phase4_wazuh_docker.sh
```

Fichiers utilises:
- config/wazuh/local_rules_phase4.xml
- automation/wazuh_to_thehive.py
- scripts/apply_phase4_wazuh_docker.sh

## 6) Verifier agents actifs

Dashboard Wazuh:
- Ouvre Agents
- Verifie ubuntu-srv1 = Active
- Verifie win-srv-2019 = Active

CLI conteneur manager:

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## 7) Tests detection

Test ping simple (critere obligatoire):

```bash
ping -c 10 IP_UBUNTU_SRV1
```

Test scan ports depuis Kali:

```bash
nmap -sS -Pn IP_UBUNTU_SRV1
nmap -sS -Pn IP_WIN_SRV_2019
```

Test brute force SSH (lab uniquement):

```bash
hydra -l invaliduser -P /usr/share/wordlists/rockyou.txt ssh://IP_UBUNTU_SRV1 -t 4 -f
```

Test ICMP flood (quelques secondes en lab):

```bash
sudo hping3 --icmp --flood IP_UBUNTU_SRV1
```

## 8) Validation finale

- Les deux agents sont Active dans le dashboard.
- L alerte ping apparait dans Security Events.
- Une alerte critique est envoyee a TheHive.

## 9) Debug rapide

Logs manager:

```bash
docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/ossec.log
```

Verifier integration:

```bash
docker exec -it single-node-wazuh.manager-1 ls -l /var/ossec/integrations/
docker exec -it single-node-wazuh.manager-1 grep -n "custom-wazuh-thehive" /var/ossec/etc/ossec.conf
```

- Ouvre Agents
- Verifie ubuntu-srv1 = Active
- Verifie win-srv-2019 = Active

CLI conteneur manager:

```bash
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## 8) Tests detection

Test ping simple (critere obligatoire):

```bash
ping -c 10 IP_UBUNTU_SRV1
```

Test scan ports depuis Kali:

```bash
nmap -sS -Pn IP_UBUNTU_SRV1
nmap -sS -Pn IP_WIN_SRV_2019
```

Test brute force SSH (lab uniquement):

```bash
hydra -l invaliduser -P /usr/share/wordlists/rockyou.txt ssh://IP_UBUNTU_SRV1 -t 4 -f
```

Test ICMP flood (quelques secondes en lab):

```bash
sudo hping3 --icmp --flood IP_UBUNTU_SRV1
```

## 9) Validation finale

- Les deux agents sont Active dans le dashboard.
- L alerte ping apparait dans Security Events.
- Une alerte critique est envoyee a TheHive.

## 10) Debug rapide

Logs manager:

```bash
docker exec -it single-node-wazuh.manager-1 tail -f /var/ossec/logs/ossec.log
```

Verifier integration:

```bash
docker exec -it single-node-wazuh.manager-1 ls -l /var/ossec/integrations/
```
key misp : dVQep6lT5MYLJ2uS6kRfm3UuouB6rhXT1QKAsQlq

webhook url : http://192.168.99.15:3001/api/v1/hooks/webhook_0b1d9e5b-b152-4663-9408-4bf03701ff08


Use this token to access the HTTP API:
8546397742:AAHhJFafZtSzv4TeIYAnOAO4fxEOFJuyjDE


Wazuh
  ↓
TheHive
  ↓
Shuffle
  ↓
Cortex
  ├── VirusTotal
  ├── AbuseIPDB
  └── MISP
  ↓
TheHive + Telegram
  ↓
Validation analyste
  ↓
Blocage ou publication MISP


Automatique :
- enrichissement ;
- création du case ;
- ajout des observables ;
- classification ;
- notification ;
- changement de priorité.

Validation obligatoire :
- blocage d’une IP ;
- isolation d’un poste ;
- suppression d’un fichier ;
- désactivation d’un compte ;
- ajout d’un IoC dans MISP.



1. Wazuh détecte 12 blocages TCP.
2. TheHive reçoit l’alerte.
3. Shuffle récupère l’IP source.
4. Shuffle vérifie si l’IP est privée ou publique.
5. Cortex lance AbuseIPDB, VirusTotal et MISP si nécessaire.
6. Shuffle ajoute les résultats dans TheHive.
7. Shuffle classe l’incident :
   - Low
   - Medium
   - High
   - Critical
8. Telegram informe l’analyste.
9. L’analyste approuve ou refuse le blocage.




🚨 Alerte SOC

Règle Wazuh : 100401
Type : Scan TCP
IP source : 192.168.99.17
Machine ciblée : UBUNTU-SRV2
Gravité : High

Actions automatiques :
✅ Alerte TheHive créée
✅ Observable ajouté
✅ Analyse Cortex terminée

Décision demandée :
[ ] Bloquer l’IP
[ ] Enquêter
[ ] Faux positif




1	Webhook_TheHiveAlert	Recevoir uniquement les créations d’alertes
2	GetAlert	Récupérer l’alerte et son état actuel
3	Normaliser	Préparer les champs nécessaires au traitement
4	CheckCaseLinked — remplace AntiDoublon	Vérifier si cette alerte est déjà liée à un case
5	PromoteAlertToCase — remplace CreateCase	Créer le case depuis l’alerte
6	PrepareObservables — remplace AddObservables	Préparer les observables à analyser, sans recopier ceux déjà transférés
7	Cortex_Enrichissement	Analyser les observables
8	MISP_Lookup	Chercher du contexte de threat intelligence
9	Consolider	Regrouper les résultats
10	UpdateCase_Report	Ajouter la synthèse au case
11	CreateTask_Decision	Documenter la décision attendue de l’analyste
12	Notify_Telegram_Email	Informer l’analyste
13	Wait_Decision	Attendre une décision explicite
14	Containment_If_Approved	Exécuter uniquement les actions autorisées
15	AuditTrail	Enregistrer le résultat, y compris refus, expiration ou erreur

## 11) Anti-duplication TheHive/Shuffle (sourceRef stable)

Objectif:
- Eviter la creation de plusieurs cases pour la meme attaque logique.
- Garder une seule alerte/case si Wazuh envoie plusieurs events corrélés.

### 11.1 Appliquer la configuration

1) Mettre les variables de deduplication dans `config/.env`:

```bash
cat >> /opt/soc-lab/config/.env <<'EOF'
WAZUH_DEDUP_MODE=window
WAZUH_DEDUP_WINDOW_SECONDS=120
EOF
```

Modes disponibles:
- `window`: deduplication generale (ignore rule_id, recommande).
- `window_with_rule`: deduplication plus stricte (inclut rule_id).
- `alert_id`: ancien comportement (plus de doublons possibles).

2) Re-appliquer l integration dans le conteneur manager:

```bash
sudo PROJECT_DIR=/opt/soc-lab MANAGER_CONTAINER=single-node-wazuh.manager-1 ANALYSISD_DECODER_ORDER_SIZE=1024 \
bash /opt/soc-lab/scripts/apply_phase4_wazuh_docker.sh
```

3) Verifier que le script charge bien le `.env` dans le manager:

```bash
docker exec -it single-node-wazuh.manager-1 \
sh -lc 'grep -nE "WAZUH_DEDUP_MODE|WAZUH_DEDUP_WINDOW_SECONDS" /var/ossec/integrations/.env'
```

### 11.2 Vérifier que c est bien appliqué

1) Verifier que la logique sourceRef stable est bien dans le script deploye:

```bash
docker exec -it single-node-wazuh.manager-1 \
sh -lc 'grep -n "def build_source_ref" /var/ossec/integrations/custom-wazuh-thehive; grep -n "WAZUH_DEDUP_MODE" /var/ossec/integrations/custom-wazuh-thehive'
```

2) Lancer deux fois la meme attaque dans la fenetre de 120 secondes:

```bash
sudo hping3 -A -p 65001 -c 1 192.168.99.18
sleep 2
sudo hping3 -A -p 65001 -c 1 192.168.99.18
```

3) Observer les logs du manager:

```bash
docker exec -it single-node-wazuh.manager-1 \
tail -f /var/ossec/logs/ossec.log
```

Resultat attendu:
- 1ere alerte: creation OK dans TheHive (HTTP 200/201).
- 2eme alerte logique identique: duplicate (HTTP 409), pas de nouvelle case.

4) Confirmer dans TheHive:
- Une seule alerte/case pour cette attaque logique.
- Meme `sourceRef` pour les events similaires dans la meme fenetre.

### 11.3 Vérifier le workflow Shuffle

Pour ne pas recréer des cases en doublon:
- Trigger Shuffle recommande: "TheHive Alert Created".
- Eviter un trigger direct sur chaque event Wazuh brut.
- Si un trigger Wazuh est obligatoire, filtrer pour ignorer les retours duplicate (409).

### 11.4 Depannage: "Too many fields for JSON decoder"

Si cette erreur continue dans `ossec.log`, applique ce plan:

1) Confirmer que la valeur manager est valide:

```bash
docker exec -it single-node-wazuh.manager-1 \
sh -lc "grep -n '^analysisd.decoder_order_size=' /var/ossec/etc/local_internal_options.conf"
```

2) Important: le script d application sur manager ne modifie pas automatiquement la configuration des agents Linux.
  Il faut aussi corriger l agent qui envoie les logs.

3) Sur chaque agent Linux, verifier si journald est encore collecte:

```bash
grep -n "<log_format>journald</log_format>\|<location>journald</location>" /var/ossec/etc/ossec.conf
```

4) Si present, supprimer le bloc journald puis redemarrer l agent:

```bash
sudo perl -0777 -i -pe 's@\n\s*<localfile>\s*\n\s*<log_format>journald</log_format>\s*\n\s*<location>journald</location>\s*\n\s*</localfile>\s*\n@\n@sg' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

5) Verifier que l erreur n augmente plus:

```bash
docker exec -it single-node-wazuh.manager-1 \
sh -lc "grep -n 'Too many fields for JSON decoder' /var/ossec/logs/ossec.log | tail -n 20"
```

6) Si l erreur persiste encore, identifier rapidement l agent source:

```bash
docker exec -it single-node-wazuh.manager-1 \
sh -lc "grep -n -B4 -A2 'Too many fields for JSON decoder' /var/ossec/logs/ossec.log | tail -n 120"
```




{
  "query": [
    {
      "_name": "getCase",
      "idOrName": "$promotealerttocase.body._id"
    },
    {
      "_name": "observables"
    }
  ]
}



{
  "case_id": "$promotealerttocase.body._id",
  "alert_id": "$exec.objectId",
  "observables_from_alert": "$getobservables.body",
  "note": "préparer la liste sans recopier en double"
}



→ PromoteAlertToCase
→ GetAlertObservables            (depuis l’alerte)
→ Loop AlertObservables
→ Create Observable in Case      (copier chaque observable dans le case)
→ Wait 5-10s
→ GetObservables (Case)          (relire observables du case)
→ Loop CaseObservables
→ TheHive Run Analyzer
→ Wait 30s
→ GetObservables (Case)          (recheck reports)
$getalert.body._id




Améliorations prévues pour passer le workflow en mode production :

1) Branches d’erreur dédiées pour chaque appel API
   - Si status >= 400 : route vers Error_Notify + log erreur
   - Stopper la chaîne d’actions en cas d’échec critique

2) Condition stricte avant notification APPROVE
   - Envoyer "Approve_Notify" uniquement si create_containment_task.status == 201

3) Gestion du cas “no analyzer found”
   - Si GetAnalyzersByType.body est vide :
     -> créer une task TheHive "Manual review required"
     -> notifier l’analyste

4) Retry + Timeout sur Cortex/TheHive
   - Timeout explicite par appel
   - Retry automatique (2 à 3 tentatives) avec délai progressif

5) Déduplication des tâches
   - Vérifier si une task similaire existe déjà (caseId + observableId + type)
   - Ne pas recréer si déjà présente

6) Enrichissement de la task (opération SOC)
   - Ajouter priorité, assignee, dueDate, éventuel groupe
   - Respect des SLA de traitement

7) Journalisation / audit
   - Logger : caseId, observableId, analystDecision, timestamp, action lancée, résultat
   - Conserver la traçabilité pour revue et conformité

8) Playbook post-APPROVE (optionnel)
   - Si approuvé : blocage technique automatisé (Firewall/EDR/Wazuh) selon dataType
   - Sinon : maintien en traitement manuel



   B) Nœuds à créer (dans cet ordre)
GetAnalyzersByType
RunAnalyzerJob
InitLoop (Tools - Python ou Set variable)
WaitDynamic
GetJobResult
CheckResult (Tools - Python)
IncLoop (Tools - Python)
BuildSummary (ton parser)
SendTelegram
WaitDecision
Check_Existing_Task
Create Containment Task
Approve_Notify
Reject_Notify
Duplicate_Notify
Error_Notify
Timeout_Notify