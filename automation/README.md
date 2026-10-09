# Dossier automation

Ce dossier contient la logique d integration entre Wazuh et TheHive, ainsi que des outils de test local.

## Ce que fait ce dossier

- Transforme une alerte Wazuh en alerte TheHive exploitable.
- Extrait automatiquement des observables (ip, domain, url, hash, filename, mail, other).
- Gere la deduplication pour eviter les doublons TheHive.

## Fichiers principaux

- wazuh_to_thehive.py
  - Script d integration execute par Wazuh manager.
  - Lit le payload alerte (fichier ou stdin).
  - Construit le titre, la description, la severite et les tags.
  - Calcule sourceRef (dedup) puis envoie vers API TheHive.
  - Gere les reponses HTTP 200/201/409 et le retour 400 CreateError de doublon TheHive.

- test_payloads/
  - Echantillons JSON et script de test local pour valider l extraction d observables sans envoi TheHive.

## Variables d environnement importantes

Chargees depuis config/.env (copiee dans /var/ossec/integrations/.env cote manager):
- THEHIVE_URL
- THEHIVE_API_KEY
- WAZUH_DEDUP_MODE
- WAZUH_DEDUP_WINDOW_SECONDS
- WAZUH_DEDUP_SCOPE
- WAZUH_DEDUP_DEBUG

## Deduplication et conservation des preuves

En modes window (defaut) et strict, la sourceRef inclut une empreinte JSON
canonique du contenu de l'alerte, hors champs racine id et timestamp.
Les IP, le processus, les hashes, le log et les autres champs du payload
participent donc a la distinction des preuves. En mode window, la fenetre
temporelle reste prise en compte. Le mode alert_id conserve son comportement.

- Une copie exacte dans la meme fenetre ne cree pas de nouvelle alerte.
- Un contenu different cree une nouvelle alerte avec ses propres observables.
- Le script ne fusionne pas les alertes et ne les rattache pas automatiquement
  au meme case : cette correlation doit etre geree dans TheHive/Shuffle.
- Des changements de metadonnees du payload peuvent aussi creer une alerte.
- Les anciennes alertes gardent leur sourceRef. Le premier rejeu d'une ancienne
  alerte apres migration peut creer une alerte supplementaire. Pour valider,
  utiliser un nouveau nom d'agent de test, puis rejouer chaque payload.

Tests de regression sans reseau ni creation d'alertes TheHive :

```bash
python automation/test_payloads/test_deduplication.py -v
```

Cette validation ne teste pas les timeouts Cortex ni les workflows Shuffle.

## Quand modifier ce dossier

- Tu veux ajouter de nouveaux types d observables.
- Tu veux changer la logique de deduplication.
- Tu veux ajuster mapping severite Wazuh -> TheHive.

## Etapes et commandes

1. Tester le parser localement (sans creation d alerte TheHive):

```bash
python automation/test_payloads/run_collect_artifacts_samples.py
```

2. Tester l integration sur un payload unique (si THEHIVE_URL et THEHIVE_API_KEY sont configures):

```bash
python automation/wazuh_to_thehive.py automation/test_payloads/linux_ufw_alert.json
```

3. Appliquer la version script cote manager Docker Wazuh:

```bash
sudo PROJECT_DIR="$(pwd)" MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
```
