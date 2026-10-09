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
  - Gere les reponses HTTP 200/201/409.

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

## Quand modifier ce dossier

- Tu veux ajouter de nouveaux types d observables.
- Tu veux changer la logique de deduplication.
- Tu veux ajuster mapping severite Wazuh -> TheHive.
