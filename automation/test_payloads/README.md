# Dossier automation/test_payloads

Ce dossier sert a valider localement la qualite d extraction des observables sans toucher a TheHive.

## Ce que fait ce dossier

- Fournit des exemples d alertes Wazuh realistes (Linux et Windows).
- Permet de tester la fonction collect_artifacts en mode offline.
- Evite de debrayer toute la chaine SOC pour un simple test parsing.

## Fichiers

- linux_ufw_alert.json
	- Cas Linux firewall/UFW.
	- Verifie extraction ip, url, domain, user-agent, mail et autres champs utiles.

- sysmon_network_alert.json
	- Cas Windows Sysmon reseau.
	- Verifie extraction destination ip/url/domain.
	- Verifie split des hash concatenees (SHA256/MD5/SHA1).

- dns_query_alert.json
	- Cas DNS.
	- Verifie extraction domain/url/hash/mail depuis champs structures et full_log.

- run_collect_artifacts_samples.py
	- Execute les tests sur tous les JSON du dossier.
	- Affiche les observables trouves, tries par type et valeur.

## Execution

Depuis la racine du projet:

python automation/test_payloads/run_collect_artifacts_samples.py

## Sortie attendue

- Nombre d observables extraits par echantillon.
- Liste detaillee par dataType (ip, domain, url, hash, filename, etc.).
- Aucune creation d alerte TheHive.

## Utilite operationnelle

Ce dossier est essentiel pour:
- valider une modification du parser avant mise en prod,
- detecter rapidement une regression,
- montrer a un nouveau membre comment la normalisation d observables fonctionne.

## Etapes et commandes

Depuis la racine du projet:

```bash
python automation/test_payloads/run_collect_artifacts_samples.py
```

Tester seulement un echantillon (Linux):

```bash
python automation/wazuh_to_thehive.py automation/test_payloads/linux_ufw_alert.json
```

Tester un autre echantillon (Windows Sysmon):

```bash
python automation/wazuh_to_thehive.py automation/test_payloads/sysmon_network_alert.json
```

