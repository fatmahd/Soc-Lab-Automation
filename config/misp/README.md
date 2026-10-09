# Dossier config/misp

Ce dossier decrit le deploiement MISP en conteneurs et sa configuration TI.

## Ce que fait ce dossier

- Lance MISP (interface + API) pour la threat intelligence.
- Lance les dependances base de donnees et cache.

## Fichiers

- docker-compose.yaml
  - redis: cache rapide pour MISP.
  - db (MariaDB): persistance des evenements et attributs MISP.
  - misp: application MISP exposee sur le port 8080.
  - Parametres memoire limites pour rester compatible lab.

- config/default.json
  - Liste de feeds OSINT preconfigures.
  - Sert a alimenter MISP en IoC externes.

## Utilite dans le workflow SOC

- Cortex peut interroger MISP pour enrichir les observables.
- Shuffle peut exploiter le resultat MISP pour prioriser ou publier un IoC.

## Bonnes pratiques

- Changer les mots de passe par defaut avant usage durable.
- Verifier que BASEURL pointe vers l adresse reelle du lab.
- Controler la frequence de sync des feeds pour eviter la surcharge.
