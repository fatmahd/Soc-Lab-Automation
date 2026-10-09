# Next-Gen AI-Driven SOC

Ce projet implemente un lab SOC oriente detection, triage et orchestration.

Objectif global:
- Detecter des attaques Linux et Windows avec Wazuh.
- Creer automatiquement des alertes TheHive.
- Enrichir les observables via Cortex et MISP.
- Piloter les actions analyste via Shuffle.

Architecture fonctionnelle:
1. Wazuh collecte et corrige les evenements.
2. Regles custom PHASE4 detectent scans, brute force, flood, comportements Sysmon.
3. Integration Python pousse les alertes vers TheHive avec sourceRef stable (anti-duplication).
4. Shuffle orchestre l enrichissement et la decision analyste.
5. Cortex lance les analyzers (AbuseIPDB, VirusTotal, MISP, etc.).

## Lecture rapide pour un nouveau membre

1. Lire d abord docs/README.md puis docs/PHASE4_WAZUH_DOCKER.md.
2. Lire config/README.md pour comprendre les stacks et regles.
3. Lire automation/README.md pour comprendre la logique Wazuh -> TheHive.
4. Lire scripts/README.md pour deploiement et tests.

## Arborescence principale

- automation/: code d integration et tests locaux d extraction d observables.
- config/: toutes les configurations Wazuh, Cortex, MISP, Shuffle et variables d environnement.
- docs/: runbooks, guides de test et mode operatoire.
- scripts/: scripts de deploiement et de validation.

## Resultat attendu du projet

Quand tout est en place:
- Une attaque detectee cote Linux/Windows remonte dans Wazuh.
- Une alerte est creee dans TheHive avec observables exploitables.
- Les enrichissements donnent du contexte de priorisation.
- L analyste valide les actions de containment avec tracabilite.
