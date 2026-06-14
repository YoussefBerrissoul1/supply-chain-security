# Récapitulatif du Projet — Audit de la Chaîne d'Approvisionnement Logicielle

Ce document résume les travaux que nous avons réalisés ensemble et l'état actuel d'avancement du projet (Phase 3 Backend Core terminée).

---

## 1. Ce qui a été implémenté

### A. Base de Données PostgreSQL & Migrations Alembic
- **Évolution du Modèle de Données** :
  - `Dependency` : ajout du champ `is_dev` pour faire la distinction entre dépendances de production et dépendances de développement (ex: `devDependencies` de `package.json`).
  - `Vulnerability` : ajout de `fixed_version` (version corrective), `exploit_available` (booléen si exploit public connu) et `published_date` (date de publication de la faille).
  - `Analysis` : ajout de `scan_type` pour savoir si l'analyse a été lancée en mode `standard` ou `deep`.
- **Migrations Alembic** :
  - Migration `0596080c4faf` : création des nouveaux champs pour la matrice de risques.
  - Migration `4ccae846cc8f` : ajout de la colonne `scan_type`.
  - Toutes les migrations ont été appliquées avec succès sur votre base PostgreSQL locale `supply_chain_security`.

### B. Algorithme de Scoring Tridimensionnel (`Risque = Sévérité × Exploitabilité × Impact`)
- **Sévérité (Base)** : CVSS score catégorisé en pénalités (CRITICAL = -15 pts, HIGH = -8 pts, MEDIUM = -3 pts).
- **Exploitabilité (Multiplicateurs)** :
  - Exploit public connu : `×1.5`
  - Faille récente (< 6 mois) : `×1.3`
  - Faille ancienne sans correctif (> 2 ans) : `×1.2`
  - Correctif disponible ignoré : `×1.4`
- **Impact (Multiplicateurs)** :
  - Dépendance de production/directe : `×1.3`
  - Dépendance de test/développement (`is_dev=True`) : `×0.5`
- **Docker** : Pénalités progressives pour les failles Docker issues de Trivy (≤ 5 failles : -10 pts, ≤ 15 failles : -15 pts, > 15 failles : -20 pts).

### C. Double Mode de Scan (Standard vs Deep)
- **Mode Standard (Rapide)** : Interroge uniquement l'API OSV (très rapide). Extrait les indicateurs d'exploitabilité via des filtres intelligents. **Bypass l'API NVD** pour éviter les limitations de vitesse (scan en moins de 20s).
- **Mode Deep (Complet)** : Interroge OSV, puis interroge l'API NVD pour chaque CVE sans score pour obtenir le score CVSS exact (au prix d'une latence d'environ 6s par CVE si aucune clé NVD n'est configurée).

### D. Service IA & Recommandations (`ai_service.py`)
- Intégration de l'API Gemini (`gemini-2.5-flash`) et OpenRouter.
- Système de secours statique (**fallback**) automatique : si aucune clé d'IA n'est fournie ou s'il y a un problème de connexion, un système expert génère des recommandations précises basées sur des règles statiques et les persiste en base de données.

---

## 2. Étape actuelle du projet

Nous avons terminé avec succès la **PHASE 3 (Backend Core)**. L'ensemble des briques de calcul, de scan, de base de données et d'intelligence artificielle fonctionnent en local et sont validées.

### Prochaines étapes suggérées :
1. **Implémentation du service de rapports PDF** (`report_service.py`) en utilisant ReportLab pour générer la synthèse téléchargeable.
2. **Intégration du scan en tâche de fond (Background Tasks)** dans les routes FastAPI pour que l'appel `POST /analyze` lance le scan de manière asynchrone sans bloquer la requête HTTP.
3. **Création du Frontend React** pour se brancher sur l'API FastAPI et afficher les dashboards.
