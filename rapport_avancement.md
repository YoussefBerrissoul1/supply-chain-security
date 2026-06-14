# Rapport d'Avancement — Supply Chain Security Platform
## PFE Cybersécurité — Étudiant : Youssef BERRISSOUL

Ce document présente une vue d'ensemble complète du projet, détaille l'état d'avancement actuel, valide le fonctionnement réel des scanners via les derniers tests, et liste de manière structurée les étapes restantes avant la finalisation du projet et la préparation de la soutenance.

---

## 1. Description du Projet et Stack Technique

### Objectif
La plateforme a pour but d'analyser automatiquement la sécurité d'un dépôt GitHub public. Elle réalise un audit de la chaîne d'approvisionnement logicielle (Software Supply Chain) à travers plusieurs étapes :
1. **Clonage superficiel** sécurisé du dépôt cible.
2. **Détection et analyse** des fichiers de dépendances (Python, Node.js, Java, Docker...).
3. **Interrogation des bases de vulnérabilités** mondiales (OSV API et NVD API) pour identifier les failles (CVE).
4. **Scan Trivy** de l'image Docker de base pour trouver les failles au niveau de l'OS.
5. **Calcul d'un score de sécurité tridimensionnel** (Sévérité × Exploitabilité × Impact).
6. **Génération de recommandations personnalisées** via l'IA (Gemini / OpenRouter) ou un système expert de secours.
7. **Production d'un rapport de synthèse PDF** professionnel pour l'utilisateur.

### Stack Technique (Backend Core)
* **Langage & Framework** : Python 3.12, FastAPI (API asynchrone ultra-rapide)
* **Base de données & ORM** : PostgreSQL, SQLAlchemy (modélisation relationnelle), Alembic (migrations)
* **APIs de Sécurité** : OSV API (prioritaire), NVD API (complément d'enrichissement), Trivy (scan d'images Docker)
* **Intelligence Artificielle** : Google Gemini API (`gemini-2.5-flash`), OpenRouter API (fallback)
* **Génération PDF** : ReportLab

---

## 2. État de l'Avancement et Étapes Complétées

Toutes les étapes fondamentales du backend ont été implémentées, commentées et validées.

| Étape | Statut | Composant / Service | Description |
| :---: | :---: | :--- | :--- |
| **1** |  ✅  | Structure du projet | Création de l'arborescence standardisée (app, core, models, routes, services...). |
| **2** |  ✅  | Base de données PostgreSQL | Création de la base locale `supply_chain_security`. |
| **3** |  ✅  | Configuration (`core/config.py`) | Gestion des variables d'environnement via Pydantic BaseSettings (lecture sécurisée du `.env`). |
| **4** |  ✅  | Moteur DB (`core/database.py`) | Configuration du SessionLocal et de la fabrique de connexions SQLAlchemy. |
| **5** |  ✅  | Modèles SQLAlchemy (`models/`) | Création des 6 tables relationnelles (`Analysis`, `Dependency`, `Vulnerability`, `DockerResult`, `Recommendation`, `Report`). |
| **6** |  ✅  | Migrations Alembic | Initialisation et application des versions de base de données (dernière migration : `4ccae846cc8f`). |
| **7** |  ✅  | Schémas Pydantic (`schemas/`) | Définition des schémas de requêtes et de réponses pour la validation automatique (ex: `AnalysisDetailResponse`). |
| **8** |  ✅  | Routes API de base (`routes/`) | Implémentation des endpoints CRUD d'historique et de consultation. |
| **9** |  ✅  | GitHub Analyzer (`github_analyzer.py`) | Clonage Git avec timeout de 120s et gestion robuste du nettoyage sur Windows (fichiers `.git` read-only). |
| **10** |  ✅  | Dependency Scanner (`dependency_scanner.py`) | Parseurs intelligents pour `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml`, et `Dockerfile`. |
| **11** |  ✅  | CVE Service (`cve_service.py`) | Interrogation OSV (rapide/gratuite) et enrichissement NVD optionnel (avec gestion stricte du rate-limit). |
| **12** |  ✅  | Docker Scanner (`docker_scanner.py`) | Analyse statique du Dockerfile (root user, secrets) et intégration de la commande `trivy image`. |
| **13** |  ✅  | Score Service (`score_service.py`) | Moteur de calcul tridimensionnel du score /100 avec pénalités progressives et plafonnements. |
| **14** |  ✅  | AI Service (`ai_service.py`) | Générateur de recommandations IA structurées (Gemini) avec fallback sur système expert statique local. |

---

## 3. Validation Réelle des Scanners (Test Réussi)

Un test d'intégration complet a été réalisé sur le dépôt réel **`Nestle-Shop-Full-App-E-Commerce`** en mode **Standard**. Les résultats valident la viabilité technique du projet :

1. **Clonage réussi** en local dans `temp_repositories/Nestle-Shop-Full-App-E-Commerce`.
2. **Détection des fichiers** : identification immédiate de Node.js (`package.json`, `package-lock.json`) et PHP (`composer.json`, `composer.lock`).
3. **Extraction des dépendances** : 7 dépendances Node.js de développement extraites avec succès.
4. **Scan CVE OSV** : **42 vulnérabilités réelles** trouvées (26 sur `axios@1.1.2`, 16 sur `vite@4.0.0`), incluant des failles de Prototype Pollution à haute sévérité.
5. **Calcul de score** : Score final calculé de **`0.0 / 100`** (risque **`CRITIQUE`**), justifié par la sévérité des failles trouvées.
6. **Nettoyage automatique** : Le répertoire cloné a été entièrement effacé après le scan pour économiser l'espace disque.

---

## 4. Étape Actuelle et Plan de Travail Restant

Vous êtes actuellement au début de la **Phase 4 (Services finaux et Asynchronisme)**.

### Étape 15 : Implémentation du service de reporting PDF (Étape Actuelle)
* **Fichier à créer** : `backend/app/services/report_service.py`
* **Objectif** : Générer une fiche d'évaluation de sécurité PDF professionnelle à l'aide de ReportLab, contenant le récapitulatif du dépôt, le score de sécurité coloré, le tableau des vulnérabilités critiques et les recommandations.
* **Intégration** : L'endpoint `GET /api/v1/analyses/{id}/report` devra retourner le fichier PDF réel sous forme de `FileResponse`.

### Étape 16 : Intégration des tâches asynchrones (BackgroundTasks)
* **Fichier à modifier** : `backend/app/routes/analysis_routes.py`
* **Objectif** : Connecter la route `POST /api/v1/analyze` pour qu'elle lance la chaîne complète d'analyse (Clonage → Dépendances → Trivy → CVE → Score → IA → PDF) en tâche de fond. 
* **Comportement** : L'utilisateur reçoit instantanément une réponse avec le statut `pending` (ce qui évite les timeouts HTTP du navigateur), et le statut évolue en base de données (`running` -> `done`/`failed`).

### Étape 17 : Développement du Frontend React
* **Objectif** : Initialisation d'une application React + Vite + TailwindCSS simple et moderne.
* **Écrans** : Formulaire de soumission de dépôt, Dashboard de suivi (historique des 10 dernières analyses), et Vue détaillée d'un scan (graphiques de sévérité des failles, score global dynamique et recommandations de sécurité).

### Étape 18 : Tests finaux et Déploiement/Validation
* Validation de tous les chemins d'exécution (avec Docker, sans Docker, avec clé IA, sans clé IA).

### Étape 19 : Documentation finale (README)
* Rédaction d'un README professionnel détaillé avec captures d'écran et guides d'installation rapides pour le jury de PFE.

---

## 5. Mesures de Sécurité pour la Publication GitHub (Important)

Puisque votre dépôt GitHub va être publié (et qu'il n'est pas privé), il est impératif de protéger vos identifiants PostgreSQL locaux (votre mot de passe réel `"momo12"`).

### Actions à mener :
1. **Modifier le fallback par défaut dans le code** :
   Dans le fichier `backend/app/core/config.py`, nous devons remplacer la ligne :
   `DB_PASSWORD: str = "momo12"` par `DB_PASSWORD: str = "postgres"` ou `""`.
2. **Utiliser le fichier `.env` pour la configuration locale** :
   Votre fichier `.env` actuel contient la ligne : `DB_PASSWORD=momo12`. C'est grâce à cela que votre base de données locale fonctionnera toujours chez vous.
3. **Vérifier le fichier `.gitignore`** :
   Le fichier `.gitignore` contient bien la règle `.env`. Ce fichier ne sera donc jamais poussé en ligne, ce qui protège votre mot de passe et vos clés d'API futures.
