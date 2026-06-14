# Suivi du Projet — Avancement, Étapes Suivantes et Écarts CLAUDE.md

Ce document décrit en détail l'avancement du projet depuis l'étape 0 jusqu'à aujourd'hui, les étapes suivantes à réaliser (sans exception) et les modifications avancées que nous avons intégrées par rapport au cahier des charges initial décrit dans le fichier `CLAUDE.md`.

---

## 1. État de l'Avancement (De l'étape 0 à aujourd'hui)

Voici le suivi exact des phases recommandées de développement (les étapes 1 à 14 sont complétées et validées) :

* [x] **Étape 1 :** Structure du projet créée.
* [x] **Étape 2 :** Création de la base PostgreSQL local (`supply_chain_security`).
* [x] **Étape 3 :** Implémentation de `core/config.py` (lecture du fichier `.env`).
* [x] **Étape 4 :** Implémentation de `core/database.py` (moteur SQLAlchemy et gestion des sessions).
* [x] **Étape 5 :** Création de tous les modèles de base SQLAlchemy (modèles de base `models/`).
* [x] **Étape 6 :** Configuration d'Alembic et application des premières migrations.
* [x] **Étape 7 :** Création des schémas Pydantic (`schemas/`) pour la validation automatique des requêtes.
* [x] **Étape 8 :** Création des routes FastAPI de base (`routes/`).
* [x] **Étape 9 :** Implémentation de `github_analyzer.py` (clonage superficiel Git et détection des fichiers).
* [x] **Étape 10 :** Implémentation de `dependency_scanner.py` (parsing et extraction des paquets).
* [x] **Étape 11 :** Implémentation de `cve_service.py` (détection des vulnérabilités via OSV et NVD).
* [x] **Étape 12 :** Implémentation de `docker_scanner.py` (scan Trivy et détection utilisateur root).
* [x] **Étape 13 :** Implémentation de `score_service.py` (moteur de calcul de score de sécurité).
* [x] **Étape 14 :** Implémentation de `ai_service.py` (générateur de recommandations de sécurité avec fallback).

---

## 2. Étapes Suivantes (Sans exception)

Voici les tâches restantes à accomplir pour finaliser le projet conformément à la stack :

* [ ] **Étape 15 : Implémenter le service de reporting (`report_service.py`)** :
  - Génération d'un fichier PDF professionnel avec ReportLab résumant le score, la matrice 3D et les recommandations.
  - Endpoint de téléchargement de rapport dans FastAPI (`GET /api/v1/analyses/{id}/report`).
* [ ] **Étape 16 : Intégrer les tâches asynchrones dans les routes** :
  - Connecter l'API `POST /analyze` pour qu'elle lance la chaîne d'analyse (Clonage → Scan → Score → IA → PDF) en arrière-plan à l'aide de `BackgroundTasks` de FastAPI (évite les timeouts HTTP).
* [ ] **Étape 17 : Développer le Frontend React** :
  - Initialiser l'application React + Vite + TailwindCSS.
  - Créer l'interface de soumission de dépôt, le dashboard des scores et l'affichage des graphiques de sévérité.
* [ ] **Étape 18 : Validation finale & Documentation** :
  - Rédaction du README final, captures d'écrans du dashboard, et préparation du support de présentation pour la soutenance de PFE.

---

## 3. Écarts et Améliorations par rapport à `CLAUDE.md`

Pour valoriser votre travail devant le jury de PFE, nous avons ajouté plusieurs fonctionnalités complexes de cybersécurité qui **n'existaient pas** dans les exigences initiales de `CLAUDE.md`.

Voici la liste de ces innovations :

### A. Matrice de Cotation des Risques 3D (Écart de calcul de score)
- *Ce que disait CLAUDE.md* : Le score appliquait une soustraction basique fixe pour chaque CVE (ex: -15 pour Critique, -8 pour High) peu importe le type de dépendance.
- *Ce qui a été implémenté* : Le score utilise un calcul tridimensionnel standardisé :
  $$\text{Pénalité\_CVE} = \text{Pénalité\_Base (Sévérité)} \times \text{Multiplicateur\_Exploitabilité} \times \text{Multiplicateur\_Impact}$$
  - **Sévérité (CVSS)** : Critique (15.0), Majeure (8.0), Moyenne (3.0).
  - **Exploitabilité** : Ajustée selon l'existence d'un exploit public connu ($\times 1.5$), la date récente de publication ($\times 1.3$) ou une faille ancienne non patchée ($\times 1.2$).
  - **Impact** : Réduit de moitié ($\times 0.5$) pour les outils de développement (devDependencies) et augmenté ($\times 1.3$) pour les dépendances de production.

### B. Extensions du Schéma de Base de Données (Écart SQL)
Pour pouvoir stocker et restituer cette matrice de cotation 3D sur l'interface utilisateur, nous avons étendu les tables SQL par rapport aux spécifications originelles :
- **Table `dependencies`** : Ajout de la colonne `is_dev` (booléen) pour marquer les paquets de dev.
- **Table `vulnerabilities`** : Ajout de `fixed_version` (correction), `exploit_available` (disponibilité d'exploit) et `published_date` (date de publication).
- **Table `analyses`** : Ajout de `scan_type` (standard ou deep).

### C. Double Mode de Scan : Standard vs Deep (Écart de flux)
- *Ce que disait CLAUDE.md* : Interrogeait OSV puis NVD systématiquement pour chaque dépendance.
- *Ce qui a été implémenté* : Un interrupteur de performance indispensable pour contourner le ralentissement de la NVD API :
  - **Standard** : Analyse instantanée (< 20 secondes) via OSV uniquement.
  - **Deep** : Analyse exhaustive qui interroge la NVD pour les scores non répertoriés sur OSV.
