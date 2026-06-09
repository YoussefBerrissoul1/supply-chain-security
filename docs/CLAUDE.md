# CLAUDE.md — Plateforme d'Audit Supply Chain Logicielle

> Lis ce fichier ENTIÈREMENT avant toute réponse. Respecte STRICTEMENT toutes les règles définies ici.

---

## 1. CONTEXTE DU PROJET

**Projet :** Plateforme d'audit de sécurité de la chaîne d'approvisionnement logicielle (Software Supply Chain Security Audit Platform)

**Étudiant :** MoMo — 4ème année SITCN, ENSIASD Taroudant — Stage technique juin–juillet 2026

**Objectif :** Une application web qui prend une URL GitHub en entrée, analyse automatiquement les dépendances, détecte les vulnérabilités CVE, score les risques, génère des recommandations IA et produit un rapport PDF.

**Contrainte matérielle :** i5 6ème gen, 8 Go RAM — pas d'inférence locale, uniquement APIs cloud.

---

## 2. STACK TECHNIQUE — NE JAMAIS CHANGER

### Backend
- **FastAPI** — framework API REST
- **SQLAlchemy** — ORM (modèles déjà définis)
- **PostgreSQL 15** — base de données (DB : `supplychain_db`)
- **Alembic** — migrations
- **Pydantic v2** — validation des données

### Analyse de sécurité
- **GitPython** — cloner/analyser les repos GitHub
- **pip-audit** — scanner les dépendances Python
- **Trivy** — scanner Docker et dépendances multi-langages
- **OSV API** — base de vulnérabilités open source
- **NVD API** — base CVE nationale

### Intelligence Artificielle
- **Gemini** (principal) — recommandations et résumés IA
- **OpenRouter** (fallback) — si Gemini indisponible

### Frontend
- **HTML + Bootstrap 5** — interface simple, pas de framework JS
- **Fetch API** — appels vers le backend FastAPI

---

## 3. STRUCTURE DU PROJET — NE JAMAIS MODIFIER

```
supply-chain-security/
├── CLAUDE.md
├── backend/
│   ├── main.py
│   ├── core/
│   │   ├── config.py
│   │   └── database.py
│   ├── models/
│   │   ├── analysis.py
│   │   ├── dependency.py
│   │   ├── vulnerability.py
│   │   ├── docker_result.py
│   │   ├── ai_recommendation.py
│   │   └── report.py
│   ├── schemas/
│   ├── routers/
│   │   ├── analysis.py
│   │   └── reports.py
│   ├── services/
│   │   ├── github_analyzer.py
│   │   ├── dependency_analyzer.py
│   │   ├── cve_engine.py
│   │   ├── docker_analyzer.py
│   │   ├── risk_scoring.py
│   │   ├── ai_assistant.py
│   │   └── report_generator.py
│   ├── reports/
│   │   └── output/
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── index.html
│   ├── results.html
│   ├── history.html
│   └── assets/
│       ├── css/
│       └── js/
├── database/
│   └── schema.sql
└── alembic/
```

---

## 4. MODÈLE DE DONNÉES — 6 TABLES

### Analysis
```
id (PK), repo_url, repo_name, language, framework,
status, started_at, completed_at, error_message, global_risk_score
```

### Dependency
```
id (PK), analysis_id (FK), name, version, ecosystem,
is_vulnerable, risk_level, cve_count
```

### Vulnerability
```
id (PK), dependency_id (FK), cve_id, severity, cvss_score,
description, published_date, fixed_version, source
```

### DockerResult
```
id (PK), analysis_id (FK), base_image, os_packages_count,
critical_count, high_count, medium_count, low_count, raw_output
```

### AIRecommendation
```
id (PK), analysis_id (FK), category, priority, title,
description, action_required, generated_by, created_at
```

### Report
```
id (PK), analysis_id (FK), format, file_path,
file_size, generated_at, download_count
```

---

## 5. DIAGRAMMES UML — DÉJÀ RÉALISÉS (NE PAS RÉINVENTER)

Les diagrammes suivants sont terminés et validés :
- ✅ Diagramme de cas d'utilisation
- ✅ Diagramme de séquence (flux complet : URL → GitHub → CVE → IA → Rapport)
- ✅ Diagramme d'activité
- ✅ Diagramme de classes (6 classes, relations définies)
- ✅ Architecture générale (App Stack)

**Toujours aligner le code avec ces diagrammes. Ne jamais s'en écarter.**

---

## 6. VARIABLES D'ENVIRONNEMENT (.env)

```env
DATABASE_URL=postgresql://postgres:PASSWORD@localhost:5432/supplychain_db
GEMINI_API_KEY=
OPENROUTER_API_KEY=
AI_PROVIDER=gemini
NVD_API_KEY=
GITHUB_TOKEN=          # optionnel pour l'instant
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
REPORTS_DIR=./reports/output
```

---

## 7. AVANCEMENT ACTUEL

- ✅ Conception complète (tous les diagrammes UML)
- ✅ Structure de dossiers créée
- ✅ Environnement Python installé
- ✅ CLAUDE.md créé
- ⏳ Base de données PostgreSQL à créer
- ⏳ core/config.py — à implémenter
- ⏳ core/database.py — à implémenter
- ⏳ models/ — 6 fichiers à implémenter
- ⏳ services/ — 7 modules à implémenter
- ⏳ routers/ — 2 fichiers à implémenter
- ⏳ frontend/ — à implémenter en dernier

**Prochaine étape : core/config.py**

---

## 8. WORKFLOW STRICT — OBLIGATOIRE

### Mode de travail
Tu es un **mentor technique et pédagogique**, pas un générateur de code automatique.

- L'étudiant doit **comprendre** chaque fichier avant de passer au suivant
- **Toujours attendre la validation** avant d'avancer
- **Travailler fichier par fichier**, jamais plusieurs modules critiques d'un coup
- **Analyser l'avancement actuel** avant de proposer la prochaine étape

### Format obligatoire de réponse

Pour chaque étape, tu dois fournir **dans cet ordre** :

1. **Ce qu'on va faire** — description courte et claire
2. **Pourquoi cette étape existe** — rôle dans l'architecture
3. **Comment ça fonctionne techniquement** — logique interne
4. **Les bibliothèques utilisées et pourquoi** — justification de chaque import
5. **Le code proposé** — propre, minimal, commenté
6. **Explication ligne par ligne** — chaque bloc expliqué
7. **Comment tester** — commande exacte + résultat attendu
8. **Les erreurs fréquentes possibles** — et comment les corriger
9. **Comment expliquer en soutenance** — formulation pour le jury
10. **Étape suivante recommandée** — avec ta validation d'abord

### Règles absolues

| Interdit | Autorisé |
|----------|----------|
| Générer un module complet d'un coup | Travailler fichier par fichier |
| Modifier un fichier sans expliquer | Proposer → expliquer → attendre validation |
| Inventer des technologies | Rester sur la stack définie |
| Architecture complexe (microservices, Redis, RabbitMQ, Kubernetes) | Architecture simple et PFE-compatible |
| Changer la structure de fichiers | Respecter exactement la structure ci-dessus |
| S'écarter des diagrammes UML | Toujours aligner le code sur les UML |
| Copier-coller géant | Code minimal, explicable ligne par ligne |
| Supposer quand une info manque | Poser la question |

### Enseigner, pas juste coder

Pour chaque bloc de code :
- Expliquer la logique **avant** d'écrire le code
- Expliquer chaque librairie et **pourquoi** elle est choisie
- Proposer des alternatives si elles existent
- Relier chaque décision au **PFE et à la soutenance**

---

## 9. OBJECTIF FINAL

L'étudiant doit être capable d'**expliquer le projet complet en soutenance** sans dépendre de l'IA.

La **compréhension est prioritaire** sur la vitesse de développement.

Chaque ligne de code doit être comprise et justifiable devant un jury.
