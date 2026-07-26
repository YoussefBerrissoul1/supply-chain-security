# Supply Chain Security — Backend

> Plateforme d'audit automatique de la chaîne d'approvisionnement logicielle.
> Détecte les vulnérabilités CVE dans les dépendances et les images Docker,
> calcule un Security Score déterministe et génère des recommandations IA.

---

## Table des matières

1. [Architecture](#architecture)
2. [Stack technique](#stack-technique)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Démarrage](#démarrage)
6. [API Endpoints](#api-endpoints)
7. [Security Score](#security-score)
8. [Providers de vulnérabilités](#providers-de-vulnérabilités)
9. [Service IA](#service-ia)
10. [Tests](#tests)
11. [Structure du projet](#structure-du-projet)

---

## Architecture

```
GitHub URL / Image Docker
        │
        ▼
 github_analyzer.py         ← Clone le dépôt, détecte les fichiers
        │
        ▼
 dependency_scanner.py      ← Parse requirements.txt, package.json, pom.xml…
        │
        ▼
 cve_service.py             ← Orchestrateur multi-sources
   ├── OSV  querybatch      ← 1 requête HTTP pour N dépendances
   ├── GHSA (optionnel)     ← Enrichissement via GitHub Token
   ├── NVD  (enrichissement)← CVSS, CWE, description
   └── EPSS (mode deep)     ← Probabilité d'exploitation (FIRST.org)
        │
        ▼
 correlation_engine.py      ← Déduplique, fusionne, priorise les sources
        │
        ▼
 docker_scanner.py          ← Analyse Dockerfile + Trivy (OS + libraries)
        │
        ▼
 score_service.py           ← Security Score /100 (déterministe)
        │
        ▼
 ai_service.py              ← Recommandations IA (Gemini → NVIDIA → OpenRouter → Static)
        │
        ▼
 report_service.py          ← Rapport PDF (ReportLab)
        │
        ▼
 PostgreSQL                 ← Persistance (SQLAlchemy + Alembic)
```

---

## Stack technique

| Composant | Technologie |
|---|---|
| Framework | FastAPI + Uvicorn |
| ORM | SQLAlchemy 2.0 |
| Base de données | PostgreSQL |
| Migrations | Alembic |
| Validation | Pydantic v2 |
| Clone Git | GitPython |
| Scanner Docker | Trivy |
| Génération PDF | ReportLab |
| IA principale | Google Gemini 2.5 Flash |
| IA fallback 1 | NVIDIA NIM / Kimi K2.6 |
| IA fallback 2 | OpenRouter |
| Tests | pytest |

---

## Installation

### Prérequis

- Python 3.12+
- PostgreSQL 15+
- [Trivy](https://trivy.dev/docs/getting-started/installation/) (installé et dans le PATH)
- Git

### 1. Environnement virtuel

```bash
cd backend/
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

### 2. Base de données

```sql
CREATE DATABASE supply_chain_security;
```

### 3. Configuration

```bash
cp .env.example .env
# Éditer .env avec vos valeurs (voir section Configuration)
```

### 4. Migrations Alembic

```bash
alembic upgrade head
```

---

## Configuration

Toutes les variables sont dans `.env` (jamais dans Git) :

```env
# Base de données PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=supply_chain_security
DB_USER=postgres
DB_PASSWORD=votre_mot_de_passe

# IA — Gemini (principal)
GEMINI_API_KEY=AIzaSy_VOTRE_CLE

# IA — NVIDIA NIM / Kimi K2.6 (fallback intermédiaire)
# Format : nvapi-xxxxxxxxxxxxxxxxxxxx
NVIDIA_API_KEY=nvapi-VOTRE_CLE

# IA — OpenRouter (fallback final LLM)
OPENROUTER_API_KEY=sk-or-VOTRE_CLE

# NVD API (optionnel — améliore le taux de requêtes)
NVD_API_KEY=VOTRE_UUID_NVD

# GitHub Token (optionnel — évite les rate limits)
GITHUB_TOKEN=ghp_VOTRE_TOKEN
```

> **Sécurité** : Les clés API ne sont jamais retournées par l'API,
> jamais affichées dans les logs, jamais envoyées au frontend.

---

## Démarrage

```bash
cd backend/
venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Documentation interactive : [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API Endpoints

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Santé de l'API |
| `POST` | `/api/v1/analyze` | Lancer une analyse |
| `GET` | `/api/v1/analyses` | Historique (10 dernières) |
| `GET` | `/api/v1/analyses/{id}` | Détail complet d'une analyse |
| `GET` | `/api/v1/analyses/{id}/report` | Télécharger le rapport PDF |

### Exemple — Lancer une analyse GitHub

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/user/repo",
    "scan_type": "standard",
    "target_type": "github"
  }'
```

### Exemple — Scanner une image Docker

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "python:3.10",
    "scan_type": "deep",
    "target_type": "docker"
  }'
```

### Validation des entrées (SEC3)

- `target_type=github` : URL doit matcher `https://github.com/{owner}/{repo}`
- `target_type=docker` : Nom d'image valide, pas de `://`, pas de `..`
- `scan_type` : uniquement `"standard"` ou `"deep"`

---

## Security Score

Le score est **100% déterministe** — l'IA ne l'influence jamais.

### Matrice 3D : Sévérité × Exploitabilité × Impact

```
Pénalité finale = Base × Exploit_mult × Impact_mult
```

| Sévérité | Base |
|---|---|
| CRITICAL (CVSS ≥ 9.0) | 15 pts |
| HIGH (CVSS 7.0–8.9) | 8 pts |
| MEDIUM (CVSS 4.0–6.9) | 3 pts |

| Facteur | Multiplicateur |
|---|---|
| Exploit public connu (CISA KEV) | × 1.5 |
| EPSS ≥ 0.7 (mode deep) | × 1.3 |
| EPSS 0.4–0.7 (mode deep) | × 1.1 |
| CVE < 6 mois | × 1.2 |
| Dépendance dev | × 0.5 |
| Dépendance production | × 1.3 |

| Pénalité supplémentaire | Règle |
|---|---|
| CVE CRITICAL sans patch | 3 pts/CVE (max 15) |
| CVE HIGH sans patch | 1.5 pts/CVE (max 9) |
| Image Docker vulnérable | 10/15/20 pts selon sévérité |
| Mauvaises pratiques Docker | 5 pts/problème (max 10) |

### Interprétation

| Score | Niveau |
|---|---|
| 90–100 | ✅ EXCELLENT |
| 70–89 | 🟢 BON |
| 50–69 | 🟡 MOYEN |
| 30–49 | 🟠 MAUVAIS |
| 0–29 | 🔴 CRITIQUE |

---

## Providers de vulnérabilités

### Architecture multi-sources

```
1. OSV  querybatch → 1 requête HTTP pour toutes les dépendances
2. GHSA             → enrichissement (si GITHUB_TOKEN configuré)
3. NVD              → CVSS, CWE, description enrichie
4. EPSS             → probabilité exploitation (mode deep uniquement)
```

### OSV (principal)

- API gratuite, sans clé
- Batch : `/v1/querybatch` — 1 seule requête pour N dépendances
- Cache TTL 24h (ThreadSafeCache)

### NVD (enrichissement)

- Enrichit les CVE-IDs détectés par OSV
- Fournit : CVSS v3, CWE, description complète
- Clé NVD recommandée (50 req/30s vs 5 req/30s sans clé)

### EPSS (mode deep uniquement)

- Source : [FIRST.org](https://api.first.org/data/v1/epss)
- Probabilité d'exploitation réelle dans les 30 prochains jours
- Batch par 30 CVE — cache TTL 24h
- Activé uniquement en `scan_type=deep` pour préserver les performances

### Trivy (Docker)

- Scanner : `--scanners vuln` (standard) / `vuln,secret,misconfig` (deep)
- Packages : `--pkg-types os,library` (OS + Python/Node/Java)
- Lock global évite les conflits de cache Trivy

---

## Service IA

L'IA génère uniquement des **recommandations textuelles**.
Elle ne participe **jamais** à la détection CVE ni au Security Score.

### Stratégie de fallback

```
Gemini 2.5 Flash (principal)
    ↓ échec
NVIDIA NIM / Kimi K2.6 (intermédiaire)
    ↓ échec
OpenRouter (dernier LLM)
    ↓ échec
Système expert statique (rule-based — toujours disponible)
```

### Sécurité des clés

- Jamais dans les logs (même en DEBUG)
- Jamais retournées par l'API
- Jamais envoyées au frontend
- Jamais dans les rapports PDF

---

## Tests

```bash
cd backend/
venv\Scripts\activate
python -m pytest tests/ -v
```

### Couverture actuelle : 120 tests

| Fichier de test | Tests | Composant |
|---|---|---|
| `test_ai_service_nvidia.py` | 14 | NVIDIA NIM — fallback chain, sécurité clé |
| `test_analysis_schema.py` | 19 | Validation SEC3 (GitHub/Docker) |
| `test_correlation_engine.py` | 12 | Fusion, déduplication, priorisation |
| `test_cve_service.py` | 11 | OSV batch, cache, résumé |
| `test_dependency_scanner.py` | 13 | Parseurs, normalisation |
| `test_docker_scanner.py` | 12 | Analyse Dockerfile statique |
| `test_ghsa_provider.py` | 14 | Filtrage version, fail-open |
| `test_score_fixes.py` | 11 | FIX1/FIX3/FIX4 validés |
| `test_score_service.py` | 13 | Score, niveaux de risque |
| **TOTAL** | **120** | — |

---

## Structure du projet

```
backend/
├── .env                    ← Variables sensibles (jamais dans Git)
├── .env.example            ← Template de configuration
├── requirements.txt
├── alembic/                ← Migrations base de données
│   └── versions/
├── app/
│   ├── main.py             ← Point d'entrée FastAPI
│   ├── core/
│   │   ├── config.py       ← Settings Pydantic (lecture .env)
│   │   └── database.py     ← Engine SQLAlchemy, SessionLocal
│   ├── models/             ← Modèles SQLAlchemy (6 tables)
│   ├── schemas/            ← Schémas Pydantic + validation SEC3
│   ├── routes/             ← Endpoints FastAPI
│   └── services/
│       ├── github_analyzer.py
│       ├── dependency_scanner.py
│       ├── cve_service.py          ← Orchestrateur multi-sources
│       ├── cve_providers/
│       │   ├── osv_provider.py     ← querybatch
│       │   ├── nvd_provider.py     ← CVSS, CWE
│       │   ├── ghsa_provider.py    ← GitHub Advisories
│       │   ├── correlation_engine.py
│       │   ├── models.py
│       │   └── utils.py            ← Cache, HTTP retry, EPSS
│       ├── docker_scanner.py       ← Trivy + analyse statique
│       ├── score_service.py        ← Security Score (déterministe)
│       ├── ai_service.py           ← Gemini → NVIDIA → OpenRouter → Static
│       └── report_service.py       ← PDF ReportLab
└── tests/                  ← 120 tests unitaires
```

---

*Projet de Fin d'Études — ENSIASD Taroudant — Youssef BERRISSOUL — 2026*
