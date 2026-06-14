# Récapitulatif complet — Supply Chain Security Platform
## PFE Cybersécurité — Youssef BERRISSOUL

---

## 1. Vue d'ensemble du projet

**Objectif** : Plateforme web qui analyse la sécurité d'un dépôt GitHub :
clonage → détection dépendances → scan CVE → scan Docker → score de sécurité → rapport IA + PDF.

**Stack** : Python 3.12 / FastAPI / SQLAlchemy / PostgreSQL / Alembic / Trivy / Gemini API

**Règles absolues (CLAUDE.md)** :
- Ne jamais sauter une étape
- Toujours expliquer avant de coder
- Toujours attendre la validation avant d'avancer
- Commentaires obligatoires dans tout le code

---

## 2. Architecture du projet

```
supply-chain-security/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py         ✅ FAIT
│   │   │   └── database.py       ✅ FAIT
│   │   ├── models/
│   │   │   ├── analysis.py       ✅ FAIT
│   │   │   ├── dependency.py     ✅ FAIT
│   │   │   ├── vulnerability.py  ✅ FAIT
│   │   │   ├── docker_result.py  ✅ FAIT
│   │   │   ├── recommendation.py ✅ FAIT
│   │   │   └── report.py         ✅ FAIT
│   │   ├── schemas/
│   │   │   └── __init__.py       ✅ FAIT (schemas Pydantic)
│   │   ├── routes/
│   │   │   └── analysis_routes.py ✅ FAIT
│   │   ├── services/
│   │   │   ├── github_analyzer.py    ✅ FAIT + fix Windows
│   │   │   ├── dependency_scanner.py ✅ FAIT
│   │   │   ├── cve_service.py        ✅ FAIT
│   │   │   ├── docker_scanner.py     ✅ FAIT
│   │   │   ├── score_service.py      ✅ FAIT (v1 - amélioration en attente)
│   │   │   ├── ai_service.py         ⏳ ÉTAPE 14
│   │   │   └── report_service.py     ⏳ ÉTAPE 15
│   │   └── main.py               ✅ FAIT
│   ├── alembic/                  ✅ FAIT (migrations)
│   ├── .env                      ✅ CONFIGURÉ
│   └── scan_demo.py              ✅ FAIT (script de démo)
└── frontend/                     ⏳ ÉTAPE 16
```

---

## 3. Fichiers créés/modifiés — Détail complet

### `backend/app/core/config.py` ✅
- `Settings` avec Pydantic BaseSettings
- Variables : `DATABASE_URL`, `GITHUB_TOKEN`, `NVD_API_KEY`, `GEMINI_API_KEY`
- Ajouts : `OSV_API_URL`, `NVD_API_URL`, `TRIVY_PATH`, `HTTP_TIMEOUT`

### `backend/app/core/database.py` ✅
- Engine SQLAlchemy + SessionLocal + Base
- `get_db()` : générateur de session (dependency injection FastAPI)

### `backend/app/models/*.py` ✅ (6 modèles)
- `Analysis` : table `analyses` (id, repo_url, repo_name, status, security_score, created_at)
- `Dependency` : table `dependencies` (name, version, ecosystem, is_outdated)
- `Vulnerability` : table `vulnerabilities` (cve_id, cvss_score, severity, description, fixed_version)
- `DockerResult` : table `docker_results` (base_image, vulnerabilities_count, has_root_user, image_score)
- `Recommendation` : table `recommendations` (target_type, recommendation_text, provider)
- `Report` : table `reports` (format, file_path)

### `backend/app/schemas/__init__.py` ✅
- `AnalysisCreate` : validation URL GitHub (HttpUrl)
- `AnalysisSummary` : liste (sans relations)
- `AnalysisDetail` : détail complet avec relations
- `HealthResponse`

### `backend/app/routes/analysis_routes.py` ✅
- `POST /api/v1/analyze` → 201 Created (crée analyse en status "pending")
- `GET /api/v1/analyses` → 200 liste 10 dernières
- `GET /api/v1/analyses/{id}` → 200 détail / 404 si introuvable
- `GET /api/v1/health` → 200 `{status, version, database}`

### `backend/app/services/github_analyzer.py` ✅ + fix Windows
- `validate_github_url()` : regex valide l'URL
- `clone_repository()` : clone Git avec timeout 120s
- `detect_dependency_files()` : scan 604 fichiers, détecte par extension
- `cleanup_repository()` : suppression garantie (finally)
- **Fix Windows** : `_force_remove_readonly()` → résout le `WinError 5` sur les fichiers `.git` read-only

### `backend/app/services/dependency_scanner.py` ✅
- `DependencyInfo` : dataclass (name, version, ecosystem, source_file)
- Parseurs : `requirements.txt`, `package.json`, `pyproject.toml`, `pom.xml`, `Dockerfile`
- Déduplication automatique (version précise conservée)
- `get_scan_summary()` : stats par écosystème

### `backend/app/services/cve_service.py` ✅
- `VulnerabilityResult` : dataclass (cve_id, cvss_score, severity, description, fixed_version)
- `Severity` enum : CRITICAL / HIGH / MEDIUM / LOW / NONE
- `query_osv()` : OSV API (prioritaire, gratuit, sans clé)
- `enrich_with_nvd()` : NVD API (enrichissement CVSS) avec retry sur rate limit
- `scan_all_vulnerabilities()` : chaîne les deux APIs pour toutes les dépendances
- `cvss_to_severity()` : CVSS float → enum Severity
- `get_cve_summary()` : statistiques globales

### `backend/app/services/docker_scanner.py` ✅
- `DockerScanResult` : dataclass complète
- `analyze_dockerfile()` : analyse statique (FROM, USER, secrets ENV, tag latest)
- `is_trivy_available()` : vérifie si Trivy est installé
- `run_trivy_scan()` : lance `trivy image --format json`
- `parse_trivy_report()` : extrait vulns par sévérité du JSON Trivy
- `calculate_image_score()` : score /100 (CRITICAL×15, HIGH×8, MEDIUM×3, root−10)
- `scan_docker()` : orchestre tout (statique + Trivy si disponible)
- `get_docker_summary()` : résumé pour logs/rapport

### `backend/app/services/score_service.py` ✅ (v1 — amélioration en attente)
- `RiskLevel` enum : CRITIQUE / MAUVAIS / MOYEN / BON / EXCELLENT
- `PenaltyLine` : dataclass pour une ligne de pénalité avec plafond
- `ScoreResult` : dataclass résultat complet
- `compute_security_score()` : assemble CVE + Docker + deps
- `_compute_cve_penalties()` : CVE CRITICAL/HIGH/MEDIUM avec plafonds
- `_compute_docker_penalties()` : ⚠️ logique par tranches de 10 (à améliorer — voir section 5)
- `_compute_abandoned_penalties()` : packages obsolètes (prêt, is_outdated=False pour l'instant)
- `format_score_report()` : rapport textuel lisible
- `get_quick_recommendations()` : recommandations par niveau de risque

---

## 4. Migrations Alembic ✅
```
alembic init alembic
alembic revision --autogenerate -m "create all tables"
alembic upgrade head
```
Toutes les 6 tables créées dans PostgreSQL.

---

## 5. Bug en attente de validation — `_compute_docker_penalties()`

> [!IMPORTANT]
> L'utilisateur a demandé cette amélioration MAIS a demandé à attendre sa validation avant de modifier le fichier.

**Problème actuel** (logique "tranches de 10") :
```python
tranche_count = max(1, (severe_docker + 9) // 10)
# 1 vuln → 1 tranche → -10pts
# 9 vulns → 1 tranche → -10pts   ← MÊME pénalité ! Incohérent.
# 10 vulns → 1 tranche → -10pts
# 11 vulns → 2 tranches → -20pts
```

**Nouvelle logique proposée (approuvée par l'utilisateur)** :
```python
if severe_docker <= 5:
    docker_vuln_penalty = 10.0    # Faible : -10 pts
elif severe_docker <= 15:
    docker_vuln_penalty = 15.0    # Moyen : -15 pts
else:
    docker_vuln_penalty = 20.0    # Sévère : -20 pts (= plafond)
```

**Statut** : En attente de validation utilisateur pour modification du fichier.

---

## 6. Tests effectués et résultats

### Tests unitaires (Python interactif)
| Test | Résultat |
|---|---|
| config.py import | ✅ |
| Tous les modèles SQLAlchemy | ✅ |
| URL GitHub valide/invalide/nettoyée | ✅ |
| Parsing requirements.txt, package.json | ✅ |
| Déduplication dépendances | ✅ |
| CVSS → Severity (5 cas) | ✅ |
| score_to_risk_level (10 assertions) | ✅ |
| Score parfait 100.0 | ✅ |
| Score Nestle-Shop simulé 46.0/100 | ✅ |
| Plafonnement 10 CRITICAL → 55.0 | ✅ |

### Tests OSV API réelle
| Test | Résultat |
|---|---|
| `requests@2.6.0` → 7 CVE OSV | ✅ |
| `axios@1.1.2` → 26 CVE OSV | ✅ |
| `vite@4.0.0` → 16 CVE OSV | ✅ |

### Tests Trivy réel
| Test | Résultat |
|---|---|
| `python:3.12-slim` → 110 CVE Trivy | ✅ |
| Dockerfile non-root → root=False | ✅ |
| Dockerfile ubuntu:latest → 3 issues | ✅ |

### Tests HTTP endpoints
| Endpoint | Code | Résultat |
|---|---|---|
| GET /api/v1/health | 200 | ✅ |
| GET /api/v1/analyses | 200 | ✅ |
| POST /api/v1/analyze | 201 | ✅ |
| GET /api/v1/analyses/{id} | 200 | ✅ |
| GET /api/v1/analyses/9999 | 404 | ✅ |
| POST /api/v1/analyze (URL invalide) | 422 | ✅ |

### Scan réel du repo `Nestle-Shop-Full-App-E-Commerce`
| Résultat | Valeur |
|---|---|
| Clonage | 7.4s, 604 fichiers |
| Écosystèmes | nodejs + php |
| Dépendances | 7 (package.json) |
| CVE totales | 42 (axios: 26, vite: 16) |
| Sévérité max | CRITICAL |
| Docker | Pas de Dockerfile |
| Score estimé | 46/100 MAUVAIS |

---

## 7. État GitHub

**Repo** : `https://github.com/YoussefBerrissoul1/supply-chain-security`
**Branche** : `master`

| Commit | Description |
|---|---|
| `e12ddb5` | feat: add score_service (step 13) |
| `bc609fd` | fix: handle Windows read-only .git files |
| `561c009` | feat: add docker_scanner service (step 12) |
| `921c50d` | feat: add dependency_scanner and cve_service (steps 10-11) |
| (antérieurs) | config, models, schemas, routes, alembic |

**Fichiers temporaires à supprimer** :
- `backend/scan_demo.py` (script de démo, ne pas committer)

---

## 8. Étapes restantes

```
⏳ 14 — ai_service.py
         Génération de recommandations via Gemini API (google-generativeai)
         Fallback : règles prédéfinies si API indisponible
         Input : ScoreResult + CVE list
         Output : list[Recommendation] + sauvegarde en base

⏳ 15 — report_service.py
         Génération rapport PDF avec ReportLab ou WeasyPrint
         Contenu : score, tableau CVE, recommandations, graphiques
         Output : fichier PDF dans reports/ + entrée base Report

⏳ 16 — Intégration route /analyze
         Connecter tous les services dans la route POST /analyze
         github_analyzer → dependency_scanner → cve_service →
         docker_scanner → score_service → ai_service → report_service
         Mettre à jour le statut : pending → running → completed/failed

⏳ 17 — Frontend React (ou HTML/CSS/JS simple)
         Dashboard avec : formulaire URL, liste analyses, détail avec score

⏳ 18 — Tests fonctionnels end-to-end

⏳ 19 — Documentation finale (README.md)
```

---

## 9. Instructions pour le prochain agent

1. **Lire `CLAUDE.md`** en premier (`supply-chain-security/CLAUDE.md`)
2. **Lire ce récapitulatif** pour connaître l'état exact
3. **Vérifier le bug en attente** (section 5 ci-dessus) — demander validation utilisateur avant de modifier
4. **Prochaine étape : `ai_service.py` (étape 14)**
5. **Règles impératives** :
   - Expliquer avant de coder
   - Commenter tout le code (même logique que les autres services)
   - Gérer les erreurs (API Gemini down → fallback)
   - Valider avec l'utilisateur avant chaque commit
