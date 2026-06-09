> ⚠️ INSTRUCTION PRIORITAIRE — À LIRE EN PREMIER
>
> Tu es mon mentor technique, PAS un générateur de code automatique.
> Pour CHAQUE fichier, tu dois obligatoirement suivre ce format EXACT :
>
> 1. Ce qu'on va faire
> 2. Pourquoi cette étape existe
> 3. Comment ça fonctionne techniquement
> 4. Les bibliothèques utilisées et pourquoi
> 5. Le code proposé
> 6. Explication ligne par ligne
> 7. Comment tester
> 8. Les erreurs fréquentes possibles
> 9. Comment expliquer en soutenance
> 10. Étape suivante recommandée
>
> Ne jamais sauter une étape. Ne jamais coder sans expliquer d'abord.
> Toujours attendre ma validation avant d'avancer.

# CLAUDE.md — Contexte Projet Supply Chain Security

> Ce fichier est lu automatiquement par Claude Code à chaque session.
> Ne pas supprimer. Ne pas modifier sans raison.

---

## IDENTITÉ DU PROJET

**Titre :** Plateforme d'Audit de la Chaîne d'Approvisionnement Logicielle  
**Étudiant :** Youssef BERRISSOUL — SITCN 4ème année — ENSIASD Taroudant  
**Type :** Projet de Fin d'Études (PFE) académique — Stage Juin/Juillet 2026  
**Objectif :** Analyser automatiquement un dépôt GitHub pour détecter les risques de sécurité logicielle.

---

## CE QUE FAIT L'APPLICATION

1. L'utilisateur soumet une URL GitHub
2. Le système clone le dépôt
3. Détecte les fichiers de dépendances (requirements.txt, package.json, pom.xml, Dockerfile…)
4. Scanne les dépendances et détecte les CVE (OSV API + NVD API + pip-audit)
5. Analyse les images Docker avec Trivy
6. Calcule un Security Score /100
7. Génère des recommandations IA (Gemini ou OpenRouter)
8. Exporte un rapport PDF (ReportLab)
9. Stocke l'historique en PostgreSQL

---

## STACK TECHNOLOGIQUE — NE PAS CHANGER

### Backend
- Python 3.12
- FastAPI
- SQLAlchemy ORM
- PostgreSQL
- Alembic (migrations)
- Pydantic v2
- Uvicorn
- python-dotenv

### Analyse sécurité
- GitPython (clonage repo)
- pip-audit (audit packages Python)
- Trivy (scan Docker)
- OSV API (https://api.osv.dev/v1/query)
- NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)

### IA
- Gemini API (provider principal)
- OpenRouter API (fallback)
- Variable AI_PROVIDER dans .env pour switcher

### Reporting
- ReportLab (génération PDF)

### Frontend
- React + Vite + TailwindCSS + Axios

---

## STRUCTURE OBLIGATOIRE — NE JAMAIS CASSER

```
supply-chain-security/
├── CLAUDE.md                  ← ce fichier
├── .gitignore
├── backend/
│   ├── .env                   ← variables d'environnement (jamais dans git)
│   ├── requirements.txt
│   ├── venv/
│   └── app/
│       ├── main.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py      ← Settings Pydantic, lecture .env
│       │   └── database.py    ← engine SQLAlchemy, SessionLocal, Base
│       ├── models/
│       │   ├── __init__.py
│       │   ├── analysis.py
│       │   ├── dependency.py
│       │   ├── vulnerability.py
│       │   ├── docker_result.py
│       │   ├── recommendation.py
│       │   └── report.py
│       ├── schemas/
│       │   ├── __init__.py
│       │   └── analysis_schema.py
│       ├── routes/
│       │   ├── __init__.py
│       │   └── analysis_routes.py
│       └── services/
│           ├── __init__.py
│           ├── github_analyzer.py
│           ├── dependency_scanner.py
│           ├── cve_service.py
│           ├── docker_scanner.py
│           ├── score_service.py
│           ├── ai_service.py
│           └── report_service.py
├── frontend/
├── docs/
├── reports/
└── scripts/
```

---

## MODÈLE DE DONNÉES — RESPECTER EXACTEMENT

### Analysis
- id (PK)
- repo_url: str
- repo_name: str
- status: Enum(pending, running, done, failed)
- security_score: float
- created_at: datetime
- Relations : → plusieurs Dependency, → plusieurs Recommendation, → plusieurs Report, → un DockerResult

### Dependency
- id (PK)
- analysis_id (FK → Analysis)
- name: str
- version: str
- ecosystem: str
- is_outdated: bool
- Relations : → plusieurs Vulnerability

### Vulnerability
- id (PK)
- dependency_id (FK → Dependency)
- cve_id: str
- cvss_score: float
- severity: Enum(CRITICAL, HIGH, MEDIUM, LOW)
- description: str

### DockerResult
- id (PK)
- analysis_id (FK → Analysis)
- base_image: str
- vulnerabilities_count: int
- has_root_user: bool
- image_score: float

### Recommendation
- id (PK)
- analysis_id (FK → Analysis)
- target_type: Enum(dependency, docker, global)
- recommendation_text: str
- provider: str

### Report
- id (PK)
- analysis_id (FK → Analysis)
- format: Enum(pdf, html)
- file_path: str

---

## API ENDPOINTS OBLIGATOIRES

```
POST   /api/v1/analyze              → lancer une analyse
GET    /api/v1/analyses             → historique (10 dernières)
GET    /api/v1/analyses/{id}        → détail complet d'une analyse
GET    /api/v1/analyses/{id}/report → télécharger le rapport PDF
GET    /api/v1/health               → vérification état API
```

---

## ALGORITHME SECURITY SCORE

Score = 100 − somme des pénalités (minimum 0)

| Facteur | Pénalité | Plafond |
|---|---|---|
| CVE CRITICAL (CVSS ≥ 9.0) | −15 pts | max −45 |
| CVE HIGH (CVSS 7.0–8.9) | −8 pts | max −24 |
| CVE MEDIUM (CVSS 4.0–6.9) | −3 pts | max −15 |
| Package abandonné (> 2 ans) | −5 pts | max −20 |
| Image Docker vulnérable | −10 pts | max −20 |
| Mauvaise pratique Docker | −5 pts | max −10 |

Interprétation :
- 0–29 → CRITIQUE
- 30–49 → MAUVAIS
- 50–69 → MOYEN
- 70–89 → BON
- 90–100 → EXCELLENT

---

## VARIABLES .env REQUISES

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/supplychain_db
GEMINI_API_KEY=AIzaSy...
OPENROUTER_API_KEY=sk-or-...
AI_PROVIDER=gemini
NVD_API_KEY=...
GITHUB_TOKEN=ghp_...
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
REPORTS_DIR=./reports/output
```

---

## RÈGLES DE DÉVELOPPEMENT — TOUJOURS RESPECTER

1. **Travailler module par module** — un fichier à la fois
2. **Ne jamais casser la structure existante**
3. **Ne jamais modifier plusieurs fichiers critiques d'un coup**
4. **Typage Python obligatoire** sur toutes les fonctions
5. **Gestion d'erreurs obligatoire** — try/except avec logs
6. **Validation Pydantic obligatoire** sur tous les endpoints
7. **Relations SQLAlchemy correctes** avec back_populates
8. **Commentaires utiles uniquement** — pas de commentaires évidents
9. **Respecter Clean Architecture** — services ne connaissent pas les routes
10. **Logs professionnels** — utiliser logging, pas print()

---

## ORDRE DE DÉVELOPPEMENT RECOMMANDÉ

Phase actuelle : **PHASE 3 — Backend Core** (en cours)

Prochaines étapes dans l'ordre :

1. ✅ Structure projet créée
2. ⏳ Créer base PostgreSQL `supplychain_db`
3. ⏳ Implémenter `core/config.py` (Settings)
4. ⏳ Implémenter `core/database.py` (engine + session)
5. ⏳ Créer tous les modèles SQLAlchemy (6 fichiers models/)
6. ⏳ Configurer Alembic + première migration
7. ⏳ Créer schemas Pydantic
8. ⏳ Créer routes FastAPI de base
9. ⏳ Implémenter github_analyzer.py
10. ⏳ Implémenter dependency_scanner.py
11. ⏳ Implémenter cve_service.py (OSV prioritaire)
12. ⏳ Implémenter docker_scanner.py (Trivy)
13. ⏳ Implémenter score_service.py
14. ⏳ Implémenter ai_service.py (Gemini + OpenRouter)
15. ⏳ Implémenter report_service.py (ReportLab)
16. ⏳ Frontend React + Vite + TailwindCSS
17. ⏳ Tests fonctionnels
18. ⏳ Documentation finale

---

## DIAGRAMMES UML RÉALISÉS (PHASE CONCEPTION TERMINÉE)

- ✅ Diagramme de cas d'utilisation (PlantUML)
- ✅ Diagramme de classes (PlantUML)
- ✅ Diagramme de séquence (PlantUML)
- ✅ Diagramme d'activité (PlantUML)
- ✅ Architecture applicative globale
- ✅ Guide de conception complet (PDF)
- ✅ Cahier des charges (Word)
- ✅ Cahier de démarche (Word)

---

## CONTEXTE ACADÉMIQUE

Ce projet est un PFE défendable en soutenance. Il doit :
- Être professionnel mais pas sur-ingénié
- Éviter : microservices, Kubernetes, Redis, RabbitMQ, auth complexe
- Être réalisable par un étudiant seul en 8 semaines
- Avoir un GitHub propre avec README complet
- Être démontrable live en soutenance

---

*Dernière mise à jour : Juin 2026*
