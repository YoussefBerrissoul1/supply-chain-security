# 🔐 Supply Chain Security Platform

**Plateforme d'Audit de la Chaîne d'Approvisionnement Logicielle**

> Projet de Fin d'Études (PFE) — Youssef BERRISSOUL — SITCN 4ème année  
> ENSIASD Taroudant — Juin/Juillet 2026

---

## 📋 Description

Cette plateforme analyse automatiquement un dépôt GitHub ou une image Docker pour détecter les risques de sécurité logicielle :

- 🔍 **Détection CVE** via OSV API + NVD API avec cache TTL 24h
- 🐳 **Scan Docker** avec Trivy (vulnérabilités OS dans les images)
- 🤖 **Recommandations IA** via Gemini (+ OpenRouter en fallback)
- 📊 **Security Score /100** calculé selon un algorithme précis
- 📄 **Rapport PDF** généré automatiquement (ReportLab côté backend)
- 📈 **Historique** des analyses en base PostgreSQL

---

## 🚀 Démarrage rapide

### Prérequis

| Outil | Version min. | Vérification |
|---|---|---|
| Python | 3.12+ | `python --version` |
| Node.js | 18+ | `node --version` |
| PostgreSQL | 14+ | `psql --version` |
| Trivy (optionnel) | latest | `trivy --version` |

### 1. Cloner le projet

```bash
git clone https://github.com/YoussefBerrissoul1/supply-chain-security.git
cd supply-chain-security
```

### 2. Configurer la base de données

```bash
psql -U postgres -c "CREATE DATABASE supplychain_db;"
```

### 3. Configurer le backend

```bash
cd backend

# Créer et activer l'environnement virtuel
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Installer les dépendances
pip install -r requirements.txt

# Configurer les variables d'environnement
copy .env.example .env         # Windows
# cp .env.example .env         # Linux/macOS
# Éditer .env avec vos clés API

# Appliquer les migrations Alembic
alembic upgrade head
```

### 4. Configurer le frontend

```bash
cd frontend
npm install
```

### 5. Démarrer l'application

#### Windows
```batch
# Depuis la racine du projet :
start.bat
```

#### Linux / macOS
```bash
chmod +x start.sh
./start.sh
```

#### Manuel (deux terminaux séparés)

**Terminal 1 — Backend :**
```bash
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend :**
```bash
cd frontend
npm run dev
```

### 6. Accéder à l'application

| Service | URL |
|---|---|
| 🖥️ Frontend (Landing + Scan) | http://localhost:5173 |
| ⚙️ Backend API | http://localhost:8000 |
| 📖 Documentation Swagger | http://localhost:8000/docs |
| 🔬 Page de scan | http://localhost:5173/scan |

---

## 🔑 Variables d'environnement

Créez un fichier `backend/.env` avec les variables suivantes :

```env
# Base de données PostgreSQL
DATABASE_URL=postgresql://postgres:password@localhost:5432/supplychain_db

# IA — Gemini (provider principal)
GEMINI_API_KEY=AIzaSy...

# IA — OpenRouter (fallback si Gemini échoue)
OPENROUTER_API_KEY=sk-or-...

# Choisir le provider IA actif
AI_PROVIDER=gemini

# NVD API (optionnel — améliore la précision des CVSS)
NVD_API_KEY=...

# GitHub Token (optionnel — améliore la limite de rate pour les repos privés)
GITHUB_TOKEN=ghp_...

# Application
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true

# Répertoire de sortie des rapports PDF
REPORTS_DIR=./reports/output
```

---

## 🏗️ Architecture

```
supply-chain-security/
├── backend/                    # API FastAPI (Python 3.12)
│   ├── app/
│   │   ├── main.py             # Point d'entrée FastAPI + CORS
│   │   ├── core/
│   │   │   ├── config.py       # Settings Pydantic v2
│   │   │   └── database.py     # Engine SQLAlchemy + SessionLocal
│   │   ├── models/             # 6 modèles SQLAlchemy
│   │   ├── schemas/            # Schémas Pydantic (Request/Response)
│   │   ├── routes/             # Endpoints API (824 lignes)
│   │   └── services/           # 7 services métier
│   │       ├── github_analyzer.py     # Clone + détection fichiers
│   │       ├── dependency_scanner.py  # Parsing dépendances
│   │       ├── cve_service.py         # OSV + NVD + CISA KEV (1273 lignes)
│   │       ├── docker_scanner.py      # Trivy + analyse statique
│   │       ├── score_service.py       # Algorithme scoring /100
│   │       ├── ai_service.py          # Gemini + OpenRouter + fallback
│   │       └── report_service.py      # PDF ReportLab
│   ├── alembic/                # 5 migrations de base
│   └── tests/                  # Tests unitaires cve_service
│
├── frontend/                   # React 18 + TypeScript + Vite
│   └── src/
│       ├── lib/
│       │   └── api.ts          # Client HTTP → backend FastAPI
│       ├── pages/
│       │   └── ScanPage.tsx    # Interface scan (connectée au backend)
│       ├── sections/           # 12 sections de la landing page
│       └── components/         # 55+ composants UI
│
├── docs/                       # Documentation projet
├── start.bat                   # Démarrage Windows
└── start.sh                    # Démarrage Linux/macOS
```

---

## 🔌 API Endpoints

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyze` | Lancer une analyse GitHub |
| `POST` | `/api/v1/analyze/docker` | Lancer une analyse Docker |
| `GET` | `/api/v1/analyses` | Historique (20 dernières) |
| `GET` | `/api/v1/analyses/{id}` | Détail complet d'une analyse |
| `GET` | `/api/v1/analyses/{id}/progress` | Progression en temps réel |
| `GET` | `/api/v1/analyses/{id}/report` | Télécharger le rapport PDF |
| `GET` | `/api/v1/health` | État de l'API + base de données |

### Exemple — Lancer une analyse

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/pallets/flask", "scan_type": "standard"}'
```

Réponse :
```json
{
  "id": 1,
  "repo_url": "https://github.com/pallets/flask",
  "repo_name": "pallets/flask",
  "status": "pending",
  "security_score": null,
  "created_at": "2026-07-22T15:00:00"
}
```

```bash
# Polling jusqu'à done
curl http://localhost:8000/api/v1/analyses/1/progress
```

---

## 📊 Algorithme Security Score

Score = 100 − somme des pénalités (minimum 0)

| Facteur | Pénalité | Plafond |
|---|---|---|
| CVE CRITICAL (CVSS ≥ 9.0) | −15 pts | max −45 |
| CVE HIGH (CVSS 7.0–8.9) | −8 pts | max −24 |
| CVE MEDIUM (CVSS 4.0–6.9) | −3 pts | max −15 |
| Package abandonné (> 2 ans) | −5 pts | max −20 |
| Image Docker vulnérable | −10 pts | max −20 |
| Mauvaise pratique Docker | −5 pts | max −10 |

| Score | Interprétation |
|---|---|
| 90–100 | 🟢 EXCELLENT |
| 70–89 | 🟡 BON |
| 50–69 | 🟠 MOYEN |
| 30–49 | 🔴 MAUVAIS |
| 0–29 | ⛔ CRITIQUE |

---

## 🛠️ Stack Technologique

### Backend
- **Python 3.12** + **FastAPI** + **Uvicorn**
- **SQLAlchemy ORM** + **Alembic** (migrations)
- **PostgreSQL** (persistance)
- **Pydantic v2** (validation)

### Services d'analyse
- **GitPython** (clonage repo)
- **OSV API** (vulnérabilités — gratuit, rapide)
- **NVD API** (CVSS précis, enrichissement)
- **CISA KEV** (exploits connus)
- **Trivy** (scan Docker)
- **pip-audit** (audit Python)

### IA
- **Gemini API** (provider principal)
- **OpenRouter API** (fallback)
- **Système expert statique** (dernier recours)

### Reporting
- **ReportLab** (génération PDF)

### Frontend
- **React 18** + **TypeScript** + **Vite**
- **TailwindCSS v4**
- **Framer Motion** (animations)
- **TanStack Query** (état serveur)
- **Radix UI** (composants accessibles)
- **Recharts** (graphiques)

---

## 🧪 Tests

```bash
cd backend
venv\Scripts\activate

# Tests unitaires cve_service
python -m pytest tests/test_cve_service.py -v

# Health check API
curl http://localhost:8000/api/v1/health
```

---

## 📝 Notes de développement

- **ProtectedRoute** : La page `/scan` est accessible sans authentification (choix délibéré pour PFE — pas d'auth complexe requise)
- **Trivy optionnel** : Si Trivy n'est pas installé, le scan Docker utilise l'analyse statique du Dockerfile uniquement
- **Fallback IA** : Si Gemini et OpenRouter échouent, un système expert statique génère des recommandations de base

---

## 👤 Auteur

**Youssef BERRISSOUL**  
SITCN 4ème année — ENSIASD Taroudant  
PFE — Juin/Juillet 2026

---

*Dernière mise à jour : Juillet 2026*
