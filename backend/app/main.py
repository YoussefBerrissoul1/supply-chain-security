"""
Point d'entrée de l'application FastAPI.
Assemble les routes, configure CORS et le logging.

Utilise l'API lifespan (FastAPI ≥ 0.93) à la place du déprécié on_event("startup").
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import logging
import shutil

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.analysis import Analysis, AnalysisStatus
from app.routes.analysis_routes import router as analysis_router

# --- Configuration du logging ---
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan : remplace @app.on_event("startup") / "shutdown" (déprécié ≥ 0.93)
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestionnaire de cycle de vie de l'application.
    Code avant yield → démarrage. Code après yield → arrêt.
    """
    logger.info("=== %s v%s démarré ===", settings.APP_NAME, settings.APP_VERSION)
    logger.info("Mode debug : %s", settings.DEBUG)
    logger.info("Documentation Swagger : http://localhost:8000/docs")

    # ── Vérification des clés API IA ─────────────────────────────────────────
    if settings.GEMINI_API_KEY:
        logger.info("✅ GEMINI_API_KEY configurée — Gemini actif (provider principal)")
    else:
        logger.warning("⚠️  GEMINI_API_KEY manquante — fallback automatique activé")

    if settings.NVIDIA_API_KEY:
        logger.info("✅ NVIDIA_API_KEY configurée — NVIDIA NIM (moonshotai/kimi-k2.6) disponible")
    else:
        logger.info("ℹ️  NVIDIA_API_KEY non configurée — NVIDIA NIM désactivé")

    if settings.OPENROUTER_API_KEY:
        logger.info("✅ OPENROUTER_API_KEY configurée — OpenRouter disponible en dernier fallback")
    else:
        logger.info("ℹ️  OPENROUTER_API_KEY non configurée — pas de fallback OpenRouter")

    # ── F2 : Nettoyage des analyses bloquées au redémarrage ──────────────────
    # Si Uvicorn redémarre pendant un scan (reload, crash), les analyses
    # restent en RUNNING indéfiniment. On les marque FAILED au démarrage.
    db = SessionLocal()
    try:
        # 1) RUNNING → FAILED (interrompues par le redémarrage)
        interrupted = db.query(Analysis).filter(
            Analysis.status == AnalysisStatus.RUNNING
        ).all()
        if interrupted:
            logger.warning(
                "[Startup] %d analyse(s) interrompue(s) → marquées FAILED",
                len(interrupted),
            )
            for analysis in interrupted:
                analysis.status = AnalysisStatus.FAILED
                logger.warning(
                    "[Startup] Analyse #%d (%s) → FAILED",
                    analysis.id, analysis.repo_name or "?",
                )
            db.commit()

        # 2) PENDING depuis > 30 min → FAILED (bloquées sans worker)
        threshold = datetime.now(timezone.utc) - timedelta(minutes=30)
        stale = db.query(Analysis).filter(
            Analysis.status == AnalysisStatus.PENDING,
            Analysis.created_at < threshold,
        ).all()
        if stale:
            logger.warning(
                "[Startup] %d analyse(s) PENDING > 30min → marquées FAILED",
                len(stale),
            )
            for analysis in stale:
                analysis.status = AnalysisStatus.FAILED
            db.commit()

    except Exception as e:
        logger.error("[Startup] Erreur nettoyage analyses bloquées : %s", e)
    finally:
        db.close()

    # ── F1 : Nettoyage des dossiers temporaires orphelins (> 2h) ─────────────
    try:
        from pathlib import Path
        clone_dir = Path(settings.CLONE_DIRECTORY)
        if clone_dir.exists():
            now_ts = datetime.now(timezone.utc).timestamp()
            orphan_count = 0
            for repo_dir in clone_dir.iterdir():
                if repo_dir.is_dir():
                    age_s = now_ts - repo_dir.stat().st_mtime
                    if age_s > 7200:  # > 2 heures
                        try:
                            shutil.rmtree(repo_dir, ignore_errors=True)
                            orphan_count += 1
                            logger.info("[Startup] Dossier orphelin supprimé : %s", repo_dir.name)
                        except Exception:
                            pass
            if orphan_count:
                logger.info("[Startup] %d dossier(s) temporaire(s) nettoyé(s)", orphan_count)
    except Exception as e:
        logger.warning("[Startup] Nettoyage temp_repositories (non critique) : %s", e)

    yield  # ← L'application tourne ici

    # Code d'arrêt (shutdown) — rien de spécifique pour l'instant
    logger.info("=== %s arrêté ===", settings.APP_NAME)


# ─────────────────────────────────────────────────────────────────────────────
# Création de l'application FastAPI
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "API d'audit de la chaîne d'approvisionnement logicielle. "
        "Analyse les dépôts GitHub et les images Docker pour détecter "
        "les vulnérabilités (CVE) via OSV, GHSA, NVD et Trivy."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────────────────────────────
# Middleware CORS
# ─────────────────────────────────────────────────────────────────────────────

# Origines autorisées : ports Vite (5173) et React (3000) en développement.
# En production, définir CORS_ORIGINS dans .env sous forme de liste JSON.
_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Enregistrement des routes
# ─────────────────────────────────────────────────────────────────────────────

app.include_router(
    analysis_router,
    prefix=settings.API_V1_PREFIX,
    tags=["Analyses"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée pour exécution directe (python -m app.main)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )
