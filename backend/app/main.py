"""
Point d'entrée de l'application FastAPI.
Assemble les routes, configure CORS et le logging.
"""

from datetime import datetime, timedelta, timezone
import logging

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


# --- Création de l'application FastAPI ---
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API d'audit de la chaîne d'approvisionnement logicielle. "
                "Analyse les dépôts GitHub pour détecter les vulnérabilités de sécurité.",
    docs_url="/docs",           # Swagger UI accessible à /docs
    redoc_url="/redoc",         # ReDoc accessible à /redoc
)


# --- Middleware CORS (autorise le frontend React à communiquer) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Ports Vite / React
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Enregistrement des routes avec le préfixe /api/v1 ---
app.include_router(
    analysis_router,
    prefix=settings.API_V1_PREFIX,
    tags=["Analyses"],
)


# --- Événement au démarrage ---
@app.on_event("startup")
def startup_event() -> None:
    """Log au démarrage de l'application et vérifie les clés API."""
    logger.info("=== %s v%s démarré ===", settings.APP_NAME, settings.APP_VERSION)
    logger.info("Mode debug : %s", settings.DEBUG)
    logger.info("Documentation Swagger : http://%s:%s/docs", "localhost", 8000)

    # Vérification des clés API IA au démarrage
    if settings.GEMINI_API_KEY:
        logger.info("✅ GEMINI_API_KEY configurée — Gemini sera utilisé pour les recommandations")
    else:
        logger.warning("⚠️ GEMINI_API_KEY manquante — mode fallback statique activé pour les recommandations")

    if settings.OPENROUTER_API_KEY:
        logger.info("✅ OPENROUTER_API_KEY configurée — disponible en fallback si Gemini échoue")
    else:
        logger.info("ℹ️ OPENROUTER_API_KEY non configurée — pas de fallback OpenRouter")

    # ── F2 : Nettoyage des analyses bloquées au redémarrage ──────────────────
    # Si Uvicorn redémarre pendant un scan (reload, crash), les analyses restent
    # en RUNNING indéfiniment. On les marque toutes FAILED au démarrage.
    db = SessionLocal()
    try:
        # 1) Toutes les analyses RUNNING → FAILED (interrompues par le redémarrage)
        interrupted = db.query(Analysis).filter(
            Analysis.status == AnalysisStatus.RUNNING
        ).all()

        if interrupted:
            logger.warning(
                "[Startup] %d analyse(s) interrompue(s) par redémarrage → marquées FAILED",
                len(interrupted)
            )
            for analysis in interrupted:
                analysis.status = AnalysisStatus.FAILED
                logger.warning(
                    "[Startup] Analyse #%d (%s) → FAILED (interrompue)",
                    analysis.id, analysis.repo_name or "?"
                )
            db.commit()

        # 2) Analyses PENDING depuis trop longtemps (> 30 min) → FAILED
        threshold_pending = datetime.now(timezone.utc) - timedelta(minutes=30)
        stale_pending = db.query(Analysis).filter(
            Analysis.status == AnalysisStatus.PENDING,
            Analysis.created_at < threshold_pending
        ).all()

        if stale_pending:
            logger.warning(
                "[Startup] %d analyse(s) PENDING > 30min → marquées FAILED",
                len(stale_pending)
            )
            for analysis in stale_pending:
                analysis.status = AnalysisStatus.FAILED
            db.commit()

    except Exception as e:
        logger.error("[Startup] Erreur lors du nettoyage des analyses bloquées : %s", e)
    finally:
        db.close()

    # ── F1 : Nettoyage des dossiers temporaires orphelins ────────────────────
    # Si le bloc finally de cleanup_repository a échoué, des dossiers restent.
    # On nettoie les dossiers de plus de 2h au démarrage.
    import shutil
    from pathlib import Path

    try:
        clone_dir = Path(settings.CLONE_DIRECTORY)
        if clone_dir.exists():
            now_ts = datetime.now(timezone.utc).timestamp()
            orphan_count = 0
            for repo_dir in clone_dir.iterdir():
                if repo_dir.is_dir():
                    age_seconds = now_ts - repo_dir.stat().st_mtime
                    if age_seconds > 7200:  # > 2 heures
                        try:
                            shutil.rmtree(repo_dir, ignore_errors=True)
                            orphan_count += 1
                            logger.info("[Startup] Dossier orphelin supprimé : %s", repo_dir.name)
                        except Exception:
                            pass
            if orphan_count:
                logger.info("[Startup] %d dossier(s) temporaire(s) orphelin(s) nettoyé(s)", orphan_count)
    except Exception as e:
        logger.warning("[Startup] Nettoyage temp_repositories non critique : %s", e)


# --- Point d'entrée pour exécution directe ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )
