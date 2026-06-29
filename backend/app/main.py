"""
Point d'entrée de l'application FastAPI.
Assemble les routes, configure CORS et le logging.
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
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


# --- Point d'entrée pour exécution directe ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )
