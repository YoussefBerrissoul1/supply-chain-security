"""
Routes FastAPI pour l'analyse de sécurité.
Définit les 5 endpoints obligatoires de l'API.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import Analysis, AnalysisStatus
from app.schemas.analysis_schema import (
    AnalysisDetailResponse,
    AnalysisListResponse,
    AnalysisRequest,
    HealthResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================
# POST /analyze — Lancer une analyse
# ============================================================

@router.post(
    "/analyze",
    response_model=AnalysisListResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Lancer une analyse de sécurité",
    description="Soumet une URL GitHub pour analyse. Retourne l'objet analyse créé.",
)
def create_analysis(
    request: AnalysisRequest,
    db: Session = Depends(get_db),
) -> Analysis:
    """
    Crée une nouvelle analyse en base avec le statut 'pending'.
    Le scan complet sera déclenché par les services (étapes suivantes).
    """
    # Extraire le nom du repo depuis l'URL (ex: "fastapi" depuis "https://github.com/fastapi/fastapi")
    repo_url_str = str(request.repo_url).rstrip("/")
    repo_name = repo_url_str.split("/")[-1]

    logger.info("Nouvelle analyse demandée pour : %s", repo_name)

    # Créer l'analyse en base
    analysis = Analysis(
        repo_url=repo_url_str,
        repo_name=repo_name,
        status=AnalysisStatus.PENDING,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    logger.info("Analyse #%d créée avec succès (statut: pending)", analysis.id)
    return analysis


# ============================================================
# GET /analyses — Historique des analyses
# ============================================================

@router.get(
    "/analyses",
    response_model=list[AnalysisListResponse],
    summary="Historique des analyses",
    description="Retourne les 10 dernières analyses, triées par date décroissante.",
)
def list_analyses(
    db: Session = Depends(get_db),
    limit: int = 10,
) -> list[Analysis]:
    """Retourne les N dernières analyses (par défaut 10)."""
    analyses = (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )
    logger.info("Historique demandé : %d analyses retournées", len(analyses))
    return analyses


# ============================================================
# GET /analyses/{id} — Détail complet d'une analyse
# ============================================================

@router.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Détail d'une analyse",
    description="Retourne le détail complet : dépendances, vulnérabilités, Docker, recommandations.",
)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
) -> Analysis:
    """Retourne une analyse par son ID avec toutes ses relations."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()

    if not analysis:
        logger.warning("Analyse #%d non trouvée", analysis_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analyse #{analysis_id} non trouvée",
        )

    logger.info("Détail de l'analyse #%d retourné", analysis_id)
    return analysis


# ============================================================
# GET /analyses/{id}/report — Télécharger le rapport PDF
# ============================================================

@router.get(
    "/analyses/{analysis_id}/report",
    summary="Télécharger le rapport PDF",
    description="Retourne le rapport PDF généré pour cette analyse.",
)
def download_report(
    analysis_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """
    Télécharge le rapport PDF d'une analyse.
    Pour l'instant, retourne un placeholder — sera complété avec report_service.py.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analyse #{analysis_id} non trouvée",
        )

    # Placeholder — sera remplacé par FileResponse quand report_service sera implémenté
    return {
        "message": f"Rapport pour l'analyse #{analysis_id} — sera disponible après implémentation du report_service",
        "analysis_id": analysis_id,
        "status": analysis.status.value,
    }


# ============================================================
# GET /health — État de l'API
# ============================================================

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Vérification de l'état de l'API",
    description="Vérifie que l'API et la base de données fonctionnent.",
)
def health_check(
    db: Session = Depends(get_db),
) -> dict:
    """Vérifie la connexion à la base et retourne le statut."""
    try:
        db.execute(db.bind.dialect.do_ping(db.connection()) if False else __import__("sqlalchemy").text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        logger.error("Erreur de connexion à la base : %s", str(e))
        db_status = "disconnected"

    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "database": db_status,
    }
