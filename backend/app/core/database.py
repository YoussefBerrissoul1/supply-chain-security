"""
Configuration de la connexion à la base de données PostgreSQL.
Fournit l'engine SQLAlchemy, la session factory et la classe Base.
"""

import logging
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)


# Engine : pool de connexions vers PostgreSQL
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,      # Affiche les requêtes SQL en mode debug
    pool_pre_ping=True,       # Vérifie que la connexion est vivante avant usage
)

# Session factory : crée une nouvelle session par requête
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Classe de base pour tous les modèles SQLAlchemy du projet."""
    pass


def get_db() -> Generator[Session, None, None]:
    """
    Dépendance FastAPI : fournit une session DB par requête.
    La session est automatiquement fermée après usage.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        logger.debug("Session DB fermée")
