"""
Modèle Analysis — table centrale de l'application.
Représente une analyse de sécurité complète d'un dépôt GitHub.
"""

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AnalysisStatus(str, enum.Enum):
    """Statuts possibles d'une analyse."""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Analysis(Base):
    """
    Table 'analyses' — enregistre chaque analyse de dépôt.
    Relations : → plusieurs Dependency, Recommendation, Report + un DockerResult.

    Champs ajoutés (rétrocompatibles — nullable avec valeurs par défaut) :
        cve_service_version      : version du moteur CVE ayant produit les résultats.
                                   Permet de détecter les analyses obsolètes à re-scanner.
        dependencies_truncated   : True si les dépendances ont été tronquées (trop nombreuses).
        dependencies_scanned_count : nombre de dépendances effectivement analysées.
        dependencies_total_count   : nombre total de dépendances dans le repo.
    """
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repo_url: Mapped[str] = mapped_column(String(500), nullable=False)
    repo_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(
        String(50), default="github", server_default="github", nullable=False
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus), default=AnalysisStatus.PENDING, nullable=False
    )
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_type: Mapped[str] = mapped_column(
        String(50), default="standard", server_default="standard", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # --- Point 2 : Traçabilité du moteur CVE ---
    # Permet de détecter les analyses produites par une ancienne version du moteur
    # (scores CVSS figés, exploits non détectés, etc.) et de les re-scanner.
    # Exemple de valeur : "2.0.0"
    cve_service_version: Mapped[str | None] = mapped_column(
        String(20), nullable=True, default=None
    )

    # --- Point 4 : Informations de troncature ---
    # Affichées dans le rapport : "Scan partiel : 100/174 dépendances analysées"
    dependencies_truncated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    dependencies_scanned_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dependencies_total_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Relations (back_populates = bidirectionnel) ---
    dependencies = relationship(
        "Dependency", back_populates="analysis", cascade="all, delete-orphan"
    )
    docker_result = relationship(
        "DockerResult", back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    recommendations = relationship(
        "Recommendation", back_populates="analysis", cascade="all, delete-orphan"
    )
    reports = relationship(
        "Report", back_populates="analysis", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Analysis(id={self.id}, repo='{self.repo_name}', status='{self.status.value}')>"
