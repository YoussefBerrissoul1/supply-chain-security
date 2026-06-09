"""
Package models — importe tous les modèles SQLAlchemy.
Cet import centralisé est nécessaire pour qu'Alembic détecte
toutes les tables lors de la génération des migrations.
"""

from app.models.analysis import Analysis, AnalysisStatus
from app.models.dependency import Dependency
from app.models.docker_result import DockerResult
from app.models.recommendation import Recommendation, TargetType
from app.models.report import Report, ReportFormat
from app.models.vulnerability import SeverityLevel, Vulnerability

__all__ = [
    "Analysis",
    "AnalysisStatus",
    "Dependency",
    "Vulnerability",
    "SeverityLevel",
    "DockerResult",
    "Recommendation",
    "TargetType",
    "Report",
    "ReportFormat",
]
