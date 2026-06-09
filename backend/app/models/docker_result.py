"""
Modèle DockerResult — résultat du scan Docker/Trivy.
Relation 1-to-1 avec Analysis.
"""

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DockerResult(Base):
    """
    Table 'docker_results' — résultat de l'analyse Trivy
    sur le Dockerfile du dépôt (si présent).
    """
    __tablename__ = "docker_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    base_image: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerabilities_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    has_root_user: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    image_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)

    # --- Relations ---
    analysis = relationship("Analysis", back_populates="docker_result")

    def __repr__(self) -> str:
        return f"<DockerResult(id={self.id}, image='{self.base_image}', vulns={self.vulnerabilities_count})>"
