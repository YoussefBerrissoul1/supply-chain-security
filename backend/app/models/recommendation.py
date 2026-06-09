"""
Modèle Recommendation — suggestions IA générées pour une analyse.
Générées par Gemini ou OpenRouter selon la configuration.
"""

import enum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class TargetType(str, enum.Enum):
    """Type de cible de la recommandation."""
    DEPENDENCY = "dependency"
    DOCKER = "docker"
    GLOBAL = "global"


class Recommendation(Base):
    """
    Table 'recommendations' — recommandations IA par analyse.
    Chaque recommandation cible un aspect spécifique (dépendance, Docker, global).
    """
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    target_type: Mapped[TargetType] = mapped_column(
        Enum(TargetType), nullable=False
    )
    recommendation_text: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)

    # --- Relations ---
    analysis = relationship("Analysis", back_populates="recommendations")

    def __repr__(self) -> str:
        return f"<Recommendation(id={self.id}, type='{self.target_type.value}', provider='{self.provider}')>"
