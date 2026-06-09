"""
Modèle Report — rapports PDF/HTML générés pour une analyse.
Stocke le chemin du fichier et le format.
"""

import enum

from sqlalchemy import Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ReportFormat(str, enum.Enum):
    """Formats de rapport supportés."""
    PDF = "pdf"
    HTML = "html"


class Report(Base):
    """
    Table 'reports' — rapports générés par ReportLab.
    Chaque rapport est associé à une analyse.
    """
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)

    # --- Relations ---
    analysis = relationship("Analysis", back_populates="reports")

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, format='{self.format.value}', path='{self.file_path}')>"
