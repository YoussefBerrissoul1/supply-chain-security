"""
Modèle Dependency — représente une dépendance détectée dans un dépôt.
Chaque dépendance est liée à une Analysis et peut avoir plusieurs Vulnerability.
"""

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Dependency(Base):
    """
    Table 'dependencies' — dépendances extraites des fichiers
    (requirements.txt, package.json, pom.xml, etc.).
    """
    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)
    is_outdated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_dev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- Relations ---
    analysis = relationship("Analysis", back_populates="dependencies")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="dependency", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Dependency(id={self.id}, name='{self.name}', version='{self.version}')>"
