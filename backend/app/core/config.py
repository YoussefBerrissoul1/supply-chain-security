"""
Configuration centralisée de l'application.
Lit les variables depuis le fichier .env via Pydantic BaseSettings.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Classe de configuration principale.
    Chaque attribut correspond à une variable du fichier .env.
    Pydantic valide automatiquement les types au démarrage.
    """

    # --- Application ---
    APP_NAME: str = "Supply Chain Security Platform"
    APP_ENV: str = "development"
    DEBUG: bool = True
    APP_VERSION: str = "1.0.0"

    # --- API ---
    API_V1_PREFIX: str = "/api/v1"

    # --- Base de données ---
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "supply_chain_security"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "momo12"

    # --- GitHub ---
    CLONE_DIRECTORY: str = "./temp_repositories"
    ENABLE_PRIVATE_REPOS: bool = False

    # --- Outils de sécurité ---
    TRIVY_PATH: str = "trivy"

    # --- IA ---
    GEMINI_API_KEY: str = ""

    # --- Rapports ---
    REPORT_OUTPUT_DIR: str = "./reports"

    # --- Logging ---
    LOG_LEVEL: str = "INFO"

    @property
    def DATABASE_URL(self) -> str:
        """Construit l'URL de connexion PostgreSQL à partir des variables individuelles."""
        return (
            f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent.parent / ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Instance unique importable partout : from app.core.config import settings
settings = Settings()
