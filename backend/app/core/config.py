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

    # --- APIs de vulnérabilités ---
    # OSV API : gratuite, pas de clé requise (prioritaire)
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    # NVD API : gratuite mais limitée à 5 req/30s sans clé, 50 req/30s avec clé
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""  # Optionnel mais recommandé (inscription gratuite sur nvd.nist.gov)

    # --- Timeouts HTTP (en secondes) ---
    HTTP_TIMEOUT: int = 30          # Timeout par requête individuelle
    CVE_MAX_CONCURRENT: int = 5     # Nombre de requêtes simultanées max (éviter le rate limit)

    # --- IA ---
    GEMINI_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""
    AI_PROVIDER: str = "gemini"     # "gemini" ou "openrouter"

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
