"""
Schemas Pydantic pour la validation des requêtes et réponses API.
Séparation claire entre Input (Request) et Output (Response).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ============================================================
# SCHEMAS D'ENTRÉE (ce que l'utilisateur envoie)
# ============================================================


class AnalysisRequest(BaseModel):
    """
    Schema d'entrée pour lancer une analyse.
    L'utilisateur envoie uniquement l'URL du dépôt GitHub.
    """
    repo_url: HttpUrl = Field(
        ...,
        description="URL complète du dépôt GitHub à analyser",
        examples=["https://github.com/fastapi/fastapi"],
    )
    scan_type: str = Field(
        default="standard",
        description="Type de scan : standard (rapide via OSV) ou deep (complet via NVD)",
        examples=["standard", "deep"],
    )


# ============================================================
# SCHEMAS DE SORTIE (ce que l'API retourne)
# ============================================================


class VulnerabilityResponse(BaseModel):
    """Détail d'une vulnérabilité (CVE) détectée."""
    id: int
    cve_id: str
    cvss_score: float
    severity: str
    description: str

    model_config = ConfigDict(from_attributes=True)


class DependencyResponse(BaseModel):
    """Détail d'une dépendance avec ses vulnérabilités."""
    id: int
    name: str
    version: str
    ecosystem: str
    is_outdated: bool
    vulnerabilities: list[VulnerabilityResponse] = []

    model_config = ConfigDict(from_attributes=True)


class DockerResultResponse(BaseModel):
    """Résultat du scan Docker/Trivy."""
    id: int
    base_image: str
    vulnerabilities_count: int
    has_root_user: bool
    image_score: float

    model_config = ConfigDict(from_attributes=True)


class RecommendationResponse(BaseModel):
    """Recommandation IA générée."""
    id: int
    target_type: str
    recommendation_text: str
    provider: str

    model_config = ConfigDict(from_attributes=True)


class ReportResponse(BaseModel):
    """Référence vers un rapport généré."""
    id: int
    format: str
    file_path: str

    model_config = ConfigDict(from_attributes=True)


# ============================================================
# SCHEMAS D'ANALYSE (résumé et détail complet)
# ============================================================


class AnalysisListResponse(BaseModel):
    """
    Version résumée d'une analyse — utilisée pour l'historique (GET /analyses).
    Ne contient PAS les dépendances ni les vulnérabilités (trop lourd).
    """
    id: int
    repo_url: str
    repo_name: str
    status: str
    security_score: float | None = None
    scan_type: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalysisDetailResponse(BaseModel):
    """
    Détail complet d'une analyse — utilisé pour GET /analyses/{id}.
    Contient TOUT : dépendances, vulnérabilités, Docker, recommandations, rapports.
    """
    id: int
    repo_url: str
    repo_name: str
    status: str
    security_score: float | None = None
    scan_type: str
    created_at: datetime
    dependencies: list[DependencyResponse] = []
    docker_result: DockerResultResponse | None = None
    recommendations: list[RecommendationResponse] = []
    reports: list[ReportResponse] = []

    model_config = ConfigDict(from_attributes=True)


# ============================================================
# SCHEMA DE SANTÉ (health check)
# ============================================================


class HealthResponse(BaseModel):
    """Réponse du endpoint /health."""
    status: str = "ok"
    version: str
    database: str
