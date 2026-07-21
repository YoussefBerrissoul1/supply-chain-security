
"""
Schemas Pydantic pour la validation des requêtes et réponses API.
Séparation claire entre Input (Request) et Output (Response).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ============================================================
# SCHEMAS D'ENTRÉE (ce que l'utilisateur envoie)
# ============================================================


class AnalysisBase(BaseModel):
    repo_url: str = Field(..., max_length=500, description="URL complète du dépôt GitHub ou nom de l'image Docker")
    scan_type: str = Field(
        default="standard",
        description="Type de scan : standard (rapide via OSV) ou deep (complet via NVD)",
        examples=["standard", "deep"],
    )
    target_type: str = Field(
        default="github",
        description="Type de cible : github ou docker",
        examples=["github", "docker"],
    )

class AnalysisRequest(AnalysisBase):
    """
    Schema d'entrée pour lancer une analyse.
    """
    pass


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
    fixed_version: str | None = None
    exploit_available: bool = False   # True si un exploit public est connu (champ de la DB)
    published_date: str | None = None

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


class AnalysisListResponse(AnalysisBase):
    """
    Version résumée d'une analyse — utilisée pour l'historique (GET /analyses).
    Ne contient PAS les dépendances ni les vulnérabilités (trop lourd).
    """
    id: int
    repo_name: str
    status: str
    security_score: float | None = None
    created_at: datetime

    # Point 2 : traçabilité du moteur CVE
    cve_service_version: str | None = None

    # Point 4 : informations de troncature (affichables dans les rapports)
    # Ex: "Scan partiel : 100/174 dépendances analysées"
    dependencies_truncated: bool = False
    dependencies_scanned_count: int | None = None
    dependencies_total_count: int | None = None

    model_config = ConfigDict(from_attributes=True)


class AnalysisDetailResponse(AnalysisListResponse):
    """
    Détail complet d'une analyse — utilisé pour GET /analyses/{id}.
    Contient TOUT : dépendances, vulnérabilités, Docker, recommandations, rapports.
    """
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
