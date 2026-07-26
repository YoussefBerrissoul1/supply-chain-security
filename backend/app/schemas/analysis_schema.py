
"""
Schemas Pydantic pour la validation des requêtes et réponses API.
Séparation claire entre Input (Request) et Output (Response).
"""

import re
from datetime import datetime

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


# ── Regex de validation ────────────────────────────────────────────────────────
# URL GitHub : https://github.com/{owner}/{repo}[.git][/]
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+(\.git)?/?$"
)

# Nom d'image Docker : image[:tag] ou registry/image[:tag]
# Accepte: python:3.12, ghcr.io/user/image:latest, ubuntu
# Rejette: ../../etc/passwd, http://, espaces, caractères spéciaux
# Règle: pas de '//' (URL complète), commence obligatoirement par [a-z0-9]
_DOCKER_IMAGE_RE = re.compile(
    r"^(?!.*://)(?!.*\.\.)([a-z0-9][a-z0-9._/:-]{0,249})$"
)


# ============================================================
# SCHEMAS D'ENTRÉE (ce que l'utilisateur envoie)
# ============================================================


class AnalysisBase(BaseModel):
    repo_url: str = Field(
        ...,
        max_length=500,
        description="URL complète du dépôt GitHub ou nom de l'image Docker",
    )
    scan_type: Literal["standard", "deep"] = Field(
        default="standard",
        description="Type de scan : standard (rapide) ou deep (complet avec NVD+EPSS)",
    )
    target_type: Literal["github", "docker"] = Field(
        default="github",
        description="Type de cible : github (URL) ou docker (image name)",
    )

    @model_validator(mode="after")
    def validate_repo_url_by_target(self) -> "AnalysisBase":
        """
        SEC3 : Valide repo_url selon le target_type.
        Utilise model_validator (mode='after') pour avoir accès aux deux champs simultanément.

        Pour target_type='github' :
            - Doit correspondre à https://github.com/{owner}/{repo}
            - Rejette les URL internes, malformées, ou non-GitHub

        Pour target_type='docker' :
            - Doit être un nom d'image Docker valide (lowercase, pas de path traversal)
            - Rejette les URL, espaces, et caractères spéciaux dangereux
        """
        url = self.repo_url.strip()

        if self.target_type == "github":
            if not _GITHUB_URL_RE.match(url):
                raise ValueError(
                    "L'URL doit être une URL GitHub publique valide : "
                    "https://github.com/{owner}/{repo}"
                )
        elif self.target_type == "docker":
            url_lower = url.lower()
            if not _DOCKER_IMAGE_RE.match(url_lower):
                raise ValueError(
                    "Nom d'image Docker invalide. Format attendu : "
                    "image:tag ou registry/image:tag (ex: python:3.12-slim)"
                )
            # Normalisation en minuscules (Docker est case-insensitive)
            self.repo_url = url_lower

        return self


class AnalysisRequest(AnalysisBase):
    """
    Schema d'entrée pour lancer une analyse.
    Hérite de AnalysisBase avec toutes les validations SEC3.
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
    cvss_source: str
    fixed_version: str | None = None
    exploit_available: bool = False
    published_date: str | None = None
    epss_score: float | None = None    # Probabilité d'exploitation (0.0 – 1.0)
    cwe: str | None = None             # Type de faiblesse (ex: "CWE-79")

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
    created_at: datetime

    status: Literal["pending", "running", "done", "failed", "cancelled", "incomplete"]
    cancel_requested: bool
    security_score: float | None = None
    
    # Nouvelles métadonnées de l'analyse
    commit_sha: str | None = None
    cve_service_version: str | None = None
    dependencies_truncated: bool = False
    dependencies_scanned_count: int | None = None
    dependencies_total_count: int | None = None
    deps_detected: int | None = None
    deps_analyzed: int | None = None
    coverage_percent: float | None = None

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
