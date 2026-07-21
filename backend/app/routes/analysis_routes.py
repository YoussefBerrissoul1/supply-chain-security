"""
Routes FastAPI pour l'analyse de securite.
Definit les 5 endpoints obligatoires de l'API.

Etape 16 : POST /analyze lance maintenant l'analyse COMPLETE en arriere-plan
via FastAPI BackgroundTasks. Le client recoit une reponse immediate avec
status=PENDING, puis l'analyse tourne en background et met a jour le statut
en base (RUNNING -> DONE ou FAILED).
"""

import logging
import traceback
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.database import get_db, SessionLocal
from app.models.analysis import Analysis, AnalysisStatus
from app.models.dependency import Dependency
from app.models.docker_result import DockerResult
from app.models.recommendation import Recommendation
from app.models.report import Report, ReportFormat
from app.models.vulnerability import Vulnerability, SeverityLevel
from app.schemas.analysis_schema import (
    AnalysisDetailResponse,
    AnalysisListResponse,
    AnalysisRequest,
    HealthResponse,
)

# --- Services ---
from app.services.github_analyzer import (
    validate_github_url,
    clone_repository,
    detect_dependency_files,
    cleanup_repository,
    GitHubAnalyzerError,
)
from app.services.dependency_scanner import scan_dependencies, DependencyInfo
from app.services.cve_service import scan_all_vulnerabilities, VulnerabilityResult, Severity, CVE_SERVICE_VERSION
from app.services.docker_scanner import (
    scan_docker,
    run_trivy_scan,
    parse_trivy_report,
    calculate_image_score,
    is_trivy_available,
)
from app.services.score_service import compute_security_score
from app.services.ai_service import generate_recommendations
from app.services.report_service import generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================
# FONCTION D'ANALYSE COMPLETE EN ARRIERE-PLAN (Etape 16)
# ============================================================

def run_full_analysis(analysis_id: int, repo_url: str, scan_type: str = "standard") -> None:
    """
    Execute la chaine d'analyse complete en arriere-plan.

    Cette fonction est appelee par BackgroundTasks et ne doit jamais
    lever d'exception non geree (sinon le worker crash silencieusement).

    Chaine d'execution :
        1. Validation URL
        2. Clonage du depot GitHub
        3. Scan des dependances
        4. Detection des CVE (OSV + NVD)
        5. Scan Docker (Trivy + analyse statique)
        6. Calcul du Security Score /100
        7. Generation des recommandations IA
        8. Generation du rapport PDF
        9. Sauvegarde en base + mise a jour statut -> DONE

    Parametres :
        analysis_id : ID de l'analyse en base (deja cree avec statut PENDING)
        repo_url    : URL GitHub a analyser
    """
    # Creer une session DB independante (le background task tourne hors requete)
    db = SessionLocal()
    repo_path = None

    try:
        # --- Mettre a jour le statut -> RUNNING ---
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            logger.error("Analyse #%d introuvable en base", analysis_id)
            return

        analysis.status = AnalysisStatus.RUNNING
        db.commit()
        logger.info("=== Demarrage analyse #%d pour %s ===", analysis_id, repo_url)

        # ----------------------------------------------------------
        # ETAPE 1 : Validation de l'URL
        # ----------------------------------------------------------
        validated_url = validate_github_url(repo_url)
        repo_name = validated_url.rstrip("/").split("/")[-1].replace(".git", "")
        logger.info("[1/8] URL validee : %s", validated_url)

        # ----------------------------------------------------------
        # ETAPE 2 : Clonage du depot
        # ----------------------------------------------------------
        repo_path = clone_repository(validated_url)
        logger.info("[2/8] Depot clone dans : %s", repo_path)

        # ----------------------------------------------------------
        # ETAPE 3 : Detection + scan des dependances
        # ----------------------------------------------------------
        dependency_files = detect_dependency_files(repo_path)
        ecosystems = list(dependency_files.keys())
        logger.info("[3/8] Ecosystemes detectes : %s", ecosystems)

        dependencies: list[DependencyInfo] = []
        if dependency_files:
            dependencies = scan_dependencies(repo_path, dependency_files)
            logger.info("[3/8] %d dependances scannees", len(dependencies))

        # Sauvegarder les dependances en base
        for dep in dependencies:
            db_dep = Dependency(
                analysis_id=analysis_id,
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                is_outdated=dep.is_outdated if hasattr(dep, 'is_outdated') else False,
                is_dev=dep.is_dev if hasattr(dep, 'is_dev') else False,
            )
            db.add(db_dep)
        db.commit()

        # ----------------------------------------------------------
        # ETAPE 4 : Detection des CVE (OSV + NVD)
        # ----------------------------------------------------------
        cve_results: dict[str, list[VulnerabilityResult]] = {}
        if dependencies:
            try:
                # Passer le scan_type au service CVE (standard ou deep)
                # standard : OSV + NVD si cvss=0, 8 workers parallèles
                # deep     : OSV + NVD systématique, 3 workers (rate limit NVD)
                cve_results = scan_all_vulnerabilities(dependencies, scan_type=scan_type)

                # Extraire et sauvegarder les métadonnées de troncature (Point 4)
                scan_meta = cve_results.pop("__scan_meta__", {})
                if scan_meta:
                    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
                    if analysis:
                        analysis.dependencies_truncated = scan_meta.get("deps_truncated", False)
                        analysis.dependencies_scanned_count = scan_meta.get("deps_scanned")
                        analysis.dependencies_total_count = scan_meta.get("deps_total")
                        # Point 2 : enregistrer la version du moteur CVE
                        analysis.cve_service_version = CVE_SERVICE_VERSION
                        db.commit()

                total_cves = sum(len(v) for v in cve_results.values())
                logger.info("[4/8] %d CVE detectees (mode %s)", total_cves, scan_type)
            except Exception as cve_err:
                # Une erreur réseau (timeout OSV/NVD) ne doit pas faire échouer toute l'analyse.
                # On continue avec cve_results vide : les dépendances seront en base
                # mais sans vulns. Le score sera plus optimiste mais l'analyse ne crash pas.
                logger.error(
                    "[4/8] Erreur lors du scan CVE (OSV/NVD) : %s. "
                    "L'analyse continue sans données CVE.",
                    cve_err,
                )

        # Sauvegarder les vulnerabilites en base
        # Il faut relier chaque vuln a la dependance correspondante
        db_deps = db.query(Dependency).filter(Dependency.analysis_id == analysis_id).all()
        dep_map = {f"{d.name}@{d.version}": d for d in db_deps}

        for dep_key, vulns in cve_results.items():
            # Ignorer la clé méta interne injectée par scan_all_vulnerabilities
            if dep_key == "__scan_meta__":
                continue
            db_dep = dep_map.get(dep_key)
            if not db_dep:
                # Essayer de trouver par nom seul
                dep_name = dep_key.split("@")[0] if "@" in dep_key else dep_key
                for k, v in dep_map.items():
                    if k.startswith(dep_name + "@"):
                        db_dep = v
                        break

            if not db_dep:
                continue

            for vuln in vulns:
                # Mapper le Severity du service vers le SeverityLevel du modele
                sev_mapping = {
                    "CRITICAL": SeverityLevel.CRITICAL,
                    "HIGH": SeverityLevel.HIGH,
                    "MEDIUM": SeverityLevel.MEDIUM,
                    "LOW": SeverityLevel.LOW,
                }
                sev_value = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
                db_sev = sev_mapping.get(sev_value, SeverityLevel.LOW)

                db_vuln = Vulnerability(
                    dependency_id=db_dep.id,
                    cve_id=vuln.cve_id,
                    cvss_score=vuln.cvss_score,
                    severity=db_sev,
                    description=vuln.description or "",
                    fixed_version=vuln.fixed_version,
                    exploit_available=vuln.exploit_available,
                    published_date=vuln.published_date,
                )
                db.add(db_vuln)
        db.commit()

        # ----------------------------------------------------------
        # ETAPE 5 : Scan Docker
        # ----------------------------------------------------------
        dockerfile_paths = dependency_files.get("docker", [])
        docker_result = None
        if dockerfile_paths:
            docker_result = scan_docker(repo_path, dockerfile_paths)
            logger.info("[5/8] Scan Docker termine")

            # Sauvegarder en base
            if docker_result:
                db_docker = DockerResult(
                    analysis_id=analysis_id,
                    base_image=docker_result.base_image,
                    vulnerabilities_count=docker_result.vulnerabilities_count,
                    has_root_user=docker_result.has_root_user,
                    image_score=docker_result.image_score,
                )
                db.add(db_docker)
                db.commit()
        else:
            logger.info("[5/8] Pas de Dockerfile — scan Docker ignore")

        # ----------------------------------------------------------
        # ETAPE 6 : Calcul du Security Score /100
        # ----------------------------------------------------------
        score_result = compute_security_score(
            cve_results=cve_results,
            docker_result=docker_result,
            dependencies=dependencies,
        )
        analysis.security_score = score_result.final_score
        db.commit()
        logger.info("[6/8] Score de securite : %.1f/100 (%s)",
                    score_result.final_score, score_result.risk_level.value)

        # ----------------------------------------------------------
        # ETAPE 7 : Recommandations IA (Gemini -> OpenRouter -> Statique)
        # ----------------------------------------------------------
        recommendations = generate_recommendations(
            db=db,
            analysis_id=analysis_id,
            score_result=score_result,
            cve_results=cve_results,
            repo_name=repo_name,
            ecosystems=ecosystems,
            total_deps=len(dependencies),
        )
        logger.info("[7/8] %d recommandations generees", len(recommendations))

        # ----------------------------------------------------------
        # ETAPE 8 : Generation du rapport PDF
        # ----------------------------------------------------------
        # Charger explicitement toutes les relations (joinedload) avant de passer
        # l'objet Analysis à ReportLab. Sans ça, SQLAlchemy ferait du lazy loading
        # sur une session potentiellement fermée => erreur.
        analysis_for_pdf = (
            db.query(Analysis)
            .options(
                joinedload(Analysis.dependencies).joinedload(Dependency.vulnerabilities),
                joinedload(Analysis.docker_result),
                joinedload(Analysis.recommendations),
                joinedload(Analysis.reports),
            )
            .filter(Analysis.id == analysis_id)
            .first()
        )
        if analysis_for_pdf:
            try:
                pdf_path = generate_pdf_report(analysis_for_pdf)

                # Sauvegarder la reference du rapport en base
                db_report = Report(
                    analysis_id=analysis_id,
                    format=ReportFormat.PDF,
                    file_path=pdf_path,
                )
                db.add(db_report)
                db.commit()
                logger.info("[8/8] Rapport PDF genere : %s", pdf_path)
            except Exception as e:
                logger.warning("Generation PDF echouee (non bloquant) : %s", e)
        else:
            logger.warning("[8/8] Analyse #%d introuvable pour generation PDF", analysis_id)

        # ----------------------------------------------------------
        # SUCCES : Mettre a jour le statut -> DONE
        # ----------------------------------------------------------
        analysis.status = AnalysisStatus.DONE
        db.commit()
        logger.info("=== Analyse #%d terminee avec succes (score: %.1f/100) ===",
                    analysis_id, score_result.final_score)

    except GitHubAnalyzerError as e:
        # Erreur connue (URL invalide, repo prive, etc.)
        logger.error("Analyse #%d echouee (GitHub) : %s", analysis_id, e)
        _mark_analysis_failed(db, analysis_id, str(e))

    except Exception as e:
        # Erreur inattendue
        logger.error("Analyse #%d echouee (erreur inattendue) : %s", analysis_id, e)
        logger.error(traceback.format_exc())
        _mark_analysis_failed(db, analysis_id, f"Erreur interne : {type(e).__name__}")

    finally:
        # Toujours nettoyer le depot clone
        if repo_path and repo_path.exists():
            try:
                cleanup_repository(repo_path)
                logger.info("Depot temporaire nettoye : %s", repo_path)
            except Exception:
                logger.warning("Nettoyage du depot echoue (non bloquant)")

        db.close()


def _mark_analysis_failed(db: Session, analysis_id: int, error_message: str) -> None:
    """Met a jour le statut de l'analyse a FAILED."""
    try:
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if analysis:
            analysis.status = AnalysisStatus.FAILED
            db.commit()
    except Exception:
        db.rollback()


# ============================================================
# FONCTION D'ANALYSE DOCKER EN ARRIERE-PLAN
# ============================================================

def run_docker_analysis(analysis_id: int, image_name: str) -> None:
    """Execute le scan Docker (Trivy) complet en arriere-plan."""
    db = SessionLocal()

    try:
        analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
        if not analysis:
            return

        analysis.status = AnalysisStatus.RUNNING
        db.commit()
        logger.info("=== Demarrage analyse Docker #%d pour %s ===", analysis_id, image_name)

        if not is_trivy_available():
            raise Exception("Trivy n'est pas installe ou introuvable dans le PATH.")

        # Correction B : fallback scan_type si la colonne est None (anciennes entrees en base)
        scan_type = analysis.scan_type or "standard"
        logger.info("Type de scan : %s", scan_type)

        trivy_data = run_trivy_scan(image_name, scan_type=scan_type)
        if trivy_data is None:
            raise Exception(f"Impossible de scanner l'image '{image_name}'.")

        vulns_by_severity, detailed_vulns = parse_trivy_report(trivy_data)
        total_vulns = sum(vulns_by_severity.values())

        # Enregistrer DockerResult
        image_score = calculate_image_score(vulns_by_severity, True, image_name)
        
        db_docker = DockerResult(
            analysis_id=analysis_id,
            base_image=image_name,
            vulnerabilities_count=total_vulns,
            has_root_user=True,
            image_score=image_score,
        )
        db.add(db_docker)
        
        # Enregistrer les dépendances et vulnérabilités détaillées
        deps_dict = {}
        for vuln in detailed_vulns:
            if vuln.pkg_name not in deps_dict:
                deps_dict[vuln.pkg_name] = {
                    "installed_version": vuln.installed_version,
                    "vulns": []
                }
            deps_dict[vuln.pkg_name]["vulns"].append(vuln)
            
        cve_results = {}
        for pkg_name, data in deps_dict.items():
            dep = Dependency(
                analysis_id=analysis_id,
                name=pkg_name,
                version=data["installed_version"],
                ecosystem="docker"
            )
            db.add(dep)
            db.flush()
            
            dep_key = f"{pkg_name}@{data['installed_version']}"
            cve_results[dep_key] = []
            for v in data["vulns"]:
                # Convertir la sévérité au format attendu (UNKNOWN -> LOW par défaut)
                try:
                    sev = SeverityLevel(v.severity)
                except ValueError:
                    sev = SeverityLevel.LOW
                    
                vuln_record = Vulnerability(
                    dependency_id=dep.id,
                    cve_id=v.cve_id,
                    cvss_score=v.cvss_score,
                    severity=sev,
                    description=v.description,
                    fixed_version=v.fixed_version,
                    published_date=v.published_date
                )
                db.add(vuln_record)
                
                # Construire un vrai VulnerabilityResult pour l'IA
                # (generate_recommendations attend dict[str, list[VulnerabilityResult]])
                severity_mapping = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                ai_severity = severity_mapping.get(sev.value, Severity.LOW)
                cve_results[dep_key].append(VulnerabilityResult(
                    cve_id=v.cve_id,
                    severity=ai_severity,
                    cvss_score=v.cvss_score,
                    description=v.description or "",
                    source="trivy",
                    fixed_version=v.fixed_version,
                    exploit_available=False,
                    published_date=v.published_date,
                ))

        db.commit()

        # Calcul du score Docker proprement avec compute_security_score
        from app.services.docker_scanner import DockerScanResult
        docker_scan_obj = DockerScanResult(
            base_image=image_name,
            vulnerabilities_count=total_vulns,
            vulnerabilities_by_severity=vulns_by_severity,
            has_root_user=True,
            image_score=image_score,
            dockerfile_issues=[],
        )
        score_result = compute_security_score(
            cve_results={},
            docker_result=docker_scan_obj,
            dependencies=[],
        )
        final_score = score_result.final_score
        analysis.security_score = final_score
        db.commit()

        # Generer recs IA 
        try:
            generate_recommendations(
                db=db, analysis_id=analysis_id, score_result=score_result,
                cve_results=cve_results, repo_name=image_name, ecosystems=["docker"], total_deps=len(deps_dict)
            )
        except Exception as ai_err:
            logger.warning("Recommandations IA non generees pour Docker #%d : %s", analysis_id, ai_err)

        analysis.status = AnalysisStatus.DONE
        db.commit()
        logger.info("=== Analyse Docker #%d terminee (score=%.1f) ===", analysis_id, image_score)

    except Exception as e:
        logger.error("Analyse Docker #%d echouee : %s", analysis_id, e)
        _mark_analysis_failed(db, analysis_id, str(e))
    finally:
        db.close()


# ============================================================
# POST /analyze — Lancer une analyse GitHub
# ============================================================

@router.post(
    "/analyze",
    response_model=AnalysisListResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Lancer une analyse de securite (GitHub)",
    description="Soumet une URL GitHub pour analyse (scan Standard ou Deep). "
                "Retourne immediatement avec status=PENDING. L'analyse tourne en arriere-plan.",
)
def create_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Analysis:
    # --- Nettoyage et validation de l'URL ---
    repo_url_str = str(request.repo_url).strip().rstrip("/")
    if repo_url_str.endswith(".git"):
        repo_url_str = repo_url_str[:-4]

    try:
        validated_url = validate_github_url(repo_url_str)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"URL GitHub invalide : {exc}",
        )

    repo_name = validated_url.rstrip("/").split("/")[-1]
    scan_type = request.scan_type if request.scan_type in ("standard", "deep") else "standard"

    # --- Correction A : protection contre les doubles scans ---
    # Si une analyse PENDING ou RUNNING existe déjà pour ce repo, on la retourne
    # plutôt que d'en créer une nouvelle (qui provoquerait un conflit de cache Trivy).
    existing = db.query(Analysis).filter(
        Analysis.repo_url == validated_url,
        Analysis.target_type == "github",
        Analysis.status.in_([AnalysisStatus.PENDING, AnalysisStatus.RUNNING]),
    ).first()
    if existing:
        logger.info(
            "Analyse #%d déjà en cours pour '%s' (%s) — retour de l'existante",
            existing.id, repo_name, existing.status.value,
        )
        return existing

    logger.info("Nouvelle analyse %s demandee pour : %s", scan_type.upper(), repo_name)

    analysis = Analysis(
        repo_url=validated_url,
        repo_name=repo_name,
        target_type="github",
        status=AnalysisStatus.PENDING,
        scan_type=scan_type,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    background_tasks.add_task(run_full_analysis, analysis.id, validated_url, scan_type)
    logger.info("Analyse #%d creee (%s) — scan lance en arriere-plan", analysis.id, scan_type)

    return analysis


# ============================================================
# GET /analyses — Historique des analyses
# ============================================================

@router.get(
    "/analyses",
    response_model=list[AnalysisListResponse],
    summary="Historique des analyses",
    description="Retourne les dernières analyses, optionnellement filtrées par type.",
)
def list_analyses(
    db: Session = Depends(get_db),
    limit: int = 20,
    target_type: str | None = None,
) -> list[Analysis]:
    """Retourne les N dernieres analyses (par defaut 20)."""
    query = db.query(Analysis)
    
    if target_type:
        query = query.filter(Analysis.target_type == target_type)
        
    analyses = query.order_by(Analysis.created_at.desc()).limit(limit).all()
    
    logger.info("Historique demande (type=%s) : %d analyses retournees", target_type, len(analyses))
    return analyses


# ============================================================
# GET /analyses/{id} — Detail complet d'une analyse
# ============================================================

@router.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisDetailResponse,
    summary="Detail d'une analyse",
    description="Retourne le detail complet : dependances, vulnerabilites, Docker, recommandations.",
)
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
) -> Analysis:
    """Retourne une analyse par son ID avec toutes ses relations."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()

    if not analysis:
        logger.warning("Analyse #%d non trouvee", analysis_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analyse #{analysis_id} non trouvee",
        )

    logger.info("Detail de l'analyse #%d retourne", analysis_id)
    return analysis


# ============================================================
# GET /analyses/{id}/progress — Progression en temps reel
# ============================================================

@router.get(
    "/analyses/{analysis_id}/progress",
    summary="Progression d'une analyse en cours",
    description="Retourne la progression detaillee : deps trouvees, CVE detectees, statut.",
)
def get_analysis_progress(
    analysis_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """
    Endpoint de progression pour l'affichage progressif dans l'interface.
    Retourne des statistiques partielles meme si l'analyse est encore RUNNING.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analyse #{analysis_id} non trouvee")

    # Compter ce qui est deja en base (meme en cours d'analyse)
    total_deps = db.query(Dependency).filter(Dependency.analysis_id == analysis_id).count()

    total_vulns = 0
    vuln_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    dep_ids = [d.id for d in db.query(Dependency.id).filter(Dependency.analysis_id == analysis_id).all()]
    if dep_ids:
        vulns = db.query(Vulnerability).filter(Vulnerability.dependency_id.in_(dep_ids)).all()
        total_vulns = len(vulns)
        for v in vulns:
            key = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            if key in vuln_by_sev:
                vuln_by_sev[key] += 1

    total_recs = db.query(Recommendation).filter(Recommendation.analysis_id == analysis_id).count()
    has_docker = db.query(DockerResult).filter(DockerResult.analysis_id == analysis_id).first() is not None

    return {
        "id": analysis_id,
        "status": analysis.status.value,
        "scan_type": analysis.scan_type,
        "target_type": analysis.target_type,
        "security_score": analysis.security_score,
        "total_deps": total_deps,
        "total_vulns": total_vulns,
        "vulns_by_severity": vuln_by_sev,
        "total_recommendations": total_recs,
        "has_docker": has_docker,
    }


# ============================================================
# GET /analyses/{id}/report — Telecharger le rapport PDF
# ============================================================

@router.get(
    "/analyses/{analysis_id}/report",
    summary="Telecharger le rapport PDF",
    description="Retourne le rapport PDF genere pour cette analyse.",
)
def download_report(
    analysis_id: int,
    db: Session = Depends(get_db),
):
    """
    Telecharge le rapport PDF d'une analyse terminee.
    Retourne un fichier PDF via FileResponse.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analyse #{analysis_id} non trouvee",
        )

    if analysis.status != AnalysisStatus.DONE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"L'analyse #{analysis_id} n'est pas terminee (statut: {analysis.status.value}). "
                   f"Le rapport sera disponible une fois l'analyse completee.",
        )

    # Chercher le rapport PDF en base
    report = (
        db.query(Report)
        .filter(Report.analysis_id == analysis_id, Report.format == ReportFormat.PDF)
        .first()
    )

    if not report or not Path(report.file_path).exists():
        # Generer le rapport a la volee si manquant
        try:
            pdf_path = generate_pdf_report(analysis)
            if not report:
                report = Report(
                    analysis_id=analysis_id,
                    format=ReportFormat.PDF,
                    file_path=pdf_path,
                )
                db.add(report)
                db.commit()
            else:
                report.file_path = pdf_path
                db.commit()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erreur lors de la generation du rapport : {e}",
            )

    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=f"rapport_securite_{analysis.repo_name}.pdf",
    )


# ============================================================
# GET /health — Etat de l'API
# ============================================================

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Verification de l'etat de l'API",
    description="Verifie que l'API et la base de donnees fonctionnent.",
)
def health_check(
    db: Session = Depends(get_db),
) -> dict:
    """Verifie la connexion a la base et retourne le statut."""
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        logger.error("Erreur de connexion a la base : %s", str(e))
        db_status = "disconnected"

    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "database": db_status,
    }


# ============================================================
# POST /analyze/docker — Scanner une image Docker Hub
# ============================================================

from pydantic import BaseModel as PydanticBaseModel

class ImageScanRequest(PydanticBaseModel):
    image_name: str
    scan_type: str = "standard"

@router.post(
    "/analyze/docker",
    response_model=AnalysisListResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Scanner une image Docker Hub",
)
def create_docker_analysis(
    request: ImageScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Analysis:
    image_name = request.image_name.strip()

    if not image_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le nom de l'image est requis.",
        )

    # --- Protection double scan Docker ---
    # Si la même image est déjà en cours de scan (PENDING ou RUNNING),
    # on retourne l'analyse existante plutôt qu'en créer une nouvelle.
    existing = db.query(Analysis).filter(
        Analysis.repo_url == image_name,
        Analysis.target_type == "docker",
        Analysis.status.in_([AnalysisStatus.PENDING, AnalysisStatus.RUNNING]),
    ).first()
    if existing:
        logger.info(
            "Image Docker '%s' déjà en cours de scan (#%d, %s) — retour de l'existante",
            image_name, existing.id, existing.status.value,
        )
        return existing

    logger.info("Nouvelle analyse Docker demandee : %s", image_name)

    # Valider le scan_type reçu du frontend ("standard" ou "deep")
    scan_type = request.scan_type if request.scan_type in ("standard", "deep") else "standard"

    analysis = Analysis(
        repo_url=image_name,
        repo_name=image_name,
        target_type="docker",
        status=AnalysisStatus.PENDING,
        scan_type=scan_type,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    background_tasks.add_task(run_docker_analysis, analysis.id, image_name)
    logger.info("Analyse Docker #%d creee (scan_type=%s)", analysis.id, scan_type)

    return analysis
