"""
Service Score — calcule le Security Score global /100 d'un dépôt analysé.

Position dans la chaîne d'analyse :
    [cve_service] ──┐
    [docker_scanner] ├── [score_service] → Security Score /100
    [dep_scanner] ───┘

Ce service reçoit :
    - Les résultats CVE    (dict de VulnerabilityResult)
    - Les résultats Docker (DockerScanResult ou None)
    - Les dépendances      (list de DependencyInfo)

Ce service retourne :
    - ScoreResult : score global, détail des pénalités, interprétation

ALGORITHME (défini dans CLAUDE.md) :
    Score = 100 − Σ pénalités   (minimum 0)

    | Facteur                       | Pénalité | Plafond |
    |-------------------------------|----------|---------|
    | CVE CRITICAL (CVSS ≥ 9.0)    | −15 pts  | max −45 |
    | CVE HIGH     (CVSS 7.0–8.9)  | −8 pts   | max −24 |
    | CVE MEDIUM   (CVSS 4.0–6.9)  | −3 pts   | max −15 |
    | Package abandonné (> 2 ans)   | −5 pts   | max −20 |
    | Image Docker vulnérable       | −10 pts  | max −20 |
    | Mauvaise pratique Docker      | −5 pts   | max −10 |

INTERPRÉTATION DU SCORE :
     0 – 29  → CRITIQUE  🔴
    30 – 49  → MAUVAIS   🟠
    50 – 69  → MOYEN     🟡
    70 – 89  → BON       🟢
    90 – 100 → EXCELLENT ✅
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from app.services.cve_service import VulnerabilityResult, Severity
from app.services.dependency_scanner import DependencyInfo
from app.services.docker_scanner import DockerScanResult

logger = logging.getLogger(__name__)


# ==============================================================
# CONSTANTES DE L'ALGORITHME DE SCORING
# (Valeurs définies dans CLAUDE.md — ne pas modifier sans validation)
# ==============================================================

# Pénalités par vulnérabilité (en points)
PENALTY_CRITICAL: float = 15.0   # CVE CVSS >= 9.0
PENALTY_HIGH: float = 8.0        # CVE CVSS 7.0-8.9
PENALTY_MEDIUM: float = 3.0      # CVE CVSS 4.0-6.9
PENALTY_LOW: float = 0.0         # CVE CVSS < 4.0 -- pas de penalite directe

# Plafonds par catégorie (limite max de déduction)
CAP_CRITICAL: float = 45.0
CAP_HIGH: float = 24.0
CAP_MEDIUM: float = 15.0

# Pénalités Docker
PENALTY_DOCKER_VULN: float = 10.0   # Par tranche de vulnérabilités Docker significatives
PENALTY_DOCKER_ROOT: float = 5.0    # Image qui tourne en root
CAP_DOCKER_VULN: float = 20.0
CAP_DOCKER_PRACTICES: float = 10.0

# Package abandonné (pas de mise à jour depuis N mois)
PACKAGE_ABANDONED_MONTHS: int = 24  # 2 ans
PENALTY_ABANDONED: float = 5.0
CAP_ABANDONED: float = 20.0


# ==============================================================
# ÉNUMÉRATION : NIVEAU DE RISQUE
# ==============================================================

class RiskLevel(str, Enum):
    """
    Interprétation qualitative du score de sécurité.
    Valeurs définies dans CLAUDE.md.
    """
    CRITIQUE  = "CRITIQUE"   # 0–29
    MAUVAIS   = "MAUVAIS"    # 30–49
    MOYEN     = "MOYEN"      # 50–69
    BON       = "BON"        # 70–89
    EXCELLENT = "EXCELLENT"  # 90–100


def score_to_risk_level(score: float) -> RiskLevel:
    """
    Convertit un score numérique en niveau de risque qualitatif.

    Paramètres :
        score : score entre 0.0 et 100.0

    Retourne :
        RiskLevel
    """
    if score >= 90:
        return RiskLevel.EXCELLENT
    elif score >= 70:
        return RiskLevel.BON
    elif score >= 50:
        return RiskLevel.MOYEN
    elif score >= 30:
        return RiskLevel.MAUVAIS
    else:
        return RiskLevel.CRITIQUE


# ==============================================================
# STRUCTURE DE DONNÉES : UNE LIGNE DE PÉNALITÉ
# ==============================================================

@dataclass
class PenaltyLine:
    """
    Représente une pénalité individuelle appliquée au score.
    Utilisée pour générer un rapport détaillé des déductions.

    Attributs :
        category    : catégorie (ex: "CVE CRITICAL", "Docker Root User")
        count       : nombre d'occurrences (ex: 3 vulnérabilités CRITICAL)
        unit_penalty: pénalité unitaire (ex: 15 pts par CRITICAL)
        raw_penalty : pénalité brute avant plafonnement (count × unit)
        applied     : pénalité réellement appliquée (après plafond)
        cap         : plafond appliqué (0 si pas de plafond)
    """
    category:     str
    count:        int
    unit_penalty: float
    raw_penalty:  float
    applied:      float
    cap:          float = 0.0

    def was_capped(self) -> bool:
        """Retourne True si la pénalité a été plafonnée."""
        return self.cap > 0 and self.raw_penalty > self.cap

    def to_dict(self) -> dict:
        return {
            "category":     self.category,
            "count":        self.count,
            "unit_penalty": self.unit_penalty,
            "applied":      self.applied,
            "capped":       self.was_capped(),
        }


# ==============================================================
# STRUCTURE DE DONNÉES : RÉSULTAT DU SCORE
# ==============================================================

@dataclass
class ScoreResult:
    """
    Résultat complet du calcul de sécurité.

    Attributs :
        final_score     : score final entre 0.0 et 100.0
        risk_level      : interprétation qualitative (CRITIQUE, MAUVAIS, ...)
        total_penalties : somme de toutes les pénalités appliquées
        penalties       : liste détaillée de chaque pénalité
        cve_counts      : { "CRITICAL": 3, "HIGH": 7, ... }
        total_cve       : nombre total de CVE
        docker_score    : score de l'image Docker (None si pas de Docker)
        has_docker      : True si un Dockerfile a été analysé
        computed_at     : timestamp du calcul
    """
    final_score:     float
    risk_level:      RiskLevel
    total_penalties: float
    penalties:       list[PenaltyLine] = field(default_factory=list)
    cve_counts:      dict[str, int] = field(default_factory=dict)
    total_cve:       int = 0
    docker_score:    Optional[float] = None
    has_docker:      bool = False
    computed_at:     str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Sérialise pour les logs, la base et le rapport PDF."""
        return {
            "final_score":     self.final_score,
            "risk_level":      self.risk_level.value,
            "total_penalties": self.total_penalties,
            "total_cve":       self.total_cve,
            "cve_counts":      self.cve_counts,
            "has_docker":      self.has_docker,
            "docker_score":    self.docker_score,
            "computed_at":     self.computed_at,
            "penalties":       [p.to_dict() for p in self.penalties],
        }

    def get_summary_line(self) -> str:
        """Retourne une ligne résumé lisible pour les logs."""
        return (
            f"Score: {self.final_score}/100 | "
            f"Risque: {self.risk_level.value} | "
            f"CVE: {self.total_cve} | "
            f"Pénalités: -{self.total_penalties}pts"
        )


# ==============================================================
# CALCUL DES PÉNALITÉS CVE
# ==============================================================

def _compute_cve_penalties(
    cve_results: dict[str, list[VulnerabilityResult]],
) -> tuple[list[PenaltyLine], dict[str, int], int]:
    """
    Calcule les pénalités dues aux CVE détectées.

    Algorithme :
        1. Compter les CVE par sévérité (en dédupliquant par CVE ID)
        2. Appliquer la pénalité unitaire × count
        3. Plafonner chaque catégorie

    Note sur la déduplication :
        Un même CVE peut apparaître dans plusieurs dépendances.
        On compte le nombre unique de CVE ID par sévérité pour éviter
        de pénaliser plusieurs fois le même problème.

    Paramètres :
        cve_results : dict retourné par cve_service.scan_all_vulnerabilities()

    Retourne :
        tuple(penalties, cve_counts_by_severity, total_cve)
    """

    # Déduplication : un CVE ID unique par sévérité
    # { "CVE-2023-001": "CRITICAL", "CVE-2023-002": "HIGH", ... }
    unique_cves: dict[str, Severity] = {}

    for dep_key, vulns in cve_results.items():
        for vuln in vulns:
            if vuln.cve_id not in unique_cves:
                unique_cves[vuln.cve_id] = vuln.severity
            else:
                # Si le même CVE est trouvé avec des sévérités différentes,
                # garder la plus élevée (cas rare mais possible selon la source)
                existing = unique_cves[vuln.cve_id]
                severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]
                if severity_order.index(vuln.severity) < severity_order.index(existing):
                    unique_cves[vuln.cve_id] = vuln.severity

    # Compter par sévérité
    counts = {
        "CRITICAL": 0,
        "HIGH":     0,
        "MEDIUM":   0,
        "LOW":      0,
        "NONE":     0,
    }
    for cve_id, severity in unique_cves.items():
        counts[severity.value] = counts.get(severity.value, 0) + 1

    total_cve = sum(counts.values())
    penalties: list[PenaltyLine] = []

    # --- CRITICAL ---
    if counts["CRITICAL"] > 0:
        raw = counts["CRITICAL"] * PENALTY_CRITICAL
        applied = min(raw, CAP_CRITICAL)
        penalties.append(PenaltyLine(
            category="CVE CRITICAL (CVSS >= 9.0)",
            count=counts["CRITICAL"],
            unit_penalty=PENALTY_CRITICAL,
            raw_penalty=raw,
            applied=applied,
            cap=CAP_CRITICAL,
        ))
        logger.info(
            "Pénalité CVE CRITICAL : %d × %.0f = %.0f (plafonné à %.0f) → appliqué : %.0f",
            counts["CRITICAL"], PENALTY_CRITICAL, raw, CAP_CRITICAL, applied,
        )

    # --- HIGH ---
    if counts["HIGH"] > 0:
        raw = counts["HIGH"] * PENALTY_HIGH
        applied = min(raw, CAP_HIGH)
        penalties.append(PenaltyLine(
            category="CVE HIGH (CVSS 7.0-8.9)",
            count=counts["HIGH"],
            unit_penalty=PENALTY_HIGH,
            raw_penalty=raw,
            applied=applied,
            cap=CAP_HIGH,
        ))
        logger.info(
            "Pénalité CVE HIGH : %d × %.0f = %.0f (plafonné à %.0f) → appliqué : %.0f",
            counts["HIGH"], PENALTY_HIGH, raw, CAP_HIGH, applied,
        )

    # --- MEDIUM ---
    if counts["MEDIUM"] > 0:
        raw = counts["MEDIUM"] * PENALTY_MEDIUM
        applied = min(raw, CAP_MEDIUM)
        penalties.append(PenaltyLine(
            category="CVE MEDIUM (CVSS 4.0-6.9)",
            count=counts["MEDIUM"],
            unit_penalty=PENALTY_MEDIUM,
            raw_penalty=raw,
            applied=applied,
            cap=CAP_MEDIUM,
        ))
        logger.info(
            "Pénalité CVE MEDIUM : %d × %.0f = %.0f (plafonné à %.0f) → appliqué : %.0f",
            counts["MEDIUM"], PENALTY_MEDIUM, raw, CAP_MEDIUM, applied,
        )

    # LOW et NONE → pas de pénalité directe (signalées mais pas déduites)
    if counts["LOW"] > 0:
        logger.info("CVE LOW : %d trouvées — informatives, pas de pénalité directe", counts["LOW"])

    return penalties, counts, total_cve


# ==============================================================
# CALCUL DES PÉNALITÉS DOCKER
# ==============================================================

def _compute_docker_penalties(
    docker_result: Optional[DockerScanResult],
) -> list[PenaltyLine]:
    """
    Calcule les pénalités liées à l'image Docker.

    Deux types de pénalités :
        1. Vulnérabilités Trivy (HIGH/CRITICAL dans l'image OS)
        2. Mauvaises pratiques (root user, secrets, latest tag)

    Paramètres :
        docker_result : résultat du docker_scanner, ou None

    Retourne :
        Liste de PenaltyLine (peut être vide)
    """
    if docker_result is None:
        return []

    penalties: list[PenaltyLine] = []
    vuln_by_sev = docker_result.vulnerabilities_by_severity

    # --- Pénalité vulnérabilités Docker (Trivy) ---
    # On compte les HIGH + CRITICAL dans l'image comme "image vulnérable"
    critical_docker = vuln_by_sev.get("CRITICAL", 0)
    high_docker = vuln_by_sev.get("HIGH", 0)
    severe_docker = critical_docker + high_docker

    if severe_docker > 0:
        # Pénalité progressive : 10 pts par tranche de 10 vulns sévères
        tranche_count = max(1, (severe_docker + 9) // 10)  # arrondi supérieur
        raw = tranche_count * PENALTY_DOCKER_VULN
        applied = min(raw, CAP_DOCKER_VULN)
        penalties.append(PenaltyLine(
            category=f"Image Docker vulnérable ({severe_docker} CRITICAL+HIGH dans l'OS)",
            count=severe_docker,
            unit_penalty=PENALTY_DOCKER_VULN,
            raw_penalty=raw,
            applied=applied,
            cap=CAP_DOCKER_VULN,
        ))
        logger.info(
            "Pénalité Docker vulns : %d HIGH+CRITICAL → -%.0f pts",
            severe_docker, applied,
        )

    # --- Pénalité mauvaises pratiques Docker ---
    bad_practices = 0

    if docker_result.has_root_user:
        bad_practices += 1
        logger.info("Pénalité Docker : image tourne en root")

    # Compter les problèmes Dockerfile (latest, secrets, etc.)
    bad_practices += len(docker_result.dockerfile_issues)

    if bad_practices > 0:
        raw = bad_practices * PENALTY_DOCKER_ROOT
        applied = min(raw, CAP_DOCKER_PRACTICES)
        penalties.append(PenaltyLine(
            category=f"Mauvaises pratiques Docker ({bad_practices} problème(s) détecté(s))",
            count=bad_practices,
            unit_penalty=PENALTY_DOCKER_ROOT,
            raw_penalty=raw,
            applied=applied,
            cap=CAP_DOCKER_PRACTICES,
        ))
        logger.info(
            "Pénalité Docker pratiques : %d problème(s) → -%.0f pts",
            bad_practices, applied,
        )

    return penalties


# ==============================================================
# CALCUL DES PÉNALITÉS PACKAGES ABANDONNÉS
# ==============================================================

def _compute_abandoned_penalties(
    dependencies: list[DependencyInfo],
) -> list[PenaltyLine]:
    """
    Détecte les dépendances avec version trop ancienne.

    Note : sans accès aux dates de publication des packages (nécessite
    des API supplémentaires comme PyPI JSON API ou npm registry),
    on détecte l'obsolescence par des heuristiques sur les versions.

    Heuristiques utilisées :
        - Version 0.x.x → package en développement (risque élevé)
        - Version majeure très basse vs taille du marché → potentiellement abandonné

    Pour un PFE, cette pénalité est calculée mais basée sur is_outdated
    qui sera mis à jour par la route /analyze lors de l'implémentation complète.

    Paramètres :
        dependencies : liste de DependencyInfo

    Retourne :
        Liste de PenaltyLine (souvent vide à ce stade)
    """
    # Dans la version actuelle, is_outdated est False par défaut
    # car la détection des dates de publication n'est pas encore implémentée
    # Cette fonction est prête pour l'extension future

    abandoned_count = sum(
        1 for dep in dependencies
        if getattr(dep, "is_outdated", False)
    )

    if abandoned_count == 0:
        return []

    raw = abandoned_count * PENALTY_ABANDONED
    applied = min(raw, CAP_ABANDONED)

    penalty = PenaltyLine(
        category=f"Packages abandonnes (> {PACKAGE_ABANDONED_MONTHS} mois sans mise a jour)",
        count=abandoned_count,
        unit_penalty=PENALTY_ABANDONED,
        raw_penalty=raw,
        applied=applied,
        cap=CAP_ABANDONED,
    )

    logger.info(
        "Pénalité packages abandonnés : %d → -%.0f pts",
        abandoned_count, applied,
    )

    return [penalty]


# ==============================================================
# FONCTION PRINCIPALE : CALCULER LE SCORE
# ==============================================================

def compute_security_score(
    cve_results: dict[str, list[VulnerabilityResult]],
    docker_result: Optional[DockerScanResult] = None,
    dependencies: Optional[list[DependencyInfo]] = None,
) -> ScoreResult:
    """
    Fonction principale du service de scoring.
    Assemble tous les résultats partiels et calcule le score global.

    Paramètres :
        cve_results   : dict retourné par cve_service.scan_all_vulnerabilities()
        docker_result : objet retourné par docker_scanner.scan_docker() (ou None)
        dependencies  : liste retournée par dependency_scanner.scan_dependencies()

    Retourne :
        ScoreResult complet avec score, niveau de risque et détail des pénalités
    """
    logger.info("=== Calcul du Security Score ===")

    all_penalties: list[PenaltyLine] = []

    # --- Calcul pénalités CVE ---
    cve_penalties, cve_counts, total_cve = _compute_cve_penalties(cve_results)
    all_penalties.extend(cve_penalties)

    # --- Calcul pénalités Docker ---
    docker_penalties = _compute_docker_penalties(docker_result)
    all_penalties.extend(docker_penalties)

    # --- Calcul pénalités packages abandonnés ---
    dep_list = dependencies or []
    abandoned_penalties = _compute_abandoned_penalties(dep_list)
    all_penalties.extend(abandoned_penalties)

    # --- Calcul du score final ---
    total_deduction = sum(p.applied for p in all_penalties)
    raw_score = 100.0 - total_deduction
    final_score = round(max(0.0, raw_score), 1)

    risk_level = score_to_risk_level(final_score)

    result = ScoreResult(
        final_score=final_score,
        risk_level=risk_level,
        total_penalties=round(total_deduction, 1),
        penalties=all_penalties,
        cve_counts=cve_counts,
        total_cve=total_cve,
        docker_score=docker_result.image_score if docker_result else None,
        has_docker=docker_result is not None,
    )

    logger.info(result.get_summary_line())

    # Log du détail des pénalités
    if all_penalties:
        logger.info("Détail des pénalités :")
        for p in all_penalties:
            capped_note = f" (plafonné à {p.cap})" if p.was_capped() else ""
            logger.info(
                "  − %s : %d × %.0f = -%.0f pts%s",
                p.category, p.count, p.unit_penalty, p.applied, capped_note,
            )
    else:
        logger.info("Aucune pénalité — Score parfait !")

    return result


# ==============================================================
# FONCTION UTILITAIRE : GÉNÉRER UN RAPPORT TEXTUEL DU SCORE
# ==============================================================

def format_score_report(score_result: ScoreResult) -> str:
    """
    Génère un rapport textuel lisible du score.
    Utilisé pour les logs détaillés et potentiellement le rapport PDF.

    Paramètres :
        score_result : ScoreResult retourné par compute_security_score()

    Retourne :
        str : rapport formaté multi-lignes
    """
    lines = [
        "=" * 55,
        f"  SECURITY SCORE : {score_result.final_score:.1f} / 100",
        f"  NIVEAU DE RISQUE : {score_result.risk_level.value}",
        "=" * 55,
        "",
        f"  Vulnerabilites detectees : {score_result.total_cve}",
    ]

    # Afficher les CVE par sévérité
    for sev, count in score_result.cve_counts.items():
        if count > 0:
            lines.append(f"    {sev:10} : {count}")

    if score_result.has_docker:
        lines.append(f"  Score image Docker : {score_result.docker_score}/100")

    lines.append("")
    lines.append("  Deductions appliquees :")

    if score_result.penalties:
        for p in score_result.penalties:
            capped = " [PLAFONNE]" if p.was_capped() else ""
            lines.append(f"    - {p.category}")
            lines.append(f"      {p.count} x {p.unit_penalty:.0f}pts = -{p.applied:.0f}pts{capped}")
    else:
        lines.append("    Aucune penalite")

    lines.append("")
    lines.append(f"  Total deduit : -{score_result.total_penalties:.1f} pts")
    lines.append(f"  Score final  : 100 - {score_result.total_penalties:.1f} = {score_result.final_score:.1f}")
    lines.append("=" * 55)

    return "\n".join(lines)


# ==============================================================
# INTERPRÉTATION : RECOMMANDATIONS RAPIDES PAR NIVEAU
# ==============================================================

RISK_RECOMMENDATIONS: dict[RiskLevel, list[str]] = {
    RiskLevel.CRITIQUE: [
        "[CRITIQUE] URGENT : Des vulnerabilites CRITIQUES necessitent une action immediate.",
        "Mettre a jour TOUTES les dependances vers leurs dernieres versions stables.",
        "Ne pas deployer en production avant resolution des CVE CRITICAL.",
        "Activer les alertes de securite GitHub Dependabot sur ce depot.",
    ],
    RiskLevel.MAUVAIS: [
        "[MAUVAIS] Des vulnerabilites HIGH necessitent une attention prioritaire.",
        "Planifier les mises a jour des dependances dans les 2 prochaines semaines.",
        "Verifier si des correctifs sont disponibles (voir 'fixed_version' dans le rapport).",
    ],
    RiskLevel.MOYEN: [
        "[MOYEN] Niveau de risque moyen -- des ameliorations sont recommandees.",
        "Mettre a jour les dependances avec des vulnerabilites MEDIUM.",
        "Ajouter des tests de securite dans le pipeline CI/CD.",
    ],
    RiskLevel.BON: [
        "[BON] Bon niveau de securite -- quelques ajustements mineurs possibles.",
        "Continuer a surveiller les nouvelles CVE avec des outils automatises.",
        "Mettre a jour regulierement les dependances (au moins mensuellement).",
    ],
    RiskLevel.EXCELLENT: [
        "[EXCELLENT] Excellent niveau de securite -- felicitations !",
        "Maintenir cette discipline en automatisant les mises a jour (Dependabot).",
        "Effectuer des audits reguliers pour rester a ce niveau.",
    ],
}


def get_quick_recommendations(score_result: ScoreResult) -> list[str]:
    """
    Retourne une liste de recommandations rapides selon le niveau de risque.

    Paramètres :
        score_result : ScoreResult retourné par compute_security_score()

    Retourne :
        Liste de strings — recommandations prêtes à afficher
    """
    return RISK_RECOMMENDATIONS.get(score_result.risk_level, [])
