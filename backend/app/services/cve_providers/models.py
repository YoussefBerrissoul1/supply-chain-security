"""
Modèles de données pour les résultats CVE.
Partagés par tous les providers (OSV, GHSA, NVD) et le moteur de corrélation.

v2.0 : Ajout des champs epss_score et cwe pour enrichissement NVD (Phase 3 audit).
"""
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """
    Niveaux de sévérité des CVE, basés sur le score CVSS.
    On utilise str + Enum pour sérialisation JSON directe.
    """
    CRITICAL = "CRITICAL"   # CVSS >= 9.0
    HIGH     = "HIGH"       # CVSS 7.0 – 8.9
    MEDIUM   = "MEDIUM"     # CVSS 4.0 – 6.9
    LOW      = "LOW"        # CVSS 0.1 – 3.9
    NONE     = "NONE"       # CVSS = 0.0 ou inconnu


def cvss_to_severity(cvss_score: float) -> Severity:
    """Convertit un score CVSS numérique en niveau de sévérité."""
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    elif cvss_score >= 7.0:
        return Severity.HIGH
    elif cvss_score >= 4.0:
        return Severity.MEDIUM
    elif cvss_score > 0.0:
        return Severity.LOW
    else:
        return Severity.NONE


@dataclass
class VulnerabilityResult:
    """
    Représente une vulnérabilité (CVE) détectée pour une dépendance.

    Champs enrichis NVD (Phase 3 audit) :
      - epss_score    : Probabilité d'exploitation dans 30 jours (0.0 – 1.0)
      - cwe           : Type de faiblesse (ex: "CWE-79", "CWE-89")
    """
    cve_id:        str
    cvss_score:    float
    severity:      Severity
    description:   str
    source:        str = "OSV"
    cvss_source:   str = "OSV"
    fixed_version: str | None = None
    exploit_available: bool = False
    published_date: str | None = None
    # Champs enrichis NVD (optionnels)
    epss_score:    float | None = None   # EPSS : 0.0 = faible risque, 1.0 = très probable
    cwe:           str | None = None     # Ex: "CWE-79" (XSS), "CWE-89" (SQLi)

    def to_dict(self) -> dict:
        return {
            "cve_id":             self.cve_id,
            "cvss_score":         self.cvss_score,
            "severity":           self.severity.value,
            "description":        self.description,
            "source":             self.source,
            "cvss_source":        self.cvss_source,
            "fixed_version":      self.fixed_version,
            "exploit_available":  self.exploit_available,
            "published_date":     self.published_date,
            "epss_score":         self.epss_score,
            "cwe":                self.cwe,
        }
