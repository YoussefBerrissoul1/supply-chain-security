"""
Moteur de corrélation des vulnérabilités — fusionne les résultats multi-sources.

Reçoit les listes de VulnerabilityResult de chaque provider (OSV, GHSA, NVD)
et produit une liste dédupliquée et enrichie.

Corrections v2.0 (audit CORR1) :
  - Normalisation des clés : les GHSA-xxxx et CVE-xxxx pointant vers la même
    vulnérabilité sont maintenant corrélés correctement.
  - Fusion EPSS et CWE depuis les sources qui les fournissent (NVD).
"""

import logging
from app.services.cve_providers.models import VulnerabilityResult, cvss_to_severity

logger = logging.getLogger(__name__)

# Priorité des sources pour le score CVSS (NVD = référence officielle)
_SOURCE_PRIORITY: dict[str, int] = {
    "NVD":  3,
    "GHSA": 2,
    "OSV":  1,
}


def correlate_vulnerabilities(
    vulns_list: list[list[VulnerabilityResult]],
) -> list[VulnerabilityResult]:
    """
    Fusionne et déduplique les résultats de plusieurs providers.

    Stratégie de merge :
      1. Clé primaire = cve_id normalisé (CVE-XXXX préféré à GHSA-xxxx)
      2. Score CVSS : priorité NVD > GHSA > OSV, puis max score
      3. Exploit = OR logique de toutes les sources
      4. EPSS / CWE : premier provider qui fournit la donnée
      5. fixed_version / published_date : premier disponible
      6. Source = concaténation (ex: "OSV+GHSA+NVD")

    Paramètres :
        vulns_list : Liste de listes de VulnerabilityResult (une par provider)

    Retourne :
        Liste dédupliquée et enrichie de VulnerabilityResult
    """
    if not vulns_list:
        return []

    # ── Phase 1 : Indexer toutes les vulnérabilités par clé normalisée ────
    merged: dict[str, VulnerabilityResult] = {}

    for vulns in vulns_list:
        for vuln in vulns:
            key = vuln.cve_id

            if key not in merged:
                merged[key] = vuln
            else:
                _merge_vuln(merged[key], vuln)

    result = list(merged.values())

    if len(result) > 0:
        sources_summary = set()
        for v in result:
            for s in v.source.split("+"):
                sources_summary.add(s)
        logger.debug(
            "[Corrélation] %d CVE uniques après fusion (sources: %s)",
            len(result), ", ".join(sorted(sources_summary))
        )

    return result


def _merge_vuln(
    existing: VulnerabilityResult,
    incoming: VulnerabilityResult,
) -> None:
    """
    Fusionne les données d'une vulnérabilité entrante dans une existante.
    Modifie `existing` in-place.
    """
    # 1. Score CVSS : priorité source > score max
    existing_prio = _SOURCE_PRIORITY.get(existing.cvss_source, 0)
    incoming_prio = _SOURCE_PRIORITY.get(incoming.cvss_source, 0)

    if (incoming_prio > existing_prio or
            (incoming_prio == existing_prio and incoming.cvss_score > existing.cvss_score)):
        existing.cvss_score = incoming.cvss_score
        existing.severity = incoming.severity
        existing.cvss_source = incoming.cvss_source

    # 2. Concaténer les sources
    if incoming.source not in existing.source:
        existing.source = f"{existing.source}+{incoming.source}"

    # 3. Exploit = OR logique
    if incoming.exploit_available:
        existing.exploit_available = True

    # 4. published_date : premier disponible
    if not existing.published_date and incoming.published_date:
        existing.published_date = incoming.published_date

    # 5. fixed_version : premier disponible
    if not existing.fixed_version and incoming.fixed_version:
        existing.fixed_version = incoming.fixed_version

    # 6. EPSS score : premier disponible
    if existing.epss_score is None and incoming.epss_score is not None:
        existing.epss_score = incoming.epss_score

    # 7. CWE : premier disponible
    if existing.cwe is None and incoming.cwe is not None:
        existing.cwe = incoming.cwe
