"""
Service CVE — détecte les vulnérabilités dans les dépendances.

Architecture Multi-Sources v3.1 (optimisée querybatch) :
  Mode standard : OSV /v1/querybatch uniquement (1 seule requête HTTP)
  Mode deep     : OSV + GHSA + NVD + EPSS (FIRST.org) + GHSA-REST

Règle de séparation standard / deep :
  Standard = OSV uniquement → rapide, sans clé API, sans enrichissement NVD
  Deep     = OSV + GHSA (si GITHUB_TOKEN) + NVD + EPSS + GHSA-REST

Gains de performance vs v2.0 :
  - v2.0 : N requêtes HTTP vers OSV (1 par dépendance) en parallèle (3-5 workers)
  - v3.1 : 1 requête HTTP vers OSV querybatch + enrichissement NVD/GHSA parallèle (deep only)
  - Sur un repo de 50 deps en mode standard : ~50 requêtes → 1 requête
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.core.config import settings
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.models import VulnerabilityResult, Severity, cvss_to_severity
from app.services.cve_providers.osv_provider import OSVProvider
from app.services.cve_providers.nvd_provider import NVDProvider
from app.services.cve_providers.ghsa_provider import GHSAProvider
from app.services.cve_providers.ghsa_rest_provider import fetch_ghsa_advisory_by_cve
from app.services.cve_providers.correlation_engine import correlate_vulnerabilities
from app.services.cve_providers.utils import fetch_epss_scores

# Re-export pour compatibilité avec les imports existants (analysis_routes.py)
from app.services.cve_providers.models import VulnerabilityResult, Severity  # noqa: F811

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────────────────────
SCAN_TIMEOUT_STANDARD: float = 180.0   # 3 min pour le mode standard
SCAN_TIMEOUT_DEEP:     float = 900.0   # 15 min pour le mode deep
MAX_DEPS_STANDARD:     int   = 60      # Limite soft en mode standard
MAX_DEPS_DEEP:         int   = 150     # Limite soft en mode deep
CVE_SERVICE_VERSION:   str   = "3.1.0" # v3.1 = querybatch + architecture multi-sources

# Nombre max de workers pour l'enrichissement NVD/GHSA en parallèle
NVD_ENRICHMENT_WORKERS = 5
GHSA_WORKERS = 5


class CVEServiceError(Exception):
    """Levée uniquement en cas d'échec total non récupérable."""
    pass


def scan_all_vulnerabilities(
    dependencies: list[DependencyInfo],
    scan_type: str = "standard",
    timeout_seconds: float | None = None,
) -> dict[str, list[VulnerabilityResult]]:
    """
    Fonction principale du service CVE.
    
    Flux d'exécution optimisé (v3.1) :
      1. OSV querybatch → 1 requête HTTP pour toutes les dépendances
      2. GHSA (si GITHUB_TOKEN) → enrichissement parallèle par dépendance
      3. Corrélation OSV + GHSA
      4. Enrichissement NVD → par CVE-ID unique en parallèle
      
    Retourne :
      dict["{name}@{version}" -> list[VulnerabilityResult]]
      + clé spéciale "__scan_meta__" avec les métadonnées du scan
    """
    if not dependencies:
        return {}

    # ── Timeout ───────────────────────────────────────────────────────────────
    if timeout_seconds is None:
        timeout_seconds = SCAN_TIMEOUT_DEEP if scan_type == "deep" else SCAN_TIMEOUT_STANDARD
    scan_deadline = time.monotonic() + timeout_seconds

    # ── Troncature ───────────────────────────────────────────────────────────
    deps_total = len(dependencies)
    max_deps = MAX_DEPS_DEEP if scan_type == "deep" else MAX_DEPS_STANDARD
    deps_truncated = deps_total > max_deps
    if deps_truncated:
        logger.info(
            "[CVE] Troncature : %d→%d dépendances (mode %s)",
            deps_total, max_deps, scan_type
        )
        dependencies = dependencies[:max_deps]
    deps_scanned = len(dependencies)

    # ── Filtrage Docker (pas de CVE API pour les layers Docker) ──────────────
    deps_to_scan = [d for d in dependencies if d.ecosystem != "docker"]

    results: dict[str, list[VulnerabilityResult]] = {}
    deps_analyzed_ok: set[str] = set()
    t_start_total = time.monotonic()

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 1 : OSV querybatch (1 seule requête HTTP)
    # ═══════════════════════════════════════════════════════════════════════════
    osv = OSVProvider()
    osv_results: dict[str, list[VulnerabilityResult]] = {}

    try:
        t0 = time.monotonic()
        logger.info("[CVE] Étape 1/3 — OSV querybatch (%d dépendances)", len(deps_to_scan))
        osv_results = osv.query_batch(deps_to_scan)
        t1 = time.monotonic()
        total_osv_vulns = sum(len(v) for v in osv_results.values())
        deps_with_vulns = sum(1 for v in osv_results.values() if v)
        logger.info(
            "[CVE] OSV terminé en %.2fs — %d dépendances analysées, "
            "%d avec vulnérabilités, %d CVE totales",
            t1 - t0, len(osv_results), deps_with_vulns, total_osv_vulns
        )
        # Toutes les deps retournées par OSV (même vides) comptent comme analysées
        for dep_key in osv_results:
            deps_analyzed_ok.add(dep_key)
    except Exception as e:
        logger.error("[CVE] OSV querybatch échoué : %s", e)
        # On continue sans OSV (résultats vides)

    if time.monotonic() > scan_deadline:
        logger.warning("[CVE] Timeout atteint après OSV — on retourne les résultats partiels")
        return _finalize_results(
            osv_results, deps_truncated, deps_scanned, deps_total,
            len(deps_analyzed_ok), len(deps_to_scan)
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 2 : GHSA enrichissement (optionnel, si GITHUB_TOKEN disponible)
    # ═══════════════════════════════════════════════════════════════════════════
    ghsa_results: dict[str, list[VulnerabilityResult]] = {}

    if scan_type == "deep" and settings.GITHUB_TOKEN:
        ghsa = GHSAProvider()
        logger.info("[CVE] Étape 2/3 — GHSA enrichissement (%d dépendances)", len(deps_to_scan))

        def _ghsa_one(dep: DependencyInfo) -> tuple[str, list[VulnerabilityResult]]:
            dep_key = f"{dep.name}@{dep.version}"
            try:
                vulns = ghsa.query(dep)
                return dep_key, vulns
            except Exception as e:
                logger.debug("[CVE] GHSA ignoré pour %s : %s", dep_key, e)
                return dep_key, []

        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=GHSA_WORKERS) as executor:
            futures = {executor.submit(_ghsa_one, dep): dep for dep in deps_to_scan}
            for future in as_completed(futures):
                if time.monotonic() > scan_deadline:
                    break
                try:
                    dep_key, vulns = future.result()
                    ghsa_results[dep_key] = vulns
                except Exception:
                    pass
        logger.info(
            "[CVE] GHSA terminé en %.2fs — %d dépendances avec vulnérabilités",
            time.monotonic() - t0,
            sum(1 for v in ghsa_results.values() if v)
        )
    elif scan_type == "deep" and not settings.GITHUB_TOKEN:
        logger.info("[CVE] Étape 2/3 — GHSA ignoré (GITHUB_TOKEN non défini)")
    else:
        logger.info("[CVE] Étape 2/3 — GHSA ignoré (mode standard)")

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 2b : Corrélation OSV + GHSA par dépendance
    # ═══════════════════════════════════════════════════════════════════════════
    for dep in deps_to_scan:
        dep_key = f"{dep.name}@{dep.version}"
        osv_vulns  = osv_results.get(dep_key, [])
        ghsa_vulns = ghsa_results.get(dep_key, [])

        # Construire les listes à corréler (seulement les sources non vides)
        sources = [s for s in [osv_vulns, ghsa_vulns] if s]

        if sources:
            results[dep_key] = correlate_vulnerabilities(sources)
        else:
            results[dep_key] = []

    if time.monotonic() > scan_deadline:
        logger.warning("[CVE] Timeout après corrélation OSV+GHSA")
        return _finalize_results(
            results, deps_truncated, deps_scanned, deps_total,
            len(deps_analyzed_ok), len(deps_to_scan)
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 3 : NVD enrichissement par CVE-ID (parallèle)
    # ═══════════════════════════════════════════════════════════════════════════
    # On enrichit uniquement si :
    #   - mode deep (toujours)
    #   - ou mode standard si le score CVSS est inconnu (0.0)

    nvd = NVDProvider()

    # Collecter les CVE uniques à enrichir
    all_cve_scored: list[tuple[str, float]] = []
    for dep_key, vulns in results.items():
        for vuln in vulns:
            if vuln.cve_id.startswith("CVE-"):
                all_cve_scored.append((vuln.cve_id, vuln.cvss_score))

    # Déduplication
    seen: set[str] = set()
    all_cve_scored_unique = []
    for cve_id, score in all_cve_scored:
        if cve_id not in seen:
            seen.add(cve_id)
            all_cve_scored_unique.append((cve_id, score))

    if scan_type == "deep":
        # Mode deep : enrichir TOUTES les CVE
        cve_to_enrich = [cve_id for cve_id, _ in all_cve_scored_unique]
        logger.info(
            "[CVE] Étape 3/3 — NVD enrichissement mode DEEP (%d CVE uniques)",
            len(cve_to_enrich)
        )
    else:
        cve_to_enrich = []
        logger.info(
            "[CVE] Étape 3/3 — NVD ignoré (mode standard, %d CVE disponibles via OSV seul)",
            len(all_cve_scored_unique)
        )

    if cve_to_enrich:
        nvd_enriched: dict[str, VulnerabilityResult | None] = {}

        def _nvd_one(cve_id: str) -> tuple[str, VulnerabilityResult | None]:
            try:
                return cve_id, nvd.enrich(cve_id)
            except Exception as e:
                logger.debug("[CVE] NVD ignoré pour %s : %s", cve_id, e)
                return cve_id, None

        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=NVD_ENRICHMENT_WORKERS) as executor:
            futures_nvd = {
                executor.submit(_nvd_one, cve_id): cve_id
                for cve_id in cve_to_enrich
            }
            for future in as_completed(futures_nvd):
                if time.monotonic() > scan_deadline:
                    break
                try:
                    cve_id, nvd_res = future.result()
                    nvd_enriched[cve_id] = nvd_res
                except Exception:
                    pass

        # Appliquer l'enrichissement NVD (CVSS, EPSS, CWE, exploit)
        nvd_improvements = 0
        for dep_key, vulns in results.items():
            for vuln in vulns:
                nvd_res = nvd_enriched.get(vuln.cve_id)
                if not nvd_res:
                    continue
                changed = False
                if nvd_res.cvss_score > vuln.cvss_score:
                    vuln.cvss_score  = nvd_res.cvss_score
                    vuln.severity    = cvss_to_severity(nvd_res.cvss_score)
                    vuln.cvss_source = "NVD"
                    changed = True
                # Toujours appliquer EPSS et CWE s'ils sont disponibles
                if nvd_res.epss_score is not None:
                    vuln.epss_score = nvd_res.epss_score
                    changed = True
                if nvd_res.cwe:
                    vuln.cwe = nvd_res.cwe
                    changed = True
                if nvd_res.exploit_available:
                    vuln.exploit_available = True
                    changed = True
                if changed:
                    nvd_improvements += 1
                # Mettre à jour la source
                if "NVD" not in vuln.source:
                    vuln.source = vuln.source + "+NVD"

        logger.info(
            "[CVE] NVD terminé en %.2fs — %d CVE enrichies / %d tentées",
            time.monotonic() - t0, nvd_improvements, len(cve_to_enrich)
        )
    else:
        logger.info("[CVE] Étape 3/3 — NVD enrichissement ignoré (aucune CVE éligible)")

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 4 : EPSS (Exploit Prediction Scoring System) — MODE DEEP UNIQUEMENT
    # Source : https://api.first.org/data/v1/epss
    # Appelé uniquement en mode deep (Q1 validé par l'utilisateur)
    # En mode standard, EPSS = None (pas de ralentissement)
    # ═══════════════════════════════════════════════════════════════════════════
    if scan_type == "deep" and time.monotonic() < scan_deadline:
        # Collecter toutes les CVE-IDs uniques détectées
        all_cve_ids = set()
        for dep_key, vulns in results.items():
            for vuln in vulns:
                if vuln.cve_id.startswith("CVE-") and vuln.epss_score is None:
                    all_cve_ids.add(vuln.cve_id)

        if all_cve_ids:
            logger.info(
                "[CVE] Étape 4/4 — EPSS enrichissement (mode DEEP) : %d CVE via FIRST.org",
                len(all_cve_ids)
            )
            t0 = time.monotonic()
            try:
                epss_data = fetch_epss_scores(list(all_cve_ids))
                epss_applied = 0
                for dep_key, vulns in results.items():
                    for vuln in vulns:
                        if vuln.cve_id in epss_data:
                            vuln.epss_score = epss_data[vuln.cve_id]
                            epss_applied += 1
                logger.info(
                    "[CVE] EPSS terminé en %.2fs — %d CVE enrichies",
                    time.monotonic() - t0, epss_applied
                )
            except Exception as epss_err:
                logger.warning("[CVE] EPSS ignoré (non bloquant) : %s", epss_err)
        else:
            logger.info("[CVE] Étape 4/4 — EPSS ignoré (toutes les CVE déjà enrichies ou aucune CVE)")
    else:
        if scan_type != "deep":
            logger.debug("[CVE] EPSS ignoré (mode standard) — activer mode deep pour l'enrichissement EPSS")

    # ═══════════════════════════════════════════════════════════════════════════
    # ÉTAPE 4b : GHSA REST enrichissement — MODE DEEP UNIQUEMENT (sans token)
    # Source : https://api.github.com/advisories (API publique, 60 req/h sans token)
    # Appelé en mode deep pour enrichir les CVE qui manquent encore de :
    #   - fixed_version (pas trouvé via OSV/NVD)
    #   - epss_score (non fourni par NVD pour cette CVE)
    # → Différence concrète et observable entre standard et deep
    # ═══════════════════════════════════════════════════════════════════════════
    if scan_type == "deep" and time.monotonic() < scan_deadline:
        # Cibler les CVE incomplètes (pas de fixed_version OU pas d'epss_score)
        cves_to_enrich_ghsa: list[tuple[str, object, str]] = []  # (cve_id, vuln_obj, dep_key)
        seen_ghsa: set[str] = set()

        for dep_key, vulns in results.items():
            for vuln in vulns:
                if (
                    vuln.cve_id.startswith("CVE-")
                    and vuln.cve_id not in seen_ghsa
                    and (vuln.fixed_version is None or vuln.epss_score is None)
                ):
                    seen_ghsa.add(vuln.cve_id)
                    cves_to_enrich_ghsa.append((vuln.cve_id, vuln, dep_key))

        if cves_to_enrich_ghsa:
            logger.info(
                "[CVE] Étape 4b — GHSA REST enrichissement (mode DEEP) : "
                "%d CVE sans fixed_version ou epss_score",
                len(cves_to_enrich_ghsa)
            )
            t0 = time.monotonic()
            ghsa_rest_hits = 0

            def _ghsa_rest_one(
                item: tuple[str, object, str]
            ) -> tuple[str, object]:
                cve_id, vuln, dep_key = item
                adv = fetch_ghsa_advisory_by_cve(cve_id, timeout=8.0)
                return cve_id, adv

            with ThreadPoolExecutor(max_workers=3) as executor:  # Limité pour rate-limit 60 req/h
                futures_ghsa = {
                    executor.submit(_ghsa_rest_one, item): item
                    for item in cves_to_enrich_ghsa
                }
                for future in as_completed(futures_ghsa):
                    if time.monotonic() > scan_deadline:
                        break
                    try:
                        cve_id, adv = future.result()
                        if adv is None:
                            continue
                        # Appliquer les enrichissements manquants sur toutes les occurrences
                        for dep_key2, vulns2 in results.items():
                            for v in vulns2:
                                if v.cve_id != cve_id:
                                    continue
                                changed = False
                                if v.fixed_version is None and adv.fixed_version:
                                    v.fixed_version = adv.fixed_version
                                    changed = True
                                if v.epss_score is None and adv.epss_score is not None:
                                    v.epss_score = adv.epss_score
                                    changed = True
                                if changed:
                                    ghsa_rest_hits += 1
                                    if "GHSA-REST" not in v.source:
                                        v.source = v.source + "+GHSA-REST"
                    except Exception:
                        pass

            logger.info(
                "[CVE] GHSA REST terminé en %.2fs — %d CVE enrichies (%d tentées)",
                time.monotonic() - t0, ghsa_rest_hits, len(cves_to_enrich_ghsa)
            )
        else:
            logger.info("[CVE] Étape 4b — GHSA REST ignoré (toutes les CVE déjà complètes)")
    else:
        if scan_type != "deep":
            logger.debug(
                "[CVE] GHSA REST ignoré (mode standard) — activer mode deep pour cet enrichissement"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # BILAN FINAL
    # ═══════════════════════════════════════════════════════════════════════════
    total_cves = sum(len(v) for v in results.values())
    total_elapsed = time.monotonic() - t_start_total

    if len(deps_to_scan) > 0 and len(deps_analyzed_ok) == 0:
        logger.warning(
            "[CVE] 0 dépendance scannée avec succès sur %d. "
            "Vérifier la connexion réseau vers api.osv.dev",
            len(deps_to_scan)
        )

    logger.info(
        "[CVE] Scan terminé en %.2fs — %d deps scannées — %d CVE détectées",
        total_elapsed, len(deps_to_scan), total_cves
    )

    return _finalize_results(
        results, deps_truncated, deps_scanned, deps_total,
        len(deps_analyzed_ok), len(deps_to_scan)
    )


def _finalize_results(
    results: dict,
    deps_truncated: bool,
    deps_scanned: int,
    deps_total: int,
    deps_analyzed_ok: int,
    deps_detected_total: int,
) -> dict:
    """Injecte les métadonnées de scan dans les résultats."""
    results["__scan_meta__"] = {  # type: ignore[assignment]
        "deps_truncated":          deps_truncated,
        "deps_scanned":            deps_scanned,
        "deps_total":              deps_total,
        "timeout_reached":         False,
        "deps_analyzed_successfully": deps_analyzed_ok,
        "deps_detected_total":     deps_detected_total,
    }
    return results


def get_cve_summary(scan_results: dict[str, list[VulnerabilityResult]]) -> dict:
    """
    Calcule un résumé statistique des CVE détectées.
    Compatible avec les résultats de scan_all_vulnerabilities().
    """
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    total_cve = 0
    affected_packages = 0

    for dep_key, vulns in scan_results.items():
        if dep_key == "__scan_meta__":
            continue
        if vulns:
            affected_packages += 1
            total_cve += len(vulns)
            for v in vulns:
                sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
                by_severity[sev] = by_severity.get(sev, 0) + 1

    clean_packages = max(0, len(scan_results) - 1 - affected_packages)  # -1 = __scan_meta__

    highest = "NONE"
    for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if by_severity.get(s.value, 0) > 0:
            highest = s.value
            break

    return {
        "total_vulnerabilities": total_cve,
        "by_severity":           by_severity,
        "affected_packages":     affected_packages,
        "clean_packages":        clean_packages,
        "highest_severity":      highest,
    }
