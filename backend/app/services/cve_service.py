"""
Service CVE — détecte les vulnérabilités dans les dépendances via OSV et NVD.

Position dans la chaîne d'analyse :
    [dependency_scanner] → [cve_service] → [score_service]

Ce service reçoit :
    - Une liste de DependencyInfo (nom, version, écosystème)

Ce service retourne :
    - Un dict : { dependency_name → liste de VulnerabilityResult }

STRATÉGIE D'INTERROGATION :
    1. OSV API  (https://api.osv.dev/v1/query)  ← PRIORITAIRE (gratuite, rapide)
    2. NVD API  (https://services.nvd.nist.gov/) ← FALLBACK ou complément (limitée)

GESTION DU RATE LIMIT :
    - OSV   : pas de limite documentée, mais on ajoute un délai entre requêtes
    - NVD   : 5 req/30s SANS clé, 50 req/30s AVEC clé
    - On respecte un délai minimum de CVE_DELAY_SECONDS entre chaque requête NVD

GESTION D'ERREURS :
    - Réseau coupé           → log + retourner [] pour cette dépendance
    - Timeout                → log + retourner []
    - Rate limit (429)       → pause + retry (max 3 tentatives)
    - Réponse vide ou 404    → retourner []
    - Dépendance sans version→ on essaie quand même (version inconnue = skip NVD)
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum

import requests
from requests.exceptions import ConnectionError, ReadTimeout, HTTPError

from app.core.config import settings
from app.services.dependency_scanner import DependencyInfo

logger = logging.getLogger(__name__)


# ==============================================================
# CONSTANTES
# ==============================================================

# Délai minimum entre les requêtes NVD (en secondes) pour respecter le rate limit
# Sans clé : 5 req / 30s → 1 req toutes les 6s de sécurité
# Avec clé  : 50 req / 30s → 0.6s suffit, mais on prend 1s de marge
NVD_DELAY_SECONDS: float = 6.0

# Délai entre requêtes OSV (plus souple)
OSV_DELAY_SECONDS: float = 0.5

# Nombre maximum de tentatives en cas d'erreur 429 (rate limit)
MAX_RETRY_ON_RATE_LIMIT: int = 3

# Pause en secondes lors d'un rate limit avant retry
RATE_LIMIT_PAUSE_SECONDS: float = 15.0

# Mapping OSV/NVD ecosystem → format attendu par l'API OSV
# OSV identifie les écosystèmes avec des noms précis
OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "PyPI",
    "nodejs": "npm",
    "java":   "Maven",
    "ruby":   "RubyGems",
    "php":    "Packagist",
    "rust":   "crates.io",
    "go":     "Go",
}


# ==============================================================
# ÉNUMÉRATION : SÉVÉRITÉ
# ==============================================================

class Severity(str, Enum):
    """
    Niveaux de sévérité des CVE, basés sur le score CVSS.
    On utilise str + Enum pour que la valeur soit directement sérialisable en JSON.
    """
    CRITICAL = "CRITICAL"   # CVSS >= 9.0
    HIGH     = "HIGH"       # CVSS 7.0 – 8.9
    MEDIUM   = "MEDIUM"     # CVSS 4.0 – 6.9
    LOW      = "LOW"        # CVSS 0.1 – 3.9
    NONE     = "NONE"       # CVSS = 0.0 ou inconnu


def cvss_to_severity(cvss_score: float) -> Severity:
    """
    Convertit un score CVSS numérique en niveau de sévérité.

    Basé sur le standard CVSS v3.x :
        9.0 – 10.0 → CRITICAL
        7.0 –  8.9 → HIGH
        4.0 –  6.9 → MEDIUM
        0.1 –  3.9 → LOW
        0.0        → NONE

    Paramètres :
        cvss_score : score entre 0.0 et 10.0

    Retourne :
        Severity enum
    """
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


# ==============================================================
# STRUCTURE DE DONNÉES : UNE VULNÉRABILITÉ
# ==============================================================

@dataclass
class VulnerabilityResult:
    """
    Représente une vulnérabilité (CVE) détectée pour une dépendance.

    Attributs :
        cve_id      : identifiant CVE (ex: "CVE-2023-12345") ou OSV ID (ex: "GHSA-xxxx")
        cvss_score  : score CVSS v3 entre 0.0 et 10.0 (0.0 si inconnu)
        severity    : niveau de sévérité calculé à partir du cvss_score
        description : description courte de la vulnérabilité
        source      : "OSV" ou "NVD" selon l'API qui l'a trouvée
        fixed_version: version corrigée si disponible, sinon None
    """
    cve_id:        str
    cvss_score:    float
    severity:      Severity
    description:   str
    source:        str = "OSV"
    fixed_version: str | None = None

    def to_dict(self) -> dict:
        """Sérialise en dict pour le stockage en base ou les logs."""
        return {
            "cve_id":        self.cve_id,
            "cvss_score":    self.cvss_score,
            "severity":      self.severity.value,
            "description":   self.description,
            "source":        self.source,
            "fixed_version": self.fixed_version,
        }


# ==============================================================
# EXCEPTION PERSONNALISÉE
# ==============================================================

class CVEServiceError(Exception):
    """
    Levée uniquement quand tout le service est en échec total
    (ex: pas de connexion internet du tout).
    Pour une seule dépendance sans résultat, on retourne [] sans exception.
    """
    pass


# ==============================================================
# CLIENT HTTP : REQUÊTE AVEC RETRY
# ==============================================================

def _http_post_with_retry(
    url: str,
    payload: dict,
    headers: dict | None = None,
    delay_before: float = 0.0,
) -> dict | None:
    """
    Effectue une requête POST HTTP avec retry automatique sur rate limit (429).

    Stratégie :
        - Attend 'delay_before' secondes avant la requête (pour respecter les rate limits)
        - En cas de 429 : pause RATE_LIMIT_PAUSE_SECONDS puis réessaie
        - En cas de timeout ou réseau : log + retourner None
        - Retourne None si toutes les tentatives échouent

    Paramètres :
        url          : URL de l'API
        payload      : corps de la requête (JSON)
        headers      : en-têtes HTTP optionnels
        delay_before : délai d'attente avant l'envoi (en secondes)

    Retourne :
        dict : réponse JSON parsée, ou None en cas d'échec
    """
    if delay_before > 0:
        time.sleep(delay_before)

    headers = headers or {"Content-Type": "application/json"}

    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT,
            )

            # --- Cas : rate limit ---
            if response.status_code == 429:
                logger.warning(
                    "Rate limit atteint sur %s (tentative %d/%d) — pause de %.0fs",
                    url, attempt, MAX_RETRY_ON_RATE_LIMIT, RATE_LIMIT_PAUSE_SECONDS,
                )
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(RATE_LIMIT_PAUSE_SECONDS)
                    continue
                else:
                    logger.error("Rate limit persistant après %d tentatives — abandon", attempt)
                    return None

            # --- Cas : erreur serveur (5xx) ---
            if response.status_code >= 500:
                logger.warning("Erreur serveur %d depuis %s", response.status_code, url)
                return None

            # --- Cas : succès ---
            response.raise_for_status()
            return response.json()

        except ReadTimeout:
            logger.warning("Timeout après %ds sur %s (tentative %d)", settings.HTTP_TIMEOUT, url, attempt)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2)  # Courte pause avant retry
                continue
            return None

        except ConnectionError:
            logger.error("Impossible de se connecter à %s — vérifier la connexion internet", url)
            return None

        except HTTPError as e:
            logger.error("Erreur HTTP %s sur %s : %s", e.response.status_code, url, e)
            return None

        except Exception as e:
            logger.error("Erreur inattendue lors de la requête vers %s : %s", url, e)
            return None

    return None


def _http_get_with_retry(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    delay_before: float = 0.0,
) -> dict | None:
    """
    Identique à _http_post_with_retry mais pour les requêtes GET (utilisé par NVD).
    """
    if delay_before > 0:
        time.sleep(delay_before)

    headers = headers or {}

    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT,
            )

            if response.status_code == 429:
                logger.warning(
                    "Rate limit NVD (tentative %d/%d) — pause de %.0fs",
                    attempt, MAX_RETRY_ON_RATE_LIMIT, RATE_LIMIT_PAUSE_SECONDS,
                )
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(RATE_LIMIT_PAUSE_SECONDS)
                    continue
                return None

            if response.status_code == 404:
                # CVE inexistante dans NVD — normal
                return None

            if response.status_code >= 500:
                logger.warning("Erreur serveur NVD %d", response.status_code)
                return None

            response.raise_for_status()
            return response.json()

        except ReadTimeout:
            logger.warning("Timeout NVD (tentative %d)", attempt)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2)
                continue
            return None

        except ConnectionError:
            logger.error("Pas de connexion vers NVD API")
            return None

        except Exception as e:
            logger.error("Erreur inattendue NVD : %s", e)
            return None

    return None


# ==============================================================
# REQUÊTEUR OSV API
# ==============================================================

def query_osv(dep: DependencyInfo) -> list[VulnerabilityResult]:
    """
    Interroge l'API OSV pour une dépendance donnée.

    L'API OSV accepte une requête POST au format :
        {
            "package": {
                "name": "requests",
                "ecosystem": "PyPI"
            },
            "version": "2.27.0"   ← optionnel mais améliore la précision
        }

    L'API retourne toutes les vulnérabilités connues pour ce paquet/version.

    Paramètres :
        dep : la dépendance à analyser

    Retourne :
        Liste de VulnerabilityResult (peut être vide si aucune CVE trouvée)
    """

    # --- Vérifier que l'écosystème est supporté par OSV ---
    osv_ecosystem = OSV_ECOSYSTEM_MAP.get(dep.ecosystem)
    if not osv_ecosystem:
        logger.debug(
            "Écosystème '%s' non supporté par OSV — dépendance '%s' ignorée",
            dep.ecosystem, dep.name,
        )
        return []

    # --- Construire le payload OSV ---
    payload: dict = {
        "package": {
            "name": dep.name,
            "ecosystem": osv_ecosystem,
        }
    }

    # Si la version est connue, on la précise pour avoir des résultats plus précis
    if dep.version and dep.version != "unknown":
        payload["version"] = dep.version

    logger.debug("OSV query : %s@%s (%s)", dep.name, dep.version, osv_ecosystem)

    # --- Appel API avec délai et retry ---
    response_data = _http_post_with_retry(
        url=settings.OSV_API_URL,
        payload=payload,
        delay_before=OSV_DELAY_SECONDS,
    )

    if not response_data:
        logger.debug("OSV : pas de réponse pour %s", dep.name)
        return []

    # --- Parser la réponse OSV ---
    vulns = response_data.get("vulns", [])

    if not vulns:
        logger.debug("OSV : aucune vulnérabilité pour %s@%s", dep.name, dep.version)
        return []

    results: list[VulnerabilityResult] = []

    for vuln in vulns:
        # Extraire l'identifiant CVE (préférer CVE-xxx, sinon prendre l'ID OSV)
        cve_id = _extract_cve_id_from_osv(vuln)

        # Extraire le score CVSS depuis les données OSV
        cvss_score = _extract_cvss_from_osv(vuln)

        # Extraire la description (summary ou détail)
        description = _extract_description_from_osv(vuln)

        # Extraire la version corrigée si disponible
        fixed_version = _extract_fixed_version_from_osv(vuln, osv_ecosystem, dep.name)

        result = VulnerabilityResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=cvss_to_severity(cvss_score),
            description=description,
            source="OSV",
            fixed_version=fixed_version,
        )

        results.append(result)
        logger.debug(
            "  CVE trouvée : %s | CVSS: %.1f | Sévérité: %s",
            cve_id, cvss_score, result.severity.value,
        )

    logger.info("OSV → %s@%s : %d vulnérabilité(s) trouvée(s)", dep.name, dep.version, len(results))
    return results


# ==============================================================
# FONCTIONS D'EXTRACTION DEPUIS LA RÉPONSE OSV
# ==============================================================

def _extract_cve_id_from_osv(vuln: dict) -> str:
    """
    Extrait l'identifiant CVE depuis un objet de vulnérabilité OSV.

    OSV retourne un ID principal (ex: "GHSA-xxxx-xxxx-xxxx") et une liste
    d'alias qui peuvent contenir le vrai ID CVE (ex: "CVE-2023-12345").

    On préfère toujours le format CVE-xxxx car c'est le standard industriel.
    """
    osv_id = vuln.get("id", "UNKNOWN")

    # Chercher un alias CVE dans la liste aliases
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias

    # Si pas d'alias CVE, retourner l'ID OSV original (GHSA, PYSEC, etc.)
    return osv_id


def _extract_cvss_from_osv(vuln: dict) -> float:
    """
    Extrait le score CVSS depuis la réponse OSV.

    OSV stocke les scores dans la section "severity" :
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            }
        ]

    Le score CVSS numérique (ex: 9.8) se trouve dans la chaîne après parsing.
    On peut aussi trouver le score dans database_specific.
    """

    # --- Méthode 1 : section severity avec vecteur CVSS ---
    severity_list = vuln.get("severity", [])
    for sev_entry in severity_list:
        sev_type = sev_entry.get("type", "")
        score_string = sev_entry.get("score", "")

        if "CVSS_V3" in sev_type and score_string:
            # Le vecteur CVSS contient le score dans sa chaîne
            # ex: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            # Le score numérique n'est PAS dans ce vecteur directement
            # OSV fournit parfois database_specific avec le score
            pass

    # --- Méthode 2 : database_specific (GitHub Advisory Database) ---
    db_specific = vuln.get("database_specific", {})

    # GitHub Advisory Database stocke le CVSS score ici
    cvss_info = db_specific.get("cvss", {})
    if isinstance(cvss_info, dict):
        score = cvss_info.get("score")
        if score is not None:
            return float(score)

    # Certains OSV mettent aussi "severity" comme string dans database_specific
    severity_str = db_specific.get("severity", "")
    if severity_str:
        # Mapping textuel → score estimé (quand le score exact n'est pas disponible)
        severity_to_score = {
            "CRITICAL": 9.5,
            "HIGH":     8.0,
            "MEDIUM":   5.5,
            "LOW":      2.0,
        }
        return severity_to_score.get(severity_str.upper(), 0.0)

    # --- Méthode 3 : affected[].severity ---
    for affected in vuln.get("affected", []):
        sev_list = affected.get("severity", [])
        for sev_entry in sev_list:
            if "score" in sev_entry:
                try:
                    return float(sev_entry["score"])
                except (ValueError, TypeError):
                    pass

    # Aucun score CVSS trouvé → score inconnu
    return 0.0


def _extract_description_from_osv(vuln: dict) -> str:
    """
    Extrait la description lisible de la vulnérabilité.

    OSV fournit :
        "summary"  : description courte (prioritaire)
        "details"  : description longue (fallback)

    On tronque à 500 caractères pour éviter les descriptions trop longues en base.
    """
    summary = vuln.get("summary", "").strip()
    if summary:
        return summary[:500]

    details = vuln.get("details", "").strip()
    if details:
        # Garder seulement la première phrase pour les descriptions longues
        first_sentence = details.split(".")[0].strip()
        return (first_sentence[:500] + "...") if len(details) > 500 else details

    return "Aucune description disponible."


def _extract_fixed_version_from_osv(
    vuln: dict,
    ecosystem: str,
    package_name: str,
) -> str | None:
    """
    Extrait la version corrigée depuis la réponse OSV.

    Dans OSV, les versions affectées sont dans "affected[].ranges" :
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.28.2"}   ← c'est ce qu'on cherche
            ]
        }]

    Paramètres :
        vuln         : dict d'une vulnérabilité OSV
        ecosystem    : écosystème OSV (ex: "PyPI")
        package_name : nom du paquet

    Retourne :
        Version corrigée sous forme de string, ou None si non disponible
    """
    for affected in vuln.get("affected", []):
        # Vérifier que c'est bien le bon paquet
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem:
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue

        # Chercher dans les ranges
        for version_range in affected.get("ranges", []):
            events = version_range.get("events", [])
            for event in events:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)

    return None


# ==============================================================
# REQUÊTEUR NVD API (fallback / complément)
# ==============================================================

def query_nvd_by_cve_id(cve_id: str) -> VulnerabilityResult | None:
    """
    Interroge la NVD API pour obtenir les détails complets d'un CVE spécifique.
    Utilisé en complément d'OSV pour enrichir un CVE déjà trouvé (score CVSS précis).

    Exemple de réponse NVD :
        {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-12345",
                    "descriptions": [{ "lang": "en", "value": "..." }],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }]
                    }
                }
            }]
        }

    Paramètres :
        cve_id : identifiant CVE au format "CVE-2023-12345"

    Retourne :
        VulnerabilityResult enrichi, ou None si non trouvé
    """

    # NVD n'accepte que les vrais IDs CVE, pas les GHSA ou PYSEC
    if not cve_id.startswith("CVE-"):
        logger.debug("NVD : '%s' n'est pas un CVE ID — ignoré", cve_id)
        return None

    params = {"cveId": cve_id}
    headers = {}

    # Si une clé API est configurée, l'ajouter pour lever les limitations
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
        delay = 1.0    # Avec clé : 50 req/30s → 1s de sécurité
    else:
        delay = NVD_DELAY_SECONDS  # Sans clé : 5 req/30s → 6s de sécurité

    logger.debug("NVD query : %s", cve_id)

    response_data = _http_get_with_retry(
        url=settings.NVD_API_URL,
        params=params,
        headers=headers,
        delay_before=delay,
    )

    if not response_data:
        return None

    vulnerabilities = response_data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    # Extraire les données du premier résultat (NVD retourne 1 résultat pour 1 CVE ID)
    cve_data = vulnerabilities[0].get("cve", {})

    cvss_score, severity_str = _extract_cvss_from_nvd(cve_data)
    description = _extract_description_from_nvd(cve_data)

    return VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=cvss_to_severity(cvss_score),
        description=description,
        source="NVD",
    )


def _extract_cvss_from_nvd(cve_data: dict) -> tuple[float, str]:
    """
    Extrait le score CVSS et la sévérité depuis les données NVD.

    NVD supporte CVSS v3.1, v3.0 et v2 (on préfère v3.1 → v3.0 → v2).

    Retourne :
        tuple (cvss_score: float, severity_string: str)
    """
    metrics = cve_data.get("metrics", {})

    # Essayer CVSS v3.1 d'abord (le plus récent et précis)
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "NONE")
            return float(score), severity

    return 0.0, "NONE"


def _extract_description_from_nvd(cve_data: dict) -> str:
    """
    Extrait la description anglaise depuis les données NVD.
    NVD fournit une liste de descriptions dans plusieurs langues.
    """
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")[:500]
    return "Aucune description NVD disponible."


# ==============================================================
# FONCTION PRINCIPALE : SCANNER TOUTES LES DÉPENDANCES
# ==============================================================

def scan_all_vulnerabilities(
    dependencies: list[DependencyInfo],
) -> dict[str, list[VulnerabilityResult]]:
    """
    Fonction principale du service CVE.
    Interroge OSV pour chaque dépendance et retourne toutes les vulnérabilités trouvées.

    Stratégie :
        1. Pour chaque dépendance → OSV API
        2. Si la CVE trouvée a un score CVSS = 0 et c'est un vrai CVE-ID → NVD API pour enrichir
        3. Retourner un dict indexé par dépendance

    Paramètres :
        dependencies : liste retournée par dependency_scanner.scan_dependencies()

    Retourne :
        dict : { "fastapi" → [VulnerabilityResult, ...], "requests" → [], ... }
               Toutes les dépendances sont incluses (même celles sans CVE = liste vide)

    Lève :
        CVEServiceError : uniquement si aucune requête n'a pu être faite du tout
    """

    if not dependencies:
        logger.warning("scan_all_vulnerabilities : liste vide reçue")
        return {}

    results: dict[str, list[VulnerabilityResult]] = {}
    total_cve_found = 0
    failed_queries = 0

    logger.info(
        "Démarrage du scan CVE pour %d dépendance(s)...",
        len(dependencies),
    )

    for index, dep in enumerate(dependencies, start=1):
        dep_key = f"{dep.name}@{dep.version}"

        logger.info(
            "[%d/%d] Scan CVE : %s (%s)",
            index, len(dependencies), dep_key, dep.ecosystem,
        )

        # --- Skip les dépendances Docker (gérées par docker_scanner) ---
        if dep.ecosystem == "docker":
            logger.debug("Dépendance Docker ignorée (sera gérée par docker_scanner) : %s", dep.name)
            continue

        try:
            # --- Interroger OSV (source principale) ---
            osv_results = query_osv(dep)

            # --- Enrichir via NVD si le score CVSS est manquant ---
            enriched_results: list[VulnerabilityResult] = []
            for vuln in osv_results:
                if vuln.cvss_score == 0.0 and vuln.cve_id.startswith("CVE-"):
                    # Essayer d'obtenir le score précis depuis NVD
                    nvd_result = query_nvd_by_cve_id(vuln.cve_id)
                    if nvd_result and nvd_result.cvss_score > 0.0:
                        # Mettre à jour le score et la sévérité
                        vuln.cvss_score = nvd_result.cvss_score
                        vuln.severity = cvss_to_severity(nvd_result.cvss_score)
                        vuln.source = "OSV+NVD"
                        logger.debug(
                            "Score enrichi via NVD pour %s : %.1f (%s)",
                            vuln.cve_id, vuln.cvss_score, vuln.severity.value,
                        )

                enriched_results.append(vuln)

            results[dep_key] = enriched_results
            total_cve_found += len(enriched_results)

        except Exception as e:
            # Une erreur sur une dépendance ne bloque PAS les autres
            logger.error(
                "Erreur inattendue lors du scan de '%s' : %s — dépendance ignorée",
                dep_key, e,
            )
            results[dep_key] = []
            failed_queries += 1

    # --- Vérification : si TOUTES les requêtes ont échoué → service indisponible ---
    if failed_queries == len(dependencies) and len(dependencies) > 0:
        raise CVEServiceError(
            "Toutes les requêtes CVE ont échoué. "
            "Vérifiez votre connexion internet et la disponibilité des APIs OSV/NVD."
        )

    # --- Résumé ---
    deps_with_vulns = sum(1 for vulns in results.values() if vulns)
    logger.info(
        "Scan CVE terminé — %d dépendances analysées, %d avec des CVE, %d CVE trouvées au total",
        len(results), deps_with_vulns, total_cve_found,
    )

    return results


# ==============================================================
# FONCTION UTILITAIRE : RÉSUMÉ DU SCAN CVE
# ==============================================================

def get_cve_summary(scan_results: dict[str, list[VulnerabilityResult]]) -> dict:
    """
    Génère un résumé statistique du scan CVE pour les logs et les rapports.

    Paramètres :
        scan_results : dict retourné par scan_all_vulnerabilities()

    Retourne :
        dict avec :
            - total_vulnerabilities : nombre total de CVE
            - by_severity           : { "CRITICAL": 3, "HIGH": 7, ... }
            - affected_packages     : nombre de paquets touchés
            - clean_packages        : nombre de paquets sans CVE
            - highest_severity      : la sévérité maximale trouvée
    """
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    total_cve = 0
    affected_packages = 0

    for vulns in scan_results.values():
        if vulns:
            affected_packages += 1
            for vuln in vulns:
                total_cve += 1
                by_severity[vuln.severity.value] += 1

    # Déterminer la sévérité maximale présente
    highest_severity = Severity.NONE
    for severity_level in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if by_severity[severity_level.value] > 0:
            highest_severity = severity_level
            break

    return {
        "total_vulnerabilities": total_cve,
        "by_severity":           by_severity,
        "affected_packages":     affected_packages,
        "clean_packages":        len(scan_results) - affected_packages,
        "highest_severity":      highest_severity.value,
    }
