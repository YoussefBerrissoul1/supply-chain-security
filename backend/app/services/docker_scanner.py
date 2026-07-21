"""
Service Docker Scanner — analyse les images Docker avec Trivy.

Position dans la chaîne d'analyse :
    [github_analyzer] → [docker_scanner] → [score_service]

Ce service fait 2 choses distinctes :

  1. ANALYSE DOCKERFILE (statique) :
       Lit le Dockerfile cloné → détecte l'image de base, l'utilisateur,
       les ports exposés. Pas besoin de Docker installé.

  2. SCAN TRIVY (dynamique) :
       Lance la commande Trivy sur l'image de base pour détecter les CVE
       présentes dans le système d'exploitation de l'image.
       Nécessite Trivy installé (https://trivy.dev).

Ce service retourne :
    DockerScanResult — dataclass avec tous les résultats

GESTION D'ERREURS :
    - Trivy non installé     → warning + analyse statique seulement
    - Image inconnue/privée  → warning + retourner score 100 (pas de pénalité)
    - Pas de Dockerfile      → retourner None (le dépôt n'a pas de Docker)
    - Timeout Trivy (> 120s) → log erreur + retourner résultat partiel
    - JSON invalide de Trivy → log erreur + retourner résultat partiel
"""

import json
import logging
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# VERROU GLOBAL TRIVY
# ---------------------------------------------------------------
# Trivy ne supporte pas deux scans simultanés sur le même cache.
# Ce Lock() garantit qu'un seul scan Trivy tourne à la fois.
# Si un 2ème scan est lancé pendant qu'un 1er tourne, il attend
# (bloque) jusqu'à ce que le 1er libère le verrou.
# C'est la solution la plus simple sans Redis/Celery (PFE).
_trivy_lock = threading.Lock()


# ==============================================================
# CONSTANTES
# ==============================================================

# Timeout maximum pour un scan Trivy (en secondes)
# Les grosses images comme "ubuntu:latest" ou "metasploitable2" peuvent prendre du temps
TRIVY_TIMEOUT_SECONDS: int = 600

# Images de base considérées comme "bonnes pratiques" (minimalistes)
# Elles reçoivent un bonus dans le scoring
MINIMAL_BASE_IMAGES: set[str] = {
    "alpine",
    "distroless",
    "scratch",
    "debian-slim",
    "python-slim",
    "node-alpine",
}

# Mapping sévérité Trivy → sévérité interne
# Trivy utilise ses propres noms (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
TRIVY_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


# ==============================================================
# STRUCTURE DE DONNÉES : RÉSULTAT DU SCAN DOCKER
# ==============================================================

@dataclass
class TrivyVulnerability:
    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None
    severity: str
    description: str
    cvss_score: float
    published_date: str | None


@dataclass
class DockerScanResult:
    """
    Résultat complet du scan Docker pour un dépôt.

    Attributs :
        base_image          : image de base extraite du FROM (ex: "python:3.12-slim")
        vulnerabilities_count : nombre total de CVE trouvées par Trivy
        has_root_user       : True si le Dockerfile n'utilise pas USER (root par défaut)
        image_score         : score /100 basé sur les vulnérabilités et les bonnes pratiques
        trivy_available     : True si Trivy est installé et a pu s'exécuter
        vulnerabilities_by_severity : { "CRITICAL": 2, "HIGH": 5, ... }
        raw_trivy_output    : sortie JSON brute de Trivy (pour les logs)
        dockerfile_issues   : liste des problèmes détectés dans le Dockerfile
    """
    base_image: str
    vulnerabilities_count: int = 0
    has_root_user: bool = True       # Par défaut True (root) jusqu'à preuve du contraire
    image_score: float = 100.0
    trivy_available: bool = False
    vulnerabilities_by_severity: dict[str, int] = field(default_factory=dict)
    detailed_vulnerabilities: list[TrivyVulnerability] = field(default_factory=list)
    raw_trivy_output: dict = field(default_factory=dict)
    dockerfile_issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Sérialise pour les logs ou la base de données."""
        return {
            "base_image":                 self.base_image,
            "vulnerabilities_count":      self.vulnerabilities_count,
            "has_root_user":              self.has_root_user,
            "image_score":                self.image_score,
            "trivy_available":            self.trivy_available,
            "vulnerabilities_by_severity": self.vulnerabilities_by_severity,
            "dockerfile_issues":          self.dockerfile_issues,
        }


# ==============================================================
# EXCEPTION PERSONNALISÉE
# ==============================================================

class DockerScannerError(Exception):
    """
    Levée uniquement si le scan COMPLET est impossible
    (ex: Dockerfile trouvé mais totalement illisible).
    Pour Trivy non installé, on continue sans lever d'exception.
    """
    pass


# ==============================================================
# ÉTAPE 1 : ANALYSE STATIQUE DU DOCKERFILE
# ==============================================================

def analyze_dockerfile(dockerfile_path: Path) -> dict:
    """
    Analyse un Dockerfile SANS exécuter Docker ni Trivy.
    Détecte l'image de base, l'utilisateur, et les mauvaises pratiques.

    Pratiques vérifiées :
        ✅ Bonne : utilisation de USER non-root
        ✅ Bonne : image minimale (alpine, slim, distroless)
        ❌ Mauvaise : pas d'instruction USER (root par défaut)
        ❌ Mauvaise : tag "latest" (non reproductible)
        ❌ Mauvaise : COPY . . sans .dockerignore
        ❌ Mauvaise : secrets en clair (ENV PASSWORD, ENV SECRET...)

    Paramètres :
        dockerfile_path : chemin complet vers le Dockerfile

    Retourne :
        dict avec base_image, has_root_user, issues détectées
    """

    result = {
        "base_image":   "unknown",
        "has_root_user": True,     # Pessimiste par défaut
        "issues":       [],
    }

    try:
        content = dockerfile_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Impossible de lire %s : %s", dockerfile_path.name, e)
        raise DockerScannerError(f"Impossible de lire le Dockerfile : {e}") from e

    lines = content.splitlines()
    has_user_instruction = False
    base_image = "unknown"

    # --- Regex pour détecter les secrets en clair ---
    # Ex: ENV PASSWORD=admin123, ENV SECRET_KEY=abc123
    secret_pattern = re.compile(
        r"^ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|API_KEY|PWD)\S*\s*=\s*\S+",
        re.IGNORECASE,
    )

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Ignorer les commentaires
        if not stripped or stripped.startswith("#"):
            continue

        # --- Détecter l'image de base (FROM) ---
        if stripped.upper().startswith("FROM"):
            # Ex: FROM python:3.12-slim  ou  FROM --platform=linux/amd64 node:18
            from_pattern = re.compile(
                r"^FROM\s+(?:--\S+\s+)?([^\s]+)",
                re.IGNORECASE,
            )
            match = from_pattern.match(stripped)
            if match:
                base_image = match.group(1)
                result["base_image"] = base_image

                # Vérifier si le tag est "latest" → mauvaise pratique
                if base_image.endswith(":latest") or ":" not in base_image:
                    result["issues"].append(
                        f"Ligne {line_num} : tag ':latest' utilisé pour '{base_image}'. "
                        f"Préférer une version fixe (ex: python:3.12-slim)."
                    )
                    logger.debug("Mauvaise pratique : tag latest sur %s", base_image)

        # --- Détecter l'instruction USER ---
        elif stripped.upper().startswith("USER"):
            has_user_instruction = True
            # Extraire le nom d'utilisateur
            user_match = re.match(r"^USER\s+(\S+)", stripped, re.IGNORECASE)
            if user_match:
                user_name = user_match.group(1)
                # Si l'utilisateur est explicitement root → c'est une mauvaise pratique
                if user_name.lower() in ("root", "0"):
                    result["issues"].append(
                        f"Ligne {line_num} : USER root explicitement défini. "
                        f"Utiliser un utilisateur non-privilégié."
                    )
                    logger.debug("Mauvaise pratique : USER root ligne %d", line_num)
                else:
                    # Utilisateur non-root → bonne pratique
                    result["has_root_user"] = False
                    logger.debug("Bonne pratique : USER %s ligne %d", user_name, line_num)

        # --- Détecter les secrets en clair ---
        elif secret_pattern.match(stripped):
            result["issues"].append(
                f"Ligne {line_num} : secret potentiel dans ENV ({stripped[:60]}). "
                f"Utiliser des Docker secrets ou des variables d'environnement runtime."
            )
            logger.warning("Secret potentiel détecté en clair : ligne %d", line_num)

    # --- Si pas d'instruction USER du tout → root par défaut ---
    if not has_user_instruction:
        result["issues"].append(
            "Pas d'instruction USER trouvée. L'image tourne en root par défaut. "
            "Ajouter 'USER appuser' après la création de l'utilisateur."
        )
        logger.debug("Mauvaise pratique : pas d'instruction USER dans le Dockerfile")
        result["has_root_user"] = True

    logger.info(
        "Analyse Dockerfile : image='%s', root=%s, %d problème(s) détecté(s)",
        result["base_image"], result["has_root_user"], len(result["issues"]),
    )

    return result


# ==============================================================
# ÉTAPE 2 : VÉRIFIER SI TRIVY EST INSTALLÉ
# ==============================================================

def is_trivy_available() -> bool:
    """
    Vérifie que Trivy est installé et accessible dans le PATH.

    Trivy est un outil open source d'Aqua Security pour scanner
    les images Docker, les filesystems et les dépôts.
    Installation : https://trivy.dev/latest/getting-started/installation/

    Retourne :
        True si la commande 'trivy --version' réussit
    """
    try:
        result = subprocess.run(
            [settings.TRIVY_PATH, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode == 0:
            version_line = result.stdout.splitlines()[0] if result.stdout else "?"
            logger.info("Trivy disponible : %s", version_line)
            return True
        else:
            logger.warning("Trivy retourne un code d'erreur : %d", result.returncode)
            return False
    except FileNotFoundError:
        # La commande 'trivy' n'existe pas dans le PATH
        logger.warning(
            "Trivy non trouvé. Scanner Docker désactivé. "
            "Installer Trivy depuis https://trivy.dev/latest/getting-started/installation/"
        )
        return False
    except subprocess.TimeoutExpired:
        logger.warning("Trivy --version a timeout — considéré non disponible")
        return False


# ==============================================================
# ÉTAPE 3 : LANCER TRIVY SUR L'IMAGE DE BASE
# ==============================================================

def run_trivy_scan(image_name: str, scan_type: str = "standard") -> dict | None:
    """
    Lance Trivy pour scanner une image Docker et retourne le rapport JSON.

    Commande exécutée :
        trivy image --format json --quiet --timeout 120s <image_name>

    Options importantes :
        --format json   : sortie parseable par Python
        --quiet         : pas de logs Trivy dans notre log
        --timeout 120s  : stop si trop long
        --no-progress   : pas d'animation de progression

    Paramètres :
        image_name : nom complet de l'image (ex: "python:3.12-slim")
        scan_type  : "standard" (rapide, OS uniquement) ou "deep" (secrets, misconfig, license)

    Retourne :
        dict : rapport JSON de Trivy, ou None en cas d'échec
    """

    logger.info("Lancement de Trivy sur l'image : %s (scan_type=%s)", image_name, scan_type)

    # "standard" = vulns OS uniquement (rapide)
    # "deep"     = vulns + secrets + misconfigs (plus long)
    scanners = "vuln" if scan_type == "standard" else "vuln,secret,misconfig"

    trivy_command = [
        settings.TRIVY_PATH,
        "image",
        "--format", "json",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT_SECONDS}s",
        "--no-progress",
        "--skip-version-check",   # Évite les messages de mise à jour qui polluent le stdout JSON
        # Ces fichiers apt sont des listes de paquets disponibles, pas des paquets installés.
        # Ils sont très gros (10-20 Mo) et Trivy les scanne inutilement pour des secrets.
        # Les vraies CVE sont détectées via les paquets système, pas ces fichiers de liste.
        "--skip-files", "/var/lib/apt/lists/*",
        "--skip-files", "/var/cache/apt/*",
        "--scanners", scanners,
        image_name,
    ]

    # --- Acquérir le verrou : un seul scan Trivy à la fois ---
    # Si un autre scan tourne déjà, on attend ici (pas de crash).
    # Dès que le premier scan termine, le verrou est libéré et on continue.
    logger.info("Trivy : attente du verrou (évite les conflits de cache)...")
    with _trivy_lock:
        logger.info("Trivy : verrou acquis — démarrage du scan de '%s'", image_name)
        try:
            process = subprocess.run(
                trivy_command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=TRIVY_TIMEOUT_SECONDS + 30,  # Marge supplémentaire pour les grosses images
            )

            # --- Analyser le code de retour ---
            # Code 0 : succès, aucune vulnérabilité
            # Code 1 : succès, des vulnérabilités ont été trouvées (comportement normal)
            # Code 2 : avertissement (OS en fin de support, ex: Ubuntu 8.04) — JSON valide quand même
            # Code > 2 : vraie erreur (image introuvable, erreur réseau, etc.)
            if process.returncode not in (0, 1, 2):
                logger.error(
                    "Trivy a échoué (code %d) pour '%s'.\nSTDERR: %s",
                    process.returncode, image_name, process.stderr[:500],
                )
                return None

            if process.returncode == 2:
                logger.warning(
                    "Trivy : code 2 pour '%s' (OS probablement en fin de support). "
                    "On continue avec les résultats disponibles.",
                    image_name,
                )

            if not process.stdout or process.stdout.strip() == "":
                logger.warning("Trivy : sortie vide pour '%s'", image_name)
                return None

            # --- Parser la sortie JSON ---
            try:
                trivy_data = json.loads(process.stdout)
                total_results = len(trivy_data.get("Results", []))
                logger.info(
                    "Trivy scan terminé pour '%s' (%d bloc(s) de résultats)",
                    image_name, total_results,
                )
                return trivy_data

            except json.JSONDecodeError as e:
                # Parfois Trivy mélange des logs avec le JSON → on essaie de l'extraire
                logger.warning("JSON invalide brut pour '%s' : %s — tentative d'extraction", image_name, e)
                try:
                    # Chercher le JSON en ignorant les lignes de log qui précèdent
                    stdout_clean = process.stdout
                    json_start = stdout_clean.find('{')
                    if json_start != -1:
                        trivy_data = json.loads(stdout_clean[json_start:])
                        logger.info("JSON extrait avec succès après nettoyage pour '%s'", image_name)
                        return trivy_data
                except Exception:
                    pass
                logger.error("Impossible de parser le JSON Trivy pour '%s'", image_name)
                return None

        except subprocess.TimeoutExpired:
            logger.error(
                "Trivy timeout après %ds pour '%s' — augmentez TRIVY_TIMEOUT_SECONDS si nécessaire",
                TRIVY_TIMEOUT_SECONDS, image_name,
            )
            return None

        except FileNotFoundError:
            logger.error(
                "Trivy introuvable lors du scan de '%s'. "
                "Vérifiez que Trivy est installé : https://trivy.dev",
                image_name,
            )
            return None

        except Exception as e:
            logger.error("Erreur inattendue Trivy pour '%s' : %s", image_name, e)
            return None


# ==============================================================
# ÉTAPE 4 : PARSER LE RAPPORT TRIVY
# ==============================================================

def parse_trivy_report(trivy_data: dict) -> tuple[dict[str, int], list[TrivyVulnerability]]:
    """
    Extrait les vulnérabilités détaillées et le nombre par sévérité depuis le rapport Trivy.
    """
    counts: dict[str, int] = {s: 0 for s in TRIVY_SEVERITY_ORDER}
    detailed_vulns: list[TrivyVulnerability] = []

    results = trivy_data.get("Results", [])

    if not results:
        logger.debug("Trivy : aucun résultat dans le rapport")
        return counts, detailed_vulns

    for result_block in results:
        vulnerabilities = result_block.get("Vulnerabilities") or []

        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity not in counts:
                severity = "UNKNOWN"

            counts[severity] += 1
            
            # Extract detailed vulnerability data
            cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg_name = vuln.get("PkgName", "UnknownPackage")
            installed_version = vuln.get("InstalledVersion", "0.0.0")
            fixed_version = vuln.get("FixedVersion", None)
            description = vuln.get("Description", "")
            published_date = vuln.get("PublishedDate", None)
            
            # Extract CVSS Score
            cvss_score = 0.0
            cvss_data = vuln.get("CVSS", {})
            if cvss_data:
                # Prefer NVD V3 score, otherwise take any V3Score
                if "nvd" in cvss_data and "V3Score" in cvss_data["nvd"]:
                    cvss_score = cvss_data["nvd"]["V3Score"]
                else:
                    for vendor_data in cvss_data.values():
                        if isinstance(vendor_data, dict) and "V3Score" in vendor_data:
                            cvss_score = vendor_data["V3Score"]
                            break
            
            detailed_vulns.append(TrivyVulnerability(
                cve_id=cve_id,
                pkg_name=pkg_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                severity=severity,
                description=description,
                cvss_score=cvss_score,
                published_date=published_date
            ))

    total = sum(counts.values())
    logger.info(
        "Trivy : %d vulnérabilité(s) total — CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d",
        total, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
    )

    return counts, detailed_vulns


# ==============================================================
# ÉTAPE 5 : CALCULER LE SCORE IMAGE DOCKER
# ==============================================================

def calculate_image_score(
    vulns_by_severity: dict[str, int],
    has_root_user: bool,
    base_image: str,
) -> float:
    """
    Calcule un score /100 pour l'image Docker basé sur les vulnérabilités
    et les bonnes pratiques.

    Algorithme de pénalités (cohérent avec le score global du CLAUDE.md) :
        - Image Docker vulnérable : −10 pts max −20
        - Mauvaise pratique (root) : −5 pts max −10

    Score minimum : 0 (jamais négatif)

    Paramètres :
        vulns_by_severity : résultat de parse_trivy_report()
        has_root_user     : True si l'image tourne en root
        base_image        : nom de l'image de base

    Retourne :
        float : score entre 0.0 et 100.0
    """
    score = 100.0
    penalties = []

    # --- Pénalités pour les vulnérabilités ---
    critical_count = vulns_by_severity.get("CRITICAL", 0)
    high_count = vulns_by_severity.get("HIGH", 0)
    medium_count = vulns_by_severity.get("MEDIUM", 0)

    if critical_count > 0:
        penalty = min(critical_count * 15, 45)
        score -= penalty
        penalties.append(f"CRITICAL x{critical_count} : -{penalty}pts")

    if high_count > 0:
        penalty = min(high_count * 8, 24)
        score -= penalty
        penalties.append(f"HIGH x{high_count} : -{penalty}pts")

    if medium_count > 0:
        penalty = min(medium_count * 3, 15)
        score -= penalty
        penalties.append(f"MEDIUM x{medium_count} : -{penalty}pts")

    # --- Pénalité pour root user ---
    if has_root_user:
        score -= 10
        penalties.append("Root user : -10pts")

    # --- Bonus pour images minimales (alpine, slim, distroless) ---
    image_name_lower = base_image.lower()
    for minimal_image in MINIMAL_BASE_IMAGES:
        if minimal_image in image_name_lower:
            # Pas de bonus en points mais on log que c'est une bonne pratique
            logger.info("Bonne pratique : image minimale '%s' détectée", base_image)
            break

    # Le score ne peut pas être négatif
    final_score = max(0.0, round(score, 1))

    if penalties:
        logger.info("Score image Docker : %.1f/100 (pénalités : %s)", final_score, ", ".join(penalties))
    else:
        logger.info("Score image Docker : %.1f/100 (aucune pénalité)", final_score)

    return final_score


# ==============================================================
# FONCTION PRINCIPALE : SCANNER UN DÉPÔT DOCKER
# ==============================================================

def scan_docker(
    repo_path: Path,
    dockerfile_paths: list[str],
    scan_type: str = "standard"
) -> DockerScanResult | None:
    """
    Fonction principale du scanner Docker.
    Orchestre : analyse statique Dockerfile → Trivy → calcul du score.

    Paramètres :
        repo_path        : chemin du dépôt cloné
        dockerfile_paths : liste des chemins relatifs vers les Dockerfiles
                           (retournés par github_analyzer)
        scan_type        : "standard" ou "deep"

    Retourne :
        DockerScanResult : résultat complet du scan
        None             : si aucun Dockerfile n'est présent dans le dépôt

    Lève :
        DockerScannerError : uniquement si le Dockerfile est illisible
    """

    if not dockerfile_paths:
        logger.info("Aucun Dockerfile dans ce dépôt — scan Docker ignoré")
        return None

    # On analyse le premier Dockerfile trouvé
    # (les monorepos avec plusieurs Dockerfiles sont rares dans un PFE)
    first_dockerfile = repo_path / dockerfile_paths[0]
    logger.info("Analyse Docker sur : %s", dockerfile_paths[0])

    # --- Étape 1 : Analyse statique du Dockerfile ---
    static_analysis = analyze_dockerfile(first_dockerfile)

    base_image = static_analysis["base_image"]
    has_root = static_analysis["has_root_user"]
    issues = static_analysis["issues"]

    # Initialiser le résultat avec les données statiques
    scan_result = DockerScanResult(
        base_image=base_image,
        has_root_user=has_root,
        dockerfile_issues=issues,
        vulnerabilities_count=0,
        vulnerabilities_by_severity={s: 0 for s in TRIVY_SEVERITY_ORDER},
    )

    # --- Étape 2 : Vérifier si Trivy est disponible ---
    trivy_ok = is_trivy_available()
    scan_result.trivy_available = trivy_ok

    if trivy_ok and base_image != "unknown":
        # --- Étape 3 : Lancer Trivy sur l'image de base ---
        trivy_data = run_trivy_scan(base_image, scan_type=scan_type)

        if trivy_data:
            # --- Étape 4 : Parser le rapport Trivy ---
            vulns_by_severity, detailed_vulns = parse_trivy_report(trivy_data)

            scan_result.vulnerabilities_by_severity = vulns_by_severity
            scan_result.vulnerabilities_count = sum(vulns_by_severity.values())
            scan_result.detailed_vulnerabilities = detailed_vulns
            scan_result.raw_trivy_output = trivy_data

            logger.info(
                "Trivy : %d vulnérabilité(s) dans '%s'",
                scan_result.vulnerabilities_count, base_image,
            )
        else:
            logger.warning(
                "Trivy n'a pas pu scanner '%s' — score calculé sur analyse statique seulement",
                base_image,
            )
    elif not trivy_ok:
        logger.warning(
            "Trivy non disponible — score Docker basé uniquement sur l'analyse statique du Dockerfile"
        )

    # --- Étape 5 : Calculer le score image ---
    scan_result.image_score = calculate_image_score(
        vulns_by_severity=scan_result.vulnerabilities_by_severity,
        has_root_user=has_root,
        base_image=base_image,
    )

    logger.info(
        "Scan Docker terminé — image='%s' | score=%.1f | vulns=%d | root=%s",
        base_image, scan_result.image_score,
        scan_result.vulnerabilities_count, has_root,
    )

    return scan_result


# ==============================================================
# FONCTION UTILITAIRE : RÉSUMÉ LISIBLE
# ==============================================================

def get_docker_summary(result: DockerScanResult | None) -> dict:
    """
    Génère un résumé du scan Docker pour les logs et les rapports.

    Paramètres :
        result : DockerScanResult retourné par scan_docker(), ou None

    Retourne :
        dict avec les informations clés
    """
    if result is None:
        return {
            "has_docker":          False,
            "base_image":          None,
            "image_score":         None,
            "vulnerabilities":     0,
            "has_root_user":       None,
            "trivy_used":          False,
            "dockerfile_issues":   [],
        }

    return {
        "has_docker":          True,
        "base_image":          result.base_image,
        "image_score":         result.image_score,
        "vulnerabilities":     result.vulnerabilities_count,
        "by_severity":         result.vulnerabilities_by_severity,
        "has_root_user":       result.has_root_user,
        "trivy_used":          result.trivy_available,
        "dockerfile_issues":   result.dockerfile_issues,
    }
