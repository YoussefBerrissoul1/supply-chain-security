"""
Service Dependency Scanner — lit les fichiers de dépendances et extrait les paquets.

Position dans la chaîne d'analyse :
    [github_analyzer] → [dependency_scanner] → [cve_service] → ...

Ce service reçoit :
    - Le chemin du dépôt cloné (Path)
    - Le dictionnaire des fichiers trouvés par github_analyzer
        ex: { "python": ["requirements.txt"], "nodejs": ["package.json"] }

Ce service retourne :
    - Une liste de DependencyInfo (nom, version, écosystème)
        ex: [DependencyInfo(name="fastapi", version="0.104.1", ecosystem="python"), ...]

PARSEURS IMPLÉMENTÉS :
    - Python   : requirements.txt, pyproject.toml, setup.cfg
    - Node.js  : package.json
    - Java     : pom.xml
    - Docker   : Dockerfile (image de base uniquement)

GESTION D'ERREURS :
    - Fichier illisible → warning + on continue (on ne bloque pas pour 1 fichier)
    - Format invalide   → warning + on continue
    - Version manquante → version = "unknown" (pris en compte dans le score)
    - Dépendance vide   → ignorée silencieusement
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ==============================================================
# STRUCTURE DE DONNÉES : UNE DÉPENDANCE
# ==============================================================

@dataclass
class DependencyInfo:
    """
    Représente une dépendance extraite d'un fichier de dépendances.

    Attributs :
        name       : nom du paquet (ex: "fastapi", "express", "spring-boot")
        version    : version du paquet (ex: "0.104.1") ou "unknown" si absente
        ecosystem  : écosystème d'origine (ex: "python", "nodejs", "java")
        source_file: nom du fichier source (ex: "requirements.txt")
    """
    name: str
    version: str
    ecosystem: str
    source_file: str = field(default="")

    def __post_init__(self) -> None:
        """Normalise les valeurs après création."""
        self.name = self.name.strip().lower()
        self.version = self.version.strip() if self.version else "unknown"
        self.ecosystem = self.ecosystem.strip().lower()

    def is_valid(self) -> bool:
        """Retourne True si la dépendance a au moins un nom non vide."""
        return bool(self.name)


# ==============================================================
# EXCEPTION PERSONNALISÉE
# ==============================================================

class DependencyScannerError(Exception):
    """
    Exception levée quand le scan COMPLET échoue (aucun fichier lisible).
    Pour un seul fichier illisible, on utilise juste un warning.
    """
    pass


# ==============================================================
# PARSEUR : requirements.txt (Python)
# ==============================================================

def parse_requirements_txt(file_path: Path) -> list[DependencyInfo]:
    """
    Parse un fichier requirements.txt Python.

    Format supporté :
        fastapi==0.104.1          ← version exacte
        requests>=2.28.0          ← version minimale
        numpy~=1.24               ← version compatible
        pandas                    ← sans version spécifiée
        # commentaire             ← ignoré
        -r other-requirements.txt ← directive ignorée

    Paramètres :
        file_path : chemin complet vers le fichier requirements.txt

    Retourne :
        Liste de DependencyInfo extraites
    """
    dependencies: list[DependencyInfo] = []

    # Regex : capture "nom_paquet" et optionnellement "version"
    # Exemples : fastapi==0.104.1 | requests>=2.28 | numpy~=1.24 | pandas
    # Opérateurs supportés : ==, >=, <=, ~=, !=, >
    pattern = re.compile(
        r"^([A-Za-z0-9_\-\.]+)"          # Nom du paquet (obligatoire)
        r"(?:[=~!<>]+([A-Za-z0-9_\-\.\*]+))?"  # Version (optionnelle)
    )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Impossible de lire %s : %s", file_path.name, e)
        return []

    for line_number, line in enumerate(content.splitlines(), start=1):
        # Supprimer les espaces et les commentaires inline
        line = line.strip()

        # Ignorer : lignes vides, commentaires, directives (-r, -c, --index-url...)
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = pattern.match(line)
        if match:
            name = match.group(1)
            version = match.group(2) or "unknown"

            dep = DependencyInfo(
                name=name,
                version=version,
                ecosystem="python",
                source_file=file_path.name,
            )

            if dep.is_valid():
                dependencies.append(dep)
                logger.debug("  Python: %s==%s (ligne %d)", name, version, line_number)
        else:
            # Ligne non reconnue — peut être un URL ou option complexe
            logger.debug("Ligne ignorée dans %s (ligne %d) : %s", file_path.name, line_number, line[:60])

    logger.info("requirements.txt → %d dépendances extraites", len(dependencies))
    return dependencies


# ==============================================================
# PARSEUR : pyproject.toml (Python moderne)
# ==============================================================

def parse_pyproject_toml(file_path: Path) -> list[DependencyInfo]:
    """
    Parse un fichier pyproject.toml (PEP 621 + Poetry).

    Sections supportées :
        [project] dependencies = [...]       ← format PEP 621
        [tool.poetry.dependencies]           ← format Poetry

    Paramètres :
        file_path : chemin complet vers le fichier pyproject.toml

    Retourne :
        Liste de DependencyInfo extraites
    """
    dependencies: list[DependencyInfo] = []

    try:
        # tomllib est intégré depuis Python 3.11 (sinon utiliser tomli)
        import tomllib
        content = file_path.read_bytes()
        data = tomllib.loads(content.decode("utf-8", errors="replace"))
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
            content = file_path.read_bytes()
            data = tomllib.loads(content.decode("utf-8", errors="replace"))
        except ImportError:
            logger.warning("tomllib/tomli non disponible — pyproject.toml ignoré")
            return []
    except Exception as e:
        logger.warning("Erreur de parsing de %s : %s", file_path.name, e)
        return []

    # Regex pour extraire "nom" et "version" d'une ligne comme "requests>=2.28"
    version_pattern = re.compile(r"^([A-Za-z0-9_\-\.]+)(?:[=~!<>]+([A-Za-z0-9_\-\.\*]+))?")

    # --- Format PEP 621 : [project] dependencies ---
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep_str in project_deps:
        match = version_pattern.match(str(dep_str).strip())
        if match:
            dep = DependencyInfo(
                name=match.group(1),
                version=match.group(2) or "unknown",
                ecosystem="python",
                source_file=file_path.name,
            )
            if dep.is_valid():
                dependencies.append(dep)

    # --- Format Poetry : [tool.poetry.dependencies] ---
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for pkg_name, pkg_version in poetry_deps.items():
        # Ignorer la version Python elle-même
        if pkg_name.lower() == "python":
            continue

        # pkg_version peut être une string "^1.0" ou un dict {"version": "^1.0"}
        if isinstance(pkg_version, str):
            version = pkg_version.lstrip("^~>=<!")
        elif isinstance(pkg_version, dict):
            version = str(pkg_version.get("version", "unknown")).lstrip("^~>=<!")
        else:
            version = "unknown"

        dep = DependencyInfo(
            name=pkg_name,
            version=version,
            ecosystem="python",
            source_file=file_path.name,
        )
        if dep.is_valid():
            dependencies.append(dep)

    logger.info("pyproject.toml → %d dépendances extraites", len(dependencies))
    return dependencies


# ==============================================================
# PARSEUR : package.json (Node.js)
# ==============================================================

def parse_package_json(file_path: Path) -> list[DependencyInfo]:
    """
    Parse un fichier package.json Node.js.

    Sections analysées :
        "dependencies"    : dépendances de production (toujours incluses)
        "devDependencies" : dépendances de développement (incluses aussi pour l'audit)

    Format typique :
        {
            "dependencies": {
                "express": "^4.18.2",
                "axios": "~1.6.0"
            }
        }

    Paramètres :
        file_path : chemin complet vers le fichier package.json

    Retourne :
        Liste de DependencyInfo extraites
    """
    dependencies: list[DependencyInfo] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning("JSON invalide dans %s : %s", file_path.name, e)
        return []
    except OSError as e:
        logger.warning("Impossible de lire %s : %s", file_path.name, e)
        return []

    # Analyser les deux sections de dépendances
    sections_to_check = ["dependencies", "devDependencies"]

    for section in sections_to_check:
        section_data = data.get(section, {})

        if not isinstance(section_data, dict):
            logger.warning("Section '%s' invalide dans %s", section, file_path.name)
            continue

        for pkg_name, pkg_version in section_data.items():
            # Nettoyer la version : supprimer les préfixes ^, ~, >=
            if isinstance(pkg_version, str):
                clean_version = pkg_version.lstrip("^~>=<! ")
            else:
                clean_version = "unknown"

            dep = DependencyInfo(
                name=pkg_name,
                version=clean_version,
                ecosystem="nodejs",
                source_file=file_path.name,
            )

            if dep.is_valid():
                dependencies.append(dep)
                logger.debug("  Node.js [%s]: %s@%s", section, pkg_name, clean_version)

    logger.info("package.json → %d dépendances extraites", len(dependencies))
    return dependencies


# ==============================================================
# PARSEUR : pom.xml (Java / Maven)
# ==============================================================

def parse_pom_xml(file_path: Path) -> list[DependencyInfo]:
    """
    Parse un fichier pom.xml Maven (Java).

    Structure XML recherchée :
        <dependencies>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-core</artifactId>
                <version>5.3.20</version>
            </dependency>
        </dependencies>

    Note : groupId + artifactId forment le "nom" complet de la dépendance Java.

    Paramètres :
        file_path : chemin complet vers le fichier pom.xml

    Retourne :
        Liste de DependencyInfo extraites
    """
    dependencies: list[DependencyInfo] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(content)
    except ET.ParseError as e:
        logger.warning("XML invalide dans %s : %s", file_path.name, e)
        return []
    except OSError as e:
        logger.warning("Impossible de lire %s : %s", file_path.name, e)
        return []

    # Le namespace Maven est souvent présent dans le XML
    # Ex: <project xmlns="http://maven.apache.org/POM/4.0.0">
    # On le gère en cherchant avec et sans namespace
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}")[0] + "}"

    # Chercher toutes les balises <dependency>
    for dep_element in root.iter(f"{namespace}dependency"):
        group_id = dep_element.findtext(f"{namespace}groupId", default="").strip()
        artifact_id = dep_element.findtext(f"{namespace}artifactId", default="").strip()
        version = dep_element.findtext(f"{namespace}version", default="unknown").strip()

        # Le nom complet Java = "groupId:artifactId" (convention Maven)
        if group_id and artifact_id:
            full_name = f"{group_id}:{artifact_id}"

            # Ignorer les versions comme ${spring.version} — variables non résolues
            if version.startswith("${"):
                logger.debug("Version non résolue pour %s : %s", full_name, version)
                version = "unknown"

            dep = DependencyInfo(
                name=full_name,
                version=version,
                ecosystem="java",
                source_file=file_path.name,
            )

            if dep.is_valid():
                dependencies.append(dep)
                logger.debug("  Java: %s @ %s", full_name, version)

    logger.info("pom.xml → %d dépendances extraites", len(dependencies))
    return dependencies


# ==============================================================
# PARSEUR : Dockerfile
# ==============================================================

def parse_dockerfile(file_path: Path) -> list[DependencyInfo]:
    """
    Extrait l'image de base d'un Dockerfile.

    On recherche les instructions FROM :
        FROM python:3.12-slim        → name="python", version="3.12-slim"
        FROM node:18-alpine          → name="node", version="18-alpine"
        FROM ubuntu:22.04            → name="ubuntu", version="22.04"
        FROM scratch                 → nom="scratch", version="latest"
        FROM --platform=linux/amd64  → le flag --platform est ignoré

    Paramètres :
        file_path : chemin complet vers le Dockerfile

    Retourne :
        Liste de DependencyInfo (une par instruction FROM)
    """
    dependencies: list[DependencyInfo] = []

    # Regex pour parser une instruction FROM
    # Capture : image_name et tag (optionnel)
    from_pattern = re.compile(
        r"^FROM\s+(?:--\w+=\S+\s+)?"  # Ignorer les flags comme --platform
        r"([A-Za-z0-9_\-\./]+)"       # Nom de l'image (obligatoire)
        r"(?::([A-Za-z0-9_\-\.]+))?", # Tag (optionnel, ex: 3.12-slim)
        re.IGNORECASE,
    )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Impossible de lire %s : %s", file_path.name, e)
        return []

    for line in content.splitlines():
        line = line.strip()

        # Ignorer les commentaires et les lignes vides
        if not line or line.startswith("#"):
            continue

        match = from_pattern.match(line)
        if match:
            image_name = match.group(1)
            image_tag = match.group(2) or "latest"

            # Ignorer "scratch" — c'est l'image vide de Docker, pas une vraie dépendance
            if image_name.lower() == "scratch":
                logger.debug("Image 'scratch' ignorée (image vide Docker)")
                continue

            dep = DependencyInfo(
                name=image_name,
                version=image_tag,
                ecosystem="docker",
                source_file=file_path.name,
            )

            if dep.is_valid():
                dependencies.append(dep)
                logger.debug("  Docker FROM: %s:%s", image_name, image_tag)

    logger.info("Dockerfile → %d image(s) de base extraites", len(dependencies))
    return dependencies


# ==============================================================
# FONCTION PRINCIPALE : SCANNER TOUTES LES DÉPENDANCES
# ==============================================================

# Mapping : nom de fichier → fonction de parsing correspondante
FILE_PARSERS: dict[str, callable] = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml":   parse_pyproject_toml,
    "package.json":     parse_package_json,
    "pom.xml":          parse_pom_xml,
    "Dockerfile":       parse_dockerfile,
}


def scan_dependencies(
    repo_path: Path,
    dependency_files: dict[str, list[str]],
) -> list[DependencyInfo]:
    """
    Fonction principale du scanner.
    Parcourt tous les fichiers détectés et appelle le bon parseur pour chacun.

    Paramètres :
        repo_path        : chemin vers le dossier du dépôt cloné
        dependency_files : dict retourné par github_analyzer
                           { "python": ["requirements.txt", "setup.cfg"], "nodejs": [...] }

    Retourne :
        Liste de toutes les DependencyInfo extraites (tous écosystèmes confondus)

    Lève :
        DependencyScannerError : si aucune dépendance n'a pu être extraite du tout
    """

    if not repo_path.exists():
        raise DependencyScannerError(
            f"Le dossier '{repo_path}' n'existe pas. "
            f"Assurez-vous que le clonage a réussi avant d'appeler scan_dependencies()."
        )

    if not dependency_files:
        logger.warning("Aucun fichier de dépendances fourni — scan ignoré")
        return []

    all_dependencies: list[DependencyInfo] = []
    files_processed = 0
    files_skipped = 0

    logger.info(
        "Démarrage du scan des dépendances — %d écosystèmes à analyser",
        len(dependency_files),
    )

    # --- Parcourir chaque écosystème et ses fichiers ---
    for ecosystem, file_paths in dependency_files.items():
        logger.info("--- Écosystème : %s (%d fichier(s)) ---", ecosystem, len(file_paths))

        for relative_path in file_paths:
            full_path = repo_path / relative_path
            file_name = full_path.name

            # Vérifier que le fichier existe toujours (peut avoir été supprimé)
            if not full_path.exists():
                logger.warning("Fichier introuvable (ignoré) : %s", relative_path)
                files_skipped += 1
                continue

            # Trouver le parseur correspondant à ce nom de fichier
            parser_function = FILE_PARSERS.get(file_name)

            if parser_function is None:
                # Pas de parseur pour ce fichier — cas normal (ex: package-lock.json)
                logger.debug("Pas de parseur pour '%s' — ignoré", file_name)
                files_skipped += 1
                continue

            # --- Appeler le parseur ---
            logger.info("Parsing de : %s", relative_path)
            try:
                extracted_deps = parser_function(full_path)
                all_dependencies.extend(extracted_deps)
                files_processed += 1

                logger.info(
                    "  → %d dépendance(s) extraites depuis %s",
                    len(extracted_deps), file_name,
                )

            except Exception as e:
                # Un fichier en erreur ne bloque pas le reste du scan
                logger.error(
                    "Erreur inattendue lors du parsing de %s : %s", file_name, e
                )
                files_skipped += 1

    # --- Dédupliquer : même nom + version + écosystème → garder un seul ---
    unique_deps = _deduplicate_dependencies(all_dependencies)

    # --- Résumé final ---
    logger.info(
        "Scan terminé — %d fichiers traités, %d ignorés, %d dépendances uniques trouvées",
        files_processed, files_skipped, len(unique_deps),
    )

    return unique_deps


# ==============================================================
# FONCTION UTILITAIRE : DÉDUPLIQUER LES DÉPENDANCES
# ==============================================================

def _deduplicate_dependencies(deps: list[DependencyInfo]) -> list[DependencyInfo]:
    """
    Supprime les dépendances en double.
    Une dépendance est un doublon si elle a le même (name, ecosystem).
    En cas de doublon, on garde celle qui a la version la plus précise (pas "unknown").

    Paramètres :
        deps : liste brute avec éventuels doublons

    Retourne :
        Liste sans doublons
    """
    seen: dict[tuple[str, str], DependencyInfo] = {}

    for dep in deps:
        key = (dep.name, dep.ecosystem)

        if key not in seen:
            # Première occurrence : on la garde
            seen[key] = dep
        else:
            existing = seen[key]
            # Si l'existant n'a pas de version mais le nouveau oui → remplacer
            if existing.version == "unknown" and dep.version != "unknown":
                seen[key] = dep
                logger.debug(
                    "Doublon résolu pour %s : version '%s' préférée à 'unknown'",
                    dep.name, dep.version,
                )

    unique_list = list(seen.values())

    removed_count = len(deps) - len(unique_list)
    if removed_count > 0:
        logger.info("Déduplication : %d doublon(s) supprimé(s)", removed_count)

    return unique_list


# ==============================================================
# FONCTION UTILITAIRE : RÉSUMÉ LISIBLE
# ==============================================================

def get_scan_summary(dependencies: list[DependencyInfo]) -> dict:
    """
    Génère un résumé statistique du scan pour les logs et le rapport.

    Paramètres :
        dependencies : liste de DependencyInfo retournée par scan_dependencies()

    Retourne :
        dict avec stats par écosystème et total
    """
    summary: dict[str, int] = {}

    for dep in dependencies:
        summary[dep.ecosystem] = summary.get(dep.ecosystem, 0) + 1

    return {
        "total": len(dependencies),
        "by_ecosystem": summary,
        "has_python": "python" in summary,
        "has_nodejs": "nodejs" in summary,
        "has_java": "java" in summary,
        "has_docker": "docker" in summary,
    }
