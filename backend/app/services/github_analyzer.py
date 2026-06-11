"""
Service GitHub Analyzer — clone un dépôt et détecte les fichiers de dépendances.

C'est le PREMIER service appelé dans la chaîne d'analyse :
URL GitHub → [github_analyzer] → [dependency_scanner] → [cve_service] → ...

GESTION D'ERREURS :
- URL invalide → rejetée avant le clonage
- Repo privé / inexistant → GitCommandError capturée
- Timeout de clonage → limite de 120 secondes
- Disque plein / permission → OSError capturée
- Nettoyage garanti → bloc finally
"""

import logging
import os
import re
import shutil
import stat
import time
from pathlib import Path

from git import Repo, GitCommandError

from app.core.config import settings

logger = logging.getLogger(__name__)


# ==============================================================
# CONSTANTES DE CONFIGURATION
# ==============================================================

# Timeout maximum pour le clonage (en secondes)
# Au-delà, on considère que le repo est trop gros
CLONE_TIMEOUT_SECONDS: int = 120

# Pattern regex pour valider une URL GitHub
# Accepte : https://github.com/user/repo ou https://github.com/user/repo.git
GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$"
)


# ==============================================================
# FICHIERS DE DÉPENDANCES CONNUS
# ==============================================================
# Ce dictionnaire mappe chaque écosystème (python, nodejs, java...)
# aux noms de fichiers qui contiennent la liste des dépendances.

DEPENDENCY_FILES: dict[str, list[str]] = {
    "python": [
        "requirements.txt",       # Le plus courant en Python
        "Pipfile",                # Utilisé par pipenv
        "pyproject.toml",         # Standard moderne (PEP 621)
        "setup.py",               # Ancien format de packaging
        "setup.cfg",              # Configuration déclarative
    ],
    "nodejs": [
        "package.json",           # Toujours présent dans un projet Node.js
        "package-lock.json",      # Versions exactes installées
        "yarn.lock",              # Alternative avec Yarn
    ],
    "java": [
        "pom.xml",                # Maven (gestionnaire de dépendances Java)
        "build.gradle",           # Gradle (alternative à Maven)
    ],
    "ruby": [
        "Gemfile",                # Bundler (gestionnaire Ruby)
        "Gemfile.lock",           # Versions exactes
    ],
    "php": [
        "composer.json",          # Composer (gestionnaire PHP)
        "composer.lock",          # Versions exactes
    ],
    "rust": [
        "Cargo.toml",             # Cargo (gestionnaire Rust)
        "Cargo.lock",             # Versions exactes
    ],
    "go": [
        "go.mod",                 # Go modules
        "go.sum",                 # Checksums des dépendances
    ],
    "docker": [
        "Dockerfile",             # Définition d'image Docker
        "docker-compose.yml",     # Orchestration multi-conteneurs
        "docker-compose.yaml",    # Variante d'extension
    ],
}


# ==============================================================
# EXCEPTION PERSONNALISÉE
# ==============================================================

class GitHubAnalyzerError(Exception):
    """
    Exception spécifique au GitHub Analyzer.
    Permet de distinguer nos erreurs des erreurs génériques Python.
    Utilisée par la route pour retourner un message clair à l'utilisateur.
    """
    pass


def _force_remove_readonly(func, path, excinfo) -> None:
    """
    Handler pour shutil.rmtree sur Windows.

    Problème Windows : Git marque certains fichiers dans .git/ en lecture
    seule (read-only). shutil.rmtree échoue alors avec PermissionError.

    Solution : quand rmtree rencontre une erreur de permission, on enlève
    l'attribut read-only avec os.chmod puis on réessaie la suppression.

    Paramètres (imposés par shutil.rmtree) :
        func : la fonction qui a échoué (os.unlink ou os.rmdir)
        path : le chemin du fichier bloqué
        excinfo : les infos de l'exception
    """
    try:
        # Enlever l'attribut read-only (0o777 = tous les droits)
        os.chmod(path, stat.S_IWRITE)
        func(path)  # Réessayer la suppression
    except Exception:
        pass  # Si ça échoue encore, on ignore (le finally s'occupera du reste)


# ==============================================================
# FONCTION : VALIDER L'URL GITHUB
# ==============================================================

def validate_github_url(repo_url: str) -> str:
    """
    Vérifie que l'URL est une URL GitHub valide AVANT de tenter le clonage.
    Ça évite de lancer un git clone sur une URL quelconque.

    Paramètres :
        repo_url : l'URL à valider

    Retourne :
        str : l'URL nettoyée (sans espaces, sans / final)

    Lève :
        GitHubAnalyzerError : si l'URL n'est pas valide
    """

    # --- Nettoyage basique ---
    cleaned_url = repo_url.strip().rstrip("/")

    # --- Vérification avec la regex ---
    if not GITHUB_URL_PATTERN.match(cleaned_url):
        logger.error("URL GitHub invalide : %s", cleaned_url)
        raise GitHubAnalyzerError(
            f"URL invalide : '{cleaned_url}'. "
            f"Format attendu : https://github.com/utilisateur/nom-du-repo"
        )

    logger.debug("URL validée : %s", cleaned_url)
    return cleaned_url


# ==============================================================
# FONCTION : CLONER UN DÉPÔT
# ==============================================================

def clone_repository(repo_url: str) -> Path:
    """
    Clone un dépôt GitHub dans un dossier temporaire.

    Paramètres :
        repo_url : URL complète du dépôt (déjà validée)

    Retourne :
        Path : le chemin vers le dossier cloné

    Lève :
        GitHubAnalyzerError : si le clonage échoue (avec un message clair)
    """

    # --- Étape 1 : Extraire le nom du repo ---
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")

    # --- Étape 2 : Construire le chemin de destination ---
    clone_dir = Path(settings.CLONE_DIRECTORY)

    # Créer le dossier temp_repositories s'il n'existe pas
    try:
        clone_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Impossible de créer le dossier %s : %s", clone_dir, e)
        raise GitHubAnalyzerError(
            f"Impossible de créer le dossier de clonage : {e}"
        ) from e

    clone_path = clone_dir / repo_name

    # --- Étape 3 : Supprimer si le dossier existe déjà ---
    if clone_path.exists():
        logger.info("Nettoyage du dossier existant : %s", clone_path)
        try:
            # Sur Windows, les fichiers .git sont en read-only → on utilise
            # _force_remove_readonly comme handler pour les débloquer avant suppression
            shutil.rmtree(clone_path, onexc=_force_remove_readonly)
        except Exception as e:
            # Dernière tentative — ignore toutes les erreurs restantes
            logger.warning(
                "Nettoyage difficile de %s : %s. Nouvelle tentative...", clone_path, e
            )
            shutil.rmtree(clone_path, ignore_errors=True)
            if clone_path.exists():
                raise GitHubAnalyzerError(
                    f"Impossible de supprimer le dossier existant '{clone_path}'. "
                    f"Fermez les programmes qui pourraient l'utiliser et réessayez."
                ) from e

    # --- Étape 4 : Cloner avec timeout ---
    logger.info("Clonage de %s vers %s ...", repo_url, clone_path)
    start_time = time.time()

    try:
        Repo.clone_from(
            url=repo_url,
            to_path=str(clone_path),
            depth=1,  # Clone superficiel = dernier commit seulement (rapide)
            env={
                # Timeout Git : coupe la connexion si trop long
                "GIT_HTTP_LOW_SPEED_LIMIT": "1000",       # Minimum 1 Ko/s
                "GIT_HTTP_LOW_SPEED_TIME": "30",           # Pendant 30 secondes max
            },
        )

        # Calculer le temps de clonage
        elapsed = round(time.time() - start_time, 1)
        logger.info("Clonage réussi en %.1f secondes : %s", elapsed, repo_name)

    except GitCommandError as e:
        elapsed = round(time.time() - start_time, 1)
        error_message = str(e).lower()

        # --- Analyser le TYPE d'erreur pour un message clair ---

        if "not found" in error_message or "404" in error_message:
            # Le repo n'existe pas
            logger.error("Dépôt non trouvé : %s", repo_url)
            raise GitHubAnalyzerError(
                f"Dépôt non trouvé : '{repo_url}'. "
                f"Vérifiez que l'URL est correcte et que le dépôt est public."
            ) from e

        elif "authentication" in error_message or "403" in error_message:
            # Le repo est privé
            logger.error("Accès refusé (repo privé ?) : %s", repo_url)
            raise GitHubAnalyzerError(
                f"Accès refusé pour '{repo_url}'. "
                f"Le dépôt est probablement privé. "
                f"Seuls les dépôts publics sont supportés."
            ) from e

        elif "could not resolve" in error_message or "unable to access" in error_message:
            # Pas de connexion internet
            logger.error("Erreur réseau lors du clonage de %s", repo_url)
            raise GitHubAnalyzerError(
                f"Erreur réseau : impossible d'accéder à '{repo_url}'. "
                f"Vérifiez votre connexion internet."
            ) from e

        elif elapsed > CLONE_TIMEOUT_SECONDS:
            # Timeout dépassé
            logger.error("Timeout de clonage après %.1fs : %s", elapsed, repo_url)
            raise GitHubAnalyzerError(
                f"Le clonage de '{repo_url}' a pris trop de temps "
                f"({elapsed}s > {CLONE_TIMEOUT_SECONDS}s max). "
                f"Le dépôt est peut-être trop volumineux."
            ) from e

        else:
            # Erreur inconnue — on log tout pour le debug
            logger.error(
                "Erreur inattendue lors du clonage de %s après %.1fs : %s",
                repo_url, elapsed, str(e),
            )
            raise GitHubAnalyzerError(
                f"Échec du clonage de '{repo_url}' : {str(e)[:200]}"
            ) from e

    except OSError as e:
        # Disque plein ou problème de fichiers
        logger.error("Erreur système lors du clonage : %s", e)
        raise GitHubAnalyzerError(
            f"Erreur système lors du clonage : {e}. "
            f"Vérifiez l'espace disque disponible."
        ) from e

    return clone_path


# ==============================================================
# FONCTION : DÉTECTER LES FICHIERS DE DÉPENDANCES
# ==============================================================

def detect_dependency_files(repo_path: Path) -> dict[str, list[str]]:
    """
    Parcourt un dépôt cloné et identifie les fichiers de dépendances.

    Paramètres :
        repo_path : chemin vers le dossier du dépôt cloné

    Retourne :
        dict : { "python": ["requirements.txt"], "docker": ["Dockerfile"], ... }
               Seuls les écosystèmes avec des fichiers trouvés sont inclus.
    """

    # Vérification : le dossier existe-t-il ?
    if not repo_path.exists():
        logger.error("Le dossier du dépôt n'existe pas : %s", repo_path)
        raise GitHubAnalyzerError(
            f"Le dossier cloné '{repo_path}' n'existe pas. Le clonage a peut-être échoué."
        )

    found_files: dict[str, list[str]] = {}

    # --- Parcours récursif de tous les fichiers ---
    try:
        all_files_in_repo = [f for f in repo_path.rglob("*") if f.is_file()]
    except PermissionError as e:
        logger.error("Permission refusée lors du scan de %s : %s", repo_path, e)
        raise GitHubAnalyzerError(
            f"Permission refusée lors du scan des fichiers : {e}"
        ) from e

    logger.info("Scan de %d fichiers dans %s", len(all_files_in_repo), repo_path.name)

    # --- Pour chaque écosystème, chercher les fichiers connus ---
    for ecosystem, filenames in DEPENDENCY_FILES.items():
        for file_in_repo in all_files_in_repo:
            if file_in_repo.name in filenames:
                if ecosystem not in found_files:
                    found_files[ecosystem] = []

                relative_path = str(file_in_repo.relative_to(repo_path))
                found_files[ecosystem].append(relative_path)

                logger.info("Fichier trouvé : [%s] %s", ecosystem, relative_path)

    # --- Log résumé ---
    if found_files:
        total = sum(len(files) for files in found_files.values())
        logger.info(
            "Détection terminée : %d fichiers dans %d écosystèmes",
            total, len(found_files),
        )
    else:
        logger.warning("Aucun fichier de dépendances trouvé dans %s", repo_path.name)

    return found_files


# ==============================================================
# FONCTION : NETTOYER LE DOSSIER CLONÉ
# ==============================================================

def cleanup_repository(repo_path: Path) -> None:
    """
    Supprime le dossier d'un dépôt cloné pour libérer l'espace disque.
    Appelée dans un bloc 'finally' pour garantir le nettoyage même en cas d'erreur.
    """
    if not repo_path or not repo_path.exists():
        logger.debug("Rien à nettoyer : %s", repo_path)
        return

    try:
        # Utiliser le handler Windows pour les fichiers .git en read-only
        shutil.rmtree(repo_path, onexc=_force_remove_readonly)
        logger.info("Dossier nettoyé : %s", repo_path)
    except Exception:
        # Deuxième tentative — ignore toutes les erreurs (nettoyage best-effort)
        logger.warning("Nettoyage difficile pour %s, tentative forcée...", repo_path)
        shutil.rmtree(repo_path, ignore_errors=True)
        if repo_path.exists():
            logger.error("ÉCHEC du nettoyage de %s — à supprimer manuellement", repo_path)
        else:
            logger.info("Nettoyage forcé réussi : %s", repo_path)
        # On ne propage PAS l'erreur — le nettoyage ne doit pas bloquer l'analyse


# ==============================================================
# FONCTION ORCHESTRATRICE : ANALYSER UN DÉPÔT
# ==============================================================

def analyze_repository(repo_url: str) -> dict:
    """
    Fonction principale qui orchestre : validation → clonage → détection → nettoyage.
    C'est CETTE fonction qui sera appelée par la route /analyze.

    Paramètres :
        repo_url : URL GitHub à analyser

    Retourne :
        dict avec les fichiers détectés, ou un message d'erreur clair

    Lève :
        GitHubAnalyzerError : si une erreur critique survient
    """

    # --- Étape 1 : Valider l'URL AVANT tout ---
    validated_url = validate_github_url(repo_url)
    repo_name = validated_url.split("/")[-1].replace(".git", "")

    repo_path = None

    try:
        # --- Étape 2 : Cloner ---
        repo_path = clone_repository(validated_url)

        # --- Étape 3 : Détecter les fichiers ---
        dependency_files = detect_dependency_files(repo_path)

        # --- Étape 4 : Construire le résultat ---
        result = {
            "repo_name": repo_name,
            "repo_url": validated_url,
            "dependency_files": dependency_files,
            "ecosystems_found": list(dependency_files.keys()),
        }

        logger.info(
            "Analyse GitHub terminée pour %s — Écosystèmes : %s",
            repo_name, result["ecosystems_found"],
        )

        return result

    finally:
        # --- Étape 5 : TOUJOURS nettoyer, même en cas d'erreur ---
        if repo_path:
            cleanup_repository(repo_path)
