"""
Service IA — génère des recommandations de sécurité personnalisées pour une analyse.
Utilise Gemini API comme fournisseur principal, OpenRouter en fallback,
et dispose d'un système de repli statique (rule-based) si aucun service n'est accessible.
"""

import json
import logging
from typing import Any, Optional
import httpx
from google import genai
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.recommendation import Recommendation, TargetType
from app.services.score_service import ScoreResult
from app.services.cve_service import VulnerabilityResult, Severity

logger = logging.getLogger(__name__)


def generate_recommendations(
    db: Session,
    analysis_id: int,
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[Recommendation]:
    """
    Orchestre la génération de recommandations.
    Stratégie de sélection du fournisseur IA :
        1. Gemini API (fournisseur principal — clé configurée dans .env)
        2. OpenRouter API (fallback si Gemini échoue)
        3. Système expert statique (dernier recours si aucune API ne répond)
    Enregistre le résultat en base de données avant de le retourner.
    """
    logger.info("=== Génération des recommandations de sécurité ===")
    provider = settings.AI_PROVIDER.lower()
    recommendations_data = []

    # Étape 1 : Essayer Gemini en priorité
    if settings.GEMINI_API_KEY:
        try:
            recommendations_data = _generate_with_gemini(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "gemini"
            logger.info("Recommandations générées avec succès via Gemini API")
        except Exception as e:
            logger.error("Échec de la génération avec Gemini : %s", e)
            recommendations_data = []  # Forcer le passage au fallback suivant

    # Étape 2 : Si Gemini n'a rien retourné, essayer OpenRouter
    if not recommendations_data and settings.OPENROUTER_API_KEY:
        try:
            recommendations_data = _generate_with_openrouter(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "openrouter"
            logger.info("Recommandations générées avec succès via OpenRouter API (fallback)")
        except Exception as e:
            logger.error("Échec de la génération avec OpenRouter : %s", e)
            recommendations_data = []

    # Étape 3 : Dernier recours — système expert statique
    if not recommendations_data:
        logger.warning("Aucune IA disponible ou toutes ont échoué. Utilisation du fallback statique.")
        provider = "static_fallback"
        recommendations_data = _generate_static_fallback(score_result, cve_results)

    # Étape 2 : Sauvegarder les recommandations dans la base de données
    db_recommendations = []
    try:
        # Supprimer d'éventuelles recommandations existantes pour cette analyse
        db.query(Recommendation).filter(Recommendation.analysis_id == analysis_id).delete()

        for rec in recommendations_data:
            # S'assurer que le type de cible est valide
            target_str = rec.get("target_type", "global").lower()
            if target_str == "dependency":
                target_type = TargetType.DEPENDENCY
            elif target_str == "docker":
                target_type = TargetType.DOCKER
            else:
                target_type = TargetType.GLOBAL

            db_rec = Recommendation(
                analysis_id=analysis_id,
                target_type=target_type,
                recommendation_text=rec.get("recommendation_text", ""),
                provider=provider
            )
            db.add(db_rec)
            db_recommendations.append(db_rec)

        db.commit()
        logger.info("%d recommandations sauvegardées en base de données", len(db_recommendations))
    except Exception as e:
        db.rollback()
        logger.error("Erreur lors de la sauvegarde des recommandations en base : %s", e)

    return db_recommendations


def _build_prompt(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> str:
    """
    Construit un prompt détaillé et structuré pour l'IA.
    Inclut le contexte complet du projet pour permettre à Gemini
    de formuler des recommandations personnalisées et pertinentes.
    """

    # 1. Contexte du projet analysé
    eco_str = ", ".join(ecosystems) if ecosystems else "non détecté"
    project_context = (
        f"Nom du dépôt GitHub analysé : {repo_name}\n"
        f"Écosystèmes détectés : {eco_str}\n"
        f"Nombre total de dépendances : {total_deps}\n"
    )

    # 2. Résumé du score de sécurité
    summary = (
        f"Score de sécurité global : {score_result.final_score}/100\n"
        f"Niveau de risque : {score_result.risk_level.value}\n"
        f"Nombre total de CVE : {score_result.total_cve}\n"
        f"Dockerfile présent : {'Oui' if score_result.has_docker else 'Non'}\n"
    )

    # 3. Détail des pénalités appliquées par la matrice 3D
    penalties_str = ""
    for p in score_result.penalties:
        penalties_str += f"- {p.category} : -{p.applied} pts\n"

    # 4. Liste des CVE critiques et importantes (max 15 pour ne pas saturer le contexte)
    cves_str = ""
    cve_count = 0
    for dep_key, vulns in cve_results.items():
        for vuln in vulns:
            # Comparaison avec l'enum Severity (pas avec des strings)
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                cve_count += 1
                if cve_count <= 15:
                    cves_str += (
                        f"- [{vuln.severity.value}] {vuln.cve_id} sur {dep_key} | "
                        f"CVSS: {vuln.cvss_score} | "
                        f"Patch: {vuln.fixed_version or 'Non disponible'} | "
                        f"Exploit public: {'Oui' if vuln.exploit_available else 'Non'}\n"
                    )

    # 5. Prompt complet avec instructions de formatage
    prompt = f"""Tu es un expert en cybersécurité spécialisé dans la sécurisation de la chaîne d'approvisionnement logicielle (Software Supply Chain Security).

CONTEXTE DU PROJET ANALYSÉ :
{project_context}

RÉSULTATS DU SCAN DE SÉCURITÉ :
{summary}

DÉTAILS DES PÉNALITÉS APPLIQUÉES (Matrice de risque 3D : Sévérité × Exploitabilité × Impact) :
{penalties_str if penalties_str else "Aucune pénalité."}

VULNÉRABILITÉS DÉTECTÉES (max 15 affichées sur {cve_count} total) :
{cves_str if cves_str else "Aucune vulnérabilité majeure."}

En te basant sur ces résultats concrets, rédige des recommandations claires, concrètes et actionnables pour corriger ces faiblesses de sécurité.
Pour chaque recommandation, précise le nom exact du paquet concerné et la version corrective si disponible.
Tu dois classer tes recommandations en 3 types de cibles :
- "dependency" (mises à jour de paquets vulnérables spécifiques avec les versions correctives)
- "docker" (bonnes pratiques Dockerfile, images de base sécurisées, utilisateur non-root)
- "global" (mise en place de pipelines CI/CD de sécurité, Dependabot, audits réguliers)

Tu dois impérativement retourner le résultat sous la forme d'un tableau JSON valide contenant des objets avec cette structure exacte, sans aucun autre texte autour :
[
  {{
    "target_type": "dependency",
    "recommendation_text": "Explication claire de ce qu'il faut mettre à jour."
  }},
  {{
    "target_type": "docker",
    "recommendation_text": "Correction pour le Dockerfile."
  }}
]
Ne mets pas de balises markdown de type ```json. Retourne uniquement la chaîne de caractères JSON brute.
"""
    return prompt


def _generate_with_gemini(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """Appelle l'API Gemini (fournisseur principal) pour obtenir les recommandations."""
    # Nouveau SDK google-genai (v2.x) : utilise un Client avec api_key
    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    prompt = _build_prompt(score_result, cve_results, repo_name, ecosystems, total_deps)

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    text = response.text.strip()

    # Nettoyer d'eventuels blocs de code markdown s'ils ont ete retournes malgre la consigne
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    return json.loads(text)


def _generate_with_openrouter(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """Appelle l'API OpenRouter (fallback si Gemini échoue)."""
    prompt = _build_prompt(score_result, cve_results, repo_name, ecosystems, total_deps)
    
    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": "google/gemini-2.5-flash",  # Utilise Gemini via OpenRouter
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    with httpx.Client() as client:
        response = client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=settings.HTTP_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        
    text = data["choices"][0]["message"]["content"].strip()
    
    # Nettoyer d'éventuels blocs de code markdown
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
        
    return json.loads(text)


def _generate_static_fallback(score_result: ScoreResult, cve_results: dict[str, list[VulnerabilityResult]]) -> list[dict]:
    """
    Système expert de secours basé sur des règles statiques.
    Génère des recommandations ciblées si l'IA n'est pas disponible.
    """
    logger.info("Génération des recommandations via le système de secours statique")
    recommendations = []

    # 1. Recommandations sur les dépendances
    dependency_recs = []
    critical_cves = []
    high_cves = []
    
    for dep_key, vulns in cve_results.items():
        for vuln in vulns:
            if vuln.severity == "CRITICAL":
                critical_cves.append((dep_key, vuln))
            elif vuln.severity == "HIGH":
                high_cves.append((dep_key, vuln))

    if critical_cves:
        for dep_key, vuln in critical_cves[:3]:  # Max 3 recommandations spécifiques
            patch_info = f" (version corrective conseillée : {vuln.fixed_version})" if vuln.fixed_version else ""
            dependency_recs.append(
                f"Urgent : Mettre à jour la dépendance {dep_key} immédiatement pour corriger la faille critique "
                f"{vuln.cve_id}. {vuln.description[:120]}...{patch_info}"
            )
    
    if high_cves and len(dependency_recs) < 3:
        for dep_key, vuln in high_cves[:2]:
            patch_info = f" (version conseillée : {vuln.fixed_version})" if vuln.fixed_version else ""
            dependency_recs.append(
                f"Sécurité : Mettre à jour le paquet {dep_key} pour corriger la faille importante "
                f"{vuln.cve_id}. {patch_info}"
            )

    # Si aucune faille spécifique n'a été trouvée mais que le score n'est pas parfait
    if not dependency_recs and score_result.total_cve > 0:
        dependency_recs.append("Vérifier et mettre à jour régulièrement l'ensemble des dépendances obsolètes détectées.")

    for rec_text in dependency_recs:
        recommendations.append({
            "target_type": "dependency",
            "recommendation_text": rec_text
        })

    # 2. Recommandations Docker
    if score_result.has_docker:
        docker_recs = []
        # On peut avoir accès aux détails de DockerResult, mais pour rester simple
        # on fait des suggestions basées sur les pénalités appliquées
        has_root_penalty = any("root" in p.category.lower() for p in score_result.penalties)
        has_vuln_penalty = any("docker" in p.category.lower() and "vuln" in p.category.lower() for p in score_result.penalties)

        if has_root_penalty:
            docker_recs.append(
                "Dockerfile : Configurer un utilisateur non-privilégié (ex: USER nonroot) "
                "au lieu de laisser l'image s'exécuter en tant que root."
            )
        if has_vuln_penalty:
            docker_recs.append(
                "Dockerfile : Utiliser une image de base plus sécurisée et minimale (comme alpine ou slim) "
                "pour réduire le nombre de vulnérabilités système détectées par Trivy."
            )
        
        # Recommandation générique Docker si besoin
        if not docker_recs:
            docker_recs.append("Dockerfile : Vérifier que les variables d'environnement ne contiennent pas de secrets codés en dur.")

        for rec_text in docker_recs:
            recommendations.append({
                "target_type": "docker",
                "recommendation_text": rec_text
            })

    # 3. Recommandations globales
    global_recs = []
    if score_result.final_score < 70:
        global_recs.append("Activer GitHub Dependabot ou un outil similaire sur ce dépôt pour automatiser la détection des failles.")
        global_recs.append("Intégrer une étape de sécurité (DevSecOps) dans votre pipeline CI/CD pour bloquer les builds contenant des CVE critiques.")
    else:
        global_recs.append("Bon niveau général. Planifier un audit mensuel des dépendances pour maintenir ce score.")

    for rec_text in global_recs:
        recommendations.append({
            "target_type": "global",
            "recommendation_text": rec_text
        })

    return recommendations
