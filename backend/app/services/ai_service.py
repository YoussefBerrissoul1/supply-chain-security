"""
Service IA — génère des recommandations de sécurité personnalisées pour une analyse.
Utilise Gemini API comme fournisseur principal, OpenRouter en fallback,
et dispose d'un système de repli statique (rule-based) si aucun service n'est accessible.
"""

import json
import logging
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

    # Vérifier si la clé Gemini est un vrai token API (commence par 'AIza')
    # Une clé commençant par 'AQ.' est un token OAuth, pas une clé API Gemini valide
    gemini_key = settings.GEMINI_API_KEY or ""
    gemini_key_valid = bool(gemini_key) and not gemini_key.startswith("AQ.")
    if gemini_key and not gemini_key_valid:
        logger.warning(
            "Clé Gemini détectée mais invalide (format OAuth token 'AQ.' au lieu de 'AIza...'). "
            "Obtenez une vraie clé sur https://aistudio.google.com/app/apikey"
        )

    # Étape 1 : Essayer Gemini en priorité (seulement si clé valide)
    if gemini_key_valid:
        try:
            recommendations_data = _generate_with_gemini(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "gemini"
            logger.info("Recommandations générées avec succès via Gemini API (%d recs)", len(recommendations_data))
        except Exception as e:
            logger.error("Échec de la génération avec Gemini : %s", e)
            recommendations_data = []
    else:
        logger.info("Gemini ignoré (clé absente ou invalide) — passage au fallback suivant")

    # Étape 2 : Si Gemini n'a rien retourné, essayer OpenRouter
    if not recommendations_data and settings.OPENROUTER_API_KEY:
        try:
            recommendations_data = _generate_with_openrouter(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "openrouter"
            logger.info("Recommandations générées avec succès via OpenRouter (qwen3-coder) (%d recs)", len(recommendations_data))
        except Exception as e:
            logger.error("Échec de la génération avec OpenRouter : %s", e)
            recommendations_data = []

    # Étape 3 : Dernier recours — système expert statique
    if not recommendations_data:
        logger.warning("Aucune IA disponible. Utilisation du fallback statique.")
        provider = "static_fallback"
        recommendations_data = _generate_static_fallback(score_result, cve_results)

    # Sauvegarder les recommandations dans la base de données
    db_recommendations = []
    try:
        db.query(Recommendation).filter(Recommendation.analysis_id == analysis_id).delete()

        for rec in recommendations_data:
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
    Demande des recommandations en paragraphes clairs et actionnables.
    """
    eco_str = ", ".join(ecosystems) if ecosystems else "non détecté"
    project_context = (
        f"Nom du dépôt GitHub analysé : {repo_name}\n"
        f"Écosystèmes détectés : {eco_str}\n"
        f"Nombre total de dépendances : {total_deps}\n"
    )

    summary = (
        f"Score de sécurité global : {score_result.final_score}/100\n"
        f"Niveau de risque : {score_result.risk_level.value}\n"
        f"Nombre total de CVE : {score_result.total_cve}\n"
        f"Dockerfile présent : {'Oui' if score_result.has_docker else 'Non'}\n"
    )

    penalties_str = ""
    for p in score_result.penalties[:10]:  # Limiter pour ne pas saturer le contexte
        penalties_str += f"- {p.category} : -{p.applied:.0f} pts\n"

    # Construire la liste des CVEs pour le prompt
    cves_str = ""
    cve_count = 0
    critical_and_high = []
    for dep_key, vulns in cve_results.items():
        for vuln in vulns:
            sev_val = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev_val in ["CRITICAL", "HIGH"]:
                critical_and_high.append((dep_key, vuln, sev_val))

    # Trier par score CVSS décroissant
    critical_and_high.sort(key=lambda x: x[1].cvss_score, reverse=True)

    for dep_key, vuln, sev_val in critical_and_high[:20]:
        cve_count += 1
        exploit_note = " ⚠️ EXPLOIT PUBLIC CONNU" if vuln.exploit_available else ""
        fixed_note = f" → corriger avec v{vuln.fixed_version}" if vuln.fixed_version else " (aucun patch disponible)"
        cves_str += (
            f"- [{sev_val} CVSS:{vuln.cvss_score}] {vuln.cve_id} sur {dep_key}{fixed_note}{exploit_note}\n"
            f"  {vuln.description[:150]}...\n"
        )

    prompt = f"""Tu es un expert senior en cybersécurité spécialisé dans la sécurisation de la chaîne d'approvisionnement logicielle (Software Supply Chain Security). Tu analyses des résultats de scan de sécurité et génères des recommandations professionnelles.

CONTEXTE DU PROJET ANALYSÉ :
{project_context}

RÉSULTATS DU SCAN DE SÉCURITÉ :
{summary}

PÉNALITÉS APPLIQUÉES (Matrice de risque : Sévérité × Exploitabilité × Impact) :
{penalties_str if penalties_str else "Aucune pénalité."}

VULNÉRABILITÉS CRITIQUES ET HAUTES (top 20 sur {cve_count} total) :
{cves_str if cves_str else "Aucune vulnérabilité majeure détectée."}

MISSION : Génère exactement 5 recommandations de sécurité. Chaque recommandation DOIT :
1. Être rédigée sous forme d'un paragraphe de 3-5 phrases complètes (pas de listes à puces)
2. Citer EXPLICITEMENT les noms de paquets et versions détectés dans ce scan
3. Donner la version corrective exacte quand disponible
4. Expliquer POURQUOI cette vulnérabilité est dangereuse (impact concret)
5. Donner des instructions CONCRÈTES (commandes npm update X, pip install X==Y, etc.)
6. Indiquer si l'utilisateur PEUT ou NE PEUT PAS télécharger ce dépôt en sécurité

Pour les recommandations de type "dependency" : citer les paquets vulnérables par nom, donner la commande de mise à jour exacte.
Pour les recommandations "docker" : donner les modifications Dockerfile exactes.
Pour les recommandations "global" : donner les étapes DevSecOps à implémenter.

Tu dois retourner UNIQUEMENT un tableau JSON valide (sans markdown, sans backticks), avec exactement 5 objets :
[
  {{
    "target_type": "dependency",
    "recommendation_text": "Paragraphe de 3-5 phrases complet et actionnable citant les paquets par nom..."
  }},
  ...
]"""
    return prompt


def _generate_with_gemini(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """Appelle l'API Gemini (fournisseur principal) pour obtenir les recommandations.
    Timeout : 45 secondes pour éviter de bloquer l'analyse indéfiniment.
    """
    import threading
    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    prompt = _build_prompt(score_result, cve_results, repo_name, ecosystems, total_deps)

    # Appel Gemini avec timeout via thread
    result_container: list = []
    error_container: list = []

    def _call_gemini():
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            result_container.append(response.text.strip())
        except Exception as e:
            error_container.append(e)

    thread = threading.Thread(target=_call_gemini, daemon=True)
    thread.start()
    thread.join(timeout=45)  # Timeout 45 secondes max

    if thread.is_alive():
        raise TimeoutError("Gemini API n'a pas répondu en 45 secondes")

    if error_container:
        raise error_container[0]

    if not result_container:
        raise RuntimeError("Gemini API: aucune réponse reçue")

    text = result_container[0]

    # Nettoyer les blocs markdown
    text = _clean_json_response(text)

    result = json.loads(text)
    if not isinstance(result, list) or len(result) == 0:
        raise ValueError("Gemini a retourné un JSON vide ou invalide")

    return result


def _generate_with_openrouter(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """
    Appelle l'API OpenRouter (fallback si Gemini échoue).
    Utilise le modèle gratuit meta-llama/llama-3.3-70b-instruct:free.
    """
    prompt = _build_prompt(score_result, cve_results, repo_name, ecosystems, total_deps)

    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://supply-chain-security.app",  # Requis par OpenRouter
        "X-Title": "Supply Chain Security Scanner",           # Requis par OpenRouter
    }

    # Modèles disponibles gratuitement sur OpenRouter — par ordre de priorité
    # qwen3-coder:free = Qwen3 Coder 480B (meilleur modèle free, excellent pour code+sécurité)
    models_to_try = [
        "qwen/qwen3-coder:free",                             # PRIORITÉ 1 : Qwen3 Coder 480B
        "meta-llama/llama-3.3-70b-instruct:free",           # Fallback 2 : Llama 3.3 70B
        "mistralai/mistral-7b-instruct:free",               # Fallback 3 : Mistral 7B
    ]

    last_error = None
    for model in models_to_try:
        # Retry 2 fois par modèle en cas de rate-limit 429 (upstream saturé)
        for attempt in range(3):
            try:
                payload = {
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Tu es un expert en cybersécurité. Tu réponds UNIQUEMENT avec du JSON valide, sans aucun texte avant ou après."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 2000,
                }

                with httpx.Client(timeout=60) as client:
                    response = client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        json=payload,
                        headers=headers,
                    )

                # Gestion du rate-limit 429 : attendre et réessayer
                if response.status_code == 429:
                    wait_time = 5 * (attempt + 1)  # 5s, 10s, 15s
                    logger.warning(
                        "OpenRouter 429 (rate-limit) sur '%s' — attente %ds (tentative %d/3)",
                        model, wait_time, attempt + 1
                    )
                    import time
                    time.sleep(wait_time)
                    last_error = Exception(f"Rate-limit 429 sur {model}")
                    continue  # Réessayer

                response.raise_for_status()
                data = response.json()

                text = data["choices"][0]["message"]["content"].strip()
                text = _clean_json_response(text)

                result = json.loads(text)
                if isinstance(result, list) and len(result) > 0:
                    logger.info("OpenRouter réussi avec le modèle : %s (tentative %d)", model, attempt + 1)
                    return result
                else:
                    raise ValueError(f"JSON vide ou invalide depuis {model}")

            except Exception as e:
                if "429" not in str(e):
                    # Erreur autre que rate-limit → passer au modèle suivant directement
                    logger.warning("OpenRouter modèle '%s' a échoué : %s", model, e)
                    last_error = e
                    break
                last_error = e

    raise Exception(f"Tous les modèles OpenRouter ont échoué. Dernière erreur : {last_error}")


def _clean_json_response(text: str) -> str:
    """
    Nettoie la réponse d'une IA pour extraire le JSON pur.
    Gère les cas où l'IA enveloppe le JSON dans des backticks markdown.
    """
    # Supprimer les blocs ```json ... ```
    if "```" in text:
        lines = text.splitlines()
        cleaned_lines = []
        in_code_block = False
        for line in lines:
            if line.strip().startswith("```"):
                in_code_block = not in_code_block
                continue
            cleaned_lines.append(line)
        text = "\n".join(cleaned_lines).strip()

    # Trouver le premier [ et le dernier ] pour extraire le JSON array
    start_idx = text.find('[')
    end_idx = text.rfind(']')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx:end_idx + 1]

    return text.strip()


def _generate_static_fallback(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]]
) -> list[dict]:
    """
    Système expert de secours basé sur des règles statiques.
    Génère des recommandations détaillées en format paragraphe si l'IA n'est pas disponible.
    """
    logger.info("Génération des recommandations via le système de secours statique")
    recommendations = []

    # Collecter les CVEs critiques et hautes avec tous les détails
    critical_cves = []
    high_cves = []
    medium_cves = []

    for dep_key, vulns in cve_results.items():
        for vuln in vulns:
            sev_val = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev_val == "CRITICAL":
                critical_cves.append((dep_key, vuln))
            elif sev_val == "HIGH":
                high_cves.append((dep_key, vuln))
            elif sev_val == "MEDIUM":
                medium_cves.append((dep_key, vuln))

    # Trier par score CVSS décroissant
    critical_cves.sort(key=lambda x: x[1].cvss_score, reverse=True)
    high_cves.sort(key=lambda x: x[1].cvss_score, reverse=True)

    # 1. Recommandation sur les CVEs critiques
    if critical_cves:
        top_criticals = critical_cves[:5]
        pkg_list = []
        for dep_key, vuln in top_criticals:
            pkg_name = dep_key.split('@')[0]
            patch = f" (mettre à jour vers la version {vuln.fixed_version})" if vuln.fixed_version else " (aucun patch officiel disponible — envisager une alternative)"
            exploit_warn = " Cette vulnérabilité a un exploit public connu, rendant l'exploitation triviale." if vuln.exploit_available else ""
            pkg_list.append(f"{pkg_name} ({vuln.cve_id}, CVSS {vuln.cvss_score}){patch}{exploit_warn}")

        pkg_text = "; ".join(pkg_list)
        rec_text = (
            f"URGENT : Ce projet contient {len(critical_cves)} vulnérabilité(s) CRITIQUE(S) nécessitant une action immédiate. "
            f"Les plus sévères sont : {pkg_text}. "
            f"Ces failles permettent généralement une exécution de code à distance ou une élévation de privilèges sans authentification, "
            f"ce qui expose l'ensemble de l'infrastructure. "
            f"Il est DÉCONSEILLÉ de déployer ce projet en production tant que ces vulnérabilités ne sont pas corrigées. "
            f"Si vous devez télécharger ce dépôt, isolez-le dans un environnement sandbox sans accès réseau."
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": rec_text})

    # 2. Recommandation sur les CVEs hautes
    if high_cves and len(recommendations) < 3:
        top_highs = high_cves[:4]
        pkg_list_h = []
        for dep_key, vuln in top_highs:
            pkg_name = dep_key.split('@')[0]
            patch = f"v{vuln.fixed_version}" if vuln.fixed_version else "vérifier la dernière version"
            pkg_list_h.append(f"{pkg_name} → {patch} ({vuln.cve_id})")

        pkg_text_h = ", ".join(pkg_list_h)
        rec_text_h = (
            f"Ce projet contient {len(high_cves)} vulnérabilité(s) de sévérité HAUTE (CVSS 7.0-8.9) "
            f"qui doivent être corrigées dans les 2 prochaines semaines au maximum. "
            f"Priorité de mise à jour : {pkg_text_h}. "
            f"Vérifiez également que vos dépendances transitives sont à jour en exécutant `pip audit` (Python), "
            f"`npm audit fix` (Node.js) ou `mvn dependency:analyze` (Java). "
            f"Ce projet peut être téléchargé mais NE DOIT PAS être utilisé sans correction de ces failles."
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": rec_text_h})

    # 3. Recommandation Docker si applicable
    if score_result.has_docker:
        docker_rec = (
            f"Le scan Docker a révélé des vulnérabilités dans l'image de base utilisée par ce projet. "
            f"Pour sécuriser votre conteneur : (1) Remplacez l'image de base par une version 'slim' ou 'alpine' "
            f"(ex: FROM python:3.12-slim au lieu de FROM python:3.12) pour réduire la surface d'attaque. "
            f"(2) Ajoutez 'USER nonroot' dans votre Dockerfile pour éviter l'exécution en tant que root, "
            f"ce qui limiterait l'impact d'une éventuelle compromission. "
            f"(3) Activez les scans Trivy automatiques dans votre CI/CD avec 'trivy image votre-image:tag --exit-code 1 --severity CRITICAL'. "
            f"Un score image faible signifie que même sans vulnérabilités dans votre code, les attaquants peuvent exploiter l'OS sous-jacent."
        )
        recommendations.append({"target_type": "docker", "recommendation_text": docker_rec})

    # 4. Recommandation globale selon le score
    if score_result.final_score < 50:
        global_rec = (
            f"Avec un score de sécurité de {score_result.final_score:.0f}/100 (niveau {score_result.risk_level.value}), "
            f"ce projet présente des risques sécuritaires sérieux. "
            f"Nous vous recommandons : (1) D'activer GitHub Dependabot sur ce dépôt (Settings > Security > Dependabot alerts) "
            f"pour être alerté automatiquement des nouvelles CVE. "
            f"(2) D'intégrer une étape de sécurité dans votre pipeline CI/CD : ajoutez 'pip-audit' (Python), 'npm audit' (Node.js) "
            f"ou 'trivy fs .' avant chaque déploiement. "
            f"(3) D'effectuer un audit complet des licences et dépendances transitives avec 'pip-licenses' ou 'license-checker'. "
            f"Ne déployez pas ce projet en production sans avoir résolu les vulnérabilités CRITIQUES et HAUTES identifiées."
        )
    elif score_result.final_score < 75:
        global_rec = (
            f"Avec un score de {score_result.final_score:.0f}/100, ce projet a un niveau de sécurité moyen. "
            f"Il peut être téléchargé et utilisé en développement avec précaution, mais des corrections sont nécessaires avant production. "
            f"Planifiez un sprint de sécurité pour traiter les {score_result.total_cve} vulnérabilités identifiées, "
            f"en commençant par les CRITICAL et HIGH. "
            f"Configurez un workflow GitHub Actions avec 'actions/dependency-review-action' pour bloquer automatiquement "
            f"les futures pull requests introduisant de nouvelles CVE. "
            f"Activez aussi les alertes de sécurité automatiques dans les paramètres de votre dépôt GitHub."
        )
    else:
        global_rec = (
            f"Avec un score de {score_result.final_score:.0f}/100 (niveau {score_result.risk_level.value}), "
            f"ce projet a un bon niveau de sécurité et peut être téléchargé et utilisé en toute confiance. "
            f"Pour maintenir ce niveau : automatisez les mises à jour avec Dependabot ou Renovate Bot, "
            f"et effectuez un audit mensuel avec 'pip-audit' ou 'npm audit'. "
            f"Restez vigilant sur les nouvelles CVE publiées en vous abonnant aux bulletins de sécurité des écosystèmes utilisés "
            f"(ex: Python Security Advisories, npm Security Advisories). "
            f"Ce projet montre de bonnes pratiques de maintenance — continuez ainsi !"
        )
    recommendations.append({"target_type": "global", "recommendation_text": global_rec})

    # 5. Recommandation sur les médecines préventives
    if medium_cves:
        med_names = list(set(dep_key.split('@')[0] for dep_key, _ in medium_cves[:6]))
        med_rec = (
            f"En plus des vulnérabilités critiques et hautes, {len(medium_cves)} vulnérabilité(s) de niveau MEDIUM "
            f"ont été détectées sur les paquets suivants : {', '.join(med_names)}. "
            f"Bien que ces failles soient moins urgentes, elles peuvent être combinées (technique de 'chaining') "
            f"pour obtenir des accès non autorisés dans certaines configurations. "
            f"Planifiez leur correction dans les 30 prochains jours. "
            f"Pour Python, utilisez 'pip list --outdated | pip install --upgrade' ; "
            f"pour Node.js, exécutez 'npx npm-check-updates -u && npm install'. "
            f"Validez toujours les mises à jour avec vos tests unitaires et d'intégration avant déploiement."
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": med_rec})
    elif not recommendations or len(recommendations) < 4:
        # Recommandation générique si peu de CVEs
        gen_rec = (
            f"Ce projet a peu de vulnérabilités connues dans les dépendances analysées ({score_result.total_cve} CVE au total). "
            f"Pour maintenir ce niveau de sécurité, implémentez une politique de mise à jour régulière : "
            f"vérifiez les nouvelles versions de chaque dépendance au moins une fois par mois et après chaque incident de sécurité majeur "
            f"dans l'écosystème concerné. "
            f"Activez les notifications GitHub Dependabot pour être alerté immédiatement en cas de nouvelles CVE. "
            f"Ce projet peut être téléchargé et utilisé en toute sécurité selon l'analyse effectuée."
        )
        recommendations.append({"target_type": "global", "recommendation_text": gen_rec})

    return recommendations[:5]  # Maximum 5 recommandations
