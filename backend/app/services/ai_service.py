"""
Service IA — génère des recommandations de sécurité personnalisées pour une analyse.
Stratégie de fallback (Gemini → NVIDIA NIM / Kimi K2.6 → OpenRouter → Statique) :
  1. Gemini (principal — gemini-2.5-flash)
  2. NVIDIA NIM / Kimi K2.6 (fallback intermédiaire — moonshotai/kimi-k2.6)
  3. OpenRouter (dernier fallback LLM)
  4. Système expert statique (rule-based — toujours disponible)

L'IA NE participe PAS à la détection des CVE ni au Security Score (déterministe).
Son rôle est uniquement l'interprétation et les recommandations.
"""

import json
import logging
import time
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

    # ── Étape 1 : Gemini (fournisseur principal) ──────────────────────────────
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

    # ── Étape 2 : NVIDIA NIM / Kimi K2.6 (fallback intermédiaire) ────────────
    # Appelé uniquement si Gemini a échoué ou n'est pas configuré
    nvidia_key = settings.NVIDIA_API_KEY or ""
    if not recommendations_data and nvidia_key:
        try:
            recommendations_data = _generate_with_nvidia(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "nvidia_kimi_k2"
            logger.info("Recommandations générées avec succès via NVIDIA NIM / Kimi K2.6 (%d recs)", len(recommendations_data))
        except Exception as e:
            logger.error("Échec de la génération avec NVIDIA NIM : %s", e)
            recommendations_data = []
    elif not recommendations_data and not nvidia_key:
        logger.info("NVIDIA NIM ignoré (NVIDIA_API_KEY absente) — passage à OpenRouter")

    # ── Étape 3 : OpenRouter (dernier fallback LLM) ───────────────────────────
    if not recommendations_data and settings.OPENROUTER_API_KEY:
        try:
            recommendations_data = _generate_with_openrouter(score_result, cve_results, repo_name, ecosystems, total_deps)
            provider = "openrouter"
            logger.info("Recommandations générées avec succès via OpenRouter (%d recs)", len(recommendations_data))
        except Exception as e:
            logger.error("Échec de la génération avec OpenRouter : %s", e)
            recommendations_data = []

    # ── Étape 4 : Fallback statique (toujours disponible) ────────────────────
    if not recommendations_data:
        logger.warning("Aucune IA disponible. Utilisation du fallback statique.")
        provider = "static_fallback"
        recommendations_data = _generate_static_fallback(
            score_result, cve_results,
            repo_name=repo_name,
            ecosystems=ecosystems or [],
            total_deps=total_deps,
        )

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

            rec_text = rec.get("recommendation_text", "")

            # Nouveau champ "package" (v2.0 prompt orienté package) :
            # On préfixe le texte avec le nom du package pour la traçabilité,
            # sans migration DB (le champ package_name n'existe pas encore en base).
            pkg_name = rec.get("package") or rec.get("package_name")
            if pkg_name and target_type == TargetType.DEPENDENCY:
                if not rec_text.startswith(f"[{pkg_name}]"):
                    rec_text = f"[{pkg_name}] {rec_text}"
                logger.debug("Recommandation pour package '%s' : %d chars", pkg_name, len(rec_text))

            db_rec = Recommendation(
                analysis_id=analysis_id,
                target_type=target_type,
                recommendation_text=rec_text,
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
    Construit un prompt orienté par package pour l'IA.

    Structure :
      - Contexte projet (score, écosystèmes, nb deps)
      - Liste des packages vulnérables, chacun avec ses CVE, EPSS, fix
      - Demande 1 recommandation par package + recommandations globales

    v2.0 : orienté package (au lieu de liste de CVE en vrac).
    Inclut EPSS pour prioriser selon la probabilité d'exploitation réelle.
    """
    eco_str = ", ".join(ecosystems) if ecosystems else "non détecté"

    # ── Construire la vue par package ──────────────────────────────────────────
    # { "flask@2.3.0": [vuln1, vuln2, ...], ... }  — seulement les packages avec CVE
    packages_with_vulns: dict[str, list[VulnerabilityResult]] = {}
    for dep_key, vulns in cve_results.items():
        # Exclure la méta-clé interne
        if dep_key == "__scan_meta__":
            continue
        real_vulns = [v for v in vulns if not v.cve_id.startswith("__")]
        if real_vulns:
            packages_with_vulns[dep_key] = real_vulns

    # Trier les packages par sévérité max (CRITICAL > HIGH > MEDIUM > LOW)
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

    def _pkg_priority(item: tuple) -> int:
        dep_key, vulns = item
        max_sev = min(
            (SEV_ORDER.get(v.severity.value if hasattr(v.severity, "value") else str(v.severity), 4)
             for v in vulns),
            default=4
        )
        # Secondaire : EPSS max (probabilité d'exploitation réelle)
        max_epss = max((v.epss_score or 0.0 for v in vulns), default=0.0)
        return max_sev * 1000 + int((1.0 - max_epss) * 999)

    sorted_packages = sorted(packages_with_vulns.items(), key=_pkg_priority)

    # Limiter à 15 packages max (éviter de saturer le contexte)
    packages_section = ""
    packages_for_json: list[str] = []
    for dep_key, vulns in sorted_packages[:15]:
        packages_for_json.append(dep_key)

        # Sévérité max du package
        sevs = [v.severity.value if hasattr(v.severity, "value") else str(v.severity) for v in vulns]
        max_sev = min(sevs, key=lambda s: SEV_ORDER.get(s, 4))

        # Trouver la meilleure version corrective (non-None)
        fixed_versions = [v.fixed_version for v in vulns if v.fixed_version]
        best_fix = fixed_versions[0] if fixed_versions else None

        packages_section += f"\n### Package : {dep_key}  [Sévérité max : {max_sev}]\n"
        if best_fix:
            packages_section += f"  Mise à jour corrective disponible : v{best_fix}\n"
        else:
            packages_section += "  Aucun patch disponible — envisager un remplacement ou une mitigation.\n"

        # Lister les CVE du package (max 5)
        for vuln in sorted(vulns, key=lambda v: v.cvss_score, reverse=True)[:5]:
            sev = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
            epss_str = f"EPSS={vuln.epss_score:.1%}" if vuln.epss_score is not None else "EPSS=?"
            exploit_flag = " ⚠️ EXPLOIT PUBLIC" if vuln.exploit_available else ""
            fix_str = f" → fix: v{vuln.fixed_version}" if vuln.fixed_version else ""
            desc_short = (vuln.description or "")[:120].rstrip()
            packages_section += (
                f"  • {vuln.cve_id} [{sev} CVSS:{vuln.cvss_score:.1f} {epss_str}]{exploit_flag}{fix_str}\n"
                f"    {desc_short}{'...' if len(vuln.description or '') > 120 else ''}\n"
            )

    # ── Résumé global ──────────────────────────────────────────────────────────
    cve_counts_str = " | ".join(
        f"{k}: {v}" for k, v in sorted(score_result.cve_counts.items(), key=lambda x: SEV_ORDER.get(x[0], 4))
        if v > 0
    )

    # Instruction Docker : interdiction explicite si pas de Dockerfile
    if not score_result.has_docker:
        docker_instruction = (
            "8. INTERDIT ABSOLU (DOCKERFILE) : Dockerfile présent = NON. "
            "Tu ne dois JAMAIS mentionner Docker, Dockerfile, image de base, Trivy, "
            "registre Docker, 'USER nonroot', ou tout concept lié à la conteneurisation dans tes recommandations. "
            "Aucune recommandation de type 'docker' ne doit exister. "
            "Ne génère QUE des recommandations de type 'dependency' et 'global' portant sur les dépendances logicielles."
        )
    else:
        docker_instruction = (
            "8. Dockerfile présent : OUI — Si le scan Docker a relevé des vulnérabilités réelles, "
            "tu peux inclure une recommandation Docker. "
            f"Vulnérabilités Docker détectées : {score_result.docker_vulns_count if hasattr(score_result, 'docker_vulns_count') else 'non précisé'}."
        )

    # Règle spécificité CVE : imposer citation explicite même sans CRITICAL/HIGH
    cve_specificity_rule = ""
    if score_result.total_cve > 0:
        cve_specificity_rule = (
            f"9. SPÉCIFICITÉ CVE OBLIGATOIRE : Ce scan a détecté {score_result.total_cve} CVE. "
            "Chaque recommandation de type 'dependency' DOIT citer : (a) le nom exact du package, "
            "(b) au moins 1 CVE-ID précis (ex: CVE-2024-XXXX) parmi les CVE listées ci-dessus pour ce package, "
            "(c) le score CVSS de cette CVE. "
            "INTERDIT de produire une recommandation qui parle d'un package sans citer le moindre CVE-ID précis. "
            "Même si toutes les CVE sont LOW ou MEDIUM, tu dois quand même les citer par leur ID exact."
        )

    # Nombre de recommandations attendues : 1 par package (max 15) + 2 globales
    n_dep_recs = min(len(packages_for_json), 15)
    n_total_recs = n_dep_recs + 2  # + DevSecOps global + Docker/Architecture

    # JSON template pour guider l'IA
    json_example_deps = "\n".join([
        f'  {{"target_type": "dependency", "package": "{pkg}", "recommendation_text": "..."}},'
        for pkg in packages_for_json[:3]
    ])

    prompt = f"""Tu es un expert senior en cybersécurité spécialisé dans la sécurisation de la chaîne d'approvisionnement logicielle (Software Supply Chain Security).
Tu rédiges un rapport d'audit professionnel destiné à une équipe technique (développeurs, RSSI, architectes).

CONTEXTE DU PROJET : {repo_name}
  Écosystèmes : {eco_str}
  Dépendances totales : {total_deps}
  Score de sécurité : {score_result.final_score}/100 (niveau : {score_result.risk_level.value})
  CVE détectées : {score_result.total_cve} ({cve_counts_str if cve_counts_str else "aucune"})
  Dockerfile présent : {"Oui" if score_result.has_docker else "Non — AUCUNE recommandation Docker autorisée"}

PACKAGES VULNÉRABLES (triés par sévérité puis probabilité d'exploitation EPSS) :
{packages_section if packages_section else "  Aucun package vulnérable détecté."}

MISSION : Génère exactement {n_total_recs} recommandations de sécurité :
  - {n_dep_recs} recommandation(s) de type "dependency" : UNE PAR PACKAGE listé ci-dessus, dans le même ordre
  - 1 recommandation de type "global" : processus DevSecOps à mettre en place
  - 1 recommandation de type "global" : architecture, monitoring, ou bonnes pratiques globales

RÈGLES ABSOLUES DE TON ET DE CONTENU :
1. Rédige un paragraphe de 3-5 phrases complètes et actionnables (PAS de listes à puces)
2. Pour "dependency" : cite le package par son nom exact, donne la commande de mise à jour (pip install, npm install, etc.), explique l'impact concret de la vulnérabilité
3. Si EPSS >= 0.4 : mentionne explicitement que ce package est activement exploité dans la nature et que la fenêtre d'exposition est courte
4. Si aucun patch disponible : propose une alternative ou une mitigation (isolation, suppression, contournement)
5. Conclure chaque recommandation par une classification de priorité : "(Priorité CRITIQUE — à traiter sous 24h)" ou "(Priorité HAUTE — à planifier sous 72h)" ou "(Priorité NORMALE — à inclure dans le prochain sprint)"
6. INTERDIT : n'utilise JAMAIS de formulations du type "peut être téléchargé", "à utiliser en toute confiance", "go/no-go", ou tout verdict binaire sur l'usage du logiciel. Un rapport d'audit présente des faits et des recommandations d'action, pas des permissions d'usage.
7. INTERDIT : n'utilise JAMAIS de formulations génériques interchangeables d'un rapport à l'autre. Chaque recommandation doit prouver qu'elle a été écrite en analysant CE projet précis — mentionne des détails uniques à ce scan : le nom du repo "{repo_name}", le nombre exact de CVE ({score_result.total_cve}), l'écosystème ({eco_str}), la combinaison spécifique de vulnérabilités. Bannir les formules génériques qui s'appliqueraient à n'importe quel projet.
{docker_instruction}
{cve_specificity_rule}

Retourne UNIQUEMENT un tableau JSON valide (sans markdown, sans backticks, sans commentaires) :
[
{json_example_deps}
  {{"target_type": "global", "package": null, "recommendation_text": "..."}},
  {{"target_type": "global", "package": null, "recommendation_text": "..."}}
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


def _generate_with_nvidia(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """
    Appelle l'API NVIDIA NIM (OpenAI-compatible) avec le modèle moonshotai/kimi-k2.6.

    Endpoint : POST https://integrate.api.nvidia.com/v1/chat/completions
    Auth      : Bearer ${NVIDIA_API_KEY}   ← jamais loggée
    Timeout   : 60 secondes
    Retries   : 2 tentatives en cas de 429 ou 5xx

    Cette fonction ne participe PAS à la détection CVE ni au Security Score.
    Elle génère uniquement des recommandations textuelles basées sur les résultats.

    Paramètres :
        score_result : résultat du scoring (score, pénalités, etc.)
        cve_results  : dict des vulnérabilités par dépendance
        repo_name    : nom du dépôt analysé
        ecosystems   : écosystèmes détectés (Python, Node.js, etc.)
        total_deps   : nombre total de dépendances analysées

    Retourne :
        list[dict] avec clés "target_type" et "recommendation_text"

    Lève :
        Exception si l'API est inaccessible après tous les retries
    """
    NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
    NVIDIA_MODEL   = "moonshotai/kimi-k2.6"  # Modèle confirmé par l'utilisateur
    TIMEOUT        = 60  # secondes — raisonnable pour un modèle LLM
    MAX_RETRIES    = 2

    # Construction du prompt — contexte compact (0.5 performance)
    # On n'envoie que les informations PERTINENTES, pas tout le dump JSON
    prompt = _build_prompt(score_result, cve_results, repo_name, ecosystems, total_deps)

    headers = {
        # La clé est transmise mais JAMAIS loggée (même en DEBUG)
        "Authorization": f"Bearer {settings.NVIDIA_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Tu es un expert en cybersécurité spécialisé en Software Supply Chain Security. "
                    "Tu réponds UNIQUEMENT avec du JSON valide (tableau), sans aucun texte avant ou après."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.6,
        "top_p": 0.9,
        "max_tokens": 2048,
        "stream": False,  # Pas de streaming — réponse complète attendue
    }

    last_error: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                response = client.post(NVIDIA_API_URL, json=payload, headers=headers)

            # ── Gestion des codes d'erreur spécifiques ────────────────────────
            if response.status_code == 401:
                # Clé invalide — pas de retry inutile, on lève immédiatement
                raise PermissionError(
                    "NVIDIA NIM : clé API invalide (401). "
                    "Vérifiez NVIDIA_API_KEY dans votre .env"
                )

            if response.status_code == 429:
                # Rate-limit — on attend avant de réessayer
                wait = 8 * attempt  # 8s, 16s
                logger.warning(
                    "[NVIDIA] Rate-limit 429 — attente %ds (tentative %d/%d)",
                    wait, attempt, MAX_RETRIES
                )
                time.sleep(wait)
                last_error = Exception(f"NVIDIA NIM rate-limit 429 (tentative {attempt})")
                continue

            if response.status_code >= 500:
                # Erreur serveur NVIDIA — retry
                logger.warning(
                    "[NVIDIA] Erreur serveur %d (tentative %d/%d)",
                    response.status_code, attempt, MAX_RETRIES
                )
                time.sleep(5 * attempt)
                last_error = Exception(f"NVIDIA NIM erreur serveur {response.status_code}")
                continue

            response.raise_for_status()

            # ── Parser la réponse ──────────────────────────────────────────────
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                raise ValueError("NVIDIA NIM : réponse vide (aucun choix retourné)")

            raw_text = choices[0].get("message", {}).get("content", "").strip()
            if not raw_text:
                raise ValueError("NVIDIA NIM : contenu vide dans la réponse")

            # Nettoyer les éventuels blocs markdown
            clean_text = _clean_json_response(raw_text)

            result = json.loads(clean_text)
            if not isinstance(result, list) or len(result) == 0:
                raise ValueError("NVIDIA NIM : JSON retourné vide ou invalide")

            logger.info(
                "[NVIDIA] Kimi K2.6 a généré %d recommandation(s) avec succès",
                len(result)
            )
            return result

        except PermissionError:
            # 401 — on remonte immédiatement sans retry
            raise

        except httpx.TimeoutException:
            logger.warning(
                "[NVIDIA] Timeout (%ds) sur la tentative %d/%d",
                TIMEOUT, attempt, MAX_RETRIES
            )
            last_error = TimeoutError(f"NVIDIA NIM timeout après {TIMEOUT}s")
            if attempt < MAX_RETRIES:
                time.sleep(3)

        except json.JSONDecodeError as e:
            logger.warning("[NVIDIA] JSON invalide dans la réponse : %s", e)
            last_error = e
            break  # JSON invalide = pas la peine de réessayer

        except Exception as e:
            logger.warning("[NVIDIA] Erreur inattendue (tentative %d/%d) : %s", attempt, MAX_RETRIES, e)
            last_error = e
            if attempt < MAX_RETRIES:
                time.sleep(3)

    raise Exception(
        f"NVIDIA NIM / Kimi K2.6 indisponible après {MAX_RETRIES} tentatives. "
        f"Dernière erreur : {last_error}"
    )


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

    models_to_try = [
        "openrouter/free",                                   # PRIORITÉ 1 : Auto-routing vers le meilleur modèle gratuit
        "google/gemma-4-31b-it:free",                        # Fallback 2 : Gemma 4
        "cohere/north-mini-code:free",                       # Fallback 3 : Cohere Code
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


def _get_ecosystem_audit_cmd(ecosystems: list[str]) -> str:
    """
    Retourne la commande d'audit adaptée à l'écosystème détecté.
    Utilisée par le fallback statique pour personnaliser les recommandations.
    """
    eco_lower = [e.lower() for e in ecosystems]
    if any(e in eco_lower for e in ["python", "pip", "pipenv", "poetry"]):
        return "`pip-audit --fix` ou `safety scan`"
    elif any(e in eco_lower for e in ["node", "nodejs", "npm", "yarn"]):
        return "`npm audit fix --force` ou `yarn audit`"
    elif any(e in eco_lower for e in ["java", "maven", "gradle"]):
        return "`mvn dependency:analyze` suivi de `mvn versions:use-latest-releases`"
    elif any(e in eco_lower for e in ["ruby", "gems", "bundler"]):
        return "`bundle audit check --update`"
    elif any(e in eco_lower for e in ["go", "golang"]):
        return "`govulncheck ./...`"
    elif any(e in eco_lower for e in ["rust", "cargo"]):
        return "`cargo audit`"
    else:
        return "`pip-audit` (Python), `npm audit` (Node.js), ou `trivy fs .` (multi-écosystème)"


def _generate_static_fallback(
    score_result: ScoreResult,
    cve_results: dict[str, list[VulnerabilityResult]],
    repo_name: str = "inconnu",
    ecosystems: list[str] | None = None,
    total_deps: int = 0,
) -> list[dict]:
    """
    Système expert de secours basé sur des règles statiques.
    Gènère des recommandations d'audit professionnelles si l'IA n'est pas disponible.

    v2.0 : ton rapport d'audit professionnel (suppression du langage go/no-go),
    recommandations contextualisées par écosystème, nombre et nature des CVE.
    """
    logger.info("Génération des recommandations via le système de secours statique")
    recommendations = []
    ecosystems = ecosystems or []
    audit_cmd = _get_ecosystem_audit_cmd(ecosystems)
    eco_str = ", ".join(ecosystems) if ecosystems else "non détecté"

    # Collecter les CVEs par niveau
    critical_cves: list[tuple] = []
    high_cves: list[tuple] = []
    medium_cves: list[tuple] = []
    exploitable_cves: list[tuple] = []  # Celles avec exploit_available=True
    high_epss_cves: list[tuple] = []   # EPSS >= 0.4 (exploitation active)

    for dep_key, vulns in cve_results.items():
        if dep_key == "__scan_meta__":
            continue
        for vuln in vulns:
            if vuln.cve_id.startswith("__"):
                continue
            sev_val = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if sev_val == "CRITICAL":
                critical_cves.append((dep_key, vuln))
            elif sev_val == "HIGH":
                high_cves.append((dep_key, vuln))
            elif sev_val == "MEDIUM":
                medium_cves.append((dep_key, vuln))
            if getattr(vuln, 'exploit_available', False):
                exploitable_cves.append((dep_key, vuln))
            if (vuln.epss_score or 0.0) >= 0.4:
                high_epss_cves.append((dep_key, vuln))

    critical_cves.sort(key=lambda x: x[1].cvss_score, reverse=True)
    high_cves.sort(key=lambda x: x[1].cvss_score, reverse=True)

    # ── 1. Recommandation CVE CRITIQUES ──────────────────────────────────────
    if critical_cves:
        top_criticals = critical_cves[:5]
        pkg_details = []
        for dep_key, vuln in top_criticals:
            pkg_name = dep_key.split('@')[0]
            patch_action = (
                f"mise à jour vers la version {vuln.fixed_version} disponible"
                if vuln.fixed_version
                else "aucun correctif officiel disponible — évaluer un remplacement ou une isolation du composant"
            )
            pkg_details.append(f"{pkg_name} ({vuln.cve_id}, CVSS {vuln.cvss_score:.1f} : {patch_action})")

        exploited_count = sum(1 for _, v in top_criticals if v.exploit_available)
        exploit_context = (
            f" Parmi ces failles, {exploited_count} font l'objet d'exploits publics connus,"
            f" réduisant la fenêtre d'exposition à quelques heures en environnement exposé."
            if exploited_count > 0 else ""
        )

        # Vary wording based on count : single vs multiple criticals
        if len(critical_cves) == 1:
            opening = f"L'audit de {repo_name} a identifié une vulnérabilité de niveau CRITIQUE"
        else:
            opening = f"L'audit de {repo_name} a identifié {len(critical_cves)} vulnérabilité(s) de niveau CRITIQUE"

        rec_text = (
            f"{opening}, susceptibles de permettre une exécution de code à distance"
            f" ou une élévation de privilèges sans authentification préalable sur les composants exposés.{exploit_context}"
            f" Composants affectés : {'; '.join(pkg_details)}."
            f" Une remise en conformité de ces composants est pré-requise avant tout déploiement en environnement accessible depuis un réseau non cloisonné."
            f" Lancez {audit_cmd} pour effectuer une remise à niveau assistée."
            f" (Priorité CRITIQUE — à traiter sous 24h)"
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": rec_text})

    # ── 2. Recommandation CVE HAUTES ────────────────────────────────────────
    if high_cves and len(recommendations) < 3:
        top_highs = high_cves[:4]
        pkg_updates = []
        for dep_key, vuln in top_highs:
            pkg_name = dep_key.split('@')[0]
            if vuln.fixed_version:
                pkg_updates.append(f"{pkg_name} → v{vuln.fixed_version} ({vuln.cve_id})")
            else:
                pkg_updates.append(f"{pkg_name} (aucun correctif — surveiller le bulletin {vuln.cve_id})")

        # Vary wording based on ecosystem-specific chaining risk
        chain_risk = ""
        if len(high_cves) >= 3:
            chain_risk = (
                f" La présence simultanée de {len(high_cves)} failles HAUTES dans {repo_name}"
                f" augmente le risque de compromission par enchaînement"
                f" (chaining) même en l'absence de vulnérabilité CRITIQUE isolée."
            )

        rec_text_h = (
            f"L'analyse de {repo_name} révèle {len(high_cves)} vulnérabilité(s) de sevérité HAUTE (CVSS 7.0–8.9)"
            f" dans l'écosystème {eco_str}.{chain_risk}"
            f" Remise à niveau recommandée : {', '.join(pkg_updates)}."
            f" Lancez {audit_cmd} pour automatiser la détection des dépendances transitives affectées."
            f" (Priorité HAUTE — à planifier sous 72h)"
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": rec_text_h})

    # ── 3. Recommandation Docker si applicable ──────────────────────────────
    if score_result.has_docker:
        has_critical = bool(critical_cves)
        docker_vulns = getattr(score_result, 'docker_vulns_count', None)
        has_docker_vulns = docker_vulns is not None and docker_vulns > 0

        if has_docker_vulns:
            base_image_risk = (
                "Les vuln\u00e9rabilit\u00e9s CRITIQUES d\u00e9tect\u00e9es dans les d\u00e9pendances applicatives"
                " s'ajoutent aux risques de l'image de base, amplifiant la surface d'attaque."
                if has_critical else
                "M\u00eame en l'absence de vuln\u00e9rabilit\u00e9 CRITIQUE dans les d\u00e9pendances,"
                " l'image de base constitue un vecteur de risque r\u00e9siduel \u00e0 contr\u00f4ler."
            )
            docker_rec = (
                f"Le scan Docker de {repo_name} a relev\u00e9 {docker_vulns} vuln\u00e9rabilit\u00e9(s) OS dans l'image de base du Dockerfile."
                f" {base_image_risk}"
                f" Actions correctives : remplacer l'image par une variante 'slim' ou 'distroless' r\u00e9duisant la surface OS,"
                f" appliquer la directive 'USER nonroot' pour \u00e9liminer l'ex\u00e9cution en contexte root,"
                f" et int\u00e9grer 'trivy image --exit-code 1 --severity CRITICAL,HIGH' dans la pipeline CI/CD."
                f" (Priorit\u00e9 {'CRITIQUE' if has_critical else 'HAUTE'} \u2014 \u00e0 traiter en parall\u00e8le des d\u00e9pendances applicatives)"
            )
        else:
            # Dockerfile pr\u00e9sent mais 0 vuln\u00e9rabilit\u00e9 OS : bonne pratique sans hallucination
            docker_rec = (
                f"Un Dockerfile a \u00e9t\u00e9 d\u00e9tect\u00e9 dans {repo_name}. Le scan d'image n'a relev\u00e9 aucune vuln\u00e9rabilit\u00e9 OS critique."
                f" Pour maintenir ce niveau de s\u00e9curit\u00e9, appliquez les bonnes pratiques de hardening de conteneur :"
                f" utiliser une image de base minimale ('slim' ou 'distroless'), s'assurer que l'application"
                f" s'ex\u00e9cute avec un utilisateur non-root (directive USER dans le Dockerfile),"
                f" et int\u00e9grer 'trivy image --exit-code 1 --severity CRITICAL,HIGH' comme \u00e9tape de validation CI/CD"
                f" pour d\u00e9tecter toute r\u00e9gression lors de futures mises \u00e0 jour de l'image de base."
                f" (Priorit\u00e9 NORMALE \u2014 bonne pratique de maintenance continue)"
            )
        recommendations.append({"target_type": "docker", "recommendation_text": docker_rec})

    # ── 4. Recommandation globale contextualisée par score et écosystème ─────────
    total_cve = score_result.total_cve
    score = score_result.final_score

    if score < 50:
        global_rec = (
            f"Le score de sécurité de {repo_name} ({score:.0f}/100, niveau {score_result.risk_level.value})"
            f" traduit un profil de risque élevé sur {total_cve} CVE détectées dans l'écosystème {eco_str}."
            f" Actions structurelles recommandées : activer GitHub Dependabot pour la surveillance continue des CVE,"
            f" intégrer {audit_cmd} comme étape de blocage dans la pipeline CI/CD,"
            f" et conduire un audit des dépendances transitives via {audit_cmd}."
            f" La correction des vulnérabilités CRITIQUES et HAUTES est pré-requise avant promotion en environnement de production."
            f" (Priorité CRITIQUE — plan de remise en conformité à définir sous 48h)"
        )
    elif score < 75:
        global_rec = (
            f"Avec un score de {score:.0f}/100, {repo_name} présente un niveau de risque intermédiaire"
            f" sur {total_cve} CVE en écosystème {eco_str}."
            f" Planifiez un sprint de remise en conformité couvrant les {len(critical_cves)} CRITIQUE(S)"
            f" et {len(high_cves)} HAUTE(S) en priorité."
            f" Configurez 'actions/dependency-review-action' dans GitHub Actions pour bloquer automatiquement"
            f" les pull requests introduisant de nouvelles CVE."
            f" (Priorité HAUTE — à inclure dans le prochain cycle de développement)"
        )
    else:
        global_rec = (
            f"Le score de sécurité de {repo_name} ({score:.0f}/100, {score_result.risk_level.value})"
            f" reflète un profil de risque maîtrisé sur {total_cve} CVE analysées en écosystème {eco_str}."
            f" Pour maintenir ce niveau : automatisez la surveillance avec Dependabot ou Renovate Bot,"
            f" exécutez {audit_cmd} à chaque cycle de release,"
            f" et abonnez-vous aux bulletins de sécurité des écosystèmes concernés."
            f" (Priorité NORMALE — à intégrer dans la politique de maintenance continue)"
        )
    recommendations.append({"target_type": "global", "recommendation_text": global_rec})

    # ── 5. CVE MEDIUM ou recommandation de maîtrise préventive ─────────────────
    if medium_cves:
        med_packages = list(dict.fromkeys(dep_key.split('@')[0] for dep_key, _ in medium_cves[:6]))
        # Contexte spécifique selon nombre de MEDIUM
        if len(medium_cves) == 1:
            med_context = f"une vulnérabilité de niveau MEDIUM a été identifiée dans {repo_name}"
        elif len(medium_cves) <= 4:
            med_context = f"{len(medium_cves)} vulnérabilités MEDIUM ont été relevées dans {repo_name}"
        else:
            med_context = f"{len(medium_cves)} vulnérabilités MEDIUM constituent un risque cumulatif dans {repo_name}"

        # Chaining risk based on count
        chain_note = (
            f" Leur combinaison potentielle (chaining) peut aboutir à un accès non autorisé"
            f" selon la configuration déploiement de {repo_name}."
            if len(medium_cves) >= 3 else ""
        )

        med_rec = (
            f"Outre les niveaux CRITIQUE et HAUTE, {med_context} sur les composants :"
            f" {', '.join(med_packages)} (ecosystème {eco_str}).{chain_note}"
            f" Planifiez leur correction dans les 30 prochains jours."
            f" Utilisez {audit_cmd} pour automatiser le traitement."
            f" (Priorité NORMALE — à intégrer dans le prochain sprint)"
        )
        recommendations.append({"target_type": "dependency", "recommendation_text": med_rec})
    elif not recommendations or len(recommendations) < 4:
        # Profil bas risque : recommandation de veille active
        gen_rec = (
            f"L'analyse de {repo_name} ({total_cve} CVE en écosystème {eco_str})"
            f" n'identifie pas de vulnérabilités CRITIQUE ni HAUTE dans les {total_deps} dépendances examinées."
            f" Le profil de risque résiduel est maîtrisé."
            f" Maintenez ce niveau en automatisant la surveillance avec Dependabot et en exécutant"
            f" {audit_cmd} à chaque cycle de release."
            f" Abonnez-vous aux bulletins de sécurité des dépendances clés pour anticiper les divulgations à venir."
            f" (Priorité NORMALE — politique de maintenance continue)"
        )
        recommendations.append({"target_type": "global", "recommendation_text": gen_rec})

    return recommendations[:5]  # Maximum 5 recommandations
