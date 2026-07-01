# -*- coding: utf-8 -*-
"""
Script de test pour verifier que les APIs IA (Gemini / OpenRouter) fonctionnent
et generent des recommandations de securite correctes.
"""

import sys
import os
import json
import io

# Forcer la sortie en UTF-8 pour Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ajouter le repertoire backend au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings
from app.services.ai_service import _build_prompt
from app.services.score_service import ScoreResult, PenaltyLine, RiskLevel
from app.services.cve_service import VulnerabilityResult, Severity


def create_fake_scan_data():
    """Cree des donnees de scan simulees mais realistes pour tester l'IA."""

    # Simuler des resultats CVE
    cve_results = {
        "express@4.17.1": [
            VulnerabilityResult(
                cve_id="CVE-2024-29041",
                severity=Severity.HIGH,
                cvss_score=7.5,
                description="Open redirect vulnerability in Express.js",
                fixed_version="4.19.2",
                exploit_available=True,
                published_date="2024-03-25",
            ),
        ],
        "lodash@4.17.20": [
            VulnerabilityResult(
                cve_id="CVE-2021-23337",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                description="Prototype pollution in lodash",
                fixed_version="4.17.21",
                exploit_available=True,
                published_date="2021-02-15",
            ),
        ],
        "jsonwebtoken@8.5.1": [
            VulnerabilityResult(
                cve_id="CVE-2022-23529",
                severity=Severity.MEDIUM,
                cvss_score=6.1,
                description="Insecure default algorithm in jsonwebtoken",
                fixed_version="9.0.0",
                exploit_available=False,
                published_date="2022-12-21",
            ),
        ],
    }

    # Simuler un ScoreResult
    score_result = ScoreResult(
        final_score=42.0,
        risk_level=RiskLevel.MAUVAIS,
        total_penalties=58.0,
        total_cve=3,
        cve_counts={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "NONE": 0},
        has_docker=True,
        penalties=[
            PenaltyLine(
                category="CVE CRITICAL (CVE-2021-23337) sur lodash@4.17.20",
                count=1, unit_penalty=15.0, raw_penalty=27.3, applied=27.3, cap=0.0,
            ),
            PenaltyLine(
                category="CVE HIGH (CVE-2024-29041) sur express@4.17.1",
                count=1, unit_penalty=8.0, raw_penalty=15.6, applied=15.6, cap=0.0,
            ),
            PenaltyLine(
                category="Image Docker vulnerable (3 CRITICAL+HIGH dans l'OS)",
                count=3, unit_penalty=10.0, raw_penalty=10.0, applied=10.0, cap=20.0,
            ),
            PenaltyLine(
                category="Mauvaises pratiques Docker (2 probleme(s) detecte(s))",
                count=2, unit_penalty=5.0, raw_penalty=10.0, applied=5.0, cap=10.0,
            ),
        ],
    )

    return score_result, cve_results


def test_prompt():
    """Affiche le prompt qui sera envoye a l'IA."""
    score_result, cve_results = create_fake_scan_data()

    prompt = _build_prompt(
        score_result, cve_results,
        repo_name="Nestle-Shop-Full-App-E-Commerce",
        ecosystems=["npm (Node.js)", "pip (Python)"],
        total_deps=47,
    )

    print("=" * 70)
    print("[PROMPT] Contenu envoye a l'IA :")
    print("=" * 70)
    print(prompt)
    print("=" * 70)
    return score_result, cve_results


def test_gemini(score_result, cve_results):
    """Teste l'API Gemini directement."""
    print("\n" + "=" * 70)
    print("[TEST] GEMINI API (fournisseur principal)")
    print("=" * 70)

    if not settings.GEMINI_API_KEY:
        print("[ERREUR] GEMINI_API_KEY est vide dans le .env")
        return False

    key_preview = settings.GEMINI_API_KEY[:12] + "..." + settings.GEMINI_API_KEY[-6:]
    print(f"[OK] Cle Gemini detectee : {key_preview}")
    print("[...] Appel en cours a Gemini (gemini-2.5-flash)...")

    try:
        # Import et appel direct avec le nouveau SDK
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)

        model = genai.GenerativeModel("gemini-2.5-flash")
        prompt = _build_prompt(
            score_result, cve_results,
            repo_name="Nestle-Shop-Full-App-E-Commerce",
            ecosystems=["npm (Node.js)", "pip (Python)"],
            total_deps=47,
        )

        response = model.generate_content(prompt)
        text = response.text.strip()

        # Nettoyer d'eventuels blocs de code markdown
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        recommendations = json.loads(text)

        print(f"\n[SUCCES] {len(recommendations)} recommandations generees par Gemini :\n")
        for i, rec in enumerate(recommendations, 1):
            target = rec.get("target_type", "?")
            rtext = rec.get("recommendation_text", "?")
            # Tronquer pour l'affichage
            display = rtext[:150] + "..." if len(rtext) > 150 else rtext
            print(f"  {i}. [{target.upper()}] {display}")
            print()

        return True

    except Exception as e:
        print(f"\n[ECHEC] Gemini : {e}")
        import traceback
        traceback.print_exc()
        return False


def test_openrouter(score_result, cve_results):
    """Teste l'API OpenRouter."""
    print("\n" + "=" * 70)
    print("[TEST] OPENROUTER API (fallback)")
    print("=" * 70)

    if not settings.OPENROUTER_API_KEY:
        print("[INFO] OPENROUTER_API_KEY est vide dans le .env (normal si non configure)")
        return None

    print(f"[OK] Cle OpenRouter detectee : {settings.OPENROUTER_API_KEY[:12]}...")
    print("[...] Appel en cours a OpenRouter...")

    try:
        from app.services.ai_service import _generate_with_openrouter
        recommendations = _generate_with_openrouter(
            score_result, cve_results,
            repo_name="Nestle-Shop-Full-App-E-Commerce",
            ecosystems=["npm (Node.js)", "pip (Python)"],
            total_deps=47,
        )

        print(f"\n[SUCCES] {len(recommendations)} recommandations generees par OpenRouter :\n")
        for i, rec in enumerate(recommendations, 1):
            target = rec.get("target_type", "?")
            rtext = rec.get("recommendation_text", "?")
            display = rtext[:150] + "..." if len(rtext) > 150 else rtext
            print(f"  {i}. [{target.upper()}] {display}")
            print()

        return True

    except Exception as e:
        print(f"\n[ECHEC] OpenRouter : {e}")
        return False


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("TEST DU SERVICE IA -- Supply Chain Security")
    print("=" * 70)
    print(f"Fournisseur configure (AI_PROVIDER) : {settings.AI_PROVIDER}")
    print(f"GEMINI_API_KEY    : {'[OK] configuree' if settings.GEMINI_API_KEY else '[VIDE]'}")
    print(f"OPENROUTER_API_KEY: {'[OK] configuree' if settings.OPENROUTER_API_KEY else '[VIDE]'}")

    # 1. Afficher le prompt
    score_result, cve_results = test_prompt()

    # 2. Tester Gemini
    gemini_ok = test_gemini(score_result, cve_results)

    # 3. Tester OpenRouter
    openrouter_ok = test_openrouter(score_result, cve_results)

    # Resume
    print("\n" + "=" * 70)
    print("RESUME DES TESTS")
    print("=" * 70)
    print(f"  Gemini      : {'[OK] FONCTIONNE' if gemini_ok else '[ECHEC]'}")
    if openrouter_ok is None:
        print(f"  OpenRouter  : [--] NON CONFIGURE (normal)")
    else:
        print(f"  OpenRouter  : {'[OK] FONCTIONNE' if openrouter_ok else '[ECHEC]'}")

    if gemini_ok:
        print("\n>>> L'IA est operationnelle ! Les recommandations seront generees par Gemini.")
    elif openrouter_ok:
        print("\n>>> Gemini KO mais OpenRouter fonctionne.")
    else:
        print("\n>>> Aucune IA disponible -- le systeme utilisera les recommandations statiques.")
    print()
