#!/usr/bin/env python3
"""
Script de migration/nettoyage — Analyses obsolètes (Point 2).

Ce script identifie les Analysis en base dont les Vulnerability associées
ont des cvss_score suspects (valeurs figées : 8.0, 5.0, 0.0 en masse)
indiquant qu'elles ont été produites par une ancienne version du moteur CVE
qui utilisait un mapping fixe sévérité→score au lieu du calcul CVSS réel.

USAGE :
    # Depuis le répertoire backend/ (avec venv activé)
    python ../scripts/rescan_stale_analyses.py

    # Mode dry-run (par défaut) : affiche les analyses suspectes sans modifier
    python ../scripts/rescan_stale_analyses.py --dry-run

    # Mode live : marque les analyses suspectes pour re-scan (status → PENDING)
    python ../scripts/rescan_stale_analyses.py --rescan

CRITÈRES DE DÉTECTION :
    Une analyse est considérée "obsolète/suspecte" si :
    - Elle a des vulnérabilités en base ET
    - Plus de 50% des CVSS sont des valeurs rondes suspectes (8.0, 5.0, 0.0)
      avec plus de 3 occurrences (évite les faux positifs)
    - OU cve_service_version IS NULL (analysa produite avant la version 2.0.0)
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

# Ajouter le répertoire backend/ au PYTHONPATH pour les imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.core.database import SessionLocal
from app.models.analysis import Analysis, AnalysisStatus
from app.models.dependency import Dependency
from app.models.vulnerability import Vulnerability

# Valeurs CVSS suspectes (générées par l'ancien moteur avec mapping fixe)
SUSPICIOUS_CVSS_VALUES: set[float] = {8.0, 5.0, 0.0}

# Seuil : % de valeurs suspectes pour flaguer une analyse (0.5 = 50%)
SUSPICIOUS_RATIO_THRESHOLD: float = 0.5

# Nombre minimum de vulns pour appliquer l'analyse statistique
MIN_VULNS_FOR_STATS: int = 3


def detect_stale_analyses(db) -> list[dict]:
    """
    Identifie les analyses obsolètes selon deux critères :
        1. cve_service_version IS NULL → produite avant la version 2.0.0
        2. Ratio élevé de CVSS suspects (8.0, 5.0, 0.0 en masse)

    Retourne une liste de dicts décrivant chaque analyse suspecte.
    """
    stale = []

    analyses = db.query(Analysis).filter(
        Analysis.status == AnalysisStatus.DONE
    ).all()

    print(f"\n📊 {len(analyses)} analyse(s) DONE trouvées en base.")
    print("-" * 60)

    for analysis in analyses:
        reasons = []

        # Critère 1 : version du moteur CVE inconnue (ancienne analyse)
        if analysis.cve_service_version is None:
            reasons.append("cve_service_version=NULL (avant moteur v2.0.0)")

        # Critère 2 : scores CVSS suspects
        all_vulns = []
        for dep in analysis.dependencies:
            all_vulns.extend(dep.vulnerabilities)

        if len(all_vulns) >= MIN_VULNS_FOR_STATS:
            scores = [v.cvss_score for v in all_vulns if v.cvss_score is not None]
            if scores:
                suspicious_count = sum(1 for s in scores if s in SUSPICIOUS_CVSS_VALUES)
                ratio = suspicious_count / len(scores)
                if ratio >= SUSPICIOUS_RATIO_THRESHOLD:
                    reasons.append(
                        f"CVSS suspects: {suspicious_count}/{len(scores)} "
                        f"({ratio:.0%}) valeurs rondes (8.0/5.0/0.0)"
                    )

                # Vérifier aussi l'absence totale de exploit_available
                exploits_found = sum(1 for v in all_vulns if v.exploit_available)
                if len(all_vulns) > 10 and exploits_found == 0:
                    reasons.append(
                        f"exploit_available=False sur TOUTES les {len(all_vulns)} vulnérabilités "
                        "(probable manque de détection)"
                    )

        if reasons:
            stale.append({
                "id": analysis.id,
                "repo_name": analysis.repo_name,
                "repo_url": analysis.repo_url,
                "security_score": analysis.security_score,
                "cve_service_version": analysis.cve_service_version,
                "scan_type": analysis.scan_type,
                "total_vulns": len(all_vulns),
                "reasons": reasons,
            })

    return stale


def print_stale_report(stale_analyses: list[dict]) -> None:
    """Affiche un rapport lisible des analyses suspectes."""
    if not stale_analyses:
        print("\n✅ Aucune analyse suspecte détectée — base propre !")
        return

    print(f"\n⚠️  {len(stale_analyses)} analyse(s) suspecte(s) détectée(s) :\n")
    for a in stale_analyses:
        print(f"  🔍 Analyse #{a['id']} : {a['repo_name']}")
        print(f"     URL          : {a['repo_url']}")
        print(f"     Score actuel : {a['security_score']}")
        print(f"     Mode scan    : {a['scan_type']}")
        print(f"     Moteur CVE   : {a['cve_service_version'] or 'INCONNU (avant v2.0.0)'}")
        print(f"     Vulns totales: {a['total_vulns']}")
        print(f"     Raisons :")
        for r in a["reasons"]:
            print(f"       - {r}")
        print()


def rescan_stale(db, stale_analyses: list[dict]) -> None:
    """
    Marque les analyses suspectes pour re-scan :
    - status → PENDING (sera repris par le prochain scan manuel ou automatique)
    - security_score → None (sera recalculé)
    - Supprime les vulnérabilités et dépendances existantes (seront re-créées)

    ATTENTION : Cette action est irréversible. Faire un backup de la DB avant.
    """
    if not stale_analyses:
        print("Rien à faire.")
        return

    confirmed = input(
        f"\n⚠️  Confirmer le re-scan de {len(stale_analyses)} analyse(s) ? "
        "Cette action supprimera les résultats actuels. [oui/NON] : "
    )
    if confirmed.lower() not in ("oui", "o", "yes", "y"):
        print("Annulé.")
        return

    for a in stale_analyses:
        analysis = db.query(Analysis).filter(Analysis.id == a["id"]).first()
        if not analysis:
            continue

        # Supprimer les dépendances (cascade supprime les vulns et vulns)
        db.query(Dependency).filter(
            Dependency.analysis_id == analysis.id
        ).delete()

        # Remettre à zéro
        analysis.status = AnalysisStatus.PENDING
        analysis.security_score = None
        analysis.cve_service_version = None
        analysis.dependencies_truncated = False
        analysis.dependencies_scanned_count = None
        analysis.dependencies_total_count = None

        db.commit()
        print(f"  ✅ Analyse #{analysis.id} ({analysis.repo_name}) marquée PENDING")

    print(f"\n✅ {len(stale_analyses)} analyse(s) marquée(s) pour re-scan.")
    print("   Relancez le scan depuis l'interface ou via POST /api/v1/analyze")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Détecte et optionnellement re-scanne les analyses CVE obsolètes."
    )
    parser.add_argument(
        "--rescan",
        action="store_true",
        help="Marquer les analyses suspectes pour re-scan (supprime les résultats actuels)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Afficher seulement les analyses suspectes sans modifier (défaut)",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        stale = detect_stale_analyses(db)
        print_stale_report(stale)

        if args.rescan:
            rescan_stale(db, stale)
        else:
            if stale:
                print(
                    "ℹ️  Pour re-scanner, relancez avec : "
                    "python scripts/rescan_stale_analyses.py --rescan"
                )

    finally:
        db.close()


if __name__ == "__main__":
    main()
