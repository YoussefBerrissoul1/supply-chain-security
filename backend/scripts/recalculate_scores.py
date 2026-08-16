#!/usr/bin/env python
"""
scripts/recalculate_scores.py
-----------------------------
Recalcule les scores de sécurité pour toutes les analyses DONE en base.

PRÉREQUIS : Faire un backup avant execution (pg_dump -U postgres -d supply_chain_security > backup.sql)

Usage :
    cd backend
    venv/Scripts/python scripts/recalculate_scores.py [--dry-run] [--limit N]

Options :
    --dry-run   : Affiche ce qui serait recalcule sans modifier la DB
    --limit N   : Limite le recalcul aux N premieres analyses

Exemple :
    venv\Scripts\python scripts\recalculate_scores.py --dry-run --limit 10
    venv\Scripts\python scripts\recalculate_scores.py
"""
import sys
import os
import argparse
import logging

# Ajouter le dossier parent (backend/) au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description='Recalcule les security scores en base')
    parser.add_argument('--dry-run', action='store_true',
                        help='Simule sans modifier la DB')
    parser.add_argument('--limit', type=int, default=None,
                        help='Limite aux N premieres analyses')
    args = parser.parse_args()

    from app.core.database import SessionLocal
    from app.models.analysis import Analysis, AnalysisStatus
    from app.models.dependency import Dependency
    from app.models.vulnerability import Vulnerability
    from app.services.score_service import compute_security_score
    from app.services.cve_providers.models import VulnerabilityResult, Severity

    db = SessionLocal()
    try:
        query = db.query(Analysis).filter(Analysis.status == AnalysisStatus.DONE)
        if args.limit:
            query = query.limit(args.limit)
        analyses = query.all()

        logger.info("Recalcul pour %d analyses (dry_run=%s)", len(analyses), args.dry_run)
        updated = 0
        skipped = 0
        errors = 0

        for analysis in analyses:
            try:
                # Reconstruire cve_results depuis la DB
                cve_results = {}
                deps = db.query(Dependency).filter(
                    Dependency.analysis_id == analysis.id
                ).all()

                for dep in deps:
                    dep_key = f"{dep.name}@{dep.version}"
                    vuln_list = []
                    for v in dep.vulnerabilities:
                        sev_map = {
                            'CRITICAL': Severity.CRITICAL,
                            'HIGH':     Severity.HIGH,
                            'MEDIUM':   Severity.MEDIUM,
                            'LOW':      Severity.LOW,
                        }
                        sev = sev_map.get(str(v.severity.value) if hasattr(v.severity, 'value') else str(v.severity), Severity.LOW)
                        vr = VulnerabilityResult(
                            cve_id=v.cve_id,
                            cvss_score=v.cvss_score or 0.0,
                            severity=sev,
                            description=v.description or "",
                            fixed_version=v.fixed_version,
                            exploit_available=v.exploit_available,
                            epss_score=v.epss_score,
                        )
                        vuln_list.append(vr)
                    if vuln_list:
                        cve_results[dep_key] = vuln_list

                # Recalculer le score
                new_result = compute_security_score(cve_results=cve_results)
                old_score = analysis.security_score or 0.0
                new_score = new_result.final_score

                delta = new_score - old_score
                delta_str = f"+{delta:.1f}" if delta >= 0 else f"{delta:.1f}"
                logger.info(
                    "Analyse #%d (%s) : %.1f → %.1f (%s)",
                    analysis.id, analysis.repo_name, old_score, new_score, delta_str
                )

                if not args.dry_run:
                    analysis.security_score = new_score
                    db.commit()

                updated += 1

            except Exception as e:
                logger.error("ERREUR analyse #%d : %s", analysis.id, e)
                errors += 1
                db.rollback()

        logger.info(
            "Recalcul terminé : %d mis à jour, %d ignorés, %d erreurs%s",
            updated, skipped, errors,
            " (DRY RUN — aucune modification en DB)" if args.dry_run else ""
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()
