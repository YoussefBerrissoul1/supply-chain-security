"""
Service de generation de rapports PDF — Etape 15.

Genere un rapport PDF professionnel a partir des resultats d'une analyse
de securite. Utilise ReportLab pour la mise en page.

Le rapport contient :
    1. Page de titre avec nom du depot et date
    2. Resume executif (score, niveau de risque, nombre de CVE)
    3. Tableau detaille des vulnerabilites detectees
    4. Resultats Docker (image de base, vulnerabilites OS, pratiques)
    5. Recommandations IA (classees par type)
    6. Detail des penalites appliquees par la matrice 3D
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.config import settings
from app.models.analysis import Analysis

logger = logging.getLogger(__name__)


# ==============================================================
# COULEURS DU THEME
# ==============================================================

COLOR_PRIMARY = colors.HexColor("#1a237e")     # Bleu marine fonce
COLOR_ACCENT = colors.HexColor("#0d47a1")      # Bleu roi
COLOR_SUCCESS = colors.HexColor("#2e7d32")      # Vert
COLOR_WARNING = colors.HexColor("#f57f17")      # Orange
COLOR_DANGER = colors.HexColor("#c62828")       # Rouge
COLOR_CRITICAL = colors.HexColor("#b71c1c")     # Rouge fonce
COLOR_LIGHT_BG = colors.HexColor("#f5f5f5")    # Gris clair (fond tableau)
COLOR_HEADER_BG = colors.HexColor("#1a237e")    # Fond en-tete tableau
COLOR_WHITE = colors.white
COLOR_BLACK = colors.black


# ==============================================================
# STYLES PERSONNALISES
# ==============================================================

def _get_styles():
    """Retourne les styles personnalises pour le rapport PDF."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=COLOR_PRIMARY,
        spaceAfter=6 * mm,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=14,
        textColor=COLOR_ACCENT,
        spaceAfter=4 * mm,
        alignment=TA_CENTER,
        fontName="Helvetica",
    ))

    styles.add(ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading1"],
        fontSize=16,
        textColor=COLOR_PRIMARY,
        spaceBefore=10 * mm,
        spaceAfter=4 * mm,
        fontName="Helvetica-Bold",
        borderWidth=0,
        borderPadding=0,
    ))

    styles.add(ParagraphStyle(
        name="SubSection",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=COLOR_ACCENT,
        spaceBefore=6 * mm,
        spaceAfter=3 * mm,
        fontName="Helvetica-Bold",
    ))

    styles.add(ParagraphStyle(
        name="BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_BLACK,
        spaceAfter=2 * mm,
        alignment=TA_JUSTIFY,
        fontName="Helvetica",
        leading=14,
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#666666"),
        alignment=TA_CENTER,
        fontName="Helvetica",
    ))

    return styles


# ==============================================================
# COULEUR SELON LA SEVERITE
# ==============================================================

def _severity_color(severity: str) -> colors.HexColor:
    """Retourne la couleur associee a un niveau de severite."""
    mapping = {
        "CRITICAL": COLOR_CRITICAL,
        "HIGH": COLOR_DANGER,
        "MEDIUM": COLOR_WARNING,
        "LOW": colors.HexColor("#1565c0"),
    }
    return mapping.get(severity.upper(), COLOR_BLACK)


def _risk_color(score: float) -> colors.HexColor:
    """Retourne la couleur associee au score de securite."""
    if score >= 90:
        return COLOR_SUCCESS
    elif score >= 70:
        return colors.HexColor("#43a047")
    elif score >= 50:
        return COLOR_WARNING
    elif score >= 30:
        return colors.HexColor("#e65100")
    else:
        return COLOR_CRITICAL


def _risk_label(score: float) -> str:
    """Retourne le libelle de risque associe au score."""
    if score >= 90:
        return "EXCELLENT"
    elif score >= 70:
        return "BON"
    elif score >= 50:
        return "MOYEN"
    elif score >= 30:
        return "MAUVAIS"
    else:
        return "CRITIQUE"


# ==============================================================
# EN-TETE ET PIED DE PAGE
# ==============================================================

def _header_footer(canvas, doc):
    """Dessine l'en-tete et le pied de page sur chaque page."""
    canvas.saveState()

    # --- En-tete : ligne bleue + titre ---
    canvas.setStrokeColor(COLOR_PRIMARY)
    canvas.setLineWidth(2)
    canvas.line(1.5 * cm, A4[1] - 1.5 * cm, A4[0] - 1.5 * cm, A4[1] - 1.5 * cm)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(COLOR_PRIMARY)
    canvas.drawString(1.5 * cm, A4[1] - 1.3 * cm, "Supply Chain Security — Rapport d'Audit")

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawRightString(A4[0] - 1.5 * cm, A4[1] - 1.3 * cm, f"Page {doc.page}")

    # --- Pied de page ---
    canvas.setStrokeColor(COLOR_PRIMARY)
    canvas.setLineWidth(1)
    canvas.line(1.5 * cm, 1.5 * cm, A4[0] - 1.5 * cm, 1.5 * cm)

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#999999"))
    canvas.drawString(1.5 * cm, 1.0 * cm, "Plateforme d'Audit de la Chaine d'Approvisionnement Logicielle")
    canvas.drawRightString(A4[0] - 1.5 * cm, 1.0 * cm, f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}")

    canvas.restoreState()


# ==============================================================
# CONSTRUCTION DES SECTIONS DU RAPPORT
# ==============================================================

def _build_title_section(analysis: Analysis, styles) -> list:
    """Construit la page de titre."""
    elements = []
    elements.append(Spacer(1, 4 * cm))

    elements.append(Paragraph(
        "Rapport d'Audit de Securite",
        styles["ReportTitle"],
    ))

    elements.append(Paragraph(
        "Analyse de la Chaine d'Approvisionnement Logicielle",
        styles["ReportSubtitle"],
    ))

    elements.append(Spacer(1, 1.5 * cm))

    # Tableau d'informations
    info_data = [
        ["Depot analyse", analysis.repo_name],
        ["URL", analysis.repo_url],
        ["Date d'analyse", analysis.created_at.strftime("%d/%m/%Y a %H:%M") if analysis.created_at else "N/A"],
        ["Type de scan", analysis.scan_type or "standard"],
        ["Statut", analysis.status.value.upper()],
    ]

    info_table = Table(info_data, colWidths=[5 * cm, 10 * cm])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_BLACK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e0e0e0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    elements.append(info_table)
    elements.append(PageBreak())

    return elements


def _build_score_section(analysis: Analysis, styles) -> list:
    """Construit la section resume du score."""
    elements = []
    score = analysis.security_score or 0.0

    elements.append(Paragraph("1. Resume Executif", styles["SectionTitle"]))

    risk = _risk_label(score)
    color = _risk_color(score)

    # Grand score visuel
    score_text = f'<font size="36" color="{color.hexval()}"><b>{score:.0f}</b></font>' \
                 f'<font size="18" color="#666666"> / 100</font>'
    elements.append(Paragraph(score_text, ParagraphStyle(
        name="ScoreDisplay", alignment=TA_CENTER, spaceAfter=3 * mm,
    )))

    risk_text = f'<font size="16" color="{color.hexval()}"><b>Niveau de risque : {risk}</b></font>'
    elements.append(Paragraph(risk_text, ParagraphStyle(
        name="RiskDisplay", alignment=TA_CENTER, spaceAfter=8 * mm,
    )))

    # Compteurs
    total_deps = len(analysis.dependencies) if analysis.dependencies else 0
    total_vulns = 0
    critical_count = 0
    high_count = 0
    medium_count = 0

    for dep in (analysis.dependencies or []):
        for v in (dep.vulnerabilities or []):
            total_vulns += 1
            if v.severity.value == "CRITICAL":
                critical_count += 1
            elif v.severity.value == "HIGH":
                high_count += 1
            elif v.severity.value == "MEDIUM":
                medium_count += 1

    has_docker = analysis.docker_result is not None

    summary_data = [
        ["Metrique", "Valeur"],
        ["Dependances analysees", str(total_deps)],
        ["Vulnerabilites detectees (total)", str(total_vulns)],
        ["CRITICAL", str(critical_count)],
        ["HIGH", str(high_count)],
        ["MEDIUM", str(medium_count)],
        ["Dockerfile analyse", "Oui" if has_docker else "Non"],
    ]

    if has_docker and analysis.docker_result:
        summary_data.append(["Image Docker", analysis.docker_result.base_image])
        summary_data.append(["Vulns Docker (OS)", str(analysis.docker_result.vulnerabilities_count)])

    summary_table = Table(summary_data, colWidths=[8 * cm, 7 * cm])
    summary_table.setStyle(TableStyle([
        # En-tete
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        # Corps
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 5 * mm))

    return elements


def _build_vulnerabilities_section(analysis: Analysis, styles) -> list:
    """Construit la section des vulnerabilites detectees."""
    elements = []

    elements.append(Paragraph("2. Vulnerabilites Detectees", styles["SectionTitle"]))

    # Collecter toutes les vulns
    all_vulns = []
    for dep in (analysis.dependencies or []):
        for v in (dep.vulnerabilities or []):
            all_vulns.append({
                "cve_id": v.cve_id,
                "severity": v.severity.value,
                "cvss": v.cvss_score,
                "package": f"{dep.name}@{dep.version}",
                "ecosystem": dep.ecosystem,
                "fixed": v.fixed_version or "Non disponible",
                "exploit": "Oui" if v.exploit_available else "Non",
            })

    if not all_vulns:
        elements.append(Paragraph(
            "Aucune vulnerabilite detectee. Le depot est securise.",
            styles["BodyText2"],
        ))
        return elements

    # Trier par severite
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_vulns.sort(key=lambda x: sev_order.get(x["severity"], 99))

    elements.append(Paragraph(
        f"{len(all_vulns)} vulnerabilite(s) detectee(s) dans les dependances du projet :",
        styles["BodyText2"],
    ))

    # Tableau des vulnerabilites
    vuln_header = ["CVE", "Severite", "CVSS", "Paquet", "Correctif", "Exploit"]
    vuln_rows = [vuln_header]

    for v in all_vulns[:30]:  # Limiter a 30 lignes
        vuln_rows.append([
            v["cve_id"],
            v["severity"],
            f'{v["cvss"]:.1f}',
            v["package"],
            v["fixed"],
            v["exploit"],
        ])

    vuln_table = Table(vuln_rows, colWidths=[3.2 * cm, 2 * cm, 1.5 * cm, 4 * cm, 3 * cm, 1.8 * cm])

    # Style du tableau
    table_style = [
        # En-tete
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        # Corps
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
    ]

    # Colorer les cellules de severite
    for i, v in enumerate(all_vulns[:30], start=1):
        sev_color = _severity_color(v["severity"])
        table_style.append(("TEXTCOLOR", (1, i), (1, i), sev_color))
        table_style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))

    vuln_table.setStyle(TableStyle(table_style))
    elements.append(vuln_table)

    if len(all_vulns) > 30:
        elements.append(Paragraph(
            f"... et {len(all_vulns) - 30} vulnerabilite(s) supplementaire(s) non affichee(s).",
            styles["SmallText"],
        ))

    elements.append(Spacer(1, 5 * mm))
    return elements


def _build_docker_section(analysis: Analysis, styles) -> list:
    """Construit la section Docker."""
    elements = []

    elements.append(Paragraph("3. Analyse Docker", styles["SectionTitle"]))

    if not analysis.docker_result:
        elements.append(Paragraph(
            "Aucun Dockerfile detecte dans le depot. Cette section n'est pas applicable.",
            styles["BodyText2"],
        ))
        return elements

    dr = analysis.docker_result

    docker_data = [
        ["Parametre", "Resultat"],
        ["Image de base", dr.base_image],
        ["Vulnerabilites OS", str(dr.vulnerabilities_count)],
        ["Execution en root", "Oui (risque)" if dr.has_root_user else "Non (securise)"],
        ["Score image", f"{dr.image_score:.0f}/100"],
    ]

    docker_table = Table(docker_data, colWidths=[6 * cm, 9 * cm])
    docker_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
    ]))

    elements.append(docker_table)

    # Alertes
    if dr.has_root_user:
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph(
            '<font color="#c62828"><b>ALERTE :</b> L\'image Docker s\'execute en tant que root. '
            'Ajoutez une instruction USER dans le Dockerfile pour reduire la surface d\'attaque.</font>',
            styles["BodyText2"],
        ))

    elements.append(Spacer(1, 5 * mm))
    return elements


def _build_recommendations_section(analysis: Analysis, styles) -> list:
    """Construit la section des recommandations IA."""
    elements = []

    elements.append(Paragraph("4. Recommandations de Securite", styles["SectionTitle"]))

    recs = analysis.recommendations or []
    if not recs:
        elements.append(Paragraph(
            "Aucune recommandation generee pour cette analyse.",
            styles["BodyText2"],
        ))
        return elements

    provider = recs[0].provider if recs else "statique"
    elements.append(Paragraph(
        f"<i>Generees par : {provider}</i>",
        styles["SmallText"],
    ))
    elements.append(Spacer(1, 3 * mm))

    # Grouper par type
    groups = {"dependency": [], "docker": [], "global": []}
    for rec in recs:
        target = rec.target_type.value if hasattr(rec.target_type, "value") else str(rec.target_type)
        groups.setdefault(target, []).append(rec.recommendation_text)

    group_labels = {
        "dependency": "Dependances",
        "docker": "Docker",
        "global": "Pratiques generales",
    }

    for group_key, label in group_labels.items():
        items = groups.get(group_key, [])
        if not items:
            continue

        elements.append(Paragraph(f"4.{list(group_labels.keys()).index(group_key)+1}. {label}", styles["SubSection"]))

        for i, text in enumerate(items, 1):
            # Tronquer les textes tres longs
            display_text = text[:500] + "..." if len(text) > 500 else text
            elements.append(Paragraph(
                f"<b>{i}.</b> {display_text}",
                styles["BodyText2"],
            ))

    elements.append(Spacer(1, 5 * mm))
    return elements


# ==============================================================
# FONCTION PRINCIPALE — GENERATION DU PDF
# ==============================================================

def generate_pdf_report(analysis: Analysis) -> str:
    """
    Genere un rapport PDF professionnel pour une analyse de securite.

    Parametres :
        analysis : objet Analysis avec toutes ses relations chargees
                   (dependencies, vulnerabilities, docker_result, recommendations)

    Retourne :
        Chemin absolu du fichier PDF genere.

    Leve :
        Exception si la generation echoue.
    """
    logger.info("=== Generation du rapport PDF pour l'analyse #%d ===", analysis.id)

    # Creer le dossier de sortie s'il n'existe pas
    output_dir = Path(settings.REPORT_OUTPUT_DIR).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Nom du fichier : rapport_<repo>_<id>_<date>.pdf
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rapport_{analysis.repo_name}_{analysis.id}_{date_str}.pdf"
    filepath = output_dir / filename

    logger.info("Chemin du rapport : %s", filepath)

    # Creer le document PDF
    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Rapport de Securite — {analysis.repo_name}",
        author="Supply Chain Security Platform",
    )

    # Recuperer les styles
    styles = _get_styles()

    # Construire le contenu
    elements = []
    elements.extend(_build_title_section(analysis, styles))
    elements.extend(_build_score_section(analysis, styles))
    elements.extend(_build_vulnerabilities_section(analysis, styles))
    elements.extend(_build_docker_section(analysis, styles))
    elements.extend(_build_recommendations_section(analysis, styles))

    # Pied de page final
    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph(
        "--- Fin du rapport ---",
        styles["SmallText"],
    ))
    elements.append(Paragraph(
        "Ce rapport a ete genere automatiquement par la Plateforme d'Audit "
        "de la Chaine d'Approvisionnement Logicielle.",
        styles["SmallText"],
    ))

    # Generer le PDF
    try:
        doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)
        logger.info("Rapport PDF genere avec succes : %s", filepath)
    except Exception as e:
        logger.error("Erreur lors de la generation du PDF : %s", e)
        raise

    return str(filepath)
