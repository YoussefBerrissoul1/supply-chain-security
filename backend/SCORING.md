# Algorithme de Score de Sécurité — v2.0

Ce document décrit l algorithme de calcul du score de sécurité implémenté dans score_service.py.

## Formule générale

```
Score = min(cap_sévérité, 100 − somme_pénalités)   [min 0]
```

## 1. Pénalités CVE (matrice 3D)

### 1a. CRITICAL / HIGH / MEDIUM

Pour chaque CVE unique (cve_id dédupliqué cross-packages) :
  pénalité = base × exploit_mult × impact_mult

| Sévérité | Base  |
|----------|-------|
| CRITICAL | 15 pts |
| HIGH     | 8 pts  |
| MEDIUM   | 3 pts  |

Multiplicateurs exploit_mult :
- Default                      : 1.0
- Exploit public connu (CISA)  : × 1.5
- EPSS >= 0.7                  : × 1.3
- EPSS >= 0.4                  : × 1.1
- CVE < 6 mois (récente)       : × 1.2

Multiplicateur impact_mult :
- Dépendance production : × 1.3
- Dépendance dev        : × 0.5

### 1b. Pénalité plancher LOW/NONE (NOUVEAU en v2.0)

  pénalité_low = min(10.0, N × 0.4)

Exemples :
| N CVE LOW | Pénalité appliquée | Score (sans autres CVE) |
|-----------|--------------------|------------------------|
| 5         | 2.0 pts            | 98.0                   |
| 23        | 9.2 pts            | 90.8                   |
| 25+       | 10.0 (plafond)     | 90.0                   |

Rationale : N CVE LOW != sécurité parfaite.

### 1c. CVE sans correctif (unpatched)

| Catégorie                         | Pénalité | Plafond |
|-----------------------------------|----------|---------|
| CVE CRITICAL sans fixed_version   | 3.0/CVE  | -15 pts |
| CVE HIGH sans fixed_version       | 1.5/CVE  | -9 pts  |

## 2. Pénalités Docker

- Image vulnérable (score < 50) : -10 à -20 pts (max -20)
- Conteneur en root             : -5 pts
- Mauvaises pratiques total     : max -10 pts

## 3. Hard caps par sévérité (NOUVEAU en v2.0)

Après calcul, le score est plafonné selon la sévérité max détectée :

| Sévérité max    | Score max | Niveau max |
|-----------------|-----------|------------|
| >= 1 CRITICAL   | 59        | MOYEN      |
| >= 1 HIGH       | 79        | BON        |
| >= 1 MEDIUM     | 89        | BON        |
| Aucune C/H/M    | 100       | EXCELLENT  |

Priorité : CRITICAL > HIGH > MEDIUM.

## 4. Interprétation du score

| Score  | Niveau   |
|--------|----------|
| 90-100 | EXCELLENT|
| 70-89  | BON      |
| 50-69  | MOYEN    |
| 30-49  | MAUVAIS  |
| 0-29   | CRITIQUE |

## Historique

| Version | Date       | Changements |
|---------|------------|-------------|
| v1.0    | 2026-07-01 | Pénalités fixes, pas de matrice 3D |
| v2.0    | 2026-08-16 | Pénalité plancher LOW proportionnelle, hard caps sévérité |
