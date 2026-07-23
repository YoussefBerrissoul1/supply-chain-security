/**
 * api.ts — Client HTTP pour l'API backend FastAPI
 *
 * Ce module expose toutes les fonctions nécessaires pour communiquer
 * avec le backend Supply Chain Security (port 8000).
 *
 * Endpoints couverts :
 *   POST /api/v1/analyze           → lancer une analyse GitHub
 *   POST /api/v1/analyze/docker    → lancer une analyse Docker
 *   GET  /api/v1/analyses          → historique des analyses
 *   GET  /api/v1/analyses/{id}     → détail complet
 *   GET  /api/v1/analyses/{id}/progress → progression en temps réel
 *   GET  /api/v1/analyses/{id}/report   → télécharger le PDF
 *   GET  /api/v1/health            → health check
 */

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** URL de base de l'API. En dev, Vite proxy redirige /api → localhost:8000 */
const API_BASE = '/api/v1';

/** Délai entre deux polls (ms) */
const POLL_INTERVAL_MS = 2500;

/** Timeout maximum pour attendre la fin d'une analyse (ms) */
const POLL_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

// ─────────────────────────────────────────────────────────────────────────────
// Types — miroir des schémas Pydantic du backend
// ─────────────────────────────────────────────────────────────────────────────

export type AnalysisStatus = 'pending' | 'running' | 'done' | 'failed' | 'cancelled';
export type ScanType       = 'standard' | 'deep';
export type TargetType     = 'github' | 'docker';

export interface VulnerabilityAPI {
  id: number;
  cve_id: string;
  cvss_score: number;
  severity: string; // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  description: string;
  fixed_version?: string | null;
  exploit_available: boolean;
  published_date?: string | null;
}

export interface DependencyAPI {
  id: number;
  name: string;
  version: string;
  ecosystem: string;
  is_outdated: boolean;
  vulnerabilities: VulnerabilityAPI[];
}

export interface DockerResultAPI {
  id: number;
  base_image: string;
  vulnerabilities_count: number;
  has_root_user: boolean;
  image_score: number;
}

export interface RecommendationAPI {
  id: number;
  target_type: string;
  recommendation_text: string;
  provider: string;
}

export interface ReportAPI {
  id: number;
  format: string;
  file_path: string;
}

/** Réponse résumée (liste historique) */
export interface AnalysisSummaryAPI {
  id: number;
  repo_url: string;
  repo_name: string;
  status: AnalysisStatus;
  security_score: number | null;
  created_at: string;
  scan_type: string;
  target_type: string;
  cve_service_version?: string | null;
  dependencies_truncated: boolean;
  dependencies_scanned_count?: number | null;
  dependencies_total_count?: number | null;
}

/** Réponse détaillée (GET /analyses/{id}) */
export interface AnalysisDetailAPI extends AnalysisSummaryAPI {
  dependencies: DependencyAPI[];
  docker_result: DockerResultAPI | null;
  recommendations: RecommendationAPI[];
  reports: ReportAPI[];
}

/** Réponse de progression (GET /analyses/{id}/progress) */
export interface AnalysisProgressAPI {
  id: number;
  status: AnalysisStatus;
  scan_type: string;
  target_type: string;
  security_score: number | null;
  total_deps: number;
  total_vulns: number;
  vulns_by_severity: Record<string, number>;
  total_recommendations: number;
  has_docker: boolean;
}

/** Réponse du health check */
export interface HealthAPI {
  status: string;
  version: string;
  database: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Erreur API personnalisée
// ─────────────────────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
    message?: string,
  ) {
    super(message ?? detail);
    this.name = 'ApiError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper fetch
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(
  endpoint: string,
  options?: RequestInit,
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      detail = body?.detail ?? detail;
    } catch {
      // pas de body JSON — garder le message par défaut
    }
    throw new ApiError(response.status, detail);
  }

  // 204 No Content
  if (response.status === 204) return undefined as unknown as T;

  return response.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fonctions API publiques
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lance une analyse GitHub en arrière-plan.
 * Le backend retourne immédiatement avec status=pending.
 */
export async function startGithubAnalysis(
  repoUrl: string,
  scanType: ScanType = 'standard',
): Promise<AnalysisSummaryAPI> {
  return apiFetch<AnalysisSummaryAPI>('/analyze', {
    method: 'POST',
    body: JSON.stringify({
      repo_url: repoUrl,
      scan_type: scanType,
      target_type: 'github',
    }),
  });
}

/**
 * Lance une analyse d'image Docker en arrière-plan.
 */
export async function startDockerAnalysis(
  imageName: string,
  scanType: ScanType = 'standard',
): Promise<AnalysisSummaryAPI> {
  return apiFetch<AnalysisSummaryAPI>('/analyze/docker', {
    method: 'POST',
    body: JSON.stringify({
      image_name: imageName,
      scan_type: scanType,
    }),
  });
}

/**
 * Récupère l'historique des analyses (20 dernières par défaut).
 */
export async function listAnalyses(
  limit = 20,
  targetType?: TargetType,
): Promise<AnalysisSummaryAPI[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (targetType) params.set('target_type', targetType);
  return apiFetch<AnalysisSummaryAPI[]>(`/analyses?${params}`);
}

/**
 * Récupère le détail complet d'une analyse (dépendances, CVE, Docker, IA…).
 */
export async function getAnalysis(id: number): Promise<AnalysisDetailAPI> {
  return apiFetch<AnalysisDetailAPI>(`/analyses/${id}`);
}

/**
 * Récupère la progression en temps réel d'une analyse en cours.
 * Utilisé pour afficher les stats partielles dans le terminal.
 */
export async function getAnalysisProgress(
  id: number,
): Promise<AnalysisProgressAPI> {
  return apiFetch<AnalysisProgressAPI>(`/analyses/${id}/progress`);
}

/**
 * Vérifie l'état de l'API et de la base de données.
 */
export async function healthCheck(): Promise<HealthAPI> {
  return apiFetch<HealthAPI>('/health');
}

/**
 * Retourne l'URL de téléchargement du rapport PDF d'une analyse.
 */
export function getReportUrl(analysisId: number): string {
  return `${API_BASE}/analyses/${analysisId}/report`;
}

/**
 * Annule une analyse en cours de manière asynchrone.
 */
export async function cancelAnalysis(analysisId: number): Promise<{message: string}> {
  return apiFetch<{message: string}>(`/analyses/${analysisId}/cancel`, {
    method: 'POST',
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Polling — attend la fin d'une analyse
// ─────────────────────────────────────────────────────────────────────────────

export interface PollCallbacks {
  /** Appelé à chaque tick de polling avec la progression courante */
  onProgress?: (progress: AnalysisProgressAPI) => void;
  /** Appelé quand l'analyse est terminée avec succès */
  onDone?: (analysis: AnalysisDetailAPI) => void;
  /** Appelé en cas d'erreur (analyse FAILED ou erreur réseau) */
  onError?: (error: string) => void;
}

/**
 * Poll régulièrement le backend jusqu'à ce que l'analyse soit terminée.
 *
 * @returns Fonction pour annuler le polling manuellement
 */
export function pollAnalysisStatus(
  analysisId: number,
  callbacks: PollCallbacks,
): () => void {
  let cancelled = false;
  const startedAt = Date.now();
  let errorCount = 0;
  const MAX_ERRORS = 3;

  async function tick() {
    if (cancelled) return;

    try {
      const progress = await getAnalysisProgress(analysisId);
      
      // En cas de succès, on réinitialise le compteur d'erreurs
      errorCount = 0;
      
      callbacks.onProgress?.(progress);

      if (progress.status === 'done') {
        // Récupérer le détail complet
        const detail = await getAnalysis(analysisId);
        callbacks.onDone?.(detail);
        return; // arrêt du polling
      }

      if (progress.status === 'failed') {
        callbacks.onError?.("L'analyse a échoué côté serveur.");
        return; // arrêt du polling
      }
      
      if (progress.status === 'cancelled') {
        callbacks.onError?.("L'analyse a été annulée côté serveur.");
        return; // arrêt du polling
      }
      
    } catch (err) {
      errorCount++;
      if (errorCount >= MAX_ERRORS) {
        const message =
          err instanceof ApiError
            ? err.detail
            : 'Erreur de connexion au serveur après plusieurs tentatives.';
        callbacks.onError?.(message);
        return; // arrêt du polling après MAX_ERRORS échecs
      }
      // Sinon, on ignore l'erreur et on attend le prochain tick
    }

    // Prochain tick
    if (!cancelled) {
      setTimeout(tick, POLL_INTERVAL_MS);
    }
  }

  // Premier tick immédiat
  setTimeout(tick, 500);

  // Retourner la fonction d'annulation
  return () => {
    cancelled = true;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Convertisseurs — API → ScanPage types
// ─────────────────────────────────────────────────────────────────────────────

/** Convertit la sévérité backend (CRITICAL/HIGH/MEDIUM/LOW) en français */
function mapSeverity(
  sev: string,
): 'CRITIQUE' | 'HAUTE' | 'MOYENNE' | 'BASSE' {
  switch (sev.toUpperCase()) {
    case 'CRITICAL': return 'CRITIQUE';
    case 'HIGH':     return 'HAUTE';
    case 'MEDIUM':   return 'MOYENNE';
    default:         return 'BASSE';
  }
}

/** Convertit le status backend en status frontend */
function mapDepStatus(
  dep: DependencyAPI,
): 'ok' | 'outdated' | 'vulnerable' {
  if (dep.vulnerabilities.length > 0) return 'vulnerable';
  if (dep.is_outdated) return 'outdated';
  return 'ok';
}

/** Convertit un score numérique en status global */
function mapScore(score: number | null): 'ok' | 'warn' | 'danger' {
  const s = score ?? 0;
  if (s >= 70) return 'ok';
  if (s >= 50) return 'warn';
  return 'danger';
}

/**
 * Convertit une AnalysisDetailAPI en ScanResult (format attendu par ScanPage).
 */
export function analysisToScanResult(analysis: AnalysisDetailAPI): import('../pages/ScanPage').ScanResult {
  const score = Math.round(analysis.security_score ?? 0);

  // Stats
  const totalVulns = analysis.dependencies.reduce(
    (acc, d) => acc + d.vulnerabilities.length,
    0,
  );
  const criticalVulns = analysis.dependencies.reduce(
    (acc, d) =>
      acc +
      d.vulnerabilities.filter((v) => v.severity.toUpperCase() === 'CRITICAL')
        .length,
    0,
  );

  const isDocker = analysis.target_type === 'docker';

  const stats = isDocker
    ? [
        { label: 'Vulnérabilités totales', value: String(analysis.docker_result?.vulnerabilities_count ?? totalVulns) },
        { label: 'CVE Critiques',          value: String(criticalVulns) },
        { label: 'Score image Docker',     value: `${Math.round(analysis.docker_result?.image_score ?? 0)}/100` },
        { label: 'Dépendances analysées',  value: String(analysis.dependencies.length) },
      ]
    : [
        { label: 'Vulnérabilités totales', value: String(totalVulns) },
        { label: 'CVE Critiques',          value: String(criticalVulns) },
        { label: 'Dépendances analysées',  value: String(analysis.dependencies.length) },
        { label: 'Dépendances à risque',   value: String(analysis.dependencies.filter((d) => d.vulnerabilities.length > 0 || d.is_outdated).length) },
      ];

  // Vulnérabilités (tous les CVE de toutes les dépendances)
  const vulns = analysis.dependencies.flatMap((dep) =>
    dep.vulnerabilities.map((v) => ({
      id: v.cve_id,
      severity: mapSeverity(v.severity),
      pkg: `${dep.name}@${dep.version}`,
      desc: v.description,
      score: v.cvss_score,
    })),
  );

  // Dépendances
  const deps = analysis.dependencies.map((dep) => ({
    name: dep.name,
    version: dep.version,
    status: mapDepStatus(dep),
  }));

  // Recommandation IA (prendre la première recommandation globale ou la première disponible)
  const aiRec =
    analysis.recommendations.find((r) => r.target_type === 'global')
      ?.recommendation_text ??
    analysis.recommendations[0]?.recommendation_text ??
    'Aucune recommandation générée.';

  // Docker config (approximation à partir des données backend)
  const dockerConfig = analysis.docker_result
    ? {
        ports: [],
        user: analysis.docker_result.has_root_user ? 'root' : 'non-root',
        os: analysis.docker_result.base_image,
        totalSize: 'N/A',
      }
    : undefined;

  return {
    target: analysis.repo_url,
    type: isDocker ? 'docker' : 'github',
    score,
    status: mapScore(score),
    stats,
    vulns,
    deps,
    aiRec,
    dockerConfig,
    analysisId: analysis.id,
  };
}
