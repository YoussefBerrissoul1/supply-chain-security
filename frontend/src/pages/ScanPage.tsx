import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight, Download, RefreshCw, Clock, ChevronRight, Layers, Box, Server, HardDrive, History, Loader2, AlertCircle, Wifi, Shield } from 'lucide-react';
import { MagneticButton } from '@/components/MagneticButton';
import { RiskMatrix } from '@/components/RiskMatrix';
import { generateReport } from '@/lib/pdf/generateReport';
import {
  startGithubAnalysis,
  startDockerAnalysis,
  pollAnalysisStatus,
  listAnalyses,
  analysisToScanResult,
  getReportUrl,
  cancelAnalysis,
  type AnalysisProgressAPI,
  type AnalysisSummaryAPI,
} from '@/lib/api';

/* ─────────────────────────────────────────────────────────────────────────────
   Types
──────────────────────────────────────────────────────────────────────────────*/
export type ScanMode = 'standard' | 'deep';
export type InputType = 'github' | 'docker' | null;
export type ScanState = 'form' | 'running' | 'results';

export interface TermLine { text: string; type: 'info' | 'warn' | 'ok' | 'cmd'; }

export interface DockerLayer { hash: string; size: string; cmd: string; vulns: number; }
export interface DockerConfig { ports: string[]; user: string; os: string; totalSize: string; }

export interface ScanResult {
  target: string;
  type: 'github' | 'docker';
  score: number;
  status: 'ok' | 'warn' | 'danger';
  stats: { label: string; value: string }[];
  vulns: { id: string; severity: 'CRITIQUE' | 'HAUTE' | 'MOYENNE' | 'BASSE'; pkg: string; desc: string; score: number }[];
  deps: { name: string; version: string; status: 'ok' | 'outdated' | 'vulnerable' }[];
  aiRec: string;
  dockerLayers?: DockerLayer[];
  dockerConfig?: DockerConfig;
  /** ID de l'analyse en base — utilisé pour télécharger le rapport PDF backend */
  analysisId?: number;
  /** TÂCHE 7 : Plan de remédiation (idéalement retourné en JSON par le backend) */
  remediationPlan?: {
    id: string;
    title: string;
    description: string;
    command?: string;
    effort: 'Faible' | 'Moyen' | 'Élevé';
    severity: 'CRITIQUE' | 'HAUTE' | 'MOYENNE' | 'BASSE';
  }[];
  bestPractices?: string[];
}

/* ─────────────────────────────────────────────────────────────────────────────
   Static demo data
──────────────────────────────────────────────────────────────────────────────*/
// Les scans récents sont maintenant chargés depuis le backend (listAnalyses)
// Cette constante n'est utilisée qu'en fallback si le backend est inaccessible.
const RECENT_SCANS_FALLBACK = [
  { target: 'github.com/facebook/react', score: 78, type: 'github' as const, date: 'il y a 2h' },
  { target: 'github.com/expressjs/express', score: 61, type: 'github' as const, date: 'il y a 5h' },
  { target: 'nginx:latest', score: 55, type: 'docker' as const, date: 'hier' },
  { target: 'github.com/lodash/lodash', score: 42, type: 'github' as const, date: 'avant-hier' },
];

const TERMINAL_GITHUB: TermLine[] = [
  { text: '[INFO] Connexion à la cible...', type: 'info' },
  { text: '[INFO] Clonage du dépôt...', type: 'info' },
  { text: '[INFO] Analyse des dépendances...', type: 'info' },
  { text: '[WARN] Vulnérabilité détectée: lodash@4.17.20 (CVE-2020-28500)', type: 'warn' },
  { text: '[INFO] Vérification des configurations cloud...', type: 'info' },
  { text: '[INFO] Calcul du score de sécurité...', type: 'info' },
  { text: '[OK] Rapport prêt.', type: 'ok' },
];

const TERMINAL_DOCKER: TermLine[] = [
  { text: '[INFO] Connexion au registre Docker...', type: 'info' },
  { text: '[INFO] Pull de l\'image...', type: 'info' },
  { text: '[INFO] Extraction des couches (layers)...', type: 'info' },
  { text: '[INFO] Analyse du système de fichiers...', type: 'info' },
  { text: '[WARN] Vulnérabilité détectée: openssl@1.1.1k (CVE-2021-3711)', type: 'warn' },
  { text: '[INFO] Vérification des ports exposés...', type: 'info' },
  { text: '[INFO] Analyse des permissions root...', type: 'info' },
  { text: '[INFO] Calcul du score de sécurité...', type: 'info' },
  { text: '[OK] Rapport prêt.', type: 'ok' },
];

const DOCKER_LAYERS: DockerLayer[] = [
  { hash: 'sha256:a3ed...f8e2', size: '78.3 MB', cmd: 'ADD file:... in /', vulns: 0 },
  { hash: 'sha256:b4cf...a123', size: '45.2 MB', cmd: 'RUN apt-get update && apt-get install -y...', vulns: 2 },
  { hash: 'sha256:c5d0...b456', size: '12.1 MB', cmd: 'COPY ./app /usr/src/app', vulns: 0 },
  { hash: 'sha256:d6e1...c789', size: '1.2 KB', cmd: 'EXPOSE 80 443', vulns: 0 },
  { hash: 'sha256:e7f2...d012', size: '0 B', cmd: 'CMD ["nginx", "-g", "daemon off;"]', vulns: 0 },
];

const DOCKER_CONFIG: DockerConfig = {
  ports: ['80', '443'],
  user: 'root',
  os: 'Debian 11 (bullseye)',
  totalSize: '135.8 MB',
};

const DEMO_RESULT_GITHUB: ScanResult = {
  target: 'github.com/exemple/app',
  type: 'github',
  score: 61,
  status: 'warn',
  stats: [
    { label: 'Vulnérabilités totales', value: '14' },
    { label: 'CVE Critiques', value: '2' },
    { label: 'Dépendances analysées', value: '247' },
    { label: 'Dépendances à risque', value: '8' },
  ],
  vulns: [
    { id: 'CVE-2020-28500', severity: 'HAUTE', pkg: 'lodash@4.17.20', desc: 'Prototype Pollution via merge', score: 7.2 },
    { id: 'CVE-2021-44228', severity: 'CRITIQUE', pkg: 'log4j-core@2.14.1', desc: 'Log4Shell — RCE via JNDI lookup', score: 10.0 },
    { id: 'CVE-2022-42889', severity: 'CRITIQUE', pkg: 'commons-text@1.9', desc: 'Text4Shell — RCE via interpolation', score: 9.8 },
    { id: 'CVE-2021-3749', severity: 'HAUTE', pkg: 'axios@0.21.1', desc: 'ReDoS via long strings', score: 7.5 },
    { id: 'CVE-2022-25878', severity: 'MOYENNE', pkg: 'protobufjs@6.11.2', desc: 'Prototype Pollution', score: 6.5 },
  ],
  deps: [
    { name: 'react', version: '18.2.0', status: 'ok' },
    { name: 'lodash', version: '4.17.20', status: 'vulnerable' },
    { name: 'axios', version: '0.21.1', status: 'vulnerable' },
    { name: 'express', version: '4.17.3', status: 'outdated' },
    { name: 'webpack', version: '5.89.0', status: 'ok' },
  ],
  aiRec: '\u{1F510} Résumé exécutif : Votre dépôt présente de sérieux risques (2 critiques, 1 haute). Une intervention immédiate est requise sur les dépendances exposant à des failles RCE (Remote Code Execution) et Prototype Pollution.\n\nCVE-2021-44228 (Log4j) :\nFaille d\'exécution de code à distance. L\'attaquant peut prendre le contrôle du serveur via une simple requête journalisée.\n\nCVE-2020-28500 (Lodash) :\nPollution de prototype exploitable via `_.merge`. Permet de manipuler la logique métier côté serveur.\n\nRecommandation globale :\nMettez en place un pipeline de CI bloquant les PRs introduisant des CVE critiques.',
  remediationPlan: [
    { id: '1', title: 'Corriger Log4Shell (Priorité Absolue)', description: 'Mettre à jour log4j-core pour combler la faille JNDI.', command: 'npm update log4j-core@2.17.1', effort: 'Faible', severity: 'CRITIQUE' },
    { id: '2', title: 'Patch Prototype Pollution', description: 'Lodash 4.17.20 est vulnérable. Migrer vers 4.17.21+.', command: 'npm install lodash@^4.17.21', effort: 'Faible', severity: 'HAUTE' },
    { id: '3', title: 'Corriger ReDoS Axios', description: 'La version actuelle est sensible aux attaques par déni de service régulier.', command: 'npm install axios@1.x', effort: 'Moyen', severity: 'MOYENNE' }
  ],
  bestPractices: [
    'Activer Dependabot ou Renovate pour des PRs automatiques.',
    'Geler les versions en production avec package-lock.json strict.',
    'Auditer automatiquement en CI avant chaque déploiement.'
  ]
};

const DEMO_RESULT_DOCKER: ScanResult = {
  target: 'nginx:latest',
  type: 'docker',
  score: 55,
  status: 'warn',
  stats: [
    { label: 'Vulnérabilités totales', value: '9' },
    { label: 'CVE Critiques', value: '1' },
    { label: 'Couches analysées', value: '5' },
    { label: 'Paquets à risque', value: '4' },
  ],
  vulns: [
    { id: 'CVE-2021-3711', severity: 'CRITIQUE', pkg: 'openssl@1.1.1k', desc: 'Buffer overflow via SM2 decryption', score: 9.8 },
    { id: 'CVE-2021-3712', severity: 'HAUTE', pkg: 'openssl@1.1.1k', desc: 'Read buffer overrun in X.509', score: 7.4 },
    { id: 'CVE-2022-29155', severity: 'HAUTE', pkg: 'curl@7.74.0', desc: 'HSTS bypass via trailing dot', score: 7.5 },
    { id: 'CVE-2023-44487', severity: 'MOYENNE', pkg: 'nginx@1.25.3', desc: 'HTTP/2 Rapid Reset DoS', score: 5.3 },
  ],
  deps: [
    { name: 'openssl', version: '1.1.1k', status: 'vulnerable' },
    { name: 'curl', version: '7.74.0', status: 'vulnerable' },
    { name: 'nginx', version: '1.25.3', status: 'outdated' },
    { name: 'zlib', version: '1.2.11', status: 'ok' },
    { name: 'pcre2', version: '10.42', status: 'ok' },
  ],
  aiRec: '\u{1F433} Résumé exécutif : L\'image nginx:latest contient 1 vulnérabilité critique liée à OpenSSL. Il est déconseillé d\'utiliser le tag :latest en production.\n\nCVE-2021-3711 (OpenSSL) :\nVulnérabilité de buffer overflow dans le déchiffrement SM2, potentiellement exploitable pour un DoS ou RCE.\n\nRecommandation globale :\nPrivilégiez les images Alpine (nginx:alpine) et utilisez un utilisateur non-root pour limiter l\'impact en cas de compromission.',
  remediationPlan: [
    { id: '1', title: 'Changer l\'image de base', description: 'Migrer de debian:bullseye vers alpine pour réduire la surface d\'attaque et corriger OpenSSL.', command: 'FROM nginx:alpine', effort: 'Moyen', severity: 'CRITIQUE' },
    { id: '2', title: 'Configurer un utilisateur Non-Root', description: 'L\'image tourne en tant que root par défaut. Créer et utiliser un utilisateur restreint.', command: 'USER nginx', effort: 'Moyen', severity: 'HAUTE' },
    { id: '3', title: 'Nettoyer curl', description: 'HSTS bypass présent. Mettre à jour les paquets système si Debian est conservé.', command: 'RUN apt-get update && apt-get upgrade -y', effort: 'Faible', severity: 'MOYENNE' }
  ],
  bestPractices: [
    'Ne jamais utiliser le tag :latest en production.',
    'Construire en multi-stage (Multi-stage builds).',
    'Scanner l\'image avec Trivy dans la pipeline CI.'
  ],
  dockerLayers: DOCKER_LAYERS,
  dockerConfig: DOCKER_CONFIG,
};

/* ─────────────────────────────────────────────────────────────────────────────
   Helpers
──────────────────────────────────────────────────────────────────────────────*/
function detectInputType(val: string): InputType {
  if (!val.trim()) return null;
  if (/^(https?:\/\/)?(www\.)?github\.com\//i.test(val)) return 'github';
  if (/^(https?:\/\/)?docker\.|:[\w.-]+(\/|$)|^\w[\w.-]*\/[\w.-]+(:.+)?$/.test(val) || val.includes(':latest')) return 'docker';
  return 'github';
}

function scoreColor(s: number) {
  if (s >= 80) return '#15803d';
  if (s >= 60) return '#b45309';
  return '#b91c1c';
}

function scoreLabel(s: number) {
  if (s >= 80) return 'Statut OK';
  if (s >= 60) return 'Attention requise';
  return 'Critique';
}

function severityColor(sev: string) {
  switch (sev) {
    case 'CRITIQUE': return '#b91c1c';
    case 'HAUTE': return '#b45309';
    case 'MOYENNE': return '#854d0e';
    default: return '#4b4e5c';
  }
}

/* ── localStorage history ─────────────────────────────────────────────────── */
const HISTORY_KEY = 'nexora-scan-history';

function loadHistory(): (ScanResult & { date: string })[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveToHistory(result: ScanResult) {
  const history = loadHistory();
  const entry = { ...result, date: new Date().toISOString() };
  // prepend, keep max 10
  const updated = [entry, ...history.filter(h => h.target !== result.target)].slice(0, 10);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `il y a ${mins}min`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `il y a ${hours}h`;
  const days = Math.floor(hours / 24);
  if (days === 1) return 'hier';
  return `il y a ${days}j`;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Sub-components
──────────────────────────────────────────────────────────────────────────────*/

function AnimatedCounter({ value, color }: { value: number; color: string }) {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let startTime: number;
    const duration = 2000;
    let animationFrameId: number;

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      setDisplayValue(Math.floor(ease * value));

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(animate);
      }
    };

    animationFrameId = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrameId);
  }, [value]);

  return <span style={{ color }}>{displayValue}</span>;
}

function TerminalLine({ line }: { line: string }) {
  const [displayed, setDisplayed] = useState('');
  const isWarn = line.startsWith('[WARN]');
  const isOk = line.startsWith('[OK]');
  const isCmd = line.startsWith('$');

  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      setDisplayed(line.slice(0, i + 1));
      i++;
      if (i >= line.length) clearInterval(t);
    }, Math.max(10, 300 / line.length)); // Vitesse adaptative
    return () => clearInterval(t);
  }, [line]);

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={isWarn ? { opacity: 1, x: [0, -2, 2, -2, 2, 0] } : { opacity: 1, x: 0 }}
      transition={{ duration: isWarn ? 0.4 : 0.2 }}
      className={`${isWarn ? 'text-[#b45309] font-bold drop-shadow-[0_0_8px_rgba(180,83,9,0.5)]' :
          isOk ? 'text-[#15803d]' :
            isCmd ? 'text-white' : 'text-gray-400'
        }`}
    >
      {displayed}
    </motion.div>
  );
}

/** Dark terminal panel */
function TerminalPanel({ lines, showCursor = false }: { lines: string[]; showCursor?: boolean }) {
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll au fond
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="bg-[#0d0f17] rounded-2xl border border-white/10 overflow-hidden shadow-xl flex flex-col h-[300px]">
      <div className="bg-[#1a1d27] px-4 py-3 flex items-center border-b border-white/5 shrink-0">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c]">nexora — terminal</div>
      </div>
      <div ref={containerRef} className="p-6 font-mono text-sm overflow-y-auto space-y-1.5 flex-1 scrollbar-hide relative">
        {lines.map((line, i) => (
          <TerminalLine key={i} line={line} />
        ))}
        {showCursor && (
          <motion.span
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.8 }}
            className="inline-block w-2.5 h-4 bg-white/70 ml-0.5 align-middle mt-1"
          />
        )}
      </div>
    </div>
  );
}

/** Markdown Typewriter for AI recommendations (Tâche B) */
function MarkdownTypewriter({ text }: { text: string }) {
  const blocks = useMemo(() => text.split('\n\n').filter(b => b.trim() !== ''), [text]);
  const [activeBlock, setActiveBlock] = useState(0);

  return (
    <div className="space-y-4">
      {blocks.map((block, i) => {
        if (i > activeBlock) return null;
        return (
          <TypewriterBlock
            key={i}
            text={block}
            onDone={() => setActiveBlock(a => Math.max(a, i + 1))}
          />
        );
      })}
    </div>
  );
}

function TypewriterBlock({ text, onDone }: { text: string; onDone: () => void }) {
  const [displayed, setDisplayed] = useState('');

  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      setDisplayed(text.slice(0, i + 1));
      i++;
      if (i >= text.length) {
        clearInterval(t);
        if (onDone) onDone();
      }
    }, 8);
    return () => clearInterval(t);
  }, [text, onDone]);

  const isHeader = text.startsWith('#');
  const isList = text.startsWith('-');

  if (isHeader) {
    const level = text.match(/^#+/)?.[0].length || 1;
    const content = displayed.replace(/^#+\s/, '');
    if (level === 1) return <h3 className="text-xl font-bold text-white mb-3 mt-4">{content}</h3>;
    if (level === 2) return <h4 className="text-lg font-bold text-white mb-2 mt-3">{content}</h4>;
    return <h5 className="text-base font-bold text-white mb-1 mt-2">{content}</h5>;
  }

  if (isList) {
    const lines = displayed.split('\n');
    return (
      <ul className="space-y-2 ml-2">
        {lines.map((l, idx) => (
          <li key={idx} className="flex gap-3 text-sm text-[#8a8d9c]">
            <span className="text-[#15803d] shrink-0 mt-0.5">•</span>
            <span>{l.replace(/^-\s/, '')}</span>
          </li>
        ))}
      </ul>
    );
  }

  const renderBold = (str: string) => {
    if (str.length < text.length) return <span>{str}</span>;
    const parts = str.split(/(\*\*.*?\*\*)/g);
    return parts.map((part, i) =>
      part.startsWith('**') && part.endsWith('**')
        ? <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>
        : <span key={i}>{part}</span>
    );
  };

  return <p className="text-sm text-[#8a8d9c] leading-relaxed">{renderBold(displayed)}</p>;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Form state
──────────────────────────────────────────────────────────────────────────────*/
function ScanForm({ onStart, onViewHistory, isSubmitting }: { onStart: (url: string, mode: ScanMode, type: InputType) => void; onViewHistory: (r: ScanResult) => void; isSubmitting: boolean }) {
  const [inputVal, setInputVal] = useState('');
  const [mode, setMode] = useState<ScanMode>('standard');
  const [explicitType, setExplicitType] = useState<InputType>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  const autoType = detectInputType(inputVal);
  const inputType = explicitType || autoType;
  const showMismatchWarning = explicitType && autoType && explicitType !== autoType;

  const placeholder = explicitType === 'docker'
    ? "Ex: nginx:latest"
    : explicitType === 'github'
      ? "Ex: https://github.com/org/repo"
      : "https://github.com/org/repo   ou   nginx:latest";

  const localHistory = loadHistory();

  // Historique chargé depuis le backend
  const [backendHistory, setBackendHistory] = useState<AnalysisSummaryAPI[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [loadingHistoryId, setLoadingHistoryId] = useState<number | string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);

  useEffect(() => {
    listAnalyses(10)
      .then((data) => setBackendHistory(data))
      .catch(() => {
        // Pas de backend disponible — on gardera le fallback local
      })
      .finally(() => setHistoryLoading(false));
  }, []);

  // Construire la liste affichée
  const displayHistory = backendHistory.length > 0
    ? backendHistory.slice(0, 4).map((s) => ({
      target: s.repo_url,
      score: Math.round(s.security_score ?? 0),
      type: (s.target_type === 'docker' ? 'docker' : 'github') as 'github' | 'docker',
      date: timeAgo(s.created_at),
      status: s.status,
      analysisId: s.id,
      fullResult: null as ScanResult | null,
    }))
    : (localHistory.length > 0
      ? localHistory.slice(0, 4).map((s) => ({
        target: s.target,
        score: s.score,
        type: s.type,
        date: timeAgo(s.date!),
        status: 'done' as const,
        analysisId: undefined as number | undefined,
        fullResult: s,
      }))
      : RECENT_SCANS_FALLBACK.map((s) => ({
        ...s,
        status: 'done' as const,
        analysisId: undefined as number | undefined,
        fullResult: null as ScanResult | null,
      }))
    );

  const handleStartSubmit = () => {
    const val = inputVal.trim();
    if (!val) {
      setValidationError("Merci de renseigner une URL de dépôt ou une image Docker.");
      return;
    }
    if (val.length > 300) {
      setValidationError("La cible est trop longue (maximum 300 caractères).");
      return;
    }

    if (inputType === 'github') {
      if (!val.match(/^[a-zA-Z0-9-]+\/[a-zA-Z0-9-_.]+$/) && !val.includes('github.com/')) {
        setValidationError("Format GitHub invalide. Utilisez un format comme 'org/repo' ou une URL complète.");
        return;
      }
    } else if (inputType === 'docker') {
      if (val.includes(' ') || val.includes('https://') || val.includes('github.com')) {
        setValidationError("Format Docker invalide. Évitez les espaces et les URLs.");
        return;
      }
    }

    if (/[<>&;]/.test(val)) {
      setValidationError("Caractères non autorisés détectés.");
      return;
    }

    setValidationError(null);
    onStart(val, mode, inputType);
  };

  const handleHistoryClick = async (s: typeof displayHistory[0]) => {
    // TÂCHE 0 : Bloquer le clic si l'analyse n'est pas terminée
    if (s.status !== 'done') return;

    if (s.fullResult) {
      // Cas du local history
      onViewHistory(s.fullResult);
      return;
    }

    if (s.analysisId) {
      // Cas du backend history : on doit récupérer les détails
      setLoadingHistoryId(s.analysisId);
      setHistoryError(null);
      try {
        const detail = await import('@/lib/api').then(m => m.getAnalysis(s.analysisId!));
        const result = import('@/lib/api').then(m => m.analysisToScanResult(detail));
        onViewHistory(await result);
      } catch (err) {
        // TÂCHE 1 : Sécurité — Ne jamais exposer err.message venant du backend
        console.error("Erreur masquée lors du fetch de l'historique.");
        setHistoryError("Impossible de charger les détails de cette analyse.");
      } finally {
        setLoadingHistoryId(null);
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      {/* Top bar */}
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Lancer une analyse</span>
      </div>

      <div className="max-w-2xl mx-auto px-6 py-20">
        <motion.div
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        >
          <h1 className="font-serif text-4xl md:text-5xl font-bold text-[#12131a] mb-3">
            Lancer une analyse
          </h1>
          <p className="text-[#4b4e5c] text-lg mb-10">
            Entrez une URL GitHub ou le nom d&apos;une image Docker. La détection est automatique.
          </p>

          <div className="bg-white rounded-2xl border border-[#e4e7f0] shadow-sm p-8 mb-8">
            {/* Target Type Selector */}
            <div className="flex bg-[#f7f8fb] p-1.5 rounded-xl mb-6 w-full max-w-sm border border-[#e4e7f0]/50 relative">
              {(['github', 'docker'] as const).map((t) => {
                const isActive = explicitType === t || (!explicitType && autoType === t);
                const isSelected = explicitType === t;
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setExplicitType(isSelected ? null : t)}
                    className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all relative z-10 ${isActive ? 'text-[#12131a]' : 'text-[#8a8d9c] hover:text-[#4b4e5c]'
                      }`}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="type-indicator"
                        className="absolute inset-0 bg-white rounded-lg shadow-sm border border-[#e4e7f0]"
                        initial={false}
                        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                      />
                    )}
                    <span className="relative z-10 flex items-center gap-2">
                      {t === 'github' ? <Box className={`w-4 h-4 ${isActive ? 'text-[#c2410c]' : ''}`} /> : <Layers className={`w-4 h-4 ${isActive ? 'text-[#15803d]' : ''}`} />}
                      {t === 'github' ? 'Dépôt GitHub' : 'Image Docker'}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Input */}
            <label htmlFor="scan-url" className="block text-sm font-semibold text-[#12131a] mb-2">
              Cible à analyser
            </label>
            <div className="relative mb-2">
              <input
                id="scan-url"
                type="text"
                value={inputVal}
                onChange={(e) => {
                  setInputVal(e.target.value);
                  if (validationError) setValidationError(null);
                }}
                placeholder={placeholder}
                className={`w-full px-4 py-3.5 rounded-xl border bg-[#f7f8fb] text-[#12131a] placeholder-[#8a8d9c] font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#c2410c] focus:border-transparent transition-all ${validationError ? 'border-[#b91c1c] bg-[#fee2e2]/30 focus:ring-[#b91c1c]' :
                    showMismatchWarning ? 'border-[#b45309]/40 bg-[#fffbeb]/30 focus:ring-[#b45309]' : 'border-[#e4e7f0]'
                  }`}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    if (!isSubmitting) handleStartSubmit();
                  }
                }}
              />
              <AnimatePresence>
                {inputType && (
                  <motion.span
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono px-2.5 py-1 rounded-full border flex items-center gap-1.5"
                    style={{
                      background: inputType === 'github' ? '#ffedd8' : '#f0fdf4',
                      color: inputType === 'github' ? '#c2410c' : '#15803d',
                      borderColor: inputType === 'github' ? '#c2410c20' : '#15803d20',
                    }}
                  >
                    {inputType === 'github' ? <Box className="w-3 h-3" /> : <Layers className="w-3 h-3" />}
                    {inputType === 'github' ? 'GitHub' : 'Docker'}
                  </motion.span>
                )}
              </AnimatePresence>
            </div>

            <AnimatePresence mode="wait">
              {validationError && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden mb-4"
                >
                  <div className="flex items-center gap-2 text-xs text-[#b91c1c] font-medium px-1">
                    <AlertCircle size={14} />
                    {validationError}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence mode="wait">
              {showMismatchWarning && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden mb-6"
                >
                  <div className="flex items-start gap-2 text-xs text-[#b45309] bg-[#fffbeb] px-3 py-2.5 rounded-lg border border-[#b45309]/20">
                    <AlertCircle size={14} className="shrink-0 mt-0.5" />
                    <p>Le format saisi semble correspondre à {autoType === 'github' ? 'un dépôt GitHub' : 'une image Docker'}, mais vous avez forcé le mode {explicitType === 'github' ? 'GitHub' : 'Docker'}. L'analyse pourrait échouer.</p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Mode selector — GitHub only */}
            <AnimatePresence mode="wait">
              {inputType !== 'docker' && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="mb-6"
                >
                  <div className="text-sm font-semibold text-[#12131a] mb-3">Mode d&apos;analyse</div>
                  <div className="grid grid-cols-2 gap-3">
                    {(['standard', 'deep'] as ScanMode[]).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setMode(m)}
                        className={`p-4 rounded-xl border-2 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#c2410c] focus-visible:ring-offset-2 active:scale-[0.98] ${mode === m
                            ? 'border-[#c2410c] bg-[#fff7ed]'
                            : 'border-[#e4e7f0] hover:border-[#c2410c]/30'
                          }`}
                      >
                        <div className="font-semibold text-[#12131a] text-sm mb-1">
                          {m === 'standard' ? 'Scan Standard' : 'Scan Approfondi'}
                        </div>
                        <div className="text-xs text-[#4b4e5c]">
                          {m === 'standard'
                            ? 'Rapide (~30s). OSV uniquement. Idéal pour CI/CD.'
                            : 'Complet (~2min). OSV + NVD. Audit avant release.'}
                        </div>
                      </button>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence mode="wait">
              {inputType === 'docker' && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="mb-6 flex items-center gap-3 p-3 rounded-xl bg-[#f0fdf4] border border-[#15803d]/20"
                >
                  <Layers className="w-5 h-5 text-[#15803d]" />
                  <span className="text-sm text-[#15803d] font-medium">Analyse d&apos;image Docker — vérification des layers</span>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Submit */}
            <MagneticButton
              className={`w-full py-4 text-base font-bold transition-all ${isSubmitting || validationError ? 'opacity-90 scale-95 pointer-events-none' : ''}`}
              onClick={() => {
                if (!isSubmitting) handleStartSubmit();
              }}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="inline w-5 h-5 mr-2 animate-spin" />
                  Connexion au backend...
                </>
              ) : (
                <>
                  Lancer l&apos;analyse
                  <ArrowRight className="inline w-4 h-4 ml-2" />
                </>
              )}
            </MagneticButton>
          </div>

          {/* Recent scans — from backend or localStorage */}
          <div>
            <div className="text-sm font-semibold text-[#4b4e5c] mb-3 flex items-center gap-2">
              <Clock size={14} />
              Dernières analyses
            </div>
            <div className="space-y-2">
              {historyError && (
                <div className="text-xs text-[#b91c1c] bg-[#fee2e2] px-3 py-2 rounded-lg mb-2 flex items-center gap-2">
                  <AlertCircle size={14} />
                  {historyError}
                </div>
              )}
              {historyLoading ? (
                <div className="flex items-center gap-2 p-4 text-sm text-[#8a8d9c]">
                  <Loader2 size={14} className="animate-spin" />
                  Chargement de l'historique...
                </div>
              ) : (
                displayHistory.map((s) => {
                  const isPending = s.status !== 'done';
                  const isLoadingThis = loadingHistoryId === s.analysisId || loadingHistoryId === s.date;

                  return (
                    <button
                      key={`${s.target}-${s.analysisId ?? s.date}`}
                      type="button"
                      disabled={isPending || isLoadingThis}
                      onClick={() => handleHistoryClick(s)}
                      className={`w-full flex items-center gap-4 p-4 bg-white rounded-xl border transition-all text-left group ${isPending
                          ? 'border-[#e4e7f0]/50 opacity-60 cursor-not-allowed'
                          : 'border-[#e4e7f0] hover:border-[#c2410c] hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#c2410c] active:scale-[0.98]'
                        }`}
                    >
                      <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center" style={{
                        background: s.type === 'github' ? '#ffedd8' : '#f0fdf4',
                      }}>
                        {s.type === 'github' ? <Box className="w-4 h-4 text-[#c2410c]" /> : <Layers className="w-4 h-4 text-[#15803d]" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-mono text-[#12131a] truncate">{s.target}</div>
                        <div className="text-xs text-[#8a8d9c] flex items-center gap-2">
                          {s.date}
                          {s.status === 'running' && <span className="text-[#b45309] font-semibold">En cours...</span>}
                          {s.status === 'failed' && <span className="text-[#b91c1c] font-semibold">Échec</span>}
                          {s.status === 'cancelled' && <span className="text-[#4b4e5c] font-semibold">Annulé</span>}
                        </div>
                      </div>

                      {isLoadingThis ? (
                        <Loader2 size={16} className="text-[#c2410c] animate-spin shrink-0" />
                      ) : (
                        <>
                          <div className="shrink-0 font-bold text-sm" style={{ color: scoreColor(s.score) }}>
                            {s.status === 'done' ? `${s.score}/100` : '—'}
                          </div>
                          {!isPending && <ChevronRight size={14} className="text-[#8a8d9c] group-hover:text-[#c2410c] transition-colors" />}
                        </>
                      )}
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Progress state
──────────────────────────────────────────────────────────────────────────────*/
function ScanProgress({
  target,
  inputType,
  analysisId,
  onDone,
  onError,
}: {
  target: string;
  inputType: InputType;
  analysisId: number;
  onDone: (r: ScanResult) => void;
  onError: (msg: string) => void;
}) {
  const [visibleLines, setVisibleLines] = useState<string[]>([`$ nexora analyze ${target}`]);
  const [elapsed, setElapsed] = useState(0);
  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const startTime = useRef(Date.now());
  const isDocker = inputType === 'docker';
  const [showTimeoutWarning, setShowTimeoutWarning] = useState(false);
  const [timeoutLimit, setTimeoutLimit] = useState(180); // 3 minutes par défaut
  const [isCancelling, setIsCancelling] = useState(false);

  const handleCancel = async () => {
    try {
      setIsCancelling(true);
      await cancelAnalysis(analysisId);
      setVisibleLines(prev => [...prev, '[INFO] Demande d\'annulation envoyée au serveur...']);
    } catch (err) {
      console.error(err);
      onError("Impossible d'annuler. L'analyse est peut-être déjà terminée.");
    }
  };

  const steps = [
    { label: 'Connexion & Extraction', detail: 'Initialisation de l\'environnement' },
    { label: 'Analyse des dépendances', detail: 'Scan des packages et couches' },
    { label: 'Vérification CVE', detail: 'Interrogation NVD & OSV' },
    { label: 'Calcul & Rapport', detail: 'Recommandation et PDF' },
  ];

  // Timer & signe de vie
  useEffect(() => {
    const t = setInterval(() => {
      setElapsed(Math.round((Date.now() - startTime.current) / 1000));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  // Polling backend
  useEffect(() => {
    let lastStatus = '';
    let depsFound = 0;
    let vulnsFound = 0;
    let isExtracting = true;
    let isWaitingForAi = false;

    // Fake life signs (Tâche 5 : terminal jamais figé > 3s)
    const lifeSigns = setInterval(() => {
      if (isExtracting) {
        setVisibleLines(prev => [...prev, isDocker ? '[INFO] Analyse de la prochaine couche système...' : '[INFO] Inspection de l\'arborescence des fichiers...']);
      } else if (isWaitingForAi) {
        setVisibleLines(prev => [...prev, '[INFO] Formulation de la remédiation en cours...']);
      }
    }, 4000);

    const cancel = pollAnalysisStatus(analysisId, {
      onProgress: (progress: AnalysisProgressAPI) => {
        const newLines: string[] = [];

        // Afficher les étapes en fonction du statut
        if (lastStatus !== progress.status) {
          if (progress.status === 'running') {
            setActiveStepIndex(0);
            newLines.push('[INFO] Analyse démarrée sur le serveur...');
            if (isDocker) {
              newLines.push('[INFO] Connexion au registre Docker...');
              newLines.push('[INFO] Extraction et analyse de l\'image...');
            } else {
              newLines.push('[INFO] Clonage du dépôt GitHub...');
            }
          }
          lastStatus = progress.status;
        }

        // Nouveaux dépendances trouvées
        if (progress.total_deps > depsFound) {
          isExtracting = false;
          setActiveStepIndex(1); // Étape 2: Dépendances
          newLines.push(
            `[INFO] ${progress.total_deps} dépendance${progress.total_deps > 1 ? 's' : ''} détectée${progress.total_deps > 1 ? 's' : ''}...`,
          );
          depsFound = progress.total_deps;
        }

        // Nouvelles vulnérabilités
        if (progress.total_vulns > vulnsFound) {
          setActiveStepIndex(2); // Étape 3: Vérification CVE
          const delta = progress.total_vulns - vulnsFound;
          const crit = progress.vulns_by_severity['CRITICAL'] ?? 0;
          newLines.push(
            `[WARN] ${delta} nouvelle${delta > 1 ? 's' : ''} CVE détectée${delta > 1 ? 's' : ''} — dont ${crit} CRITIQUE${crit > 1 ? 'S' : ''}`,
          );
          vulnsFound = progress.total_vulns;
        }

        if (progress.total_recommendations > 0 && !visibleLines.some(l => l.includes('IA'))) {
          setActiveStepIndex(3); // Étape 4: Génération
          isWaitingForAi = true;
          newLines.push('[INFO] Génération des recommandations IA et du plan de remédiation...');
        }

        if (newLines.length > 0) {
          setVisibleLines((prev) => [...prev, ...newLines]);
        }
      },

      onDone: (analysis) => {
        clearInterval(lifeSigns);
        setActiveStepIndex(4); // Fini
        setVisibleLines((prev) => [
          ...prev,
          '[INFO] Calcul du score de sécurité...',
          '[INFO] Génération du rapport PDF...',
          `[OK] Analyse terminée — Score : ${Math.round(analysis.security_score ?? 0)}/100`,
        ]);
        setTimeout(() => {
          onDone(analysisToScanResult(analysis));
        }, 1200);
      },

      onError: (msg) => {
        clearInterval(lifeSigns);
        setVisibleLines((prev) => [...prev, `[ERREUR] ${msg}`]);
        setTimeout(() => onError(msg), 1200);
      },
    });

    return () => {
      cancel();
      clearInterval(lifeSigns);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]);

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Analyse en cours</span>
      </div>

      <div className="max-w-5xl mx-auto px-6 py-16">
        {/* Modal de Timeout UI */}
        {showTimeoutWarning && (
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-[#fffbeb] border border-[#fef3c7] rounded-xl p-6 mb-8 shadow-sm"
          >
            <h3 className="text-[#92400e] font-bold mb-2 flex items-center gap-2">
              <AlertCircle size={18} />
              Ce scan prend plus de temps que prévu
            </h3>
            <p className="text-[#b45309] text-sm mb-4">
              L'analyse est toujours en cours sur nos serveurs (elle peut prendre jusqu'à 5 minutes). Vous pouvez continuer à patienter ou fermer cet écran (l'analyse continuera en arrière-plan et sera disponible dans l'historique).
            </p>
            <div className="flex gap-3">
              <button 
                onClick={() => {
                  setTimeoutLimit(prev => prev + 60);
                  setShowTimeoutWarning(false);
                }}
                className="px-4 py-2 bg-[#d97706] text-white text-sm font-bold rounded-lg hover:bg-[#b45309] transition-colors"
                disabled={isCancelling}
              >
                Continuer à attendre
              </button>
              <button 
                onClick={handleCancel}
                disabled={isCancelling}
                className="px-4 py-2 bg-transparent border border-[#d97706] text-[#d97706] text-sm font-bold rounded-lg hover:bg-[#fef3c7] transition-colors disabled:opacity-50"
              >
                {isCancelling ? 'Annulation en cours...' : 'Masquer et annuler'}
              </button>
            </div>
          </motion.div>
        )}

        <motion.div
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="flex flex-col lg:flex-row gap-8"
        >
          {/* Section de gauche: Stepper & Infos */}
          <div className="w-full lg:w-1/3">
            <h1 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Analyse en cours…</h1>

            <div className="flex items-center gap-2 mb-8 bg-white p-3 rounded-xl border border-[#e4e7f0]">
              <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: isDocker ? '#f0fdf4' : '#ffedd8' }}>
                {isDocker ? <Layers className="w-4 h-4 text-[#15803d]" /> : <Box className="w-4 h-4 text-[#c2410c]" />}
              </div>
              <p className="text-sm font-mono text-[#8a8d9c] truncate" title={target}>{target}</p>
            </div>

            <div className="bg-white rounded-2xl border border-[#e4e7f0] p-6 shadow-sm">
              <div className="flex items-center justify-between mb-6 border-b border-[#e4e7f0] pb-4">
                <span className="text-sm font-bold text-[#12131a]">Temps écoulé</span>
                <span className="text-xl font-mono font-bold text-[#c2410c]">{elapsed}s</span>
              </div>

              <div className="space-y-6">
                {steps.map((step, idx) => {
                  const isActive = idx === activeStepIndex;
                  const isDone = idx < activeStepIndex;
                  return (
                    <div key={idx} className="flex gap-4 relative">
                      {idx !== steps.length - 1 && (
                        <div className="absolute top-6 left-[11px] w-0.5 h-full -z-10 bg-[#e4e7f0]">
                          {(isDone || isActive) && (
                            <motion.div
                              initial={{ height: 0 }}
                              animate={{ height: isDone ? '100%' : '50%' }}
                              transition={{ duration: 0.8 }}
                              className={`w-full ${isDone ? 'bg-[#15803d]' : 'bg-[#c2410c]'}`}
                            />
                          )}
                        </div>
                      )}
                      <div className={`shrink-0 w-6 h-6 rounded-full flex items-center justify-center mt-0.5 transition-colors ${isDone ? 'bg-[#15803d] text-white' : isActive ? 'bg-[#c2410c] text-white animate-pulse' : 'bg-[#f7f8fb] text-[#8a8d9c] border border-[#e4e7f0]'
                        }`}>
                        {isDone ? <span className="text-[10px] font-bold">✓</span> : <span className="text-[10px] font-bold">{idx + 1}</span>}
                      </div>
                      <div>
                        <div className={`text-sm font-bold ${isActive ? 'text-[#12131a]' : isDone ? 'text-[#15803d]' : 'text-[#8a8d9c]'}`}>
                          {step.label}
                        </div>
                        <div className="text-xs text-[#8a8d9c] mt-0.5">{step.detail}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between px-2">
              <div className="flex items-center gap-2 text-xs text-[#8a8d9c]">
                <Wifi className="w-3 h-3 text-[#15803d]" />
                <span>Connecté au serveur</span>
              </div>
              <button 
                onClick={handleCancel}
                disabled={isCancelling}
                className="text-xs font-bold text-[#c2410c] hover:text-[#9a3412] disabled:opacity-50 transition-colors"
              >
                {isCancelling ? 'Annulation en cours...' : 'Annuler l\'analyse'}
              </button>
            </div>
          </div>

          {/* Section de droite: Terminal interactif */}
          <div className="w-full lg:w-2/3">
            <TerminalPanel lines={visibleLines} showCursor />
          </div>
        </motion.div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Results / Dashboard
──────────────────────────────────────────────────────────────────────────────*/
function getTabs(type: 'github' | 'docker') {
  if (type === 'docker') {
    return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'Docker', 'IA & Remédiation', 'Rapport'] as const;
  }
  return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'IA & Remédiation', 'Rapport'] as const;
}

function RemediationTab({ result }: { result: ScanResult }) {
  const [checkedSteps, setCheckedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (id: string) => {
    const next = new Set(checkedSteps);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setCheckedSteps(next);
  };

  return (
    <div className="space-y-8">
      {/* Explication IA Structurée (Tâche 6) */}
      <div className="bg-[#0d0f17] rounded-2xl border border-white/10 overflow-hidden shadow-lg">
        <div className="bg-[#1a1d27] px-4 py-3 flex items-center border-b border-white/5">
          <div className="flex gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/80" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <div className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c] flex items-center justify-center gap-2">
            <Shield size={14} className="text-[#15803d]" /> nexora — moteur ia
          </div>
        </div>
        <div className="p-8">
          <MarkdownTypewriter text={result.aiRec} />
        </div>
      </div>

      {/* Plan de Remédiation Premium (Tâche 7) */}
      <div className="bg-white rounded-2xl border border-[#e4e7f0] shadow-sm overflow-hidden">
        <div className="p-8 border-b border-[#e4e7f0] bg-[#f7f8fb]">
          <h3 className="font-serif text-2xl font-bold text-[#12131a] mb-2">Plan d'Action Stratégique</h3>
          <p className="text-[#4b4e5c] text-sm">Étapes concrètes priorisées pour sécuriser votre {result.type === 'docker' ? 'image' : 'dépôt'}.</p>

          {result.remediationPlan && (
            <div className="mt-6 flex items-center gap-4 bg-white p-4 rounded-xl border border-[#e4e7f0]">
              <div className="flex-1">
                <div className="flex justify-between text-xs font-bold text-[#12131a] mb-2">
                  <span>Progression de la remédiation</span>
                  <span>{checkedSteps.size} / {result.remediationPlan.length} actions</span>
                </div>
                <div className="w-full bg-[#f7f8fb] rounded-full h-2 overflow-hidden">
                  <motion.div
                    className="h-full bg-[#15803d]"
                    initial={{ width: 0 }}
                    animate={{ width: `${(checkedSteps.size / result.remediationPlan.length) * 100}%` }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="p-8">
          {!result.remediationPlan ? (
            <div className="text-center py-10 bg-[#fffbeb] text-[#b45309] rounded-xl border border-[#b45309]/20">
              <AlertCircle className="w-8 h-8 mx-auto mb-3" />
              <p className="font-bold mb-1">Données structurées indisponibles</p>
              <p className="text-sm">Le backend doit être mis à jour pour renvoyer le plan d'action au format JSON.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {result.remediationPlan.map((step, idx) => {
                const isChecked = checkedSteps.has(step.id);
                return (
                  <motion.div
                    key={step.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={`flex items-start gap-4 p-5 rounded-xl border transition-all ${isChecked ? 'bg-[#f7f8fb] border-[#e4e7f0] opacity-60' : 'bg-white border-[#e4e7f0] shadow-sm hover:border-[#12131a]/20'}`}
                  >
                    <button
                      onClick={() => toggleStep(step.id)}
                      className={`mt-1 shrink-0 w-6 h-6 rounded-md border flex items-center justify-center transition-colors ${isChecked ? 'bg-[#15803d] border-[#15803d] text-white' : 'bg-white border-[#8a8d9c] hover:border-[#12131a]'}`}
                    >
                      {isChecked && <motion.svg initial={{ scale: 0 }} animate={{ scale: 1 }} className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></motion.svg>}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <h4 className={`font-bold text-base ${isChecked ? 'text-[#8a8d9c] line-through' : 'text-[#12131a]'}`}>
                          {idx + 1}. {step.title}
                        </h4>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase" style={{ background: `${severityColor(step.severity)}15`, color: severityColor(step.severity) }}>
                          {step.severity}
                        </span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#f7f8fb] text-[#4b4e5c] border border-[#e4e7f0]">
                          ⏱ Effort: {step.effort}
                        </span>
                      </div>
                      <p className={`text-sm mb-3 ${isChecked ? 'text-[#8a8d9c]' : 'text-[#4b4e5c]'}`}>{step.description}</p>
                      {step.command && (
                        <div className="bg-[#12131a] text-[#8a8d9c] font-mono text-xs px-4 py-2.5 rounded-lg flex items-center justify-between group">
                          <span>$ {step.command}</span>
                          <button className="opacity-0 group-hover:opacity-100 transition-opacity text-white hover:text-[#c2410c]" onClick={() => navigator.clipboard.writeText(step.command!)}>Copy</button>
                        </div>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}

          {result.bestPractices && result.bestPractices.length > 0 && (
            <div className="mt-10 pt-8 border-t border-[#e4e7f0]">
              <h4 className="font-bold text-[#12131a] mb-4 flex items-center gap-2">
                <Box className="w-5 h-5 text-[#8a8d9c]" />
                Bonnes pratiques recommandées
              </h4>
              <ul className="space-y-3">
                {result.bestPractices.map((bp, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-[#4b4e5c]">
                    <span className="text-[#15803d] mt-0.5">✓</span>
                    {bp}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanResults({ result, onReset }: { result: ScanResult; onReset: () => void }) {
  const tabs = getTabs(result.type);
  const [activeTab, setActiveTab] = useState<string>(tabs[0]);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const handleDownloadPdf = async () => {
    if (isGeneratingPdf) return;
    setIsGeneratingPdf(true);
    try {
      await generateReport(result);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      {/* Top bar */}
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm font-mono truncate max-w-xs">{result.target}</span>
      </div>

      {/* Summary banner */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="bg-white border-b border-[#e4e7f0] px-6 py-8"
      >
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center gap-6">
          <div className="flex items-baseline gap-3">
            <span
              className="font-mono font-bold leading-none"
              style={{ fontSize: 'clamp(3.5rem, 10vw, 7rem)' }}
            >
              <AnimatedCounter value={result.score} color={scoreColor(result.score)} />
            </span>
            <span className="font-mono text-2xl text-[#8a8d9c]">/100</span>
          </div>

          <div className="flex flex-col gap-3">
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.4, type: "spring" }}
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-bold text-sm border self-start"
              style={{
                background: result.status === 'ok' ? '#dcfce7' : result.status === 'warn' ? '#fef3c7' : '#fee2e2',
                color: scoreColor(result.score),
                borderColor: `${scoreColor(result.score)}33`,
              }}
            >
              <motion.div
                className="w-2 h-2 rounded-full"
                style={{ background: scoreColor(result.score) }}
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ repeat: Infinity, duration: 2.4, ease: 'easeInOut' }}
              />
              {scoreLabel(result.score)}
            </motion.div>
            <p className="text-sm text-[#4b4e5c] font-mono">{result.target}</p>
          </div>

          <div className="md:ml-auto flex items-center gap-3">
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 hover:text-[#12131a] transition-all"
            >
              <RefreshCw size={14} />
              Nouvelle analyse
            </button>
            <button
              type="button"
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 hover:text-[#12131a] transition-all disabled:opacity-50"
            >
              {isGeneratingPdf ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
              {isGeneratingPdf ? 'Génération...' : 'Exporter PDF'}
            </button>
          </div>
        </div>
      </motion.div>

      <div className="bg-white border-b border-[#e4e7f0] px-6">
        <div className="max-w-7xl mx-auto flex gap-0 overflow-x-auto scrollbar-hide">
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-4 text-sm font-medium whitespace-nowrap border-b-2 transition-colors relative ${activeTab === tab
                  ? 'border-[#c2410c] text-[#c2410c]'
                  : 'border-transparent text-[#4b4e5c] hover:text-[#12131a]'
                }`}
            >
              {activeTab === tab && (
                <motion.div
                  layoutId="tab-indicator"
                  className="absolute bottom-[-2px] left-0 right-0 h-[2px] bg-[#c2410c]"
                  transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                />
              )}
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="max-w-7xl mx-auto px-6 py-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 20, filter: 'blur(5px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            exit={{ opacity: 0, y: -10, filter: 'blur(5px)' }}
            transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          >
            {/* Vue d'ensemble */}
            {activeTab === "Vue d'ensemble" && (
              <div className="space-y-8">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {result.stats.map((s, i) => (
                    <motion.div
                      key={s.label}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.1, duration: 0.5 }}
                      className="bg-white rounded-2xl border border-[#e4e7f0] p-6 shadow-sm hover:border-[#c2410c]/30 transition-colors"
                    >
                      <div className="font-serif text-4xl font-bold text-[#12131a] mb-2">{s.value}</div>
                      <div className="text-sm text-[#4b4e5c]">{s.label}</div>
                    </motion.div>
                  ))}
                </div>

                <div className="bg-white rounded-2xl border border-[#e4e7f0] p-8 shadow-sm">
                  <div className="mb-8">
                    <h3 className="font-serif text-2xl font-bold text-[#12131a] mb-2">Matrice des Risques</h3>
                    <p className="text-[#4b4e5c] text-sm">Classification des vulnérabilités selon leur probabilité et leur impact.</p>
                  </div>
                  <RiskMatrix vulns={result.vulns} />
                </div>
              </div>
            )}

            {/* Vulnérabilités */}
            {activeTab === 'Vulnérabilités' && (
              <div className="bg-white rounded-2xl border border-[#e4e7f0] overflow-hidden shadow-sm">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#e4e7f0] bg-[#f7f8fb]">
                      <th className="text-left px-6 py-3 font-semibold text-[#12131a]">CVE ID</th>
                      <th className="text-left px-6 py-3 font-semibold text-[#12131a]">Sévérité</th>
                      <th className="text-left px-6 py-3 font-semibold text-[#12131a]">Paquet</th>
                      <th className="text-left px-6 py-3 font-semibold text-[#12131a] hidden md:table-cell">Description</th>
                      <th className="text-right px-6 py-3 font-semibold text-[#12131a]">Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.vulns.map((v, i) => (
                      <motion.tr
                        key={v.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.08 }}
                        className="border-b border-[#e4e7f0] last:border-0"
                      >
                        <td className="px-6 py-4 font-mono text-[#12131a]">{v.id}</td>
                        <td className="px-6 py-4">
                          <span
                            className="text-xs font-bold px-2 py-0.5 rounded-full"
                            style={{ background: `${severityColor(v.severity)}18`, color: severityColor(v.severity) }}
                          >
                            {v.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-mono text-xs text-[#4b4e5c]">{v.pkg}</td>
                        <td className="px-6 py-4 text-[#4b4e5c] hidden md:table-cell">{v.desc}</td>
                        <td className="px-6 py-4 text-right font-bold font-mono" style={{ color: severityColor(v.severity) }}>
                          {v.score.toFixed(1)}
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Dépendances */}
            {activeTab === 'Dépendances' && (
              <div className="space-y-3">
                {result.deps.map((d, i) => (
                  <motion.div
                    key={d.name}
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.07 }}
                    className="flex items-center gap-4 bg-white rounded-xl border border-[#e4e7f0] px-6 py-4 shadow-sm"
                  >
                    <span className="font-mono font-bold text-[#12131a]">{d.name}</span>
                    <span className="font-mono text-sm text-[#8a8d9c]">@{d.version}</span>
                    <span
                      className="ml-auto text-xs font-bold px-2.5 py-1 rounded-full"
                      style={{
                        background: d.status === 'ok' ? '#dcfce7' : d.status === 'outdated' ? '#fef3c7' : '#fee2e2',
                        color: d.status === 'ok' ? '#15803d' : d.status === 'outdated' ? '#b45309' : '#b91c1c',
                      }}
                    >
                      {d.status === 'ok' ? '✓ À jour' : d.status === 'outdated' ? '⚠ Obsolète' : '✕ Vulnérable'}
                    </span>
                  </motion.div>
                ))}
              </div>
            )}

            {/* Docker (conditionnel) */}
            {activeTab === 'Docker' && result.dockerLayers && result.dockerConfig && (
              <div className="space-y-8">
                {/* Docker config */}
                <div>
                  <h3 className="font-serif text-xl font-bold text-[#12131a] mb-4">Configuration détectée</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { icon: Server, label: 'Ports exposés', value: result.dockerConfig.ports.join(', '), warn: false },
                      { icon: HardDrive, label: 'Utilisateur', value: result.dockerConfig.user, warn: result.dockerConfig.user === 'root' },
                      { icon: Layers, label: 'OS de base', value: result.dockerConfig.os, warn: false },
                      { icon: Box, label: 'Taille totale', value: result.dockerConfig.totalSize, warn: false },
                    ].map((item, idx) => (
                      <motion.div
                        key={item.label}
                        initial={{ opacity: 0, y: 12 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.08 }}
                        className={`bg-white rounded-xl border p-5 ${item.warn ? 'border-[#b45309]/30 bg-[#fffbeb]' : 'border-[#e4e7f0]'}`}
                      >
                        <item.icon className="w-5 h-5 text-[#8a8d9c] mb-3" />
                        <div className="text-xs text-[#8a8d9c] mb-1">{item.label}</div>
                        <div className="font-mono font-bold text-[#12131a] flex items-center gap-1.5">
                          {item.value}
                          {item.warn && <span className="text-xs font-bold text-[#b45309]">⚠</span>}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </div>

                {/* Docker layers */}
                <div>
                  <h3 className="font-serif text-xl font-bold text-[#12131a] mb-4">Couches de l'image</h3>
                  <div className="bg-white rounded-2xl border border-[#e4e7f0] overflow-hidden">
                    {result.dockerLayers.map((layer, idx) => (
                      <motion.div
                        key={layer.hash}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.06 }}
                        className={`flex items-center gap-4 px-6 py-4 ${idx < result.dockerLayers!.length - 1 ? 'border-b border-[#e4e7f0]' : ''}`}
                      >
                        <div className="shrink-0 w-8 h-8 rounded-lg bg-[#f7f8fb] flex items-center justify-center text-xs font-mono text-[#8a8d9c]">
                          {idx + 1}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="font-mono text-xs text-[#8a8d9c] truncate">{layer.hash}</div>
                          <div className="font-mono text-sm text-[#12131a] truncate">{layer.cmd}</div>
                        </div>
                        <div className="shrink-0 text-xs font-mono text-[#4b4e5c]">{layer.size}</div>
                        {layer.vulns > 0 && (
                          <span className="shrink-0 text-xs font-bold px-2 py-0.5 rounded-full bg-[#fee2e2] text-[#b91c1c]">
                            {layer.vulns} CVE
                          </span>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* IA & Remédiation */}
            {activeTab === 'IA & Remédiation' && (
              <RemediationTab result={result} />
            )}

            {activeTab === 'Rapport' && (
              <div className="bg-white rounded-2xl border border-[#e4e7f0] shadow-sm overflow-hidden">
                <div className="p-8 border-b border-[#e4e7f0]">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-serif text-2xl font-bold text-[#12131a]">Rapport d&apos;audit NEXORA</h3>
                    <button
                      type="button"
                      onClick={handleDownloadPdf}
                      disabled={isGeneratingPdf}
                      className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#12131a] text-white rounded-lg text-sm font-semibold hover:bg-[#12131a]/80 transition-colors disabled:opacity-50"
                    >
                      {isGeneratingPdf ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                      Télécharger PDF
                    </button>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-sm">
                    <div><div className="text-[#8a8d9c] mb-1">Cible</div><div className="font-mono text-[#12131a] break-all">{result.target}</div></div>
                    <div><div className="text-[#8a8d9c] mb-1">Score</div><div className="font-bold" style={{ color: scoreColor(result.score) }}>{result.score}/100</div></div>
                    <div><div className="text-[#8a8d9c] mb-1">CVE détectées</div><div className="font-bold text-[#12131a]">{result.vulns.length}</div></div>
                    <div><div className="text-[#8a8d9c] mb-1">Date</div><div className="font-mono text-[#12131a]">{new Date().toLocaleDateString('fr-FR')}</div></div>
                  </div>
                </div>
                <div className="p-8 bg-[#f7f8fb] flex flex-col items-center gap-4">
                  <Download className="w-10 h-10 text-[#8a8d9c]" />
                  <p className="text-[#4b4e5c] text-center">Le rapport PDF complet inclut toutes les vulnérabilités, recommandations et métriques de votre analyse.</p>
                  <div className="flex flex-wrap gap-3 justify-center">
                    {/* PDF généré par le backend (ReportLab) */}
                    {result.analysisId && (
                      <a
                        href={getReportUrl(result.analysisId)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 px-8 py-3 bg-[#c2410c] text-white rounded-full font-semibold hover:bg-[#b45309] transition-colors"
                      >
                        <Download size={18} />
                        Rapport PDF Backend
                      </a>
                    )}
                    {/* PDF généré par le frontend (jsPDF) */}
                    <button
                      type="button"
                      onClick={handleDownloadPdf}
                      disabled={isGeneratingPdf}
                      className="inline-flex items-center gap-2 px-8 py-3 bg-[#12131a] text-white rounded-full font-semibold hover:bg-[#12131a]/80 transition-colors disabled:opacity-50"
                    >
                      {isGeneratingPdf ? <Loader2 size={18} className="animate-spin" /> : <Download size={18} />}
                      {isGeneratingPdf ? 'Génération...' : 'Rapport PDF Frontend'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Root component (state machine)
──────────────────────────────────────────────────────────────────────────────*/
export function ScanPage() {
  const [state, setState] = useState<ScanState>('form');
  const [target, setTarget] = useState('');
  const [inputType, setInputType] = useState<InputType>(null);
  const [scanMode, setScanMode] = useState<ScanMode>('standard');
  const [analysisId, setAnalysisId] = useState<number | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  /**
   * handleStart — appelé quand l'utilisateur clique sur "Lancer l'analyse".
   * 1. Appelle le backend (POST /analyze ou /analyze/docker)
   * 2. Récupère l'ID de l'analyse
   * 3. Passe en mode 'running' pour afficher le terminal de progression réelle
   */
  const handleStart = useCallback(async (url: string, mode: ScanMode, type: InputType) => {
    setIsSubmitting(true);
    setApiError(null);
    setTarget(url);
    setInputType(type);
    setScanMode(mode);

    try {
      let analysis;
      if (type === 'docker') {
        analysis = await startDockerAnalysis(url, mode);
      } else {
        analysis = await startGithubAnalysis(url, mode);
      }
      setAnalysisId(analysis.id);
      setState('running');
    } catch (err) {
      // TÂCHE 1 : Ne pas exposer l'erreur interne
      console.error("Erreur masquée lors du lancement du scan.");
      setApiError("Impossible de contacter le service d'analyse. Réessayez dans quelques instants.");
    } finally {
      setIsSubmitting(false);
    }
  }, []);

  const handleDone = useCallback((r: ScanResult) => {
    setResult(r);
    saveToHistory(r);
    setState('results');
  }, []);

  const handleError = useCallback((msg: string) => {
    setApiError(msg);
    setState('form');
  }, []);

  const handleReset = useCallback(() => {
    setTarget('');
    setInputType(null);
    setResult(null);
    setAnalysisId(null);
    setApiError(null);
    setState('form');
  }, []);

  const handleViewHistory = useCallback((r: ScanResult) => {
    setResult(r);
    setState('results');
  }, []);

  return (
    <>
      {/* Bandeau d'erreur */}
      {apiError && state === 'form' && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="fixed top-0 left-0 right-0 z-40 bg-[#fee2e2] border-b border-[#b91c1c]/20 px-6 py-4 flex items-center gap-3"
        >
          <AlertCircle size={16} className="text-[#b91c1c] shrink-0" />
          <span className="text-sm text-[#b91c1c] font-medium flex-1">{apiError}</span>
          <button
            type="button"
            onClick={() => setApiError(null)}
            className="text-[#b91c1c] hover:text-[#7f1d1d] font-bold text-lg leading-none"
          >
            ×
          </button>
        </motion.div>
      )}

      <AnimatePresence mode="wait">
        {state === 'form' && (
          <motion.div key="form" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <ScanForm onStart={handleStart} onViewHistory={handleViewHistory} isSubmitting={isSubmitting} />
          </motion.div>
        )}
        {state === 'running' && analysisId !== null && (
          <motion.div key="running" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <ScanProgress
              target={target}
              inputType={inputType}
              analysisId={analysisId}
              onDone={handleDone}
              onError={handleError}
            />
          </motion.div>
        )}
        {state === 'results' && result && (
          <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <ScanResults result={result} onReset={handleReset} />
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
