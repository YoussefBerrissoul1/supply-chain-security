import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight, Download, RefreshCw, Clock, ChevronRight, Layers, Box, Server, HardDrive, History, Loader2 } from 'lucide-react';
import { MagneticButton } from '@/components/MagneticButton';
import { RiskMatrix } from '@/components/RiskMatrix';
import { generateReport } from '@/lib/pdf/generateReport';

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
  date?: string;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Static demo data
──────────────────────────────────────────────────────────────────────────────*/
const RECENT_SCANS = [
  { target: 'github.com/facebook/react',     score: 78, type: 'github' as const, date: 'il y a 2h' },
  { target: 'github.com/expressjs/express',  score: 61, type: 'github' as const, date: 'il y a 5h' },
  { target: 'nginx:latest',                  score: 55, type: 'docker' as const, date: 'hier' },
  { target: 'github.com/lodash/lodash',      score: 42, type: 'github' as const, date: 'avant-hier' },
];

const TERMINAL_GITHUB: TermLine[] = [
  { text: '[INFO] Connexion à la cible...',           type: 'info' },
  { text: '[INFO] Clonage du dépôt...',               type: 'info' },
  { text: '[INFO] Analyse des dépendances...',        type: 'info' },
  { text: '[WARN] Vulnérabilité détectée: lodash@4.17.20 (CVE-2020-28500)', type: 'warn' },
  { text: '[INFO] Vérification des configurations cloud...', type: 'info' },
  { text: '[INFO] Calcul du score de sécurité...',   type: 'info' },
  { text: '[OK] Rapport prêt.',                       type: 'ok'   },
];

const TERMINAL_DOCKER: TermLine[] = [
  { text: '[INFO] Connexion au registre Docker...',   type: 'info' },
  { text: '[INFO] Pull de l\'image...',               type: 'info' },
  { text: '[INFO] Extraction des couches (layers)...', type: 'info' },
  { text: '[INFO] Analyse du système de fichiers...', type: 'info' },
  { text: '[WARN] Vulnérabilité détectée: openssl@1.1.1k (CVE-2021-3711)', type: 'warn' },
  { text: '[INFO] Vérification des ports exposés...', type: 'info' },
  { text: '[INFO] Analyse des permissions root...',   type: 'info' },
  { text: '[INFO] Calcul du score de sécurité...',   type: 'info' },
  { text: '[OK] Rapport prêt.',                       type: 'ok'   },
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
    { label: 'CVE Critiques',          value: '2'  },
    { label: 'Dépendances analysées',  value: '247'},
    { label: 'Dépendances à risque',   value: '8'  },
  ],
  vulns: [
    { id: 'CVE-2020-28500', severity: 'HAUTE',    pkg: 'lodash@4.17.20',       desc: 'Prototype Pollution via merge',        score: 7.2 },
    { id: 'CVE-2021-44228', severity: 'CRITIQUE', pkg: 'log4j-core@2.14.1',    desc: 'Log4Shell — RCE via JNDI lookup',      score: 10.0 },
    { id: 'CVE-2022-42889', severity: 'CRITIQUE', pkg: 'commons-text@1.9',     desc: 'Text4Shell — RCE via interpolation',   score: 9.8 },
    { id: 'CVE-2021-3749',  severity: 'HAUTE',    pkg: 'axios@0.21.1',          desc: 'ReDoS via long strings',              score: 7.5 },
    { id: 'CVE-2022-25878', severity: 'MOYENNE',  pkg: 'protobufjs@6.11.2',    desc: 'Prototype Pollution',                  score: 6.5 },
  ],
  deps: [
    { name: 'react',    version: '18.2.0', status: 'ok'         },
    { name: 'lodash',   version: '4.17.20', status: 'vulnerable' },
    { name: 'axios',    version: '0.21.1',  status: 'vulnerable' },
    { name: 'express',  version: '4.17.3',  status: 'outdated'   },
    { name: 'webpack',  version: '5.89.0',  status: 'ok'         },
  ],
  aiRec: '\u{1F510} Recommandation prioritaire : Mettez immédiatement à jour lodash vers la version 4.17.21+ pour corriger la vulnérabilité de Prototype Pollution (CVE-2020-28500). Cette faille permet à un attaquant de modifier Object.prototype via _.merge(), _.mergeWith(), _.defaultsDeep() — vecteur d injection de propriétés côté serveur.\n\nPour log4j-core, migrez impérativement vers 2.17.1+. Définissez LOG4J_FORMAT_MSG_NO_LOOKUPS=true comme variable d environnement en attendant la mise à jour. Bloquez les requêtes contenant ${jndi: au niveau de votre WAF.\n\nPour axios, la version 1.x corrige le ReDoS. Vérifiez également vos en-têtes CORS et les timeouts configurés.',
};

const DEMO_RESULT_DOCKER: ScanResult = {
  target: 'nginx:latest',
  type: 'docker',
  score: 55,
  status: 'warn',
  stats: [
    { label: 'Vulnérabilités totales', value: '9'  },
    { label: 'CVE Critiques',          value: '1'  },
    { label: 'Couches analysées',      value: '5'  },
    { label: 'Paquets à risque',       value: '4'  },
  ],
  vulns: [
    { id: 'CVE-2021-3711',  severity: 'CRITIQUE', pkg: 'openssl@1.1.1k',       desc: 'Buffer overflow via SM2 decryption',  score: 9.8 },
    { id: 'CVE-2021-3712',  severity: 'HAUTE',    pkg: 'openssl@1.1.1k',       desc: 'Read buffer overrun in X.509',        score: 7.4 },
    { id: 'CVE-2022-29155', severity: 'HAUTE',    pkg: 'curl@7.74.0',          desc: 'HSTS bypass via trailing dot',         score: 7.5 },
    { id: 'CVE-2023-44487', severity: 'MOYENNE',  pkg: 'nginx@1.25.3',         desc: 'HTTP/2 Rapid Reset DoS',              score: 5.3 },
  ],
  deps: [
    { name: 'openssl',  version: '1.1.1k',  status: 'vulnerable' },
    { name: 'curl',     version: '7.74.0',   status: 'vulnerable' },
    { name: 'nginx',    version: '1.25.3',   status: 'outdated'   },
    { name: 'zlib',     version: '1.2.11',   status: 'ok'         },
    { name: 'pcre2',    version: '10.42',    status: 'ok'         },
  ],
  aiRec: '\u{1F433} Analyse d\'image Docker — nginx:latest\n\nPriorité critique : La version d\'OpenSSL (1.1.1k) embarquée dans l\'image de base Debian contient une vulnérabilité de buffer overflow (CVE-2021-3711) exploitable lors du déchiffrement SM2. Reconstruisez l\'image avec un base layer mis à jour (debian:bookworm-slim) qui inclut OpenSSL 3.x.\n\nSécurité de l\'image : L\'utilisateur root est configuré par défaut. Ajoutez un USER non-root dans votre Dockerfile. Les ports 80 et 443 sont exposés — vérifiez que seuls les ports nécessaires sont ouverts.\n\nRecommandation : Utilisez une image multi-stage build pour réduire la surface d\'attaque. La taille actuelle (135.8 MB) peut être réduite de ~40% avec une image Alpine.',
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
    case 'HAUTE':    return '#b45309';
    case 'MOYENNE':  return '#854d0e';
    default:         return '#4b4e5c';
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

/** Dark terminal panel */
function TerminalPanel({ lines, showCursor = false }: { lines: string[]; showCursor?: boolean }) {
  return (
    <div className="bg-[#0d0f17] rounded-2xl border border-white/10 overflow-hidden shadow-xl">
      <div className="bg-[#1a1d27] px-4 py-3 flex items-center border-b border-white/5">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/80" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
          <div className="w-3 h-3 rounded-full bg-green-500/80" />
        </div>
        <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c]">nexora — terminal</div>
      </div>
      <div className="p-6 font-mono text-sm min-h-[220px] space-y-1.5">
        {lines.map((line, i) => {
          const color =
            line.startsWith('[WARN]') ? 'text-[#b45309]' :
            line.startsWith('[OK]')   ? 'text-[#15803d]' :
            line.startsWith('$')      ? 'text-white'     :
            'text-gray-400';
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.2, delay: i * 0.05 }}
              className={color}
            >
              {line}
            </motion.div>
          );
        })}
        {showCursor && (
          <motion.span
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.8 }}
            className="inline-block w-2.5 h-4 bg-white/70 ml-0.5 align-middle"
          />
        )}
      </div>
    </div>
  );
}

/** Typewriter for AI recommendations */
function Typewriter({ text }: { text: string }) {
  const [displayed, setDisplayed] = useState('');
  const [idx, setIdx]             = useState(0);
  const [paused, setPaused]       = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    if (idx >= text.length || pausedRef.current) return;
    const t = setTimeout(() => setIdx((i) => i + 1), 18);
    return () => clearTimeout(t);
  }, [idx, text]);

  useEffect(() => setDisplayed(text.slice(0, idx)), [idx, text]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setPaused((p) => !p)}
        className="absolute top-0 right-0 text-xs font-mono text-gray-500 hover:text-gray-300 transition-colors"
      >
        {paused ? '▶ Reprendre' : '⏸ Pause'}
      </button>
      <p className="text-sm text-gray-300 font-mono leading-relaxed pr-24 whitespace-pre-line">
        {displayed}
        {!paused && idx < text.length && (
          <span className="inline-block w-2 h-4 bg-[#c2410c] ml-0.5 animate-pulse align-middle" />
        )}
      </p>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Form state
──────────────────────────────────────────────────────────────────────────────*/
function ScanForm({ onStart, onViewHistory }: { onStart: (url: string, mode: ScanMode, type: InputType) => void; onViewHistory: (r: ScanResult) => void }) {
  const [inputVal, setInputVal]   = useState('');
  const [mode, setMode]           = useState<ScanMode>('standard');
  const inputType                 = detectInputType(inputVal);
  const history                   = loadHistory();

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
            {/* Input */}
            <label htmlFor="scan-url" className="block text-sm font-semibold text-[#12131a] mb-2">
              Cible à analyser
            </label>
            <div className="relative mb-6">
              <input
                id="scan-url"
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="https://github.com/org/repo   ou   nginx:latest"
                className="w-full px-4 py-3.5 rounded-xl border border-[#e4e7f0] bg-[#f7f8fb] text-[#12131a] placeholder-[#8a8d9c] font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#c2410c] focus:border-transparent transition-all"
                onKeyDown={(e) => e.key === 'Enter' && inputVal.trim() && onStart(inputVal.trim(), mode, inputType)}
              />
              {inputType && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono px-2.5 py-1 rounded-full border flex items-center gap-1.5" style={{
                  background: inputType === 'github' ? '#ffedd8' : '#f0fdf4',
                  color: inputType === 'github' ? '#c2410c' : '#15803d',
                  borderColor: inputType === 'github' ? '#c2410c20' : '#15803d20',
                }}>
                  {inputType === 'github' ? <Box className="w-3 h-3" /> : <Layers className="w-3 h-3" />}
                  {inputType === 'github' ? 'GitHub' : 'Docker'}
                </span>
              )}
            </div>

            {/* Mode selector — GitHub only */}
            {inputType !== 'docker' && (
              <div className="mb-6">
                <div className="text-sm font-semibold text-[#12131a] mb-3">Mode d&apos;analyse</div>
                <div className="grid grid-cols-2 gap-3">
                  {(['standard', 'deep'] as ScanMode[]).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMode(m)}
                      className={`p-4 rounded-xl border-2 text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#c2410c] focus-visible:ring-offset-2 active:scale-[0.98] ${
                        mode === m
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
              </div>
            )}

            {inputType === 'docker' && (
              <div className="mb-6 flex items-center gap-3 p-3 rounded-xl bg-[#f0fdf4] border border-[#15803d]/20">
                <Layers className="w-5 h-5 text-[#15803d]" />
                <span className="text-sm text-[#15803d] font-medium">Analyse d&apos;image Docker — mode automatique</span>
              </div>
            )}

            {/* Submit */}
            <MagneticButton
              className="w-full py-4 text-base font-bold"
              onClick={() => inputVal.trim() && onStart(inputVal.trim(), mode, inputType)}
            >
              Lancer l&apos;analyse
              <ArrowRight className="inline w-4 h-4 ml-2" />
            </MagneticButton>
          </div>

          {/* Recent scans — from localStorage or demo data */}
          <div>
            <div className="text-sm font-semibold text-[#4b4e5c] mb-3 flex items-center gap-2">
              <Clock size={14} />
              Dernières analyses
            </div>
            <div className="space-y-2">
              {(history.length > 0
                ? history.slice(0, 4).map((s) => ({
                    target: s.target,
                    score: s.score,
                    type: s.type,
                    date: timeAgo(s.date!),
                    fullResult: s,
                  }))
                : RECENT_SCANS.map((s) => ({ ...s, fullResult: null as ScanResult | null }))
              ).map((s) => (
                <button
                  key={s.target}
                  type="button"
                  onClick={() => {
                    if (s.fullResult) {
                      onViewHistory(s.fullResult);
                    } else {
                      setInputVal(s.target);
                    }
                  }}
                  className="w-full flex items-center gap-4 p-4 bg-white rounded-xl border border-[#e4e7f0] hover:border-[#c2410c] hover:shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#c2410c] focus-visible:ring-offset-2 transition-all text-left group active:scale-[0.98]"
                >
                  <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center" style={{
                    background: s.type === 'github' ? '#ffedd8' : '#f0fdf4',
                  }}>
                    {s.type === 'github' ? <Box className="w-4 h-4 text-[#c2410c]" /> : <Layers className="w-4 h-4 text-[#15803d]" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-mono text-[#12131a] truncate">{s.target}</div>
                    <div className="text-xs text-[#8a8d9c]">{s.date}</div>
                  </div>
                  <div className="shrink-0 font-bold text-sm" style={{ color: scoreColor(s.score) }}>
                    {s.score}/100
                  </div>
                  <ChevronRight size={14} className="text-[#8a8d9c] group-hover:text-[#c2410c] transition-colors" />
                </button>
              ))}
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
function ScanProgress({ target, inputType, onDone }: { target: string; inputType: InputType; onDone: (r: ScanResult) => void }) {
  const [visibleLines, setVisibleLines] = useState<string[]>([]);
  const [elapsed, setElapsed]           = useState(0);
  const startTime                       = useRef(Date.now());
  const isDocker                        = inputType === 'docker';
  const termLines                       = isDocker ? TERMINAL_DOCKER : TERMINAL_GITHUB;

  useEffect(() => {
    const t = setInterval(() => {
      setElapsed(Math.round((Date.now() - startTime.current) / 1000));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const timeouts: ReturnType<typeof setTimeout>[] = [];
    termLines.forEach((line, idx) => {
      const t = setTimeout(() => {
        setVisibleLines((prev) => [...prev, line.text]);
      }, 600 + idx * 900);
      timeouts.push(t);
    });

    const done = setTimeout(() => {
      const baseResult = isDocker ? DEMO_RESULT_DOCKER : DEMO_RESULT_GITHUB;
      onDone({ ...baseResult, target, type: isDocker ? 'docker' : 'github' });
    }, 600 + termLines.length * 900 + 500);
    timeouts.push(done);

    return () => timeouts.forEach(clearTimeout);
  }, [target, onDone, isDocker, termLines]);

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Analyse en cours</span>
      </div>

      <div className="max-w-3xl mx-auto px-6 py-16">
        <motion.div 
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }} 
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="font-serif text-3xl font-bold text-[#12131a] mb-1">Analyse en cours…</h1>
              <div className="flex items-center gap-2">
                <div className="shrink-0 w-5 h-5 rounded flex items-center justify-center" style={{
                  background: isDocker ? '#f0fdf4' : '#ffedd8',
                }}>
                  {isDocker ? <Layers className="w-3 h-3 text-[#15803d]" /> : <Box className="w-3 h-3 text-[#c2410c]" />}
                </div>
                <p className="text-sm font-mono text-[#8a8d9c]">{target}</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-mono font-bold text-[#12131a]">{elapsed}s</div>
              <div className="text-xs text-[#8a8d9c]">Temps écoulé</div>
            </div>
          </div>

          <TerminalPanel lines={visibleLines} showCursor />
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
    return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'Docker', 'Recommandations IA', 'Rapport'] as const;
  }
  return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'Recommandations IA', 'Rapport'] as const;
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
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center gap-6">
          <div className="flex items-baseline gap-3">
            <span
              className="font-mono font-bold leading-none"
              style={{ fontSize: 'clamp(3.5rem, 10vw, 7rem)', color: scoreColor(result.score) }}
            >
              {result.score}
            </span>
            <span className="font-mono text-2xl text-[#8a8d9c]">/100</span>
          </div>

          <div className="flex flex-col gap-3">
            <div
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-bold text-sm border"
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
            </div>
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
      </div>

      <div className="bg-white border-b border-[#e4e7f0] px-6">
        <div className="max-w-7xl mx-auto flex gap-0 overflow-x-auto scrollbar-hide">
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-4 text-sm font-medium whitespace-nowrap border-b-2 transition-colors relative ${
                activeTab === tab
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

            {/* Recommandations IA */}
            {activeTab === 'Recommandations IA' && (
              <div className="bg-[#0d0f17] rounded-2xl border border-white/10 overflow-hidden">
                <div className="bg-[#1a1d27] px-4 py-3 flex items-center border-b border-white/5">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                  </div>
                  <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c]">nexora — recommandations IA</div>
                </div>
                <div className="p-6">
                  <Typewriter text={result.aiRec} />
                </div>
              </div>
            )}

            {/* Rapport */}
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
                <div className="p-8 bg-[#f7f8fb] text-center">
                  <Download className="w-10 h-10 text-[#8a8d9c] mx-auto mb-4" />
                  <p className="text-[#4b4e5c] mb-4">Le rapport PDF complet inclut toutes les vulnérabilités, recommandations et métriques de votre analyse.</p>
                  <button
                    type="button"
                    onClick={handleDownloadPdf}
                    disabled={isGeneratingPdf}
                    className="inline-flex items-center gap-2 px-8 py-3 bg-[#c2410c] text-white rounded-full font-semibold hover:bg-[#b45309] transition-colors disabled:opacity-50"
                  >
                    {isGeneratingPdf ? <Loader2 size={18} className="animate-spin" /> : <Download size={18} />}
                    {isGeneratingPdf ? 'Génération en cours...' : 'Générer le rapport complet'}
                  </button>
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
  const [state, setState]       = useState<ScanState>('form');
  const [target, setTarget]     = useState('');
  const [inputType, setInputType] = useState<InputType>(null);
  const [result, setResult]     = useState<ScanResult | null>(null);

  const handleStart = useCallback((url: string, _mode: ScanMode, type: InputType) => {
    setTarget(url);
    setInputType(type);
    setState('running');
  }, []);

  const handleDone = useCallback((r: ScanResult) => {
    setResult(r);
    saveToHistory(r);
    setState('results');
  }, []);

  const handleReset = useCallback(() => {
    setTarget('');
    setInputType(null);
    setResult(null);
    setState('form');
  }, []);

  const handleViewHistory = useCallback((r: ScanResult) => {
    setResult(r);
    setState('results');
  }, []);

  return (
    <AnimatePresence mode="wait">
      {state === 'form' && (
        <motion.div key="form" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <ScanForm onStart={handleStart} onViewHistory={handleViewHistory} />
        </motion.div>
      )}
      {state === 'running' && (
        <motion.div key="running" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <ScanProgress target={target} inputType={inputType} onDone={handleDone} />
        </motion.div>
      )}
      {state === 'results' && result && (
        <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <ScanResults result={result} onReset={handleReset} />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
