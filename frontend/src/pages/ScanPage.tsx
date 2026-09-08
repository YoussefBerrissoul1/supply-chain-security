import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight, Download, RefreshCw, Clock, ChevronRight, Layers, Box, Server, HardDrive, History, Loader2, AlertCircle, Wifi, Shield, Copy, Check as CheckIcon } from 'lucide-react';
import { MagneticButton } from '@/components/MagneticButton';
import { RiskMatrix } from '@/components/RiskMatrix';
import { ScanTimeline, buildTimelineSteps } from '@/components/ScanTimeline';
import { AnimatedScore } from '@/components/AnimatedScore';
import { generateReport } from '@/lib/pdf/generateReport';
import {
  startGithubAnalysis,
  startDockerAnalysis,
  pollAnalysisStatus,
  listAnalyses,
  getAnalysis,
  analysisToScanResult,
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
  scan_type?: string;               // 'standard' | 'deep' — retourné par le backend
  score: number;                    // 0 si scoreIsNull (ne pas afficher)
  scoreIsNull?: boolean;            // true si le score backend est null (FAILED/INCOMPLETE)
  status: 'ok' | 'warn' | 'danger';
  stats: { label: string; value: string }[];
  vulns: {
    id: string;
    severity: 'CRITIQUE' | 'HAUTE' | 'MOYENNE' | 'BASSE';
    pkg: string;
    desc: string;
    score: number;
    fixed_version?: string | null;
    epss_score?: number | null;
    cwe?: string | null;
    exploit_available?: boolean;
    cvss_source?: string;
  }[];
  deps: { name: string; version: string; status: 'ok' | 'outdated' | 'vulnerable' }[];
  aiRec: string;
  dockerLayers?: DockerLayer[];
  dockerConfig?: DockerConfig;
  date?: string;
  analysisId?: number;
  isHistorical?: boolean;
  fromCache?: boolean;
  commit_sha?: string;
  coverage_percent?: number;
  analysisStatus?: string;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Helpers & Storage
──────────────────────────────────────────────────────────────────────────────*/
function detectInputType(val: string): InputType {
  if (!val.trim()) return null;
  if (/^(https?:\/\/)?(www\.)?github\.com\//i.test(val)) return 'github';
  if (/^(https?:\/\/)?docker\.|:[\w.-]+(\/|$)|^\w[\w.-]*\/[\w.-]+(:.+)?$/.test(val) || val.includes(':latest')) return 'docker';
  return 'github';
}

function scoreColor(s: number, scoreIsNull?: boolean) {
  if (scoreIsNull) return '#6b7280'; // gris — score indisponible
  if (s >= 90) return '#15803d';
  if (s >= 70) return '#16a34a';
  if (s >= 50) return '#b45309';
  if (s >= 30) return '#c2410c';
  return '#b91c1c';
}

function scoreLabel(s: number, scoreIsNull?: boolean, analysisStatus?: string) {
  if (scoreIsNull) {
    if (analysisStatus === 'failed') return 'Échec du scan';
    if (analysisStatus === 'incomplete') return 'Analyse incomplète';
    return 'Non applicable';
  }
  if (s >= 90) return 'Excellent';
  if (s >= 70) return 'Bon';
  if (s >= 50) return 'Moyen';
  if (s >= 30) return 'Mauvais';
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
  const updated = [entry, ...history.filter(h => h.target !== result.target)].slice(0, 10);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
}

const ACTIVE_SCAN_KEY = 'nexora-active-scan';
interface ActiveScanState {
  phase: 'running' | 'results';
  analysisId: number;
  target: string;
  inputType: InputType;
  scanMode: ScanMode;
}
function saveActiveScan(s: ActiveScanState) {
  try { sessionStorage.setItem(ACTIVE_SCAN_KEY, JSON.stringify(s)); } catch { }
}
function loadActiveScan(): ActiveScanState | null {
  try {
    const raw = sessionStorage.getItem(ACTIVE_SCAN_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function clearActiveScan() {
  try { sessionStorage.removeItem(ACTIVE_SCAN_KEY); } catch { }
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
const MAX_TERMINAL_LINES = 100;

function TerminalPanel({ lines, showCursor = false }: { lines: string[]; showCursor?: boolean }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll vers le bas à chaque nouvelle ligne
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

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
      {/* Hauteur max fixe + scroll interne — ne grandit JAMAIS la page */}
      <div
        ref={scrollRef}
        className="p-6 font-mono text-sm space-y-1.5 overflow-y-auto"
        style={{ minHeight: '220px', maxHeight: '420px' }}
      >
        {lines.map((line, i) => {
          const color =
            line.startsWith('[WARN]') ? 'text-[#b45309]' :
              line.startsWith('[OK]') ? 'text-[#15803d]' :
                line.startsWith('[ERREUR]') ? 'text-red-400' :
                  line.startsWith('$') ? 'text-white' :
                    'text-gray-400';
          return (
            <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.2 }} className={color}>
              {line}
            </motion.div>
          );
        })}
        {showCursor && (
          <motion.span animate={{ opacity: [1, 0] }} transition={{ repeat: Infinity, duration: 0.8 }} className="inline-block w-2.5 h-4 bg-white/70 ml-0.5 align-middle" />
        )}
      </div>
    </div>
  );
}


function AITerminal({ text, isFinished, onFinish }: { text: string; isFinished: boolean; onFinish: () => void }) {
  const [bootPhase, setBootPhase] = useState(0);
  const [displayedText, setDisplayedText] = useState('');
  const [textIdx, setTextIdx] = useState(0);

  const bootSequence = [
    '> Initialisation de NEXORA AI Engine...',
    '✓ Résultats du scan reçus',
    '✓ Analyse des vulnérabilités...',
    '✓ Corrélation CVE effectuée',
    '✓ Priorisation des risques calculée',
    '✓ Génération de la stratégie de remédiation en cours...',
    '------------------------------------------------------------'
  ];

  useEffect(() => {
    if (isFinished) {
      setBootPhase(bootSequence.length);
      setDisplayedText(text);
      return;
    }

    if (bootPhase < bootSequence.length) {
      const t = setTimeout(() => {
        setBootPhase(b => b + 1);
      }, 700); // Temps entre chaque ligne d'initialisation
      return () => clearTimeout(t);
    } else {
      if (textIdx < text.length) {
        // Animation du texte brut
        const t = setTimeout(() => {
          setIdx((prev) => Math.min(prev + 3, text.length));
        }, 15);
        return () => clearTimeout(t);
      } else {
        onFinish();
      }
    }
  }, [bootPhase, textIdx, isFinished, text, bootSequence.length, onFinish]);

  // Alias the internal state to avoid conflict
  const setIdx = setTextIdx;
  const idx = textIdx;

  useEffect(() => {
    if (bootPhase >= bootSequence.length && !isFinished) {
      setDisplayedText(text.slice(0, idx));
    }
  }, [idx, text, bootPhase, bootSequence.length, isFinished]);

  return (
    <div className="bg-[#050505] rounded-xl border border-[#333] shadow-[0_10px_40px_-10px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col min-h-[600px] w-full">
      {/* Top bar macOS style */}
      <div className="bg-[#1a1a1a] px-5 py-3.5 flex items-center border-b border-[#333] shrink-0">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-[#ff5f56]" />
          <div className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
          <div className="w-3 h-3 rounded-full bg-[#27c93f]" />
        </div>
        <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c] font-semibold tracking-wider">
          NEXORA AI Security Engine
        </div>
        <div className="w-10" /> {/* Spacer to center the title perfectly */}
      </div>

      {/* Terminal content */}
      <div className="p-6 md:p-8 font-mono text-sm md:text-[15px] leading-relaxed overflow-y-auto flex-1 scrollbar-hide text-[#d1d5db]">
        {/* Boot sequence */}
        {bootSequence.slice(0, bootPhase).map((line, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className={`mb-1.5 ${line.startsWith('✓') ? 'text-[#27c93f]' : 'text-[#8a8d9c]'}`}
          >
            {line}
          </motion.div>
        ))}

        {/* Main Text */}
        {bootPhase >= bootSequence.length && (
          <div className="mt-4 whitespace-pre-wrap text-white">
            {displayedText}
            {!isFinished && <span className="inline-block w-2.5 h-4 bg-[#27c93f] ml-1 animate-pulse align-middle" />}
          </div>
        )}

        {/* Boot Cursor */}
        {bootPhase < bootSequence.length && !isFinished && (
          <span className="inline-block w-2.5 h-4 bg-[#27c93f] ml-1 mt-1 animate-pulse align-middle" />
        )}
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Form state
──────────────────────────────────────────────────────────────────────────────*/
function ScanForm({ onStart, onViewHistory, isSubmitting }: { onStart: (url: string, mode: ScanMode, type: InputType) => void; onViewHistory: (r: ScanResult) => void; isSubmitting: boolean }) {
  const [inputVal, setInputVal] = useState('');
  const [mode, setMode] = useState<ScanMode>('standard');
  const inputType = detectInputType(inputVal);
  const localHistory = loadHistory();

  const [backendHistory, setBackendHistory] = useState<AnalysisSummaryAPI[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [loadingHistoryId, setLoadingHistoryId] = useState<number | null>(null);

  useEffect(() => {
    listAnalyses(10)
      .then((data) => setBackendHistory(data))
      .catch(() => { })
      .finally(() => setHistoryLoading(false));
  }, []);

  const displayHistory = backendHistory.length > 0
    ? backendHistory.slice(0, 4).map((s) => ({
      target: s.repo_url,
      score: Math.round(s.security_score ?? 0),
      scoreIsNull: s.security_score === null,
      type: (s.target_type === 'docker' ? 'docker' : 'github') as 'github' | 'docker',
      date: timeAgo(s.created_at),
      status: s.status,
      analysisId: s.id,
      fullResult: null as ScanResult | null,
    }))
    : localHistory.slice(0, 4).map((s) => ({
      target: s.target,
      score: s.score,
      type: s.type,
      date: timeAgo(s.date!),
      status: 'done' as const,
      analysisId: undefined as number | undefined,
      fullResult: s,
    }));

  const handleHistoryClick = async (s: any) => {
    if (s.fullResult) {
      s.fullResult.isHistorical = true;
      onViewHistory(s.fullResult);
      return;
    }
    if (s.analysisId && s.status === 'done') {
      setLoadingHistoryId(s.analysisId);
      try {
        const full = await getAnalysis(s.analysisId);
        const res = analysisToScanResult(full);
        res.isHistorical = true;
        onViewHistory(res);
      } catch (err) {
        console.error("Failed to load full history:", err);
        setInputVal(s.target);
      } finally {
        setLoadingHistoryId(null);
      }
    } else {
      setInputVal(s.target);
    }
  };

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Lancer une analyse</span>
      </div>

      <div className="max-w-2xl mx-auto px-6 py-20">
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
          <h1 className="font-serif text-4xl md:text-5xl font-bold text-[#12131a] mb-3">Lancer une analyse</h1>
          <p className="text-[#4b4e5c] text-lg mb-10">Entrez une URL GitHub ou le nom d'une image Docker. La détection est automatique.</p>

          <div className="bg-white rounded-2xl border border-[#e4e7f0] shadow-sm p-8 mb-8">
            <label htmlFor="scan-url" className="block text-sm font-semibold text-[#12131a] mb-2">Cible à analyser</label>
            <div className="relative mb-6">
              <input
                id="scan-url"
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                disabled={isSubmitting}
                placeholder="https://github.com/org/repo   ou   nginx:latest"
                className="w-full px-4 py-3.5 rounded-xl border border-[#e4e7f0] bg-[#f7f8fb] text-[#12131a] placeholder-[#8a8d9c] font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#c2410c] focus:border-transparent transition-all disabled:opacity-50"
                onKeyDown={(e) => e.key === 'Enter' && inputVal.trim() && !isSubmitting && onStart(inputVal.trim(), mode, inputType)}
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

            {inputType !== 'docker' && (
              <div className="mb-6">
                <div className="text-sm font-semibold text-[#12131a] mb-3">Mode d'analyse</div>
                <div className="grid grid-cols-2 gap-3">
                  {(['standard', 'deep'] as ScanMode[]).map((m) => (
                    <button
                      key={m}
                      type="button"
                      disabled={isSubmitting}
                      onClick={() => setMode(m)}
                      className={`p-4 rounded-xl border-2 text-left transition-all ${mode === m ? 'border-[#c2410c] bg-[#fff7ed]' : 'border-[#e4e7f0] hover:border-[#c2410c]/30'} disabled:opacity-50`}
                    >
                      <div className="font-semibold text-[#12131a] text-sm mb-1">{m === 'standard' ? 'Scan Standard' : 'Scan Approfondi'}</div>
                      <div className="text-xs text-[#4b4e5c]">{m === 'standard' ? 'Rapide (~30s). OSV uniquement.' : 'Complet (~2min). OSV + NVD.'}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <MagneticButton className="w-full py-4 text-base font-bold" onClick={() => inputVal.trim() && !isSubmitting && onStart(inputVal.trim(), mode, inputType)} disabled={isSubmitting}>
              {isSubmitting ? <><Loader2 className="inline w-4 h-4 mr-2 animate-spin" /> Lancement...</> : <>Lancer l'analyse <ArrowRight className="inline w-4 h-4 ml-2" /></>}
            </MagneticButton>
          </div>

          <div>
            <div className="text-sm font-semibold text-[#4b4e5c] mb-3 flex items-center gap-2">
              <Clock size={14} /> Dernières analyses
              {backendHistory.length > 0 && <span className="ml-auto text-xs text-[#15803d] font-mono">● </span>}
            </div>
            <div className="space-y-2">
              {historyLoading ? (
                <div className="flex items-center gap-2 p-4 text-sm text-[#8a8d9c]"><Loader2 size={14} className="animate-spin" /> Chargement...</div>
              ) : displayHistory.length === 0 ? (
                <div className="p-4 text-sm text-[#8a8d9c] italic">Aucune analyse récente.</div>
              ) : (
                displayHistory.map((s) => (
                  <button
                    key={`${s.target}-${s.analysisId ?? s.date}`}
                    type="button"
                    disabled={isSubmitting || loadingHistoryId !== null}
                    onClick={() => handleHistoryClick(s)}
                    className="w-full flex items-center gap-4 p-4 bg-white rounded-xl border border-[#e4e7f0] hover:border-[#c2410c] hover:shadow-sm transition-all text-left group disabled:opacity-50"
                  >
                    <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: s.type === 'github' ? '#ffedd8' : '#f0fdf4' }}>
                      {s.type === 'github' ? <Box className="w-4 h-4 text-[#c2410c]" /> : <Layers className="w-4 h-4 text-[#15803d]" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-mono text-[#12131a] truncate">{s.target}</div>
                      <div className="text-xs text-[#8a8d9c] flex items-center gap-2">
                        {s.date}
                        {s.status === 'running' && <span className="text-[#b45309] font-semibold">En cours...</span>}
                        {s.status === 'failed' && <span className="text-[#b91c1c] font-semibold">Echec</span>}
                        {s.status === 'incomplete' && <span className="text-[#b45309] font-semibold">Incomplet</span>}
                      </div>
                    </div>
                    <div className="shrink-0 font-bold text-sm mr-2" style={{ color: scoreColor(s.score, (s as any).scoreIsNull) }}>
                      {s.status === 'done' || s.status === 'incomplete'
                        ? ((s as any).scoreIsNull ? 'N/A' : `${s.score}/100`)
                        : '—'}
                    </div>
                    {loadingHistoryId === s.analysisId ? (
                      <Loader2 size={14} className="text-[#c2410c] animate-spin" />
                    ) : (
                      <ChevronRight size={14} className="text-[#8a8d9c] group-hover:text-[#c2410c] transition-colors" />
                    )}
                  </button>
                ))
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
function ScanProgress({ target, inputType, analysisId, onDone, onError }: { target: string; inputType: InputType; analysisId: number; onDone: (r: ScanResult) => void; onError: (msg: string) => void }) {
  const [visibleLines, setVisibleLines] = useState<string[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const startTime = useRef(Date.now());
  const isDocker = inputType === 'docker';

  const [hasStarted, setHasStarted] = useState(false);
  const [depsFound, setDepsFound] = useState(0);
  const [vulnsFound, setVulnsFound] = useState(0);
  const [recsFound, setRecsFound] = useState(0);
  const [isDone, setIsDone] = useState(false);

  // Refs pour éviter le problème de stale closure dans le useEffect de polling.
  // L'effet a [analysisId] comme dépendance, donc les valeurs de state
  // capturées dans la closure restent figées à 0 — les refs sont synchrones.
  const depsFoundRef  = useRef(0);
  const vulnsFoundRef = useRef(0);
  const recsFoundRef  = useRef(0);

  const timelineSteps = buildTimelineSteps({ isDocker, hasStarted, depsFound, vulnsFound, recsFound, isDone });

  useEffect(() => {
    const t = setInterval(() => setElapsed(Math.round((Date.now() - startTime.current) / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  // Ref vers la fonction de re-trigger (pour visibilitychange)
  const forcePollRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let lastStatus = '';

    // Expose une fonction de re-trigger accessible par le listener visibilitychange
    let externalTrigger: (() => void) | null = null;

    const cancel = pollAnalysisStatus(analysisId, {
      onProgress: (progress) => {
        const newLines: string[] = [];
        if (lastStatus !== progress.status) {
          if (progress.status === 'running') {
            setHasStarted(true);
            newLines.push('[INFO] Analyse démarrée sur le serveur...');
            newLines.push(isDocker ? '[INFO] Connexion au registre Docker...' : '[INFO] Clonage du dépôt GitHub...');
          }
          lastStatus = progress.status;
        }
        // Utilise les refs (pas le state) pour comparer — évite la stale closure
        if (progress.total_deps > depsFoundRef.current) {
          depsFoundRef.current = progress.total_deps;
          setDepsFound(progress.total_deps);
          newLines.push(`[INFO] ${progress.total_deps} dépendance(s) détectée(s)...`);
        }
        if (progress.total_vulns > vulnsFoundRef.current) {
          const delta = progress.total_vulns - vulnsFoundRef.current;
          const crit = progress.vulns_by_severity['CRITICAL'] ?? 0;
          vulnsFoundRef.current = progress.total_vulns;
          setVulnsFound(progress.total_vulns);
          newLines.push(`[WARN] ${delta} nouvelle(s) CVE détectée(s) — dont ${crit} CRITIQUE(S)`);
        }
        if (progress.total_recommendations > recsFoundRef.current) {
          recsFoundRef.current = progress.total_recommendations;
          setRecsFound(progress.total_recommendations);
          newLines.push('[INFO] Génération des recommandations IA...');
        }
        if (newLines.length > 0) {
          setVisibleLines((prev) => {
            // Dédupliquer : ne pas ajouter si identique à la dernière ligne
            const filtered = newLines.filter((line, idx) => {
              const prevLine = idx === 0 ? prev[prev.length - 1] : newLines[idx - 1];
              return line !== prevLine;
            });
            if (filtered.length === 0) return prev;
            // Limite : garder les MAX_TERMINAL_LINES dernières lignes
            const combined = [...prev, ...filtered];
            return combined.length > MAX_TERMINAL_LINES
              ? combined.slice(combined.length - MAX_TERMINAL_LINES)
              : combined;
          });
        }
      },
      onDone: (analysis) => {
        setIsDone(true);
        const scoreDisp = analysis.security_score !== null ? `${Math.round(analysis.security_score ?? 0)}/100` : 'N/A';
        setVisibleLines((prev) => [...prev, '[INFO] Calcul du score de sécurité...', '[INFO] Génération du rapport PDF...', `[OK] Analyse terminée — Score : ${scoreDisp}`]);
        setTimeout(() => {
          try {
            onDone(analysisToScanResult(analysis));
          } catch (err) {
            console.error("Erreur lors de la conversion des résultats:", err);
            onError("Le scan est terminé mais les résultats n'ont pas pu être chargés.");
          }
        }, 900);
      },
      onError: (msg) => {
        setVisibleLines((prev) => [...prev, `[ERREUR] ${msg}`]);
        setTimeout(() => onError(msg), 1200);
      },
    }, (trigger) => {
      // Le polling expose son re-trigger via ce callback optionnel
      externalTrigger = trigger;
      forcePollRef.current = trigger;
    });

    // Cleanup
    forcePollRef.current = null;
    return () => {
      cancel();
      forcePollRef.current = null;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]);

  // Listener visibilitychange — force un tick immédiat au retour sur l'onglet
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && forcePollRef.current) {
        // L'onglet redevient visible : déclencher un tick immédiat
        // sans attendre la prochaine échéance du setTimeout
        setVisibleLines((prev) => [...prev, '[INFO] Reprise de la synchronisation...']);
        forcePollRef.current();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, []);

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Analyse en cours</span>
      </div>
      <div className="max-w-5xl mx-auto px-6 py-12">
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="font-serif text-3xl font-bold text-[#12131a] mb-1">Analyse en cours…</h1>
              <div className="flex items-center gap-2">
                <div className="shrink-0 w-5 h-5 rounded flex items-center justify-center" style={{ background: isDocker ? '#f0fdf4' : '#ffedd8' }}>
                  {isDocker ? <Layers className="w-3 h-3 text-[#15803d]" /> : <Box className="w-3 h-3 text-[#c2410c]" />}
                </div>
                <p className="text-sm font-mono text-[#8a8d9c] truncate max-w-sm">{target}</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-mono font-bold text-[#12131a]">{elapsed}s</div>
              <div className="text-xs text-[#8a8d9c]">Temps écoulé</div>
            </div>
          </div>

          {/* Layout 2 colonnes : timeline + terminal */}
          <div className="grid grid-cols-1 md:grid-cols-[280px_1fr] gap-6">
            <ScanTimeline steps={timelineSteps} />
            <TerminalPanel lines={visibleLines} showCursor />
          </div>

          <div className="mt-4 flex items-center gap-2 text-xs text-[#8a8d9c]">
            <Wifi className="w-3 h-3" />
            <span>Connexion active — polling toutes les 2,5s</span>
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
  if (type === 'docker') return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'Recommandations IA', 'Rapport'] as const;
  return ["Vue d'ensemble", 'Vulnérabilités', 'Dépendances', 'Recommandations IA', 'Rapport'] as const;
}

function ScanResults({ result, onReset, onRerun }: { result: ScanResult; onReset: () => void; onRerun: (forceRescan: boolean) => void }) {
  const tabs = getTabs(result.type);
  const [activeTab, setActiveTab] = useState<string>(tabs[0]);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [aiAnimationFinished, setAiAnimationFinished] = useState(result.isHistorical === true);
  const [copiedSha, setCopiedSha] = useState(false);

  const stats = result.stats ?? [];
  const vulns = result.vulns ?? [];
  const deps = result.deps ?? [];

  const handleDownloadPdf = async () => {
    if (isGeneratingPdf) return;
    setPdfError(null);
    setIsGeneratingPdf(true);
    try {
      await generateReport(result);
    } catch (err: any) {
      setPdfError(err.message ?? 'Erreur lors de la generation du rapport PDF.');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  const handleCopySha = () => {
    if (!result.commit_sha) return;
    navigator.clipboard.writeText(result.commit_sha).then(() => {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }).catch(() => {});
  };

  const coverageLow = result.coverage_percent !== undefined && result.coverage_percent < 95;

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm font-mono truncate max-w-xs">{result.target}</span>
      </div>

      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }} className="bg-white border-b border-[#e4e7f0] px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center gap-6">
          <div className="flex items-baseline gap-3">
            <AnimatedScore
              value={result.score}
              isNull={result.scoreIsNull}
              className="font-mono font-bold leading-none"
              style={{ fontSize: 'clamp(3.5rem, 10vw, 7rem)', color: scoreColor(result.score, result.scoreIsNull) }}
            />
            {!result.scoreIsNull && <span className="font-mono text-2xl text-[#8a8d9c]">/100</span>}
          </div>
          <div className="flex flex-col gap-3">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-bold text-sm border self-start" style={{ background: result.status === 'ok' ? '#dcfce7' : result.status === 'warn' ? '#fef3c7' : '#fee2e2', color: scoreColor(result.score, result.scoreIsNull), borderColor: `${scoreColor(result.score, result.scoreIsNull)}33` }}>
              <motion.div className="w-2 h-2 rounded-full" style={{ background: scoreColor(result.score, result.scoreIsNull) }} animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 2.4 }} />
              {scoreLabel(result.score, result.scoreIsNull, result.analysisStatus)}
            </div>
            <p className="text-sm text-[#4b4e5c] font-mono truncate max-w-xs">{result.target}</p>
            {/* Commit SHA avec bouton copy */}
            {result.commit_sha && (
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-[#8a8d9c]">SHA:</span>
                <span className="text-xs font-mono text-[#4b4e5c]">{result.commit_sha.slice(0, 10)}&hellip;</span>
                <motion.button
                  type="button"
                  onClick={handleCopySha}
                  whileTap={{ scale: 0.9 }}
                  className="text-[#8a8d9c] hover:text-[#12131a] transition-colors"
                  title="Copier le SHA"
                >
                  <AnimatePresence mode="wait">
                    {copiedSha
                      ? <motion.span key="ok" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}><CheckIcon size={12} className="text-[#15803d]" /></motion.span>
                      : <motion.span key="copy" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}><Copy size={12} /></motion.span>
                    }
                  </AnimatePresence>
                </motion.button>
                {copiedSha && <motion.span initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="text-[10px] text-[#15803d] font-semibold">Copié!</motion.span>}
              </div>
            )}
            {/* Cache badge */}
            {result.fromCache && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className="inline-flex items-center gap-1.5 text-xs text-[#15803d] bg-[#dcfce7] px-2.5 py-1 rounded-full border border-[#15803d]/20"
              >
                <span>⚡</span> Résultat depuis le cache (analyse de moins de 24h)
              </motion.div>
            )}
            {/* Badge mode de scan */}
            {result.scan_type && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-semibold ${
                  result.scan_type === 'deep'
                    ? 'text-[#1e40af] bg-[#dbeafe] border-[#1e40af]/20'
                    : 'text-[#4b4e5c] bg-[#f1f5f9] border-[#4b4e5c]/20'
                }`}
              >
                {result.scan_type === 'deep' ? '🔬 Scan Approfondi' : '⚡ Scan Standard'}
              </motion.div>
            )}
            {/* Coverage warning */}
            {coverageLow && (
              <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="inline-flex items-center gap-1.5 text-xs text-[#b45309] bg-[#fef3c7] px-2.5 py-1 rounded-full border border-[#b45309]/20">
                <span>⚠️</span> Couverture {result.coverage_percent}% — analyse partielle
              </motion.div>
            )}
          </div>
          <div className="md:ml-auto flex items-center gap-3">
            <button type="button" onClick={onReset} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 transition-all"><RefreshCw size={14} /> Nouvelle analyse</button>
            {!result.isHistorical && (
              <button type="button" onClick={() => onRerun(true)} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#c2410c]/40 text-sm text-[#c2410c] hover:bg-[#fff7ed] transition-all" title="Relancer ce scan en ignorant le cache">
                <RefreshCw size={14} /> Relancer le scan
              </button>
            )}
            <button type="button" onClick={handleDownloadPdf} disabled={isGeneratingPdf} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 transition-all disabled:opacity-50">
              {isGeneratingPdf ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} {isGeneratingPdf ? 'Téléchargement...' : 'Rapport PDF'}
            </button>
          </div>
        </div>
      </motion.div>

      <div className="bg-white border-b border-[#e4e7f0] px-6">
        <div className="max-w-7xl mx-auto flex gap-0 overflow-x-auto scrollbar-hide">
          {tabs.map((tab) => (
            <button key={tab} type="button" onClick={() => setActiveTab(tab)} className={`px-5 py-4 text-sm font-medium whitespace-nowrap border-b-2 transition-colors relative ${activeTab === tab ? 'border-[#c2410c] text-[#c2410c]' : 'border-transparent text-[#4b4e5c] hover:text-[#12131a]'}`}>
              {activeTab === tab && <motion.div layoutId="tab-indicator" className="absolute bottom-[-2px] left-0 right-0 h-[2px] bg-[#c2410c]" />}
              {tab}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-10">
        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.3 }}>

            {activeTab === "Vue d'ensemble" && (
              <div className="space-y-8">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {stats.map((s, i) => (
                    <motion.div
                      key={s.label}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.08, duration: 0.4 }}
                      whileHover={{ y: -3, boxShadow: '0 8px 24px -6px rgba(0,0,0,0.10)' }}
                      className="bg-white rounded-2xl border border-[#e4e7f0] p-6 shadow-sm cursor-default transition-shadow"
                    >
                      <div className="font-serif text-4xl font-bold text-[#12131a] mb-2">{s.value}</div>
                      <div className="text-sm text-[#4b4e5c]">{s.label}</div>
                    </motion.div>
                  ))}
                </div>
                <div className="bg-white rounded-2xl border border-[#e4e7f0] p-8 shadow-sm">
                  <div className="mb-8"><h3 className="font-serif text-2xl font-bold text-[#12131a] mb-2">Matrice des Risques</h3></div>
                  <RiskMatrix vulns={vulns} />
                </div>
              </div>
            )}

            {activeTab === 'Vulnérabilités' && (
              <div className="bg-white rounded-2xl border border-[#e4e7f0] overflow-hidden shadow-sm">
                {vulns.length === 0 ? (
                  <div className="px-8 py-12 text-center text-[#8a8d9c]">
                    <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
                    <p className="font-semibold">Aucune vulnérabilité détectée</p>
                  </div>
                ) : (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#e4e7f0] bg-[#f7f8fb]">
                        <th className="text-left px-6 py-3 font-semibold text-[#12131a]">CVE ID</th>
                        <th className="text-left px-6 py-3 font-semibold text-[#12131a]">Sévérité</th>
                        <th className="text-left px-6 py-3 font-semibold text-[#12131a]">Paquet</th>
                        <th className="text-left px-6 py-3 font-semibold text-[#12131a]">Description</th>
                        <th className="text-right px-6 py-3 font-semibold text-[#12131a]">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vulns.map((v, i) => (
                        <motion.tr key={`${v.id}-${i}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }} className="border-b border-[#e4e7f0] last:border-0 hover:bg-[#f7f8fb] transition-colors">
                          <td className="px-6 py-4">
                            <div className="font-mono text-xs text-[#12131a] font-bold">{v.id}</div>
                            {/* CWE + EPSS sous le CVE ID */}
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                              {v.cwe && <span className="text-[10px] font-mono text-[#8a8d9c] bg-[#f7f8fb] border border-[#e4e7f0] px-1.5 py-0.5 rounded">{v.cwe}</span>}
                              {v.epss_score !== null && v.epss_score !== undefined && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded" style={{ background: v.epss_score >= 0.4 ? '#fee2e2' : '#f0fdf4', color: v.epss_score >= 0.4 ? '#b91c1c' : '#15803d' }}>
                                  EPSS {(v.epss_score * 100).toFixed(1)}%
                                </span>
                              )}
                              {v.exploit_available && (
                                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[#fef2f2] text-[#b91c1c] border border-[#fecaca]">⚡ EXPLOIT</span>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4"><span className="text-xs font-bold px-2 py-0.5 rounded-full" style={{ background: `${severityColor(v.severity)}18`, color: severityColor(v.severity) }}>{v.severity}</span></td>
                          <td className="px-6 py-4 font-mono text-xs text-[#4b4e5c] max-w-[140px] truncate">{v.pkg}</td>
                          <td className="px-6 py-4 text-sm text-[#4b4e5c] max-w-[420px] leading-snug line-clamp-3">{v.desc}</td>
                          <td className="px-6 py-4 text-right font-bold font-mono" style={{ color: severityColor(v.severity) }}>{v.score ? v.score.toFixed(1) : 'N/A'}</td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {activeTab === 'Dépendances' && (
              <div className="space-y-2">
                {deps.map((d, i) => (
                  <motion.div
                    key={d.name}
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04, duration: 0.3 }}
                    whileHover={{ x: 4, boxShadow: '0 4px 16px -4px rgba(0,0,0,0.08)' }}
                    className="flex items-center gap-4 bg-white rounded-xl border border-[#e4e7f0] px-6 py-4 shadow-sm cursor-default"
                  >
                    <span className="font-mono font-bold text-[#12131a]">{d.name}</span>
                    <span className="font-mono text-sm text-[#8a8d9c]">@{d.version}</span>
                    <span className="ml-auto text-xs font-bold px-2.5 py-1 rounded-full" style={{ background: d.status === 'ok' ? '#dcfce7' : d.status === 'outdated' ? '#fef3c7' : '#fee2e2', color: d.status === 'ok' ? '#15803d' : d.status === 'outdated' ? '#b45309' : '#b91c1c' }}>
                      {d.status === 'ok' ? '✓ À jour' : d.status === 'outdated' ? '⚠ Obsolète' : '✕ Vulnérable'}
                    </span>
                  </motion.div>
                ))}
              </div>
            )}

            {activeTab === 'Docker' && result.dockerLayers && result.dockerConfig && (
              <div className="space-y-8">
                <div>
                  <h3 className="font-serif text-xl font-bold text-[#12131a] mb-4">Configuration détectée</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { icon: Server, label: 'Ports exposés', value: result.dockerConfig.ports.join(', '), warn: false },
                      { icon: HardDrive, label: 'Utilisateur', value: result.dockerConfig.user, warn: result.dockerConfig.user === 'root' },
                      { icon: Layers, label: 'OS de base', value: result.dockerConfig.os, warn: false },
                      { icon: Box, label: 'Taille totale', value: result.dockerConfig.totalSize, warn: false },
                    ].map((item, idx) => (
                      <div key={item.label} className={`bg-white rounded-xl border p-5 ${item.warn ? 'border-[#b45309]/30 bg-[#fffbeb]' : 'border-[#e4e7f0]'}`}>
                        <item.icon className="w-5 h-5 text-[#8a8d9c] mb-3" />
                        <div className="text-xs text-[#8a8d9c] mb-1">{item.label}</div>
                        <div className="font-mono font-bold text-[#12131a] flex items-center gap-1.5">{item.value} {item.warn && <span className="text-[#b45309]">⚠</span>}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3 className="font-serif text-xl font-bold text-[#12131a] mb-4">Couches de l'image</h3>
                  <div className="bg-white rounded-2xl border border-[#e4e7f0] overflow-hidden">
                    {result.dockerLayers.map((layer, idx) => (
                      <div key={layer.hash} className={`flex items-center gap-4 px-6 py-4 ${idx < result.dockerLayers!.length - 1 ? 'border-b border-[#e4e7f0]' : ''}`}>
                        <div className="shrink-0 w-8 h-8 rounded-lg bg-[#f7f8fb] flex items-center justify-center text-xs font-mono text-[#8a8d9c]">{idx + 1}</div>
                        <div className="flex-1 min-w-0"><div className="font-mono text-xs text-[#8a8d9c] truncate">{layer.hash}</div><div className="font-mono text-sm text-[#12131a] truncate">{layer.cmd}</div></div>
                        <div className="shrink-0 text-xs font-mono text-[#4b4e5c]">{layer.size}</div>
                        {layer.vulns > 0 && <span className="shrink-0 text-xs font-bold px-2 py-0.5 rounded-full bg-[#fee2e2] text-[#b91c1c]">{layer.vulns} CVE</span>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'Recommandations IA' && (
              <div className="mt-4">
                <AITerminal text={result.aiRec} isFinished={aiAnimationFinished} onFinish={() => setAiAnimationFinished(true)} />
              </div>
            )}

            {activeTab === 'Rapport' && (
              <motion.div 
                initial="hidden"
                animate="visible"
                exit="hidden"
                variants={{
                  hidden: { opacity: 0 },
                  visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
                }}
                className="bg-white rounded-2xl border border-[#e4e7f0] shadow-sm overflow-hidden"
              >
                <motion.div variants={{ hidden: { opacity: 0, y: 15 }, visible: { opacity: 1, y: 0 } }} className="p-8 border-b border-[#e4e7f0]">
                  <div className="flex items-center justify-between mb-8">
                    <h3 className="font-serif text-2xl font-bold text-[#12131a]">Rapport d'audit NEXORA</h3>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-sm">
                    <motion.div variants={{ hidden: { opacity: 0, x: -10 }, visible: { opacity: 1, x: 0 } }} className="p-4 rounded-xl hover:bg-[#f7f8fb] transition-colors group">
                      <div className="text-[#8a8d9c] mb-1 group-hover:text-[#4b4e5c] transition-colors">Cible</div>
                      <div className="font-mono text-[#12131a] break-all">{result.target}</div>
                    </motion.div>
                    <motion.div variants={{ hidden: { opacity: 0, x: -10 }, visible: { opacity: 1, x: 0 } }} className="p-4 rounded-xl hover:bg-[#f7f8fb] transition-colors group">
                      <div className="text-[#8a8d9c] mb-1 group-hover:text-[#4b4e5c] transition-colors">Score</div>
                      <div className="font-bold" style={{ color: scoreColor(result.score, result.scoreIsNull) }}>
                        {result.scoreIsNull ? 'N/A' : `${result.score}/100`}
                      </div>
                    </motion.div>
                    <motion.div variants={{ hidden: { opacity: 0, x: -10 }, visible: { opacity: 1, x: 0 } }} className="p-4 rounded-xl hover:bg-[#f7f8fb] transition-colors group">
                      <div className="text-[#8a8d9c] mb-1 group-hover:text-[#4b4e5c] transition-colors">CVE détectées</div>
                      <div className="font-bold text-[#12131a]">{vulns.length}</div>
                    </motion.div>
                    <motion.div variants={{ hidden: { opacity: 0, x: -10 }, visible: { opacity: 1, x: 0 } }} className="p-4 rounded-xl hover:bg-[#f7f8fb] transition-colors group">
                      <div className="text-[#8a8d9c] mb-1 group-hover:text-[#4b4e5c] transition-colors">Date</div>
                      <div className="font-mono text-[#12131a]">{new Date().toLocaleDateString('fr-FR')}</div>
                    </motion.div>
                  </div>
                </motion.div>
                
                <motion.div variants={{ hidden: { opacity: 0, y: 15 }, visible: { opacity: 1, y: 0 } }} className="p-10 bg-[#f7f8fb] flex flex-col items-center gap-6">
                  <motion.div 
                    animate={{ y: [0, -6, 0] }}
                    transition={{ repeat: Infinity, duration: 3.5, ease: "easeInOut" }}
                    className="w-16 h-16 bg-white rounded-full flex items-center justify-center shadow-[0_2px_10px_-3px_rgba(0,0,0,0.1)] border border-[#e4e7f0]"
                  >
                    <Download className="w-8 h-8 text-[#12131a]" />
                  </motion.div>
                  <p className="text-[#4b4e5c] text-center max-w-md">Le rapport PDF complet inclut toutes les vulnérabilités, recommandations et métriques de votre analyse.</p>
                  
                  <div className="flex justify-center mt-2">
                    <motion.button 
                      type="button" 
                      onClick={handleDownloadPdf} 
                      disabled={isGeneratingPdf} 
                      whileHover={{ scale: 1.02, y: -2 }}
                      whileTap={{ scale: 0.98 }}
                      className="inline-flex items-center gap-2 px-8 py-3 bg-[#12131a] text-white rounded-full font-semibold hover:bg-[#12131a]/90 hover:shadow-lg hover:shadow-black/10 transition-all disabled:opacity-50 disabled:pointer-events-none"
                    >
                      {isGeneratingPdf ? <Loader2 size={18} className="animate-spin" /> : <Download size={18} />} 
                      {isGeneratingPdf ? 'Téléchargement...' : 'Télécharger le rapport PDF'}
                    </motion.button>
                  </div>
                  {pdfError && (
                    <motion.p
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="text-sm text-[#b91c1c] bg-[#fee2e2] px-4 py-2 rounded-lg border border-[#b91c1c]/20 max-w-md text-center"
                    >
                      <AlertCircle size={14} className="inline mr-1.5 -mt-0.5" />{pdfError}
                    </motion.p>
                  )}
                </motion.div>
              </motion.div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   Main Page Component
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
  const [isRestoring, setIsRestoring] = useState(true);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.get('new') === 'true') {
      clearActiveScan();
      setIsRestoring(false);
      window.history.replaceState({}, '', '/scan');
      return;
    }

    const active = loadActiveScan();
    if (!active) {
      setIsRestoring(false);
      return;
    }
    setTarget(active.target);
    setInputType(active.inputType);
    setScanMode(active.scanMode);
    setAnalysisId(active.analysisId);

    if (active.phase === 'results') {
      getAnalysis(active.analysisId).then((detail) => {
        const res = analysisToScanResult(detail);
        res.isHistorical = true;
        setResult(res);
        setState('results');
      }).catch(() => {
        clearActiveScan();
        setState('form');
      }).finally(() => setIsRestoring(false));
    } else {
      setState('running');
      setIsRestoring(false);
    }
  }, []);

  const handleStart = async (url: string, mode: ScanMode, type: InputType, forceRescan = false) => {
    setApiError(null);
    setIsSubmitting(true);
    try {
      let analysis;
      if (type === 'docker') {
        analysis = await startDockerAnalysis(url, mode, forceRescan);
      } else {
        analysis = await startGithubAnalysis(url, mode, forceRescan);
      }
      setTarget(url);
      setInputType(type);
      setScanMode(mode);
      setAnalysisId(analysis.id);

      // — Cache hit : le backend retourne une analyse déjà terminée —
      // Pas besoin de polling. On charge le détail immédiatement et on passe
      // directement à l'état 'results', sans jamais afficher ScanProgress.
      if (analysis.status === 'done' || analysis.status === 'incomplete') {
        const detail = await getAnalysis(analysis.id);
        const res = analysisToScanResult(detail);
        res.fromCache = true;
        saveActiveScan({ phase: 'results', analysisId: analysis.id, target: url, inputType: type, scanMode: mode });
        saveToHistory(res);
        setResult(res);
        setState('results');
        return;
      }

      // Scan normal : passe par ScanProgress (polling)
      saveActiveScan({ phase: 'running', analysisId: analysis.id, target: url, inputType: type, scanMode: mode });
      setState('running');
    } catch (err: any) {
      console.error(err);
      if (err.message && err.message.includes('429')) {
        setApiError("Limite de requêtes atteinte (Rate limit Github ou NVD). Veuillez patienter quelques instants.");
      } else {
        setApiError("Impossible de démarrer l'analyse. Vérifiez l'URL ou le tag Docker.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDone = useCallback((r: ScanResult) => {
    setResult(r);
    saveToHistory(r);
    if (r.analysisId) saveActiveScan({ phase: 'results', analysisId: r.analysisId, target: r.target, inputType: r.type, scanMode: 'standard' });
    else clearActiveScan();
    setState('results');
  }, []);

  const handleError = useCallback((msg: string) => {
    setApiError(msg);
    clearActiveScan();
    setState('form');
  }, []);

  const handleReset = useCallback(() => {
    setResult(null);
    setTarget('');
    setInputType(null);
    setAnalysisId(null);
    setApiError(null);
    clearActiveScan();
    setState('form');
  }, []);

  const handleViewHistory = useCallback((r: ScanResult) => {
    // If not explicitly set, we assume it's historical when viewed via handleViewHistory
    if (r.isHistorical === undefined) r.isHistorical = true;
    setResult(r);
    if (r.analysisId) saveActiveScan({ phase: 'results', analysisId: r.analysisId, target: r.target, inputType: r.type, scanMode: 'standard' });
    setState('results');
  }, []);

  // Relancer le même scan avec forceRescan=true (ignore le cache 24h)
  const handleRerun = useCallback((forceRescan: boolean) => {
    if (!result) return;
    handleStart(result.target, (result.scan_type as ScanMode) ?? scanMode, result.type, forceRescan);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result, scanMode]);

  if (isRestoring) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#f7f8fb]">
        <Loader2 className="w-10 h-10 text-[#c2410c] animate-spin" />
      </div>
    );
  }

  return (
    <>
      {apiError && (
        <div className="fixed top-0 left-0 right-0 z-50 bg-[#fee2e2] border-b border-[#b91c1c]/20 px-6 py-4 flex items-center justify-center gap-3">
          <AlertCircle size={16} className="text-[#b91c1c] shrink-0" />
          <span className="text-sm text-[#b91c1c] font-medium">{apiError}</span>
          <button type="button" onClick={() => setApiError(null)} className="ml-4 text-[#b91c1c] hover:text-[#7f1d1d] font-bold text-lg leading-none">×</button>
        </div>
      )}

      {/* FIX PAGE BLANCHE : PAS de AnimatePresence avec mode="wait" à la racine. Transition immédiate. */}
      {state === 'form' && (
        <motion.div key="form" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <ScanForm onStart={handleStart} onViewHistory={handleViewHistory} isSubmitting={isSubmitting} />
        </motion.div>
      )}

      {state === 'running' && analysisId === null && (
        <motion.div key="running-fallback" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex min-h-screen items-center justify-center bg-[#f7f8fb]">
          <Loader2 className="w-10 h-10 text-[#c2410c] animate-spin" />
        </motion.div>
      )}

      {state === 'running' && analysisId !== null && inputType !== null && (
        <motion.div key="running" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <ScanProgress target={target} inputType={inputType} analysisId={analysisId} onDone={handleDone} onError={handleError} />
        </motion.div>
      )}

      {state === 'results' && !result && (
        <motion.div key="results-fallback" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex min-h-screen items-center justify-center bg-[#f7f8fb]">
          <Loader2 className="w-10 h-10 text-[#15803d] animate-spin" />
        </motion.div>
      )}

      {state === 'results' && result && (
        <motion.div key={`results-${result.analysisId ?? 'new'}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <ScanResults result={result} onReset={handleReset} onRerun={handleRerun} />
        </motion.div>
      )}
    </>
  );
}
