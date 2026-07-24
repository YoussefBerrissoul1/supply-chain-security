import React, { useState, useEffect, useRef, useCallback } from 'react';
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
  getAnalysis,
  analysisToScanResult,
  getReportUrl,
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
  date?: string;
  analysisId?: number;
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
              line.startsWith('[OK]') ? 'text-[#15803d]' :
                line.startsWith('$') ? 'text-white' :
                  'text-gray-400';
          return (
            <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.2, delay: i * 0.05 }} className={color}>
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
          // On avance plus vite pour les gros blocs
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
                    disabled={isSubmitting}
                    onClick={() => {
                      if (s.fullResult) onViewHistory(s.fullResult);
                      else setInputVal(s.target);
                    }}
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
                      </div>
                    </div>
                    <div className="shrink-0 font-bold text-sm" style={{ color: scoreColor(s.score) }}>{s.status === 'done' ? `${s.score}/100` : '—'}</div>
                    <ChevronRight size={14} className="text-[#8a8d9c] group-hover:text-[#c2410c] transition-colors" />
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

  useEffect(() => {
    const t = setInterval(() => setElapsed(Math.round((Date.now() - startTime.current) / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let lastStatus = '';
    let depsFound = 0;
    let vulnsFound = 0;

    const cancel = pollAnalysisStatus(analysisId, {
      onProgress: (progress) => {
        const newLines: string[] = [];
        if (lastStatus !== progress.status) {
          if (progress.status === 'running') {
            newLines.push('[INFO] Analyse démarrée sur le serveur...');
            newLines.push(isDocker ? '[INFO] Connexion au registre Docker...' : '[INFO] Clonage du dépôt GitHub...');
          }
          lastStatus = progress.status;
        }
        if (progress.total_deps > depsFound) {
          newLines.push(`[INFO] ${progress.total_deps} dépendance(s) détectée(s)...`);
          depsFound = progress.total_deps;
        }
        if (progress.total_vulns > vulnsFound) {
          const delta = progress.total_vulns - vulnsFound;
          const crit = progress.vulns_by_severity['CRITICAL'] ?? 0;
          newLines.push(`[WARN] ${delta} nouvelle(s) CVE détectée(s) — dont ${crit} CRITIQUE(S)`);
          vulnsFound = progress.total_vulns;
        }
        if (progress.total_recommendations > 0 && !visibleLines.some(l => l.includes('IA'))) {
          newLines.push('[INFO] Génération des recommandations IA...');
        }
        if (newLines.length > 0) setVisibleLines((prev) => [...prev, ...newLines]);
      },
      onDone: (analysis) => {
        setVisibleLines((prev) => [...prev, '[INFO] Calcul du score de sécurité...', '[INFO] Génération du rapport PDF...', `[OK] Analyse terminée — Score : ${Math.round(analysis.security_score ?? 0)}/100`]);
        setTimeout(() => {
          try {
            onDone(analysisToScanResult(analysis));
          } catch (err) {
            console.error("Erreur lors de la conversion des résultats:", err);
            onError("Le scan est terminé mais les résultats n'ont pas pu être chargés.");
          }
        }, 800);
      },
      onError: (msg) => {
        setVisibleLines((prev) => [...prev, `[ERREUR] ${msg}`]);
        setTimeout(() => onError(msg), 1200);
      },
    });
    return () => cancel();
  }, [analysisId, isDocker, onDone, onError]);

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm">Analyse en cours</span>
      </div>
      <div className="max-w-3xl mx-auto px-6 py-16">
        <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="font-serif text-3xl font-bold text-[#12131a] mb-1">Analyse en cours…</h1>
              <div className="flex items-center gap-2">
                <div className="shrink-0 w-5 h-5 rounded flex items-center justify-center" style={{ background: isDocker ? '#f0fdf4' : '#ffedd8' }}>
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
          <div className="mt-4 flex items-center gap-2 text-xs text-[#8a8d9c]">
            <Wifi className="w-3 h-3" />
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

function ScanResults({ result, onReset }: { result: ScanResult; onReset: () => void }) {
  const tabs = getTabs(result.type);
  const [activeTab, setActiveTab] = useState<string>(tabs[0]);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [aiAnimationFinished, setAiAnimationFinished] = useState(false);

  const stats = result.stats ?? [];
  const vulns = result.vulns ?? [];
  const deps = result.deps ?? [];

  const handleDownloadPdf = async () => {
    if (isGeneratingPdf) return;
    setIsGeneratingPdf(true);
    try { await generateReport(result); } finally { setIsGeneratingPdf(false); }
  };

  return (
    <div className="min-h-screen bg-[#f7f8fb] font-sans">
      <div className="bg-white border-b border-[#e4e7f0] px-6 py-4 flex items-center gap-4">
        <a href="/" className="font-serif text-xl font-bold text-[#12131a]">NEXORA</a>
        <span className="text-[#e4e7f0]">/</span>
        <span className="text-[#4b4e5c] text-sm font-mono truncate max-w-xs">{result.target}</span>
      </div>

      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="bg-white border-b border-[#e4e7f0] px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center gap-6">
          <div className="flex items-baseline gap-3">
            <span className="font-mono font-bold leading-none" style={{ fontSize: 'clamp(3.5rem, 10vw, 7rem)', color: scoreColor(result.score) }}>{result.score}</span>
            <span className="font-mono text-2xl text-[#8a8d9c]">/100</span>
          </div>
          <div className="flex flex-col gap-3">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-bold text-sm border self-start" style={{ background: result.status === 'ok' ? '#dcfce7' : result.status === 'warn' ? '#fef3c7' : '#fee2e2', color: scoreColor(result.score), borderColor: `${scoreColor(result.score)}33` }}>
              <motion.div className="w-2 h-2 rounded-full" style={{ background: scoreColor(result.score) }} animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 2.4 }} />
              {scoreLabel(result.score)}
            </div>
            <p className="text-sm text-[#4b4e5c] font-mono">{result.target}</p>
          </div>
          <div className="md:ml-auto flex items-center gap-3">
            <button type="button" onClick={onReset} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 transition-all"><RefreshCw size={14} /> Nouvelle analyse</button>
            <button type="button" onClick={handleDownloadPdf} disabled={isGeneratingPdf} className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#e4e7f0] text-sm text-[#4b4e5c] hover:border-[#12131a]/30 transition-all disabled:opacity-50">
              {isGeneratingPdf ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} {isGeneratingPdf ? 'Génération...' : 'Exporter PDF'}
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
                    <motion.div key={s.label} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.1 }} className="bg-white rounded-2xl border border-[#e4e7f0] p-6 shadow-sm">
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
                    {vulns.map((v, i) => (
                      <motion.tr key={v.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="border-b border-[#e4e7f0] last:border-0">
                        <td className="px-6 py-4 font-mono text-[#12131a]">{v.id}</td>
                        <td className="px-6 py-4"><span className="text-xs font-bold px-2 py-0.5 rounded-full" style={{ background: `${severityColor(v.severity)}18`, color: severityColor(v.severity) }}>{v.severity}</span></td>
                        <td className="px-6 py-4 font-mono text-xs text-[#4b4e5c]">{v.pkg}</td>
                        <td className="px-6 py-4 text-[#4b4e5c] hidden md:table-cell">{v.desc}</td>
                        <td className="px-6 py-4 text-right font-bold font-mono" style={{ color: severityColor(v.severity) }}>{v.score ? v.score.toFixed(1) : 'N/A'}</td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {activeTab === 'Dépendances' && (
              <div className="space-y-3">
                {deps.map((d, i) => (
                  <motion.div key={d.name} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }} className="flex items-center gap-4 bg-white rounded-xl border border-[#e4e7f0] px-6 py-4 shadow-sm">
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
                      <div className="font-bold" style={{ color: scoreColor(result.score) }}>{result.score}/100</div>
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
                      {isGeneratingPdf ? 'Génération...' : 'Exporter le rapport'}
                    </motion.button>
                  </div>
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
        setResult(analysisToScanResult(detail));
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

  const handleStart = async (url: string, mode: ScanMode, type: InputType) => {
    setApiError(null);
    setIsSubmitting(true);
    try {
      let analysis;
      if (type === 'docker') {
        analysis = await startDockerAnalysis(url);
      } else {
        analysis = await startGithubAnalysis(url, mode);
      }
      setTarget(url);
      setInputType(type);
      setScanMode(mode);
      setAnalysisId(analysis.id);
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
    setResult(r);
    if (r.analysisId) saveActiveScan({ phase: 'results', analysisId: r.analysisId, target: r.target, inputType: r.type, scanMode: 'standard' });
    setState('results');
  }, []);

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
        <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <ScanResults result={result} onReset={handleReset} />
        </motion.div>
      )}
    </>
  );
}
