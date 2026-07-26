/**
 * ScanTimeline — Timeline visuelle des étapes du scan en cours.
 * Étape done = check animé, active = pulse + spinner, pending = cercle gris.
 * Aucun pourcentage fictif. États déduits des données réelles.
 */
import React from "react";
import { motion } from "framer-motion";
import { Check, Loader2 } from "lucide-react";

export type TimelineStepState = "done" | "active" | "pending";

export interface TimelineStep {
  id: string;
  label: string;
  sublabel?: string;
  state: TimelineStepState;
}

function StepIcon({ state }: { state: TimelineStepState }) {
  if (state === "done") {
    return (
      <motion.div
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: "spring", stiffness: 400, damping: 20 }}
        className="w-7 h-7 rounded-full bg-[#15803d] flex items-center justify-center shrink-0"
      >
        <Check className="w-3.5 h-3.5 text-white" strokeWidth={3} />
      </motion.div>
    );
  }
  if (state === "active") {
    return (
      <div className="relative w-7 h-7 shrink-0">
        <motion.div
          className="absolute inset-0 rounded-full bg-[#c2410c]/20"
          animate={{ scale: [1, 1.7], opacity: [0.5, 0] }}
          transition={{ repeat: Infinity, duration: 1.6, ease: "easeOut" }}
        />
        <div className="w-7 h-7 rounded-full bg-[#fff7ed] border-2 border-[#c2410c] flex items-center justify-center">
          <Loader2 className="w-3 h-3 text-[#c2410c] animate-spin" />
        </div>
      </div>
    );
  }
  return (
    <div className="w-7 h-7 rounded-full border-2 border-[#e4e7f0] bg-white shrink-0 flex items-center justify-center">
      <div className="w-2 h-2 rounded-full bg-[#d1d5db]" />
    </div>
  );
}

export function ScanTimeline({ steps }: { steps: TimelineStep[] }) {
  return (
    <div className="bg-white rounded-2xl border border-[#e4e7f0] p-6 shadow-sm">
      <div className="text-xs font-semibold text-[#8a8d9c] uppercase tracking-widest mb-5">
        Pipeline d&apos;analyse
      </div>
      <div className="space-y-0">
        {steps.map((step, idx) => {
          const isLast = idx === steps.length - 1;
          return (
            <div key={step.id} className="flex gap-4">
              <div className="flex flex-col items-center">
                <StepIcon state={step.state} />
                {!isLast && (
                  <div
                    className="w-px flex-1 mt-1 mb-1"
                    style={{
                      background: step.state === "done" ? "#15803d" : "#e4e7f0",
                      minHeight: "28px",
                    }}
                  />
                )}
              </div>
              <motion.div
                className="pb-5 pt-0.5 flex-1"
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.06 }}
              >
                <div
                  className="text-sm font-medium leading-tight"
                  style={{
                    color:
                      step.state === "done"
                        ? "#15803d"
                        : step.state === "active"
                        ? "#c2410c"
                        : "#9ca3af",
                  }}
                >
                  {step.label}
                </div>
                {step.sublabel && step.state === "active" && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-xs text-[#8a8d9c] mt-0.5 font-mono"
                  >
                    {step.sublabel}
                  </motion.div>
                )}
              </motion.div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Calcule les étapes à partir des données de progression réelles. */
export function buildTimelineSteps(opts: {
  isDocker: boolean;
  hasStarted: boolean;
  depsFound: number;
  vulnsFound: number;
  recsFound: number;
  isDone: boolean;
}): TimelineStep[] {
  const { isDocker, hasStarted, depsFound, vulnsFound, recsFound, isDone } = opts;

  const githubDefs: Omit<TimelineStep, "state">[] = [
    { id: "init",   label: "Initialisation" },
    { id: "clone",  label: "Récupération du dépôt",          sublabel: "Clonage GitHub…" },
    { id: "deps",   label: "Détection des dépendances",      sublabel: "requirements.txt, package.json…" },
    { id: "vuln",   label: "Analyse des vulnérabilités",     sublabel: "OSV → GHSA → NVD…" },
    { id: "correl", label: "Corrélation & enrichissement",   sublabel: "Déduplication, EPSS…" },
    { id: "score",  label: "Calcul du Security Score" },
    { id: "recs",   label: "Recommandations IA" },
    { id: "done",   label: "Analyse terminée" },
  ];

  const dockerDefs: Omit<TimelineStep, "state">[] = [
    { id: "init",   label: "Initialisation" },
    { id: "pull",   label: "Récupération de l'image",        sublabel: "Pulling image…" },
    { id: "trivy",  label: "Scan Trivy (OS + libraries)",    sublabel: "Analyse des packages…" },
    { id: "correl", label: "Corrélation des vulnérabilités", sublabel: "CVE enrichissement…" },
    { id: "score",  label: "Calcul du Security Score" },
    { id: "recs",   label: "Recommandations IA" },
    { id: "done",   label: "Analyse terminée" },
  ];

  const defs = isDocker ? dockerDefs : githubDefs;

  let activeIdx = 0;
  if (!hasStarted) {
    activeIdx = 0;
  } else if (isDone) {
    activeIdx = defs.length; // all done
  } else if (recsFound > 0) {
    activeIdx = isDocker ? 5 : 6;
  } else if (vulnsFound > 0) {
    activeIdx = isDocker ? 4 : 5;
  } else if (depsFound > 0) {
    activeIdx = isDocker ? 3 : 4;
  } else {
    activeIdx = isDocker ? 2 : 2;
  }

  return defs.map((step, idx) => ({
    ...step,
    state:
      idx < activeIdx ? "done"
      : idx === activeIdx && activeIdx < defs.length ? "active"
      : "pending",
  }));
}
