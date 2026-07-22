import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, useInView } from 'framer-motion';

const TERMINAL_LINES = [
  { text: "$ nexora scan --project ./app --deep", type: "cmd",  delay: 0    },
  { text: "[INFO] Initialisation du scan...",              type: "info", delay: 600  },
  { text: "[INFO] Analyse des dépendances: 247 packages",  type: "info", delay: 1200 },
  { text: "[WARN] Vulnérabilité détectée: lodash@4.17.20 (CVE-2020-28500)", type: "warn", delay: 2000 },
  { text: "[INFO] Vérification des configurations cloud...", type: "info", delay: 2800 },
  { text: "[INFO] Patch généré automatiquement.",           type: "info", delay: 3600 },
  { text: "[OK] Rapport généré: rapport_2025.pdf",          type: "ok",   delay: 4200 },
  { text: "[OK] Score de sécurité: 85/100",                 type: "ok",   delay: 4800 },
];

// Total display duration of last line + small pause before restart
const CYCLE_MS = 7000;

export function TerminalAnimated() {
  const ref           = useRef<HTMLDivElement>(null);
  const isInView      = useInView(ref, { margin: '-20%' }); // NOT once: false, amount: 0.1 so we can pause when out of view
  const [visibleLines, setVisibleLines] = useState<number>(0);

  // Hold refs to all pending timeouts so we can cancel on reset / unmount
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const clearAllTimeouts = useCallback(() => {
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];
  }, []);

  const runCycle = useCallback(() => {
    // Reset immediately
    setVisibleLines(0);

    // Schedule each line appearance
    const newTimeouts: ReturnType<typeof setTimeout>[] = [];
    TERMINAL_LINES.forEach((line, index) => {
      const t = setTimeout(() => setVisibleLines(index + 1), line.delay);
      newTimeouts.push(t);
    });

    // Schedule the next cycle restart after CYCLE_MS
    const restartT = setTimeout(() => {
      clearAllTimeouts();
      runCycle();
    }, CYCLE_MS);
    newTimeouts.push(restartT);

    timeoutsRef.current = newTimeouts;
  }, [clearAllTimeouts]);

  useEffect(() => {
    if (!isInView) {
      // Section left viewport — pause by clearing pending timeouts
      clearAllTimeouts();
      return;
    }

    // Section entered viewport — start a fresh cycle
    runCycle();

    return clearAllTimeouts;
  }, [isInView, runCycle, clearAllTimeouts]);

  return (
    <section id="terminal" className="py-24 px-6 relative overflow-hidden" ref={ref}>
      {/* Subtle Halo */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-[radial-gradient(circle_at_center,var(--violet-100),transparent_70%)] opacity-[0.08] pointer-events-none" />

      <div className="max-w-4xl mx-auto">
        {/* Section label */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1, margin: '-100px' }}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <h2 className="font-serif text-4xl md:text-5xl font-bold mb-4 text-[#12131a]">
            Comment ça marche
          </h2>
          <p className="text-xl text-[#4b4e5c] max-w-xl mx-auto font-light">
            Une seule commande. Un rapport complet. Automatiquement.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: false, amount: 0.1, margin: '-100px' }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="bg-[#0d0f17] rounded-2xl shadow-2xl border border-white/10 overflow-hidden relative z-10"
        >
          {/* Terminal Header */}
          <div className="bg-[#1a1d27] px-4 py-3 flex items-center border-b border-white/5">
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500/80" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <div className="w-3 h-3 rounded-full bg-green-500/80" />
            </div>
            <div className="flex-1 text-center text-xs font-mono text-[#8a8d9c]">
              bash — nexora
            </div>
          </div>

          {/* Terminal Body */}
          <div className="p-6 md:p-8 font-mono text-sm md:text-base min-h-[300px]">
            {TERMINAL_LINES.map((line, idx) => (
              <motion.div
                key={`${idx}`}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: visibleLines > idx ? 1 : 0, x: visibleLines > idx ? 0 : -10 }}
                transition={{ duration: 0.25 }}
                className={`mb-2 font-mono ${
                  line.type === 'cmd'  ? 'text-white'      :
                  line.type === 'info' ? 'text-gray-400'   :
                  line.type === 'warn' ? 'text-[#b45309]'  :
                  line.type === 'ok'   ? 'text-[#15803d]'  : 'text-gray-300'
                }`}
                style={{ display: visibleLines > idx ? 'block' : 'none' }}
              >
                {line.text}
              </motion.div>
            ))}

            {/* Blinking Cursor */}
            {visibleLines > 0 && (
              <motion.div
                animate={{ opacity: [1, 0] }}
                transition={{ repeat: Infinity, duration: 0.8 }}
                className="w-2.5 h-5 bg-white/70 inline-block align-middle ml-1 mt-1"
              />
            )}
          </div>
        </motion.div>

        {/* Screen Reader Only */}
        <div className="sr-only" aria-live="off">
          {TERMINAL_LINES.map((l) => l.text).join('\n')}
        </div>
      </div>
    </section>
  );
}
