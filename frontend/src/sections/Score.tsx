import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence, useInView, useReducedMotion } from 'framer-motion';

/* ------------------------------------------------------------------ */
/*  Easing & timing helpers                                            */
/* ------------------------------------------------------------------ */

// easeOutQuad: ralentissement plus doux que le cubic,
// laissant le temps aux premières couleurs (rouge/orange) d'être visibles.
const easeOutQuad = (t: number): number => 1 - (1 - t) * (1 - t);

const ANIMATION_DURATION_MS = 3500;

/* ------------------------------------------------------------------ */
/*  Color gradient                                                     */
/* ------------------------------------------------------------------ */

const COLOR_STOPS: { stop: number; rgb: [number, number, number] }[] = [
  { stop: 0,   rgb: [185, 28, 28] },   // #B91C1C dark red
  { stop: 20,  rgb: [220, 38, 38] },   // #DC2626 red
  { stop: 40,  rgb: [234, 88, 12] },   // #EA580C orange
  { stop: 60,  rgb: [233, 185, 12] },  // #E9B90C yellow
  { stop: 75,  rgb: [132, 204, 22] },  // #84CC16 light green
  { stop: 90,  rgb: [22, 163, 74] },   // #16A34A green
  { stop: 100, rgb: [21, 128, 61] },   // #15803D dark green
];

const lerp = (a: number, b: number, t: number): number => a + (b - a) * t;

const lerpColor = (
  c1: [number, number, number],
  c2: [number, number, number],
  t: number
): [number, number, number] => [
  Math.round(lerp(c1[0], c2[0], t)),
  Math.round(lerp(c1[1], c2[1], t)),
  Math.round(lerp(c1[2], c2[2], t)),
];

// Retourne un tuple RGB brut pour permettre d'appliquer des opacités (rgba) ensuite.
const scoreColor = (score: number): [number, number, number] => {
  const clamped = Math.max(0, Math.min(100, score));

  if (clamped <= COLOR_STOPS[0].stop) return COLOR_STOPS[0].rgb;
  
  const last = COLOR_STOPS[COLOR_STOPS.length - 1];
  if (clamped >= last.stop) return last.rgb;

  for (let i = 0; i < COLOR_STOPS.length - 1; i++) {
    const a = COLOR_STOPS[i];
    const b = COLOR_STOPS[i + 1];
    if (clamped >= a.stop && clamped <= b.stop) {
      const t = (clamped - a.stop) / (b.stop - a.stop);
      return lerpColor(a.rgb, b.rgb, t);
    }
  }

  return COLOR_STOPS[0].rgb;
};

/* ------------------------------------------------------------------ */
/*  Gestionnaire centralisé du Statut                                  */
/* ------------------------------------------------------------------ */

const getScoreStatus = (score: number) => {
  let label = '';
  let badgeText = '';

  if (score < 20) {
    label = 'Critique';
    badgeText = 'Risque critique';
  } else if (score < 40) {
    label = 'Très vulnérable';
    badgeText = 'Vulnérable';
  } else if (score < 60) {
    label = 'Vulnérabilités importantes';
    badgeText = 'À corriger';
  } else if (score < 75) {
    label = 'Sécurité moyenne';
    badgeText = 'Moyen';
  } else if (score < 90) {
    label = 'Bonne sécurité';
    badgeText = 'Sécurisé';
  } else {
    label = 'Excellente sécurité';
    badgeText = 'Statut OK';
  }

  // Couleurs générées dynamiquement avec des niveaux d'opacité
  const [r, g, b] = scoreColor(score);
  
  return {
    label,
    badgeText,
    mainColor: `rgb(${r}, ${g}, ${b})`,
    bgColor: `rgba(${r}, ${g}, ${b}, 0.15)`,
    borderColor: `rgba(${r}, ${g}, ${b}, 0.3)`,
    dotColor: `rgb(${r}, ${g}, ${b})`,
  };
};

/* ------------------------------------------------------------------ */
/*  Composant Score                                                    */
/* ------------------------------------------------------------------ */

export function Score() {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: false, amount: 0.1, margin: '-20%' });
  const prefersReducedMotion = useReducedMotion();

  const targetScore = 85;

  const [currentScore, setCurrentScore] = useState(0);
  const [activeMetric, setActiveMetric] = useState<'score' | 'risk'>('score');

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveMetric((prev) => (prev === 'score' ? 'risk' : 'score'));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (prefersReducedMotion) {
      setCurrentScore(targetScore);
      return;
    }

    if (!isInView) {
      setCurrentScore(0);
      return;
    }

    let rafId = 0;
    const start = performance.now();

    const tick = (now: number) => {
      const elapsed = now - start;
      const t = Math.min(1, elapsed / ANIMATION_DURATION_MS);
      const eased = easeOutQuad(t);
      
      setCurrentScore(eased * targetScore);
      
      if (t < 1) {
        rafId = requestAnimationFrame(tick);
      }
    };

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [isInView, prefersReducedMotion]);

  const ringSize = 340;
  const strokeWidth = 12;
  const radius = (ringSize - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - currentScore / 100);

  // LA fonction unique de vérité pour tout le statut
  const status = getScoreStatus(currentScore);
  const displayScore = Math.round(currentScore);

  return (
    <section id="score" className="py-32 px-6 relative overflow-hidden bg-[#f7f8fb]">
      {/* Halo */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[radial-gradient(circle_at_center,var(--blue-100),transparent_60%)] opacity-[0.4] pointer-events-none" />

      <div className="max-w-4xl mx-auto text-center relative z-10" ref={ref}>
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: -20 }}
          transition={{ duration: 0.6 }}
          className="font-serif text-3xl md:text-4xl font-bold mb-4 text-[#12131a]"
        >
          Score de Sécurité
        </motion.h2>
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: -20 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="text-lg text-[#4b4e5c] mb-12"
        >
          Analysez, détectez, corrigez — en temps réel.
        </motion.p>

        <div className="flex flex-col items-center justify-center">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={isInView ? { scale: 1, opacity: 1 } : { scale: 0.8, opacity: 0 }}
            transition={{ type: 'spring', bounce: 0.4, duration: 1 }}
            className="relative flex items-center justify-center w-[340px] h-[340px]"
          >
            <svg
              width={ringSize}
              height={ringSize}
              className="absolute -rotate-90 top-0 left-0 pointer-events-none"
              viewBox={`0 0 ${ringSize} ${ringSize}`}
              aria-hidden="true"
            >
              <circle
                cx={ringSize / 2}
                cy={ringSize / 2}
                r={radius}
                fill="none"
                stroke="#e4e7f0"
                strokeWidth={strokeWidth}
              />
              <circle
                cx={ringSize / 2}
                cy={ringSize / 2}
                r={radius}
                fill="none"
                stroke={status.mainColor} // <-- Utilise la couleur issue de status
                strokeWidth={strokeWidth}
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={dashOffset}
              />
            </svg>

            {/* Contenu central */}
            <div className="absolute inset-0 flex items-center justify-center">
              <AnimatePresence mode="wait">
                {activeMetric === 'score' ? (
                  <motion.div
                    key="score"
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -10, scale: 0.95 }}
                    transition={{ duration: 0.4, ease: "easeInOut" }}
                    className="flex flex-col items-center"
                  >
                    <div className="flex items-baseline">
                      <span
                        className="font-mono font-bold leading-none tabular-nums"
                        style={{
                          fontSize: 'clamp(4rem, 10vw, 6rem)',
                          color: status.mainColor,
                        }}
                      >
                        {displayScore}
                      </span>
                      <span className="font-mono text-3xl text-[#8a8d9c] ml-1">/100</span>
                    </div>
                  </motion.div>
                ) : (
                  <motion.div
                    key="risk"
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -10, scale: 0.95 }}
                    transition={{ duration: 0.4, ease: "easeInOut" }}
                    className="flex flex-col items-center justify-center w-full"
                  >
                    <div className="text-[#8a8d9c] text-sm uppercase tracking-widest font-semibold mb-2">
                      Statut
                    </div>
                    {/* Conteneur pour l'animation cross-fade des labels */}
                    <div className="relative h-12 w-full flex items-center justify-center">
                      <AnimatePresence mode="popLayout">
                        <motion.div
                          key={status.label}
                          initial={{ opacity: 0, y: 15 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -15 }}
                          transition={{ duration: 0.3, ease: 'easeOut' }}
                          className="absolute font-serif font-bold text-center leading-tight px-4"
                          style={{
                            fontSize: 'clamp(1.2rem, 5vw, 1.8rem)',
                            color: status.mainColor,
                          }}
                        >
                          {status.label}
                        </motion.div>
                      </AnimatePresence>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>

          {/* Badge Dynamique Totalement Synchronisé */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: -20 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mt-12 px-6 py-2 rounded-full font-bold text-lg border shadow-sm flex items-center gap-2 overflow-hidden relative"
            style={{
              backgroundColor: status.bgColor,
              borderColor: status.borderColor,
              color: status.mainColor,
            }}
          >
            <motion.div
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: status.dotColor }}
              animate={prefersReducedMotion ? {} : { opacity: [1, 0.4, 1] }}
              transition={{ repeat: Infinity, duration: 2.4, ease: 'easeInOut' }}
            />
            {/* Animation de changement du texte du badge */}
            <div className="relative flex items-center justify-center">
              <AnimatePresence mode="popLayout">
                <motion.span
                  key={status.badgeText}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.3, ease: 'easeOut' }}
                  className="whitespace-nowrap"
                >
                  {status.badgeText}
                </motion.span>
              </AnimatePresence>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
