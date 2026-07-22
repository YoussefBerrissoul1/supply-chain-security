import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence, useMotionValue, useSpring, useInView, useReducedMotion, useTransform } from 'framer-motion';

export function Score() {
  const ref = React.useRef(null);
  const isInView = useInView(ref, { once: false, amount: 0.1, margin: '-20%' });
  const prefersReducedMotion = useReducedMotion();

  const targetScore = 85;
  const scoreValue  = useMotionValue(0);
  const springScore = useSpring(scoreValue, { damping: 40, stiffness: 25, restDelta: 0.5 });
  const [displayScore, setDisplayScore] = React.useState(0);

  // Toggle between 'score' and 'risk'
  const [activeMetric, setActiveMetric] = useState<'score' | 'risk'>('score');

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveMetric((prev) => (prev === 'score' ? 'risk' : 'score'));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  // Progress ring geometry
  const ringSize = 340;
  const strokeWidth = 10;
  const radius = (ringSize - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progressValue = useMotionValue(circumference);
  const springProgress = useSpring(progressValue, { damping: 40, stiffness: 25, restDelta: 0.5 });

  // Color transition: Red -> Orange -> Green
  const ringColor = useTransform(
    scoreValue,
    [0, 50, 85, 100],
    ['#ef4444', '#f97316', '#15803d', '#15803d'] // red-500 -> orange-500 -> green-700
  );

  useEffect(() => {
    if (isInView) {
      if (prefersReducedMotion) {
        setDisplayScore(targetScore);
      } else {
        scoreValue.set(targetScore);
        progressValue.set(circumference * (1 - targetScore / 100));
      }
    } else {
      // Reverse animation when scrolled out
      if (!prefersReducedMotion) {
        scoreValue.set(0);
        progressValue.set(circumference);
      }
    }
  }, [isInView, scoreValue, prefersReducedMotion, progressValue, circumference]);

  useEffect(() => springScore.onChange((v) => setDisplayScore(Math.round(v))), [springScore]);

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
          {/* Score with ring */}
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={isInView ? { scale: 1, opacity: 1 } : { scale: 0.8, opacity: 0 }}
            transition={{ type: 'spring', bounce: 0.4, duration: 1 }}
            className="relative flex items-center justify-center w-[340px] h-[340px]"
          >
            {/* SVG Progress ring */}
            <svg
              width={ringSize}
              height={ringSize}
              className="absolute -rotate-90 top-0 left-0"
              viewBox={`0 0 ${ringSize} ${ringSize}`}
            >
              {/* Background track */}
              <circle
                cx={ringSize / 2}
                cy={ringSize / 2}
                r={radius}
                fill="none"
                stroke="#e4e7f0"
                strokeWidth={strokeWidth}
              />
              {/* Animated progress arc */}
              <motion.circle
                cx={ringSize / 2}
                cy={ringSize / 2}
                r={radius}
                fill="none"
                stroke={ringColor}
                strokeWidth={strokeWidth}
                strokeLinecap="round"
                strokeDasharray={circumference}
                style={{ strokeDashoffset: springProgress, stroke: ringColor }}
              />
            </svg>

            {/* Alternating Text inside ring */}
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
                        className="font-mono font-bold text-[#12131a] leading-none"
                        style={{ fontSize: 'clamp(4rem, 10vw, 6rem)' }}
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
                    className="flex flex-col items-center"
                  >
                    <div className="text-[#8a8d9c] text-sm uppercase tracking-widest font-semibold mb-1">
                      Niveau de risque
                    </div>
                    <div className="font-serif font-bold text-[#15803d] leading-none" style={{ fontSize: 'clamp(2.5rem, 7vw, 3.5rem)' }}>
                      Faible
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>

          {/* Badge with subtle pulse micro-interaction */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: -20 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mt-12 bg-[#dcfce7] text-[#15803d] px-6 py-2 rounded-full font-bold text-lg border border-[#15803d]/20 shadow-sm flex items-center gap-2"
          >
            {/* Pulsing dot */}
            <motion.div
              className="w-2.5 h-2.5 rounded-full bg-[#15803d]"
              animate={prefersReducedMotion ? {} : { opacity: [1, 0.35, 1] }}
              transition={{ repeat: Infinity, duration: 2.4, ease: 'easeInOut' }}
            />
            Statut OK
          </motion.div>
        </div>
      </div>
    </section>
  );
}
