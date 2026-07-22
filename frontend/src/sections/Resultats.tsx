import React, { useEffect } from 'react';
import { motion, useMotionValue, useSpring, useInView, useReducedMotion } from 'framer-motion';
import { FlaskConical, Clock, Target, ShieldCheck } from 'lucide-react';

/* ── animated counter ────────────────────────────────────────────────── */
function AnimatedStat({
  value,
  suffix = '',
  prefix = '',
  label,
  icon: Icon,
  color,
  delay = 0,
}: {
  value: number;
  suffix?: string;
  prefix?: string;
  label: string;
  icon: React.ElementType;
  color: string;
  delay?: number;
}) {
  const ref = React.useRef(null);
  const isInView = useInView(ref, { once: false, amount: 0.1, margin: '-15%' });
  const prefersReduced = useReducedMotion();

  const motionVal = useMotionValue(0);
  const spring = useSpring(motionVal, { damping: 30, stiffness: 60, restDelta: 0.5 });
  const [display, setDisplay] = React.useState(0);

  useEffect(() => {
    if (isInView) {
      if (prefersReduced) setDisplay(value);
      else motionVal.set(value);
    }
  }, [isInView, motionVal, prefersReduced, value]);

  useEffect(() => spring.onChange((v) => setDisplay(Math.round(v))), [spring]);

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: false, amount: 0.1, margin: '-50px' }}
      transition={{ duration: 0.5, delay }}
      className="bg-white rounded-2xl border border-[#e4e7f0] p-8 shadow-sm hover:shadow-md transition-shadow"
    >
      <div
        className="w-12 h-12 rounded-xl flex items-center justify-center mb-5"
        style={{ backgroundColor: `${color}12` }}
      >
        <Icon className="w-6 h-6" style={{ color }} />
      </div>
      <div className="font-mono text-4xl md:text-5xl font-bold text-[#12131a] mb-2">
        {prefix}{display}{suffix}
      </div>
      <div className="text-sm text-[#4b4e5c]">{label}</div>
    </motion.div>
  );
}

/* ── section ──────────────────────────────────────────────────────────── */
const METRICS = [
  { value: 247, suffix: '+', icon: FlaskConical, color: '#6d28d9', label: 'Dépendances analysées par scan' },
  { value: 2,   prefix: '< ', suffix: ' min', icon: Clock, color: '#0ea5e9', label: "Temps moyen d'analyse complète" },
  { value: 99,  suffix: '.2%', icon: Target, color: '#c2410c', label: 'Précision de détection (faux positifs < 1%)' },
  { value: 85,  suffix: '/100', icon: ShieldCheck, color: '#15803d', label: 'Score moyen de sécurité post-correction' },
];

export function Resultats() {
  return (
    <section id="resultats" className="py-32 px-6 bg-white">
      <div className="max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1, margin: '-100px' }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <span className="text-sm font-semibold uppercase tracking-widest text-[#c2410c] mb-4 inline-block">
            Résultats
          </span>
          <h2 className="font-serif text-4xl md:text-5xl font-bold text-[#12131a] mb-4">
            Testé en conditions réelles
          </h2>
          <p className="text-xl text-[#4b4e5c] max-w-2xl mx-auto font-light">
            NEXORA a été validé en environnement de production sur l&apos;infrastructure SRM-FM.
            Les résultats parlent d&apos;eux-mêmes.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {METRICS.map((m, idx) => (
            <AnimatedStat
              key={m.label}
              value={m.value}
              suffix={m.suffix}
              prefix={m.prefix}
              label={m.label}
              icon={m.icon}
              color={m.color}
              delay={idx * 0.1}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
