import React from 'react';
import { motion } from 'framer-motion';
import { Droplets, Search, ShieldCheck } from 'lucide-react';

const ANALOGIES = [
  { icon: Droplets,    color: '#0ea5e9', infra: "Canalisation d'eau",    code: 'Dépendance logicielle' },
  { icon: Search,      color: '#c2410c', infra: 'Inspection du réseau',  code: 'Audit de sécurité NEXORA' },
  { icon: ShieldCheck, color: '#15803d', infra: 'Intégrité garantie',    code: 'Score de sécurité /100' },
];

export function SRMPont() {
  return (
    <section id="pont-nexora" className="py-24 px-6 bg-[#07080b] text-white overflow-hidden relative">
      {/* Subtle background grain */}
      <div
        className="absolute inset-0 pointer-events-none mix-blend-soft-light opacity-[0.04]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E\")",
          backgroundSize: '128px 128px',
        }}
      />

      <div className="max-w-5xl mx-auto relative z-10 text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1, margin: '-100px' }}
          transition={{ duration: 0.7 }}
        >
          <span className="text-sm font-semibold uppercase tracking-widest text-[#c2410c] mb-6 inline-block">
            Pourquoi ce lien
          </span>
          <h2 className="font-serif text-4xl md:text-6xl font-bold mb-8 leading-[1.05]">
            Pourquoi ce lien avec NEXORA
          </h2>
          <p className="text-xl md:text-2xl text-white/70 font-light leading-relaxed max-w-3xl mx-auto">
            Comme un réseau de distribution d&apos;eau qui ne tolère aucune rupture de canalisation,
            un projet logiciel dépend de centaines de composants invisibles. Une seule faille
            non détectée dans cette chaîne peut compromettre l&apos;ensemble du système —
            exactement comme une brèche dans une infrastructure physique vitale.
          </p>
        </motion.div>

        {/* Visual analogy */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-px bg-white/10 rounded-2xl overflow-hidden"
        >
          {ANALOGIES.map((item, idx) => (
            <div key={idx} className="bg-[#0d0f17] p-8 flex flex-col items-center gap-4">
              <div
                className="w-14 h-14 rounded-xl flex items-center justify-center"
                style={{ backgroundColor: `${item.color}15` }}
              >
                <item.icon className="w-7 h-7" style={{ color: item.color }} />
              </div>
              <div className="text-center">
                <div className="text-xs font-mono text-white/40 uppercase tracking-wider mb-1">Infrastructure</div>
                <div className="text-white/80 font-medium mb-3">{item.infra}</div>
                <div className="w-6 h-px bg-[#c2410c] mx-auto mb-3" />
                <div className="text-xs font-mono text-white/40 uppercase tracking-wider mb-1">Logiciel</div>
                <div className="text-white font-semibold">{item.code}</div>
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

