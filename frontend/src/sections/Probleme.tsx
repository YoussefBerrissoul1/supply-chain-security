import React, { useRef } from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import { Package, Clock, Search } from 'lucide-react';

const PROBLEMS = [
  {
    icon: Package,
    title: "Des composants partout",
    description: "La majorité des applications modernes reposent sur des composants open-source, souvent invisibles et rarement audités.",
  },
  {
    icon: Clock,
    title: "Des failles qui durent",
    description: "Une vulnérabilité non corrigée peut rester exposée pendant des mois avant d'être remarquée — et exploitée.",
  },
  {
    icon: Search,
    title: "La détection dépassée",
    description: "La détection manuelle ne suit plus le rythme des mises à jour et des nouvelles dépendances introduites chaque jour.",
  },
];

export function Probleme() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start end", "end start"]
  });
  
  // Parallax transform for a background decorative shape
  const yBg = useTransform(scrollYProgress, [0, 1], ["0%", "100%"]);

  return (
    <section id="projet" ref={ref} className="py-32 px-6 bg-[#f7f8fb] relative overflow-hidden">
      {/* Decorative Parallax Background */}
      <motion.div 
        className="absolute -top-[10%] -right-[10%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle,rgba(194,65,12,0.03)_0%,transparent_70%)] pointer-events-none"
        style={{ y: yBg }}
      />
      <motion.div 
        className="absolute -bottom-[20%] -left-[10%] w-[800px] h-[800px] rounded-full bg-[radial-gradient(circle,rgba(15,23,42,0.02)_0%,transparent_70%)] pointer-events-none"
        style={{ y: useTransform(scrollYProgress, [0, 1], ["50%", "-50%"]) }}
      />

      <div className="max-w-7xl mx-auto relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">

          {/* Left: Headline + body */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: false, amount: 0.1, margin: '-100px' }}
            transition={{ duration: 0.6 }}
          >
            <span className="text-sm font-semibold uppercase tracking-widest text-[#c2410c] mb-4 inline-block">
              Le Contexte
            </span>
            <h2 className="font-serif text-4xl md:text-5xl font-bold mb-6 text-[#12131a] leading-[1.05]">
              Une chaîne logicielle, autant de portes d&apos;entrée
            </h2>
            <p className="text-xl text-[#4b4e5c] font-light leading-relaxed">
              Un projet moderne dépend de centaines de composants externes — bibliothèques
              open-source, images Docker, outils tiers. Chacun de ces composants est une porte
              d&apos;entrée potentielle. Une dépendance oubliée, une image non mise à jour, une
              vulnérabilité connue mais jamais corrigée : c&apos;est ainsi que la majorité des
              incidents de sécurité logicielle commencent aujourd&apos;hui.
            </p>
          </motion.div>

          {/* Right: 3 problem cards */}
          <div className="space-y-4">
            {PROBLEMS.map((p, idx) => (
              <motion.div
                key={p.title}
                initial={{ opacity: 0, x: 30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: false, amount: 0.1, margin: '-50px' }}
                transition={{ duration: 0.5, delay: idx * 0.12 }}
                className="flex items-start gap-5 bg-white p-6 rounded-2xl border border-[#e4e7f0] shadow-sm"
              >
                <div className="shrink-0 w-12 h-12 bg-[#ffedd8] rounded-xl flex items-center justify-center">
                  <p.icon className="w-6 h-6 text-[#c2410c]" />
                </div>
                <div>
                  <h3 className="font-bold text-[#12131a] mb-1">{p.title}</h3>
                  <p className="text-[#4b4e5c] text-sm leading-relaxed">{p.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
