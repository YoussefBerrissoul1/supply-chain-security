import React, { useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Activity, GitBranch, Cpu, FileText, Blocks, Eye, Bell } from 'lucide-react';

// ── Group 1 — core product (larger cards, featured) ─────────────────────────
const CORE_FEATURES = [
  {
    icon: Shield,
    title: "Scan automatisé",
    description: "Analyse en continu de votre code source et de l'infrastructure pour une protection 24/7.",
  },
  {
    icon: AlertTriangle,
    title: "Détection de vulnérabilités",
    description: "Recherche profonde de failles 0-day avec un moteur propulsé par l'IA.",
  },
  {
    icon: Activity,
    title: "Score en temps réel",
    description: "Évaluation dynamique de votre posture de sécurité globale avec des KPI clairs.",
  },
];

// ── Group 2 — complementary features (denser list/grid) ─────────────────────
const EXTRA_FEATURES = [
  { icon: GitBranch, title: "Analyse des dépendances",  description: "Identification des paquets obsolètes et vulnérabilités de la supply chain logicielle." },
  { icon: Cpu,       title: "Intégration SRM-FM",       description: "Connectivité native avec les systèmes de gestion de risques de sécurité avancés." },
  { icon: FileText,  title: "Rapports détaillés",       description: "Génération de documentations de conformité et d'audits en un clic (PDF/CSV)." },
  { icon: Blocks,    title: "CI/CD Intégration",        description: "Bloquez les déploiements non sécurisés directement depuis vos pipelines GitHub ou GitLab." },
  { icon: Eye,       title: "Surveillance continue",    description: "Monitoring permanent du dark web et des bases CVE publiques." },
  { icon: Bell,      title: "Alertes intelligentes",    description: "Notifications triées par criticité via Slack, Teams, ou Webhook." },
];

/* ── 3D Tilt Card for core features ──────────────────────────────────────── */
function TiltCard({ children, className }: { children: React.ReactNode; className?: string }) {
  const cardRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const card = cardRef.current;
    if (!card) return;
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const rotateX = ((y - centerY) / centerY) * -4; // max 4 degrees
    const rotateY = ((x - centerX) / centerX) * 4;
    card.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
  }, []);

  const handleMouseLeave = useCallback(() => {
    const card = cardRef.current;
    if (card) card.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
  }, []);

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={className}
      style={{ transition: 'transform 0.15s ease-out', willChange: 'transform' }}
    >
      {children}
    </div>
  );
}

export function Features() {
  return (
    <section id="comment-ca-marche" className="py-32 px-6">
      <div className="max-w-7xl mx-auto">

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1, margin: '-100px' }}
          transition={{ duration: 0.6 }}
          className="text-center mb-20"
        >
          <h2 className="font-serif text-4xl md:text-5xl font-bold mb-4 text-[#12131a]">
            Fonctionnalités Clés
          </h2>
          <p className="text-xl text-[#4b4e5c] max-w-2xl mx-auto font-light">
            Une suite complète d'outils pour anticiper, détecter et neutraliser les menaces avant
            qu'elles n'impactent votre activité.
          </p>
        </motion.div>

        {/* ── Groupe 1 — Cœur du produit (3 grandes cartes avec 3D tilt) ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          {CORE_FEATURES.map((f, idx) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: false, amount: 0.1, margin: '-50px' }}
              transition={{ duration: 0.5, delay: idx * 0.1 }}
            >
              <TiltCard className="group relative bg-white p-10 rounded-2xl border border-[#e4e7f0] shadow-sm hover:shadow-lg transition-shadow overflow-hidden h-full">
                {/* Animated bottom border */}
                <div className="absolute bottom-0 left-0 h-1 w-full bg-[#c2410c] scale-x-0 group-hover:scale-x-100 origin-left transition-transform duration-300 ease-out" />

                <div className="w-14 h-14 bg-[#ffedd8] rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                  <f.icon className="w-7 h-7 text-[#c2410c]" />
                </div>

                <h3 className="text-xl font-bold mb-3 text-[#12131a]">{f.title}</h3>
                <p className="text-[#4b4e5c] leading-relaxed">{f.description}</p>
              </TiltCard>
            </motion.div>
          ))}
        </div>

        {/* ── Divider ─────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-4 my-10 px-2">
          <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#e4e7f0] to-transparent" />
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8a8d9c]">
            Fonctionnalités complémentaires
          </span>
          <div className="flex-1 h-px bg-gradient-to-r from-transparent via-[#e4e7f0] to-transparent" />
        </div>

        {/* ── Groupe 2 — Complémentaires (6 cartes condensées, 2×3) ───────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {EXTRA_FEATURES.map((f, idx) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: false, amount: 0.1, margin: '-50px' }}
              transition={{ duration: 0.4, delay: idx * 0.07 }}
              className="group flex items-start gap-4 bg-[#f7f8fb] p-5 rounded-xl border border-[#e4e7f0] hover:border-[#c2410c]/30 hover:bg-white transition-all duration-200"
            >
              <div className="shrink-0 w-10 h-10 bg-white rounded-lg flex items-center justify-center border border-[#e4e7f0] group-hover:border-[#c2410c]/30 transition-colors">
                <f.icon className="w-5 h-5 text-[#c2410c]" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#12131a] mb-1">{f.title}</h3>
                <p className="text-xs text-[#4b4e5c] leading-relaxed">{f.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
