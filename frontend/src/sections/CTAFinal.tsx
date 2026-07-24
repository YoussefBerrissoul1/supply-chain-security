import React from 'react';
import { motion } from 'framer-motion';
import { MagneticButton } from '@/components/MagneticButton';
import { ShieldCheck, Lock, GraduationCap } from 'lucide-react';

const BADGES = [
  { icon: ShieldCheck, label: 'Conforme ISO 27001' },
  { icon: Lock,        label: 'Chiffrement E2E' },
  { icon: GraduationCap, label: 'Projet académique — SRM-FM 2026' },
];

export function CTAFinal() {
  return (
    <section id="cta" className="py-32 px-6 bg-[#eef0f6] relative overflow-hidden">
      {/* Decorative background pattern */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{ backgroundImage: 'radial-gradient(#12131a 1px, transparent 1px)', backgroundSize: '32px 32px' }}
      />

      <div className="max-w-4xl mx-auto text-center relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: false, amount: 0.1 }}
          transition={{ duration: 0.6 }}
        >
          <h2 className="font-serif text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-[#12131a] tracking-tight">
            Prêt à sécuriser votre application&nbsp;?
          </h2>
          <p className="text-xl text-[#4b4e5c] mb-12 max-w-2xl mx-auto font-light">
            Rejoignez les équipes d&apos;ingénierie qui déploient en toute confiance. Obtenez
            votre premier rapport de vulnérabilité en moins de 5 minutes.
          </p>

          <div className="flex flex-col items-center gap-6">
            <MagneticButton
              className="px-10 py-5 text-lg font-bold"
              onClick={() => (window.location.href = '/scan?new=true')}
            >
              Lancer un scan
            </MagneticButton>
          </div>

          {/* Trust badges */}
          <div className="mt-16 pt-10 border-t border-[#12131a]/10 flex flex-col sm:flex-row justify-center gap-8 md:gap-16 opacity-60">
            {BADGES.map(({ icon: Icon, label }) => (
              <div key={label} className="flex flex-col items-center gap-2 text-[#12131a]">
                <Icon size={28} />
                <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
