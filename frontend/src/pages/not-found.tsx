import { motion } from 'framer-motion';
import { ShieldOff, ArrowLeft, Home } from 'lucide-react';
import { MagneticButton } from '@/components/MagneticButton';

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#f7f8fb] px-6 relative overflow-hidden">
      {/* Subtle background pattern */}
      <div
        className="absolute inset-0 opacity-[0.025] pointer-events-none"
        style={{ backgroundImage: 'radial-gradient(#12131a 1px, transparent 1px)', backgroundSize: '32px 32px' }}
      />

      {/* Radial halo */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[radial-gradient(circle_at_center,rgba(194,65,12,0.06),transparent_60%)] pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
        transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 text-center max-w-lg"
      >
        {/* Icon */}
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2, type: 'spring', bounce: 0.4 }}
          className="w-20 h-20 mx-auto mb-8 bg-[#fff7ed] rounded-2xl border border-[#c2410c]/20 flex items-center justify-center"
        >
          <ShieldOff className="w-10 h-10 text-[#c2410c]" />
        </motion.div>

        {/* 404 number */}
        <h1
          className="font-serif font-bold text-[#12131a] tracking-tight leading-none mb-4"
          style={{ fontSize: 'clamp(5rem, 15vw, 10rem)' }}
        >
          404
        </h1>

        <h2 className="font-serif text-2xl md:text-3xl font-bold text-[#12131a] mb-4">
          Page introuvable
        </h2>

        <p className="text-lg text-[#4b4e5c] font-light leading-relaxed mb-10">
          Cette page n&apos;existe pas ou a été déplacée. Vérifiez l&apos;URL ou
          retournez à la page d&apos;accueil.
        </p>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <MagneticButton
            className="px-8 py-3.5 text-base font-semibold"
            onClick={() => (window.location.href = '/')}
          >
            <Home className="w-4 h-4 mr-2 inline" />
            Retour à l&apos;accueil
          </MagneticButton>

          <button
            onClick={() => window.history.back()}
            className="group px-8 py-3.5 text-base font-medium text-[#4b4e5c] border border-[#e4e7f0] rounded-full hover:border-[#12131a]/30 hover:text-[#12131a] transition-all"
          >
            <ArrowLeft className="w-4 h-4 mr-2 inline transition-transform group-hover:-translate-x-1" />
            Page précédente
          </button>
        </div>

        {/* Status badge */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="mt-12 inline-flex items-center gap-2 text-xs font-mono text-[#8a8d9c] uppercase tracking-widest"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#15803d] opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-[#15803d]" />
          </span>
          Systèmes opérationnels
        </motion.div>
      </motion.div>
    </div>
  );
}
