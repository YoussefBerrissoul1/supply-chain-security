import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'wouter';
import { STATUS_CONFIG } from '@/lib/errors/config';
import { MagneticButton } from '@/components/MagneticButton';
import { HelpCircle } from 'lucide-react';

interface StatusLayoutProps {
  code: number | 'UNKNOWN';
}

export function StatusLayout({ code }: StatusLayoutProps) {
  const config = STATUS_CONFIG[code] || STATUS_CONFIG['UNKNOWN'];
  const Icon = config.icon || HelpCircle;

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#f7f8fb] px-6 relative overflow-hidden">
      {/* Subtle background pattern */}
      <div
        className="absolute inset-0 opacity-[0.025] pointer-events-none"
        style={{ backgroundImage: 'radial-gradient(#12131a 1px, transparent 1px)', backgroundSize: '32px 32px' }}
      />

      {/* Radial halo (adapts color slightly based on status, but keeping neutral for now) */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[radial-gradient(circle_at_center,rgba(194,65,12,0.06),transparent_60%)] pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
        transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 text-center max-w-lg bg-white p-10 rounded-3xl shadow-xl border border-[#e4e7f0]"
        role="alert"
        aria-live="assertive"
      >
        {/* Status Code Watermark with strange/unique floating animation */}
        <motion.div 
          animate={{
            y: [0, -15, 0, 10, 0],
            x: [0, 10, -5, -10, 0],
            rotateZ: [0, 3, -2, 0],
            filter: [
              'blur(0px) drop-shadow(0px 0px 0px rgba(194,65,12,0))',
              'blur(3px) drop-shadow(10px 10px 20px rgba(194,65,12,0.1))',
              'blur(0px) drop-shadow(0px 0px 0px rgba(194,65,12,0))'
            ],
          }}
          transition={{
            duration: 7,
            repeat: Infinity,
            ease: "easeInOut"
          }}
          className="absolute top-2 right-4 text-[160px] font-mono font-black text-[#c2410c]/20 -z-10 select-none leading-none tracking-tighter mix-blend-multiply"
        >
          {config.code}
        </motion.div>

        {/* Icon */}
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2, type: 'spring', bounce: 0.4 }}
          className="w-20 h-20 mx-auto mb-6 bg-[#fff7ed] rounded-2xl border border-[#c2410c]/20 flex items-center justify-center relative z-10"
        >
          <Icon className="w-10 h-10 text-[#c2410c]" aria-hidden="true" />
        </motion.div>

        <h1 className="font-serif text-3xl md:text-4xl font-bold text-[#12131a] mb-4 relative z-10">
          {config.title}
        </h1>

        <p className="text-[#4b4e5c] font-light leading-relaxed mb-8 relative z-10">
          {config.description}
        </p>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 relative z-10">
          {config.actions.map((action, idx) => {
            if (action.href) {
              return (
                <Link href={action.href} key={idx}>
                  <a className={
                    action.primary 
                      ? "px-6 py-3 text-sm font-semibold rounded-full bg-[#c2410c] text-white hover:bg-[#9a3412] transition-colors shadow-sm flex items-center justify-center"
                      : "px-6 py-3 text-sm font-medium text-[#4b4e5c] border border-[#e4e7f0] rounded-full hover:border-[#12131a]/30 hover:text-[#12131a] transition-colors bg-white flex items-center justify-center"
                  }>
                    {action.label}
                  </a>
                </Link>
              );
            }

            return (
              <button
                key={idx}
                onClick={action.onClick}
                className={
                  action.primary 
                    ? "px-6 py-3 text-sm font-semibold rounded-full bg-[#c2410c] text-white hover:bg-[#9a3412] transition-colors shadow-sm"
                    : "px-6 py-3 text-sm font-medium text-[#4b4e5c] border border-[#e4e7f0] rounded-full hover:border-[#12131a]/30 hover:text-[#12131a] transition-colors bg-white"
                }
              >
                {action.label}
              </button>
            );
          })}
        </div>
      </motion.div>
    </div>
  );
}
