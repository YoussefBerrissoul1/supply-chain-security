import { useRef, useEffect, useState } from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import { MagneticButton } from '@/components/MagneticButton';
import earthVideo from '@/earth.mp4';

/* ─── smooth cubic-bezier shorthand ─── */
const smoothEase = [0.22, 1, 0.36, 1] as const;

export function Hero() {
  const sectionRef = useRef<HTMLElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [videoLoaded, setVideoLoaded] = useState(false);

  /* parallax: video moves slower than scroll */
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end start'],
  });
  const videoY = useTransform(scrollYProgress, [0, 1], ['0%', '30%']);
  const videoScale = useTransform(scrollYProgress, [0, 1], [1, 1.15]);
  const overlayOpacity = useTransform(scrollYProgress, [0, 0.5], [0.4, 0.85]);
  const textY = useTransform(scrollYProgress, [0, 1], ['0%', '50%']);
  const opacityOut = useTransform(scrollYProgress, [0, 0.5], [1, 0]);

  /* ensure autoplay on mount (some browsers block until interaction) */
  useEffect(() => {
    const v = videoRef.current;
    if (v) {
      v.play().catch(() => {});
    }
  }, []);

  return (
    <section
      ref={sectionRef}
      className="relative h-[100dvh] w-full flex items-center overflow-hidden bg-[#07080b]"
    >
      {/* ── Video Background ── */}
      <motion.div
        className="absolute inset-0 z-0 will-change-transform"
        style={{ y: videoY, scale: videoScale }}
        initial={{ scale: 1.15, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 2.5, ease: 'easeOut' }}
      >
        <video
          ref={videoRef}
          src={earthVideo}
          autoPlay
          loop
          muted
          playsInline
          onLoadedData={() => setVideoLoaded(true)}
          className="w-full h-full object-cover"
          style={{
            opacity: videoLoaded ? 1 : 0,
            transition: 'opacity 1.2s cubic-bezier(0.22,1,0.36,1)',
          }}
        />

        {/* Radial vignette — cinematic depth */}
        <motion.div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse 80% 80% at 50% 50%, transparent 30%, #07080b 100%)',
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.7 }}
          transition={{ duration: 2, delay: 0.3 }}
        />

        {/* Gradient overlay (scroll-reactive) */}
        <motion.div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'linear-gradient(to bottom, rgba(7,8,11,0.65) 0%, rgba(7,8,11,0.25) 40%, rgba(7,8,11,0.85) 100%)',
            opacity: overlayOpacity,
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 1.8, delay: 0.5 }}
        />

        {/* Subtle animated grain / noise layer */}
        <div
          className="absolute inset-0 pointer-events-none mix-blend-soft-light opacity-[0.04]"
          style={{
            backgroundImage:
              'url("data:image/svg+xml,%3Csvg viewBox=\'0 0 256 256\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cfilter id=\'noise\'%3E%3CfeTurbulence type=\'fractalNoise\' baseFrequency=\'0.9\' numOctaves=\'4\' stitchTiles=\'stitch\'/%3E%3C/filter%3E%3Crect width=\'100%25\' height=\'100%25\' filter=\'url(%23noise)\'/%3E%3C/svg%3E")',
            backgroundSize: '128px 128px',
          }}
        />
      </motion.div>

      {/* ── Content ── */}
      <motion.div 
        className="relative z-10 w-full max-w-7xl mx-auto px-6 flex flex-col items-start justify-center h-full pt-20"
        style={{ y: textY, opacity: opacityOut }}
      >
        {/* Tagline */}
        <motion.div
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 1, delay: 0.6, ease: smoothEase }}
          className="mb-4"
        >
          <span className="text-sm font-semibold tracking-widest text-[#8a8d9c] uppercase">
            Sécurité applicative nouvelle génération
          </span>
        </motion.div>

        {/* Title with animated glow */}
        <div className="relative">
          {/* Pulsing glow behind text */}
          <motion.div
            className="absolute inset-0 -inset-x-8 -inset-y-4 pointer-events-none"
            style={{
              background: 'radial-gradient(ellipse 60% 60% at 30% 50%, rgba(194,65,12,0.15), transparent 70%)',
            }}
            animate={{ opacity: [0.4, 0.7, 0.4] }}
            transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }}
          />
          <motion.h1
            initial={{ opacity: 0, y: 50, filter: 'blur(12px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ duration: 1.2, delay: 0.8, ease: smoothEase }}
            className="relative font-serif text-white font-bold tracking-tight leading-[0.95] mb-6 max-w-4xl"
            style={{ fontSize: 'clamp(3.5rem, 8vw, 7.5rem)' }}
          >
            NEXORA
          </motion.h1>
        </div>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 30, filter: 'blur(8px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 1, delay: 1.0, ease: smoothEase }}
          className="text-lg md:text-xl text-white/80 max-w-2xl font-light leading-relaxed mb-10"
        >
          Anticipez les menaces avant qu'elles ne vous atteignent. Notre
          plateforme automatise la détection, analyse les vulnérabilités et
          sécurise vos environnements en temps réel.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 30, filter: 'blur(6px)' }}
          animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
          transition={{ duration: 1, delay: 1.2, ease: smoothEase }}
          className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto"
        >
          <MagneticButton
            className="w-full sm:w-auto px-8 py-4 text-base font-semibold"
            onClick={() => (window.location.href = '/scan?new=true')}
          >
            Lancer un scan
          </MagneticButton>
          <button
            className="group w-full sm:w-auto px-8 py-4 text-base font-medium text-white border border-white/20 rounded-full transition-all duration-500 hover:bg-white/10 hover:border-white/40 hover:shadow-[0_0_30px_rgba(255,255,255,0.06)] focus:outline-none focus:ring-2 focus:ring-white/50"
            onClick={() =>
              document
                .getElementById('terminal')
                ?.scrollIntoView({ behavior: 'smooth' })
            }
          >
            <span className="inline-block transition-transform duration-500 group-hover:translate-x-1">
              →
            </span>{' '}
            Voir comment ça marche
          </button>
        </motion.div>
      </motion.div>

      {/* ── Scroll indicator ── */}
      <motion.div
        className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-white/50 z-10"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.8, duration: 1.2, ease: smoothEase }}
      >
        <span className="text-xs uppercase tracking-widest font-mono">
          Scroll
        </span>
        <motion.div className="w-[1px] h-12 bg-white/20 overflow-hidden relative rounded-full">
          <motion.div
            className="w-full h-1/2 bg-gradient-to-b from-white/80 to-white/0 absolute top-0 rounded-full"
            animate={{ y: ['-100%', '200%'] }}
            transition={{
              repeat: Infinity,
              duration: 1.8,
              ease: 'easeInOut',
              repeatDelay: 0.3,
            }}
          />
        </motion.div>
      </motion.div>
    </section>
  );
}
