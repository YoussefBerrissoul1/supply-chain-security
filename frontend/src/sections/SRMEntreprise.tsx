import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Droplets, Zap, Recycle, TrendingUp, X, ChevronLeft, ChevronRight } from 'lucide-react';
import logoSrm from '@assets/logo_srm.png';
import srm1 from '@assets/srm1.jpg';
import srm2 from '@assets/smr2.jpg';
import srm3 from '@assets/smr3.avif';
import srm4 from '@assets/smr4.avif';
import srm5 from '@assets/srm5.jpeg';
import srm6 from '@assets/srm6.jpeg';
import srm7 from '@assets/srm7.png';

const STATS = [
  { value: '194',        label: 'Communes desservies' },
  { value: '~4M',        label: "Habitants dans la région" },
  { value: '9',          label: 'Provinces et préfectures' },
  { value: 'Mds DH',     label: "Programme d'investissement pluriannuel" },
];

const SERVICES = [
  {
    icon: Droplets,
    label: 'Eau potable',
    sub: 'Production et distribution sur la région Fès-Meknès',
    color: '#0ea5e9',
    bg: '#f0f9ff',
  },
  {
    icon: Zap,
    label: 'Électricité',
    sub: 'Distribution et gestion du réseau électrique régional',
    color: '#f59e0b',
    bg: '#fffbeb',
  },
  {
    icon: Recycle,
    label: 'Assainissement',
    sub: 'Collecte, traitement et valorisation des eaux usées',
    color: '#10b981',
    bg: '#ecfdf5',
  },
];

const GALLERY_IMAGES = [
  { src: srm1, alt: "Infrastructure SRM-FM 1" },
  { src: srm2, alt: "Infrastructure SRM-FM 2" },
  { src: srm3, alt: "Infrastructure SRM-FM 3" },
  { src: srm4, alt: "Infrastructure SRM-FM 4" },
  { src: srm5, alt: "Infrastructure SRM-FM 5" },
  { src: srm6, alt: "Infrastructure SRM-FM 6" },
  { src: srm7, alt: "Infrastructure SRM-FM 7" }
];

export function SRMEntreprise() {
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const wrapperRef = useRef<HTMLDivElement>(null);

  // Lock body scroll when lightbox is open
  useEffect(() => {
    if (lightboxIndex !== null) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => { document.body.style.overflow = 'unset'; };
  }, [lightboxIndex]);

  // Lightbox navigation
  const nextImage = useCallback((e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (lightboxIndex !== null) {
      setLightboxIndex((prev) => (prev !== null ? (prev + 1) % GALLERY_IMAGES.length : null));
    }
  }, [lightboxIndex]);

  const prevImage = useCallback((e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (lightboxIndex !== null) {
      setLightboxIndex((prev) => (prev !== null ? (prev === 0 ? GALLERY_IMAGES.length - 1 : prev - 1) : null));
    }
  }, [lightboxIndex]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (lightboxIndex === null) return;
      if (e.key === 'ArrowRight') nextImage();
      if (e.key === 'ArrowLeft') prevImage();
      if (e.key === 'Escape') setLightboxIndex(null);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [lightboxIndex, nextImage, prevImage]);

  // Intersection Observer for dots synchronization
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const index = Number(entry.target.getAttribute('data-index'));
            if (!isNaN(index)) {
              setCurrentIndex(index);
            }
          }
        });
      },
      {
        root: wrapperRef.current,
        // rootMargin réduite à une ligne fine au centre de l'écran pour déclencher exactement au milieu
        rootMargin: '0px -50% 0px -50%',
        threshold: 0,
      }
    );

    const els = document.querySelectorAll('.gallery-item');
    els.forEach(el => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <>
      <section id="srm-entreprise" className="py-24 px-6 bg-white border-y border-[#12131a]/5">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: false, amount: 0.1, margin: '-100px' }}
            transition={{ duration: 0.6 }}
            className="mb-16"
          >
            <span className="text-sm font-semibold uppercase tracking-widest text-[#c2410c] mb-4 inline-block">
              L'entreprise d'accueil
            </span>
            <h2 className="font-serif text-4xl md:text-5xl font-bold text-[#12131a] leading-[1.05] max-w-2xl">
              Un projet né dans une infrastructure vitale
            </h2>
          </motion.div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            {/* Left: text + stats */}
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: false, amount: 0.1, margin: '-100px' }}
              transition={{ duration: 0.6 }}
            >
              <div className="flex flex-col sm:flex-row items-center gap-6 mb-10 p-6 bg-[#f7f8fb] rounded-2xl border border-[#e4e7f0] w-fit shadow-sm">
                <div className="w-40 h-40 bg-white rounded-xl border border-[#e4e7f0] flex items-center justify-center overflow-hidden shrink-0 p-4 shadow-sm transition-transform duration-500 hover:scale-105">
                  <img src={logoSrm} alt="Logo SRM-FM" className="w-full h-full object-contain" />
                </div>
                <div className="text-center sm:text-left">
                  <div className="text-xs font-mono text-[#8a8d9c] uppercase tracking-widest mb-1.5">Partenaire industriel</div>
                  <div className="font-serif text-3xl font-bold text-[#12131a] leading-tight">SRM-FM<br/>Fès-Meknès</div>
                </div>
              </div>

              <p className="text-xl text-[#4b4e5c] font-light leading-relaxed mb-10">
                La SRM-FM est l&apos;acteur unique de la gestion déléguée de l&apos;eau potable, de
                l&apos;électricité et de l&apos;assainissement liquide sur la région Fès-Meknès : 194
                communes, près de 4 millions d&apos;habitants. Un vaste programme d&apos;investissement
                pluriannuel modernise ces réseaux vitaux.
              </p>

              {/* Stats grid */}
              <div className="grid grid-cols-2 gap-4">
                {STATS.map((s) => (
                  <div key={s.label} className="p-5 bg-[#f7f8fb] rounded-xl border border-[#e4e7f0] hover:border-[#c2410c]/30 transition-colors">
                    <div className="font-serif text-3xl font-bold text-[#12131a] mb-1">{s.value}</div>
                    <div className="text-sm text-[#4b4e5c]">{s.label}</div>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* Right: infrastructure services */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: false, amount: 0.1, margin: '-100px' }}
              transition={{ duration: 0.6, delay: 0.15 }}
              className="space-y-4"
            >
              {SERVICES.map((item, idx) => (
                <motion.div
                  key={item.label}
                  initial={{ opacity: 0, y: 12 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: false, amount: 0.1 }}
                  transition={{ delay: idx * 0.1 + 0.2 }}
                  className="flex items-center gap-5 p-6 bg-[#f7f8fb] rounded-2xl border border-[#e4e7f0] hover:shadow-md hover:border-[#c2410c]/30 hover:scale-[1.02] transition-all duration-300"
                >
                  <div
                    className="shrink-0 w-12 h-12 rounded-xl flex items-center justify-center shadow-sm"
                    style={{ backgroundColor: item.bg }}
                  >
                    <item.icon className="w-6 h-6" style={{ color: item.color }} />
                  </div>
                  <div>
                    <div className="font-bold text-[#12131a]">{item.label}</div>
                    <div className="text-sm text-[#4b4e5c] mt-0.5">{item.sub}</div>
                  </div>
                </motion.div>
              ))}

              {/* Investment badge */}
              <div className="flex items-center gap-3 p-4 bg-[#fff7ed] rounded-xl border border-[#c2410c]/20 hover:bg-[#ffedd8] transition-colors">
                <div className="shrink-0 w-9 h-9 rounded-lg bg-[#c2410c]/10 flex items-center justify-center">
                  <TrendingUp className="w-5 h-5 text-[#c2410c]" />
                </div>
                <p className="text-sm text-[#4b4e5c]">
                  Programme d&apos;investissement pluriannuel de{' '}
                  <span className="font-bold text-[#12131a]">plusieurs milliards de DH</span>
                </p>
              </div>
            </motion.div>
          </div>

          {/* Infinite CSS Carousel Section */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: false, amount: 0.1, margin: '-100px' }}
            transition={{ duration: 0.6 }}
            className="mt-32 relative"
          >
            <div className="mb-12 text-center">
              <h3 className="font-serif text-3xl font-bold text-[#12131a] mb-4">
                Installations et Infrastructures
              </h3>
              <p className="text-[#4b4e5c] max-w-2xl mx-auto">
                Aperçu des infrastructures critiques gérées par la SRM-FM dans la région de Fès-Meknès.
              </p>
            </div>

            {/* Injection des Keyframes CSS pour le défilement fluide et infini */}
            <style>{`
              @keyframes infinite-scroll {
                0% { transform: translateX(0); }
                100% { transform: translateX(-50%); }
              }
              .animate-infinite-scroll {
                /* 30s de défilement lent, parfaitement linéaire */
                animation: infinite-scroll 30s linear infinite;
              }
              /* Pause automatique fluide au survol */
              .carousel-wrapper:hover .animate-infinite-scroll {
                animation-play-state: paused;
              }
            `}</style>

            <div className="relative w-full overflow-hidden carousel-wrapper" ref={wrapperRef}>
              {/* Le ruban de la "cassette" */}
              <div className="flex w-max animate-infinite-scroll">
                
                {/* Set 1 */}
                <div className="flex gap-6 pr-6">
                  {GALLERY_IMAGES.map((img, idx) => (
                    <div
                      key={`set1-${idx}`}
                      data-index={idx} // Utilisé par l'IntersectionObserver
                      className="gallery-item w-[85vw] sm:w-[60vw] md:w-[45vw] lg:w-[35vw] aspect-[16/9] md:aspect-[21/9] shrink-0 relative rounded-2xl overflow-hidden cursor-pointer group/item shadow-lg bg-[#07080b]"
                      onClick={() => setLightboxIndex(idx)}
                    >
                      <img
                        src={img.src}
                        alt={img.alt}
                        className="absolute inset-0 w-full h-full object-cover grayscale transition-all duration-500 ease-in-out group-hover/item:grayscale-0 group-hover/item:scale-[1.03] group-hover/item:brightness-110 group-hover/item:contrast-105"
                      />
                      {/* Overlay d'indication au hover */}
                      <div className="absolute inset-0 bg-gradient-to-t from-[#12131a]/60 to-transparent opacity-0 group-hover/item:opacity-100 transition-opacity duration-500 flex items-end justify-center pb-8">
                         <span className="text-white text-sm font-medium tracking-wide bg-white/10 backdrop-blur-md px-6 py-2 rounded-full transform translate-y-4 group-hover/item:translate-y-0 transition-transform duration-500">
                            Agrandir l'image
                         </span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Set 2 (Identique au Set 1 pour créer la boucle parfaite de 50%) */}
                <div className="flex gap-6 pr-6">
                  {GALLERY_IMAGES.map((img, idx) => (
                    <div
                      key={`set2-${idx}`}
                      data-index={idx} // Toujours utile pour les dots lors du second passage
                      className="gallery-item w-[85vw] sm:w-[60vw] md:w-[45vw] lg:w-[35vw] aspect-[16/9] md:aspect-[21/9] shrink-0 relative rounded-2xl overflow-hidden cursor-pointer group/item shadow-lg bg-[#07080b]"
                      onClick={() => setLightboxIndex(idx)}
                    >
                      <img
                        src={img.src}
                        alt={img.alt}
                        className="absolute inset-0 w-full h-full object-cover grayscale transition-all duration-500 ease-in-out group-hover/item:grayscale-0 group-hover/item:scale-[1.03] group-hover/item:brightness-110 group-hover/item:contrast-105"
                      />
                      <div className="absolute inset-0 bg-gradient-to-t from-[#12131a]/60 to-transparent opacity-0 group-hover/item:opacity-100 transition-opacity duration-500 flex items-end justify-center pb-8">
                         <span className="text-white text-sm font-medium tracking-wide bg-white/10 backdrop-blur-md px-6 py-2 rounded-full transform translate-y-4 group-hover/item:translate-y-0 transition-transform duration-500">
                            Agrandir l'image
                         </span>
                      </div>
                    </div>
                  ))}
                </div>

              </div>

              {/* Filtres de fondu sur les bords pour un look premium et estompé (optionnel mais recommandé) */}
              <div className="absolute top-0 bottom-0 left-0 w-12 md:w-32 bg-gradient-to-r from-white to-transparent pointer-events-none z-10" />
              <div className="absolute top-0 bottom-0 right-0 w-12 md:w-32 bg-gradient-to-l from-white to-transparent pointer-events-none z-10" />
            </div>

            {/* Indicateurs de progression (Dots) synchronisés visuellement */}
            <div className="flex justify-center gap-3 mt-8">
              {GALLERY_IMAGES.map((_, idx) => (
                <div
                  key={idx}
                  className={`h-2 rounded-full transition-all duration-300 ${
                    idx === currentIndex ? 'bg-[#c2410c] w-8' : 'bg-[#e4e7f0] w-2'
                  }`}
                  aria-hidden="true"
                />
              ))}
            </div>

          </motion.div>
        </div>
      </section>

      {/* Lightbox Overlay (Inchangé) */}
      <AnimatePresence>
        {lightboxIndex !== null && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-[#12131a]/95 backdrop-blur-md p-6"
            onClick={() => setLightboxIndex(null)}
          >
            {/* Close Button */}
            <button
              className="absolute top-6 right-6 text-white/70 hover:text-white bg-white/10 hover:bg-white/20 rounded-full p-3 transition-colors backdrop-blur-sm z-50"
              onClick={(e) => {
                e.stopPropagation();
                setLightboxIndex(null);
              }}
            >
              <X size={28} />
            </button>

            {/* Left Arrow */}
            <button
              className="absolute left-6 text-white/70 hover:text-white bg-white/10 hover:bg-white/20 rounded-full p-4 transition-colors backdrop-blur-sm z-50"
              onClick={prevImage}
            >
              <ChevronLeft size={36} />
            </button>

            {/* Right Arrow */}
            <button
              className="absolute right-6 text-white/70 hover:text-white bg-white/10 hover:bg-white/20 rounded-full p-4 transition-colors backdrop-blur-sm z-50"
              onClick={nextImage}
            >
              <ChevronRight size={36} />
            </button>

            <AnimatePresence mode="wait">
              <motion.img
                key={lightboxIndex}
                src={GALLERY_IMAGES[lightboxIndex].src}
                alt="Agrandissement"
                initial={{ scale: 0.9, opacity: 0, x: 20 }}
                animate={{ scale: 1, opacity: 1, x: 0 }}
                exit={{ scale: 0.9, opacity: 0, x: -20 }}
                transition={{ type: "spring", damping: 25, stiffness: 300 }}
                className="max-w-full max-h-[90vh] rounded-xl shadow-2xl object-contain relative z-40"
                onClick={(e) => e.stopPropagation()}
              />
            </AnimatePresence>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
