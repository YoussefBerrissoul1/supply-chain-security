import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence, useMotionValue, useTransform, useSpring, useReducedMotion } from 'framer-motion';
import dashboard1 from '@assets/generated_images/dashboard-1.png';
import network2 from '@assets/generated_images/network-2.png';
import code3 from '@assets/generated_images/code-3.png';
import { CheckCircle2 } from 'lucide-react';

const IMAGES = [
  { src: dashboard1, alt: "Cybersecurity dashboard UI" },
  { src: network2, alt: "Security network visualization" },
  { src: code3, alt: "Abstract code security" }
];

const BENEFITS = [
  "Synchronisation bidirectionnelle des incidents",
  "Cartographie complète de la surface d'attaque",
  "Tableaux de bord personnalisés par équipe",
  "Gestion centralisée des remédiations",
  "Exports compatibles avec les standards (ISO 27001)"
];

/* --- Stagger Animations pour le texte --- */
const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.12, delayChildren: 0.1 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 25 },
  show: { opacity: 1, y: 0, transition: { duration: 0.8, ease: "easeOut" } }
};

/* --- Composant interactif pour les bénéfices --- */
const BenefitItem = ({ text }: { text: string }) => (
  <motion.li 
    variants={itemVariants}
    className="group flex items-start gap-4 p-3 -ml-3 rounded-2xl transition-colors duration-300 hover:bg-[#f7f8fb] cursor-default"
    whileHover={{ x: 6 }}
    transition={{ duration: 0.3, ease: "easeOut" }}
  >
    <div className="relative mt-0.5 shrink-0">
      {/* Halo lumineux au survol (Glow) */}
      <div className="absolute inset-0 bg-[#15803d] rounded-full blur-md opacity-0 group-hover:opacity-40 transition-opacity duration-300" />
      <CheckCircle2 className="relative w-6 h-6 text-[#15803d]/70 group-hover:text-[#15803d] transition-all duration-300 group-hover:scale-110" />
    </div>
    <span className="text-lg text-[#4b4e5c] group-hover:text-[#12131a] transition-colors duration-300 font-medium">
      {text}
    </span>
  </motion.li>
);

export function SRMIntegration() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isHovered, setIsHovered] = useState(false);
  const prefersReducedMotion = useReducedMotion();
  const containerRef = useRef<HTMLDivElement>(null);

  /* --- 3D Mouse Tracking (Tilt Effect) --- */
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const springConfig = { damping: 30, stiffness: 150, mass: 1 };
  
  // Rotation maximale de 5 degrés
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [5, -5]), springConfig);
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-5, 5]), springConfig);
  
  // Mouvement du reflet "Glare"
  const glareX = useSpring(useTransform(x, [-0.5, 0.5], [200, -200]), springConfig);
  const glareY = useSpring(useTransform(y, [-0.5, 0.5], [200, -200]), springConfig);

  const handleMouseMove = (e: React.MouseEvent) => {
    if (prefersReducedMotion || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    x.set(mouseX / rect.width - 0.5);
    y.set(mouseY / rect.height - 0.5);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
    setIsHovered(false);
  };

  /* --- Diaporama Automatique --- */
  useEffect(() => {
    if (isHovered) return; // Pause élégante au survol
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % IMAGES.length);
    }, 5500); // 5.5s pour laisser le temps de voir l'effet Ken Burns
    return () => clearInterval(timer);
  }, [isHovered]);

  /* --- Swipe Handlers (Mobile) --- */
  const handleDragEnd = (e: any, { offset }: any) => {
    const swipe = offset.x;
    if (swipe < -40) {
      setCurrentIndex((prev) => (prev + 1) % IMAGES.length);
    } else if (swipe > 40) {
      setCurrentIndex((prev) => (prev === 0 ? IMAGES.length - 1 : prev - 1));
    }
  };

  return (
    <section id="srm-fm" className="py-24 px-6 bg-white overflow-hidden">
      
      {/* Préchargement critique pour éviter les flashs */}
      <div className="hidden" aria-hidden="true">
        {IMAGES.map((img, i) => <img key={i} src={img.src} alt="" />)}
      </div>

      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-20 items-center">
          
          {/* Text Content (Staggered Animation) */}
          <motion.div
            variants={containerVariants}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true, margin: "-100px" }}
          >
            <motion.h2 variants={itemVariants} className="font-serif text-4xl md:text-5xl font-bold mb-6 text-[#12131a] leading-[1.1]">
              Intégration SRM-FM
            </motion.h2>
            <motion.p variants={itemVariants} className="text-xl text-[#4b4e5c] mb-10 font-light leading-relaxed">
              Ne travaillez plus en silos. NEXORA s'intègre nativement à vos processus de Security Risk Management (SRM) pour unifier la vision technique et managériale du risque cyber.
            </motion.p>
            
            <ul className="space-y-2">
              {BENEFITS.map((benefit, idx) => (
                <BenefitItem key={idx} text={benefit} />
              ))}
            </ul>
          </motion.div>

          {/* Slideshow 3D Cinématographique */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 1, ease: "easeOut" }}
            className="relative lg:ml-8"
            style={{ perspective: "1500px" }}
          >
            {/* Halo dynamique à l'arrière plan */}
            <div 
              className="absolute inset-0 bg-gradient-to-tr from-[#15803d]/30 to-[#0ea5e9]/20 blur-[80px] rounded-full transition-all duration-700 ease-out"
              style={{ transform: isHovered ? 'scale(1.05)' : 'scale(0.9)', opacity: isHovered ? 1 : 0.4 }} 
            />

            <motion.div
              ref={containerRef}
              style={{
                rotateX: prefersReducedMotion ? 0 : rotateX,
                rotateY: prefersReducedMotion ? 0 : rotateY,
                transformStyle: "preserve-3d"
              }}
              animate={{ scale: isHovered && !prefersReducedMotion ? 1.02 : 1 }}
              transition={{ duration: 0.4, ease: "easeOut" }}
              onMouseMove={(e) => { handleMouseMove(e); setIsHovered(true); }}
              onMouseLeave={handleMouseLeave}
              className="relative rounded-[2rem] overflow-hidden aspect-[4/3] shadow-[0_20px_80px_rgba(0,0,0,0.15)] bg-[#07080b] border border-white/20 backdrop-blur-xl z-10"
            >
              
              {/* Le Crossfade et le Ken Burns */}
              <AnimatePresence>
                <motion.img
                  key={currentIndex}
                  src={IMAGES[currentIndex].src}
                  alt={IMAGES[currentIndex].alt}
                  initial={{ opacity: 0, scale: 1.1, x: 20 }}
                  animate={{ opacity: 1, scale: 1, x: 0 }}
                  exit={{ opacity: 0, scale: 0.95, x: -20 }}
                  transition={{
                    opacity: { duration: 1.2, ease: "easeInOut" },
                    scale: { duration: 10, ease: "linear" }, // Zoom lent continu
                    x: { duration: 10, ease: "linear" }       // Déplacement lent
                  }}
                  drag="x"
                  dragConstraints={{ left: 0, right: 0 }}
                  dragElastic={0.2}
                  onDragEnd={handleDragEnd}
                  className="absolute inset-0 w-full h-full object-cover will-change-transform cursor-grab active:cursor-grabbing"
                />
              </AnimatePresence>

              {/* Effet "Glare" (Reflet de vitre dynamique) */}
              <motion.div 
                className="absolute inset-0 z-20 pointer-events-none bg-gradient-to-tr from-transparent via-white/15 to-transparent mix-blend-overlay"
                style={{ x: glareX, y: glareY, opacity: isHovered && !prefersReducedMotion ? 1 : 0 }}
                transition={{ opacity: { duration: 0.3 } }}
              />

              {/* Inner Shadow pour renforcer le Glassmorphism */}
              <div className="absolute inset-0 z-10 shadow-[inset_0_0_40px_rgba(255,255,255,0.05)] pointer-events-none rounded-[2rem] border border-white/10" />

              {/* Indicateurs Modernes Animés (Layout Animation) */}
              <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex gap-3 z-30">
                {IMAGES.map((_, idx) => (
                  <button
                    key={idx}
                    onClick={() => setCurrentIndex(idx)}
                    className="relative h-1.5 rounded-full overflow-hidden transition-all duration-500 ease-out flex items-center justify-center bg-white/20 backdrop-blur-md cursor-pointer hover:bg-white/40"
                    style={{ width: idx === currentIndex ? 48 : 16 }}
                    aria-label={`Aller à l'image ${idx + 1}`}
                  >
                    {idx === currentIndex && (
                      <motion.div
                        layoutId="active-dot"
                        className="absolute inset-0 bg-white"
                        initial={false}
                        transition={{ type: "spring", stiffness: 300, damping: 30 }}
                      />
                    )}
                  </button>
                ))}
              </div>
              
            </motion.div>
          </motion.div>

        </div>
      </div>
    </section>
  );
}
