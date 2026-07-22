import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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

export function SRMIntegration() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isHovered, setIsHovered] = useState(false);

  useEffect(() => {
    if (isHovered) return;
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % IMAGES.length);
    }, 4500);
    return () => clearInterval(timer);
  }, [isHovered]);

  return (
    <section id="srm-fm" className="py-24 px-6 bg-white">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          
          {/* Text Content */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: false, amount: 0.1, margin: "-100px" }}
            transition={{ duration: 0.6 }}
          >
            <h2 className="font-serif text-4xl md:text-5xl font-bold mb-6 text-[#12131a]">
              Intégration SRM-FM
            </h2>
            <p className="text-xl text-[#4b4e5c] mb-10 font-light leading-relaxed">
              Ne travaillez plus en silos. NEXORA s'intègre nativement à vos processus de Security Risk Management (SRM) pour unifier la vision technique et managériale du risque cyber.
            </p>
            
            <ul className="space-y-4">
              {BENEFITS.map((benefit, idx) => (
                <motion.li 
                  key={idx}
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: false, amount: 0.1 }}
                  transition={{ delay: idx * 0.1 + 0.3 }}
                  className="flex items-start gap-3"
                >
                  <CheckCircle2 className="w-6 h-6 text-[#15803d] shrink-0 mt-0.5" />
                  <span className="text-lg text-[#12131a]">{benefit}</span>
                </motion.li>
              ))}
            </ul>
          </motion.div>

          {/* Slideshow */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: false, amount: 0.1, margin: "-100px" }}
            transition={{ duration: 0.6 }}
            className="relative rounded-2xl overflow-hidden aspect-[4/3] shadow-2xl bg-[#07080b]"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
          >
            <AnimatePresence mode="wait">
              <motion.img
                key={currentIndex}
                src={IMAGES[currentIndex].src}
                alt={IMAGES[currentIndex].alt}
                initial={{ opacity: 0, scale: 1 }}
                animate={{ opacity: 1, scale: 1.06 }}
                exit={{ opacity: 0 }}
                transition={{ 
                  opacity: { duration: 0.8 },
                  scale: { duration: 5, ease: "linear" }
                }}
                className="absolute inset-0 w-full h-full object-cover"
                onError={(e) => {
                  e.currentTarget.style.display = 'none';
                }}
              />
            </AnimatePresence>
            
            {/* Dots indicator */}
            <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex gap-2 z-10">
              {IMAGES.map((_, idx) => (
                <button
                  key={idx}
                  onClick={() => setCurrentIndex(idx)}
                  className={`w-2 h-2 rounded-full transition-all duration-300 ${
                    idx === currentIndex ? 'bg-white w-6' : 'bg-white/50 hover:bg-white/80'
                  }`}
                  aria-label={`Go to slide ${idx + 1}`}
                />
              ))}
            </div>
          </motion.div>

        </div>
      </div>
    </section>
  );
}
