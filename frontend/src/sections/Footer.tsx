import React from 'react';
import { motion } from 'framer-motion';
import { Mail, Linkedin, Github, Instagram, Link2, Globe, Building2, Phone } from 'lucide-react';

/* ------------------------------------------------------------------ */
/* Animations (Framer Motion)                                         */
/* ------------------------------------------------------------------ */

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.15,
      delayChildren: 0.1,
    }
  }
};

const columnVariants = {
  hidden: { opacity: 0, y: 30 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.8,
      ease: 'easeOut',
    }
  }
};

const lineVariants = {
  hidden: { scaleX: 0, opacity: 0 },
  show: {
    scaleX: 1,
    opacity: 1,
    transition: { duration: 0.8, ease: "easeInOut" }
  }
};

const copyrightVariants = {
  hidden: { opacity: 0, y: 15 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: "easeOut" }
  }
};

/* ------------------------------------------------------------------ */
/* Styles CSS Injectés (Keyframes pour les animations continues)       */
/* ------------------------------------------------------------------ */

const injectedStyles = `
  @keyframes shimmer-sweep {
    0% { transform: translateX(-150%) skewX(-15deg); }
    20% { transform: translateX(200%) skewX(-15deg); }
    100% { transform: translateX(200%) skewX(-15deg); }
  }
  .animate-shimmer-fast {
    animation: shimmer-sweep 8s infinite;
  }
  .animate-shimmer-slow {
    animation: shimmer-sweep 15s infinite;
  }

  @keyframes float-1 {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(30px, -50px) scale(1.1); }
    66% { transform: translate(-20px, 20px) scale(0.9); }
  }
  @keyframes float-2 {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(-30px, 40px) scale(0.9); }
    66% { transform: translate(40px, -20px) scale(1.1); }
  }
  .animate-blob-1 { animation: float-1 25s infinite ease-in-out; }
  .animate-blob-2 { animation: float-2 30s infinite ease-in-out; }
  
  @keyframes logo-pulse {
    0%, 100% { filter: drop-shadow(0 0 2px rgba(18,19,26,0.05)); }
    50% { filter: drop-shadow(0 0 12px rgba(18,19,26,0.15)); }
  }
  .animate-logo-pulse {
    animation: logo-pulse 4s infinite ease-in-out;
  }
  
  @keyframes traveling-light {
    0% { left: -20%; }
    40% { left: 120%; }
    100% { left: 120%; }
  }
  .animate-traveling-light {
    animation: traveling-light 6s infinite ease-in-out;
  }
`;

/* ------------------------------------------------------------------ */
/* Composants Réutilisables                                            */
/* ------------------------------------------------------------------ */

const ContactLink = ({ icon: Icon, href, text }: { icon: any, href: string, text: string }) => (
  <li>
    <a 
      href={href} 
      target="_blank" 
      rel="noopener noreferrer"
      className="group flex items-start gap-3 text-[#4b4e5c] hover:text-[#c2410c] transition-colors duration-300 w-fit py-1"
    >
      <Icon size={18} className="shrink-0 transition-transform duration-300 ease-out group-hover:scale-110 group-hover:rotate-[3deg] group-hover:translate-x-1 mt-0.5" />
      <span className="relative overflow-hidden block">
        {/* Typographie optimisée pour éviter les coupures disgracieuses */}
        <span className="block transition-transform duration-300 ease-out group-hover:translate-x-1.5 text-[13px] xl:text-sm leading-snug break-words max-w-[200px] sm:max-w-none">
          {text}
        </span>
        <span className="absolute left-0 bottom-0 w-full h-[1px] bg-[#c2410c] origin-left scale-x-0 transition-transform duration-300 ease-out group-hover:scale-x-100" />
      </span>
    </a>
  </li>
);

const SocialIcon = ({ icon: Icon, href, hoverClass }: { icon: any, href: string, hoverClass: string }) => (
  <a
    href={href}
    target="_blank"
    rel="noopener noreferrer"
    className={`w-12 h-12 rounded-full bg-white border border-[#e4e7f0] shadow-sm flex items-center justify-center text-[#4b4e5c] transition-all duration-300 group ${hoverClass}`}
  >
    <Icon size={20} className="transition-transform duration-300 ease-out group-hover:scale-[1.15] group-hover:rotate-[4deg]" />
  </a>
);

/* ------------------------------------------------------------------ */
/* Main Footer Component                                               */
/* ------------------------------------------------------------------ */

export function Footer() {
  return (
    <footer id="contact" className="relative bg-[#fbfcfd] pt-28 pb-10 px-6 overflow-hidden border-t border-[#12131a]/5">
      
      {/* Injection des CSS Keyframes */}
      <style>{injectedStyles}</style>

      {/* Background Animé (Blobs) */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
        <div className="absolute top-[-10%] left-[-5%] w-[40vw] h-[40vw] max-w-[600px] max-h-[600px] rounded-full bg-[#0ea5e9]/5 blur-[120px] animate-blob-1" />
        <div className="absolute bottom-[-10%] right-[-5%] w-[35vw] h-[35vw] max-w-[500px] max-h-[500px] rounded-full bg-[#f59e0b]/5 blur-[100px] animate-blob-2" />
      </div>

      <motion.div 
        className="max-w-7xl mx-auto relative z-10"
        variants={containerVariants}
        initial="hidden"
        whileInView="show"
        viewport={{ once: true, margin: "-50px" }}
      >
        {/* CARTE UNIFIÉE (La vraie structure de grille pro) */}
        <div className="group/card relative overflow-hidden bg-white/40 backdrop-blur-2xl border border-white/60 shadow-[0_4px_24px_rgba(0,0,0,0.02)] rounded-[2.5rem] p-8 md:p-12 mb-12 transition-all duration-700 hover:shadow-[0_12px_40px_rgba(0,0,0,0.05)] hover:bg-white/60">
          
          {/* Shimmer effect transversal unifié */}
          <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden rounded-[2.5rem]">
            <div className="absolute top-0 bottom-0 left-0 w-[300px] bg-gradient-to-r from-transparent via-white/50 to-transparent animate-shimmer-slow opacity-40 group-hover/card:opacity-100 transition-opacity duration-700" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10 lg:gap-12 relative z-10">
            
            {/* Col 1 — À Propos / Marque */}
            <motion.div variants={columnVariants} className="flex flex-col h-full">
              <a href="#" className="relative w-fit inline-block font-serif text-3xl font-bold tracking-tight text-[#12131a] mb-6 transition-transform duration-300 hover:scale-[1.02] origin-left animate-logo-pulse">
                <span className="relative z-10">NEXORA</span>
                <span className="absolute inset-0 z-20 bg-gradient-to-r from-transparent via-white to-transparent bg-clip-text text-transparent animate-shimmer-fast pointer-events-none mix-blend-lighten" />
              </a>
              <p className="text-[#8a8d9c] text-[13px] xl:text-sm leading-relaxed pr-4">
                Audit intelligent de la chaîne d'approvisionnement logicielle. 
                Sécurisez vos dépôts en temps réel.
              </p>
            </motion.div>

            {/* Col 2 — Contact */}
            <motion.div variants={columnVariants} className="flex flex-col h-full">
              <h4 className="font-semibold text-[#12131a] mb-6 tracking-wide">Contact</h4>
              <ul className="space-y-3">
                <ContactLink icon={Mail} href="mailto:youssef.berrissoul1@gmail.com" text="youssef.berrissoul1@gmail.com" />
                <ContactLink icon={Linkedin} href="https://www.linkedin.com/in/youssef-berrissoul/" text="LinkedIn" />
                <ContactLink icon={Github} href="https://github.com/YoussefBerrissoul1" text="GitHub" />
                <ContactLink icon={Instagram} href="https://www.instagram.com/you_ssef__03/" text="Instagram" />
                <ContactLink icon={Link2} href="https://linktr.ee/YoussefBerrissoul" text="Linktree" />
              </ul>
            </motion.div>

            {/* Col 3 — Entreprise d'accueil */}
            <motion.div variants={columnVariants} className="flex flex-col h-full">
              <h4 className="font-semibold text-[#12131a] mb-6 tracking-wide">Entreprise d'accueil</h4>
              <ul className="space-y-3">
                <ContactLink icon={Building2} href="https://www.srm-fm.ma" text="SRM-FM Fès-Meknès" />
                <ContactLink icon={Globe} href="https://www.srm-fm.ma" text="www.srm-fm.ma" />
                <ContactLink icon={Mail} href="mailto:contact@srm-fm.ma" text="contact@srm-fm.ma" />
                <ContactLink icon={Phone} href="tel:+212535550000" text="+212 5 35 55 00 00" />
                <ContactLink icon={Linkedin} href="https://www.linkedin.com/company/société-régionale-multiservices-fès-meknès-s-a" text="Page LinkedIn" />
              </ul>
            </motion.div>

            {/* Col 4 — Réseaux Sociaux */}
            <motion.div variants={columnVariants} className="flex flex-col h-full">
              <h4 className="font-semibold text-[#12131a] mb-6 tracking-wide">Réseaux Sociaux</h4>
              <div className="flex flex-wrap gap-4">
                <SocialIcon 
                  icon={Linkedin} 
                  href="https://www.linkedin.com/in/youssef-berrissoul/" 
                  hoverClass="hover:bg-[#0a66c2] hover:text-white hover:border-[#0a66c2] hover:shadow-[0_0_16px_rgba(10,102,194,0.4)]" 
                />
                <SocialIcon 
                  icon={Github} 
                  href="https://github.com/YoussefBerrissoul1" 
                  hoverClass="hover:bg-[#12131a] hover:text-white hover:border-[#12131a] hover:shadow-[0_0_16px_rgba(18,19,26,0.3)]" 
                />
                <SocialIcon 
                  icon={Instagram} 
                  href="https://www.instagram.com/you_ssef__03/" 
                  hoverClass="hover:bg-gradient-to-tr hover:from-[#f09433] hover:via-[#e6683c] hover:to-[#bc1888] hover:text-white hover:border-transparent hover:shadow-[0_0_16px_rgba(225,48,108,0.4)]" 
                />
                <SocialIcon 
                  icon={Link2} 
                  href="https://linktr.ee/YoussefBerrissoul" 
                  hoverClass="hover:bg-[#43e660] hover:text-[#12131a] hover:border-[#43e660] hover:shadow-[0_0_16px_rgba(67,230,96,0.4)]" 
                />
              </div>
            </motion.div>

          </div>
        </div>

        {/* Ligne de séparation animée */}
        <motion.div 
          variants={lineVariants}
          className="relative w-full h-[1px] bg-gradient-to-r from-transparent via-[#12131a]/10 to-transparent overflow-hidden mb-8"
        >
          <div className="absolute top-0 h-full w-[150px] bg-gradient-to-r from-transparent via-[#c2410c]/30 to-transparent animate-traveling-light pointer-events-none" />
        </motion.div>

        {/* Bottom bar (Copyright) */}
        <motion.div 
          variants={copyrightVariants}
          className="flex flex-col md:flex-row justify-center items-center gap-2 md:gap-4 text-[#8a8d9c] text-sm px-4 pb-2 text-center"
        >
          <span className="font-medium text-[#12131a]">© 2026 Youssef Berrissoul</span>
          <span className="hidden md:inline-block text-[#e4e7f0]">•</span>
          <span>En collaboration avec la SRM-FM</span>
          <span className="hidden md:inline-block text-[#e4e7f0]">•</span>
          <span>Tous droits réservés.</span>
        </motion.div>

      </motion.div>
    </footer>
  );
}
