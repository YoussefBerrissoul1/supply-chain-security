import React, { useEffect, useRef, useState, useCallback } from 'react';
import { motion, useScroll } from 'framer-motion';
import { useLocation } from 'wouter';
import { MagneticButton } from './MagneticButton';
import { Menu, X } from 'lucide-react';

const LINKS = [
  { label: 'Projet',           href: '#projet' },
  { label: 'Comment ça marche', href: '#terminal' },
  { label: 'SRM-FM',           href: '#srm-fm' },
  { label: 'Résultats',        href: '#score' },
  { label: 'Contact',          href: '#contact' },
];

// How long (ms) to suppress scroll-spy after a programmatic scroll
const SCROLL_LOCKOUT = 750;

export function Navbar() {
  const { scrollY } = useScroll();
  const [, setLocation] = useLocation();
  const [isScrolled, setIsScrolled]         = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeTab, setActiveTab]           = useState(LINKS[0].label);

  // While true, scroll-spy won't overwrite activeTab
  const spyLocked = useRef(false);
  const spyTimer  = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ── scroll-spy via IntersectionObserver ───────────────────────── */
  useEffect(() => {
    const navbarH = 80; // px — keep in sync with h-20
    const observers: IntersectionObserver[] = [];

    LINKS.forEach((link) => {
      const el = document.querySelector<HTMLElement>(link.href);
      if (!el) return;

      const obs = new IntersectionObserver(
        ([entry]) => {
          if (spyLocked.current) return;       // locked → ignore
          if (entry.isIntersecting) setActiveTab(link.label);
        },
        {
          // rootMargin accounts for fixed navbar; 60% threshold prevents
          // flickering when two sections overlap near the viewport center
          rootMargin: `-${navbarH}px 0px -40% 0px`,
          threshold: 0,
        }
      );

      obs.observe(el);
      observers.push(obs);
    });

    return () => observers.forEach((o) => o.disconnect());
  }, []);

  /* ── navbar background on scroll ───────────────────────────────── */
  useEffect(() => {
    return scrollY.onChange((latest) => {
      setIsScrolled(latest > window.innerHeight * 0.8);
    });
  }, [scrollY]);

  /* ── click handler: immediate active + lock spy ─────────────────── */
  const handleNavClick = useCallback(
    (e: React.MouseEvent<HTMLAnchorElement>, link: (typeof LINKS)[0]) => {
      e.preventDefault();

      // 1. Update active state immediately
      setActiveTab(link.label);

      // 2. Lock the scroll-spy so it can't overwrite during the animation
      spyLocked.current = true;
      if (spyTimer.current) clearTimeout(spyTimer.current);
      spyTimer.current = setTimeout(() => {
        spyLocked.current = false;
      }, SCROLL_LOCKOUT);

      // 3. Smooth scroll
      document.querySelector(link.href)?.scrollIntoView({ behavior: 'smooth' });
    },
    []
  );

  return (
    <motion.header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
        isScrolled
          ? 'bg-white/70 backdrop-blur-xl saturate-150 border-b border-[#12131a]/5 text-[#12131a]'
          : 'bg-[#07080b]/35 backdrop-blur-sm text-white'
      }`}
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
        <a href="#" className="font-serif text-2xl font-bold tracking-tight">
          NEXORA
        </a>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-8 relative">
          {LINKS.map((link) => (
            <a
              key={link.label}
              href={link.href}
              className={`text-sm font-medium transition-colors relative px-2 py-1 ${
                isScrolled ? 'hover:text-[#c2410c]' : 'hover:text-white/80'
              }`}
              onClick={(e) => handleNavClick(e, link)}
            >
              {link.label}
              {activeTab === link.label && (
                <motion.div
                  layoutId="nav-indicator"
                  className={`absolute -bottom-1 left-0 right-0 h-[2px] ${
                    isScrolled ? 'bg-[#c2410c]' : 'bg-white'
                  }`}
                  transition={{ type: 'spring', stiffness: 400, damping: 35 }}
                />
              )}
            </a>
          ))}
        </nav>

        <div className="hidden md:block">
          <MagneticButton
            className="px-6 py-2.5 text-sm"
            onClick={() => setLocation('/scan')}
          >
            Lancer un scan
          </MagneticButton>
        </div>

        {/* Mobile Toggle */}
        <button
          className="md:hidden p-2 -mr-2"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          aria-label="Ouvrir / fermer le menu"
        >
          {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {/* Mobile Menu */}
      <motion.div
        className="md:hidden overflow-hidden bg-white text-[#12131a] absolute w-full top-20 shadow-2xl"
        initial={false}
        animate={{ height: isMobileMenuOpen ? 'auto' : 0, opacity: isMobileMenuOpen ? 1 : 0 }}
        transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
      >
        <div className="px-6 py-6 flex flex-col gap-4 border-b border-[#12131a]/5">
          {LINKS.map((link, i) => (
            <motion.a
              key={link.label}
              href={link.href}
              className="text-lg font-medium py-2 border-b border-[#12131a]/5"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: isMobileMenuOpen ? 1 : 0, x: isMobileMenuOpen ? 0 : -20 }}
              transition={{ delay: i * 0.05 + 0.1 }}
              onClick={(e) => {
                setIsMobileMenuOpen(false);
                handleNavClick(e, link);
              }}
            >
              {link.label}
            </motion.a>
          ))}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: isMobileMenuOpen ? 1 : 0, y: isMobileMenuOpen ? 0 : 10 }}
            transition={{ delay: 0.3 }}
            className="pt-4"
          >
            <MagneticButton
              className="w-full py-3"
              onClick={() => {
                setIsMobileMenuOpen(false);
                setLocation('/scan');
              }}
            >
              Lancer un scan
            </MagneticButton>
          </motion.div>
        </div>
      </motion.div>
    </motion.header>
  );
}
