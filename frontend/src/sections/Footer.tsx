import React from 'react';

export function Footer() {
  return (
    <footer id="contact" className="bg-white pt-20 pb-10 px-6 border-t border-[#12131a]/5">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-16">

          {/* Col 1 — Brand */}
          <div className="col-span-1">
            <a href="#" className="font-serif text-2xl font-bold tracking-tight text-[#12131a] mb-4 inline-block">
              NEXORA
            </a>
            <p className="text-[#8a8d9c] text-sm leading-relaxed max-w-xs">
              La plateforme de sécurité applicative conçue pour les équipes de développement modernes.
            </p>
          </div>

          {/* Col 2 — Produit */}
          <div>
            <h4 className="font-semibold text-[#12131a] mb-4">Produit</h4>
            <ul className="space-y-3">
              <li><a href="#comment-ca-marche" className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Fonctionnalités</a></li>
              <li><a href="#srm-fm"             className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Intégrations</a></li>
              <li><a href="#terminal"           className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Comment ça marche</a></li>
              <li><a href="#score"              className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Score de Sécurité</a></li>
            </ul>
          </div>

          {/* Col 3 — Contexte académique */}
          <div>
            <h4 className="font-semibold text-[#12131a] mb-4">Contexte</h4>
            <ul className="space-y-3">
              <li><a href="#srm-entreprise" className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">SRM-FM Fès-Meknès</a></li>
              <li><a href="#projet"          className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">ENSIASD Taroudant</a></li>
              <li><a href="#pont-nexora"     className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Pourquoi NEXORA</a></li>
              <li><a href="#contact"         className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Contact</a></li>
            </ul>
          </div>

          {/* Col 4 — Légal */}
          <div>
            <h4 className="font-semibold text-[#12131a] mb-4">Légal</h4>
            <ul className="space-y-3">
              <li><a href="#" className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Mentions légales</a></li>
              <li><a href="#" className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Politique de confidentialité</a></li>
              <li><a href="#" className="text-[#4b4e5c] hover:text-[#c2410c] text-sm transition-colors">Sécurité</a></li>
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="pt-8 border-t border-[#12131a]/10 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-[#8a8d9c] text-sm">
            © {new Date().getFullYear()} NEXORA. Réalisé par YOUSSEF BERRISOUL.
          </p>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-2 text-sm text-[#4b4e5c]">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#15803d] opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#15803d]" />
              </span>
              Systèmes opérationnels
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
