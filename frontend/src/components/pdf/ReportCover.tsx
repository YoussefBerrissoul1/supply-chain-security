import React from 'react';
import logoSrm from '@assets/logo_srm.png';

interface ReportCoverProps {
  repoUrl: string;
}

export function ReportCover({ repoUrl }: ReportCoverProps) {
  const date = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <div className="w-[210mm] h-[297mm] bg-[#07080b] text-white flex flex-col relative overflow-hidden" id="pdf-page-cover">
      {/* Background styling for premium look */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(194,65,12,0.15),transparent_50%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-5 pointer-events-none" />

      {/* Header Logos */}
      <div className="px-[20mm] pt-[20mm] flex justify-between items-start relative z-10">
        <div>
          <h1 className="font-serif text-4xl font-bold tracking-tight">NEXORA</h1>
          <p className="text-[#8a8d9c] text-sm uppercase tracking-widest mt-1">Plateforme d'analyse IA</p>
        </div>
        <div className="w-24 h-24 bg-white rounded-xl p-3 shadow-2xl flex items-center justify-center">
          <img src={logoSrm} alt="Logo SRM-FM" className="w-full h-full object-contain" />
        </div>
      </div>

      {/* Main Title Area */}
      <div className="flex-1 px-[20mm] flex flex-col justify-center relative z-10">
        <div className="w-16 h-1 bg-[#c2410c] mb-8" />
        <h2 className="text-[#8a8d9c] uppercase tracking-[0.2em] font-semibold mb-4">Rapport de Sécurité Officiel</h2>
        <h3 className="font-serif text-6xl font-bold leading-[1.1] mb-6">
          Évaluation<br />des Risques &<br />Vulnérabilités
        </h3>
        
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-md max-w-lg mt-8">
          <p className="text-sm text-[#8a8d9c] mb-1">Cible de l'analyse :</p>
          <p className="font-mono text-lg text-white break-all">{repoUrl}</p>
        </div>
      </div>

      {/* Footer of cover */}
      <div className="px-[20mm] pb-[20mm] flex justify-between items-end relative z-10">
        <div>
          <p className="text-[#8a8d9c] text-sm">Généré le</p>
          <p className="font-medium capitalize">{date}</p>
          <p className="text-xs text-[#8a8d9c] mt-4 uppercase tracking-widest font-semibold">Réalisé par YOUSSEF BERRISOUL</p>
        </div>
        <div className="text-right">
          <p className="text-[#8a8d9c] text-sm">Classification</p>
          <p className="font-bold text-[#c2410c]">CONFIDENTIEL - USAGE INTERNE</p>
        </div>
      </div>
    </div>
  );
}
