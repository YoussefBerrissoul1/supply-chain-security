import React from 'react';
import logoSrm from '@assets/logo_srm.png';

interface ReportCoverProps {
  repoUrl: string;
}

export function ReportCover({ repoUrl }: ReportCoverProps) {
  const date = new Date().toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });

  // Extract repo name from URL
  const repoName = repoUrl.replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\/$/, '');

  return (
    <div className="w-[210mm] h-[297mm] bg-[#05070A] text-[#F8FAFC] flex flex-col relative overflow-hidden font-sans" id="pdf-page-cover">
      
      {/* Left Orange Vertical Line */}
      <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-[#F97316] z-50" />

      {/* ================= BACKGROUND ================= */}
      <div className="absolute inset-0 pointer-events-none z-0">
        {/* Subtle orange radial glow top right (Reduced size/opacity) */}
        <div className="absolute -top-20 -right-20 w-[300px] h-[300px] bg-[#F97316] opacity-[0.04] blur-[80px] rounded-full" />
        
       

        {/* Technical lines */}
        <div className="absolute left-[25mm] top-0 bottom-0 w-px bg-[rgba(255,255,255,0.02)]" />
        <div className="absolute right-[20mm] top-0 bottom-0 w-px bg-[rgba(255,255,255,0.02)]" />
        <div className="absolute left-0 right-0 top-[30mm] h-px bg-[rgba(255,255,255,0.02)]" />
        <div className="absolute left-0 right-0 bottom-[30mm] h-px bg-[rgba(255,255,255,0.02)]" />
        
        {/* Subtle Grid */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGcgc3Ryb2tlPSJyZ2JhKDI1NSwyNTUsMjU1LDAuMDMpIiBmaWxsPSJub25lIj48cGF0aCBkPSJNMCAwaDQwdjQwSDB6Ii8+PC9nPjwvc3ZnPg==')] opacity-40" />
        
        {/* Noise slightly more visible */}
        <div className="absolute inset-0 opacity-[0.03] mix-blend-overlay bg-[url('https://www.transparenttextures.com/patterns/stardust.png')]" />
      </div>

      {/* ================= HEADER ================= */}
      <div className="w-full px-[25mm] pt-[15mm] z-10">
        <div className="flex justify-between items-start pb-6 border-b border-[rgba(255,255,255,0.1)]">
          <div className="flex flex-col gap-1">
            <h1 className="text-3xl font-bold tracking-tight text-[#F8FAFC]">NEXORA</h1>
            <p className="text-xs text-[#94A3B8] uppercase tracking-[0.15em] font-medium">Supply Chain Security Platform</p>
            <p className="text-[10px] text-[#F97316] uppercase tracking-widest font-semibold mt-0.5">Enterprise Security Assessment</p>
          </div>
          {/* Logo SRM bigger and better aligned */}
          <div className="w-20 h-20 bg-white rounded-lg p-1.5 shadow-lg border border-[rgba(255,255,255,0.1)] flex items-center justify-center -mt-2">
            <img src={logoSrm} alt="Logo SRM-FM" className="w-full h-full object-contain" />
          </div>
        </div>
      </div>

      {/* ================= MAIN CONTENT ================= */}
      <div className="flex-1 px-[25mm] flex flex-col justify-center z-10 w-full pb-[10mm]">
        
        {/* Confidential Badge & Version */}
        <div className="mb-10 flex justify-between items-center">
          <div className="inline-flex items-center gap-4 bg-[#0F1115] border border-[rgba(255,255,255,0.1)] px-5 py-2.5 rounded-full shadow-lg">
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#F97316] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#F97316]"></span>
            </span>
            <span className="text-xs font-bold text-[#F8FAFC] uppercase tracking-widest">Confidentiel</span>
            <span className="w-px h-4 bg-[rgba(255,255,255,0.15)]"></span>
            <span className="text-xs text-[#94A3B8] uppercase tracking-wider font-medium">Usage Interne</span>
          </div>
          <div className="text-right">
            <p className="text-[#F8FAFC] font-bold text-sm">Version 2.0</p>
            <p className="text-[#94A3B8] text-xs">Security Assessment Report</p>
          </div>
        </div>

        {/* Title */}
        <div className="flex flex-col mb-10">
          <h2 className="text-[#F97316] text-xs uppercase tracking-[0.25em] font-bold mb-4 flex items-center gap-3">
            <div className="w-8 h-px bg-[#F97316]/60"></div>
            Rapport Officiel de Cybersécurité
          </h2>
          {/* Removed bg-clip-text which breaks html2canvas */}
          <h3 className="text-[3.25rem] font-extrabold leading-[1.15] tracking-tight text-[#F8FAFC] mb-6 font-serif">
            Évaluation des Risques <br />
            <span className="text-[#D1D5DB]">& Vulnérabilités</span>
          </h3>
          <p className="text-base text-[#94A3B8] max-w-lg leading-relaxed font-medium">
            Analyse automatisée de la posture de sécurité des dépôts GitHub, des dépendances logicielles et des images Docker avec détection des vulnérabilités et recommandations basées sur l'IA.
          </p>
        </div>

        <div className="w-full h-px bg-[rgba(255,255,255,0.05)] mb-8"></div>

        {/* Repository Section */}
        <div className="bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.1)] rounded-xl p-6 mb-8 relative overflow-hidden group">
          <div className="relative z-10 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Repository Analysé</h4>
              <div className="flex gap-2">
                <span className="px-2 py-1 text-[9px] uppercase tracking-wider font-semibold rounded bg-white/5 text-white/70 border border-white/10">Repository Public</span>
                <span className="px-2 py-1 text-[9px] uppercase tracking-wider font-semibold rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">Python</span>
              </div>
            </div>
            
            <div className="flex items-center gap-4 mb-2">
              <svg className="w-8 h-8 text-[#F8FAFC]" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              <span className="text-[1.75rem] font-bold text-[#F8FAFC] tracking-tight">{repoName}</span>
            </div>
            <p className="text-sm text-[#94A3B8] font-mono">{repoUrl}</p>
          </div>
        </div>

        {/* Visual Summary */}
        <div className="flex flex-wrap gap-x-6 gap-y-3 mb-8">
          {[
            'GitHub Repository', 'Dependency Analysis', 'Docker Image Scan',
            'SBOM Generation', 'CVE Detection', 'AI Recommendations'
          ].map(item => (
            <div key={item} className="flex items-center gap-2">
              <svg className="w-4 h-4 text-[#F97316]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-xs text-[#E5E7EB] font-medium">{item}</span>
            </div>
          ))}
        </div>
        
        <div className="w-full h-px bg-[rgba(255,255,255,0.05)] mb-8"></div>

        {/* Technologies */}
        <div className="mb-10">
          <h4 className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold mb-4">Technologies Utilisées</h4>
          <div className="flex flex-wrap gap-3">
            {[
              {name: 'GitHub', icon: <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>},
              {name: 'Docker', icon: <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.81 0h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0-2.416h2.118a.186.186 0 00.186-.186V6.593a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.186.185.186m-2.81 2.416h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0-2.416h2.118a.186.186 0 00.186-.186V6.593a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.186.185.186m0-2.415h2.118a.186.186 0 00.186-.185V4.177a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.81 4.831h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.81 0h2.119a.186.186 0 00.185-.185V9.006a.186.186 0 00-.185-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m14.337-3.206a4.583 4.583 0 00-.73-2.582c-.207-.326-.51-.529-.86-.529-.395 0-.746.242-1.01.691-.258.437-.417 1.054-.46 1.765a2.412 2.412 0 00-.916-.188h-1.077c-.104 0-.188.083-.188.188v2.709c0 .104.084.187.188.187h12.187c.103 0 .187-.083.187-.187v-1.867c0-.105-.084-.188-.187-.188zM4.17 12.964c-2.3 0-4.17 1.868-4.17 4.168 0 2.302 1.87 4.17 4.17 4.17h15.66c2.3 0 4.17-1.868 4.17-4.17 0-2.3-1.87-4.168-4.17-4.168H4.17z"/></svg>},
              {name: 'Trivy', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>},
              {name: 'OSV', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>},
              {name: 'SBOM', icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>},
              {name: 'Gemini AI', icon: <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2.25c.34 3.738 2.872 7.022 6.388 8.163-3.516 1.141-6.048 4.425-6.388 8.163-.34-3.738-2.872-7.022-6.388-8.163C9.128 9.272 11.66 5.988 12 2.25z"/></svg>}
            ].map(tech => (
              <div key={tech.name} className="bg-[#12141A] border border-[rgba(255,255,255,0.15)] rounded-lg px-4 py-2 text-xs text-[#E5E7EB] font-semibold flex items-center gap-2 shadow-sm">
                <div className="text-[#94A3B8]">{tech.icon}</div>
                {tech.name}
              </div>
            ))}
          </div>
        </div>

        <div className="w-full h-px bg-[rgba(255,255,255,0.05)] mb-8"></div>

        {/* Info Grid */}
        <div className="grid grid-cols-3 gap-y-8 gap-x-6">
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[#F97316] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Auteur</span>
            <span className="text-sm font-bold text-[#F8FAFC]">YOUSSEF BERRISOUL</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Entreprise</span>
            <span className="text-sm font-bold text-[#F8FAFC]">SRM-FM & ENSIASD</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Date</span>
            <span className="text-sm font-bold text-[#F8FAFC] capitalize">{date}</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Version</span>
            <span className="text-sm font-bold text-[#F8FAFC] font-mono">1.2.0</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Classification</span>
            <span className="text-sm font-bold text-[#F97316]">Strict</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Plateforme</span>
            <span className="text-sm font-bold text-[#F8FAFC]">NEXORA AI Engine</span>
          </div>
        </div>

      </div>

      {/* ================= FOOTER ================= */}
      <div className="w-full px-[25mm] pb-[15mm] z-10 mt-auto">
        <div className="flex justify-between items-center pt-5 border-t border-[rgba(255,255,255,0.15)]">
          <div className="flex flex-col">
            <span className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-semibold mb-0.5">Powered by</span>
            <span className="text-[#F8FAFC] text-xs font-bold tracking-widest uppercase">NEXORA AI Engine</span>
          </div>
          <div className="flex flex-col text-right">
            <span className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-semibold mb-0.5">Supply Chain Security Platform</span>
            <span className="text-[#F8FAFC] text-xs font-mono font-bold tracking-widest">© 2026</span>
          </div>
        </div>
      </div>

    </div>
  );
}
