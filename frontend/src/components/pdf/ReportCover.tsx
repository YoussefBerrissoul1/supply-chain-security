import React from 'react';
import logoSrm from '@assets/logo_srm.png';
import { ScanResult } from '@/pages/ScanPage';

interface ReportCoverProps {
  data: ScanResult;
}

export function ReportCover({ data }: ReportCoverProps) {
  const date = new Date().toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });

  // Extract repo name from URL
  const repoName = data.target.replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\/$/, '');
  const isGithub = data.type === 'github';

  return (
    <div className="w-[210mm] h-[297mm] bg-[#0B0F19] text-[#F8FAFC] flex flex-col relative overflow-hidden font-sans" id="pdf-page-cover">
      
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
      </div>

      {/* ================= HEADER ================= */}
      <div className="w-full px-[25mm] pt-[15mm] z-10">
        <div className="flex justify-between items-start pb-6 border-b border-[rgba(255,255,255,0.1)]">
          <div className="flex flex-col gap-1">
            <h1 className="text-3xl font-bold tracking-tight text-[#F8FAFC]">Supply Chain Security Platform</h1>
            <p className="text-[10px] text-[#F97316] uppercase tracking-widest font-semibold mt-0.5">Enterprise Security Assessment</p>
          </div>
          {/* Logo SRM kept official */}
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
            <p className="text-[#F8FAFC] font-bold text-sm">Version 1.0</p>
            <p className="text-[#94A3B8] text-xs">Security Assessment Report</p>
          </div>
        </div>

        {/* Title */}
        <div className="flex flex-col mb-10">
          <h2 className="text-[#F97316] text-xs uppercase tracking-[0.25em] font-bold mb-4 flex items-center gap-3">
            <div className="w-8 h-px bg-[#F97316]/60"></div>
            Rapport Officiel de Cybersécurité
          </h2>
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
        <div className="bg-[#12141A] border border-[rgba(255,255,255,0.1)] rounded-xl p-6 mb-8 relative overflow-hidden group">
          <div className="relative z-10 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Cible Analysée</h4>
              <div className="flex gap-2">
                <span className="px-2 py-1 text-[9px] uppercase tracking-wider font-semibold rounded bg-white/5 text-white/70 border border-white/10">
                  {isGithub ? 'Repository' : 'Docker Image'}
                </span>
                {data.analysisStatus && data.analysisStatus.toLowerCase() === 'incomplete' && (
                  <span className="px-2 py-1 text-[9px] uppercase tracking-wider font-semibold rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
                    Analyse Partielle
                  </span>
                )}
              </div>
            </div>
            
            <div className="flex items-center gap-4 mb-2">
              {isGithub ? (
                <svg className="w-8 h-8 text-[#F8FAFC]" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              ) : (
                <svg className="w-8 h-8 text-[#F8FAFC]" fill="currentColor" viewBox="0 0 24 24"><path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.81 0h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0-2.416h2.118a.186.186 0 00.186-.186V6.593a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.186.185.186m-2.81 2.416h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0-2.416h2.118a.186.186 0 00.186-.186V6.593a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.186.185.186m0-2.415h2.118a.186.186 0 00.186-.185V4.177a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.81 4.831h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.81 0h2.119a.186.186 0 00.185-.185V9.006a.186.186 0 00-.185-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m14.337-3.206a4.583 4.583 0 00-.73-2.582c-.207-.326-.51-.529-.86-.529-.395 0-.746.242-1.01.691-.258.437-.417 1.054-.46 1.765a2.412 2.412 0 00-.916-.188h-1.077c-.104 0-.188.083-.188.188v2.709c0 .104.084.187.188.187h12.187c.103 0 .187-.083.187-.187v-1.867c0-.105-.084-.188-.187-.188zM4.17 12.964c-2.3 0-4.17 1.868-4.17 4.168 0 2.302 1.87 4.17 4.17 4.17h15.66c2.3 0 4.17-1.868 4.17-4.17 0-2.3-1.87-4.168-4.17-4.168H4.17z"/></svg>
              )}
              <span className="text-[1.75rem] font-bold text-[#F8FAFC] tracking-tight">{repoName}</span>
            </div>
            <p className="text-sm text-[#94A3B8] font-mono mb-3">{data.target}</p>
            
            {/* Added Metadata: Coverage & Commit SHA */}
            <div className="flex gap-4 pt-3 border-t border-[rgba(255,255,255,0.05)]">
              {data.commit_sha && (
                <div className="flex flex-col">
                  <span className="text-[9px] text-[#94A3B8] uppercase tracking-wider font-medium">Commit SHA</span>
                  <span className="text-xs font-mono text-gray-300">{data.commit_sha.substring(0, 8)}</span>
                </div>
              )}
              {data.coverage_percent !== undefined && (
                <div className="flex flex-col">
                  <span className="text-[9px] text-[#94A3B8] uppercase tracking-wider font-medium">Couverture</span>
                  <span className={`text-xs font-bold ${data.coverage_percent < 95 ? 'text-orange-400' : 'text-green-400'}`}>
                    {data.coverage_percent}% des fichiers
                  </span>
                </div>
              )}
            </div>
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

        {/* Info Grid */}
        <div className="grid grid-cols-3 gap-y-8 gap-x-6">
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[#F97316] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Auteur</span>
            <span className="text-sm font-bold text-[#F8FAFC]">YOUSSEF BERRISSOUL</span>
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
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Classification</span>
            <span className="text-sm font-bold text-[#F97316]">Strict</span>
          </div>
          <div className="flex flex-col gap-1.5 border-l-[3px] border-[rgba(255,255,255,0.2)] pl-4 py-1">
            <span className="text-[10px] text-[#94A3B8] uppercase tracking-[0.15em] font-semibold">Moteur</span>
            <span className="text-sm font-bold text-[#F8FAFC]">Multi-Source Engine</span>
          </div>
        </div>

      </div>

      {/* ================= FOOTER ================= */}
      <div className="w-full px-[25mm] pb-[15mm] z-10 mt-auto">
        <div className="flex justify-between items-center pt-5 border-t border-[rgba(255,255,255,0.15)]">
          <div className="flex flex-col">
            <span className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-semibold mb-0.5">Powered by</span>
            <span className="text-[#F8FAFC] text-xs font-bold tracking-widest uppercase">Multi-Source Engine</span>
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
