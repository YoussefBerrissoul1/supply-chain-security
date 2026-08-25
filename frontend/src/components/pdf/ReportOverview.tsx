import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { Layers, Box, ShieldAlert } from 'lucide-react';
import { RiskMatrix } from '@/components/RiskMatrix';

interface ReportOverviewProps {
  data: ScanResult;
}

export function ReportOverview({ data }: ReportOverviewProps) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return '#15803d';
    if (score >= 60) return '#b45309';
    return '#b91c1c';
  };

  const scoreColor = getScoreColor(data.score);

  return (
    <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm]" id="pdf-page-overview">
      <div className="mb-6 border-b border-[#e4e7f0] pb-4 shrink-0">
        <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-1">Synthèse Exécutive</h2>
        <p className="text-[#4b4e5c] text-sm">Aperçu global de l'analyse de sécurité et statistiques principales.</p>
      </div>

      <div className="flex gap-6 mb-6 shrink-0">
        {/* Score Card */}
        <div className="bg-[#f7f8fb] rounded-2xl p-6 border border-[#e4e7f0] flex-1 flex flex-col items-center justify-center relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-transparent to-[#12131a]/5 rounded-bl-[80px] pointer-events-none" />
          <h3 className="text-xs font-semibold text-[#8a8d9c] uppercase tracking-widest mb-3">Score de Sécurité</h3>
          <div className="flex items-baseline gap-1">
            <span className="font-mono text-7xl font-black leading-none" style={{ color: scoreColor }}>
              {data.score}
            </span>
            <span className="text-xl text-[#8a8d9c] font-mono">/100</span>
          </div>
          <div className="mt-3 px-3 py-1 rounded-full text-xs font-bold border bg-white" style={{ borderColor: `${scoreColor}40`, color: scoreColor }}>
            {data.score >= 80 ? 'Niveau Adéquat' : data.score >= 60 ? 'Risques Modérés' : 'Niveau Critique'}
          </div>
        </div>

        {/* Info Card */}
        <div className="bg-white rounded-2xl border border-[#e4e7f0] p-6 flex-1 shadow-sm flex flex-col justify-center space-y-4">
          <div>
            <div className="text-[10px] text-[#8a8d9c] uppercase font-bold tracking-wider mb-1 flex items-center gap-1.5">
              {data.type === 'github' ? <Box size={12} /> : <Layers size={12} />}
              Cible Analysée
            </div>
            <div className="font-mono text-lg text-[#12131a] font-bold break-all leading-tight">{data.target}</div>
          </div>

          <div>
            <div className="text-[10px] text-[#8a8d9c] uppercase font-bold tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldAlert size={12} />
              Vulnérabilités
            </div>
            <div className="font-mono text-xl text-[#12131a] font-bold">{data.vulns.length} détectées</div>
          </div>
        </div>
      </div>

      {/*
        FIX: hauteur FIXE (au lieu de `flex-1 min-h-0`) pour que la matrice
        n'entre plus en conflit d'espace avec les sections qui suivent.
        C'était la cause du chevauchement "Métriques Détaillées" / matrice
        et du bloc "Configuration Docker" tronqué en bas de page.
      */}
      <div className="mb-6 border border-[#e4e7f0] rounded-2xl p-4 bg-white shadow-sm flex flex-col items-center">
        <h3 className="font-serif text-lg font-bold text-[#12131a] mb-2 text-center shrink-0">Matrice des Risques</h3>
        <RiskMatrix vulns={data.vulns} isInteractive={false} isPdfMode={true} />
      </div>

      <h3 className="font-serif text-xl font-bold text-[#12131a] mb-4 shrink-0">Métriques Détaillées</h3>
      <div className="grid grid-cols-4 gap-4 shrink-0">
        {data.stats.map((stat, idx) => (
          <div key={idx} className="bg-[#f7f8fb] border border-[#e4e7f0] rounded-xl p-4 flex flex-col items-center text-center">
            <span className="font-mono text-2xl font-bold text-[#12131a] mb-1">{stat.value}</span>
            <span className="text-[#4b4e5c] text-xs font-medium leading-tight">{stat.label}</span>
          </div>
        ))}
      </div>

      {/*
        La Configuration Docker a été déplacée sur sa propre page
        (voir ReportDockerConfig.tsx) : elle ne risque plus de sortir
        de la page ou de se faire couper.
      */}
    </div>
  );
}
