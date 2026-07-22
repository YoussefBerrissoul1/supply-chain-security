import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportFooter } from './ReportFooter';

interface ReportRecommendationsProps {
  data: ScanResult;
  pageNumber: number;
  totalPages: number;
}

export function ReportRecommendations({ data, pageNumber, totalPages }: ReportRecommendationsProps) {
  return (
    <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm]" id="pdf-page-recommendations">
      <div className="mb-10 border-b border-[#e4e7f0] pb-6">
        <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Recommandations IA & Conclusion</h2>
        <p className="text-[#4b4e5c]">Actions prioritaires recommandées par NEXORA AI.</p>
      </div>

      <div className="bg-[#07080b] rounded-2xl p-8 mb-10 border border-[#c2410c]/20 shadow-xl relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(194,65,12,0.1),transparent_70%)] pointer-events-none" />
        
        <h3 className="text-[#8a8d9c] uppercase tracking-widest text-xs font-bold mb-6 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#c2410c]" />
          Analyse Experte IA
        </h3>
        
        <div className="text-gray-300 font-mono text-sm leading-relaxed whitespace-pre-line relative z-10">
          {data.aiRec}
        </div>
      </div>

      <h3 className="font-serif text-2xl font-bold text-[#12131a] mb-6">Bonnes Pratiques de Sécurité</h3>
      <div className="grid grid-cols-1 gap-4 mb-auto">
        <div className="flex items-start gap-4 p-5 bg-[#f7f8fb] rounded-xl border border-[#e4e7f0]">
          <div className="w-8 h-8 rounded-full bg-white flex items-center justify-center shrink-0 border border-[#e4e7f0] font-bold text-[#12131a]">1</div>
          <div>
            <div className="font-bold text-[#12131a] mb-1">Mises à jour régulières</div>
            <div className="text-sm text-[#4b4e5c]">Intégrez des outils d'analyse SCA (Software Composition Analysis) dans vos pipelines CI/CD pour bloquer les versions vulnérables avant déploiement.</div>
          </div>
        </div>
        <div className="flex items-start gap-4 p-5 bg-[#f7f8fb] rounded-xl border border-[#e4e7f0]">
          <div className="w-8 h-8 rounded-full bg-white flex items-center justify-center shrink-0 border border-[#e4e7f0] font-bold text-[#12131a]">2</div>
          <div>
            <div className="font-bold text-[#12131a] mb-1">Principe du moindre privilège</div>
            <div className="text-sm text-[#4b4e5c]">Réduisez la surface d'attaque en utilisant des images Docker minimalistes (distroless/alpine) et en ne tournant jamais en tant que root.</div>
          </div>
        </div>
        <div className="flex items-start gap-4 p-5 bg-[#f7f8fb] rounded-xl border border-[#e4e7f0]">
          <div className="w-8 h-8 rounded-full bg-white flex items-center justify-center shrink-0 border border-[#e4e7f0] font-bold text-[#12131a]">3</div>
          <div>
            <div className="font-bold text-[#12131a] mb-1">Surveillance continue</div>
            <div className="text-sm text-[#4b4e5c]">Les vulnérabilités évoluent (zero-days). Planifiez des scans hebdomadaires automatiques avec NEXORA pour maintenir votre score de sécurité.</div>
          </div>
        </div>
      </div>

      <div className="mt-8 text-center border-t border-[#e4e7f0] pt-8">
        <p className="font-serif font-bold text-[#12131a] text-lg">Fin du rapport d'analyse</p>
        <p className="text-xs text-[#8a8d9c] mt-1">Ce document est généré automatiquement par la plateforme intelligente NEXORA.</p>
        <p className="text-xs font-semibold text-[#12131a] mt-2 uppercase tracking-widest">Réalisé par YOUSSEF BERRISOUL</p>
      </div>
      <ReportFooter pageNumber={pageNumber} totalPages={totalPages} />
    </div>
  );
}
