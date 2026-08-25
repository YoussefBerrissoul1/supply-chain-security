import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportFooter } from './ReportFooter';

interface ReportConclusionProps {
  data: ScanResult;
  pageNumber: number;
  totalPages: number;
}

export function ReportConclusion({ data, pageNumber, totalPages }: ReportConclusionProps) {
  const maturity =
    data.score >= 90 ? 'Excellent' : data.score >= 80 ? 'Adéquat' : data.score >= 60 ? 'Modéré' : 'Critique';

  const criticalCount = data.vulns.filter((v) => (v.severity || '').toUpperCase() === 'CRITIQUE').length;
  const highCount = data.vulns.filter((v) => (v.severity || '').toUpperCase() === 'HAUTE').length;
  const otherCount = data.vulns.length - criticalCount - highCount;

  return (
    <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] shadow-2xl pdf-page-element">
      <div className="mb-8 border-b border-[#e4e7f0] pb-6">
        <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Conclusion</h2>
        <p className="text-[#4b4e5c]">Synthèse finale de la posture de sécurité.</p>
      </div>

      <div className="space-y-5">
        <div className="bg-[#f7f8fb] border border-[#e4e7f0] rounded-xl p-5">
          <div className="text-xs uppercase font-bold text-[#8a8d9c] tracking-wider mb-1">Niveau de maturité globale</div>
          <div className="font-serif text-2xl font-bold text-[#12131a]">
            {maturity} ({data.score}/100)
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
            <div className="text-xs uppercase font-bold text-[#8a8d9c] tracking-wider mb-1">Points forts</div>
            <p className="text-sm text-[#4b4e5c]">
              {data.vulns.length === 0
                ? 'Aucune vulnérabilité connue détectée dans le périmètre analysé.'
                : `${otherCount} vulnérabilité(s) de sévérité faible ou moyenne, sans impact majeur immédiat.`}
            </p>
          </div>
          <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
            <div className="text-xs uppercase font-bold text-[#8a8d9c] tracking-wider mb-1">Risques principaux</div>
            <p className="text-sm text-[#4b4e5c]">
              {criticalCount + highCount > 0
                ? `${criticalCount} vulnérabilité(s) critique(s) et ${highCount} de sévérité haute nécessitent une action rapide.`
                : 'Aucun risque critique ou élevé identifié à ce jour.'}
            </p>
          </div>
        </div>

        <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
          <div className="text-xs uppercase font-bold text-[#8a8d9c] tracking-wider mb-1">Priorité des prochaines actions</div>
          <p className="text-sm text-[#4b4e5c]">
            {criticalCount + highCount > 0
              ? 'Traiter en priorité les vulnérabilités critiques et hautes listées dans le plan de remédiation, puis reconduire un scan de validation.'
              : "Maintenir la vigilance via des scans réguliers et appliquer les opportunités d'amélioration proposées dans ce rapport."}
          </p>
        </div>
      </div>

      <div className="mt-auto text-center border-t border-[#e4e7f0] pt-10 pb-8">
        <p className="font-serif font-bold text-[#12131a] text-xl">Fin du rapport d'analyse</p>
      </div>

      <ReportFooter pageNumber={pageNumber} totalPages={totalPages} />
    </div>
  );
}
