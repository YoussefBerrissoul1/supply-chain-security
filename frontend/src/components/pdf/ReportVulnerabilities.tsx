import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportFooter } from './ReportFooter';
import { balancedChunks } from './reportUtils';

interface ReportVulnerabilitiesProps {
  data: ScanResult;
  startPage: number;
  totalPages: number;
}

const IDEAL_ITEMS_PER_PAGE = 6;

export function ReportVulnerabilities({ data, startPage, totalPages }: ReportVulnerabilitiesProps) {
  const chunks = balancedChunks(data.vulns, IDEAL_ITEMS_PER_PAGE);

  const severityColor = (sev: string) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITIQUE': return '#b91c1c';
      case 'HAUTE':    return '#b45309';
      case 'MOYENNE':  return '#854d0e';
      default:         return '#4b4e5c';
    }
  };

  if (chunks.length === 0) {
    return (
      <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] shadow-2xl pdf-page-element">
        <div className="mb-8 border-b border-[#e4e7f0] pb-6">
          <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Détail des Vulnérabilités</h2>
          <p className="text-[#4b4e5c]">Aucune vulnérabilité détectée dans le périmètre analysé.</p>
        </div>
        <ReportFooter pageNumber={startPage} totalPages={totalPages} />
      </div>
    );
  }

  return (
    <>
      {chunks.map((chunk, pageIndex) => (
        <div key={pageIndex} className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] report-vuln-page shadow-2xl pdf-page-element" id={`pdf-page-vulns-${pageIndex}`}>
          <div className="mb-8 border-b border-[#e4e7f0] pb-6">
            <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">
              Détail des Vulnérabilités {chunks.length > 1 ? `(${pageIndex + 1}/${chunks.length})` : ''}
            </h2>
            <p className="text-[#4b4e5c]">Liste complète des failles détectées et de leurs scores de criticité.</p>
          </div>

          <div className="space-y-4">
            {chunk.map((v) => (
              <div key={v.id} className="bg-white rounded-xl border border-[#e4e7f0] p-5 shadow-sm flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span
                      className="text-[10px] font-bold px-2 py-0.5 rounded-sm uppercase tracking-wider"
                      style={{ background: `${severityColor(v.severity)}18`, color: severityColor(v.severity) }}
                    >
                      {v.severity}
                    </span>
                    <span className="font-mono text-sm font-bold text-[#12131a]">{v.id}</span>
                  </div>
                  <div className="font-mono font-bold text-lg" style={{ color: severityColor(v.severity) }}>
                    {v.score.toFixed(1)} <span className="text-xs text-[#8a8d9c] font-sans font-normal">/ 10</span>
                  </div>
                </div>

                <div className="text-sm text-[#4b4e5c]">{v.desc}</div>

                <div className="bg-[#f7f8fb] px-3 py-2 rounded-lg inline-flex items-center gap-2 border border-[#e4e7f0] self-start mt-1">
                  <span className="text-xs text-[#8a8d9c]">Paquet impacté:</span>
                  <span className="font-mono text-xs font-bold text-[#12131a]">{v.pkg}</span>
                </div>
              </div>
            ))}
          </div>
          <ReportFooter pageNumber={startPage + pageIndex} totalPages={totalPages} />
        </div>
      ))}
    </>
  );
}
