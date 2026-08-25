import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportFooter } from './ReportFooter';
import { balancedChunks } from './reportUtils';

interface ReportRecommendationsProps {
  data: ScanResult;
  startPage: number;
  totalPages: number;
}

type CombinedItem =
  | { kind: 'rec'; id: string | number; text: string }
  | {
      kind: 'step';
      id: string | number;
      title: string;
      severity: string;
      effort: string;
      description: string;
      command?: string;
    };

const IDEAL_ITEMS_PER_PAGE = 3;

/**
 * FIX demandé : recommandations IA et plan de remédiation ne doivent plus
 * être deux sections séparées avec leurs propres pages/titres. Ici, les deux
 * types de contenu sont fusionnés dans un seul tableau `combined`, puis
 * paginés ensemble via `balancedChunks` sous un seul titre de section
 * ("Recommandations & Plan de Remédiation"), ce qui évite aussi les pages
 * quasi vides (ex: une page avec une seule étape de remédiation).
 */
export function ReportRecommendations({ data, startPage, totalPages }: ReportRecommendationsProps) {
  const severityColor = (sev: string) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITIQUE': return '#b91c1c';
      case 'HAUTE':    return '#b45309';
      case 'MOYENNE':  return '#854d0e';
      default:         return '#4b4e5c';
    }
  };

  const combined: CombinedItem[] = [
    ...(data.aiRec ? data.aiRec.split('\n\n').map((text, idx) => ({
      kind: 'rec' as const,
      id: `rec-${idx}`,
      text: text,
    })) : [])
  ];

  const chunks = balancedChunks(combined, IDEAL_ITEMS_PER_PAGE);
  let pageCursor = startPage;

  if (chunks.length === 0) {
    return (
      <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] shadow-2xl pdf-page-element">
        <div className="mb-8 border-b border-[#e4e7f0] pb-6">
          <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Recommandations & Plan de Remédiation</h2>
          <p className="text-[#4b4e5c]">Aucune recommandation ni action de remédiation générée pour cette analyse.</p>
        </div>
        <ReportFooter pageNumber={pageCursor} totalPages={totalPages} />
      </div>
    );
  }

  return (
    <>
      {chunks.map((chunk, pageIdx) => (
        <div key={`recplan-${pageIdx}`} className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] shadow-2xl pdf-page-element">
          <div className="mb-8 border-b border-[#e4e7f0] pb-6">
            <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">
              Recommandations & Plan de Remédiation {chunks.length > 1 ? `(${pageIdx + 1}/${chunks.length})` : ''}
            </h2>
            <p className="text-[#4b4e5c]">Analyse IA et étapes concrètes priorisées pour sécuriser votre environnement.</p>
          </div>

          <div className="space-y-4 flex-1">
            {chunk.map((item) =>
              item.kind === 'rec' ? (
                <div key={item.id} className="bg-[#07080b] rounded-xl p-5 border border-[#c2410c]/20 shadow-sm relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(194,65,12,0.1),transparent_70%)] pointer-events-none" />
                  <div className="flex items-center gap-2 mb-2 relative z-10">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#c2410c]" />
                    <span className="text-[#8a8d9c] uppercase tracking-widest text-[10px] font-bold">Recommandation IA</span>
                  </div>
                  <p className="text-gray-300 font-mono text-sm leading-relaxed relative z-10">{item.text}</p>
                </div>
              ) : (
                <div key={item.id} className="bg-white rounded-xl border border-[#e4e7f0] p-5 shadow-sm">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    <h4 className="font-bold text-base text-[#12131a]">{item.title}</h4>
                    <span
                      className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase"
                      style={{ background: `${severityColor(item.severity)}15`, color: severityColor(item.severity) }}
                    >
                      {item.severity}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#f7f8fb] text-[#4b4e5c] border border-[#e4e7f0]">
                      Effort: {item.effort}
                    </span>
                  </div>
                  <p className="text-sm text-[#4b4e5c] mb-3">{item.description}</p>
                  {item.command && (
                    <div className="bg-[#12131a] text-[#8a8d9c] font-mono text-xs px-4 py-2.5 rounded-lg flex items-center">
                      <span>$ {item.command}</span>
                    </div>
                  )}
                </div>
              )
            )}
          </div>

          <ReportFooter pageNumber={pageCursor++} totalPages={totalPages} />
        </div>
      ))}
    </>
  );
}
