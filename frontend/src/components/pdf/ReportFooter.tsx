import React from 'react';

interface ReportFooterProps {
  pageNumber: number;
  totalPages: number;
}

export function ReportFooter({ pageNumber, totalPages }: ReportFooterProps) {
  const currentDate = new Date().toLocaleDateString('fr-FR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <div className="absolute bottom-0 left-0 w-full h-[120px] px-[20mm] flex flex-col justify-end pb-8 bg-white z-50">
      <div className="w-full h-px bg-[#e4e7f0] mb-4" />
      <div className="flex items-center justify-between text-[10px] text-[#8a8d9c] font-sans">
        <div className="flex flex-col">
          <span className="font-semibold text-[#12131a]">NEXORA Security Scanner</span>
          <span>Version 1.2.0 • Rapport généré le {currentDate}</span>
          <span className="mt-0.5 text-[#12131a] font-medium">Réalisé par YOUSSEF BERRISOUL</span>
        </div>
        
        <div className="text-center px-4 max-w-[50%]">
          CONFIDENTIALITÉ STRICTE — Ce rapport contient des informations sensibles sur l'infrastructure de la SRM-FM. Ne pas distribuer.
        </div>
        
        <div className="text-right font-mono font-bold text-[#12131a]">
          Page {pageNumber} / {totalPages}
        </div>
      </div>
    </div>
  );
}
