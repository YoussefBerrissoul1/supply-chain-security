import React from 'react';
import { motion } from 'framer-motion';

interface VulnMock {
  id: string;
  score: number;
  severity: string;
}

interface RiskMatrixProps {
  vulns: VulnMock[];
  isInteractive?: boolean;
  isPdfMode?: boolean;
}

// 5x5 Matrix Grid Configuration
// Y-axis: Likelihood (1-5, bottom to top)
// X-axis: Impact (1-5, left to right)
const Y_LABELS = ['Très Probable', 'Probable', 'Possible', 'Peu Probable', 'Rare']; // Top to bottom visually
const X_LABELS = ['Mineur', 'Faible', 'Modéré', 'Majeur', 'Sévère'];

const CELL_RISKS = [
  // Row 5 (Likelihood 5 - Très Probable)
  ['MEDIUM', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL'],
  // Row 4 (Likelihood 4 - Probable)
  ['MEDIUM', 'MEDIUM', 'HIGH', 'HIGH', 'CRITICAL'],
  // Row 3 (Likelihood 3 - Possible)
  ['LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'HIGH'],
  // Row 2 (Likelihood 2 - Peu Probable)
  ['LOW', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH'],
  // Row 1 (Likelihood 1 - Rare)
  ['LOW', 'LOW', 'LOW', 'MEDIUM', 'MEDIUM'],
];

const RISK_COLORS: Record<string, string> = {
  'LOW': 'bg-[#22c55e] border-[#16a34a]',       // Green (Vibrant)
  'MEDIUM': 'bg-[#eab308] border-[#ca8a04]',    // Yellow (Vibrant)
  'HIGH': 'bg-[#f97316] border-[#ea580c]',      // Orange (Vibrant)
  'CRITICAL': 'bg-[#ef4444] border-[#dc2626]',  // Red (Vibrant)
};

export function RiskMatrix({ vulns, isInteractive = true, isPdfMode = false }: RiskMatrixProps) {
  // Deterministic mapping of a vulnerability to a grid cell based on its score
  const getCellForVuln = (v: VulnMock) => {
    // Map CVSS (0-10) to 1-5 coordinates roughly
    let impact = 1;
    let likelihood = 1;

    if (v.score >= 9.0) { impact = 5; likelihood = 4 + (v.score > 9.5 ? 1 : 0); }
    else if (v.score >= 7.0) { impact = 4; likelihood = 3 + (v.score > 8.0 ? 1 : 0); }
    else if (v.score >= 4.0) { impact = 3; likelihood = 2 + (v.score > 5.5 ? 1 : 0); }
    else { impact = 2; likelihood = 1 + (v.score > 2.0 ? 1 : 0); }

    // Visual row index is 5 - likelihood (because row 0 visually is likelihood 5)
    return { row: 5 - likelihood, col: impact - 1 };
  };

  // Group vulns by cell
  const gridContent = Array(5).fill(0).map(() => Array(5).fill([] as VulnMock[]));
  
  vulns.forEach(v => {
    const { row, col } = getCellForVuln(v);
    if (row >= 0 && row < 5 && col >= 0 && col < 5) {
      gridContent[row][col] = [...gridContent[row][col], v];
    }
  });

  return (
    <div className="w-full flex flex-col items-center">
      <div className={`flex w-full relative ${isPdfMode ? 'max-w-[400px]' : 'max-w-2xl'}`}>
        {/* Y-axis Label */}
        <div className={`flex flex-col justify-between pr-3 py-4 font-semibold text-[#8a8d9c] uppercase tracking-widest text-right whitespace-nowrap h-full ${isPdfMode ? 'text-[8px] max-w-[80px]' : 'text-xs'}`}>
          <div className="h-[20%] flex items-center justify-end">Très Probable</div>
          <div className="h-[20%] flex items-center justify-end">Probable</div>
          <div className="h-[20%] flex items-center justify-end">Possible</div>
          <div className="h-[20%] flex items-center justify-end">Peu Probable</div>
          <div className="h-[20%] flex items-center justify-end">Rare</div>
          
          <div className="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[#4b4e5c] font-bold tracking-widest">
            PROBABILITÉ
          </div>
        </div>

        {/* 5x5 Grid */}
        <div className="flex-1 grid grid-cols-5 grid-rows-5 gap-1.5 p-2 bg-[#f7f8fb] border border-[#e4e7f0] rounded-xl">
          {CELL_RISKS.map((rowArr, rowIdx) => 
            rowArr.map((riskLevel, colIdx) => {
              const cellVulns = gridContent[rowIdx][colIdx];
              const cellColor = RISK_COLORS[riskLevel];
              
              return (
                <div 
                  key={`${rowIdx}-${colIdx}`}
                  className={`relative w-full aspect-square border rounded-lg flex items-center justify-center transition-all ${cellColor} ${isInteractive ? 'hover:scale-[1.03] hover:shadow-md hover:z-10 cursor-default' : ''}`}
                >
                  {cellVulns.length > 0 && (
                    <div className={`${isPdfMode ? 'w-5 h-5 text-[10px]' : 'w-6 h-6 md:w-8 md:h-8 text-xs md:text-sm'} rounded-full bg-white shadow-sm flex items-center justify-center font-bold text-black`}>
                      {cellVulns.length}
                    </div>
                  )}

                  {/* Tooltip for Web Mode */}
                  {isInteractive && cellVulns.length > 0 && (
                    <div className="absolute opacity-0 hover:opacity-100 bottom-full mb-2 bg-[#12131a] text-white text-xs p-3 rounded-lg shadow-xl w-48 z-50 pointer-events-none transition-opacity">
                      <div className="font-bold mb-1 border-b border-white/20 pb-1">Vulnérabilités :</div>
                      <div className="flex flex-col gap-1">
                        {cellVulns.map(v => (
                          <div key={v.id} className="flex justify-between">
                            <span className="font-mono">{v.id}</span>
                            <span>{v.score}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
      
      {/* X-axis Label */}
      <div className={`w-full relative mt-2 ${isPdfMode ? 'max-w-[400px] pl-[80px]' : 'max-w-2xl pl-24'} pr-2`}>
        <div className={`flex justify-between font-semibold text-[#8a8d9c] uppercase tracking-widest text-center px-2 ${isPdfMode ? 'text-[8px]' : 'text-xs'}`}>
          <span className="flex-1">Mineur</span>
          <span className="flex-1">Faible</span>
          <span className="flex-1">Modéré</span>
          <span className="flex-1">Majeur</span>
          <span className="flex-1">Sévère</span>
        </div>
        <div className={`text-center text-[#4b4e5c] font-bold tracking-widest uppercase ${isPdfMode ? 'mt-1 text-[8px]' : 'mt-2 text-xs'}`}>
          IMPACT (Sévérité)
        </div>
      </div>

      {/* Legend */}
      <div className={`mt-6 flex flex-wrap justify-center gap-4 font-medium ${isPdfMode ? 'text-[9px]' : 'text-xs'}`}>
        <div className="flex items-center gap-2"><div className={`w-4 h-4 rounded-full border ${RISK_COLORS['LOW']}`} /> Risque Faible</div>
        <div className="flex items-center gap-2"><div className={`w-4 h-4 rounded-full border ${RISK_COLORS['MEDIUM']}`} /> Risque Modéré</div>
        <div className="flex items-center gap-2"><div className={`w-4 h-4 rounded-full border ${RISK_COLORS['HIGH']}`} /> Risque Élevé</div>
        <div className="flex items-center gap-2"><div className={`w-4 h-4 rounded-full border ${RISK_COLORS['CRITICAL']}`} /> Risque Critique</div>
      </div>
    </div>
  );
}
