import React from 'react';
import { ScanResult } from '@/pages/ScanPage';

interface ReportDockerConfigProps {
  data: ScanResult;
}

/**
 * Page dédiée à la Configuration Docker.
 * Auparavant intégrée en bas de la page Overview, elle pouvait sortir
 * de la page A4 ou se superposer à la Matrice des Risques quand le
 * contenu total dépassait la hauteur disponible. En lui donnant sa
 * propre page, ce risque disparaît complètement.
 */
export function ReportDockerConfig({ data }: ReportDockerConfigProps) {
  if (!data.dockerConfig) return null;

  return (
    <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm]" id="pdf-page-docker">
      <div className="mb-8 border-b border-[#e4e7f0] pb-4">
        <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-1">Configuration Docker</h2>
        <p className="text-[#4b4e5c] text-sm">Détails de l'image et de l'environnement d'exécution analysés.</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
          <div className="text-xs text-[#8a8d9c] mb-1">OS de base</div>
          <div className="font-mono font-bold text-[#12131a]">{data.dockerConfig.os}</div>
        </div>
        <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
          <div className="text-xs text-[#8a8d9c] mb-1">Utilisateur</div>
          <div className="font-mono font-bold text-[#12131a] flex items-center gap-2">
            {data.dockerConfig.user}
            {data.dockerConfig.user === 'root' && (
              <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full font-bold">ATTENTION</span>
            )}
          </div>
        </div>
        <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
          <div className="text-xs text-[#8a8d9c] mb-1">Ports exposés</div>
          <div className="font-mono font-bold text-[#12131a]">{data.dockerConfig.ports.join(', ')}</div>
        </div>
        <div className="bg-white border border-[#e4e7f0] rounded-xl p-5 shadow-sm">
          <div className="text-xs text-[#8a8d9c] mb-1">Taille totale</div>
          <div className="font-mono font-bold text-[#12131a]">{data.dockerConfig.totalSize}</div>
        </div>
      </div>
    </div>
  );
}
