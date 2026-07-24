import React from 'react';
import { ReportFooter } from './ReportFooter';

interface ReportBestPracticesProps {
  pageNumber: number;
  totalPages: number;
}

/**
 * Cette section est TOUJOURS affichée, même si le score est de 100/100
 * et qu'aucune vulnérabilité n'a été détectée. Le rapport ne doit jamais
 * s'arrêter sur "Aucun problème détecté" : il doit toujours proposer des
 * pistes d'amélioration continue.
 */
export function ReportBestPractices({ pageNumber, totalPages }: ReportBestPracticesProps) {
  const practices = [
    {
      title: 'Mises à jour régulières',
      text: "Intégrez des outils d'analyse SCA (Software Composition Analysis) dans vos pipelines CI/CD pour bloquer les versions vulnérables avant déploiement. Maintenez vos dépendances à jour en permanence.",
    },
    {
      title: 'Principe du moindre privilège',
      text: "Réduisez la surface d'attaque en utilisant des images Docker minimalistes (distroless/alpine) et en ne tournant jamais en tant que root. Limitez les permissions réseau et système.",
    },
    {
      title: 'Surveillance continue',
      text: 'Les vulnérabilités évoluent (zero-days). Planifiez des scans hebdomadaires automatiques avec NEXORA pour maintenir votre score de sécurité. Soyez alertés des nouvelles failles.',
    },
    {
      title: 'Gouvernance GitHub',
      text: 'Activez Dependabot, le Secret Scanning et la Branch Protection. Ajoutez CodeQL, un SBOM et exigez la signature des commits ainsi que le MFA pour tous les contributeurs.',
    },
  ];

  return (
    <div className="w-[210mm] h-[297mm] bg-white relative flex flex-col pt-[20mm] px-[20mm] shadow-2xl pdf-page-element">
      <div className="mb-8 border-b border-[#e4e7f0] pb-6">
        <h2 className="font-serif text-3xl font-bold text-[#12131a] mb-2">Opportunités d'Amélioration</h2>
        <p className="text-[#4b4e5c]">Bonnes pratiques recommandées, quel que soit le score obtenu.</p>
      </div>

      <div className="grid grid-cols-1 gap-5">
        {practices.map((p, idx) => (
          <div key={idx} className="flex items-start gap-4 p-5 bg-[#f7f8fb] rounded-xl border border-[#e4e7f0]">
            <div className="w-9 h-9 rounded-full bg-white flex items-center justify-center shrink-0 border border-[#e4e7f0] font-bold text-[#12131a]">
              {idx + 1}
            </div>
            <div>
              <div className="font-bold text-base text-[#12131a] mb-1">{p.title}</div>
              <div className="text-[#4b4e5c] text-sm">{p.text}</div>
            </div>
          </div>
        ))}
      </div>

      <ReportFooter pageNumber={pageNumber} totalPages={totalPages} />
    </div>
  );
}
