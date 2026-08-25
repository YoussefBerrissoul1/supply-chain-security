import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportCover } from './ReportCover';
import { ReportOverview } from './ReportOverview';
import { ReportDockerConfig } from './ReportDockerConfig';
import { ReportVulnerabilities } from './ReportVulnerabilities';
import { ReportRecommendations } from './ReportRecommendations';
import { ReportBestPractices } from './ReportBestPractices';
import { ReportConclusion } from './ReportConclusion';
import { ReportFooter } from './ReportFooter';
import { balancedChunks } from './reportUtils';

interface PDFReportTemplateProps {
  data: ScanResult;
}

const VULN_IDEAL_PER_PAGE = 6;
const RECPLAN_IDEAL_PER_PAGE = 3;

export function PDFReportTemplate({ data }: PDFReportTemplateProps) {
  const vulnPages = balancedChunks(data.vulns, VULN_IDEAL_PER_PAGE).length || 1;

  const combinedRecPlanCount = data.aiRec ? data.aiRec.split('\n\n').length : 0;
  const recPlanPages = combinedRecPlanCount > 0 ? Math.ceil(combinedRecPlanCount / RECPLAN_IDEAL_PER_PAGE) : 1;

  const hasDockerPage = !!data.dockerConfig;

  // Cover + Overview + (Docker Config optionnel) + Vulns + Recs&Plan (fusionnés) + Bonnes Pratiques + Conclusion
  const totalPages = 1 + 1 + (hasDockerPage ? 1 : 0) + vulnPages + recPlanPages + 1 + 1;

  const overviewPageNumber = 2;
  const dockerPageNumber = hasDockerPage ? 3 : null;
  const vulnStartPage = hasDockerPage ? 4 : 3;
  const recPlanStartPage = vulnStartPage + vulnPages;
  const bestPracticesPageNumber = recPlanStartPage + recPlanPages;
  const conclusionPageNumber = bestPracticesPageNumber + 1;

  return (
    <div className="bg-[#e4e7f0] flex flex-col items-center p-8 gap-8 font-sans antialiased pdf-report-container">
      {/* Page 1: Cover */}
      <div className="relative shadow-2xl pdf-page-element">
        <ReportCover data={data} />
      </div>

      {/* Page 2: Overview */}
      <div className="relative shadow-2xl pdf-page-element">
        <ReportOverview data={data} />
        <ReportFooter pageNumber={overviewPageNumber} totalPages={totalPages} />
      </div>

      {/* Page 3 (optionnelle) : Configuration Docker, isolée pour ne plus déborder */}
      {hasDockerPage && (
        <div className="relative shadow-2xl pdf-page-element">
          <ReportDockerConfig data={data} />
          <ReportFooter pageNumber={dockerPageNumber as number} totalPages={totalPages} />
        </div>
      )}

      {/* Vulnérabilités (pagination équilibrée) */}
      <ReportVulnerabilities data={data} startPage={vulnStartPage} totalPages={totalPages} />

      {/* Recommandations IA + Plan de remédiation : UNE SEULE section fusionnée */}
      <ReportRecommendations data={data} startPage={recPlanStartPage} totalPages={totalPages} />

      {/* Bonnes pratiques — toujours affichées, même à 100/100 */}
      <ReportBestPractices pageNumber={bestPracticesPageNumber} totalPages={totalPages} />

      {/* Conclusion */}
      <ReportConclusion data={data} pageNumber={conclusionPageNumber} totalPages={totalPages} />
    </div>
  );
}
