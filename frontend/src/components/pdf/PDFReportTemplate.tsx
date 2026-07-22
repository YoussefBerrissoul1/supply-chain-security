import React from 'react';
import { ScanResult } from '@/pages/ScanPage';
import { ReportCover } from './ReportCover';
import { ReportOverview } from './ReportOverview';
import { ReportVulnerabilities } from './ReportVulnerabilities';
import { ReportRecommendations } from './ReportRecommendations';
import { ReportFooter } from './ReportFooter';

interface PDFReportTemplateProps {
  data: ScanResult;
}

export function PDFReportTemplate({ data }: PDFReportTemplateProps) {
  // Calculate total pages for footer (Cover = 1, Overview = 2, Vulns = N, Recommendations = N+1)
  const ITEMS_PER_PAGE = 7;
  const vulnPages = Math.ceil(data.vulns.length / ITEMS_PER_PAGE) || 1;
  const totalPages = 1 + 1 + vulnPages + 1; // Cover + Overview + Vulns + Recs

  return (
    <div className="bg-[#e4e7f0] flex flex-col items-center p-8 gap-8 font-sans antialiased pdf-report-container">
      {/* Page 1: Cover */}
      <div className="relative shadow-2xl pdf-page-element">
        <ReportCover repoUrl={data.target} />
      </div>

      {/* Page 2: Overview */}
      <div className="relative shadow-2xl pdf-page-element">
        <ReportOverview data={data} />
        <ReportFooter pageNumber={2} totalPages={totalPages} />
      </div>

      {/* Page 3+: Vulnerabilities */}
      <ReportVulnerabilities data={data} startPage={3} totalPages={totalPages} />

      {/* Final Page: Recommendations */}
      <div className="relative shadow-2xl pdf-page-element">
        <ReportRecommendations data={data} pageNumber={totalPages} totalPages={totalPages} />
      </div>
    </div>
  );
}
