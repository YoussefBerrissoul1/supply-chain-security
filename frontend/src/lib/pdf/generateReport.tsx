import React from 'react';
import { createRoot } from 'react-dom/client';
import html2canvas from 'html2canvas-pro';
import { jsPDF } from 'jspdf';
import { ScanResult } from '@/pages/ScanPage';
import { PDFReportTemplate } from '@/components/pdf/PDFReportTemplate';

export async function generateReport(data: ScanResult) {
  // 1. Create a hidden container off-screen
  const container = document.createElement('div');
  container.style.position = 'absolute';
  container.style.left = '-9999px';
  container.style.top = '0';
  container.style.width = '210mm';
  document.body.appendChild(container);

  // 2. Render the React component tree synchronously
  const root = createRoot(container);
  
  // We wrap it in a Promise to wait for React to flush changes to the DOM
  await new Promise<void>((resolve) => {
    root.render(
      <div id="pdf-render-root">
        <PDFReportTemplate data={data} />
      </div>
    );
    // Give the DOM a moment to mount and load fonts/images
    setTimeout(resolve, 1500);
  });

  try {
    // 3. Initialize jsPDF
    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
      compress: true,
    });

    // 4. Find all pages
    const pages = Array.from(container.querySelectorAll('.pdf-page-element')) as HTMLElement[];

    if (pages.length === 0) {
      throw new Error("Aucune page trouvée pour le rendu PDF.");
    }

    for (let i = 0; i < pages.length; i++) {
      const pageEl = pages[i];
      
      // Capture the page with html2canvas
      const canvas = await html2canvas(pageEl, {
        scale: 2, // High resolution for premium look
        useCORS: true, // Allow external images if any
        logging: false,
        backgroundColor: '#ffffff'
      });

      const imgData = canvas.toDataURL('image/jpeg', 0.95);
      
      // A4 dimensions in mm
      const pdfWidth = 210;
      const pdfHeight = 297;

      if (i > 0) {
        pdf.addPage();
      }

      pdf.addImage(imgData, 'JPEG', 0, 0, pdfWidth, pdfHeight);
    }

    // 5. Download the PDF
    const filename = `NEXORA_Audit_${data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
    pdf.save(filename);

  } catch (error: any) {
    console.error('Error generating PDF:', error);
    alert(`Erreur lors de la génération du rapport PDF: ${error.message || error}`);
  } finally {
    // Cleanup
    root.unmount();
    document.body.removeChild(container);
  }
}
