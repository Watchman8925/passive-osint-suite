import JSZip from 'jszip';

import { InvestigationResult } from '../components/results/InvestigationResults';

export interface ExportOptions {
  format: 'json' | 'csv' | 'pdf' | 'xml' | 'excel';
  includeMetadata?: boolean;
  includeRawData?: boolean;
  customFields?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
}

export interface ExportResult {
  success: boolean;
  downloadUrl?: string;
  filename?: string;
  error?: string;
  size?: number;
  blob?: Blob;
}

class ExportService {
  /**
   * Export a single investigation result
   */
  async exportResult(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    try {
      switch (options.format) {
        case 'json':
          return this.exportToJSON(result, options);
        case 'csv':
          return this.exportToCSV(result, options);
        case 'pdf':
          return this.exportToPDF(result, options);
        case 'xml':
          return this.exportToXML(result, options);
        case 'excel':
          return this.exportToExcel(result, options);
        default:
          throw new Error(`Unsupported export format: ${options.format}`);
      }
    } catch (error) {
      console.error('Export failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Export failed'
      };
    }
  }

  /**
   * Export multiple results
   */
  async exportMultipleResults(results: InvestigationResult[], options: ExportOptions): Promise<ExportResult> {
    try {
      const processedData = {
        metadata: {
          export_date: new Date().toISOString(),
          total_results: results.length,
          format: options.format,
          included_fields: options.customFields || 'all'
        },
        results: results.map(result => this.processResultForExport(result, options))
      };

      switch (options.format) {
        case 'json':
          return this.downloadJSON(processedData, 'investigation_results_batch');
        case 'csv':
          return this.exportBatchToCSV(results, options);
        case 'pdf':
          return this.exportBatchToPDF(results, options);
        case 'xml':
          return this.exportBatchToXML(results, options);
        case 'excel':
          return this.exportBatchToExcel(results, options);
        default:
          throw new Error(`Unsupported batch export format: ${options.format}`);
      }
    } catch (error) {
      console.error('Batch export failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Batch export failed'
      };
    }
  }

  /**
   * Export to JSON format
   */
  private async exportToJSON(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    const processedData = this.processResultForExport(result, options);
    return this.downloadJSON(processedData, `result_${result.id}`);
  }

  /**
   * Export to CSV format
   */
  private async exportToCSV(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    const flatData = this.flattenResultData(result, options);
    const csv = this.convertToCSV(flatData);
    return this.downloadFile(csv, `result_${result.id}.csv`, 'text/csv');
  }

  /**
   * Export to PDF format
   */
  private async exportToPDF(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    const pdfContent = this.buildPdfDocument([result], options);
    return this.downloadFile(pdfContent, `result_${result.id}.pdf`, 'application/pdf');
  }

  /**
   * Export to XML format
   */
  private async exportToXML(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    const xml = this.convertToXML(result, options);
    return this.downloadFile(xml, `result_${result.id}.xml`, 'application/xml');
  }

  /**
   * Export to Excel format
   */
  private async exportToExcel(result: InvestigationResult, options: ExportOptions): Promise<ExportResult> {
    const flatData = this.flattenResultData(result, options);
    const workbookBuffer = await this.createExcelWorkbook(flatData, 'Result');
    return this.downloadFile(
      workbookBuffer,
      `result_${result.id}.xlsx`,
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
  }

  /**
   * Process result data based on export options
   */
  private processResultForExport(result: InvestigationResult, options: ExportOptions): any {
    const processed: any = {
      id: result.id,
      investigation_id: result.investigation_id,
      investigation_name: result.investigation_name,
      module_type: result.module_type,
      target: result.target,
      timestamp: result.timestamp,
      status: result.status,
      tags: result.tags
    };

    if (options.includeMetadata !== false) {
      processed.metadata = result.metadata;
    }

    if (options.includeRawData !== false) {
      processed.data = result.data;
    }

    if (options.customFields && options.customFields.length > 0) {
      const filtered: any = {};
      options.customFields.forEach(field => {
        if (field in processed) {
          filtered[field] = processed[field];
        }
      });
      return filtered;
    }

    return processed;
  }

  /**
   * Flatten nested data for CSV export
   */
  private flattenResultData(result: InvestigationResult, options: ExportOptions): any[] {
    const flatRows: any[] = [];
    
    // Main result row
    const mainRow = {
      id: result.id,
      investigation_name: result.investigation_name,
      module_type: result.module_type,
      target: result.target,
      status: result.status,
      timestamp: result.timestamp,
      execution_time: result.metadata.execution_time,
      confidence_score: result.metadata.confidence_score,
      items_found: result.metadata.items_found,
      data_sources: result.metadata.data_sources.join('; '),
      tags: result.tags.join('; '),
      size_mb: result.size_mb
    };

    // Flatten data object
    if (options.includeRawData !== false && result.data) {
      this.flattenObject(result.data, mainRow, 'data_');
    }

    flatRows.push(mainRow);
    return flatRows;
  }

  /**
   * Recursively flatten nested objects
   */
  private flattenObject(obj: any, target: any, prefix: string = ''): void {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        const newKey = prefix + key;

        if (value && typeof value === 'object' && !Array.isArray(value)) {
          this.flattenObject(value, target, newKey + '_');
        } else if (Array.isArray(value)) {
          target[newKey] = value.join('; ');
        } else {
          target[newKey] = value;
        }
      }
    }
  }

  /**
   * Convert data to CSV format
   */
  private convertToCSV(data: any[]): string {
    if (data.length === 0) return '';

    const headers = Object.keys(data[0]);
    const csvRows = [headers.join(',')];

    for (const row of data) {
      const values = headers.map(header => {
        const value = row[header];
        if (value === null || value === undefined) return '';
        if (typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return value.toString();
      });
      csvRows.push(values.join(','));
    }

    return csvRows.join('\n');
  }

  /**
   * Convert result to XML format
   */
  private convertToXML(result: InvestigationResult, options: ExportOptions): string {
    const processedData = this.processResultForExport(result, options);
    
    const xml = this.objectToXML(processedData, 'investigation_result');
    
    return `<?xml version="1.0" encoding="UTF-8"?>\n${xml}`;
  }

  /**
   * Convert object to XML recursively
   */
  private objectToXML(obj: any, rootName: string): string {
    let xml = `<${rootName}>`;
    
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        
        if (Array.isArray(value)) {
          xml += `<${key}>`;
          value.forEach((item, index) => {
            if (typeof item === 'object') {
              xml += this.objectToXML(item, `item_${index}`);
            } else {
              xml += `<item>${this.escapeXML(item)}</item>`;
            }
          });
          xml += `</${key}>`;
        } else if (typeof value === 'object' && value !== null) {
          xml += this.objectToXML(value, key);
        } else {
          xml += `<${key}>${this.escapeXML(value)}</${key}>`;
        }
      }
    }
    
    xml += `</${rootName}>`;
    return xml;
  }

  /**
   * Escape XML special characters
   */
  private escapeXML(str: any): string {
    if (str === null || str === undefined) return '';
    return str.toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  private buildPdfDocument(results: InvestigationResult[], options: ExportOptions): string {
    const lines: string[] = [];

    results.forEach((result, index) => {
      lines.push(`Investigation Result ${index + 1}: ${result.investigation_name}`);
      lines.push(`Investigation ID: ${result.investigation_id}`);
      lines.push(`Target: ${result.target}`);
      lines.push(`Module: ${result.module_type}`);
      lines.push(`Status: ${result.status}`);
      lines.push(`Timestamp: ${new Date(result.timestamp).toLocaleString()}`);
      lines.push(`Execution Time: ${result.metadata.execution_time}s`);
      lines.push(`Confidence Score: ${(result.metadata.confidence_score * 100).toFixed(1)}%`);
      lines.push(`Items Found: ${result.metadata.items_found}`);
      lines.push(`Data Sources: ${(result.metadata.data_sources || []).join(', ') || 'N/A'}`);
      lines.push(`Tags: ${(result.tags || []).join(', ') || 'N/A'}`);

      if (options.includeRawData !== false && result.data) {
        lines.push('Raw Data:');
        const rawLines = JSON.stringify(result.data, null, 2).split('\n');
        rawLines.forEach(line => lines.push(`  ${line}`));
      }

      lines.push('');
    });

    if (lines.length === 0) {
      lines.push('No investigation results available.');
    }

    return this.composePdfFromLines(lines);
  }

  private composePdfFromLines(lines: string[]): string {
    const sanitizedLines = lines.map(line => this.escapePdfText(line));
    const contentLines: string[] = ['BT', '/F1 14 Tf', '50 780 Td'];

    sanitizedLines.forEach((line, index) => {
      if (index === 0) {
        contentLines.push(`(${line}) Tj`);
      } else {
        contentLines.push('0 -18 Td');
        contentLines.push(`(${line}) Tj`);
      }
    });

    contentLines.push('ET');

    const contentStream = contentLines.join('\n');
    const objects: string[] = [];
    objects[1] = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
    objects[2] = '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';
    objects[3] =
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n';
    objects[4] = '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n';
    objects[5] = `5 0 obj\n<< /Length ${contentStream.length} >>\nstream\n${contentStream}\nendstream\nendobj\n`;

    let pdf = '%PDF-1.4\n';
    const offsets: number[] = [0];

    for (let i = 1; i <= 5; i++) {
      offsets[i] = pdf.length;
      pdf += objects[i];
    }

    const xrefPosition = pdf.length;
    pdf += 'xref\n0 6\n0000000000 65535 f \n';

    for (let i = 1; i <= 5; i++) {
      pdf += `${offsets[i].toString().padStart(10, '0')} 00000 n \n`;
    }

    pdf += 'trailer\n<< /Root 1 0 R /Size 6 >>\nstartxref\n';
    pdf += `${xrefPosition}\n%%EOF`;

    return pdf;
  }

  private escapePdfText(text: string): string {
    const sanitized = text
      .replace(/\\/g, '\\\\')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)');

    return sanitized.replace(/[\u007f-\uffff]/g, '?');
  }

  private async createExcelWorkbook(rows: any[], sheetName: string): Promise<ArrayBuffer> {
    const headers = rows.length > 0 ? Object.keys(rows[0]) : [];
    const timestamp = new Date().toISOString();
    const zip = new JSZip();

    zip.file('[Content_Types].xml', this.buildContentTypesXml());
    zip.folder('_rels')?.file('.rels', this.buildRootRelsXml());

    const xlFolder = zip.folder('xl');
    xlFolder?.file('workbook.xml', this.buildWorkbookXml(sheetName));
    xlFolder?.folder('_rels')?.file('workbook.xml.rels', this.buildWorkbookRelsXml());
    xlFolder?.folder('worksheets')?.file('sheet1.xml', this.buildWorksheetXml(headers, rows));
    xlFolder?.file('styles.xml', this.buildStylesXml());

    const docPropsFolder = zip.folder('docProps');
    docPropsFolder?.file('core.xml', this.buildCoreXml(timestamp));
    docPropsFolder?.file('app.xml', this.buildAppXml(sheetName));

    return zip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE' });
  }

  private buildWorksheetXml(headers: string[], rows: any[]): string {
    const columnLabels = headers.map((_, index) => this.getExcelColumnLabel(index));
    const lastColumn = columnLabels[columnLabels.length - 1] || 'A';
    const lastRow = Math.max(rows.length + 1, 1);
    const dimension = `A1:${lastColumn}${lastRow}`;

    let xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
    xml += '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n';
    xml += `  <dimension ref="${dimension}" />\n`;
    xml += '  <sheetData>\n';

    if (headers.length > 0) {
      xml += '    <row r="1">\n';
      headers.forEach((header, index) => {
        const cellRef = `${columnLabels[index]}1`;
        xml += `      <c r="${cellRef}" t="inlineStr"><is><t>${this.escapeXML(header)}</t></is></c>\n`;
      });
      xml += '    </row>\n';

      rows.forEach((row, rowIndex) => {
        xml += `    <row r="${rowIndex + 2}">\n`;
        headers.forEach((header, columnIndex) => {
          let value: unknown = undefined;
          if (
            row !== null &&
            typeof row === 'object' &&
            !Array.isArray(row) &&
            Object.prototype.hasOwnProperty.call(row, header)
          ) {
            value = (row as Record<string, unknown>)[header];
          }
          if (value === null || value === undefined || value === '') {
            return;
          }
          const cellRef = `${columnLabels[columnIndex]}${rowIndex + 2}`;
          if (typeof value === 'number') {
            xml += `      <c r="${cellRef}"><v>${value}</v></c>\n`;
          } else if (typeof value === 'boolean') {
            xml += `      <c r="${cellRef}" t="b"><v>${value ? 1 : 0}</v></c>\n`;
          } else {
            xml += `      <c r="${cellRef}" t="inlineStr"><is><t>${this.escapeXML(String(value))}</t></is></c>\n`;
          }
        });
        xml += '    </row>\n';
      });
    } else {
      xml += '    <row r="1">\n';
      xml += '      <c r="A1" t="inlineStr"><is><t>No data available</t></is></c>\n';
      xml += '    </row>\n';
    }

    xml += '  </sheetData>\n';
    xml += '</worksheet>';
    return xml;
  }

  private getExcelColumnLabel(index: number): string {
    let label = '';
    let n = index + 1;
    while (n > 0) {
      const remainder = (n - 1) % 26;
      label = String.fromCharCode(65 + remainder) + label;
      n = Math.floor((n - 1) / 26);
    }
    return label || 'A';
  }

  private buildContentTypesXml(): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`;
  }

  private buildRootRelsXml(): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`;
  }

  private buildWorkbookXml(sheetName: string): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="${this.escapeXML(sheetName)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`;
  }

  private buildWorkbookRelsXml(): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;
  }

  private buildStylesXml(): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1">
    <font>
      <name val="Calibri"/>
      <sz val="11"/>
      <color theme="1"/>
      <family val="2"/>
      <scheme val="minor"/>
    </font>
  </fonts>
  <fills count="1">
    <fill>
      <patternFill patternType="none"/>
    </fill>
  </fills>
  <borders count="1">
    <border>
      <left/>
      <right/>
      <top/>
      <bottom/>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
  </cellXfs>
  <cellStyles count="1">
    <cellStyle name="Normal" xfId="0" builtinId="0"/>
  </cellStyles>
</styleSheet>`;
  }

  private buildCoreXml(timestamp: string): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Investigation Results</dc:title>
  <dc:creator>OSINT Suite</dc:creator>
  <cp:lastModifiedBy>OSINT Suite</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">${timestamp}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">${timestamp}</dcterms:modified>
</cp:coreProperties>`;
  }

  private buildAppXml(sheetName: string): string {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>OSINT Suite</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
  <HeadingPairs>
    <vt:vector size="2" baseType="variant">
      <vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant>
      <vt:variant><vt:i4>1</vt:i4></vt:variant>
    </vt:vector>
  </HeadingPairs>
  <TitlesOfParts>
    <vt:vector size="1" baseType="lpstr">
      <vt:lpstr>${this.escapeXML(sheetName)}</vt:lpstr>
    </vt:vector>
  </TitlesOfParts>
</Properties>`;
  }

  /**
   * Batch export methods
   */
  private async exportBatchToCSV(results: InvestigationResult[], options: ExportOptions): Promise<ExportResult> {
    const allFlatData: any[] = [];
    
    results.forEach(result => {
      const flatData = this.flattenResultData(result, options);
      allFlatData.push(...flatData);
    });
    
    const csv = this.convertToCSV(allFlatData);
    return this.downloadFile(csv, 'investigation_results_batch.csv', 'text/csv');
  }

  private async exportBatchToPDF(results: InvestigationResult[], options: ExportOptions): Promise<ExportResult> {
    const pdfContent = this.buildPdfDocument(results, options);
    return this.downloadFile(pdfContent, 'investigation_results_batch.pdf', 'application/pdf');
  }

  private async exportBatchToXML(results: InvestigationResult[], options: ExportOptions): Promise<ExportResult> {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<investigation_results>\n';
    
    results.forEach(result => {
      const processedData = this.processResultForExport(result, options);
      xml += '  ' + this.objectToXML(processedData, 'result').replace(/\n/g, '\n  ') + '\n';
    });
    
    xml += '</investigation_results>';
    
    return this.downloadFile(xml, 'investigation_results_batch.xml', 'application/xml');
  }

  private async exportBatchToExcel(results: InvestigationResult[], options: ExportOptions): Promise<ExportResult> {
    const allFlatData: any[] = [];

    results.forEach(result => {
      const flatData = this.flattenResultData(result, options);
      allFlatData.push(...flatData);
    });

    const workbookBuffer = await this.createExcelWorkbook(allFlatData, 'Results');
    return this.downloadFile(
      workbookBuffer,
      'investigation_results_batch.xlsx',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
  }

  /**
   * Utility methods
   */
  private downloadJSON(data: any, filename: string): ExportResult {
    const jsonString = JSON.stringify(data, null, 2);
    return this.downloadFile(jsonString, `${filename}.json`, 'application/json');
  }

  private downloadFile(
    content: string | ArrayBuffer | Uint8Array | Blob,
    filename: string,
    mimeType: string
  ): ExportResult {
    const blobParts: BlobPart[] = content instanceof Blob ? [content] : [content];
    const blob = new Blob(blobParts, { type: mimeType });
    return this.createBlobResult(blob, filename);
  }

  private createBlobResult(blob: Blob, filename: string): ExportResult {
    let downloadUrl: string | undefined;
    try {
      if (typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function') {
        downloadUrl = URL.createObjectURL(blob);
      }
    } catch (error) {
      console.warn('Failed to create object URL for export', error);
    }

    return {
      success: true,
      filename,
      downloadUrl,
      size: blob.size,
      blob
    };
  }
}

export const exportService = new ExportService();