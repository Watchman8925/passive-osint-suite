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
    // Note: In a real implementation, you would use a library like jsPDF or Puppeteer
    // For now, we'll create a simple HTML report and convert to PDF client-side
    const htmlContent = this.generateHTMLReport(result, options);
    
    // This would typically be handled by a backend service
    // For demo purposes, we'll return a placeholder
    return {
      success: true,
      filename: `result_${result.id}.pdf`,
      downloadUrl: `data:text/html,${encodeURIComponent(htmlContent)}`,
      size: htmlContent.length
    };
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
    // Note: In a real implementation, you would use a library like SheetJS
    const csvData = await this.exportToCSV(result, options);
    // Convert CSV to Excel format here
    return {
      ...csvData,
      filename: csvData.filename?.replace('.csv', '.xlsx')
    };
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

  /**
   * Generate HTML report
   */
  private generateHTMLReport(result: InvestigationResult, options: ExportOptions): string {
    const processedData = this.processResultForExport(result, options);
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Investigation Result Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 25px; }
        .metadata { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .data-section { background: #fafafa; padding: 15px; border-left: 4px solid #007cba; }
        pre { background: #f0f0f0; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .tag { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Investigation Result Report</h1>
        <h2>${result.investigation_name}</h2>
        <p><strong>Target:</strong> ${result.target} | <strong>Module:</strong> ${result.module_type}</p>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
    </div>
    
    <div class="section metadata">
        <h3>Metadata</h3>
        <p><strong>Status:</strong> ${result.status}</p>
        <p><strong>Execution Time:</strong> ${result.metadata.execution_time}s</p>
        <p><strong>Confidence Score:</strong> ${(result.metadata.confidence_score * 100).toFixed(1)}%</p>
        <p><strong>Items Found:</strong> ${result.metadata.items_found}</p>
        <p><strong>Data Sources:</strong> ${result.metadata.data_sources.join(', ')}</p>
        <p><strong>Tags:</strong> ${result.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}</p>
    </div>
    
    ${options.includeRawData !== false ? `
    <div class="section data-section">
        <h3>Investigation Data</h3>
        <pre>${JSON.stringify(result.data, null, 2)}</pre>
    </div>
    ` : ''}
    
    <div class="section">
        <p><em>Report generated by OSINT Intelligence Platform on ${new Date().toLocaleString()}</em></p>
    </div>
</body>
</html>
    `;
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
    // Generate combined HTML report
    let htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <title>Investigation Results Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .result { border: 1px solid #ddd; margin-bottom: 30px; padding: 20px; }
        .section { margin-bottom: 25px; }
        .metadata { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        pre { background: #f0f0f0; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Investigation Results Batch Report</h1>
        <p><strong>Total Results:</strong> ${results.length}</p>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
    </div>
`;

    results.forEach((result, index) => {
      htmlContent += `
    <div class="result">
        <h2>Result ${index + 1}: ${result.investigation_name}</h2>
        <p><strong>Target:</strong> ${result.target} | <strong>Module:</strong> ${result.module_type}</p>
        <div class="metadata">
            <p><strong>Status:</strong> ${result.status}</p>
            <p><strong>Execution Time:</strong> ${result.metadata.execution_time}s</p>
            <p><strong>Items Found:</strong> ${result.metadata.items_found}</p>
        </div>
        ${options.includeRawData !== false ? `
        <div class="section">
            <h4>Data</h4>
            <pre>${JSON.stringify(result.data, null, 2)}</pre>
        </div>
        ` : ''}
    </div>
`;
    });

    htmlContent += `
</body>
</html>
`;

    return {
      success: true,
      filename: 'investigation_results_batch.pdf',
      downloadUrl: `data:text/html,${encodeURIComponent(htmlContent)}`,
      size: htmlContent.length
    };
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
    const csvResult = await this.exportBatchToCSV(results, options);
    return {
      ...csvResult,
      filename: csvResult.filename?.replace('.csv', '.xlsx')
    };
  }

  /**
   * Utility methods
   */
  private downloadJSON(data: any, filename: string): ExportResult {
    const jsonString = JSON.stringify(data, null, 2);
    return this.downloadFile(jsonString, `${filename}.json`, 'application/json');
  }

  private downloadFile(content: string, filename: string, mimeType: string): ExportResult {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    // Trigger download
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Clean up URL object
    setTimeout(() => URL.revokeObjectURL(url), 100);
    
    return {
      success: true,
      filename,
      downloadUrl: url,
      size: blob.size
    };
  }
}

export const exportService = new ExportService();