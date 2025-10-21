import { describe, expect, it } from 'vitest';

import { exportService } from './exportService';
import type { InvestigationResult } from '../components/results/InvestigationResults';

const sampleResult: InvestigationResult = {
  id: 'test-1',
  investigation_id: 'inv-test',
  investigation_name: 'Sample Investigation',
  module_type: 'domain-recon',
  target: 'example.com',
  timestamp: new Date().toISOString(),
  status: 'completed',
  data: {
    domain_info: { registrar: 'Example Registrar', creation_date: '2020-01-01' },
    notes: 'This is a sample dataset for export testing.',
  },
  metadata: {
    execution_time: 10.5,
    data_sources: ['WHOIS', 'DNS'],
    confidence_score: 0.85,
    items_found: 5,
  },
  tags: ['test', 'pdf', 'excel'],
  size_mb: 1.2,
};

describe('exportService binary exports', () => {
  it('produces a non-empty PDF blob', async () => {
    const result = await exportService.exportResult(sampleResult, {
      format: 'pdf',
      includeMetadata: true,
      includeRawData: true,
    });

    expect(result.success).toBe(true);
    expect(result.filename).toMatch(/\.pdf$/);
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.blob?.type).toBe('application/pdf');
    expect(result.blob?.size ?? 0).toBeGreaterThan(0);
  });

  it('produces a non-empty Excel workbook', async () => {
    const result = await exportService.exportResult(sampleResult, {
      format: 'excel',
      includeMetadata: true,
      includeRawData: true,
    });

    expect(result.success).toBe(true);
    expect(result.filename).toMatch(/\.xlsx$/);
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.blob?.type).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    expect(result.blob?.size ?? 0).toBeGreaterThan(0);
  });
});
