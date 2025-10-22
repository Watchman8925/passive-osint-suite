import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';

import InvestigationResults from '../components/results/InvestigationResults';
import { SelectedInvestigationProvider } from '../contexts/SelectedInvestigationContext';
import { investigationApi } from '../services/api';

vi.mock('../services/api', () => ({
  investigationApi: {
    getInvestigation: vi.fn(),
    getInvestigationProgress: vi.fn()
  }
}));

const getInvestigationMock = investigationApi.getInvestigation as unknown as vi.Mock;
const getProgressMock = investigationApi.getInvestigationProgress as unknown as vi.Mock;

describe('InvestigationResults', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('informs user when no investigation is selected', () => {
    render(
      <SelectedInvestigationProvider>
        <InvestigationResults />
      </SelectedInvestigationProvider>
    );

    expect(screen.getByText(/No investigation selected/i)).toBeInTheDocument();
    expect(getInvestigationMock).not.toHaveBeenCalled();
  });

  it('renders investigation results from API', async () => {
    getInvestigationMock.mockResolvedValue({
      id: 'inv-42',
      name: 'ACME Investigation',
      status: 'running',
      targets: ['example.com'],
      results: {
        'domain-recon': {
          id: 'res-1',
          module_type: 'domain-recon',
          status: 'completed',
          target: 'example.com',
          metadata: {
            execution_time: 12,
            data_sources: ['DNS'],
            confidence_score: 0.92,
            items_found: 3
          },
          data: { domain: 'example.com' },
          tags: ['domain'],
          size_mb: 1.5,
          timestamp: '2024-01-01T00:00:00Z'
        }
      }
    });
    getProgressMock.mockResolvedValue({
      overall_progress: 1,
      completed_tasks: 5,
      total_tasks: 5
    });

    render(
      <SelectedInvestigationProvider>
        <InvestigationResults investigationId="inv-42" />
      </SelectedInvestigationProvider>
    );

    await waitFor(() => expect(getInvestigationMock).toHaveBeenCalledWith('inv-42'));

    const headings = await screen.findAllByText('ACME Investigation');
    expect(headings.length).toBeGreaterThan(0);
    const moduleBadges = await screen.findAllByText(/Domain Recon/i, { selector: 'span' });
    expect(moduleBadges.length).toBeGreaterThan(0);

    const progressSummary = await screen.findByText(/Tasks/i);
    expect(progressSummary).toHaveTextContent('Tasks 5/5');

    const confidenceBadges = await screen.findAllByText('92%');
    expect(confidenceBadges.length).toBeGreaterThan(0);
  });

  it('shows error state when API fails', async () => {
    getInvestigationMock.mockRejectedValue(new Error('boom'));

    render(
      <SelectedInvestigationProvider>
        <InvestigationResults investigationId="inv-error" />
      </SelectedInvestigationProvider>
    );

    await waitFor(() => expect(screen.getByText(/Unable to load results/i)).toBeInTheDocument());
  });
});
