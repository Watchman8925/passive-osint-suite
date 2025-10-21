import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi } from 'vitest';

import EnhancedInvestigationDashboard from '../components/dashboard/EnhancedInvestigationDashboard';
import { useInvestigations } from '../hooks/useInvestigations';
import { SelectedInvestigationProvider } from '../contexts/SelectedInvestigationContext';
import { osintAPI } from '../services/osintAPI';

vi.mock('../hooks/useInvestigations');
vi.mock('../hooks/useServiceHealth', () => ({
  useServiceHealth: () => ({
    loading: false,
    backend: 'ok',
    tor: 'ok',
    errors: [],
    raw: { health: null, tor: null },
    refresh: vi.fn()
  })
}));
vi.mock('../design/ThemeProvider', () => ({
  useTheme: () => ({ mode: 'light', toggle: vi.fn(), tokens: {} as any })
}));
vi.mock('../components/anonymity/AnonymityStatusPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="anonymity-panel" />
}));
vi.mock('../components/tasks/LiveTasksPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="live-tasks" />
}));
vi.mock('../components/dashboard/CreateInvestigationModal', () => ({
  __esModule: true,
  default: ({ isOpen, onClose, onSuccess }: any) => (
    isOpen ? (
      <div data-testid="create-investigation-modal">
        <button onClick={onClose}>close</button>
        <button onClick={onSuccess}>success</button>
      </div>
    ) : null
  )
}));
vi.mock('../components/dashboard/InvestigationDetailsModal', () => ({
  __esModule: true,
  default: ({ investigationId, isOpen, onClose }: any) => (
    isOpen ? (
      <div data-testid="details-modal">
        Details {investigationId}
        <button onClick={onClose}>close</button>
      </div>
    ) : null
  )
}));
vi.mock('../components/results/InvestigationResults', () => ({
  __esModule: true,
  default: ({ investigationId }: { investigationId?: string }) => (
    <div data-testid="results-component">Results for {investigationId}</div>
  )
}));
vi.mock('../components/visualization/VisualizationDashboard', () => ({
  __esModule: true,
  default: ({ results }: any) => (
    <div data-testid="visualization">Visualization {results.length}</div>
  )
}));

vi.mock('../services/osintAPI', () => ({
  osintAPI: {
    executeModule: vi.fn().mockResolvedValue({})
  }
}));

const mockedUseInvestigations = useInvestigations as unknown as vi.Mock;

describe('EnhancedInvestigationDashboard', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows loading skeleton when investigations are loading', () => {
    mockedUseInvestigations.mockReturnValue({
      data: null,
      loading: true,
      error: null,
      refresh: vi.fn()
    });

    render(
      <SelectedInvestigationProvider>
        <EnhancedInvestigationDashboard />
      </SelectedInvestigationProvider>
    );

    expect(screen.getByTestId('investigation-list-loading')).toBeInTheDocument();
  });

  it('executes modules via API when investigation and module selected', async () => {
    const refresh = vi.fn();
    mockedUseInvestigations.mockReturnValue({
      data: [
        {
          investigation_id: 'inv-1',
          name: 'Test Investigation',
          targets: ['example.com'],
          status: 'active',
          priority: 'high',
          investigation_type: 'domain',
          progress: 50
        }
      ],
      loading: false,
      error: null,
      refresh
    });

    render(
      <SelectedInvestigationProvider>
        <EnhancedInvestigationDashboard />
      </SelectedInvestigationProvider>
    );

    fireEvent.click(screen.getByText('Test Investigation'));

    await waitFor(() => expect(screen.getByTestId('details-modal')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Modules/ }));

    const moduleCard = await screen.findByText('Domain Reconnaissance');
    fireEvent.click(moduleCard);

    await waitFor(() => expect(osintAPI.executeModule).toHaveBeenCalledTimes(1));
    expect(osintAPI.executeModule).toHaveBeenCalledWith(
      'domain-recon',
      expect.objectContaining({ investigation_id: 'inv-1' })
    );
    expect(refresh).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText('Results for inv-1')).toBeInTheDocument());
  });
});
