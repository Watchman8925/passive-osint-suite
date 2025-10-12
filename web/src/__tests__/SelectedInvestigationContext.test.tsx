import React from 'react';
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SelectedInvestigationProvider, useSelectedInvestigation } from '../contexts/SelectedInvestigationContext';

// Helper component to interact with context
const Harness: React.FC = () => {
  const { selectedId, setSelectedId, clear } = useSelectedInvestigation();
  return (
    <div>
      <div data-testid="current">{selectedId || 'none'}</div>
      <button onClick={() => setSelectedId('abc123')}>Set</button>
      <button onClick={() => clear()}>Clear</button>
    </div>
  );
};

describe('SelectedInvestigationContext', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('initially shows none and stores selection', async () => {
    const user = userEvent.setup();
    await act(async () => {
      render(
        <SelectedInvestigationProvider>
          <Harness />
        </SelectedInvestigationProvider>
      );
    });

    expect(screen.getByTestId('current').textContent).toBe('none');
    await act(async () => {
      await user.click(screen.getByText('Set'));
    });
    expect(screen.getByTestId('current').textContent).toBe('abc123');
    // persisted
    expect(localStorage.getItem('osint.selectedInvestigationId')).toBe('abc123');
  });

  it('clears selection and removes from storage', async () => {
    const user = userEvent.setup();
    await act(async () => {
      render(
        <SelectedInvestigationProvider>
          <Harness />
        </SelectedInvestigationProvider>
      );
    });

    await act(async () => {
      await user.click(screen.getByText('Set'));
    });
    await act(async () => {
      await user.click(screen.getByText('Clear'));
    });
    expect(screen.getByTestId('current').textContent).toBe('none');
    expect(localStorage.getItem('osint.selectedInvestigationId')).toBeNull();
  });

  it('hydrates from localStorage', async () => {
    localStorage.setItem('osint.selectedInvestigationId', 'hydrated');
    await act(async () => {
      render(
        <SelectedInvestigationProvider>
          <Harness />
        </SelectedInvestigationProvider>
      );
    });
    expect(screen.getByTestId('current').textContent).toBe('hydrated');
  });
});
