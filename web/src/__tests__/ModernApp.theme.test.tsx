import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ModernApp from '../ModernApp';
import { ThemeProvider } from '../design/ThemeProvider';
import { SelectedInvestigationProvider } from '../contexts/SelectedInvestigationContext';

const renderWithProviders = () =>
  render(
    <ThemeProvider>
      <SelectedInvestigationProvider>
        <ModernApp />
      </SelectedInvestigationProvider>
    </ThemeProvider>
  );

describe('ModernApp glass theme', () => {
  beforeEach(() => {
    vi.spyOn(window, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'ok' })
    } as unknown as Response);
    vi.spyOn(window, 'setInterval').mockReturnValue(0 as unknown as number);
    vi.spyOn(window, 'clearInterval').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders glass header and sidebar shells', async () => {
    const { container } = renderWithProviders();

    await waitFor(() => expect(window.fetch).toHaveBeenCalled());

    const header = container.querySelector('header');
    expect(header?.className).toContain('glass');

    const sidebar = container.querySelector('aside');
    expect(sidebar?.className).toContain('glass');

    expect(container.innerHTML).not.toContain('bg-white');
  });

  it('keeps glass surfaces active for each navigation route', async () => {
    const user = userEvent.setup();
    const { container } = renderWithProviders();

    const navButtons = await screen.findAllByRole('button', { name: /dashboard|modules|intelligence|analysis|investigations|ai assistant|reports/i });

    for (const button of navButtons) {
      await user.click(button);
      await waitFor(() => expect(button).toBeInTheDocument());
      const main = container.querySelector('main');
      expect(main?.querySelector('.glass')).not.toBeNull();
      expect(main?.innerHTML ?? '').not.toContain('bg-white');
    }
  });
});
