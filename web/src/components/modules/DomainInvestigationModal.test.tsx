import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { DomainInvestigationModal } from './DomainInvestigationModal';
import toast from 'react-hot-toast';
import { resetAuthTokenStoreForTests, setAuthToken } from '../../services/authTokenStore';
import { AuthProvider } from '../../contexts/AuthContext';

// Mock react-hot-toast
vi.mock('react-hot-toast', () => ({
  default: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

// Mock fetch
global.fetch = vi.fn();

describe('DomainInvestigationModal', () => {
  const mockOnClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthTokenStoreForTests();
    setAuthToken('token-123');
  });

  const renderModal = () =>
    render(
      <AuthProvider>
        <DomainInvestigationModal
          isOpen={true}
          onClose={mockOnClose}
          apiUrl="http://localhost:8000"
        />
      </AuthProvider>
    );

  it('should call /api/modules/execute with correct payload', async () => {
    const mockResponse = {
      status: 'success',
      module_name: 'domain_recon',
      result: {
        domain: 'example.com',
        dns: { A: ['93.184.216.34'] },
      },
      execution_time: 1.5,
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    renderModal();

    // Enter a domain
    const input = screen.getByPlaceholderText('example.com');
    fireEvent.change(input, { target: { value: 'example.com' } });

    // Click run button
    const runButton = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:8000/api/modules/execute',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            module_name: 'domain_recon',
            parameters: {
              target: 'example.com',
              dns_lookup: true,
              whois_lookup: true,
              subdomain_scan: true,
            },
          }),
        })
      );
    });

    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith('Domain investigation completed!');
    });
  });

  it('should handle errors and display toast notification', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      json: async () => ({ detail: 'Module not found' }),
    });

    renderModal();

    const input = screen.getByPlaceholderText('example.com');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const runButton = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Module not found');
    });
  });

  it('should validate domain format before making API call', async () => {
    renderModal();

    const input = screen.getByPlaceholderText('example.com');
    fireEvent.change(input, { target: { value: 'invalid domain!' } });

    const runButton = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith(
        expect.stringContaining('valid domain name')
      );
    });

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should handle ModuleExecutionResponse error status', async () => {
    const mockErrorResponse = {
      status: 'error',
      module_name: 'domain_recon',
      error: 'Domain analysis failed',
      execution_time: 0.5,
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockErrorResponse,
    });

    renderModal();

    const input = screen.getByPlaceholderText('example.com');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const runButton = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Domain analysis failed');
    });
  });

  it('requires authentication before running an investigation', async () => {
    resetAuthTokenStoreForTests();

    renderModal();

    const input = screen.getByPlaceholderText('example.com');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const runButton = screen.getByRole('button', { name: /run investigation/i });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('You need to sign in before running investigations.');
    });

    expect(global.fetch).not.toHaveBeenCalled();
  });
});
